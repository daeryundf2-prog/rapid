"""Search index API (plan search-2026-10-13 §3.2, S1 endpoints).

* ``GET  /api/runs/{run}/search/index``         -- status ``none|building|ready|stale``
* ``POST /api/runs/{run}/search/index/build``   -- 202 AnalysisState (kind ``search-index``)
* ``POST /api/runs/{run}/search/query``         -- one result page (§3.2 response shape); with
  ``keywords`` instead of ``q`` the console's global search: v1 ``GET /search`` hits (R7 P2)
* ``POST /api/runs/{run}/search/count``         -- per-term totals (budgeted, resumable by ``offset``)
* ``POST /api/runs/{run}/search/hashes``        -- hash list / hash set lookup
* ``GET|POST|PUT|DELETE /api/runs/{run}/search/saved[/{id}]`` -- saved searches (case DB)
* ``GET  /api/runs/{run}/search/history``       -- ``<run>/search/history.sqlite`` (last 500)
* ``GET|POST|DELETE /api/hash-sets[/{id}]``     -- hash-set store

Queries (meta read, staleness, the query itself) run in a worker thread; a
watcher sets the engine's cancel event when the client disconnects (checked
by the SQLite progress handler) or the request task is cancelled. The run's
query slot is held until that worker really ends and released in its
``finally``. History and saved-search counts are written by a background
thread, never on the event loop.
"""

from __future__ import annotations

import asyncio
import email.parser
import email.policy
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from ...core.jobs import RunJobStore
from ...core.search_index.build import read_index_meta, stale_reasons
from ...core.search_index.engine import (
    DEFAULT_BUDGET_SECONDS,
    PAGE_MAX,
    Budget,
    QueryRequest,
    SearchOptions,
    run_count,
    run_hashes,
    run_query,
)
from ...core.search_index.hashsets import (
    LABELS,
    MAX_UPLOAD_BYTES,
    HashSetError,
    create_hash_set,
    delete_hash_set,
    hash_set_path,
    list_hash_sets,
    read_hash_set,
    read_hash_values,
)
from ...core.search_index.hits import (
    MAX_CONSOLE_KEYWORDS,
    attach_console_hits,
    console_keywords,
    console_query,
)
from ...core.search_index.query import QueryError
from ...core.search_index.schema import INDEX_FILE_NAME
from ...core.search_index.textutil import normalize_hash
from .analyses import ANALYSIS_RUNNER, public_state
from .search_index_service import (
    CORRUPT_INDEX,
    NO_INDEX,
    QUERY_LIMITER,
    SEARCH_HISTORY,
    QuerySlot,
    ReviewMarks,
    completed_run,
    create_saved,
    delete_saved,
    get_saved,
    index_status,
    list_saved,
    record_saved_count,
    search_history,
    submit_build,
    update_saved,
)

MAX_HASHES = 100_000
MAX_COUNT_TERMS = 5000
MAX_INVALID = 100
DISCONNECT_POLL_SECONDS = 0.25


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchOptionsBody(_Body):
    tz: str | None = Field(default=None, max_length=16)
    reference_ts: str | None = Field(default=None, max_length=64)
    case_sensitive: bool = False
    whole_word: bool = False
    hide_hashsets: list[str] = Field(default_factory=list, max_length=32)

    def to_options(self) -> SearchOptions:
        return SearchOptions(
            tz=self.tz,
            reference_ts=self.reference_ts,
            case_sensitive=self.case_sensitive,
            whole_word=self.whole_word,
            hide_hashsets=list(self.hide_hashsets),
        )


class PageBody(_Body):
    cursor: str | None = Field(default=None, max_length=4096)
    limit: int = Field(default=100, ge=1, le=PAGE_MAX)
    offset: int = Field(default=0, ge=0, description="keywords 검색: 이 쪽 앞의 적중 수(search_result_id 번호만; 쪽은 cursor로 넘긴다)")


class HistogramBody(_Body):
    bucket: str = Field(default="auto", max_length=8)


class IndexBuildBody(_Body):
    mode: Literal["full", "incremental"] = "full"
    analysis_ids: list[str] = Field(default_factory=list, max_length=200)


class SearchQueryBody(_Body):
    # The parser enforces the 4,000-character limit with a Korean 400.
    q: str = Field(default="", max_length=100_000)
    keywords: list[str] | None = Field(
        default=None,
        max_length=MAX_CONSOLE_KEYWORDS,
        description=(
            "콘솔 전체 검색(q 대신): 키워드 중 하나라도 들어 있는 행(v1 exact와 같은 정규화). "
            "응답은 rows 대신 matches(v1 GET /search 적중 모양)이고 검색 기록에 남지 않는다"
        ),
    )
    options: SearchOptionsBody = Field(default_factory=SearchOptionsBody)
    page: PageBody = Field(default_factory=PageBody)
    sort: Literal["relevance", "ts", "-ts", "path"] = "relevance"
    collapse: bool = True
    facets: bool = True
    histogram: HistogramBody | None = Field(default=None, description="null(기본): 히스토그램 없음. 요청하면 집계 패스에서 함께 만든다")
    highlight: bool = True
    view: Literal["rows", "timeline"] = "rows"
    aggregates: bool = Field(default=True, description="false: 첫 페이지만 빠르게(total·facets·histogram은 null)")
    saved_id: int | None = Field(default=None, ge=1, description="저장 검색에서 실행했을 때 그 id (건수 배지를 갱신)")


class CountTerm(_Body):
    label: str = Field(default="", max_length=500)
    q: str = Field(..., max_length=100_000)


class SearchCountBody(_Body):
    terms: list[CountTerm] = Field(..., min_length=1)
    options: SearchOptionsBody = Field(default_factory=SearchOptionsBody)
    offset: int = Field(default=0, ge=0)


class HashesBody(_Body):
    hashes: list[str] | None = None
    hashset_id: str | None = Field(default=None, max_length=64)
    algorithms: list[Literal["md5", "sha1", "sha256"]] = Field(default_factory=list)
    docs_per_hash: int = Field(default=50, ge=1, le=50)


class SavedBody(_Body):
    name: str = Field(..., min_length=1, max_length=200)
    q: str = Field(..., min_length=1, max_length=4000)
    options: dict[str, Any] = Field(default_factory=dict)
    sort: Literal["relevance", "ts", "-ts", "path"] = "relevance"
    view: Literal["rows", "timeline"] = "rows"


class SavedUpdateBody(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    q: str | None = Field(default=None, min_length=1, max_length=4000)
    options: dict[str, Any] | None = None
    sort: Literal["relevance", "ts", "-ts", "path"] | None = None
    view: Literal["rows", "timeline"] | None = None


class HashSetJsonBody(_Body):
    name: str = Field(..., min_length=1, max_length=200)
    label: Literal["known-good", "known-bad", "custom"] = "custom"
    lines: str = Field(..., min_length=1)
    filename: str = Field(default="", max_length=200)


def query_error(exc: QueryError) -> JSONResponse:
    """400 ``{"detail": "질의 7번째 글자: …", "position": 7}`` (404 for a missing hash set)."""
    if exc.status == 404:
        return JSONResponse(status_code=404, content={"detail": exc.detail})
    return JSONResponse(status_code=400, content={"detail": exc.detail, "position": exc.position, "message": exc.message})


class RequestGone(Exception):
    """The request ended before its worker started (the slot was already given back)."""


async def run_cancellable(request: Request, work: Callable[[threading.Event], dict[str, object]], slot: QuerySlot) -> dict[str, object]:
    """Run ``work(cancel_event)`` in a worker thread holding ``slot``.

    A client disconnect or a cancelled request task sets the cancel event (the engine
    stops at its next progress check). The slot is released in the worker's ``finally``
    -- so it is held exactly as long as the work runs -- or here when the worker never
    started; it is never leaked.
    """
    cancel = threading.Event()
    finished = asyncio.Event()

    def runner() -> dict[str, object]:
        if not slot.claim():
            raise RequestGone()
        try:
            return work(cancel)
        finally:
            slot.release()

    async def watch() -> None:
        while not finished.is_set():
            if await request.is_disconnected():
                cancel.set()
                return
            try:
                await asyncio.wait_for(finished.wait(), timeout=DISCONNECT_POLL_SECONDS)
            except asyncio.TimeoutError:
                continue

    watcher = asyncio.create_task(watch())
    try:
        return await run_in_threadpool(runner)
    except BaseException:
        cancel.set()
        raise
    finally:
        finished.set()
        watcher.cancel()
        if not slot.started:
            slot.release()


def load_meta(index_path: Path) -> dict[str, object]:
    """Index meta or 404 (no index) / 409 (unreadable); a short lock is retried (never a false 404)."""
    meta, unreadable = read_index_meta(index_path)
    if meta is None:
        if unreadable is not None:
            raise HTTPException(status_code=409, detail=CORRUPT_INDEX.format(reason=unreadable))
        raise HTTPException(status_code=404, detail=NO_INDEX)
    return meta


def _parse_multipart(body: bytes, content_type: str) -> dict[str, tuple[bytes, str]]:
    """``multipart/form-data`` -> ``{field: (bytes, filename)}`` (stdlib email parser)."""
    message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    fields: dict[str, tuple[bytes, str]] = {}
    if not message.is_multipart():
        raise HTTPException(status_code=400, detail="multipart 본문을 해석할 수 없습니다")
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        fields[str(name)] = (payload, str(part.get_filename() or ""))
    return fields


def build_search_index_router(store: RunJobStore, *, owner: object | None = None) -> APIRouter:
    router = APIRouter()

    @router.get("/api/runs/{run_id}/search/index")
    def get_search_index(run_id: str) -> dict[str, object]:
        """Index status: ``none|building|ready|stale`` (+ the running build's AnalysisState)."""
        job, _output_dir = completed_run(store, run_id)
        return {"run_id": run_id, **index_status(job)}

    @router.post("/api/runs/{run_id}/search/index/build", status_code=202)
    def build_search_index(run_id: str, body: IndexBuildBody | None = None) -> dict[str, object]:
        """Queue a ``search-index`` analysis (409 while one runs or the run is not finished)."""
        completed_run(store, run_id)
        options = (body or IndexBuildBody()).model_dump()
        state = submit_build(store, run_id, options, owner=owner)
        return public_state(state)

    @router.post("/api/runs/{run_id}/search/query")
    async def search_query(run_id: str, body: SearchQueryBody, request: Request) -> Any:
        job, output_dir = completed_run(store, run_id)
        index_path = output_dir / INDEX_FILE_NAME
        marks = ReviewMarks(job, run_id)
        keywords: list[str] | None = None
        q = body.q
        if body.keywords is not None:
            if body.q.strip():
                raise HTTPException(status_code=400, detail="q와 keywords 중 하나만 주세요")
            keywords = console_keywords(body.keywords)
            if not keywords:
                raise HTTPException(status_code=400, detail="검색어를 입력하세요")
            q = console_query(keywords)
        query_request = QueryRequest(
            q=q,
            options=body.options.to_options(),
            cursor=body.page.cursor,
            limit=body.page.limit,
            sort=body.sort,
            collapse=body.collapse,
            facets=body.facets,
            histogram=body.histogram.bucket if body.histogram is not None else None,
            highlight=body.highlight,
            view=body.view,
            aggregates=body.aggregates,
        )
        built: dict[str, object] = {}

        def work(cancel: threading.Event) -> dict[str, object]:
            meta = load_meta(index_path)
            built["build_id"] = meta.get("build_id")
            stale = bool(stale_reasons(meta, job.summary or {}, output_dir, ANALYSIS_RUNNER.load_state))
            result = run_query(
                index_path,
                meta,
                query_request,
                budget=Budget(DEFAULT_BUDGET_SECONDS, cancel),
                review_provider=marks.load,
                # Console hits: the grid overlays review marks from the review map itself.
                review_lookup=marks.overlay if keywords is None else None,
                hashset_resolver=hash_set_path,
                stale=stale,
            )
            marks.apply_truncation(result, uses_review=bool(result.pop("uses_review", False)))
            if keywords is not None:
                attach_console_hits(result, keywords, summary=job.summary or {}, run_id=run_id, offset=body.page.offset)
            return result

        slot = QUERY_LIMITER.acquire(run_id)
        try:
            result = await run_cancellable(request, work, slot)
        except QueryError as exc:
            return query_error(exc)
        page = result["page"] if isinstance(result.get("page"), dict) else {}
        if keywords is not None:
            # The console's global search is not an analyst query: like v1, no history entry
            # (nothing is written into the run folder).
            return {"run_id": run_id, "keywords": keywords, "backend": "index", **result}
        if not body.page.cursor:
            # One history entry per search (not per page), written off the event loop.
            SEARCH_HISTORY.record(
                output_dir,
                {
                    "q": body.q,
                    "options": body.options.model_dump(),
                    "sort": body.sort,
                    "view": body.view,
                    "collapse": body.collapse,
                    "total": page.get("total"),
                    "total_exact": page.get("total_exact"),
                    "elapsed_ms": result.get("elapsed_ms"),
                    "build_id": built.get("build_id"),
                    "saved_id": body.saved_id,
                },
                truncated=bool(result.get("truncated")),
            )
            if body.saved_id is not None and page.get("total") is not None:
                saved_id, total, exact = body.saved_id, int(page.get("total") or 0), bool(page.get("total_exact"))
                SEARCH_HISTORY.submit(lambda: record_saved_count(job, run_id, saved_id, total, exact))
        return {"run_id": run_id, **result}

    @router.post("/api/runs/{run_id}/search/count")
    async def search_count(run_id: str, body: SearchCountBody, request: Request) -> Any:
        if len(body.terms) > MAX_COUNT_TERMS:
            raise HTTPException(status_code=413, detail=f"검색어가 너무 많습니다(최대 {MAX_COUNT_TERMS:,}개)")
        job, output_dir = completed_run(store, run_id)
        index_path = output_dir / INDEX_FILE_NAME
        if body.offset > len(body.terms):
            raise HTTPException(status_code=400, detail="offset이 검색어 수보다 큽니다")
        marks = ReviewMarks(job, run_id)
        terms = [term.model_dump() for term in body.terms]

        def work(cancel: threading.Event) -> dict[str, object]:
            return run_count(
                index_path,
                load_meta(index_path),
                terms,
                body.options.to_options(),
                offset=body.offset,
                budget=Budget(DEFAULT_BUDGET_SECONDS, cancel),
                review_provider=marks.load,
                hashset_resolver=hash_set_path,
            )

        slot = QUERY_LIMITER.acquire(run_id)
        try:
            result = await run_cancellable(request, work, slot)
        except QueryError as exc:
            return query_error(exc)
        return {"run_id": run_id, **result}

    @router.post("/api/runs/{run_id}/search/hashes")
    async def search_hashes(run_id: str, body: HashesBody, request: Request) -> dict[str, object]:
        if body.hashes is not None and len(body.hashes) > MAX_HASHES:
            raise HTTPException(status_code=413, detail="해시 목록이 너무 큽니다(최대 100,000개)")
        if (body.hashes is None) == (body.hashset_id is None):
            raise HTTPException(status_code=400, detail="hashes 또는 hashset_id 중 하나만 주세요")
        _job, output_dir = completed_run(store, run_id)
        index_path = output_dir / INDEX_FILE_NAME
        invalid: list[dict[str, object]] = []
        invalid_count = 0
        pairs: list[tuple[str, str]] = []
        wanted = set(body.algorithms)
        if body.hashset_id is not None:
            try:
                pairs = read_hash_values(body.hashset_id)
            except HashSetError as exc:
                raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
        else:
            for line, raw in enumerate(body.hashes or [], start=1):
                text = str(raw or "").strip()
                if not text:
                    continue
                normalized = normalize_hash(text)
                reason = None
                if normalized is None:
                    reason = "해시 형식이 아닙니다(MD5 32자·SHA-1 40자·SHA-256 64자 16진수)"
                elif wanted and normalized[0] not in wanted:
                    reason = f"요청한 알고리즘({', '.join(sorted(wanted))})이 아닙니다"
                if reason is not None:
                    invalid_count += 1
                    if len(invalid) < MAX_INVALID:
                        invalid.append({"line": line, "value": text[:80], "reason": reason})
                    continue
                assert normalized is not None
                pairs.append(normalized)
        if wanted:
            pairs = [pair for pair in pairs if pair[0] in wanted]

        def work(cancel: threading.Event) -> dict[str, object]:
            meta = load_meta(index_path)
            result = run_hashes(index_path, meta, pairs, budget=Budget(DEFAULT_BUDGET_SECONDS, cancel), docs_per_hash=body.docs_per_hash)
            return {**result, "index": {"build_id": meta.get("build_id")}}

        slot = QUERY_LIMITER.acquire(run_id)
        try:
            result = await run_cancellable(request, work, slot)
        except QueryError as exc:
            return query_error(exc)
        return {"run_id": run_id, **result, "invalid": invalid, "invalid_count": invalid_count}

    # -- saved searches / history ---------------------------------------------

    @router.get("/api/runs/{run_id}/search/saved")
    def list_saved_searches(run_id: str) -> dict[str, object]:
        job, _output_dir = completed_run(store, run_id)
        SEARCH_HISTORY.flush()  # last counts of searches run from saved searches
        return {"run_id": run_id, "saved": list_saved(job, run_id)}

    @router.post("/api/runs/{run_id}/search/saved", status_code=201)
    def create_saved_search(run_id: str, body: SavedBody) -> dict[str, object]:
        job, _output_dir = completed_run(store, run_id)
        return create_saved(job, run_id, body.model_dump())

    @router.get("/api/runs/{run_id}/search/saved/{saved_id}")
    def get_saved_search(run_id: str, saved_id: int) -> dict[str, object]:
        job, _output_dir = completed_run(store, run_id)
        SEARCH_HISTORY.flush()
        return get_saved(job, run_id, saved_id)

    @router.put("/api/runs/{run_id}/search/saved/{saved_id}")
    def update_saved_search(run_id: str, saved_id: int, body: SavedUpdateBody) -> dict[str, object]:
        job, _output_dir = completed_run(store, run_id)
        return update_saved(job, run_id, saved_id, body.model_dump())

    @router.delete("/api/runs/{run_id}/search/saved/{saved_id}", status_code=204)
    def delete_saved_search(run_id: str, saved_id: int) -> None:
        job, _output_dir = completed_run(store, run_id)
        delete_saved(job, run_id, saved_id)

    @router.get("/api/runs/{run_id}/search/history")
    def get_search_history(run_id: str, limit: int = Query(50, ge=1, le=500)) -> dict[str, object]:
        job, _output_dir = completed_run(store, run_id)
        return {"run_id": run_id, "history": search_history(job, limit)}

    # -- hash sets ----------------------------------------------------------------

    @router.get("/api/hash-sets")
    def get_hash_sets() -> dict[str, object]:
        return {"hash_sets": list_hash_sets()}

    @router.get("/api/hash-sets/{hash_set_id}")
    def get_hash_set(hash_set_id: str) -> dict[str, object]:
        try:
            return read_hash_set(hash_set_id)
        except HashSetError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    @router.delete("/api/hash-sets/{hash_set_id}", status_code=204)
    def remove_hash_set(hash_set_id: str) -> None:
        try:
            delete_hash_set(hash_set_id)
        except HashSetError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    @router.post(
        "/api/hash-sets",
        status_code=201,
        openapi_extra={
            "requestBody": {
                "content": {
                    "application/json": {"schema": HashSetJsonBody.model_json_schema()},
                    "multipart/form-data": {"schema": {"type": "object", "properties": {"file": {"type": "string", "format": "binary"}, "name": {"type": "string"}, "label": {"type": "string", "enum": list(LABELS)}}}},
                    "text/plain": {"schema": {"type": "string"}},
                    "text/csv": {"schema": {"type": "string"}},
                }
            }
        },
    )
    async def upload_hash_set(
        request: Request,
        name: str | None = Query(default=None, max_length=200),
        label: str = Query(default="custom", max_length=16),
        filename: str = Query(default="", max_length=200),
    ) -> dict[str, object]:
        """``{name, label, lines}`` JSON, ``multipart/form-data`` (``file`` + ``name``/``label``) or a raw text/CSV body (``?name=&label=&filename=``); <= 50 MB."""
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES + 64 * 1024:
            raise HTTPException(status_code=413, detail="해시 세트 파일이 너무 큽니다(최대 50 MB)")
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES + 64 * 1024:
                raise HTTPException(status_code=413, detail="해시 세트 파일이 너무 큽니다(최대 50 MB)")
            chunks.append(chunk)
        raw = b"".join(chunks)
        content_type = request.headers.get("content-type", "")
        data: bytes
        if content_type.startswith("application/json"):
            try:
                body = HashSetJsonBody.model_validate(json.loads(raw.decode("utf-8")))
            except (ValueError, UnicodeDecodeError) as exc:
                raise HTTPException(status_code=400, detail=f"요청 본문이 올바른 해시 세트 JSON이 아닙니다: {exc}") from exc
            name, label, filename, data = body.name, body.label, body.filename, body.lines.encode("utf-8")
        elif content_type.startswith("multipart/form-data"):
            fields = _parse_multipart(raw, content_type)
            if "file" not in fields:
                raise HTTPException(status_code=400, detail="multipart 본문에 file 항목이 없습니다")
            data, filename = fields["file"]
            name = (fields.get("name", (b"", ""))[0].decode("utf-8", "replace").strip() or name or filename or "").strip()
            label = fields.get("label", (label.encode("utf-8"), ""))[0].decode("utf-8", "replace").strip() or label
        else:
            data = raw
        try:
            return await run_in_threadpool(create_hash_set, name=name or filename or "", label=label, data=data, filename=filename)
        except HashSetError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc

    return router
