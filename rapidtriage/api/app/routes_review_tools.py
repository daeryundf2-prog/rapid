"""Review-tool API (AXIOM adoption E3, plan §3.3).

* ``GET/POST /api/cases/{case_id}/tags``, ``PATCH/DELETE /api/cases/{case_id}/tags/{tag_id}``
  -- user/system review tags (colour token, shortcut 1-9, description, author).
* ``GET/POST /api/cases/{case_id}/histogram-baselines`` -- saved category counts.
* ``GET /api/runs/{run_id}/histogram?compare=<baseline_id>`` -- the run's category
  counts (files, documents, timeline, indicators, artifact kinds) with a baseline's
  counts and deltas.
* ``GET /api/runs/{run_id}/review-history`` -- a row's mark history (author, time,
  note/tags before and after).
* ``GET /api/runs/{run_id}/related-media?path=`` -- other files with the same content
  hash (case DB file rows, else the files output's ``duplicate_content_groups``).

The ``/api/cases/{case_id}`` routes find the case DB through ``run_id`` (the run's
canonical case DB, see ``run_review.canonical_run_case``) or an explicit
``database`` path (checked like every other case-DB route). Tag batches with
hash propagation extend ``POST /api/case-db/review-batch`` (``tag_ids``,
``remove_tag_ids``, ``propagate_by_hash``; routes_case_db.py).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ...core.case_db import (
    CaseDatabase,
    CaseDatabaseError,
    ReviewToolError,
    apply_schema,
    apply_tag_ids,
    create_case_tag,
    create_histogram_baseline,
    delete_case_tag,
    get_histogram_baseline,
    list_case_tags,
    list_histogram_baselines,
    review_mark_history_entries,
    update_case_tag,
)
from ...core.case_db.helpers import normalize_path_for_db
from ...core.case_db.review_schema import COLOR_TOKEN_LABELS, COLOR_TOKENS
from ...core.jobs import RunJobStore, run_output_dir
from .helpers import get_job, get_output_path, resolve_request_reviewer
from .run_review import RunLocatorIndex, canonical_run_case
from .tree import build_run_tree, read_output_key

# Collections counted as one bar each (artifact kinds get one bar per kind).
HISTOGRAM_COLLECTIONS = ("files", "docs", "timeline", "indicators")
RELATED_MEDIA_PATH_LIMIT = 20


class CaseTagCreateRequest(BaseModel):
    name: Any = None
    color_token: Any = None
    shortcut: Any = None
    description: Any = ""
    created_by: str | None = None


class CaseTagUpdateRequest(BaseModel):
    """Only the fields present in the body change; ``shortcut: null`` clears the key."""

    name: Any = None
    color_token: Any = None
    shortcut: Any = None
    description: Any = None
    actor: str | None = None


class HistogramBaselineCreateRequest(BaseModel):
    name: Any = None
    run_id: str | None = None
    created_by: str | None = None


def review_tool_http_error(exc: CaseDatabaseError) -> HTTPException:
    status = exc.status if isinstance(exc, ReviewToolError) else 400
    message = str(exc)
    if message.startswith("case not found:"):
        status, message = 404, f"케이스를 찾을 수 없습니다: {message.split(':', 1)[1].strip()}"
    return HTTPException(status_code=status, detail=message)


TAG_BATCH_EXCLUSIVE_FIELDS = ("status", "verification_status", "tags", "add_tags", "note", "include_in_report")


def apply_review_tag_batch(database: CaseDatabase, request: Any, targets: list[dict[str, str]]) -> dict[str, object]:
    """``POST /api/case-db/review-batch`` with ``tag_ids`` / ``remove_tag_ids`` / ``propagate_by_hash``.

    One transaction: tags by id on the resolved targets, and with ``propagate_by_hash``
    on every file row of the same run (the case's newest evidence source when
    ``run_id`` is given) whose hash equals a target's. Above 10,000 rows nothing is
    applied and the refusal says why (422).
    """
    mixed = [name for name in TAG_BATCH_EXCLUSIVE_FIELDS if getattr(request, name, None) is not None]
    if mixed:
        raise HTTPException(status_code=422, detail=f"tag_ids는 다른 표시({', '.join(mixed)})와 함께 보낼 수 없습니다")
    add_ids = [int(item) for item in request.tag_ids or []]
    remove_ids = [int(item) for item in request.remove_tag_ids or []]
    if request.propagate_by_hash and not add_ids:
        raise HTTPException(status_code=422, detail="같은 해시 행에 전파할 태그(tag_ids)를 고르세요")
    if not add_ids and not remove_ids:
        raise HTTPException(status_code=422, detail="적용할 태그(tag_ids 또는 remove_tag_ids)가 없습니다")
    case_id = request.case_id
    try:
        with database.connect() as connection:
            apply_schema(connection)
            if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (case_id,)).fetchone() is None:
                raise HTTPException(status_code=404, detail=f"케이스를 찾을 수 없습니다: {case_id}")
            evidence_source_id = None
            if request.run_id:
                row = connection.execute(
                    "SELECT id FROM evidence_source WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)
                ).fetchone()
                evidence_source_id = int(row[0]) if row is not None else None
            result = apply_tag_ids(
                connection,
                case_id,
                targets,
                add_ids=add_ids,
                remove_ids=remove_ids,
                actor=resolve_request_reviewer(request.reviewer) or "local-user",
                propagate_by_hash=bool(request.propagate_by_hash),
                evidence_source_id=evidence_source_id,
            )
    except CaseDatabaseError as exc:
        raise review_tool_http_error(exc) from exc
    result.update(database=str(database.path), run_id=request.run_id, updated_count=result["applied_count"])
    return result


def histogram_counts(tree: dict[str, Any]) -> dict[str, dict[str, object]]:
    """``{key: {label, count, group}}`` from ``build_run_tree``: one bar per collection / artifact kind."""
    counts: dict[str, dict[str, object]] = {}
    for node in tree.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        collection = str(node.get("collection") or "")
        if collection in HISTOGRAM_COLLECTIONS:
            counts[f"collection:{collection}"] = {
                "label": str(node.get("label") or collection),
                "count": int(node.get("count") or 0),
                "group": "collection",
            }
        elif collection == "artifacts" and node.get("id") == "artifacts":
            for group in node.get("children") or []:
                for kind_node in (group.get("children") or []) if isinstance(group, dict) else []:
                    kind = str(kind_node.get("kind") or "") if isinstance(kind_node, dict) else ""
                    if not kind or kind_node.get("artifact_type"):
                        continue
                    entry = counts.setdefault(
                        f"kind:{kind}", {"label": str(kind_node.get("label") or kind), "count": 0, "group": "artifact"}
                    )
                    # A kind split over domains (``artifacts:<kind>@<domain>``) sums back to the kind.
                    entry["count"] = int(entry["count"]) + int(kind_node.get("count") or 0)
    return counts


def build_review_tools_router(
    store: RunJobStore,
    open_request_case_database: Callable[[str | Path], CaseDatabase],
) -> APIRouter:
    router = APIRouter()

    def _case_database(case_id: str, run_id: str | None, database: str | None, *, must_exist: bool = True) -> CaseDatabase | None:
        if run_id:
            job = get_job(store, run_id)
            if job.summary is None:
                raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
            path, canonical = canonical_run_case(job.summary, run_id)
            if case_id != canonical:
                raise HTTPException(status_code=404, detail=f"이 런의 케이스가 아닙니다: {case_id} (런의 케이스: {canonical})")
            if not path.is_file():
                if must_exist:
                    raise HTTPException(
                        status_code=409, detail="케이스 DB가 아직 없습니다. 먼저 케이스 DB를 준비하세요 (검토 표시 한 번이면 준비됩니다)."
                    )
                return None
            return open_request_case_database(path)
        if database:
            return open_request_case_database(database)
        raise HTTPException(status_code=422, detail="run_id 또는 database가 필요합니다")

    @contextmanager
    def _connection(database: CaseDatabase, case_id: str) -> Iterator[sqlite3.Connection]:
        try:
            with database.connect() as connection:
                apply_schema(connection)
                if connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (case_id,)).fetchone() is None:
                    raise HTTPException(status_code=404, detail=f"케이스를 찾을 수 없습니다: {case_id}")
                yield connection
        except CaseDatabaseError as exc:
            raise review_tool_http_error(exc) from exc

    # --- tags ---------------------------------------------------------------------

    @router.get("/api/cases/{case_id}/tags")
    def list_tags(
        case_id: str,
        run_id: str | None = Query(None),
        database: str | None = Query(None),
        include_deleted: bool = Query(False),
    ) -> dict[str, object]:
        """Tags of the case with live mark counts; ``exists: false`` before the run has a case DB."""
        opened = _case_database(case_id, run_id, database, must_exist=False)
        payload: dict[str, object] = {
            "command": "case.tags",
            "case_id": case_id,
            "exists": opened is not None,
            "color_tokens": [{"token": token, "label": COLOR_TOKEN_LABELS[token]} for token in COLOR_TOKENS],
            "tags": [],
        }
        if opened is None:
            return payload
        with _connection(opened, case_id) as connection:
            payload["tags"] = list_case_tags(connection, case_id, include_deleted=include_deleted)
        payload["database"] = str(opened.path)
        return payload

    @router.post("/api/cases/{case_id}/tags", status_code=201)
    def create_tag(
        case_id: str,
        request: CaseTagCreateRequest,
        run_id: str | None = Query(None),
        database: str | None = Query(None),
    ) -> dict[str, object]:
        opened = _case_database(case_id, run_id, database)
        assert opened is not None
        with _connection(opened, case_id) as connection:
            try:
                tag = create_case_tag(
                    connection,
                    case_id,
                    name=request.name,
                    color_token=request.color_token,
                    shortcut=request.shortcut,
                    description=request.description,
                    actor=resolve_request_reviewer(request.created_by) or "local-user",
                )
            except CaseDatabaseError as exc:
                raise review_tool_http_error(exc) from exc
        return {"command": "case.tags.create", "tag": tag}

    @router.patch("/api/cases/{case_id}/tags/{tag_id}")
    def update_tag(
        case_id: str,
        tag_id: int,
        request: CaseTagUpdateRequest,
        run_id: str | None = Query(None),
        database: str | None = Query(None),
    ) -> dict[str, object]:
        opened = _case_database(case_id, run_id, database)
        assert opened is not None
        fields = {key: getattr(request, key) for key in ("name", "color_token", "shortcut", "description") if key in request.model_fields_set}
        if not fields:
            raise HTTPException(status_code=422, detail="바꿀 항목(name, color_token, shortcut, description)이 없습니다")
        with _connection(opened, case_id) as connection:
            try:
                tag = update_case_tag(
                    connection, case_id, tag_id, actor=resolve_request_reviewer(request.actor) or "local-user", **fields
                )
            except CaseDatabaseError as exc:
                raise review_tool_http_error(exc) from exc
        return {"command": "case.tags.update", "tag": tag}

    @router.delete("/api/cases/{case_id}/tags/{tag_id}")
    def delete_tag(
        case_id: str,
        tag_id: int,
        run_id: str | None = Query(None),
        database: str | None = Query(None),
        actor: str | None = Query(None),
    ) -> dict[str, object]:
        """Soft delete: the tag keeps its row (``deleted_at``), leaves every mark and frees its key."""
        opened = _case_database(case_id, run_id, database)
        assert opened is not None
        with _connection(opened, case_id) as connection:
            try:
                tag = delete_case_tag(connection, case_id, tag_id, actor=resolve_request_reviewer(actor) or "local-user")
            except CaseDatabaseError as exc:
                raise review_tool_http_error(exc) from exc
        return {"command": "case.tags.delete", "tag": tag, "removed_from_marks": tag.get("removed_from_marks", 0)}

    # --- histogram baselines ------------------------------------------------------------

    def _run_histogram(run_id: str) -> dict[str, dict[str, object]]:
        return histogram_counts(build_run_tree(store, run_id))

    @router.get("/api/cases/{case_id}/histogram-baselines")
    def list_baselines(
        case_id: str,
        run_id: str | None = Query(None),
        database: str | None = Query(None),
    ) -> dict[str, object]:
        opened = _case_database(case_id, run_id, database, must_exist=False)
        if opened is None:
            return {"command": "case.histogram-baselines", "case_id": case_id, "exists": False, "baselines": []}
        with _connection(opened, case_id) as connection:
            baselines = list_histogram_baselines(connection, case_id)
        return {"command": "case.histogram-baselines", "case_id": case_id, "exists": True, "baselines": baselines}

    @router.post("/api/cases/{case_id}/histogram-baselines", status_code=201)
    def create_baseline(
        case_id: str,
        request: HistogramBaselineCreateRequest,
        run_id: str | None = Query(None),
        database: str | None = Query(None),
    ) -> dict[str, object]:
        """Saves the counts of ``request.run_id`` (default: the ``run_id`` query) as computed by the server."""
        source_run = request.run_id or run_id
        if not source_run:
            raise HTTPException(status_code=422, detail="기준선으로 저장할 런(run_id)이 필요합니다")
        opened = _case_database(case_id, run_id or (None if database else source_run), database)
        assert opened is not None
        counts = _run_histogram(source_run)
        with _connection(opened, case_id) as connection:
            try:
                baseline = create_histogram_baseline(
                    connection,
                    case_id,
                    name=request.name,
                    run_id=source_run,
                    counts=counts,
                    actor=resolve_request_reviewer(request.created_by) or "local-user",
                )
            except CaseDatabaseError as exc:
                raise review_tool_http_error(exc) from exc
        return {"command": "case.histogram-baselines.create", "baseline": baseline}

    @router.get("/api/runs/{run_id}/histogram")
    def run_histogram(run_id: str, compare: int | None = Query(None, ge=1)) -> dict[str, object]:
        """Category counts of the run; with ``compare`` also the baseline count and delta per bar."""
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        counts = _run_histogram(run_id)
        database_path, case_id = canonical_run_case(job.summary, run_id)
        baseline: dict[str, object] | None = None
        if compare is not None:
            if not database_path.is_file():
                raise HTTPException(status_code=404, detail=f"기준선을 찾을 수 없습니다: {compare} (케이스 DB 없음)")
            opened = open_request_case_database(database_path)
            with _connection(opened, case_id) as connection:
                try:
                    baseline = get_histogram_baseline(connection, case_id, compare)
                except CaseDatabaseError as exc:
                    raise review_tool_http_error(exc) from exc
        base_counts = baseline.get("counts") if isinstance(baseline, dict) else None
        base_counts = base_counts if isinstance(base_counts, dict) else {}
        bars: list[dict[str, object]] = []
        for key in sorted(set(counts) | set(base_counts)):
            current = counts.get(key)
            previous = base_counts.get(key) if isinstance(base_counts.get(key), dict) else None
            count = int(current["count"]) if current else 0
            bar: dict[str, object] = {
                "key": key,
                "label": str((current or previous or {}).get("label") or key),
                "group": str((current or {}).get("group") or ("artifact" if key.startswith("kind:") else "collection")),
                "count": count,
            }
            if baseline is not None:
                base = int(previous.get("count") or 0) if previous else 0
                bar["baseline_count"] = base
                bar["delta"] = count - base
            bars.append(bar)
        bars.sort(key=lambda bar: (-int(bar["count"]), str(bar["label"])))
        payload: dict[str, object] = {
            "command": "run.histogram",
            "run_id": run_id,
            "case_id": case_id,
            "bars": bars,
            "total": sum(int(bar["count"]) for bar in bars),
        }
        if baseline is not None:
            payload["baseline"] = {key: value for key, value in baseline.items() if key != "counts"}
            payload["baseline_total"] = sum(int(bar.get("baseline_count") or 0) for bar in bars)
        return payload

    # --- mark history ---------------------------------------------------------------

    @router.get("/api/runs/{run_id}/review-history")
    def run_review_history(
        run_id: str,
        collection: str | None = Query(None),
        kind: str | None = Query(None),
        locator: str | None = Query(None),
        target_type: str | None = Query(None),
        target_id: str | None = Query(None),
    ) -> dict[str, object]:
        """Change history of one row's mark (newest first): author, time, note and tags before/after."""
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        database_path, case_id = canonical_run_case(job.summary, run_id)
        payload: dict[str, object] = {"command": "case-db.review-history", "run_id": run_id, "case_id": case_id, "entries": []}
        if not database_path.is_file():
            return payload
        try:
            connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise HTTPException(status_code=400, detail=f"케이스 DB를 열 수 없습니다: {exc}") from exc
        connection.row_factory = sqlite3.Row
        try:
            if not (target_type and target_id):
                if not (collection and locator):
                    raise HTTPException(status_code=422, detail="collection·locator 또는 target_type·target_id가 필요합니다")
                outputs = job.summary.get("outputs")
                try:
                    output_dir = run_output_dir(job.summary)
                except RuntimeError:
                    output_dir = None
                index = RunLocatorIndex(connection, case_id, outputs if isinstance(outputs, dict) else {}, output_dir=output_dir)
                hit = index.resolve(collection, locator, kind or "")
                if hit is None:
                    return payload
                target_type, target_id = hit
            payload["target_type"], payload["target_id"] = target_type, target_id
            payload["entries"] = review_mark_history_entries(connection, case_id, target_type, target_id)
        except sqlite3.Error as exc:
            payload["error"] = str(exc)
        finally:
            connection.close()
        return payload

    # --- export context ----------------------------------------------------------------

    @router.get("/api/runs/{run_id}/export-context")
    def export_context(run_id: str) -> dict[str, object]:
        """Case/evidence numbers for the grid CSV's fixed trailing columns (read-only).

        ``case_number``: ``case_record.case_number`` when the case DB has it (케이스 만들기, E1),
        else null. ``evidence_number``: the newest evidence source's ``evidence_number`` when
        present, else its case-DB citation id (``<prefix>-EVID-<n>``).
        """
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        database_path, case_id = canonical_run_case(job.summary, run_id)
        payload: dict[str, object] = {
            "command": "run.export-context",
            "run_id": run_id,
            "case_id": case_id,
            "case_number": None,
            "evidence_number": None,
            "evidence_name": None,
        }
        if not database_path.is_file():
            return payload
        try:
            connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                case_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(case_record)")}
                if "case_number" in case_columns:
                    row = connection.execute("SELECT case_number FROM case_record WHERE case_id = ?", (case_id,)).fetchone()
                    payload["case_number"] = (str(row[0]) if row is not None and row[0] else None)
                evidence_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(evidence_source)")}
                # Prefer the examiner-entered evidence number (case intake); fall back to the
                # citation id for run-imported DBs where that column is empty.
                number = (
                    "COALESCE(NULLIF(evidence_number, ''), citation_id)"
                    if "evidence_number" in evidence_columns
                    else "citation_id"
                )
                row = connection.execute(
                    f"SELECT {number} AS number, display_name FROM evidence_source WHERE case_id = ? ORDER BY id DESC LIMIT 1",
                    (case_id,),
                ).fetchone()
                if row is not None:
                    payload["evidence_number"] = str(row["number"] or "") or None
                    payload["evidence_name"] = str(row["display_name"] or "") or None
            finally:
                connection.close()
        except sqlite3.Error as exc:
            payload["error"] = str(exc)
        return payload

    # --- related media ---------------------------------------------------------------

    @router.get("/api/runs/{run_id}/related-media")
    def related_media(run_id: str, path: str = Query(..., min_length=1)) -> dict[str, object]:
        """Other files with the same content hash as ``path`` ("관련 미디어 n")."""
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")
        database_path, case_id = canonical_run_case(job.summary, run_id)
        payload: dict[str, object] = {"command": "run.related-media", "run_id": run_id, "path": path, "count": 0, "paths": [], "source": "none"}
        normalized = normalize_path_for_db(path)
        if database_path.is_file():
            try:
                connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
                try:
                    row = connection.execute(
                        "SELECT id, hash_sha256, hash_md5 FROM file_record WHERE case_id = ? AND normalized_path = ? "
                        "AND (COALESCE(hash_sha256, '') != '' OR COALESCE(hash_md5, '') != '') ORDER BY id LIMIT 1",
                        (case_id, normalized),
                    ).fetchone()
                    if row is not None:
                        column, value = ("hash_sha256", row[1]) if row[1] else ("hash_md5", row[2])
                        others = connection.execute(
                            f"SELECT DISTINCT path FROM file_record WHERE case_id = ? AND lower({column}) = lower(?) "
                            "AND normalized_path != ? ORDER BY path",
                            (case_id, value, normalized),
                        ).fetchall()
                        payload.update(
                            count=len(others),
                            paths=[str(item[0]) for item in others[:RELATED_MEDIA_PATH_LIMIT]],
                            source="case-db",
                            hash_algorithm=column.removeprefix("hash_"),
                            hash=str(value).lower(),
                        )
                        return payload
                finally:
                    connection.close()
            except sqlite3.Error:
                pass
        try:
            groups = read_output_key(get_output_path(store, run_id, "files"), "duplicate_content_groups")
        except HTTPException:
            groups = None
        for group in groups if isinstance(groups, list) else []:
            paths = [str(item) for item in group.get("paths") or []] if isinstance(group, dict) else []
            if normalized in {normalize_path_for_db(item) for item in paths}:
                others = [item for item in paths if normalize_path_for_db(item) != normalized]
                payload.update(
                    count=max(int(group.get("file_count") or len(paths)) - 1, 0),
                    paths=others[:RELATED_MEDIA_PATH_LIMIT],
                    source="duplicate_content_groups",
                    hash_algorithm="sha256",
                    hash=str(group.get("sha256") or ""),
                )
                break
        return payload

    return router
