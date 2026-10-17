"""통합 보기 (derived tables) routes (plan axiom-adoption §3.2): table pages and a value's original rows."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ...core.jobs import RunJobStore
from .analyses import run_scope
from .derived import (
    MAX_VALUE_CHARS,
    NO_SOURCE_REASON,
    TABLE_INDEX_CACHE,
    TABLE_LABELS,
    TABLE_MAX_BYTES,
    TableIndex,
    derived_sources,
    page_rows,
    parse_query,
    require_table,
    source_info,
    table_summaries,
    value_rows,
)


def build_derived_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    def _source(run_id: str) -> tuple[dict[str, object], str]:
        scope = run_scope(store, run_id, require_ready=False)
        sources = derived_sources(scope.output_dir)
        if not sources:
            raise HTTPException(status_code=409, detail=NO_SOURCE_REASON)
        return sources[0], str(Path(scope.output_dir).resolve())

    def _index(source: dict[str, object], run_key: str, table: str) -> TableIndex:
        path = Path(str(source["directory"])) / f"{table}.jsonl"
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise HTTPException(status_code=409, detail="통합 보기 표 파일을 읽을 수 없습니다. 통합 보기 분석을 다시 실행하세요") from exc
        if size > TABLE_MAX_BYTES:
            raise HTTPException(status_code=409, detail=f"통합 보기 표 파일({size // (1024 * 1024):,} MB)이 읽기 한도를 넘습니다")
        try:
            return TABLE_INDEX_CACHE.get(run_key, str(source["analysis_id"]), table, path)
        except OSError as exc:
            raise HTTPException(status_code=409, detail="통합 보기 표 파일을 읽을 수 없습니다") from exc

    @router.get("/api/runs/{run_id}/derived")
    def get_derived(run_id: str) -> dict[str, object]:
        """The run's 통합 보기 set: ``{run_id, source: {status, analysis_id, generated_at, coverage, …} | null,
        reason?, tables: [{table, label, rows, occurrences, capped, cap_reason, dropped_values, by_kind,
        by_semantic, by_class?}], url_classes?}`` (``source = null`` with a Korean ``reason`` when none)."""
        scope = run_scope(store, run_id, require_ready=False)
        sources = derived_sources(scope.output_dir)
        if not sources:
            return {"run_id": run_id, "source": None, "reason": NO_SOURCE_REASON, "tables": []}
        source = sources[0]
        summary = source["summary"] if isinstance(source["summary"], dict) else {}
        url_classes = summary.get("url_classes") if isinstance(summary.get("url_classes"), dict) else {}
        return {
            "run_id": run_id,
            "source": source_info(source),
            "tables": list(table_summaries(summary).values()),
            "url_classes": {"version": url_classes.get("version"), "labels": url_classes.get("labels") or {}},
            "limitation": summary.get("limitation"),
        }

    @router.get("/api/runs/{run_id}/derived/{table}")
    def get_derived_table(
        run_id: str,
        table: str,
        q: str | None = Query(default=None),
        kind: str | None = Query(default=None),
        sort: str | None = Query(default=None),
        limit: str | None = Query(default=None),
        after: str | None = Query(default=None),
    ) -> dict[str, object]:
        """One keyset page of a table: ``{run_id, table, label, source, total, matched, limit, sort, q, kind,
        rows: [{value, normalized, semantic, semantics, count, kinds, families, first_seen, last_seen,
        sample_count, url_class?, url_class_label?, examples?, length?, sha256?}], next_cursor}``.

        ``table`` ∈ people, devices, paths, attachments, credentials, urls (else 404). ``q`` = substring of
        the value or its normalised form (casefolded, ≤200 chars); ``kind`` = rows seen in that row source;
        ``sort`` = ``count`` (desc, default) | ``first_seen`` (oldest first) | ``last_seen`` (newest first);
        ``limit`` 1–500 (default 100); ``after`` = the previous page's ``next_cursor``. Bad parameters and
        a cursor of another sort or generation are a Korean 422; a run without a 통합 보기 set is a 409.
        Credentials rows carry the masked value, its length and SHA-256 only."""
        require_table(table)
        query = parse_query(q, kind, sort, limit, after)
        source, run_key = _source(run_id)
        index = _index(source, run_key, table)
        rows, matched, next_cursor = page_rows(index, query, analysis_id=str(source["analysis_id"]))
        return {
            "run_id": run_id,
            "table": table,
            "label": TABLE_LABELS[table],
            "source": source_info(source),
            "total": len(index.lines),
            "matched": matched,
            "limit": query.limit,
            "sort": query.sort,
            "q": q.strip() if q else None,
            "kind": query.kind,
            "rows": rows,
            "next_cursor": next_cursor,
        }

    @router.get("/api/runs/{run_id}/derived/{table}/rows")
    def get_derived_value_rows(run_id: str, table: str, value: str = Query(default="")) -> dict[str, object]:
        """Original rows of one table value: the row (by its ``normalized`` value) with ``samples`` =
        ``[{kind, record_index, field, family, artifact_type, time, collection, locator, kind?|scope?|
        analysis_id?}]`` (≤20, spread over the kinds it was seen in). ``value`` missing or too long is a
        Korean 422; a value the table does not have is a 404."""
        require_table(table)
        text = value.strip()
        if not text or len(text) > MAX_VALUE_CHARS:
            raise HTTPException(status_code=422, detail=f"value(정규화 값)는 1~{MAX_VALUE_CHARS}자여야 합니다")
        source, run_key = _source(run_id)
        index = _index(source, run_key, table)
        return {"run_id": run_id, "table": table, "label": TABLE_LABELS[table], "source": source_info(source), **value_rows(index, text)}

    return router
