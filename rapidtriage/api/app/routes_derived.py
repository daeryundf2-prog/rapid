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
    TABLES,
    TableIndex,
    derived_sources,
    page_rows,
    parse_query,
    require_table,
    source_info,
    table_summaries,
    value_rows,
)
from .derived_graph import (
    GRAPH_MAX_NODES,
    GRAPH_MIN_NODES,
    build_graph,
    read_sample_rows,
)
from .helpers import get_named_output, get_output_path
from .jsonl_records import iter_records_at


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
            "total": len(index),
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
        ``[{kind, record_index, field, family, artifact_type, time, collection, locator, scope?,
        analysis_id?, analysis_kind?}]`` (≤20, spread over the kinds it was seen in). ``value`` missing or too long is a
        Korean 422; a value the table does not have is a 404."""
        require_table(table)
        text = value.strip()
        if not text or len(text) > MAX_VALUE_CHARS:
            raise HTTPException(status_code=422, detail=f"value(정규화 값)는 1~{MAX_VALUE_CHARS}자여야 합니다")
        source, run_key = _source(run_id)
        index = _index(source, run_key, table)
        summary = source["summary"] if isinstance(source["summary"], dict) else {}
        analysis_kinds = summary.get("analysis_kinds") if isinstance(summary.get("analysis_kinds"), dict) else {}
        return {
            "run_id": run_id,
            "table": table,
            "label": TABLE_LABELS[table],
            "source": source_info(source),
            **value_rows(index, text, analysis_kinds),
        }

    @router.get("/api/runs/{run_id}/derived/{table}/graph")
    def get_derived_value_graph(
        run_id: str,
        table: str,
        value: str = Query(default=""),
        max_nodes: int = Query(default=GRAPH_MAX_NODES),
    ) -> dict[str, object]:
        """연결 그래프 라이트 (plan r4 §2.3): ``value`` (normalised) -> its original rows (the stored
        samples, ≤20, by family) -> the other identifier values on those rows (every 통합 보기 table,
        read with the derived pass's own column rules; credentials masked). Bounded to ``max_nodes``
        nodes (10–200, default 200): value nodes ranked by rows shared with the centre, then table
        count. Response: ``{run_id, table, label, source, center, nodes: [{id, type: value|row,
        …}], edges: [{source, target}], rows, rows_read, values, dropped_values, truncated,
        max_nodes}``; a row node carries the grid address (``collection``, ``locator``, ``kind`` |
        ``scope`` | ``analysis_id``), a value node ``table``, ``normalized``, ``count`` and
        ``in_table``. ``value`` missing / too long or ``max_nodes`` out of range is a Korean 422; an
        unknown value is a 404."""
        require_table(table)
        text = value.strip()
        if not text or len(text) > MAX_VALUE_CHARS:
            raise HTTPException(status_code=422, detail=f"value(정규화 값)는 1~{MAX_VALUE_CHARS}자여야 합니다")
        if not GRAPH_MIN_NODES <= max_nodes <= GRAPH_MAX_NODES:
            raise HTTPException(
                status_code=422, detail=f"max_nodes는 {GRAPH_MIN_NODES}~{GRAPH_MAX_NODES} 사이여야 합니다"
            )
        source, run_key = _source(run_id)
        index = _index(source, run_key, table)
        summary = source["summary"] if isinstance(source["summary"], dict) else {}
        analysis_kinds = summary.get("analysis_kinds") if isinstance(summary.get("analysis_kinds"), dict) else {}
        position = index.position.get(text)
        if position is None:
            raise HTTPException(status_code=404, detail="이 통합 보기 표에 없는 값입니다 (정규화 값으로 요청하세요)")
        center = index.rows_at([position])[0]
        samples = [sample for sample in center.get("samples") or [] if isinstance(sample, dict)]
        output_dir = Path(run_key)

        def read_artifacts(kind: str, indices):
            name = f"artifacts_{kind}"
            return iter_records_at(store.read_output(run_id, name), get_output_path(store, run_id, name), indices)

        rows = read_sample_rows(
            samples,
            read_artifacts=read_artifacts,
            files_payload=lambda: get_named_output(store, run_id, "files"),
            output_dir=output_dir,
        )
        indexes = {}
        for other in TABLES:
            try:
                indexes[other] = index if other == table else _index(source, run_key, other)
            except HTTPException:
                indexes[other] = None  # missing / oversized table: its values show without a count
        graph = build_graph(
            table=table, center=center, rows=rows, indexes=indexes, analysis_kinds=analysis_kinds, max_nodes=max_nodes
        )
        return {"run_id": run_id, "table": table, "label": TABLE_LABELS[table], "source": source_info(source), **graph}

    return router
