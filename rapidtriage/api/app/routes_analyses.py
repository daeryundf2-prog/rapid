"""Analysis workbench routes (plan P1 §3.1): submit, list, read, cancel, rows."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ...core.jobs import RunJobStore
from .analyses import (
    ACTIVE_STATUSES,
    ANALYSIS_RUNNER,
    ROWS_FILE_NAME,
    STATE_FILE_NAME,
    analysis_directory,
    analysis_payload,
    public_state,
    run_scope,
    with_josa,
)
from .analysis_kinds import korean_ocr_row_details
from .artifact_filter import annotate_page_counts, filter_artifact_page
from .artifact_sort import (
    SORT_ORDERS,
    STALE_INDEX_MESSAGE,
    SortState,
    StaleSortIndex,
    paginate_sorted_artifact_output,
    sort_descriptor,
)
from .pagination import paginate_artifact_output
from .triage_flags import (
    flag_rows_source,
    flags_join,
    is_flags_sort,
    mark_flag_page,
    parse_flag_query,
)

# A running analysis's rows grow on every flush: a whole-kind sort index would
# be stale before it is ready (and each row count would be another cache entry).
RUNNING_SORT_REASON = "실행 중인 분석은 전체 정렬을 할 수 없습니다. 분석이 끝난 뒤 다시 정렬하세요."
ORDER_ERROR_MESSAGE = "정렬 순서(order)는 asc 또는 desc여야 합니다"

PAGINATION_KEYS = (
    "collection",
    "offset",
    "limit",
    "returned",
    "total",
    "next_offset",
    "previous_offset",
    "has_more",
    "matched",
    "filtered",
    "path_contains",
    "artifact_types",
    "scanned",
    "truncated",
)


class AnalysisCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(..., min_length=1, max_length=64)
    options: dict[str, Any] = Field(default_factory=dict)


def korean_body_errors(
    errors: list[dict[str, Any]], extra_labels: Mapping[str, str] | None = None
) -> list[dict[str, object]]:
    """Request-body validation errors of ``POST /analyses`` -> ``[{loc, msg, type}]`` in Korean.

    ``extra_labels`` adds Korean field names for other routes (case intake).
    """
    messages = {
        "json_invalid": "요청 본문이 올바른 JSON이 아닙니다",
        "model_attributes_type": "요청 본문은 JSON 객체여야 합니다",
        "dict_type": "요청 본문은 JSON 객체여야 합니다",
        "missing": "{field} 값이 필요합니다",
        "extra_forbidden": "알 수 없는 필드입니다: {field}",
        "string_type": "{topic} 문자열이어야 합니다",
        "string_too_short": "{subject} 비어 있습니다",
        "string_too_long": "{subject} 너무 깁니다",
        "literal_error": "{field} 값이 허용된 값이 아닙니다",
        "int_parsing": "{topic} 정수여야 합니다",
        "int_type": "{topic} 정수여야 합니다",
        "bool_parsing": "{topic} true 또는 false여야 합니다",
        "bool_type": "{topic} true 또는 false여야 합니다",
        "list_type": "{topic} 목록(배열)이어야 합니다",
        "too_short": "{subject} 비어 있습니다",
    }
    labels = {"kind": "분석 종류(kind)", "options": "옵션(options)", **dict(extra_labels or {})}
    result: list[dict[str, object]] = []
    for error in errors:
        loc = [str(part) for part in error.get("loc", ())]
        field = loc[-1] if len(loc) > 1 else "본문"
        error_type = str(error.get("type") or "")
        template = messages.get(error_type, "{field} 값이 올바르지 않습니다")
        if field == "options" and error_type == "dict_type":
            template = "{topic} 객체여야 합니다"
        name = labels.get(field, field)
        if field.isdigit() and len(loc) > 2:
            # A list item (``tag_ids: ["x"]`` -> loc ``body, tag_ids, 0``): name the list and the position.
            name = f"{labels.get(loc[-2], loc[-2])}의 {int(field) + 1}번째 항목"
        message = template.format(field=name, topic=with_josa(name, "은", "는"), subject=with_josa(name, "이", "가"))
        result.append({"loc": loc, "msg": message, "type": error_type})
    return result


def parse_sort_request(sort: str | None, order: str | None) -> tuple[str | None, str | None]:
    """``sort``/``order`` query -> (key, order) like ``GET /artifacts``.

    Unlike ``GET /artifacts``, an invalid ``order`` is a 400 even without
    ``sort`` (plan §3.1: the console never sends a meaningless order).
    """
    sort_key = sort.strip() if sort and sort.strip() else None
    sort_order = (order or "").strip().lower() or None
    if sort_order is not None and sort_order not in SORT_ORDERS:
        raise HTTPException(status_code=400, detail=ORDER_ERROR_MESSAGE)
    if not sort_key:
        return None, None
    head, _, suffix = sort_key.rpartition(":")
    if head and suffix.lower() in SORT_ORDERS:
        sort_key = head
        sort_order = sort_order or suffix.lower()
    sort_order = sort_order or "asc"
    if sort_order not in SORT_ORDERS:
        raise HTTPException(status_code=400, detail=ORDER_ERROR_MESSAGE)
    return sort_key, sort_order


def build_analyses_router(store: RunJobStore, *, owner: object | None = None) -> APIRouter:
    """``owner`` tags submitted analyses so only that app's shutdown cancels them."""
    router = APIRouter()

    @router.post("/api/runs/{run_id}/analyses", status_code=202)
    def create_analysis(run_id: str, request: AnalysisCreateRequest) -> dict[str, object]:
        """Queue one analysis over a completed/failed run (409 while the same kind runs)."""
        scope = run_scope(store, run_id)
        state = ANALYSIS_RUNNER.submit(scope, request.kind.strip(), request.options, owner=owner)
        return {
            "analysis_id": state["analysis_id"],
            "kind": state["kind"],
            "status": state["status"],
            "analysis": public_state(state),
        }

    @router.get("/api/runs/{run_id}/analyses")
    def list_analyses(run_id: str) -> dict[str, object]:
        """Every analysis of the run, newest first."""
        scope = run_scope(store, run_id, require_ready=False)
        return {"analyses": [public_state(state) for state in ANALYSIS_RUNNER.list_states(scope.output_dir)]}

    @router.get("/api/runs/{run_id}/analyses/{analysis_id}")
    def get_analysis(run_id: str, analysis_id: str) -> dict[str, object]:
        scope = run_scope(store, run_id, require_ready=False)
        return analysis_payload(scope.output_dir, analysis_id)

    @router.post("/api/runs/{run_id}/analyses/{analysis_id}/cancel")
    def cancel_analysis(run_id: str, analysis_id: str) -> dict[str, object]:
        """Request cancellation; the runner stops at its next unit boundary."""
        scope = run_scope(store, run_id, require_ready=False)
        directory = analysis_directory(scope.output_dir, analysis_id)
        state = ANALYSIS_RUNNER.cancel(scope.output_dir, directory.name)
        if state is None:
            raise HTTPException(status_code=404, detail="분석을 찾을 수 없습니다")
        return public_state(state)

    @router.get("/api/runs/{run_id}/analyses/{analysis_id}/rows")
    def get_analysis_rows(
        run_id: str,
        analysis_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=1000),
        sort: str | None = Query(default=None),
        order: str | None = Query(default=None),
        locate: int | None = Query(default=None, ge=0),
        path_contains: str | None = Query(default=None),
        flag: list[str] = Query(default=[]),
        flag_grade: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Result rows paged like an artifacts kind page; every row has ``record_index``.

        특이사항: rows carry ``flags`` (kind ``analysis:<analysis_id>``) and the
        response reports ``flags_join``; ``flag``/``flag_grade`` filter and
        ``sort=flags`` orders A, B, C, unflagged, as on ``GET /artifacts``.

        ``sort`` (``timestamp`` | ``details.<name>``, optional ``:asc``/``:desc``)
        uses the whole-kind ``artifact_sort`` index over ``rows.jsonl`` of a
        finished analysis (cache key: run id + ``analysis:<id>#<row_count>`` +
        file size/mtime); ``locate`` adds ``sort.position``. While the analysis
        is queued/running the page keeps JSONL order and ``sort.status`` is
        ``unsupported`` with ``RUNNING_SORT_REASON`` (no index is built). Every
        reader (pages, ``path_contains``, the sort index) stops at the flushed
        ``row_count``: lines a running analysis is still writing are never served.
        """
        scope = run_scope(store, run_id, require_ready=False)
        state = analysis_payload(scope.output_dir, analysis_id)
        directory = analysis_directory(scope.output_dir, analysis_id)
        rows_path = directory / ROWS_FILE_NAME
        record_count = int(state.get("row_count") or 0)
        payload: dict[str, object] = {"records_path": str(rows_path), "record_count": record_count, "artifacts": []}
        payload_path = directory / STATE_FILE_NAME
        needle = path_contains.strip() if path_contains and path_contains.strip() else None
        flag_sort = is_flags_sort(sort)
        flag_query = parse_flag_query(flag, flag_grade, sort_flags=flag_sort)
        sort_key, sort_order = parse_sort_request(None if flag_sort else sort, order)
        running_sort = bool(sort_key) and state.get("status") in ACTIVE_STATUSES
        flag_kind = f"analysis:{directory.name}"
        join = flags_join(scope.output_dir)
        if not rows_path.is_file():
            page: dict[str, object] = {"artifacts": [], "pagination": {"offset": offset, "limit": limit, "returned": 0, "total": 0}}
        else:
            try:
                if flag_query.active and not (sort_key and not running_sort):
                    page = filter_artifact_page(
                        payload,
                        payload_path=payload_path,
                        path_contains=needle,
                        offset=offset,
                        limit=limit,
                        record_limit=record_count,
                        rows_source=flag_rows_source(
                            payload, payload_path, kind=flag_kind, join=join, query=flag_query, record_limit=record_count
                        ),
                    )
                    mark_flag_page(page, flag_query, record_count=record_count, other_filters=bool(needle))
                elif sort_key and not running_sort:
                    page = paginate_sorted_artifact_output(
                        payload,
                        run_id=run_id,
                        kind=f"analysis:{directory.name}",
                        payload_path=payload_path,
                        sort=sort_key,
                        order=sort_order or "asc",
                        offset=offset,
                        limit=limit,
                        cursor=None,
                        path_contains=needle,
                        locate=locate,
                        record_limit=record_count,
                        allowed_records=(
                            join.require_index().matching(flag_kind, flag_query.rule_ids, flag_query.grade)
                            if flag_query.filtered
                            else None
                        ),
                    )
                    if flag_query.filtered:
                        mark_flag_page(page, flag_query)
                elif needle:
                    page = filter_artifact_page(
                        payload,
                        payload_path=payload_path,
                        path_contains=needle,
                        offset=offset,
                        limit=limit,
                        record_limit=record_count,
                    )
                else:
                    page = paginate_artifact_output(payload, payload_path=payload_path, offset=offset, limit=limit)
            except StaleSortIndex as exc:
                raise HTTPException(status_code=409, detail=STALE_INDEX_MESSAGE) from exc
        if running_sort:
            unsupported = SortState("unsupported", 0.0, reason=RUNNING_SORT_REASON)
            page["sort"] = sort_descriptor(str(sort_key), sort_order or "asc", unsupported, locate, filtered=bool(needle))
        annotate_page_counts(page, payload, filtered=bool(needle) or flag_query.filtered)
        pagination = page.get("pagination") if isinstance(page.get("pagination"), dict) else {}
        rows = page.get("artifacts") or []
        if state.get("kind") == "ocr-batch":
            # Rows stored before row errors were Korean: Korean ``error``, original text in ``error_detail``.
            rows = [
                {**row, "details": korean_ocr_row_details(row["details"])}
                if isinstance(row, dict) and isinstance(row.get("details"), dict)
                else row
                for row in rows
            ]
        response: dict[str, object] = {
            "run_id": run_id,
            "analysis_id": state.get("analysis_id"),
            "kind": state.get("kind"),
            "status": state.get("status"),
            "rows": join.attach(rows, flag_kind),
            "flags_join": dict(join.info),
            "record_count": page.get("record_count"),
            "matched": page.get("matched"),
            "pagination": {key: pagination[key] for key in PAGINATION_KEYS if key in pagination},
        }
        if sort_key or flag_sort:
            response["sort"] = page.get("sort")
        if flag_query.filtered:
            response["pagination"]["flags"] = flag_query.descriptor()
        return response

    return router
