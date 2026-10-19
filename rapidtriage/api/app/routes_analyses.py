"""Analysis workbench routes (plan P1 §3.1): submit, list, read, cancel, rows."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ...core.carving import SIGNATURE_KINDS
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
from .jsonl_records import iter_artifact_records, iter_record_range
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


# R3 §3.3 server filters on result-row ``details`` (``GET .../rows``): exact values, Korean 422.
ROW_SOURCES = ("mft", "usn", "timestamp-mismatch", "logfile-transaction", "volume-information")
RECOVERY_METHODS = ("carved", "parsed", "rejected")
DETAIL_FILTER_MAX_VALUES = 32
# Sorted pages with a details filter collect the matching record indices first.
DETAIL_FILTER_SCAN_CAP = 5_000_000
# Matching-record sets of sorted, details-filtered pages (per rows file / row count / filter):
# the next page of the same view does not rescan the rows.
ALLOWED_RECORDS_CACHE_SIZE = 8
ALLOWED_RECORDS_CACHE_MAX_INDICES = 500_000
_ALLOWED_RECORDS_CACHE: dict[tuple[object, ...], tuple[set[int], bool]] = {}
SOURCE_ROW_RANGES_KEY = "source_row_ranges"


def parse_detail_filters(
    source: list[str], signature_kind: list[str], recovery_method: list[str]
) -> dict[str, frozenset[str]]:
    """``{details key: allowed values}``; an unknown value is a 422 with a Korean message."""
    filters: dict[str, frozenset[str]] = {}
    for key, label, values, allowed in (
        ("source", "행 출처(source)", source, ROW_SOURCES),
        ("signature_kind", "서명 종류(signature_kind)", signature_kind, SIGNATURE_KINDS),
        ("recovery_method", "복구 방법(recovery_method)", recovery_method, RECOVERY_METHODS),
    ):
        wanted = [item.strip() for value in values for item in value.split(",") if item.strip()]
        if not wanted:
            continue
        if len(wanted) > DETAIL_FILTER_MAX_VALUES:
            raise HTTPException(status_code=422, detail=f"{label} 값은 한 번에 {DETAIL_FILTER_MAX_VALUES}개까지 지정할 수 있습니다")
        unknown = sorted(set(wanted) - set(allowed))
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"알 수 없는 {label} 값입니다: {', '.join(unknown[:5])} (가능: {', '.join(allowed)})",
            )
        filters[key] = frozenset(wanted)
    return filters


def parse_in_use_filter(value: str | None) -> bool | None:
    """``in_use=true|false`` (MFT record allocation state of ntfs-meta rows); a bad value is a Korean 422."""
    if value is None:
        return None
    text = value.strip().lower()
    if text in ("true", "false"):
        return text == "true"
    raise HTTPException(
        status_code=422,
        detail=f"in_use 값은 true 또는 false여야 합니다(받은 값: {value.strip()[:32]})",
    )


def detail_row_filter(
    filters: Mapping[str, frozenset[str]], in_use: bool | None = None
) -> Callable[[Mapping[str, object]], bool]:
    """Predicate over a ``<kind>-row`` record: every filtered ``details`` key holds one of its values.

    ``recovery_method`` of carve rows written before R3 (no such key) is
    ``carved``, or ``rejected`` for a ``false-positive-rejected`` row.
    ``in_use`` keeps rows whose ``details.in_use`` is exactly that boolean
    (rows without an allocation state never match). ``source`` of ntfs-meta
    rows written before R3 (no such key) is ``mft``.
    """

    def matches(row: Mapping[str, object]) -> bool:
        raw = row.get("details")
        details: Mapping[str, object] = raw if isinstance(raw, Mapping) else {}
        if in_use is not None and details.get("in_use") is not in_use:
            return False
        for key, values in filters.items():
            value = details.get(key)
            if key == "recovery_method" and value is None and row.get("artifact_type") == "carve-row":
                value = "rejected" if details.get("status") == "false-positive-rejected" else "carved"
            if key == "source" and value is None and row.get("artifact_type") == "ntfs-meta-row":
                value = "mft"
            if str(value or "") not in values:
                return False
        return True

    return matches


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
        source: list[str] = Query(default=[]),
        signature_kind: list[str] = Query(default=[]),
        recovery_method: list[str] = Query(default=[]),
        in_use: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Result rows paged like an artifacts kind page; every row has ``record_index``.

        R3 §3.3 details filters (repeatable or comma-separated, exact values;
        unknown values are a 422 in Korean): ``source`` (ntfs-meta row source:
        mft / usn / timestamp-mismatch / logfile-transaction), ``signature_kind``
        (carve) and ``recovery_method`` (carved / parsed / rejected). They compose
        with ``path_contains``, ``flag`` and ``sort`` (a sorted page collects the
        matching record indices first, at most ``DETAIL_FILTER_SCAN_CAP`` rows).
        ``in_use`` (``true`` / ``false``; anything else is a Korean 422) keeps
        rows of in-use / deleted MFT records (``details.in_use``): the console's
        타임스탬프 불일치 node defaults to ``in_use=true`` with a sibling node for
        deleted records. The pagination reports it in ``details_filter``.

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
        detail_filters = parse_detail_filters(source, signature_kind, recovery_method)
        filter_truncation: dict[str, bool] = {}
        in_use_filter = parse_in_use_filter(in_use)
        row_filter = (
            detail_row_filter(detail_filters, in_use_filter) if detail_filters or in_use_filter is not None else None
        )
        ranged = source_range_rows(state, payload, payload_path, detail_filters, record_count)
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
                        row_filter=row_filter,
                    )
                    mark_flag_page(page, flag_query, record_count=record_count, other_filters=bool(needle or row_filter))
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
                        allowed_records=_allowed_records(
                            join.require_index().matching(flag_kind, flag_query.rule_ids, flag_query.grade)
                            if flag_query.filtered
                            else None,
                            payload,
                            payload_path,
                            row_filter,
                            record_count,
                            ranged=ranged,
                            cache_key=(str(rows_path), record_count, repr(sorted(detail_filters.items())), in_use_filter),
                            truncation=filter_truncation,
                        ),
                    )
                    if flag_query.filtered:
                        mark_flag_page(page, flag_query)
                elif needle or row_filter is not None:
                    # source= pages read only the row ranges of those sources (recorded when the
                    # analysis wrote them): the $LogFile rows after 2 M MFT rows are reachable.
                    page = filter_artifact_page(
                        payload,
                        payload_path=payload_path,
                        path_contains=needle,
                        offset=offset,
                        limit=limit,
                        record_limit=record_count,
                        rows_source=ranged() if ranged is not None else None,
                        row_filter=row_filter,
                    )
                else:
                    page = paginate_artifact_output(payload, payload_path=payload_path, offset=offset, limit=limit)
            except StaleSortIndex as exc:
                raise HTTPException(status_code=409, detail=STALE_INDEX_MESSAGE) from exc
        if running_sort:
            unsupported = SortState("unsupported", 0.0, reason=RUNNING_SORT_REASON)
            page["sort"] = sort_descriptor(
                str(sort_key),
                sort_order or "asc",
                unsupported,
                locate,
                filtered=bool(needle) or row_filter is not None or flag_query.filtered,
            )
        annotate_page_counts(page, payload, filtered=bool(needle) or flag_query.filtered or row_filter is not None)
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
        if detail_filters or in_use_filter is not None:
            response["pagination"]["details_filter"] = {
                **{key: sorted(values) for key, values in detail_filters.items()},
                **({"in_use": in_use_filter} if in_use_filter is not None else {}),
                # A sorted page whose matching-record scan stopped at DETAIL_FILTER_SCAN_CAP.
                **({"truncated": True, "scan_cap": DETAIL_FILTER_SCAN_CAP} if filter_truncation.get("truncated") else {}),
            }
        return response

    return router


def source_range_rows(
    state: Mapping[str, object],
    payload: Mapping[str, object],
    payload_path,
    filters: Mapping[str, frozenset[str]],
    record_count: int,
) -> Callable[[], Iterator[tuple[int, dict[str, object]]]] | None:
    """Row source over the recorded ranges of the requested ``source=`` values (``None`` when the
    analysis summary has no ranges for every one of them: older analyses scan all rows)."""
    sources = filters.get("source")
    summary = state.get("summary") if isinstance(state.get("summary"), Mapping) else {}
    ranges = summary.get(SOURCE_ROW_RANGES_KEY) if isinstance(summary, Mapping) else None
    if not sources or not isinstance(ranges, Mapping):
        return None
    spans: list[tuple[int, int, int]] = []
    for source in sources:
        item = ranges.get(source)
        if not isinstance(item, Mapping):
            return None
        try:
            start, end, start_byte = int(item["start"]), int(item["end"]), int(item["start_byte"])
        except (KeyError, TypeError, ValueError):
            return None
        if end > start:
            spans.append((start, min(end, record_count), start_byte))
    merged: list[tuple[int, int, int]] = []
    for start, end, start_byte in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            previous = merged[-1]
            merged[-1] = (previous[0], max(previous[1], end), previous[2])
        else:
            merged.append((start, end, start_byte))

    def rows() -> Iterator[tuple[int, dict[str, object]]]:
        for start, end, start_byte in merged:
            yield from iter_record_range(payload, payload_path=payload_path, start=start, end=end, start_byte=start_byte)

    return rows


def _allowed_records(
    flagged: list[int] | None,
    payload: Mapping[str, object],
    payload_path,
    row_filter: Callable[[Mapping[str, object]], bool] | None,
    record_count: int,
    *,
    ranged: Callable[[], Iterator[tuple[int, dict[str, object]]]] | None = None,
    cache_key: tuple[object, ...] | None = None,
    truncation: dict[str, bool] | None = None,
) -> list[int] | set[int] | None:
    """Record indices a sorted page may show: the 특이사항 set and/or the details-filter matches.

    The scan reads only the ``source=`` row ranges when known, stops at ``DETAIL_FILTER_SCAN_CAP``
    (``truncation["truncated"]``) and is cached per rows file, row count and filter.
    """
    if row_filter is None:
        return flagged
    cached = _ALLOWED_RECORDS_CACHE.get(cache_key) if cache_key is not None else None
    if cached is None:
        matching: set[int] = set()
        truncated = False
        rows = ranged() if ranged is not None else iter_artifact_records(payload, payload_path=payload_path, limit=record_count)
        for scanned, (record_index, row) in enumerate(rows):
            if scanned >= DETAIL_FILTER_SCAN_CAP:
                truncated = True
                break
            if row_filter(row):
                matching.add(record_index)
        cached = (matching, truncated)
        if cache_key is not None and len(matching) <= ALLOWED_RECORDS_CACHE_MAX_INDICES:
            if len(_ALLOWED_RECORDS_CACHE) >= ALLOWED_RECORDS_CACHE_SIZE:
                _ALLOWED_RECORDS_CACHE.pop(next(iter(_ALLOWED_RECORDS_CACHE)))
            _ALLOWED_RECORDS_CACHE[cache_key] = cached
    matching, truncated = cached
    if truncation is not None and truncated:
        truncation["truncated"] = True
    return matching if flagged is None else matching.intersection(flagged)
