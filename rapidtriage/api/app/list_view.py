"""``view=list``: the lean listing pages the console grid reads (``/artifacts``, ``/files``, ``/timeline``).

A default listing page carries every row's whole ``details`` and the output's page-level
blocks: on a case with about a million artifacts one ``GET /artifacts?limit=100`` was many MB, mostly
per-row parser profiles / manifests / validation plans (``mft_full_parser_profile``,
``ntfs_report_citation_manifest``, ``commercial_uplift_evidence`` …) and ``GET /files``
megabytes of duplicate-group blocks no grid column shows. ``view=list`` (opt in; the default
response is unchanged for every other consumer) keeps what the console reads from a list:

* Rows (artifacts only; files and timeline rows are never cut): ``details`` keeps every
  listable value -- a scalar, a list of scalars, or a list of flat records (Prefetch
  ``volumes``, attachment lists: grid columns, promoted ``details.<key>`` columns, the quick
  filter and row conditions read only those) -- and of the other nested values only
  :data:`DETAILS_NESTED_KEPT`, reduced to their listable members. Every value left out is
  named in the row's ``details_omitted`` (sorted; ``key`` for a whole value, ``key.member``
  for a member of a kept container; absent when nothing was left out). The viewer loads the
  full row (plain ``kind=&offset=<record_index>&limit=1``) for a row that has
  ``details_omitted``, and says so until it has it.
* Page: flat values, the row list and the control blocks of :data:`PAGE_BLOCKS_KEPT`
  (``pagination`` without its report-grade manifests); every page key or ``pagination``
  member left out is named in ``view_omitted`` (``pagination.<name>`` for the latter). Pages
  report ``view: "list"``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from fastapi import HTTPException

LIST_VIEW = "list"
VIEW_MESSAGE = "view는 list만 쓸 수 있습니다"

# Nested details values the console reads from LIST rows (frontend/src): ``raw`` (chat view
# sender/text), ``exif_gps_profile`` (geo view), ``source_hashes`` (grid SHA-256), ``recovery``
# (grid recovery columns), ``coverage`` (부분 결과 condition), the EVTX EventData containers
# (family columns ``event_data.<name>``, derived columns) and ``commercial_uplift_evidence``
# ``source_refs`` (chat view service). ``None`` = every listable member, else only those members.
DETAILS_NESTED_KEPT: Mapping[str, frozenset[str] | None] = {
    "raw": None,
    "exif_gps_profile": None,
    "source_hashes": None,
    "recovery": None,
    "coverage": None,
    "event_data": None,
    "data": None,
    "user_data": None,
    "binxml_event_data_values_by_name": None,
    "event_data_values_by_name": None,
    "commercial_uplift_evidence": frozenset({"source_refs"}),
}

# Page-level blocks a listing client reads (paging, filters, joins, sort state, live runs).
PAGE_BLOCKS_KEPT = frozenset(
    {
        "pagination",
        "cross_kind",
        "sort",
        "live",
        "ntfs_join",
        "flags_join",
        "path_filter",
        "flags",
        "conditions",
        "fields",
        "applied_filters",
    }
)
# Report-grade manifests of ``pagination`` (~30 KB per page; no listing client reads them).
PAGINATION_MANIFESTS = (
    "pagination_manifest",
    "cursor_endpoint_coverage_manifest",
    "pagination_cursor_report_grade_validation_plan",
    "functional_priority_profile",
)

_SCALARS = (str, int, float, bool, type(None))


def parse_view(view: str | None) -> bool:
    """``True`` for ``view=list``, ``False`` when absent; any other value is a Korean 422."""
    if view is None or not view.strip():
        return False
    if view.strip() != LIST_VIEW:
        raise HTTPException(status_code=422, detail=VIEW_MESSAGE)
    return True


def _flat(value: object) -> bool:
    """A scalar or a list of scalars."""
    return isinstance(value, _SCALARS) or (isinstance(value, list) and all(isinstance(item, _SCALARS) for item in value))


def _listable(value: object) -> bool:
    """A flat value or a list of scalars and flat records (one level: ``[{"device": …, "serial": …}]``)."""
    if _flat(value):
        return True
    return isinstance(value, list) and all(
        isinstance(item, _SCALARS) or (isinstance(item, Mapping) and all(_flat(member) for member in item.values()))
        for item in value
    )


def project_details(details: Mapping[str, object]) -> tuple[dict[str, object], list[str]]:
    """``(list details, omitted keys)`` of one row's ``details`` (a new dict; the input is untouched)."""
    kept: dict[str, object] = {}
    omitted: list[str] = []
    for key, value in details.items():
        if _listable(value):
            kept[key] = value
            continue
        if not isinstance(value, Mapping) or key not in DETAILS_NESTED_KEPT:
            omitted.append(key)
            continue
        members = DETAILS_NESTED_KEPT[key]
        container: dict[str, object] = {}
        for name, item in value.items():
            if (members is None or name in members) and _listable(item):
                container[name] = item
            else:
                omitted.append(f"{key}.{name}")
        kept[key] = container
    return kept, sorted(omitted)


def project_artifact_row(row: object) -> object:
    """An artifact row with its list ``details`` (+ ``details_omitted``); other rows as they are."""
    if not isinstance(row, Mapping) or not isinstance(row.get("details"), Mapping):
        return row
    details, omitted = project_details(row["details"])
    projected = {**row, "details": details}
    if omitted:
        projected["details_omitted"] = omitted
    return projected


def project_page(
    page: Mapping[str, object], rows_key: str, project_row: Callable[[object], object] | None = None
) -> dict[str, object]:
    """The list view of one listing page (rows under ``rows_key``)."""
    projected: dict[str, object] = {}
    omitted: list[str] = []
    for key, value in page.items():
        if key == rows_key:
            projected[key] = [project_row(row) for row in value] if project_row is not None and isinstance(value, list) else value
        elif key == "pagination" and isinstance(value, Mapping):
            projected[key] = {name: item for name, item in value.items() if name not in PAGINATION_MANIFESTS}
            omitted.extend(f"pagination.{name}" for name in value if name in PAGINATION_MANIFESTS)
        elif _flat(value) or key in PAGE_BLOCKS_KEPT:
            projected[key] = value
        else:
            omitted.append(key)
    projected["view"] = LIST_VIEW
    if omitted:
        projected["view_omitted"] = sorted(omitted)
    return projected
