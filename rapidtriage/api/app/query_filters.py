"""Strict query parameters of the run list endpoints (D26 practitioner review #5).

FastAPI drops query parameters a route does not declare, so ``GET /artifacts?event_idx=1102``
answered 200 with the unfiltered rows as if they had been filtered. :func:`strict_query_filters`
(a route dependency) answers such a request with a Korean 422 that lists the supported
parameters, and returns the filters the route applies; the route echoes them as
``applied_filters``.
"""

from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.dependencies.models import Dependant

#: Paging / ordering / page-shape parameters: accepted where declared, never echoed as filters.
PAGING_PARAMETERS = frozenset({"offset", "limit", "cursor", "after", "locate", "sort", "order", "view"})


def _query_names(dependant: Dependant) -> list[str]:
    names = [str(field.alias) for field in dependant.query_params]
    for sub in dependant.dependencies:
        names.extend(_query_names(sub))
    return names


def _supported_names(route: object) -> tuple[str, ...]:
    """Declared query parameter names (aliases) of ``route``'s endpoint and its dependencies."""
    dependant = getattr(route, "dependant", None)
    return tuple(dict.fromkeys(_query_names(dependant))) if isinstance(dependant, Dependant) else ()


def strict_query_filters(request: Request) -> dict[str, list[str]]:
    """Reject undeclared query parameters (Korean 422); return ``{name: [values]}`` of the filters.

    Paging/ordering parameters and blank values are left out of the returned filters.
    """
    route = request.scope.get("route")
    if route is None:
        return {}
    supported = _supported_names(route)
    present = list(dict.fromkeys(request.query_params.keys()))
    unknown = [name for name in present if name not in supported]
    if unknown:
        filters = [name for name in supported if name not in PAGING_PARAMETERS]
        paging = [name for name in supported if name in PAGING_PARAMETERS]
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    f"지원하지 않는 조회 조건입니다: {', '.join(unknown)}. "
                    f"이 목록에서 쓸 수 있는 조건: {', '.join(filters) or '없음'}"
                    + (f" (페이지·정렬: {', '.join(paging)})" if paging else "")
                ),
                "unsupported_filters": unknown,
                "supported_filters": filters,
                "paging_parameters": paging,
            },
        )
    applied: dict[str, list[str]] = {}
    for name in present:
        if name in PAGING_PARAMETERS:
            continue
        values = [value.strip() for value in request.query_params.getlist(name) if value.strip()]
        if values:
            applied[name] = values
    return applied


def with_applied_filters(page: dict[str, object], applied: dict[str, list[str]]) -> dict[str, object]:
    """``page`` plus ``applied_filters`` (a shallow copy: ``page`` may be a cached output payload)."""
    return {**page, "applied_filters": applied}
