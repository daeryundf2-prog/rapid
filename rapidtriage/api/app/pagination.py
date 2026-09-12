from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from fastapi import HTTPException

from .constants import (
    PAGINATION_CURSOR_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    PAGINATION_TRUSTED_DIFF_BLOCKER_78,
    PAGINATION_TRUSTED_TOOLS,
    VIEWER_WORKFLOW_GAP_IDS,
)
from .viewer_core import (
    build_cursor_api_coverage_manifest,
    cursor_api_functional_profile,
    missing_pagination_trusted_diff,
    pagination_core_accuracy_gates,
    ui_virtualization_core_accuracy_gates,
    ui_virtualization_metadata,
)


def paginate_payload(
    payload: dict[str, object],
    collection_name: str,
    *,
    offset: int,
    limit: int,
    cursor: str | None = None,
    omit_fields: tuple[str, ...] = (),
) -> dict[str, object]:
    if limit <= 0:
        return payload
    if cursor:
        offset = decode_pagination_cursor(cursor)
    rows = payload.get(collection_name)
    if not isinstance(rows, list):
        rows = []
    total = len(rows)
    end = min(offset + limit, total)
    returned = max(0, end - offset)
    has_more = end < total
    cursor_value = encode_pagination_cursor(offset)
    next_cursor = encode_pagination_cursor(end) if has_more else None
    previous_cursor = encode_pagination_cursor(max(0, offset - limit)) if offset > 0 else None
    pagination_manifest = build_pagination_cursor_manifest(
        collection_name=collection_name,
        offset=offset,
        limit=limit,
        returned=returned,
        total=total,
        cursor=cursor_value,
        next_cursor=next_cursor,
        previous_cursor=previous_cursor,
        has_more=has_more,
    )
    cursor_coverage_manifest = build_cursor_api_coverage_manifest(
        collection_name=collection_name,
        total=total,
        returned=returned,
        has_more=has_more,
        pagination_manifest=pagination_manifest,
    )
    pagination_validation_plan = build_pagination_cursor_report_grade_validation_plan(
        collection_name=collection_name,
        total=total,
        returned=returned,
        has_more=has_more,
        pagination_manifest=pagination_manifest,
        coverage_manifest=cursor_coverage_manifest,
    )
    page = dict(payload)
    for field in omit_fields:
        if field in page:
            page[field] = [] if isinstance(page[field], list) else None
    if omit_fields:
        page["omitted_fields"] = list(omit_fields)
    page[collection_name] = rows[offset:end]
    page["pagination"] = {
        "collection": collection_name,
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "total": total,
        "next_offset": end if end < total else None,
        "previous_offset": max(0, offset - limit) if offset > 0 else None,
        "cursor": cursor_value,
        "next_cursor": next_cursor,
        "previous_cursor": previous_cursor,
        "has_more": has_more,
        "page_window_id": pagination_manifest["page_window_id"],
        "pagination_manifest": pagination_manifest,
        "cursor_endpoint_coverage_manifest": cursor_coverage_manifest,
        "pagination_cursor_report_grade_validation_plan": pagination_validation_plan,
        "pagination_cursor_report_grade_validation_plan_hash": pagination_validation_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": pagination_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": pagination_validation_plan["blocking_slot_count"],
        "snapshot_policy": pagination_manifest["snapshot_policy"],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "functional_priority_profile": cursor_api_functional_profile(
            collection_name,
            total=total,
            returned=returned,
            has_more=has_more,
            coverage_manifest=cursor_coverage_manifest,
        ),
        "pagination_assessment": pagination_assessment(
            collection_name,
            offset=offset,
            limit=limit,
            total=total,
            returned=returned,
            has_more=has_more,
            pagination_manifest=pagination_manifest,
            coverage_manifest=cursor_coverage_manifest,
            validation_plan=pagination_validation_plan,
        ),
        "core_accuracy_gates": [
            *pagination_core_accuracy_gates(
                collection_name,
                total=total,
                returned=returned,
                has_more=has_more,
                pagination_manifest=pagination_manifest,
                validation_plan=pagination_validation_plan,
            ),
            *ui_virtualization_core_accuracy_gates(
                label=collection_name,
                total=total,
                visible=returned,
                api_pagination=True,
            ),
        ],
        "ui_virtualization": ui_virtualization_metadata(
            label=collection_name,
            total=total,
            visible=returned,
            api_pagination=True,
        ),
    }
    return page


def build_pagination_cursor_manifest(
    *,
    collection_name: str,
    offset: int,
    limit: int,
    returned: int,
    total: int,
    cursor: str,
    next_cursor: str | None,
    previous_cursor: str | None,
    has_more: bool,
) -> dict[str, object]:
    page_window_core = {
        "collection": collection_name,
        "offset": max(0, int(offset)),
        "limit": max(0, int(limit)),
        "returned": max(0, int(returned)),
        "total": max(0, int(total)),
        "cursor": cursor,
        "next_cursor": next_cursor,
        "previous_cursor": previous_cursor,
        "has_more": bool(has_more),
    }
    page_window_id = hashlib.sha256(json.dumps(page_window_core, sort_keys=True).encode("utf-8")).hexdigest()
    endpoint_id = hashlib.sha256(f"pagination:{collection_name}".encode()).hexdigest()
    manifest_core = {
        "profile": "pagination-cursor-manifest-v1",
        "profile_version": "pagination-cursor-manifest-v1",
        "item_number": 78,
        "endpoint_id": endpoint_id,
        "page_window_id": page_window_id,
        **page_window_core,
        "cursor_token_hashes": {
            "cursor": hashlib.sha256(str(cursor).encode("utf-8")).hexdigest() if cursor else "",
            "next_cursor": hashlib.sha256(str(next_cursor).encode("utf-8")).hexdigest() if next_cursor else "",
            "previous_cursor": hashlib.sha256(str(previous_cursor).encode("utf-8")).hexdigest()
            if previous_cursor
            else "",
        },
        "cursor_encoding": "offset-compatible-v1",
        "bounded_window": True,
        "limit_enforced": True,
        "snapshot_policy": {
            "snapshot_isolated": False,
            "warning": "offset-compatible cursors are not database snapshot cursors; rerun/import large cases into Case DB for stable review snapshots",
        },
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def build_pagination_cursor_report_grade_validation_plan(
    *,
    collection_name: str,
    total: int,
    returned: int,
    has_more: bool,
    pagination_manifest: Mapping[str, object],
    coverage_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    coverage = dict(coverage_manifest) if isinstance(coverage_manifest, Mapping) else {}
    manifest_hash = str(pagination_manifest.get("manifest_hash") or "")
    page_window_id = str(pagination_manifest.get("page_window_id") or "")
    cursor_hashes = pagination_manifest.get("cursor_token_hashes")
    cursor_hashes = dict(cursor_hashes) if isinstance(cursor_hashes, Mapping) else {}
    coverage_hash = str(coverage.get("manifest_hash") or "")
    trusted_status = str(trusted_diff.get("status")) if isinstance(trusted_diff, Mapping) else "missing"
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "cursor-page-window-manifest",
            "status": "ready",
            "evidence_ref": "pagination_manifest.manifest_hash",
            "evidence_hash": manifest_hash,
            "description": "Every API page emits a stable pagination-cursor-manifest for replayable page-window comparison.",
        },
        {
            "slot_id": "page-window-id",
            "status": "ready",
            "evidence_ref": "pagination_manifest.page_window_id",
            "evidence_hash": hashlib.sha256(page_window_id.encode("utf-8")).hexdigest() if page_window_id else "",
            "description": "Offset, limit, returned, total, and cursor boundary fields are collapsed into a deterministic page-window ID.",
        },
        {
            "slot_id": "cursor-token-hashes",
            "status": "ready",
            "evidence_ref": "pagination_manifest.cursor_token_hashes",
            "evidence_hash": hashlib.sha256(json.dumps(cursor_hashes, sort_keys=True).encode("utf-8")).hexdigest(),
            "description": "Cursor, next cursor, and previous cursor tokens are hash-recorded without exposing opaque tokens as evidence values.",
        },
        {
            "slot_id": "bounded-row-window",
            "status": "ready",
            "evidence_ref": "pagination.returned/limit/total",
            "evidence_hash": hashlib.sha256(
                json.dumps(
                    {
                        "collection": collection_name,
                        "total": int(total),
                        "returned": int(returned),
                        "has_more": bool(has_more),
                    },
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "description": "Returned rows are bounded and the last-page has_more contract is explicit.",
        },
        {
            "slot_id": "endpoint-coverage-manifest",
            "status": "ready",
            "evidence_ref": "cursor_endpoint_coverage_manifest.manifest_hash",
            "evidence_hash": coverage_hash,
            "description": "API pagination coverage is recorded with covered and missing endpoint-family inventories.",
        },
        {
            "slot_id": "snapshot-limitation-disclosure",
            "status": "ready",
            "evidence_ref": "pagination_manifest.snapshot_policy",
            "evidence_hash": hashlib.sha256(
                json.dumps(pagination_manifest.get("snapshot_policy") or {}, sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "description": "Offset-compatible cursors disclose that they are not snapshot-isolated database cursors.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "snapshot-isolated-database-cursors",
            "status": "blocked",
            "blocker": "snapshot-isolated-database-cursors-required",
            "required_evidence": "Case DB snapshot/revision-bound cursor tokens that remain stable while source rows mutate.",
        },
        {
            "slot_id": "trusted-pagination-manifest-diff",
            "status": "blocked" if trusted_status != "pass" else "ready",
            "blocker": None if trusted_status == "pass" else PAGINATION_TRUSTED_DIFF_BLOCKER_78,
            "required_evidence": "Trusted pagination cursor manifest or known-answer page-window export diff.",
        },
        {
            "slot_id": "endpoint-wide-compatibility",
            "status": "blocked",
            "blocker": "endpoint-wide-pagination-compatibility-required",
            "required_evidence": "Compatibility matrix covering files, docs, timeline, indicators, artifacts, search, review, and report endpoints.",
        },
        {
            "slot_id": "cursor-invalidation-replay",
            "status": "blocked",
            "blocker": "cursor-invalidation-replay-validation-required",
            "required_evidence": "Replay fixture proving stale cursor rejection or deterministic behavior after underlying row changes.",
        },
        {
            "slot_id": "large-case-page-latency",
            "status": "blocked",
            "blocker": "large-case-page-latency-validation-required",
            "required_evidence": "1M/10M-row page latency, memory, and p95 navigation evidence for each endpoint family.",
        },
        {
            "slot_id": "cross-client-cursor-compatibility",
            "status": "blocked",
            "blocker": "cross-client-cursor-compatibility-required",
            "required_evidence": "CLI, API, and browser E2E cursor compatibility proof using the same page-window manifests.",
        },
    ]
    blockers = [
        str(slot["blocker"])
        for slot in blocking_slots
        if slot.get("status") == "blocked" and slot.get("blocker")
    ]
    plan_core = {
        "profile_version": PAGINATION_CURSOR_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 78,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["pagination"],
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "collection": collection_name,
        "total": int(total),
        "returned": int(returned),
        "has_more": bool(has_more),
        "pagination_manifest_hash": manifest_hash,
        "page_window_id": page_window_id,
        "cursor_endpoint_coverage_manifest_hash": coverage_hash,
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": blockers,
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as internal cursor-page evidence only until snapshot cursors, trusted diffs, endpoint-wide compatibility, and large-case latency evidence are attached.",
    }
    validation_plan_sha256 = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_sha256": validation_plan_sha256,
        "validation_plan_hash": validation_plan_sha256,
    }


def pagination_assessment(
    collection_name: str,
    *,
    offset: int = 0,
    limit: int = 0,
    total: int,
    returned: int,
    has_more: bool | None = None,
    pagination_manifest: Mapping[str, object] | None = None,
    coverage_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    actual_has_more = bool(has_more) if has_more is not None else (offset + returned) < total
    manifest = dict(pagination_manifest) if pagination_manifest else build_pagination_cursor_manifest(
        collection_name=collection_name,
        offset=offset,
        limit=limit,
        returned=returned,
        total=total,
        cursor=encode_pagination_cursor(offset),
        next_cursor=encode_pagination_cursor(offset + returned) if (offset + returned) < total else None,
        previous_cursor=encode_pagination_cursor(max(0, offset - limit)) if offset > 0 and limit > 0 else None,
        has_more=actual_has_more,
    )
    report_plan = dict(validation_plan) if isinstance(validation_plan, Mapping) else build_pagination_cursor_report_grade_validation_plan(
        collection_name=collection_name,
        total=total,
        returned=returned,
        has_more=actual_has_more,
        pagination_manifest=manifest,
        coverage_manifest=coverage_manifest,
        trusted_diff=trusted_diff,
    )
    core_gates = pagination_core_accuracy_gates(
        collection_name,
        total=total,
        returned=returned,
        has_more=actual_has_more,
        pagination_manifest=manifest,
        validation_plan=report_plan,
        trusted_diff=trusted_diff,
    )
    blockers = [
        "cursor-is-offset-token-not-snapshot-isolated-database-cursor",
        "search-endpoints-still-return-bounded-result-sets-before-case-db-pagination",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(PAGINATION_TRUSTED_DIFF_BLOCKER_78)
    return {
        "component": "artifact-pagination-cursor-api",
        "status": "offset-compatible-cursor-pagination",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "collection": collection_name,
        "offset": offset,
        "limit": limit,
        "total": total,
        "returned": returned,
        "has_more": actual_has_more,
        "pagination_manifest": manifest,
        "pagination_cursor_report_grade_validation_plan": report_plan,
        "pagination_cursor_report_grade_validation_plan_hash": report_plan["validation_plan_sha256"],
        "report_grade_ready_slot_count": report_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": report_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "trusted_pagination_diff": dict(trusted_diff) if trusted_diff else missing_pagination_trusted_diff(),
        "core_accuracy_gates": core_gates,
        "blockers": blockers,
    }


def build_pagination_trusted_diff(
    rapid_page: Mapping[str, object],
    trusted_page: Mapping[str, object],
    *,
    trusted_tool: str = "pagination-cursor-manifest",
) -> dict[str, object]:
    rapid_pagination = extract_pagination_manifest(rapid_page)
    trusted_pagination = extract_pagination_manifest(trusted_page)
    compared_fields = [
        "collection",
        "offset",
        "limit",
        "returned",
        "total",
        "next_cursor",
        "previous_cursor",
        "has_more",
        "page_window_id",
        "manifest_hash",
    ]
    mismatches = [
        {"field": field, "rapid": rapid_pagination.get(field), "trusted": trusted_pagination.get(field)}
        for field in compared_fields
        if rapid_pagination.get(field) != trusted_pagination.get(field)
    ]
    status = "pass" if not mismatches and trusted_tool in PAGINATION_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["pagination"]],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else PAGINATION_TRUSTED_DIFF_BLOCKER_78,
    }


def extract_pagination_manifest(page: Mapping[str, object]) -> Mapping[str, object]:
    pagination = page.get("pagination")
    if isinstance(pagination, Mapping):
        pagination_manifest = pagination.get("pagination_manifest")
        if isinstance(pagination_manifest, Mapping):
            return pagination_manifest
        return pagination
    pagination_manifest = page.get("pagination_manifest")
    if isinstance(pagination_manifest, Mapping):
        return pagination_manifest
    return page


def encode_pagination_cursor(offset: int) -> str:
    return f"offset:{max(0, int(offset))}"


def decode_pagination_cursor(cursor: str) -> int:
    text = str(cursor or "").strip()
    if not text:
        return 0
    if text.startswith("offset:"):
        text = text.split(":", 1)[1]
    try:
        return max(0, int(text))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid pagination cursor")
