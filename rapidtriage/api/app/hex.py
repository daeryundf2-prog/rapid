from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.submission import compute_hashes
from .constants import (
    HEX_PREVIEW_MAX_BYTES,
    HEX_PREVIEW_ROW_WIDTH,
    HEX_RANGE_EXPORT_MAX_BYTES,
    HEX_VIEWER_REPORT_GRADE_BLOCKERS,
    HEX_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
    HEX_VIEWER_TRUSTED_TOOLS,
    SOURCE_VIEWER_VERSION,
    VIEWER_WORKFLOW_GAP_IDS,
)
from .helpers import (
    _hex_viewer_diff_key,
    _hex_viewer_diff_values,
    compute_hashes_for_bytes,
    optional_int_for_api,
    stable_payload_sha256,
)
from .viewer_core import (
    build_viewer_trusted_diff_result,
    source_viewer_component_assessment,
    structured_viewer_metadata,
    viewer_workflow_commercial_uplift_evidence,
    viewer_workflow_reportability_decision,
)


def build_hex_preview(source_path: Path, *, run_id: str | None = None) -> dict[str, object]:
    try:
        with source_path.open("rb") as handle:
            data = handle.read(HEX_PREVIEW_MAX_BYTES + 1)
    except OSError as exc:
        return {
            "preview_type": "binary",
            "message": f"Hex preview failed: {exc}",
            "viewer_metadata": structured_viewer_metadata("binary", "hex-preview-failed", "parse-failed"),
            "hex": {"error": str(exc)},
        }
    preview = data[:HEX_PREVIEW_MAX_BYTES]
    preview_hashes = compute_hashes_for_bytes(preview)
    rows = build_hex_rows(preview)
    range_profile = hex_range_citation_profile(run_id=run_id, source_path=source_path, preview=preview)
    preview_manifest = build_hex_preview_manifest(
        source_path=source_path,
        rows=rows,
        preview_hashes=preview_hashes,
        truncated=len(data) > HEX_PREVIEW_MAX_BYTES,
        range_profile=range_profile,
    )
    validation_plan = build_hex_viewer_report_grade_validation_plan(
        context="hex-preview",
        source_path=source_path,
        rows=rows,
        preview_hashes=preview_hashes,
        truncated=len(data) > HEX_PREVIEW_MAX_BYTES,
        source_hash_status="available-on-demand-via-source-metadata",
        preview_manifest=preview_manifest,
        range_export_ready=True,
    )
    core_accuracy_gates = hex_viewer_core_accuracy_gates(
        source_path=source_path,
        rows=rows,
        preview_hashes=preview_hashes,
        truncated=len(data) > HEX_PREVIEW_MAX_BYTES,
        preview_manifest=preview_manifest,
        validation_plan=validation_plan,
    )
    return {
        "preview_type": "hex",
        "message": "Bounded hex preview is available.",
        "text": "",
        "truncated": len(data) > HEX_PREVIEW_MAX_BYTES,
        "viewer_metadata": {
            "source_format": source_path.suffix.lower().lstrip(".") or "binary",
            "strategy": "bounded-hex-preview",
            "preview_status": "available",
            "parser": "rapidtriage.source-viewer.hex",
            "parser_version": SOURCE_VIEWER_VERSION,
            "max_bytes": HEX_PREVIEW_MAX_BYTES,
            "row_width": HEX_PREVIEW_ROW_WIDTH,
            "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        },
        "hex": {
            "offset_base": 0,
            "bytes_read": len(preview),
            "max_bytes": HEX_PREVIEW_MAX_BYTES,
            "row_width": HEX_PREVIEW_ROW_WIDTH,
            "preview_sha256": preview_hashes["sha256"],
            "source_hash_status": "available-on-demand-via-source-metadata",
            "first_offset_hex": "0x00000000" if preview else "",
            "last_offset_hex": f"0x{max(len(preview) - 1, 0):08x}" if preview else "",
            "offset_navigation": {
                "unit": "byte",
                "base": "hex",
                "supports_keyword_byte_hits": True,
                "supports_source_hash_verification": True,
                "supports_range_citation_export": True,
                "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
                "default_range_export_url": range_profile.get("default_export_url"),
            },
            "range_citation_profile": range_profile,
            "hex_preview_manifest": preview_manifest,
            "hex_viewer_report_grade_validation_plan": validation_plan,
            "hex_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "rows": rows,
            "truncated": len(data) > HEX_PREVIEW_MAX_BYTES,
            "safety": "read-only bounded preview; use source hashes before reporting byte offsets",
            "hex_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["hex"],
                "raw-source-hex-viewer",
                [
                    "hex-viewer-is-bounded-preview-not-full-disk-editor",
                    "sector/partition-aware-navigation-not-implemented",
                    "file-format-structure-decoding-requires-specialized-parser",
                ],
            ),
            "core_accuracy_gates": core_accuracy_gates,
            "trusted_hex_viewer_diff": {
                "status": "missing",
                "blocker_id": HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
                "required_tools": sorted(HEX_VIEWER_TRUSTED_TOOLS),
            },
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=53,
                component="raw-source-hex-viewer",
                core_accuracy_gates=core_accuracy_gates,
                blockers=[
                    "interactive-jump-to-offset-ui-not-implemented",
                    "copy-safe-byte-selection-ui-not-implemented",
                    "export-range-citation-package-needs-trusted-offset-validation",
                    "sector-partition-aware-navigation-not-implemented",
                    HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[
                    f"source_path:{source_path}",
                    f"preview_sha256:{preview_hashes['sha256']}",
                    f"hex_viewer_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                ],
                controls={
                    "max_hex_preview_bytes": HEX_PREVIEW_MAX_BYTES,
                    "row_width": HEX_PREVIEW_ROW_WIDTH,
                    "row_count": len(rows),
                    "hex_preview_manifest_hash": preview_manifest["manifest_hash"],
                    "hex_viewer_report_grade_validation_plan_present": True,
                    "hex_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                    "hex_viewer_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                    "hex_viewer_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
                    "hex_preview_row_hash_count": preview_manifest["row_hash_count"],
                    "supports_keyword_byte_hits": True,
                    "full_file_inline_hash": False,
                    "export_range_citation": True,
                    "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
                },
            ),
        },
    }


def build_hex_rows(data: bytes, *, base_offset: int = 0) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for relative_offset in range(0, len(data), HEX_PREVIEW_ROW_WIDTH):
        chunk = data[relative_offset : relative_offset + HEX_PREVIEW_ROW_WIDTH]
        absolute_offset = base_offset + relative_offset
        rows.append(
            {
                "offset": absolute_offset,
                "relative_offset": relative_offset,
                "offset_hex": f"0x{absolute_offset:08x}",
                "hex": " ".join(f"{byte:02x}" for byte in chunk),
                "ascii": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk),
            }
        )
    return rows


def hex_range_citation_profile(*, run_id: str | None, source_path: Path, preview: bytes) -> dict[str, object]:
    default_length = min(len(preview), 256)
    quoted_path = quote(str(source_path))
    default_export_url = (
        f"/api/runs/{run_id}/source-hex-range?path={quoted_path}&offset=0&length={default_length}"
        if run_id and default_length
        else None
    )
    return {
        "profile_version": "hex-range-citation-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "qc_prep_item": 12,
        "range_export_endpoint": "/api/runs/{run_id}/source-hex-range",
        "default_offset": 0,
        "default_offset_hex": "0x00000000" if default_length else "",
        "default_length": default_length,
        "default_export_url": default_export_url,
        "max_export_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
        "supports_offset_jump": True,
        "supports_range_hashes": True,
        "supports_copy_safe_citation": True,
        "supports_report_candidate_payload": True,
        "supports_compare_pin_payload": True,
        "source_hash_policy": "preview/range hashes are immediate; full-source hashes require include_hashes=true or source-metadata?hash=true",
        "report_use_warning": "Attach the range package, source hash, and trusted offset validation before using byte offsets in a court exhibit.",
    }


def hex_range_review_link_profile(package: Mapping[str, object]) -> dict[str, object]:
    locator = (
        package.get("hex_range_proof_manifest", {}).get("source_viewer_locator", {})
        if isinstance(package.get("hex_range_proof_manifest"), Mapping)
        else {}
    )
    copy_safe = package.get("copy_safe_citation") if isinstance(package.get("copy_safe_citation"), Mapping) else {}
    citation_text = str(copy_safe.get("text") or package.get("citation") or "")
    core = {
        "citation_id": str(package.get("citation_id") or ""),
        "source_name": str(package.get("name") or ""),
        "offset_hex": str(package.get("offset_hex") or ""),
        "length_returned": optional_int_for_api(package.get("length_returned")) or 0,
        "range_sha256": str((package.get("range_hashes") or {}).get("sha256") or "")
        if isinstance(package.get("range_hashes"), Mapping)
        else "",
        "manifest_hash": str(package.get("hex_range_proof_manifest_hash") or ""),
    }
    profile = {
        "profile_version": "hex-range-review-link-profile-v1",
        "qc_prep_item": 12,
        "source_viewer_locator": dict(locator) if isinstance(locator, Mapping) else {},
        "review_note_citation": {
            "profile_version": "hex-range-review-note-citation-v1",
            "qc_prep_item": 12,
            "text": citation_text,
            "source_viewer_locator": dict(locator) if isinstance(locator, Mapping) else {},
            "ready_for_review_note": bool(citation_text),
            "ready_for_report": bool(package.get("source_hashes")),
        },
        "compare_pin_payload": {
            "source": "hex-range",
            "title": f"{core['source_name']} {core['offset_hex']}",
            "pointer": f"hex-range:{core['citation_id']}",
            "preview": citation_text,
            "source_viewer_locator": dict(locator) if isinstance(locator, Mapping) else {},
            "manifest_hash": core["manifest_hash"],
        },
        "report_candidate_payload": {
            "source": "hex-range",
            "citation_id": core["citation_id"],
            "summary": f"{core['source_name']} byte range {core['offset_hex']} len={core['length_returned']}",
            "citation": citation_text,
            "range_sha256": core["range_sha256"],
            "source_hash_status": str(package.get("source_hash_status") or ""),
            "ready_for_report_draft": bool(package.get("source_hashes")),
            "required_before_report": [
                "include source hashes",
                "attach hex range proof manifest",
                "validate offset/range with trusted hex manifest",
            ],
        },
        "commercial_grade_blockers": [
            "trusted-offset-manifest-diff-required-before-court-use",
            "browser-e2e-compare-pin-flow-required",
        ],
    }
    return {**profile, "profile_hash": stable_payload_sha256({**profile, "core": core})}


def build_hex_preview_manifest(
    *,
    source_path: Path,
    rows: Sequence[Mapping[str, object]],
    preview_hashes: Mapping[str, str],
    truncated: bool,
    range_profile: Mapping[str, object],
) -> dict[str, object]:
    row_entries: list[dict[str, object]] = []
    for row in rows[:256]:
        row_core = {
            "offset": row.get("offset"),
            "offset_hex": str(row.get("offset_hex") or ""),
            "hex": str(row.get("hex") or ""),
            "ascii_sha256": hashlib.sha256(str(row.get("ascii") or "").encode("utf-8", errors="replace")).hexdigest(),
        }
        row_entries.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "hex-preview-source-locator-manifest-v1",
        "item_number": 53,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "path": str(source_path),
        "name": source_path.name,
        "preview_sha256": str(preview_hashes.get("sha256") or ""),
        "preview_byte_count": sum(len(str(row.get("hex") or "").split()) for row in rows),
        "row_count": len(rows),
        "bounded_row_count": len(row_entries),
        "row_hash_count": sum(1 for row in row_entries if row.get("row_hash")),
        "truncated": truncated,
        "default_range_export_url": range_profile.get("default_export_url"),
        "source_viewer_locator": {
            "viewer": "source-hex",
            "path": str(source_path),
            "offset": 0,
            "offset_hex": "0x00000000" if rows else "",
            "row_width": HEX_PREVIEW_ROW_WIDTH,
            "open_action": "open-hex-preview-at-offset",
        },
        "rows": row_entries,
        "blockers": [
            "interactive-jump-to-offset-ui-not-implemented",
            "trusted-offset-manifest-diff-required-before-court-use",
            "sector-partition-aware-navigation-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_hex_range_citation_package(
    *,
    run_id: str,
    source_path: Path,
    offset: int,
    length: int,
    include_source_hashes: bool,
) -> dict[str, object]:
    stat = source_path.stat()
    if offset >= stat.st_size:
        raise HTTPException(status_code=416, detail="offset is outside the source file")
    read_length = min(length, HEX_RANGE_EXPORT_MAX_BYTES, max(stat.st_size - offset, 0))
    with source_path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(read_length)
    range_hashes = compute_hashes_for_bytes(data)
    rows = build_hex_rows(data, base_offset=offset)
    end_exclusive = offset + len(data)
    citation_id = hashlib.sha256(
        f"{run_id}|{source_path}|{stat.st_size}|{offset}|{end_exclusive}|{range_hashes['sha256']}".encode()
    ).hexdigest()[:16]
    source_hashes = compute_hashes(source_path) if include_source_hashes else {}
    proof_manifest = build_hex_range_proof_manifest(
        source_path=source_path,
        offset=offset,
        end_exclusive=end_exclusive,
        rows=rows,
        range_hashes=range_hashes,
        source_hashes=source_hashes,
        include_source_hashes=include_source_hashes,
        citation_id=citation_id,
    )
    validation_plan = build_hex_viewer_report_grade_validation_plan(
        context="hex-range-citation",
        source_path=source_path,
        rows=rows,
        preview_hashes=range_hashes,
        truncated=length > len(data),
        source_hash_status="computed" if include_source_hashes else "available-on-demand",
        range_manifest=proof_manifest,
        range_export_ready=True,
        include_source_hashes=include_source_hashes,
    )
    core_accuracy_gates = hex_viewer_core_accuracy_gates(
        source_path=source_path,
        rows=rows,
        preview_hashes=range_hashes,
        truncated=length > len(data),
        range_manifest=proof_manifest,
        validation_plan=validation_plan,
    )
    package = {
        "command": "source-hex-range",
        "profile_version": "hex-range-citation-package-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "qc_prep_item": 12,
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "size": stat.st_size,
        "offset": offset,
        "offset_hex": f"0x{offset:08x}",
        "end_offset_exclusive": end_exclusive,
        "end_offset_exclusive_hex": f"0x{end_exclusive:08x}",
        "length_requested": length,
        "length_returned": len(data),
        "max_export_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
        "truncated": length > len(data),
        "range_hashes": range_hashes,
        "source_hashes": source_hashes,
        "source_hash_status": "computed" if include_source_hashes else "available-on-demand",
        "hex_range_proof_manifest": proof_manifest,
        "hex_range_proof_manifest_hash": proof_manifest["manifest_hash"],
        "hex_viewer_report_grade_validation_plan": validation_plan,
        "hex_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "rows": rows,
        "citation": (
            f"{source_path.name} bytes {offset}-{max(end_exclusive - 1, offset)} "
            f"({f'0x{offset:08x}'}-{f'0x{max(end_exclusive - 1, offset):08x}'}) "
            f"sha256={range_hashes['sha256']}"
        ),
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; range={offset}-{max(end_exclusive - 1, offset)}; "
                f"offset_hex=0x{offset:08x}; length={len(data)}; range_sha256={range_hashes['sha256']}; "
                f"citation_id={citation_id}"
            ),
            "redacts_full_path": True,
            "full_path_available_in_authorized_payload": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=53,
            component="hex-range-citation-package",
            blockers=[
                "trusted-offset-manifest-diff-required-before-court-use",
                "source-full-hash-required-before-court-use",
                "sector-partition-aware-navigation-not-implemented",
            ],
            controls={
                "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
                "range_hashes": True,
                "source_hashes_included": include_source_hashes,
                "copy_safe_citation": True,
            },
        ),
        "core_accuracy_gates": core_accuracy_gates,
    }
    review_link_profile = hex_range_review_link_profile(package)
    return {
        **package,
        "hex_range_review_link_profile": review_link_profile,
        "review_note_citation": review_link_profile["review_note_citation"],
        "compare_pin_payload": review_link_profile["compare_pin_payload"],
        "report_candidate_payload": review_link_profile["report_candidate_payload"],
    }


def build_hex_range_proof_manifest(
    *,
    source_path: Path,
    offset: int,
    end_exclusive: int,
    rows: Sequence[Mapping[str, object]],
    range_hashes: Mapping[str, str],
    source_hashes: Mapping[str, str],
    include_source_hashes: bool,
    citation_id: str,
) -> dict[str, object]:
    row_entries: list[dict[str, object]] = []
    for row in rows:
        row_core = {
            "offset": row.get("offset"),
            "offset_hex": str(row.get("offset_hex") or ""),
            "hex": str(row.get("hex") or ""),
            "ascii_sha256": hashlib.sha256(str(row.get("ascii") or "").encode("utf-8", errors="replace")).hexdigest(),
        }
        row_entries.append({**row_core, "row_hash": stable_payload_sha256(row_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "hex-range-proof-manifest-v1",
        "item_number": 53,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["hex"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "offset": offset,
        "offset_hex": f"0x{offset:08x}",
        "end_offset_exclusive": end_exclusive,
        "end_offset_exclusive_hex": f"0x{end_exclusive:08x}",
        "length_returned": max(end_exclusive - offset, 0),
        "range_sha256": str(range_hashes.get("sha256") or ""),
        "source_sha256": str(source_hashes.get("sha256") or ""),
        "source_hashes_included": include_source_hashes,
        "row_count": len(row_entries),
        "row_hash_count": sum(1 for row in row_entries if row.get("row_hash")),
        "source_viewer_locator": {
            "viewer": "source-hex-range",
            "path": str(source_path),
            "offset": offset,
            "offset_hex": f"0x{offset:08x}",
            "length": max(end_exclusive - offset, 0),
            "open_action": "open-hex-range-citation",
        },
        "rows": row_entries,
        "blockers": [
            "trusted-offset-manifest-diff-required-before-court-use",
            *([] if include_source_hashes else ["source-full-hash-required-before-court-use"]),
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_hex_viewer_report_grade_validation_plan(
    *,
    context: str,
    source_path: Path,
    rows: Sequence[Mapping[str, object]],
    preview_hashes: Mapping[str, str],
    truncated: bool,
    source_hash_status: str,
    preview_manifest: Mapping[str, object] | None = None,
    range_manifest: Mapping[str, object] | None = None,
    range_export_ready: bool = False,
    include_source_hashes: bool = False,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    preview_manifest = preview_manifest if isinstance(preview_manifest, Mapping) else {}
    range_manifest = range_manifest if isinstance(range_manifest, Mapping) else {}
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    row_hash_count = int(preview_manifest.get("row_hash_count") or range_manifest.get("row_hash_count") or 0)
    manifest_hash = str(preview_manifest.get("manifest_hash") or range_manifest.get("manifest_hash") or "")
    validation_slots = [
        slot(
            "hex-bounded-row-window",
            ready=bool(rows),
            evidence=f"context={context} row_count={len(rows)} truncated={truncated}",
            blocker_id="hex-bounded-row-window-required",
            operator_action="Emit bounded rows before byte-level review.",
        ),
        slot(
            "hex-byte-and-hex-offsets",
            ready=bool(rows) and all(row.get("offset") is not None and row.get("offset_hex") for row in rows),
            evidence=f"row_count={len(rows)}",
            blocker_id="hex-byte-offsets-required",
            operator_action="Preserve byte offsets and hex offsets for each row.",
        ),
        slot(
            "hex-preview-or-range-hash",
            ready=bool(preview_hashes.get("sha256")),
            evidence=f"sha256={preview_hashes.get('sha256', '')}",
            blocker_id="hex-preview-or-range-hash-required",
            operator_action="Hash the preview or exported range.",
        ),
        slot(
            "hex-source-or-range-locator-manifest",
            ready=bool(manifest_hash) and row_hash_count > 0,
            evidence=f"manifest_hash={manifest_hash} row_hash_count={row_hash_count}",
            blocker_id="hex-source-or-range-locator-manifest-required",
            operator_action="Attach source/range locator manifest and row hashes.",
        ),
        slot(
            "hex-range-citation-export",
            ready=range_export_ready,
            evidence=f"range_export_ready={range_export_ready} max_export_bytes={HEX_RANGE_EXPORT_MAX_BYTES}",
            blocker_id="hex-range-citation-export-required",
            operator_action="Expose bounded range citation export for selected bytes.",
        ),
        slot(
            "hex-source-hash-workflow",
            ready=bool(source_hash_status),
            evidence=f"source_hash_status={source_hash_status} include_source_hashes={include_source_hashes}",
            blocker_id="hex-source-hash-workflow-required",
            operator_action="Compute or disclose an on-demand source hash workflow.",
        ),
        slot(
            "hex-interactive-jump-to-offset-ui",
            ready=False,
            evidence="interactive_jump_to_offset_ui=false",
            blocker_id="interactive-jump-to-offset-ui-not-implemented",
            operator_action="Add full-file jump-to-offset UI with bounded server reads.",
        ),
        slot(
            "hex-copy-safe-byte-selection-ui",
            ready=False,
            evidence="copy_safe_byte_selection_ui=false",
            blocker_id="copy-safe-byte-selection-ui-not-implemented",
            operator_action="Add byte selection hashing and copy-safe report snippets.",
        ),
        slot(
            "hex-full-file-inline-hash-for-large-source",
            ready=False,
            evidence="full_file_inline_hash_for_large_source=false",
            blocker_id="full-file-inline-hash-for-large-source-required",
            operator_action="Display full-source hashes inline without forcing large previews into memory.",
        ),
        slot(
            "hex-sector-partition-aware-navigation",
            ready=False,
            evidence="sector_partition_aware_navigation=false",
            blocker_id="sector-partition-aware-navigation-not-implemented",
            operator_action="Attach disk/partition/sector context for image-backed byte offsets.",
        ),
        slot(
            "hex-external-byte-citation-package-validation",
            ready=False,
            evidence="external_byte_citation_package_validation=false",
            blocker_id="external-byte-citation-package-validation-required",
            operator_action="Validate citation packages against an external byte-offset corpus.",
        ),
        slot(
            "hex-trusted-offset-manifest",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
            operator_action="Attach a passing trusted offset manifest diff.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": HEX_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 53,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["hex"],
        "batch_id": "commercial-uplift-051-055",
        "selected_track": "raw-source-hex-viewer-report-validation",
        "context": context,
        "path": str(source_path),
        "row_count": len(rows),
        "row_width": HEX_PREVIEW_ROW_WIDTH,
        "truncated": truncated,
        "preview_or_range_sha256": str(preview_hashes.get("sha256") or ""),
        "manifest_hash": manifest_hash,
        "row_hash_count": row_hash_count,
        "source_hash_status": source_hash_status,
        "include_source_hashes": include_source_hashes,
        "range_export_ready": range_export_ready,
        "range_export_max_bytes": HEX_RANGE_EXPORT_MAX_BYTES,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(HEX_VIEWER_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage web -> source-preview for a binary file",
            "GET /api/runs/<run_id>/source-hex-range?path=<path>&offset=<n>&length=<n>&include_hashes=true",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 53 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-hex-preview-triage-pivot",
            "forbidden_claim": "full-source byte-citation or disk-sector navigation complete",
            "required_disclaimer": (
                "Hex viewer output is bounded preview/range-citation evidence until jump-to-offset UI, "
                "byte selection hashing, full-source hash display, sector/partition context, external citation "
                "validation, and trusted offset manifests are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def hex_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    rows: Sequence[Mapping[str, object]],
    preview_hashes: Mapping[str, str],
    truncated: bool,
    trusted_diff: Mapping[str, object] | None = None,
    preview_manifest: Mapping[str, object] | None = None,
    range_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if rows:
        satisfied.append("bounded hex rows")
    if all(row.get("offset") is not None and row.get("offset_hex") for row in rows):
        satisfied.append("byte offsets and hex offsets")
    if preview_hashes.get("sha256"):
        satisfied.append("preview hash")
    if rows:
        satisfied.append("byte-search citation support")
    if truncated is not None:
        satisfied.append("full-source validation warning")
    preview_manifest = preview_manifest if isinstance(preview_manifest, Mapping) else {}
    range_manifest = range_manifest if isinstance(range_manifest, Mapping) else {}
    if preview_manifest.get("manifest_hash"):
        satisfied.append("hex preview source locator manifest")
    if range_manifest.get("manifest_hash"):
        satisfied.append("hex range proof manifest")
    if int(preview_manifest.get("row_hash_count") or range_manifest.get("row_hash_count") or 0) > 0:
        satisfied.append("hex row hashes")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("hex viewer report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("hex viewer report-grade ready slots")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted hex offset manifest diff pass")
    return [
        build_accuracy_gate(
            53,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"row_count:{len(rows)}",
                f"preview_sha256:{preview_hashes.get('sha256', '')}",
                f"hex_preview_manifest_hash:{preview_manifest.get('manifest_hash', '')}",
                f"hex_range_manifest_hash:{range_manifest.get('manifest_hash', '')}",
                f"hex_viewer_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"hex_viewer_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}",
                f"hex_viewer_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def build_hex_viewer_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "hex-viewer-trusted-offset-manifest",
) -> dict[str, object]:
    rapid_index = {_hex_viewer_diff_key(row): _hex_viewer_diff_values(row) for row in rapid_rows}
    trusted_index = {_hex_viewer_diff_key(row): _hex_viewer_diff_values(row) for row in trusted_rows}
    return build_viewer_trusted_diff_result(
        profile_version="hex-viewer-trusted-offset-manifest-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=HEX_VIEWER_TRUSTED_TOOLS,
        blocker_id=HEX_VIEWER_TRUSTED_DIFF_BLOCKER,
        compare_fields=("offset", "offset_hex", "hex", "ascii"),
    )
