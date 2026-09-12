"""Preview sandbox run policy manifest and validation plan."""

from __future__ import annotations

import hashlib
import json
import mimetypes
from collections.abc import Mapping
from pathlib import Path

from .constants import (
    PREVIEW_SANDBOX_GAP_ID,
    PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS,
    PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
)

__all__ = [
    "build_preview_sandbox_run_policy_manifest",
    "preview_sandbox_report_grade_validation_plan",
    "preview_sandbox_run_output_policy_row",
]


def build_preview_sandbox_run_policy_manifest(*, outputs: Mapping[str, Path]) -> dict[str, object]:
    previewable_output_items = sorted(
        (
            str(name),
            path,
        )
        for name, path in outputs.items()
        if name
        in {
            "manifest",
            "docs",
            "docs_index",
            "files",
            "timeline",
            "timeline_report",
            "indicators",
            "summary",
            "report",
        }
    )
    previewable_outputs = [str(path.name) for _, path in previewable_output_items]
    policy_rows = [
        preview_sandbox_run_output_policy_row(name, path, sequence=index)
        for index, (name, path) in enumerate(previewable_output_items, start=1)
    ]
    row_hashes = [str(row["row_hash"]) for row in policy_rows]
    row_head_hash = hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest()
    manifest_core: dict[str, object] = {
        "profile_version": "preview-sandbox-run-policy-manifest-v1",
        "item_number": 73,
        "commercial_gap_ids": [PREVIEW_SANDBOX_GAP_ID],
        "commercial_claim_allowed": False,
        "source_preview_endpoint": "/api/runs/{run_id}/source-preview?path=...",
        "policy": {
            "read_only_preview": True,
            "executes_content": False,
            "external_network_access": False,
            "active_content_blocking": True,
            "renderer_strategy": "escaped-bounded-data-rendering",
            "original_file_opening": "download-only-user-controlled-action",
            "structured_preview_max_bytes": "api-enforced",
            "hex_preview_max_bytes": "api-enforced",
            "os_sandbox_enabled_for_risky_codecs": False,
        },
        "previewable_run_outputs": previewable_outputs,
        "preview_policy_rows": policy_rows,
        "preview_policy_row_count": len(policy_rows),
        "preview_policy_row_head_hash": row_head_hash,
        "active_content_blocked_count": sum(1 for row in policy_rows if row["active_content_blocked"]),
        "operator_review_requirements": [
            "Treat preview output as a bounded rendering, not as source extraction.",
            "Use citations/hashes from report or source rows before selecting evidence.",
            "Open risky active-content files only through a separately sandboxed external workflow.",
        ],
        "blockers": [
            PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
            "separate-os-sandbox-for-risky-codecs-macros-not-enabled",
            "browser-renderer-exploit-corpus-not-attached",
        ],
    }
    manifest_core["policy_hash"] = hashlib.sha256(
        json.dumps(manifest_core["policy"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_core["manifest_hash"] = hashlib.sha256(
        json.dumps(manifest_core, sort_keys=True).encode("utf-8")
    ).hexdigest()
    validation_plan = preview_sandbox_report_grade_validation_plan(policy_manifest=manifest_core)
    return {
        **manifest_core,
        "preview_sandbox_report_grade_validation_plan": validation_plan,
        "preview_sandbox_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
    }


def preview_sandbox_report_grade_validation_plan(*, policy_manifest: Mapping[str, object]) -> dict[str, object]:
    policy = policy_manifest.get("policy") if isinstance(policy_manifest.get("policy"), Mapping) else {}
    policy_manifest_hash = str(policy_manifest.get("manifest_hash") or "")
    policy_hash = str(policy_manifest.get("policy_hash") or "")
    row_head_hash = str(policy_manifest.get("preview_policy_row_head_hash") or "")
    row_count = int(policy_manifest.get("preview_policy_row_count") or 0)
    active_content_blocked_count = int(policy_manifest.get("active_content_blocked_count") or 0)
    no_exec_contract = {
        "executes_content": bool(policy.get("executes_content")),
        "external_network_access": bool(policy.get("external_network_access")),
        "renderer_strategy": str(policy.get("renderer_strategy") or ""),
        "original_file_opening": str(policy.get("original_file_opening") or ""),
    }
    no_exec_contract_hash = hashlib.sha256(
        json.dumps(no_exec_contract, sort_keys=True).encode("utf-8")
    ).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "run-policy-manifest",
            "status": "ready",
            "evidence_ref": "preview_sandbox_policy_manifest_hash",
            "evidence_hash": policy_manifest_hash,
            "description": "Run outputs expose the no-exec preview policy manifest.",
        },
        {
            "slot_id": "preview-policy-row-hashes",
            "status": "ready",
            "evidence_ref": "preview_policy_row_head_hash",
            "evidence_hash": row_head_hash,
            "description": "Previewable output rows are individually hashed for reviewer traceability.",
        },
        {
            "slot_id": "no-exec-no-network-contract",
            "status": "ready",
            "evidence_ref": "no_exec_contract_hash",
            "evidence_hash": no_exec_contract_hash,
            "description": "Preview policy records no active execution and no external network access.",
        },
        {
            "slot_id": "active-content-blocking-policy",
            "status": "ready",
            "evidence_ref": "active_content_blocked_count",
            "evidence_hash": hashlib.sha256(str(active_content_blocked_count).encode("ascii")).hexdigest(),
            "description": "Active-content-capable output types are flagged for blocked rendering.",
        },
        {
            "slot_id": "bounded-renderer-policy",
            "status": "ready",
            "evidence_ref": "policy_hash",
            "evidence_hash": policy_hash,
            "description": "The policy fixes escaped bounded rendering and user-controlled downloads.",
        },
        {
            "slot_id": "source-preview-endpoint-contract",
            "status": "ready",
            "evidence_ref": "source_preview_endpoint",
            "evidence_hash": hashlib.sha256(
                str(policy_manifest.get("source_preview_endpoint") or "").encode("utf-8")
            ).hexdigest(),
            "description": "The source-preview endpoint contract is recorded for audit/replay.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "os-level-renderer-sandbox",
            "status": "blocked",
            "blocker": "os-level-renderer-sandbox-required",
            "required_evidence": "Windows/macOS/Linux renderer sandbox proof for risky codecs, Office macros, and HTML/SVG rendering",
        },
        {
            "slot_id": "trusted-no-exec-manifest",
            "status": "blocked",
            "blocker": PREVIEW_SANDBOX_TRUSTED_DIFF_BLOCKER_73,
            "required_evidence": "trusted no-exec/no-network preview manifest diff for representative active-content files",
        },
        {
            "slot_id": "browser-renderer-exploit-corpus",
            "status": "blocked",
            "blocker": "browser-renderer-exploit-corpus-required",
            "required_evidence": "browser/renderer exploit corpus proving previews fail closed without script/network execution",
        },
        {
            "slot_id": "malicious-active-content-corpus",
            "status": "blocked",
            "blocker": "malicious-active-content-corpus-required",
            "required_evidence": "HTML/SVG/JS/Office macro corpus with expected blocked-render outcomes",
        },
        {
            "slot_id": "risky-codec-macro-external-sandbox",
            "status": "blocked",
            "blocker": "risky-codec-macro-external-sandbox-required",
            "required_evidence": "external sandbox workflow for media codecs, Office macros, embedded scripts, and unknown binaries",
        },
        {
            "slot_id": "browser-e2e-preview-sandbox",
            "status": "blocked",
            "blocker": "browser-e2e-preview-sandbox-required",
            "required_evidence": "browser E2E evidence that preview pages do not execute active content or contact networks",
        },
    ]
    plan_core = {
        "profile_version": PREVIEW_SANDBOX_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 73,
        "gap_id": PREVIEW_SANDBOX_GAP_ID,
        "commercial_gap_ids": [PREVIEW_SANDBOX_GAP_ID],
        "scope": "run-preview-policy",
        "policy_manifest_hash": policy_manifest_hash,
        "policy_hash": policy_hash,
        "preview_policy_row_count": row_count,
        "preview_policy_row_head_hash": row_head_hash,
        "active_content_blocked_count": active_content_blocked_count,
        "no_exec_contract_hash": no_exec_contract_hash,
        "read_only_preview": bool(policy.get("read_only_preview")),
        "executes_content": bool(policy.get("executes_content")),
        "external_network_access": bool(policy.get("external_network_access")),
        "active_content_blocking": bool(policy.get("active_content_blocking")),
        "renderer_strategy": str(policy.get("renderer_strategy") or ""),
        "os_sandbox_enabled_for_risky_codecs": bool(policy.get("os_sandbox_enabled_for_risky_codecs")),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(PREVIEW_SANDBOX_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use preview output only as bounded triage rendering until OS renderer sandbox and trusted no-exec corpus evidence are attached.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_hash": validation_plan_hash,
        "validation_plan_sha256": validation_plan_hash,
    }


def preview_sandbox_run_output_policy_row(name: str, path: Path, *, sequence: int) -> dict[str, object]:
    suffix = path.suffix.lower()
    mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    active_content = suffix in {".html", ".htm", ".svg", ".js", ".vbs", ".hta"} or mime_type in {
        "text/html",
        "image/svg+xml",
        "application/javascript",
    }
    row_core = {
        "sequence": sequence,
        "output_name": name,
        "source_name": path.name,
        "source_path_sha256": hashlib.sha256(str(path).encode("utf-8", errors="replace")).hexdigest(),
        "suffix": suffix,
        "mime_type": mime_type,
        "read_only_preview": True,
        "executes_content": False,
        "external_network_access": False,
        "active_content_blocked": active_content,
        "renderer_strategy": "escaped-bounded-data-rendering",
        "original_file_opening": "download-only-user-controlled-action",
        "os_sandbox_enabled_for_risky_codecs": False,
    }
    return {
        **row_core,
        "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }
