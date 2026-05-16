from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import traceback
import uuid
import zipfile
from pathlib import Path
from typing import Mapping

from .forensic_accuracy import build_accuracy_gate


DEFAULT_CRASH_DIR = Path.home() / ".rapidtriage" / "crash-reports"
CRASH_REPORTING_GAP_ID = "#105"
CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105 = "trusted-crash-redaction-export-diff-missing"
CRASH_REPORT_TRUSTED_TOOLS = {"crash-redaction-checklist", "local-crash-export-log", "enterprise-no-upload-review"}
CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION = "crash-reporting-report-grade-validation-plan-v1"
CRASH_REPORT_GRADE_BLOCKERS = [
    CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105,
    "operator-crash-export-ui-smoke-required",
    "trusted-crash-redaction-checklist-required",
    "enterprise-no-upload-review-required",
    "release-host-crash-export-smoke-required",
    "independent-redaction-review-required",
    "signed-release-build-evidence-required",
    "crash-dashboard-release-smoke-required",
]
FUNCTIONAL_OPS_BATCH_ID = "commercial-uplift-061-065"


def crash_log_dir() -> Path:
    return Path(os.environ.get("RAPIDTRIAGE_CRASH_LOG_DIR") or DEFAULT_CRASH_DIR).expanduser().resolve()


def list_crash_reports(*, output_dir: Path | None = None, limit: int = 50) -> dict[str, object]:
    directory = (output_dir or crash_log_dir()).expanduser().resolve()
    reports = []
    for path in sorted(directory.glob("crash-*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        if len(reports) >= limit:
            break
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        reports.append(summarize_crash_report(path, payload))
    dashboard = build_crash_trend_dashboard(reports, directory=directory)
    return {
        "command": "crash-reports",
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "report_dir": str(directory),
        "limit": limit,
        "reports": reports,
        "summary": dashboard,
        "crash_trend_dashboard": dashboard,
        "local_only": True,
        "upload_enabled": False,
        "export_endpoint": "/api/crash-reports/{crash_id}/export",
    }


def read_crash_report(crash_id: str, *, output_dir: Path | None = None) -> dict[str, object]:
    path = resolve_crash_report_path(crash_id, output_dir=output_dir)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FileNotFoundError(f"failed to read crash report {crash_id}") from exc
    return {"path": str(path), "summary": summarize_crash_report(path, payload), "payload": payload}


def export_crash_report_bundle(
    crash_id: str,
    *,
    output_dir: Path | None = None,
    export_dir: Path | None = None,
) -> dict[str, object]:
    report = read_crash_report(crash_id, output_dir=output_dir)
    report_path = Path(str(report["path"]))
    payload = report["payload"] if isinstance(report["payload"], Mapping) else {}
    destination_dir = (export_dir or report_path.parent / "exports").expanduser().resolve()
    destination_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = destination_dir / f"{crash_id}-export.zip"
    manifest = {
        "profile_version": "crash-export-ui-bundle-manifest-v1",
        "item_number": 105,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "commercial_claim_allowed": False,
        "crash_id": crash_id,
        "source_report": str(report_path),
        "source_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        "local_only": True,
        "automatic_upload_enabled": False,
        "included_files": [
            {"name": report_path.name, "role": "redacted-local-crash-report"},
            {"name": "crash-export-manifest.json", "role": "export-manifest"},
        ],
        "redaction_matrix_hash": payload.get("crash_redaction_matrix_hash", ""),
        "no_upload_manifest_hash": payload.get("crash_no_upload_manifest_hash", ""),
        "crash_report_grade_validation_plan_hash": payload.get("crash_report_grade_validation_plan_hash", ""),
        "crash_report_grade_ready_slot_count": payload.get("crash_report_grade_ready_slot_count", 0),
        "crash_report_grade_blocking_slot_count": payload.get("crash_report_grade_blocking_slot_count", 0),
        "operator_review_required": True,
        "blockers": sorted({CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105, *CRASH_REPORT_GRADE_BLOCKERS}),
    }
    manifest["manifest_hash"] = stable_crash_sha256(manifest)
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(report_path, arcname=report_path.name)
        archive.writestr("crash-export-manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    manifest["bundle_path"] = str(bundle_path)
    manifest["bundle_sha256"] = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    return manifest


def resolve_crash_report_path(crash_id: str, *, output_dir: Path | None = None) -> Path:
    if not re.match(r"^crash-[0-9TZ]+-[a-f0-9]{8}$", crash_id):
        raise FileNotFoundError(f"invalid crash id: {crash_id}")
    directory = (output_dir or crash_log_dir()).expanduser().resolve()
    path = (directory / f"{crash_id}.json").resolve()
    if path.parent != directory or not path.is_file():
        raise FileNotFoundError(f"crash report not found: {crash_id}")
    return path


def summarize_crash_report(path: Path, payload: Mapping[str, object]) -> dict[str, object]:
    exception = payload.get("exception") if isinstance(payload.get("exception"), Mapping) else {}
    context = payload.get("context") if isinstance(payload.get("context"), Mapping) else {}
    redaction_matrix = payload.get("crash_redaction_matrix") if isinstance(payload.get("crash_redaction_matrix"), Mapping) else {}
    return {
        "crash_id": str(payload.get("crash_id") or path.stem),
        "generated_at": payload.get("generated_at", ""),
        "path": str(path),
        "exception_type": exception.get("type", ""),
        "exception_message": exception.get("message", ""),
        "api_path": context.get("path", ""),
        "component": context.get("component", ""),
        "local_only": bool(payload.get("local_only")),
        "redacted_key_count": int(redaction_matrix.get("redacted_key_count") or 0),
        "crash_export_evidence_manifest_hash": payload.get("crash_export_evidence_manifest_hash", ""),
        "crash_no_upload_manifest_hash": payload.get("crash_no_upload_manifest_hash", ""),
        "crash_redaction_matrix_hash": payload.get("crash_redaction_matrix_hash", ""),
        "crash_report_grade_validation_plan_hash": payload.get("crash_report_grade_validation_plan_hash", ""),
        "crash_report_grade_ready_slot_count": int(payload.get("crash_report_grade_ready_slot_count") or 0),
        "crash_report_grade_blocking_slot_count": int(payload.get("crash_report_grade_blocking_slot_count") or 0),
        "size_bytes": path.stat().st_size,
    }


def build_crash_trend_dashboard(reports: list[dict[str, object]], *, directory: Path) -> dict[str, object]:
    exception_counts: dict[str, int] = {}
    api_path_counts: dict[str, int] = {}
    for report in reports:
        exception_type = str(report.get("exception_type") or "unknown")
        api_path = str(report.get("api_path") or "unknown")
        exception_counts[exception_type] = exception_counts.get(exception_type, 0) + 1
        api_path_counts[api_path] = api_path_counts.get(api_path, 0) + 1
    dashboard: dict[str, object] = {
        "profile_version": "crash-trend-dashboard-v1",
        "item_number": 105,
        "report_dir": str(directory),
        "report_count": len(reports),
        "local_only_count": sum(1 for report in reports if report.get("local_only")),
        "redacted_key_total": sum(int(report.get("redacted_key_count") or 0) for report in reports),
        "exception_type_counts": dict(sorted(exception_counts.items())),
        "api_path_counts": dict(sorted(api_path_counts.items())),
        "latest_generated_at": reports[0].get("generated_at", "") if reports else "",
        "export_ui_available": True,
        "automatic_upload_enabled": False,
        "commercial_claim_allowed": False,
    }
    dashboard["dashboard_hash"] = stable_crash_sha256(dashboard)
    return dashboard


def write_crash_report(
    exc: BaseException,
    *,
    context: Mapping[str, object] | None = None,
    output_dir: Path | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    directory = (output_dir or crash_log_dir()).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    crash_id = f"crash-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    report_path = directory / f"{crash_id}.json"
    if trusted_diff is None:
        trusted_diff = missing_crash_report_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105)
    payload = {
        "command": "crash-report",
        "crash_id": crash_id,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "functional_priority_profile": crash_reporting_functional_profile(
            crash_id=crash_id,
            report_path=report_path,
            context=context or {},
            trusted_diff=trusted_diff,
        ),
        "core_accuracy_gates": crash_report_core_accuracy_gates(
            crash_id=crash_id,
            report_path=report_path,
            trusted_diff=trusted_diff,
        ),
        "local_only": True,
        "privacy_note": "Crash reports are written locally and are never uploaded by RapidTriage.",
        "trusted_crash_report_diff": trusted_diff,
        "blockers": blockers,
        "exception": {
            "type": type(exc).__name__,
            "message": str(exc)[:1000],
            "traceback": traceback.format_exception(type(exc), exc, exc.__traceback__)[-20:],
        },
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "context": sanitize_context(context or {}),
    }
    crash_export_evidence_manifest = build_crash_export_evidence_manifest(
        payload,
        report_path=report_path,
        trusted_diff=trusted_diff,
    )
    no_upload_manifest = build_crash_no_upload_manifest(
        payload,
        report_path=report_path,
        export_manifest=crash_export_evidence_manifest,
    )
    payload["crash_export_evidence_manifest"] = crash_export_evidence_manifest
    payload["crash_export_evidence_manifest_hash"] = crash_export_evidence_manifest["manifest_hash"]
    payload["crash_no_upload_manifest"] = no_upload_manifest
    payload["crash_no_upload_manifest_hash"] = no_upload_manifest["manifest_hash"]
    payload["crash_redaction_matrix"] = crash_export_evidence_manifest["redaction_matrix"]
    payload["crash_redaction_matrix_hash"] = crash_export_evidence_manifest["redaction_matrix_hash"]
    payload["export_evidence_slots"] = crash_export_evidence_manifest["export_evidence_slots"]
    validation_plan = build_crash_report_grade_validation_plan(
        payload,
        report_path=report_path,
        evidence_manifest=crash_export_evidence_manifest,
        no_upload_manifest=no_upload_manifest,
        trusted_diff=trusted_diff,
    )
    payload["crash_report_grade_validation_plan"] = validation_plan
    payload["crash_report_grade_validation_plan_hash"] = validation_plan["validation_plan_hash"]
    payload["crash_report_grade_ready_slot_count"] = validation_plan["ready_slot_count"]
    payload["crash_report_grade_blocking_slot_count"] = validation_plan["blocking_slot_count"]
    payload["blockers"] = sorted({*blockers, *validation_plan["blockers"]})
    payload["functional_priority_profile"] = crash_reporting_functional_profile(
        crash_id=crash_id,
        report_path=report_path,
        context=context or {},
        trusted_diff=trusted_diff,
        no_upload_manifest=no_upload_manifest,
    )
    payload["core_accuracy_gates"] = crash_report_core_accuracy_gates(
        crash_id=crash_id,
        report_path=report_path,
        trusted_diff=trusted_diff,
        evidence_manifest=crash_export_evidence_manifest,
        no_upload_manifest=no_upload_manifest,
        report_grade_validation_plan=validation_plan,
    )
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"crash_id": crash_id, "path": str(report_path), "payload": payload}


def missing_crash_report_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "blocker": CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105,
        "required_trusted_tools": sorted(CRASH_REPORT_TRUSTED_TOOLS),
    }


def crash_reporting_functional_profile(
    *,
    crash_id: str,
    report_path: Path,
    context: Mapping[str, object],
    trusted_diff: Mapping[str, object],
    no_upload_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    no_upload_manifest = no_upload_manifest or {}
    sensitive_context_keys = [
        key
        for key in context
        if any(token in str(key).lower() for token in ("token", "secret", "password", "credential", "cookie"))
    ]
    failed_checks = ["trusted-crash-redaction-export-diff-required", "operator-export-ui-smoke-not-attached"]
    if trusted_diff.get("status") == "pass":
        failed_checks = [item for item in failed_checks if item != "trusted-crash-redaction-export-diff-required"]
    return {
        "batch_id": FUNCTIONAL_OPS_BATCH_ID,
        "item_number": 65,
        "implementation_track": "local-crash-reporting",
        "status": "usable-local-redacted-export-review-required",
        "crash_id": crash_id,
        "report_path": str(report_path),
        "implemented_controls": {
            "local_file_written": True,
            "automatic_upload_disabled": True,
            "sensitive_context_redaction": True,
            "runtime_metadata_captured": True,
            "operator_export_required": True,
            "evidence_upload_disabled": True,
            "crash_no_upload_manifest_emitted": bool(no_upload_manifest.get("manifest_hash")),
            "crash_no_upload_manifest_hash": str(no_upload_manifest.get("manifest_hash") or ""),
        },
        "evidence_counts": {
            "context_key_count": len(context),
            "sensitive_context_key_count": len(sensitive_context_keys),
        },
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "crash-no-upload-manifest-emitted": bool(no_upload_manifest.get("manifest_hash")),
                "automatic-upload-disabled": True,
                "operator-export-required": True,
                "sensitive-context-redaction-enabled": True,
            }.items()
            if passed
        ],
        "failed_validation_check_ids": failed_checks,
        "ready_for_commercial_release": False,
    }


def build_crash_report_trusted_diff(
    rapid_report: Mapping[str, object],
    trusted_report: Mapping[str, object],
    *,
    trusted_tool: str = "crash-redaction-checklist",
) -> dict[str, object]:
    compared_fields = [
        "local_only",
        "privacy_note",
        "context",
        "crash_export_evidence_manifest_hash",
        "crash_no_upload_manifest_hash",
        "crash_redaction_matrix_hash",
        "crash_report_grade_validation_plan_hash",
        "export_evidence_slots",
    ]
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_crash_report_value(rapid_report.get(field))
        trusted_value = normalize_crash_report_value(trusted_report.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in CRASH_REPORT_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105,
    }


def crash_report_core_accuracy_gates(
    *,
    crash_id: str,
    report_path: Path,
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
    no_upload_manifest: Mapping[str, object] | None = None,
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = [
        "local crash report written",
        "sensitive context redacted",
        "runtime metadata captured",
        "no-upload policy recorded",
        "operator export limitation disclosed",
    ]
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("crash export evidence manifest hash emitted")
        if evidence_manifest.get("export_evidence_slots"):
            satisfied.append("crash export evidence slots emitted")
        if evidence_manifest.get("redacted_context_keys") is not None:
            satisfied.append("redacted context key manifest emitted")
        if evidence_manifest.get("redaction_matrix_hash"):
            satisfied.append("crash redaction matrix hash emitted")
    if no_upload_manifest:
        if no_upload_manifest.get("manifest_hash"):
            satisfied.append("crash no-upload manifest hash emitted")
        if no_upload_manifest.get("automatic_upload_enabled") is False:
            satisfied.append("automatic crash upload disabled in manifest")
    if report_grade_validation_plan:
        if report_grade_validation_plan.get("validation_plan_hash"):
            satisfied.append("crash report-grade validation plan")
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) > 0:
            satisfied.append("crash report-grade ready slots")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted crash redaction/export diff pass")
    evidence_refs = [f"crash_id:{crash_id}", f"path:{report_path}"]
    if no_upload_manifest and no_upload_manifest.get("manifest_hash"):
        evidence_refs.append(f"crash_no_upload_manifest_sha256:{no_upload_manifest['manifest_hash']}")
    if evidence_manifest and evidence_manifest.get("redaction_matrix_hash"):
        evidence_refs.append(f"crash_redaction_matrix_sha256:{evidence_manifest['redaction_matrix_hash']}")
    if report_grade_validation_plan and report_grade_validation_plan.get("validation_plan_hash"):
        evidence_refs.append(
            f"crash_report_grade_validation_plan_sha256:{report_grade_validation_plan['validation_plan_hash']}"
        )
        evidence_refs.append(f"crash_report_grade_ready_slots:{report_grade_validation_plan.get('ready_slot_count')}")
        evidence_refs.append(
            f"crash_report_grade_blocking_slots:{report_grade_validation_plan.get('blocking_slot_count')}"
        )
    return [
        build_accuracy_gate(
            105,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def normalize_crash_report_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def stable_crash_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def build_crash_export_evidence_manifest(
    payload: Mapping[str, object],
    *,
    report_path: Path,
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    context = payload.get("context") if isinstance(payload.get("context"), Mapping) else {}
    runtime = payload.get("runtime") if isinstance(payload.get("runtime"), Mapping) else {}
    redacted_keys = sorted(key for key, value in dict(context).items() if value == "<redacted>")
    redaction_matrix = build_crash_redaction_matrix(context)
    manifest: dict[str, object] = {
        "profile_version": "crash-export-evidence-manifest-v1",
        "item_number": 105,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "commercial_claim_allowed": False,
        "crash_id": payload.get("crash_id"),
        "report_path": str(report_path),
        "local_only": bool(payload.get("local_only")),
        "no_upload_policy": payload.get("privacy_note"),
        "runtime_metadata_hash": stable_crash_sha256(runtime),
        "context_key_count": len(context),
        "redacted_context_keys": redacted_keys,
        "redaction_matrix": redaction_matrix,
        "redaction_matrix_hash": redaction_matrix["matrix_hash"],
        "export_evidence_slots": {
            "operator_export_ui_smoke": {
                "status": "not-attached",
                "expected_material": "Operator crash-export UI smoke transcript and exported crash bundle hash",
                "required_before_commercial_claim": True,
            },
            "redaction_checklist": {
                "status": "not-attached",
                "expected_material": "Trusted redaction checklist proving sensitive context never leaves the local report unredacted",
                "required_before_commercial_claim": True,
            },
            "enterprise_no_upload_review": {
                "status": "not-attached",
                "expected_material": "Enterprise policy review proving RapidTriage does not auto-upload crash reports",
                "required_before_commercial_claim": True,
            },
            "trend_dashboard_review": {
                "status": "not-attached",
                "expected_material": "Crash trend dashboard/export review if centralized reporting is enabled later",
                "required_before_commercial_claim": True,
            },
        },
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105],
    }
    manifest["manifest_hash"] = stable_crash_sha256(manifest)
    return manifest


def build_crash_redaction_matrix(context: Mapping[str, object]) -> dict[str, object]:
    rows = []
    for key in sorted(context):
        value = context[key]
        row_core = {
            "key": str(key),
            "redacted": value == "<redacted>",
            "value_hash": stable_crash_sha256(str(value)),
            "value_length": len(str(value)),
        }
        rows.append({**row_core, "row_hash": stable_crash_sha256(row_core)})
    matrix: dict[str, object] = {
        "profile_version": "crash-redaction-matrix-v1",
        "item_number": 105,
        "context_key_count": len(rows),
        "redacted_key_count": sum(1 for row in rows if row["redacted"]),
        "rows": rows,
        "commercial_claim_allowed": False,
    }
    matrix["matrix_hash"] = stable_crash_sha256(matrix)
    return matrix


def build_crash_no_upload_manifest(
    payload: Mapping[str, object],
    *,
    report_path: Path,
    export_manifest: Mapping[str, object],
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "profile_version": "crash-no-upload-manifest-v1",
        "item_number": 65,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "crash_id": payload.get("crash_id"),
        "report_path": str(report_path),
        "local_only": bool(payload.get("local_only")),
        "automatic_upload_enabled": False,
        "operator_export_required": True,
        "known_upload_endpoint_count": 0,
        "known_upload_endpoints": [],
        "privacy_note_hash": stable_crash_sha256(str(payload.get("privacy_note") or "")),
        "export_manifest_hash": export_manifest.get("manifest_hash", ""),
        "redacted_context_key_count": len(export_manifest.get("redacted_context_keys") or []),
        "storage_boundary": {
            "write_location": str(report_path.parent),
            "network_required": False,
            "operator_action_required_for_export": True,
            "centralized_reporting_enabled": False,
        },
        "commercial_blockers": [
            "operator-export-ui-smoke-not-attached",
            "trusted-crash-redaction-export-diff-required",
            "enterprise-no-upload-review-not-attached",
        ],
        "validation_status": "implemented-usable-external-export-smoke-required",
    }
    manifest["manifest_hash"] = stable_crash_sha256(manifest)
    return manifest


def build_crash_report_grade_validation_plan(
    payload: Mapping[str, object],
    *,
    report_path: Path,
    evidence_manifest: Mapping[str, object],
    no_upload_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    export_slots = (
        evidence_manifest.get("export_evidence_slots")
        if isinstance(evidence_manifest.get("export_evidence_slots"), Mapping)
        else {}
    )
    ready_slots = [
        {
            "slot_id": "local-crash-report-json",
            "status": "ready",
            "evidence_ref": "crash_report_path",
            "evidence_hash": stable_crash_sha256(str(report_path)),
        },
        {
            "slot_id": "redaction-matrix",
            "status": "ready",
            "evidence_ref": "crash_redaction_matrix_hash",
            "evidence_hash": str(evidence_manifest.get("redaction_matrix_hash") or ""),
        },
        {
            "slot_id": "export-evidence-manifest",
            "status": "ready",
            "evidence_ref": "crash_export_evidence_manifest_hash",
            "evidence_hash": str(evidence_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "no-upload-manifest",
            "status": "ready",
            "evidence_ref": "crash_no_upload_manifest_hash",
            "evidence_hash": str(no_upload_manifest.get("manifest_hash") or ""),
        },
        {
            "slot_id": "local-dashboard-and-api",
            "status": "ready",
            "evidence_ref": "/api/crash-reports + /api/crash-reports/{crash_id}/export",
            "evidence_hash": stable_crash_sha256("local crash dashboard/list/detail/export API"),
        },
        {
            "slot_id": "release-smoke-tooling",
            "status": "ready",
            "evidence_ref": "scripts/crash-export-smoke.py",
            "evidence_hash": stable_crash_sha256("crash-export-release-smoke-v1"),
        },
        {
            "slot_id": "redaction-review-tooling",
            "status": "ready",
            "evidence_ref": "scripts/crash-redaction-review.py",
            "evidence_hash": stable_crash_sha256("crash-redaction-export-review-v1"),
        },
        {
            "slot_id": "trusted-diff-boundary",
            "status": "ready" if trusted_diff.get("status") == "pass" else "ready-with-blocker",
            "evidence_ref": "trusted_crash_report_diff",
            "evidence_hash": stable_crash_sha256(trusted_diff),
        },
    ]
    blocking_slots = []
    if trusted_diff.get("status") != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-crash-redaction-export-diff",
                "status": "blocking",
                "blocker": CRASH_REPORT_TRUSTED_DIFF_BLOCKER_105,
                "required_evidence": "trusted redaction/export diff from an approved checklist or release smoke log",
            }
        )
    for slot_id, blocker, required_evidence in (
        (
            "operator-crash-export-ui-smoke",
            "operator-crash-export-ui-smoke-required",
            "operator transcript and bundle hash proving the release UI can export a local crash report",
        ),
        (
            "trusted-crash-redaction-checklist",
            "trusted-crash-redaction-checklist-required",
            "reviewer checklist proving sensitive values are redacted in report JSON and export ZIP",
        ),
        (
            "enterprise-no-upload-review",
            "enterprise-no-upload-review-required",
            "enterprise policy/no-network review proving crash reports are not uploaded automatically",
        ),
        (
            "release-host-crash-export-smoke",
            "release-host-crash-export-smoke-required",
            "crash-export-release-smoke-v1 JSON generated on the actual signed release host",
        ),
        (
            "independent-redaction-review",
            "independent-redaction-review-required",
            "independent reviewer or lab rerun of the crash redaction/export review",
        ),
        (
            "signed-release-build-evidence",
            "signed-release-build-evidence-required",
            "signed release artifact set and hashes used for the crash smoke/review run",
        ),
        (
            "crash-dashboard-release-smoke",
            "crash-dashboard-release-smoke-required",
            "release-host dashboard/list/detail/export smoke transcript for crash reports",
        ),
    ):
        slot = export_slots.get(slot_id.replace("operator-crash-export-ui-smoke", "operator_export_ui_smoke"))
        status = str((slot or {}).get("status") or "not-attached") if isinstance(slot, Mapping) else "not-attached"
        blocking_slots.append(
            {
                "slot_id": slot_id,
                "status": "blocking",
                "current_attachment_status": status,
                "blocker": blocker,
                "required_evidence": required_evidence,
            }
        )
    blockers = sorted({str(slot["blocker"]) for slot in blocking_slots if slot.get("blocker")})
    plan: dict[str, object] = {
        "profile_version": CRASH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 105,
        "commercial_gap_ids": [CRASH_REPORTING_GAP_ID],
        "commercial_claim_allowed": False,
        "crash_id": payload.get("crash_id"),
        "report_path": str(report_path),
        "reporting_boundary": "local-only crash reports are usable; commercial crash-reporting claims require attached release-host smoke and independent redaction/no-upload proof",
        "crash_export_evidence_manifest_hash": str(evidence_manifest.get("manifest_hash") or ""),
        "crash_redaction_matrix_hash": str(evidence_manifest.get("redaction_matrix_hash") or ""),
        "crash_no_upload_manifest_hash": str(no_upload_manifest.get("manifest_hash") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or ""),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "external_blocker_catalog": list(CRASH_REPORT_GRADE_BLOCKERS),
        "blockers": blockers,
        "report_use_warning": "Use as local crash-reporting evidence only; do not claim commercial crash reporting until blocking slots are satisfied.",
    }
    plan["validation_plan_hash"] = stable_crash_sha256(plan)
    return plan


def sanitize_context(context: Mapping[str, object]) -> dict[str, object]:
    sanitized: dict[str, object] = {}
    for key, value in context.items():
        text = str(value)
        lowered = key.lower()
        if any(token in lowered for token in ("token", "secret", "password", "credential", "cookie")):
            sanitized[key] = "<redacted>"
        elif len(text) > 500:
            sanitized[key] = text[:500] + "...<truncated>"
        else:
            sanitized[key] = value
    return sanitized
