#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rapidtriage.core.crash import build_crash_report_trusted_diff


def stable_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review crash export smoke evidence for redaction/no-upload controls")
    parser.add_argument("smoke_json", help="Path to crash-export-smoke.json")
    parser.add_argument("--output", help="Review JSON output path")
    parser.add_argument("--json", action="store_true", help="Print the review payload as JSON")
    args = parser.parse_args(argv)

    smoke_path = Path(args.smoke_json).expanduser().resolve()
    smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
    bundle_path = Path(str(smoke.get("export_bundle_path", ""))).expanduser().resolve()
    if not bundle_path.is_file():
        raise SystemExit(f"export bundle not found: {bundle_path}")

    with zipfile.ZipFile(bundle_path) as bundle:
        members = sorted(bundle.namelist())
        manifest = json.loads(bundle.read("crash-export-manifest.json").decode("utf-8"))
        crash_id = str(smoke.get("crash_id") or manifest.get("crash_id") or "")
        report_text = bundle.read(f"{crash_id}.json").decode("utf-8")
        report_payload: dict[str, Any] = json.loads(report_text)

    trusted_diff = build_crash_report_trusted_diff(report_payload, report_payload, trusted_tool="local-crash-export-log")
    redaction_matrix = report_payload.get("crash_redaction_matrix") if isinstance(report_payload.get("crash_redaction_matrix"), dict) else {}
    checks = {
        "smoke_checks_passed": not smoke.get("failed_check_ids"),
        "bundle_hash_matches_smoke": hashlib.sha256(bundle_path.read_bytes()).hexdigest() == smoke.get("export_bundle_sha256"),
        "manifest_hash_matches_smoke": manifest.get("manifest_hash") == smoke.get("export_manifest_hash"),
        "manifest_is_local_only": manifest.get("local_only") is True,
        "manifest_no_automatic_upload": manifest.get("automatic_upload_enabled") is False,
        "redacted_report_in_bundle": f"{report_payload.get('crash_id')}.json" in members,
        "sensitive_tokens_absent": all(token not in report_text for token in ("release-secret-token", "secret-value")),
        "redaction_matrix_has_hash": bool(report_payload.get("crash_redaction_matrix_hash")),
        "report_grade_plan_has_hash": bool(report_payload.get("crash_report_grade_validation_plan_hash")),
        "manifest_preserves_report_grade_hash": manifest.get("crash_report_grade_validation_plan_hash")
        == report_payload.get("crash_report_grade_validation_plan_hash"),
        "redacted_key_count_recorded": int(redaction_matrix.get("redacted_key_count") or 0) >= 1,
        "trusted_diff_passes": trusted_diff.get("status") == "pass",
    }
    review: dict[str, object] = {
        "command": "crash-redaction-review",
        "profile_version": "crash-redaction-export-review-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": ["#105"],
        "smoke_json": str(smoke_path),
        "smoke_hash": hashlib.sha256(smoke_path.read_bytes()).hexdigest(),
        "export_bundle_path": str(bundle_path),
        "export_bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        "crash_id": report_payload.get("crash_id"),
        "crash_report_grade_validation_plan_hash": report_payload.get("crash_report_grade_validation_plan_hash", ""),
        "crash_report_grade_ready_slot_count": report_payload.get("crash_report_grade_ready_slot_count", 0),
        "crash_report_grade_blocking_slot_count": report_payload.get("crash_report_grade_blocking_slot_count", 0),
        "review_tool": "local-crash-export-log",
        "trusted_crash_report_diff": trusted_diff,
        "checks": checks,
        "passed_check_count": sum(1 for passed in checks.values() if passed),
        "failed_check_ids": [name for name, passed in checks.items() if not passed],
        "commercial_claim_allowed": False,
        "remaining_external_validation": [
            "Have an independent reviewer or lab rerun this review on the signed release artifact set.",
            "Attach reviewer identity/signoff before commercial crash-reporting claims.",
        ],
    }
    review["review_hash"] = stable_hash(review)
    output = Path(args.output).expanduser().resolve() if args.output else smoke_path.with_name("crash-redaction-review.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(review, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote crash redaction/export review: {output}")
    return 0 if not review["failed_check_ids"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
