#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rapidtriage.core.crash import export_crash_report_bundle, list_crash_reports, write_crash_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate local-only crash export smoke evidence")
    parser.add_argument("--output-dir", default="crash-export-smoke", help="Directory for crash reports and smoke log")
    parser.add_argument("--json", action="store_true", help="Print the smoke payload as JSON")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir).expanduser().resolve()
    crash_dir = output_dir / "crash-reports"
    export_dir = output_dir / "exports"
    output_dir.mkdir(parents=True, exist_ok=True)

    report = write_crash_report(
        RuntimeError("release smoke crash"),
        context={
            "component": "release-smoke",
            "path": "/release/smoke/crash-export",
            "auth_token": "release-secret-token",
            "case_path": str(output_dir / "case-placeholder"),
        },
        output_dir=crash_dir,
    )
    listing = list_crash_reports(output_dir=crash_dir, limit=25)
    export = export_crash_report_bundle(report["crash_id"], output_dir=crash_dir, export_dir=export_dir)
    bundle_path = Path(str(export["bundle_path"]))
    bundle_members = []
    manifest_payload: dict[str, object] = {}
    with zipfile.ZipFile(bundle_path) as archive:
        bundle_members = sorted(archive.namelist())
        manifest_payload = json.loads(archive.read("crash-export-manifest.json").decode("utf-8"))
        report_text = archive.read(f"{report['crash_id']}.json").decode("utf-8")

    checks = {
        "crash_report_written": Path(str(report["path"])).is_file(),
        "dashboard_lists_report": any(item.get("crash_id") == report["crash_id"] for item in listing["reports"]),
        "dashboard_local_only": listing["crash_trend_dashboard"]["automatic_upload_enabled"] is False,
        "export_bundle_written": bundle_path.is_file(),
        "export_manifest_present": "crash-export-manifest.json" in bundle_members,
        "redacted_report_present": f"{report['crash_id']}.json" in bundle_members,
        "secret_redacted": "release-secret-token" not in report_text,
        "bundle_hash_verified": hashlib.sha256(bundle_path.read_bytes()).hexdigest() == export["bundle_sha256"],
        "manifest_hash_preserved": manifest_payload.get("manifest_hash") == export["manifest_hash"],
        "no_automatic_upload": export["automatic_upload_enabled"] is False,
    }
    payload: dict[str, object] = {
        "command": "crash-export-smoke",
        "profile_version": "crash-export-release-smoke-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": ["#105"],
        "output_dir": str(output_dir),
        "crash_id": report["crash_id"],
        "crash_report_path": report["path"],
        "crash_report_sha256": hashlib.sha256(Path(str(report["path"])).read_bytes()).hexdigest(),
        "dashboard_hash": listing["crash_trend_dashboard"]["dashboard_hash"],
        "export_bundle_path": str(bundle_path),
        "export_bundle_sha256": export["bundle_sha256"],
        "export_manifest_hash": export["manifest_hash"],
        "bundle_members": bundle_members,
        "checks": checks,
        "passed_check_count": sum(1 for passed in checks.values() if passed),
        "failed_check_ids": [name for name, passed in checks.items() if not passed],
        "commercial_claim_allowed": False,
        "remaining_external_validation": [
            "Attach this smoke JSON from the actual release build host.",
            "Attach trusted redaction/export review before commercial crash-reporting claims.",
        ],
    }
    payload["smoke_hash"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    smoke_path = output_dir / "crash-export-smoke.json"
    smoke_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote crash export smoke evidence: {smoke_path}")
    return 0 if not payload["failed_check_ids"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
