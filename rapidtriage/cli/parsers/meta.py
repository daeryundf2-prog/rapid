"""Parser registration for doctor, policy, worker and plugin commands."""

from __future__ import annotations

import argparse
import textwrap


def register_system(sub: argparse._SubParsersAction) -> None:
    """Register doctor, audit-verify, enterprise-policy, rearchitecture-status, worker-parse."""
    doctor = sub.add_parser(
        "doctor",
        help="Check local runtime, optional tools, storage, and web UI assets",
        description="Check local runtime, optional tools, storage, and web UI assets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage doctor
              rapidtriage doctor --json
              rapidtriage doctor --host 127.0.0.1 --port 8765 --strict
            """
        ),
    )
    doctor.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    doctor.add_argument("--host", default="127.0.0.1", help="Host to check for web port availability")
    doctor.add_argument("--port", type=int, default=8765, help="Port to check for web server availability")
    doctor.add_argument("--app-data-dir", help="Override the app data directory to probe")
    doctor.add_argument("--no-write-probe", action="store_true", help="Do not create a temporary write probe file")
    doctor.add_argument("--strict", action="store_true", help="Return exit code 1 when any doctor check is error")

    # T-359: export audit chain check (handler: cli/audit_verify.py).
    audit_verify = sub.add_parser(
        "audit-verify",
        help="Verify an export audit chain (exit 0 intact, 3 broken, 4 missing)",
        description="Verify the hash chain of an export audit file (rapidtriage-export-audit.jsonl or an .audit sidecar)",
    )
    audit_verify.add_argument("audit_file", help="Export audit file to verify")
    audit_verify.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    enterprise_policy = sub.add_parser(
        "enterprise-policy",
        help="Print local-only enterprise/security policy status",
        description="Print local-only enterprise policy status for telemetry, license, RBAC, and collaboration readiness",
    )
    enterprise_policy.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    rearchitecture_status = sub.add_parser(
        "rearchitecture-status",
        help="Evaluate Python/Rust commercial re-architecture progress",
        description="Evaluate the staged Python/Rust re-architecture plan, worker foundation, storage foundation, and local blockers",
    )
    rearchitecture_status.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    worker_parse = sub.add_parser(
        "worker-parse",
        help="Run an isolated Rust parser worker and store ArtifactRecordV1 JSONL",
        description="Run rapid-worker as an isolated parser process and stream normalized ArtifactRecordV1 rows to JSONL",
    )
    worker_parse.add_argument("source", help="Evidence source path for the worker")
    worker_parse.add_argument("--kind", required=True, help="Worker parser kind, e.g. noop or file-inventory")
    worker_parse.add_argument("--output", required=True, help="ArtifactRecordV1 JSONL output path")
    worker_parse.add_argument("--worker", help="Path to rapid-worker executable; defaults to RAPIDTRIAGE_RUST_WORKER or PATH")
    worker_parse.add_argument("--case-id", default="CASE", help="Case ID to pass to the worker")
    worker_parse.add_argument("--source-id", default="SOURCE", help="Source ID to pass to the worker")
    worker_parse.add_argument("--timeout-seconds", type=float, default=30.0, help="Worker timeout in seconds")
    worker_parse.add_argument("--extra-arg", action="append", default=[], help="Extra raw argument for the worker; repeat as needed")
    worker_parse.add_argument("--json", action="store_true", help="Print machine-readable JSON")


def register_plugins(sub: argparse._SubParsersAction) -> None:
    """Register plugins, keyword-packs."""
    plugins = sub.add_parser(
        "plugins",
        help="List or validate RapidTriage plugin manifests",
        description="List or validate RapidTriage plugin manifests",
    )
    plugins.add_argument("--plugin-dir", action="append", help="Directory containing plugin.json files")
    plugins.add_argument("--validate", help="Validate one plugin.json manifest")
    plugins.add_argument("--list", action="store_true", help="List built-in and discovered plugins")
    plugins.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    keyword_packs = sub.add_parser(
        "keyword-packs",
        help="List built-in keyword packs for repeatable searches",
        description="List built-in keyword packs for credentials, execution, network, browser/AI, and Windows IR review",
    )
    keyword_packs.add_argument("--json", action="store_true", help="Print machine-readable JSON")
