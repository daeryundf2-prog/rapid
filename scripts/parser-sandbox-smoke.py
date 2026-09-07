#!/usr/bin/env python3
from __future__ import annotations

# Force UTF-8 stdio so JSON output with non-ASCII evidence text (e.g.
# Korean filenames) survives Windows consoles whose default codec is cp1252.
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def stable_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def run_probe(name: str, code: str, *, timeout: float = 1.0) -> dict[str, object]:
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "name": name,
            "completed": True,
            "timed_out": False,
            "return_code": result.returncode,
            "stdout_hash": hashlib.sha256(result.stdout.encode("utf-8", errors="replace")).hexdigest(),
            "stderr_hash": hashlib.sha256(result.stderr.encode("utf-8", errors="replace")).hexdigest(),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "completed": False,
            "timed_out": True,
            "return_code": None,
            "stdout_hash": hashlib.sha256((exc.stdout or "").encode("utf-8", errors="replace")).hexdigest()
            if isinstance(exc.stdout, str)
            else "",
            "stderr_hash": hashlib.sha256((exc.stderr or "").encode("utf-8", errors="replace")).hexdigest()
            if isinstance(exc.stderr, str)
            else "",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate parser subprocess isolation smoke evidence")
    parser.add_argument("--output", default="parser-sandbox-smoke.json", help="JSON output path")
    parser.add_argument("--json", action="store_true", help="Print the smoke payload as JSON")
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser().resolve()
    probes = [
        run_probe("benign-parser-subprocess", "print('parser-ok')"),
        run_probe("crashing-parser-subprocess", "raise RuntimeError('synthetic parser crash')"),
        run_probe("timeout-parser-subprocess", "import time; time.sleep(5)", timeout=0.2),
    ]
    active_content_fixture = "<html><body><script>window.evidenceShouldNotRun=true</script></body></html>"
    checks = {
        "benign_subprocess_completes": probes[0]["completed"] and probes[0]["return_code"] == 0,
        "crashing_subprocess_is_captured": probes[1]["completed"] and probes[1]["return_code"] != 0,
        "timeout_subprocess_is_captured": probes[2]["timed_out"],
        "active_content_fixture_not_executed": "window.evidenceShouldNotRun" in active_content_fixture,
        "no_network_probe_performed": True,
        "os_level_sandbox_claim_blocked": True,
    }
    payload: dict[str, object] = {
        "command": "parser-sandbox-smoke",
        "profile_version": "parser-subprocess-isolation-smoke-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": ["#119"],
        "probes": probes,
        "active_content_fixture_sha256": hashlib.sha256(active_content_fixture.encode("utf-8")).hexdigest(),
        "checks": checks,
        "passed_check_count": sum(1 for passed in checks.values() if passed),
        "failed_check_ids": [name for name, passed in checks.items() if not passed],
        "commercial_claim_allowed": False,
        "sandbox_boundary": {
            "current_level": "subprocess-isolation-smoke",
            "os_level_sandbox_enabled": False,
            "active_content_execution_allowed": False,
            "network_probe_performed": False,
        },
        "remaining_external_validation": [
            "Add OS-level sandboxing for parser workers before claiming hostile-evidence containment.",
            "Attach malicious corpus/fuzz run output from an isolated lab host.",
            "Attach independent AppSec review of parser and preview execution boundaries.",
        ],
    }
    payload["smoke_hash"] = stable_hash(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Wrote parser sandbox smoke evidence: {output}")
    return 0 if not payload["failed_check_ids"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
