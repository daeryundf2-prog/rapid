#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID = "#120"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a local dependency vulnerability monitoring baseline")
    parser.add_argument("--output", default="dependency-monitoring.json", help="JSON output path")
    args = parser.parse_args(argv)

    output = Path(args.output).expanduser().resolve()
    pip_list = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        text=True,
        capture_output=True,
        check=False,
    )
    pip_audit = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--format=json"],
        text=True,
        capture_output=True,
        check=False,
    )
    payload = {
        "command": "dependency-monitoring",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
        "python": sys.executable,
        "pip_list": {
            "return_code": pip_list.returncode,
            "packages": json.loads(pip_list.stdout) if pip_list.returncode == 0 and pip_list.stdout.strip() else [],
            "error": pip_list.stderr.strip(),
        },
        "vulnerability_scan": {
            "commercial_gap_ids": [DEPENDENCY_VULNERABILITY_MONITORING_GAP_ID],
            "tool": "pip-audit",
            "available": pip_audit.returncode != 1 or bool(pip_audit.stdout.strip()),
            "return_code": pip_audit.returncode,
            "raw_output": pip_audit.stdout[:20000],
            "error": pip_audit.stderr[:4000],
            "release_policy": "Block release on known exploitable high/critical dependency issues unless a documented exception is approved.",
        },
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote dependency monitoring baseline: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
