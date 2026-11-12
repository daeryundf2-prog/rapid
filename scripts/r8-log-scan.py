#!/usr/bin/env python3
"""Scan logs and error responses for leaked paths, secrets and personal identifiers (R8 T-003).

Prints hit COUNTS per pattern and file only; matched text is never printed or written, so
the report itself cannot leak what it found. Exit 1 when any pattern hits.

  python scripts/r8-log-scan.py D:/qa/server.log D:/qa/responses/ --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024


def _luhn_ok(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# name -> (regex, optional validator on the matched text)
PATTERNS: dict[str, tuple[re.Pattern[str], object]] = {
    # user profile folders (the card's `[A-Za-z]:\\Users\\[^\\]+`, plus / and JSON-escaped \\)
    "windows_user_path": (
        re.compile(
            r"[A-Za-z]:(?:\\\\|\\|/)Users(?:\\\\|\\|/)[^\\/\s\"']+", re.IGNORECASE
        ),
        None,
    ),
    "posix_home_path": (re.compile(r"(?<![\w.])/(?:home|Users)/[A-Za-z0-9._-]+"), None),
    "aws_access_key": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    "github_token": (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), None),
    "openai_style_key": (re.compile(r"\bsk-(?:[A-Za-z0-9_-]{20,})\b"), None),
    "slack_token": (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), None),
    "bearer_token": (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"), None),
    "private_key_block": (
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
        None,
    ),
    "secret_assignment": (
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password|passwd|token)\b[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{8,}"
        ),
        None,
    ),
    "kr_resident_number": (
        re.compile(
            r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[1-8]\d{6}(?!\d)"
        ),
        None,
    ),
    "card_number": (re.compile(r"(?<!\d)(?:\d{4}[- ]?){3}\d{1,7}(?!\d)"), _luhn_ok),
}


def scan_text(text: str) -> dict[str, int]:
    hits: dict[str, int] = {}
    for name, (rx, validator) in PATTERNS.items():
        n = sum(
            1 for m in rx.finditer(text) if validator is None or validator(m.group(0))
        )
        if n:
            hits[name] = n
    return hits


def iter_files(paths: list[Path]):
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            yield path
        else:
            raise SystemExit(f"not found: {path}")


def scan_paths(paths: list[Path]) -> dict:
    per_file = []
    totals: dict[str, int] = {}
    for path in iter_files(paths):
        with path.open("rb") as fh:
            data = fh.read(MAX_BYTES)
        hits = scan_text(data.decode("utf-8", errors="replace"))
        per_file.append(
            {
                "file": str(path),
                "hits": hits,
                "truncated": path.stat().st_size > MAX_BYTES,
            }
        )
        for k, v in hits.items():
            totals[k] = totals.get(k, 0) + v
    return {
        "files_scanned": len(per_file),
        "total_hits": sum(totals.values()),
        "by_pattern": totals,
        "files": per_file,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="+", type=Path, help="log files or folders")
    ap.add_argument("--output", type=Path, help="write the count report JSON here")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    report = scan_paths(args.paths)
    if args.output:
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"files {report['files_scanned']} · hits {report['total_hits']}")
        for name, n in sorted(report["by_pattern"].items()):
            print(f"  {name}: {n}")
    return 1 if report["total_hits"] else 0


if __name__ == "__main__":
    sys.exit(main())
