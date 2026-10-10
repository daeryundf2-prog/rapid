#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["windowsprefetch>=4.0.0"]
# ///
# --- How to run ---
#   uv run scripts/prefetch-reference-diff.py --pf-root <dir> --output <report.json> --json
#
# Diffs RapidTriage native prefetch header parsing against the
# independent `windowsprefetch` parser on real .pf files. Compares per
# file: SCCA version, executable name, run count, and the last-run
# timestamp set.
#
# Engineering measurement only; windowsprefetch is not in the recognized
# trusted-tool list, so results stay engineering_check_only.
# ------------------
from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.prefetch import prefetch_header_hints

COMPARE_FIELDS = ("prefetch_version", "executable_name", "run_count")


def _canon_ts(value: object) -> str:
    text = str(value or "").replace(" ", "T", 1)
    if not text or text in ("None", "NoneType"):
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    truncated = parsed.replace(microsecond=(parsed.microsecond // 1000) * 1000)
    return truncated.isoformat()


def _canon_name(value: object) -> str:
    return str(value or "").strip().lower()


def rapid_fields(path: Path) -> dict[str, object]:
    hints = prefetch_header_hints(path)
    return {
        "prefetch_version": str(hints.get("prefetch_version") or ""),
        "executable_name": _canon_name(hints.get("header_executable_name")),
        "run_count": str(hints.get("run_count") or ""),
        "last_run_at": _canon_ts(hints.get("last_run_at")),
        "run_times": sorted(
            _canon_ts(ts) for ts in (hints.get("last_run_times") or []) if _canon_ts(ts)
        ),
        "binary_format_detected": bool(hints.get("binary_format_detected")),
    }


def trusted_fields(path: Path) -> dict[str, object]:
    from windowsprefetch import Prefetch

    pf = Prefetch(str(path))
    run_times = sorted(
        _canon_ts(ts) for ts in (pf.timestamps or []) if _canon_ts(ts)
    )
    return {
        "prefetch_version": str(getattr(pf, "version", "") or ""),
        "executable_name": _canon_name(getattr(pf, "executableName", "")),
        "run_count": str(getattr(pf, "runCount", "") or ""),
        "last_run_at": run_times[-1] if run_times else "",
        "run_times": run_times,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pf-root", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=200)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    files = sorted(
        p
        for p in args.pf_root.rglob("*.pf")
        if p.is_file() and p.stat().st_size > 0x100
    )[: args.max_files]

    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(str(path.stat().st_size).encode())

    per_file: list[dict[str, object]] = []
    totals = {
        "files": 0,
        "matched": 0,
        "mismatch": 0,
        "one_sided": 0,
        "rapid_failures": 0,
        "trusted_failures": 0,
        "errors": [],
    }
    field_totals: dict[str, int] = {}
    run_time_match = 0
    last_run_match = 0

    for path in files:
        try:
            rapid = rapid_fields(path)
        except Exception as exc:
            totals["rapid_failures"] += 1
            totals["errors"].append({"file": str(path), "side": "rapid", "error": str(exc)[:200]})
            continue
        try:
            trusted = trusted_fields(path)
        except Exception as exc:
            totals["trusted_failures"] += 1
            totals["errors"].append({"file": str(path), "side": "trusted", "error": str(exc)[:200]})
            continue

        totals["files"] += 1
        field_diffs = []
        one_sided = []
        for name in COMPARE_FIELDS:
            rv = rapid.get(name, "")
            tv = trusted.get(name, "")
            if rv == tv:
                continue
            row = {"field": name, "rapid": rv, "trusted": tv}
            if rv and tv:
                field_diffs.append(row)
                field_totals[name] = field_totals.get(name, 0) + 1
            else:
                one_sided.append(row)

        if rapid["last_run_at"] == trusted["last_run_at"]:
            last_run_match += 1
        elif rapid["last_run_at"] and trusted["last_run_at"]:
            field_diffs.append(
                {
                    "field": "last_run_at",
                    "rapid": rapid["last_run_at"],
                    "trusted": trusted["last_run_at"],
                }
            )
            field_totals["last_run_at"] = field_totals.get("last_run_at", 0) + 1
        else:
            one_sided.append(
                {
                    "field": "last_run_at",
                    "rapid": rapid["last_run_at"],
                    "trusted": trusted["last_run_at"],
                }
            )

        # Run-time sets: rapid parses a bounded slot list; trusted may
        # decode all eight. Subset-consistency rather than set equality.
        rapid_times = set(rapid["run_times"])
        trusted_times = set(trusted["run_times"])
        if rapid_times == trusted_times:
            run_time_match += 1
        elif rapid_times <= trusted_times:
            field_totals["run_times_subset"] = field_totals.get("run_times_subset", 0) + 1
        else:
            field_diffs.append(
                {
                    "field": "run_times-conflict",
                    "rapid": sorted(rapid_times - trusted_times)[:10],
                    "trusted": sorted(trusted_times)[:10],
                }
            )
            field_totals["run_times-conflict"] = field_totals.get("run_times-conflict", 0) + 1

        if field_diffs:
            totals["mismatch"] += 1
            status = "diffs-present"
        elif one_sided:
            totals["one_sided"] += 1
            status = "one-sided-fields"
        else:
            totals["matched"] += 1
            status = "match"
        per_file.append(
            {
                "file": path.name,
                "rapid_format_detected": rapid["binary_format_detected"],
                "field_diffs": field_diffs[:10],
                "one_sided_fields": one_sided[:10],
                "status": status,
            }
        )

    compared = totals["matched"] + totals["mismatch"]
    report = {
        "schema_version": "prefetch-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native prefetch header parse vs windowsprefetch on "
            "real .pf files. windowsprefetch is not on the recognized "
            "trusted-tool list; results are engineering evidence only."
        ),
        "pf_root": str(args.pf_root),
        "pf_root_sha256_dir_listing": digest.hexdigest(),
        "totals": totals,
        "field_match_rate": round(totals["matched"] / compared, 6) if compared else None,
        "last_run_at_match": last_run_match,
        "run_times_exact_match": run_time_match,
        "field_diff_counts": field_totals,
        "timestamp_normalization": "truncated-to-milliseconds",
        "per_file_diffs": [item for item in per_file if item["status"] != "match"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(
            f"files={totals['files']} matched={totals['matched']} mismatch={totals['mismatch']} "
            f"one_sided={totals['one_sided']} rapid_fail={totals['rapid_failures']} "
            f"trusted_fail={totals['trusted_failures']}"
        )
        print(f"-> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
