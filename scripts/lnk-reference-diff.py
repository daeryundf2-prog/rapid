#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["LnkParse3>=1.5.0"]
# ///
# --- How to run ---
#   uv run scripts/lnk-reference-diff.py --lnk-root <dir> --output <report.json> --json
#
# Diffs RapidTriage native LNK parsing (recent_files.parse_lnk_metadata)
# against LnkParse3 on real .lnk files. Compares per file: target path,
# target timestamps, target file size, relative path.
#
# Engineering measurement only; LnkParse3 is not in the recognized
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
import os
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.artifacts.windows.recent_files import parse_lnk_metadata

MAX_FILES_DEFAULT = 200
COMPARE_FIELDS = (
    "target_path",
    "relative_path",
    "target_created_at",
    "target_modified_at",
    "target_accessed_at",
    "target_file_size",
)


def _canon_ts(value: object) -> str:
    text = str(value or "").replace(" ", "T", 1)
    if not text or text in ("None", "NoneType"):
        return ""
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    truncated = parsed.replace(microsecond=(parsed.microsecond // 1000) * 1000)
    return truncated.isoformat()


def _canon_path(value: object) -> str:
    return str(value or "").strip().replace("/", "\\").rstrip("\\")


def _join_base_suffix(base: str, suffix: str) -> str:
    # Mirror RapidTriage's MS-SHLLINK reconstruction: append
    # CommonPathSuffix unless LocalBasePath already ends with it.
    if not base:
        return suffix
    if not suffix or base.lower().endswith(suffix.lower()):
        return base
    return base.rstrip("\\") + "\\" + suffix.lstrip("\\")


def _trusted_ansi(text: str) -> str:
    # LnkParse3 decodes ANSI fields as latin-1; re-decode with the host
    # ANSI codepage (mbcs) to recover the writer's original characters.
    if not text or all(ord(ch) < 0x80 for ch in text):
        return text
    try:
        raw = text.encode("latin-1")
    except UnicodeEncodeError:
        return text
    try:
        return raw.decode("mbcs", errors="ignore") if os.name == "nt" else text
    except LookupError:
        return text


def rapid_fields(path: Path) -> dict[str, str]:
    meta = parse_lnk_metadata(path)
    return {
        "lnk_parse_status": str(meta.get("lnk_parse_status") or ""),
        "target_path": _canon_path(meta.get("target_path")),
        "relative_path": _canon_path(meta.get("relative_path")),
        "target_created_at": _canon_ts(meta.get("target_created_at")),
        "target_modified_at": _canon_ts(meta.get("target_modified_at")),
        "target_accessed_at": _canon_ts(meta.get("target_accessed_at")),
        "target_file_size": str(meta.get("target_file_size") or ""),
    }


def trusted_fields(path: Path) -> dict[str, str]:
    from LnkParse3.lnk_file import LnkFile

    with path.open("rb") as handle:
        lnk = LnkFile(fhandle=handle)
    data = lnk.get_json()
    header = data.get("header") or {}
    link_info = data.get("link_info") or {}
    string_data = data.get("data") or {}
    local_base = _trusted_ansi(str(link_info.get("local_base_path") or ""))
    suffix = _trusted_ansi(str(link_info.get("common_path_suffix") or ""))
    target = _join_base_suffix(local_base, suffix)
    if not target:
        # No LinkInfo section: match RapidTriage's fallback order —
        # relative_path next, then a target-item-list reconstruction
        # (volume name + File entry names; may carry 8.3 short names).
        target = _trusted_ansi(str(string_data.get("relative_path") or ""))
    if not target:
        items = (data.get("target") or {}).get("items") or []
        volume = next(
            (_trusted_ansi(str(i.get("volume_name") or "")) for i in items if i.get("volume_name")),
            "",
        )
        names = [
            _trusted_ansi(str(i.get("long_name") or i.get("primary_name") or ""))
            for i in items
            if i.get("class") == "File entry"
        ]
        names = [n for n in names if n]
        if names:
            target = volume + "\\".join(names) if volume else "\\".join(names)
    return {
        "lnk_parse_status": "parsed",
        "target_path": _canon_path(target),
        "relative_path": _canon_path(string_data.get("relative_path")),
        "target_created_at": _canon_ts(header.get("creation_time")),
        "target_modified_at": _canon_ts(header.get("modified_time")),
        "target_accessed_at": _canon_ts(header.get("accessed_time")),
        "target_file_size": str(header.get("file_size") or ""),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lnk-root", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=MAX_FILES_DEFAULT)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    files = sorted(p for p in args.lnk_root.rglob("*.lnk") if p.is_file())[: args.max_files]

    per_file: list[dict[str, object]] = []
    totals = {
        "files": 0,
        "matched": 0,
        "mismatch": 0,
        "rapid_parse_failures": 0,
        "trusted_parse_failures": 0,
        "one_sided": 0,
        "errors": [],
    }
    field_totals: dict[str, int] = {}
    for path in files:
        try:
            rapid = rapid_fields(path)
        except Exception as exc:
            totals["rapid_parse_failures"] += 1
            totals["errors"].append({"file": str(path), "side": "rapid", "error": str(exc)[:200]})
            continue
        try:
            trusted = trusted_fields(path)
        except Exception as exc:
            totals["trusted_parse_failures"] += 1
            totals["errors"].append({"file": str(path), "side": "trusted", "error": str(exc)[:200]})
            continue
        totals["files"] += 1
        field_diffs = []
        one_sided: list[dict[str, str]] = []
        for name in COMPARE_FIELDS:
            rapid_value = rapid.get(name, "")
            trusted_value = trusted.get(name, "")
            if rapid_value == trusted_value:
                continue
            row = {"field": name, "rapid": rapid_value, "trusted": trusted_value}
            if rapid_value and trusted_value:
                field_diffs.append(row)
            else:
                # Reference emits nothing (or we do): unverifiable one-sided
                # presence — neither match nor mismatch.
                one_sided.append(row)
        for fd in field_diffs:
            field_totals[fd["field"]] = field_totals.get(fd["field"], 0) + 1
        one_sided_counts: dict[str, int] = {}
        for fd in one_sided:
            side = "trusted-empty" if fd["rapid"] else "rapid-empty"
            key = f"{fd['field']}:{side}"
            one_sided_counts[key] = one_sided_counts.get(key, 0) + 1
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
                "rapid_parse_status": rapid["lnk_parse_status"],
                "field_diffs": field_diffs[:10],
                "one_sided_fields": one_sided[:10],
                "one_sided_counts": one_sided_counts,
                "status": status,
            }
        )

    compared = totals["matched"] + totals["mismatch"]
    report = {
        "schema_version": "lnk-reference-diff-v1",
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "RapidTriage native LNK parse vs LnkParse3 on real .lnk files. "
            "LnkParse3 is not on the recognized trusted-tool list; results "
            "are engineering evidence only."
        ),
        "lnk_root": str(args.lnk_root),
        "lnk_root_sha256_dir_listing": _listing_hash(files),
        "totals": totals,
        "field_match_rate": round(totals["matched"] / compared, 6) if compared else None,
        "field_match_rate_note": (
            "matched+mismatch = files where every compared field had values on "
            "both sides or agreed-empty; files with one-sided fields (reference "
            "emits nothing, e.g. shell-folder links without LinkInfo) are "
            "counted separately and cannot confirm or refute accuracy."
        ),
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
            f"rapid_fail={totals['rapid_parse_failures']} trusted_fail={totals['trusted_parse_failures']}"
        )
        print(f"-> {args.output}")
    return 0


def _listing_hash(files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(str(path.stat().st_size).encode())
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
