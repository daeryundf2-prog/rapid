#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/sample-check.py --parser <id> --input <sample file or folder> \
#       --expect <known-answer.json> [--json] [--show-values]
#   python scripts/sample-check.py --probe-hash <32 hex> \
#       [--candidate-path "<original path>" ...] [--candidate-file <file> ...] \
#       [--head-bytes N ...] [--json] [--show-values]
#
# R6 S1 lane B sample harness (docs/plans/r6-followups-2026-10-19.md section 1.3,
# docs/validation/r6-sample-validation-2026-10-19.md). Runs one RapidTriage
# parser directly on a real sample (kept outside Git under
# D:\rapid-qa\samples\<parser>\) the way `rapidtriage artifacts --kind` does and
# compares the rows to a known-answer JSON written by whoever made the sample:
#
#   {"parser": "<id>",
#    "expect": [{"match": {"field": value, ...}, "fields": {"field": expected, ...}}],
#    "counts": {"<artifact_type>": n}}
#
# Field names address the flattened row: `artifact_type`, `path`, `provider`
# and every `details` key; nested values use dots (`details.a.b` or `a.b`).
# The report carries row counts, artifact_type counts, matched/mismatched
# expectations and mismatched field NAMES only. Values (expected/actual) appear
# only with --show-values; never paste such output into Git.
#
# --probe-hash tries MD5 / SHA-1 / SHA-256 (full, 32-hex prefix/suffix) and
# CRC32 (8-hex slices) over candidate path strings (cp949 / UTF-16LE / UTF-8 x
# as-is / lower / upper x as-is / swapped separators) and candidate files
# (whole content and first N bytes) - used to pin the GOM Player
# _RECENTMEDIANAME### identifier. Matches name the candidate by index.
#
# Exit codes: 0 all expectations met / probe matched, 1 mismatch / no match,
# 2 input error. Read-only. Engineering measurement only.
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
import re
import sys
import zlib
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA_VERSION = "rapidtriage-sample-check-v1"
PROBE_SCHEMA_VERSION = "rapidtriage-sample-probe-hash-v1"
EXIT_PASS, EXIT_MISMATCH, EXIT_INPUT_ERROR = 0, 1, 2
# parser id -> artifact collector kind (provider run like `rapidtriage artifacts --kind`).
PROVIDER_PARSERS = {
    "media-player": "media-player",
    "p2p": "p2p",
    "windows-phone-link": "windows-phone-link",
    "windows-messenger": "windows-messenger",
    "email-clients": "email-clients",
    "mobile-export": "mobile-export",
    "browser": "browser",
    "windows-system": "windows-system",
    "media-image": "media-image",
}
ARCHIVE_PARSERS = {"egg": ".egg", "alz": ".alz"}
PARSER_IDS = tuple(sorted([*PROVIDER_PARSERS, *ARCHIVE_PARSERS, "url-carve"]))
DEFAULT_URL_SCAN_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_HEAD_BYTES = (512, 4096, 65536, 1024 * 1024)
MAX_PROBE_FILE_BYTES = 2 * 1024 * 1024 * 1024
HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


class InputError(Exception):
    pass


# ---------------------------------------------------------------------------
# Row production
# ---------------------------------------------------------------------------


def flatten_row(row: Mapping[str, object]) -> dict[str, object]:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    flat: dict[str, object] = dict(details)  # type: ignore[arg-type]
    for key in ("artifact_type", "path", "provider"):
        if key in row:
            flat[key] = row[key]
    flat["details"] = details
    return flat


def provider_rows(kind: str, root: Path) -> tuple[list[dict[str, object]], list[str]]:
    from rapidtriage.core.artifacts import run_artifact_collection

    payload = run_artifact_collection(root, kind=kind, use_cache=False)
    rows = [flatten_row(row) for row in payload.get("artifacts", []) if isinstance(row, Mapping)]
    errors = [
        str(item.get("error_type") or "error")
        for item in payload.get("parser_errors", [])
        if isinstance(item, Mapping)
    ]
    return rows, errors


def iter_sample_files(root: Path, suffix: str | None = None) -> Iterator[Path]:
    if root.is_file():
        if suffix is None or root.suffix.lower() == suffix:
            yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and (suffix is None or path.suffix.lower() == suffix):
            yield path


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix() if root.is_dir() else path.name
    except ValueError:
        return path.name


def archive_rows(fmt: str, root: Path) -> tuple[list[dict[str, object]], list[str]]:
    from rapidtriage.core.egg_archive import list_alz, list_egg

    reader = list_egg if fmt == "egg" else list_alz
    rows: list[dict[str, object]] = []
    errors: list[str] = []
    for path in iter_sample_files(root, ARCHIVE_PARSERS[fmt]):
        try:
            listing = reader(path)
        except (ValueError, OSError, EOFError) as exc:
            errors.append(type(exc).__name__)
            rows.append({"artifact_type": f"{fmt}-open-failed", "archive_file": _relative(path, root)})
            continue
        archive_fields = {
            "archive_file": _relative(path, root),
            "archive_status": listing.get("analysis_status"),
            "archive_solid": listing.get("solid"),
            "archive_split": listing.get("split"),
            "archive_entry_count": len(listing.get("entries") or []),
        }
        rows.append({"artifact_type": f"{fmt}-archive", **archive_fields, "notes": listing.get("notes")})
        for entry in listing.get("entries") or []:
            rows.append({"artifact_type": f"{fmt}-entry", **archive_fields, **entry})
    return rows, errors


def url_carve_rows(root: Path, max_scan_bytes: int) -> tuple[list[dict[str, object]], list[str]]:
    from rapidtriage.core.url_carving import UrlCarveState, scan_url_source

    state = UrlCarveState(None, 1_000_000)
    rows: list[dict[str, object]] = []
    errors: list[str] = []
    for path in iter_sample_files(root):
        try:
            candidates, scanned = scan_url_source(path, state=state, read_limit=min(path.stat().st_size, max_scan_bytes))
        except OSError as exc:
            errors.append(type(exc).__name__)
            continue
        for candidate in candidates:
            rows.append({"artifact_type": "carved-url-candidate", "source_file": _relative(path, root), "scanned_bytes": scanned, **candidate})
    return rows, errors


def collect_rows(parser_id: str, root: Path, *, max_scan_bytes: int = DEFAULT_URL_SCAN_BYTES) -> tuple[list[dict[str, object]], list[str]]:
    if parser_id in PROVIDER_PARSERS:
        return provider_rows(PROVIDER_PARSERS[parser_id], root)
    if parser_id in ARCHIVE_PARSERS:
        return archive_rows(parser_id, root)
    if parser_id == "url-carve":
        return url_carve_rows(root, max_scan_bytes)
    raise InputError(f"unknown parser id: {parser_id} (known: {', '.join(PARSER_IDS)})")


# ---------------------------------------------------------------------------
# Known-answer comparison
# ---------------------------------------------------------------------------

_MISSING = object()


def lookup(row: Mapping[str, object], field: str) -> object:
    if field in row:
        return row[field]
    current: object = row
    for part in field.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def values_equal(expected: object, actual: object) -> bool:
    if actual is _MISSING:
        return False
    if expected == actual:
        return True
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)) and not isinstance(actual, bool):
        return abs(float(expected) - float(actual)) < 1e-9
    if isinstance(expected, (list, dict)) or isinstance(actual, (list, dict)):
        return False
    return str(expected) == str(actual)


def load_known_answer(path: Path, parser_id: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"unreadable known-answer file: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise InputError("known-answer root must be an object")
    if payload.get("parser") not in (None, parser_id):
        raise InputError(f"known-answer parser {payload.get('parser')!r} does not match --parser {parser_id!r}")
    expect = payload.get("expect", [])
    counts = payload.get("counts", {})
    if not isinstance(expect, list) or not all(isinstance(item, dict) for item in expect):
        raise InputError("known-answer 'expect' must be a list of objects")
    for index, item in enumerate(expect):
        if not isinstance(item.get("match", {}), dict) or not isinstance(item.get("fields", {}), dict):
            raise InputError(f"known-answer expect[{index}] needs object 'match' and 'fields'")
    if not isinstance(counts, dict):
        raise InputError("known-answer 'counts' must be an object")
    return {"expect": expect, "counts": counts}


def _mismatched_fields(row: Mapping[str, object], fields: Mapping[str, object]) -> list[str]:
    return sorted(key for key, value in fields.items() if not values_equal(value, lookup(row, key)))


def check_rows(
    rows: list[dict[str, object]], known: Mapping[str, object], *, show_values: bool = False
) -> dict[str, object]:
    results: list[dict[str, object]] = []
    used_rows: set[int] = set()
    for index, item in enumerate(known["expect"]):  # type: ignore[union-attr]
        match: Mapping[str, object] = item.get("match", {})
        fields: Mapping[str, object] = item.get("fields", {})
        candidates = [
            i for i, row in enumerate(rows) if all(values_equal(value, lookup(row, key)) for key, value in match.items())
        ]
        result: dict[str, object] = {"index": index, "match_fields": sorted(match), "candidate_rows": len(candidates)}
        if not candidates:
            result.update({"status": "missing", "mismatched_fields": []})
            if show_values:
                result["expected_match"] = dict(match)
            results.append(result)
            continue

        misses = {i: _mismatched_fields(rows[i], fields) for i in candidates}
        best = min(candidates, key=lambda i: (len(misses[i]), i in used_rows, i))
        used_rows.add(best)
        bad = misses[best]
        result.update({"status": "mismatch" if bad else "matched", "mismatched_fields": bad})
        if show_values and bad:
            result["values"] = {
                key: {"expected": fields[key], "actual": None if lookup(rows[best], key) is _MISSING else lookup(rows[best], key)}
                for key in bad
            }
        results.append(result)
    matched_rows = set(used_rows)
    counts = Counter(str(row.get("artifact_type") or "") for row in rows)
    count_results = [
        {"artifact_type": name, "expected": int(expected), "actual": counts.get(name, 0), "ok": counts.get(name, 0) == int(expected)}
        for name, expected in sorted(known["counts"].items())  # type: ignore[union-attr]
    ]
    statuses = Counter(str(result["status"]) for result in results)
    total = len(results)
    return {
        "expectations": {
            "total": total,
            "matched": statuses.get("matched", 0),
            "mismatch": statuses.get("mismatch", 0),
            "missing": statuses.get("missing", 0),
            "recall": round(statuses.get("matched", 0) / total, 4) if total else None,
        },
        "results": results,
        "counts": count_results,
        "rows_matched_by_expectations": len(matched_rows),
        "rows_not_in_known_answer": len(rows) - len(matched_rows),
    }


def run_check(parser_id: str, input_path: Path, expect_path: Path, *, show_values: bool, max_scan_bytes: int) -> dict[str, object]:
    if parser_id not in PARSER_IDS:
        raise InputError(f"unknown parser id: {parser_id} (known: {', '.join(PARSER_IDS)})")
    if not input_path.exists():
        raise InputError("input path does not exist")
    known = load_known_answer(expect_path, parser_id)
    rows, errors = collect_rows(parser_id, input_path, max_scan_bytes=max_scan_bytes)
    comparison = check_rows(rows, known, show_values=show_values)
    exp = comparison["expectations"]
    ok = exp["mismatch"] == 0 and exp["missing"] == 0 and all(item["ok"] for item in comparison["counts"])  # type: ignore[index,union-attr]
    return {
        "schema": SCHEMA_VERSION,
        "parser": parser_id,
        "row_count": len(rows),
        "artifact_type_counts": dict(sorted(Counter(str(row.get("artifact_type") or "") for row in rows).items())),
        "parser_error_types": dict(sorted(Counter(errors).items())),
        "values_shown": show_values,
        "verdict": "pass" if ok else "mismatch",
        **comparison,
    }


# ---------------------------------------------------------------------------
# --probe-hash
# ---------------------------------------------------------------------------


def path_variants(text: str) -> Iterator[tuple[str, bytes]]:
    seen: set[bytes] = set()
    separators = {"as-is": text, "backslash": text.replace("/", "\\"), "slash": text.replace("\\", "/")}
    for sep_name, sep_text in separators.items():
        for case_name, cased in (("as-is", sep_text), ("lower", sep_text.lower()), ("upper", sep_text.upper())):
            for encoding in ("cp949", "utf-16le", "utf-8"):
                try:
                    data = cased.encode(encoding)
                except UnicodeEncodeError:
                    continue
                for nul_name, blob in (("", data), ("+nul", data + ("\x00".encode(encoding)))):
                    if blob in seen:
                        continue
                    seen.add(blob)
                    yield f"{encoding}/{case_name}/{sep_name}{nul_name}", blob


def digests(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
    }


def digest_positions(target: str, digest: str) -> list[str]:
    if len(digest) == len(target):
        return ["full"] if digest == target else []
    if len(digest) > len(target):
        found = []
        if digest.startswith(target):
            found.append("prefix")
        if digest.endswith(target):
            found.append("suffix")
        return found
    return [f"slice@{offset}" for offset in range(0, len(target) - len(digest) + 1, 2) if target[offset : offset + len(digest)] == digest]


def probe_blob(target: str, blob: bytes) -> list[dict[str, str]]:
    matches = []
    for algorithm, digest in digests(blob).items():
        for position in digest_positions(target, digest):
            matches.append({"algorithm": algorithm, "position": position})
    return matches


def file_blobs(path: Path, head_sizes: Iterable[int]) -> Iterator[tuple[str, bytes]]:
    size = path.stat().st_size
    if size > MAX_PROBE_FILE_BYTES:
        raise InputError(f"candidate file larger than {MAX_PROBE_FILE_BYTES} bytes")
    data = path.read_bytes()
    yield "content/whole", data
    for count in sorted(set(head_sizes)):
        if 0 < count < size:
            yield f"content/head-{count}", data[:count]


def probe_hash(
    target: str,
    candidate_paths: list[str],
    candidate_files: list[Path],
    *,
    head_sizes: Iterable[int] = DEFAULT_HEAD_BYTES,
    show_values: bool = False,
) -> dict[str, object]:
    if not HEX32.match(target):
        raise InputError("--probe-hash needs a 32-hex-digit value")
    if not candidate_paths and not candidate_files:
        raise InputError("--probe-hash needs --candidate-path and/or --candidate-file")
    target = target.lower()
    matches: list[dict[str, object]] = []
    tried = 0
    for index, text in enumerate(candidate_paths):
        for variant, blob in path_variants(text):
            tried += 1
            for hit in probe_blob(target, blob):
                matches.append({"candidate": f"path[{index}]", "variant": variant, **hit})
    for index, path in enumerate(candidate_files):
        if not path.is_file():
            raise InputError(f"candidate file [{index}] does not exist")
        for variant, blob in file_blobs(path, head_sizes):
            tried += 1
            for hit in probe_blob(target, blob):
                matches.append({"candidate": f"file[{index}]", "variant": variant, **hit})
        for variant, blob in path_variants(path.name):
            tried += 1
            for hit in probe_blob(target, blob):
                matches.append({"candidate": f"file[{index}]", "variant": f"name/{variant}", **hit})
    report: dict[str, object] = {
        "schema": PROBE_SCHEMA_VERSION,
        "algorithms": ["md5", "sha1", "sha256", "crc32"],
        "candidate_paths": len(candidate_paths),
        "candidate_files": len(candidate_files),
        "variants_tried": tried,
        "matches": matches,
        "verdict": "match" if matches else "no-match",
        "values_shown": show_values,
    }
    if show_values:
        report["target"] = target
        report["candidate_path_values"] = list(candidate_paths)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def render_text(report: Mapping[str, object]) -> str:
    if report.get("schema") == PROBE_SCHEMA_VERSION:
        lines = [f"probe-hash: {str(report['verdict']).upper()} ({report['variants_tried']} variants)"]
        for hit in report["matches"]:  # type: ignore[union-attr]
            lines.append(f"  {hit['candidate']:10} {hit['variant']:36} {hit['algorithm']:7} {hit['position']}")
        return "\n".join(lines)
    exp = report["expectations"]
    lines = [
        f"sample-check {report['parser']}: {str(report['verdict']).upper()}",
        f"rows {report['row_count']}  expectations {exp['matched']}/{exp['total']} matched, "  # type: ignore[index]
        f"{exp['mismatch']} mismatch, {exp['missing']} missing; rows outside known-answer {report['rows_not_in_known_answer']}",  # type: ignore[index]
    ]
    for name, count in report["artifact_type_counts"].items():  # type: ignore[union-attr]
        lines.append(f"  {name:44} {count:>8}")
    for result in report["results"]:  # type: ignore[union-attr]
        if result["status"] != "matched":
            fields = ", ".join(result["mismatched_fields"]) or "-"
            lines.append(f"  expect[{result['index']}] {result['status']}: {fields}")
            for key, value in (result.get("values") or {}).items():
                lines.append(f"      {key}: expected {value['expected']!r} actual {value['actual']!r}")
    for item in report["counts"]:  # type: ignore[union-attr]
        if not item["ok"]:
            lines.append(f"  count {item['artifact_type']}: expected {item['expected']} actual {item['actual']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check one parser against a known-answer sample (read-only).")
    parser.add_argument("--parser", choices=PARSER_IDS, help="parser id")
    parser.add_argument("--input", type=Path, help="sample file or folder")
    parser.add_argument("--expect", type=Path, help="known-answer JSON")
    parser.add_argument("--show-values", action="store_true", help="include expected/actual values (never commit)")
    parser.add_argument("--json", action="store_true", help="print the JSON report")
    parser.add_argument("--output", type=Path, help="also write the JSON report to this file")
    parser.add_argument("--max-scan-bytes", type=int, default=DEFAULT_URL_SCAN_BYTES, help="url-carve read cap per file")
    parser.add_argument("--probe-hash", metavar="HEX32", help="identify the hash behind a 32-hex identifier")
    parser.add_argument("--candidate-path", action="append", default=[], help="original path string to probe")
    parser.add_argument("--candidate-file", action="append", default=[], type=Path, help="file whose content/name to probe")
    parser.add_argument("--head-bytes", action="append", type=int, help="content prefix sizes to probe (default 512, 4096, 65536, 1048576)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.probe_hash is not None:
            report = probe_hash(
                args.probe_hash,
                args.candidate_path,
                args.candidate_file,
                head_sizes=args.head_bytes or DEFAULT_HEAD_BYTES,
                show_values=args.show_values,
            )
            ok = report["verdict"] == "match"
        else:
            if not (args.parser and args.input and args.expect):
                raise InputError("--parser, --input and --expect are required (or use --probe-hash)")
            report = run_check(args.parser, args.input, args.expect, show_values=args.show_values, max_scan_bytes=args.max_scan_bytes)
            ok = report["verdict"] == "pass"
    except InputError as exc:
        print(f"sample-check: input error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text if args.json else render_text(report))
    return EXIT_PASS if ok else EXIT_MISMATCH


if __name__ == "__main__":
    raise SystemExit(main())
