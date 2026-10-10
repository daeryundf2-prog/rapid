#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# --- How to run ---
#   python scripts/measure-artifact-record-bloat.py <run>/artifacts \
#       [--include-huge] [--huge-sample 50000] [--output report.json] [--json]
#
# Streams per-kind artifact outputs (``rapidtriage-artifacts-<kind>.json``
# ``artifacts`` arrays and ``rapidtriage-artifacts-<kind>.jsonl`` record
# streams) without loading whole files, and reports per file: record count,
# total/mean/median/max record bytes (compact JSON), artifact_type counts,
# duplicated ``artifact_record.fields`` serialization, and for each top-level
# ``details`` key the bytes it accounts for plus whether its value is
# identical across all records of the same artifact_type (the P10 hoist
# candidates). Engineering measurement; not release evidence.
# ------------------
"""Measure per-record metadata bloat in RapidTriage artifact outputs."""

from __future__ import annotations

import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import statistics
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:  # optional: deep (constant-part) hoist analysis uses the shipped splitter
    from rapidtriage.core.artifact_profiles import _MISSING as profile_missing
    from rapidtriage.core.artifact_profiles import _split as profile_split
    from rapidtriage.core.artifact_profiles import is_hoistable_detail_key
except ImportError:  # pragma: no cover - script copied outside the repo
    profile_missing = None
    profile_split = None
    is_hoistable_detail_key = None

CHUNK_CHARS = 1 << 24
DEFAULT_HUGE_BYTES = 5 * 1024**3
DEFAULT_HUGE_SAMPLE = 50_000
_WS = " \t\r\n"


class StreamError(ValueError):
    """Raised when a streamed document is malformed."""


class _Buffered:
    """Buffered text reader exposing raw_decode over a sliding window."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self._dec = json.JSONDecoder()
        self.buf = ""
        self.pos = 0
        self.eof = False
        self.truncated = False

    def _more(self) -> bool:
        if self.eof:
            return False
        if self.pos:
            self.buf = self.buf[self.pos :]
            self.pos = 0
        data = self._handle.read(CHUNK_CHARS)
        if not data:
            self.eof = True
            return False
        self.buf += data
        return True

    def peek(self) -> str:
        while True:
            i = self.pos
            n = len(self.buf)
            while i < n and self.buf[i] in _WS:
                i += 1
            self.pos = i
            if i < n:
                return self.buf[i]
            if not self._more():
                return ""

    def take(self, expected: str) -> None:
        if self.peek() != expected:
            raise StreamError(f"expected {expected!r} near offset {self.pos}")
        self.pos += 1

    def value(self) -> Any:
        self.peek()
        while True:
            try:
                result, end = self._dec.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError as exc:
                if not self._more():
                    self.truncated = True
                    raise StreamError(f"truncated or invalid JSON value: {exc}") from exc
                continue
            if end == len(self.buf) and not self.eof and self._more():
                continue  # a scalar token may continue into the next chunk
            self.pos = end
            return result


def iter_json_member(path: Path, member: str, header: dict[str, Any]) -> Iterator[Any]:
    """Yield items of a top-level array ``member``; other members go to ``header``.

    Members other than ``member`` are parsed whole (they are summaries), so
    this is bounded by the largest single record, not the file size.
    """
    with path.open("r", encoding="utf-8") as handle:
        reader = _Buffered(handle)
        reader.take("{")
        while True:
            ch = reader.peek()
            if ch == "}" or ch == "":
                return
            if ch == ",":
                reader.pos += 1
                continue
            key = reader.value()
            reader.take(":")
            if key != member:
                header[key] = reader.value()
                continue
            reader.take("[")
            while True:
                ch = reader.peek()
                if ch == "]":
                    reader.pos += 1
                    break
                if ch == ",":
                    reader.pos += 1
                    continue
                if ch == "":
                    header["__truncated__"] = True
                    return
                try:
                    yield reader.value()
                except StreamError:
                    header["__truncated__"] = True
                    return


def iter_jsonl(path: Path, header: dict[str, Any]) -> Iterator[Any]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                header["__truncated__"] = True
                return


def _compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _nbytes(text: str) -> int:
    return len(text.encode("utf-8"))


class FileStats:
    def __init__(self, path: Path, fmt: str, deep_sample: int = 0) -> None:
        self.path = path
        self.fmt = fmt
        self.deep_sample = deep_sample
        self.samples: dict[str, list[dict[str, Any]]] = {}
        self.sizes: list[int] = []
        self.type_counts: dict[str, int] = {}
        self.top_key_bytes: dict[str, int] = {}
        self.dual_serialization = 0
        self.profile_ref_count = 0
        # (artifact_type, details_key) -> [count, bytes, first_hash, constant]
        self.cells: dict[tuple[str, str], list[Any]] = {}

    def add(self, record: Any) -> None:
        if not isinstance(record, dict):
            return
        size = _nbytes(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
        self.sizes.append(size)
        artifact_type = str(record.get("artifact_type") or "")
        self.type_counts[artifact_type] = self.type_counts.get(artifact_type, 0) + 1
        for key, value in record.items():
            self.top_key_bytes[key] = self.top_key_bytes.get(key, 0) + _nbytes(
                json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            )
        if record.get("profile_ref"):
            self.profile_ref_count += 1
        envelope = record.get("artifact_record")
        details = record.get("details")
        if isinstance(envelope, dict) and "fields" in envelope and isinstance(details, dict):
            self.dual_serialization += 1
        if not isinstance(details, dict):
            return
        if self.deep_sample and profile_split is not None:
            bucket = self.samples.setdefault(artifact_type, [])
            if len(bucket) < self.deep_sample:
                bucket.append(details)
        for key, value in details.items():
            text = _compact(value)
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            cell = self.cells.get((artifact_type, key))
            if cell is None:
                self.cells[(artifact_type, key)] = [1, _nbytes(text), digest, True]
                continue
            cell[0] += 1
            cell[1] += _nbytes(text)
            if cell[3] and cell[2] != digest:
                cell[3] = False

    def deep_hoist(self) -> dict[str, dict[str, Any]]:
        """Bytes the constant parts of each details key would save (sampled rows)."""
        result: dict[str, dict[str, Any]] = {}
        if profile_split is None:
            return result
        for samples in self.samples.values():
            if len(samples) < 2:
                continue
            for key in samples[0]:
                if not all(key in item for item in samples[1:]):
                    continue
                values = [item[key] for item in samples]
                before = sum(_nbytes(_compact(value)) for value in values)
                hoisted, template, residues = profile_split(values)
                after = before
                if hoisted:
                    after = sum(_nbytes(_compact(item)) for item in residues if item is not profile_missing)
                entry = result.setdefault(
                    key,
                    {"sample_rows": 0, "bytes_before": 0, "bytes_after": 0, "hoist_candidate": None},
                )
                entry["sample_rows"] += len(values)
                entry["bytes_before"] += before
                entry["bytes_after"] += after
                if is_hoistable_detail_key is not None:
                    entry["hoist_candidate"] = bool(is_hoistable_detail_key(str(key)))
        return dict(sorted(result.items(), key=lambda item: -(item[1]["bytes_before"] - item[1]["bytes_after"])))

    def report(self, header: dict[str, Any], sampled: bool, preview: bool, top: int) -> dict[str, Any]:
        sizes = self.sizes
        count = len(sizes)
        keys: dict[str, dict[str, Any]] = {}
        for (artifact_type, key), (n, nbytes, _digest, constant) in self.cells.items():
            # A key is constant for a type only when every record carries the
            # same value (absent in some records counts as varying).
            constant = constant and n == self.type_counts.get(artifact_type, 0) and n > 1
            entry = keys.setdefault(
                key,
                {"bytes": 0, "records": 0, "constant_types": [], "varying_types": []},
            )
            entry["bytes"] += nbytes
            entry["records"] += n
            (entry["constant_types"] if constant else entry["varying_types"]).append(artifact_type)
        total = sum(sizes)
        ranked = sorted(keys.items(), key=lambda item: (-item[1]["bytes"], item[0]))
        details_keys = []
        for key, entry in ranked[:top] if top > 0 else ranked:
            details_keys.append(
                {
                    "key": key,
                    "bytes": entry["bytes"],
                    "share": round(entry["bytes"] / total, 4) if total else 0.0,
                    "records": entry["records"],
                    "constant_per_type": not entry["varying_types"],
                    "constant_types": sorted(entry["constant_types"]),
                    "varying_types": sorted(entry["varying_types"]),
                }
            )
        return {
            "file": self.path.name,
            "format": self.fmt,
            "file_bytes": self.path.stat().st_size,
            "preview_only": preview,
            "sampled": sampled,
            "truncated": bool(header.get("__truncated__")),
            "record_count": count,
            "declared_record_count": header.get("record_count")
            or (header.get("summary") or {}).get("artifact_count"),
            "record_bytes_total": total,
            "record_bytes_mean": round(total / count, 1) if count else 0.0,
            "record_bytes_median": statistics.median(sizes) if sizes else 0,
            "record_bytes_max": max(sizes) if sizes else 0,
            "artifact_type_counts": dict(sorted(self.type_counts.items())),
            "top_level_key_bytes": dict(sorted(self.top_key_bytes.items(), key=lambda item: -item[1])),
            "dual_serialization_records": self.dual_serialization,
            "profile_ref_records": self.profile_ref_count,
            "artifact_type_profiles_bytes": _nbytes(_compact(header.get("artifact_type_profiles")))
            if header.get("artifact_type_profiles")
            else 0,
            "details_keys": details_keys,
            "deep_hoist_sample": dict(list(self.deep_hoist().items())[: top if top > 0 else None]),
        }


def measure_file(path: Path, *, limit: int | None, top: int, preview: bool, deep_sample: int = 0) -> dict[str, Any]:
    fmt = "jsonl" if path.suffix == ".jsonl" else "json"
    header: dict[str, Any] = {}
    stats = FileStats(path, fmt, deep_sample)
    iterator = iter_jsonl(path, header) if fmt == "jsonl" else iter_json_member(path, "artifacts", header)
    sampled = False
    for index, record in enumerate(iterator):
        if limit is not None and index >= limit:
            sampled = True
            break
        stats.add(record)
    return stats.report(header, sampled, preview, top)


def collect_targets(paths: list[Path]) -> list[Path]:
    targets: list[Path] = []
    for path in paths:
        if path.is_dir():
            targets.extend(sorted(path.glob("rapidtriage-artifacts-*.json")))
            targets.extend(sorted(path.glob("rapidtriage-artifacts-*.jsonl")))
        elif path.is_file():
            targets.append(path)
    return sorted(set(targets))


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="artifacts directory or per-kind files")
    parser.add_argument("--include-huge", action="store_true", help="sample files larger than --huge-bytes")
    parser.add_argument("--huge-bytes", type=int, default=DEFAULT_HUGE_BYTES)
    parser.add_argument("--huge-sample", type=int, default=DEFAULT_HUGE_SAMPLE)
    parser.add_argument("--top", type=int, default=15, help="details keys per file (0 = all)")
    parser.add_argument(
        "--deep-sample",
        type=int,
        default=0,
        help="rows per artifact_type kept to estimate constant-part (deep) hoisting per details key",
    )
    parser.add_argument("--output", type=Path, help="write the full JSON report here")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    args = parser.parse_args(argv)

    targets = collect_targets(args.paths)
    jsonl_stems = {path.with_suffix("").name for path in targets if path.suffix == ".jsonl"}
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for path in targets:
        size = path.stat().st_size
        limit = None
        if size > args.huge_bytes:
            if not args.include_huge:
                skipped.append({"file": path.name, "file_bytes": size, "reason": "huge"})
                continue
            limit = args.huge_sample
        preview = path.suffix == ".json" and path.with_suffix("").name in jsonl_stems
        print(f"measuring {path.name} ({_human(size)})", file=sys.stderr, flush=True)
        files.append(measure_file(path, limit=limit, top=args.top, preview=preview, deep_sample=args.deep_sample))

    counted = [item for item in files if not item["preview_only"]]
    record_total = sum(item["record_count"] for item in counted)
    bytes_total = sum(item["record_bytes_total"] for item in counted)
    report = {
        "schema": "rapidtriage-artifact-record-bloat-v1",
        "paths": [str(path) for path in args.paths],
        "artifacts_dir_bytes": sum(path.stat().st_size for path in targets),
        "measured_record_count": record_total,
        "measured_record_bytes": bytes_total,
        "measured_record_bytes_mean": round(bytes_total / record_total, 1) if record_total else 0.0,
        "dual_serialization_records": sum(item["dual_serialization_records"] for item in files),
        "skipped": skipped,
        "files": files,
    }
    if args.output:
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    print(f"artifacts dir bytes: {_human(report['artifacts_dir_bytes'])}")
    print(
        f"measured records: {record_total}  bytes: {_human(bytes_total)}  "
        f"mean: {_human(report['measured_record_bytes_mean'])}  "
        f"dual-serialized: {report['dual_serialization_records']}"
    )
    print(f"{'file':52} {'on-disk':>10} {'records':>9} {'mean':>10} {'median':>10} {'max':>10}")
    for item in files:
        flag = " (preview)" if item["preview_only"] else (" (sampled)" if item["sampled"] else "")
        print(
            f"{item['file'][:52]:52} {_human(item['file_bytes']):>10} {item['record_count']:>9} "
            f"{_human(item['record_bytes_mean']):>10} {_human(item['record_bytes_median']):>10} "
            f"{_human(item['record_bytes_max']):>10}{flag}"
        )
    for item in files:
        if not item["details_keys"]:
            continue
        print(f"\n== {item['file']} details keys (bytes, constant-per-type)")
        for key in item["details_keys"]:
            print(
                f"  {key['key'][:48]:48} {_human(key['bytes']):>10} {key['share']:>6.1%} "
                f"{'CONST' if key['constant_per_type'] else 'vary':5} "
                f"const={len(key['constant_types'])} vary={len(key['varying_types'])}"
            )
    for item in skipped:
        print(f"skipped {item['file']} ({_human(item['file_bytes'])}): {item['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
