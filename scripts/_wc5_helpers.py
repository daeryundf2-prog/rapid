"""Shared helpers for the WC-5 reference-diff scripts (T-208..T-212).

Loads RapidTriage JSONL output and reference-tool CSV exports, normalises
keys/paths/timestamps and builds the common keyed-diff report:

    recall · matched · missing · mismatched · reference_tool
    (+ extra, counts, fields_compared, fields_not_compared)

``missing`` are reference keys RapidTriage did not produce (only_reference),
``extra`` are RapidTriage keys the reference did not list (only_rapid), and
``mismatched`` are shared keys whose compared fields disagree.

Reports are engineering checks only (``release_evidence_status`` stays
``engineering_check_only``); a reference export from a real case stays
outside Git.

Kept apart from the T-204..T-207 lane's common module on purpose; fold the
two together once both lanes are merged.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

SCHEMA_VERSION = "reference-diff-v1"
LIST_CAP = 1000
EXIT_INPUT_ERROR = 2

_WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2}):?(\d{2})?$", re.IGNORECASE)
_USERS_RE = re.compile(r"[\\/](?:users|documents and settings)[\\/]([^\\/]+)[\\/]", re.IGNORECASE)
_NAIVE_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M",
    "%d.%m.%Y %H:%M:%S",
)


class InputError(Exception):
    """Unreadable or missing input; the CLI exits 2."""


# --- loading -----------------------------------------------------------------


def flatten_record(record: Mapping[str, object]) -> dict[str, object]:
    """Merge an ``ArtifactRecord.to_dict()`` row into one flat mapping.

    ``details`` keys are lifted to the top; the record's own ``artifact_type``,
    ``provider`` and ``path`` win over same-named detail keys.
    """
    flat: dict[str, object] = {}
    details = record.get("details")
    if isinstance(details, Mapping):
        flat.update(details)
        fields = details.get("fields")
        if isinstance(fields, Mapping):
            for key, value in fields.items():
                flat.setdefault(key, value)
    for key, value in record.items():
        if key != "details":
            flat[key] = value
    return flat


def load_ours(path: Path) -> list[dict[str, object]]:
    """Read RapidTriage JSONL (one record per line) or a JSON array/``records`` file."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"cannot read --ours {path}: {exc}") from exc
    stripped = text.lstrip()
    rows: list[object]
    if stripped.startswith("["):
        rows = json.loads(stripped)
    elif stripped.startswith("{") and "\n" not in stripped.strip():
        payload = json.loads(stripped)
        rows = payload.get("records", [payload]) if isinstance(payload, dict) else [payload]
    else:
        rows = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise InputError(f"--ours {path} line {number}: invalid JSON ({exc.msg})") from exc
    return [flatten_record(row) for row in rows if isinstance(row, Mapping)]


def load_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV/TSV export (UTF-8, BOM tolerated, delimiter sniffed)."""
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise InputError(f"cannot read reference {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"reference {path} is not UTF-8 text") from exc
    first_line = text.split("\n", 1)[0]
    delimiter = "\t" if first_line.count("\t") > first_line.count(",") else ","
    reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
    return [{str(k): (v or "") for k, v in row.items() if k is not None} for row in reader]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --- field lookup ----------------------------------------------------------


def _column_token(name: object) -> str:
    return re.sub(r"[^0-9a-z]", "", str(name).casefold())


def find_column(columns: Iterable[object], aliases: Sequence[str]) -> str | None:
    """Return the first column whose case/punctuation-insensitive name is an alias."""
    by_token: dict[str, str] = {}
    for column in columns:
        by_token.setdefault(_column_token(column), str(column))
    for alias in aliases:
        hit = by_token.get(_column_token(alias))
        if hit is not None:
            return hit
    return None


def pick(row: Mapping[str, object], aliases: Sequence[str]) -> object:
    column = find_column(row.keys(), aliases)
    return row.get(column) if column is not None else None


def any_has(rows: Iterable[Mapping[str, object]], aliases: Sequence[str]) -> bool:
    return any(find_column(row.keys(), aliases) is not None for row in rows)


# --- normalisation ---------------------------------------------------------


def parse_tz(text: str) -> timezone:
    value = (text or "UTC").strip()
    if value.upper() in {"UTC", "Z", "GMT"}:
        return timezone.utc
    match = _OFFSET_RE.match(value)
    if match:
        sign = -1 if match.group(1) == "-" else 1
        delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3) or 0))
        return timezone(sign * delta)
    raise InputError(f"unsupported --reference-tz {text!r}; use UTC or an offset like +09:00")


def _from_number(number: float) -> datetime | None:
    if number <= 0:
        return None
    try:
        if number >= 1e17:  # FILETIME, 100 ns since 1601
            return _WEBKIT_EPOCH + timedelta(microseconds=number / 10)
        if number >= 1e16:  # WebKit/Chromium, us since 1601
            return _WEBKIT_EPOCH + timedelta(microseconds=number)
        if number >= 1e14:  # PRTime (Firefox), us since 1970
            return _UNIX_EPOCH + timedelta(microseconds=number)
        if number >= 1e11:  # unix milliseconds
            return _UNIX_EPOCH + timedelta(milliseconds=number)
        return _UNIX_EPOCH + timedelta(seconds=number)
    except OverflowError:
        return None


def norm_ts(value: object, naive_tz: timezone = timezone.utc) -> str:
    """Normalise a timestamp to UTC ``YYYY-MM-DDTHH:MM:SSZ`` (second precision).

    Accepts ISO 8601 (with or without offset), common tool layouts, and
    numeric FILETIME / WebKit / PRTime / unix ms / unix s. Naive text is read
    in ``naive_tz``. Empty and zero values become ``""``; unparseable text is
    returned stripped so the difference stays visible.
    """
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, (int, float)):
        stamp = _from_number(float(value))
        if stamp is None:
            return ""
    else:
        text = str(value).strip()
        if not text or text in {"0", "-", "N/A", "n/a", "null", "None"}:
            return ""
        if re.fullmatch(r"\d+(\.\d+)?", text):
            stamp = _from_number(float(text))
            if stamp is None:
                return ""
        else:
            stamp = _parse_text_ts(text)
            if stamp is None:
                return text
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=naive_tz)
    stamp = stamp.astimezone(timezone.utc)
    if stamp.year <= 1601:
        return ""
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_text_ts(text: str) -> datetime | None:
    cleaned = text.replace(" UTC", "").replace(" GMT", "").strip()
    iso = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)  # trim 7-digit .NET fractions
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        pass
    for layout in _NAIVE_FORMATS:
        try:
            return datetime.strptime(re.sub(r"(\.\d{6})\d+", r"\1", cleaned), layout)
        except ValueError:
            continue
    try:  # RFC 2822 mail dates: "Mon, 01 Jan 2024 10:00:00 +0900"
        return parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None


def norm_text(value: object) -> str:
    return "" if value is None else " ".join(str(value).split()).casefold()


def norm_path(value: object) -> str:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    text = re.sub(r"\\{2,}", r"\\", text)
    return text.rstrip("\\").casefold()


def norm_int(value: object) -> str:
    if value is None or value == "":
        return ""
    try:
        return str(int(float(str(value).replace(",", "").strip())))
    except ValueError:
        return norm_text(value)


def account_from_path(value: object) -> str:
    match = _USERS_RE.search(str(value or "") + "\\")
    return match.group(1).casefold() if match else ""


# --- keyed diff ------------------------------------------------------------


class FieldSpec:
    """One compared field: aliases on each side plus the normaliser."""

    def __init__(
        self,
        name: str,
        ours: Sequence[str],
        reference: Sequence[str],
        normalise: Callable[[object], str],
    ) -> None:
        self.name = name
        self.ours = tuple(ours)
        self.reference = tuple(reference)
        self.normalise = normalise


def index_rows(
    rows: Iterable[Mapping[str, object]],
    key_fn: Callable[[Mapping[str, object]], str],
    fields: Sequence[FieldSpec],
    side: str,
) -> tuple[dict[str, dict[str, str]], int, int]:
    """Key rows and normalise compared fields.

    Returns ``(index, duplicate_keys, rows_without_key)``. On a duplicate key
    the row with more non-empty compared values wins (first row on a tie).
    """
    index: dict[str, dict[str, str]] = {}
    duplicates = 0
    keyless = 0
    for row in rows:
        key = key_fn(row)
        if not key:
            keyless += 1
            continue
        values = {}
        for spec in fields:
            aliases = spec.ours if side == "ours" else spec.reference
            values[spec.name] = spec.normalise(pick(row, aliases))
        if key in index:
            duplicates += 1
            if sum(bool(v) for v in values.values()) <= sum(bool(v) for v in index[key].values()):
                continue
        index[key] = values
    return index, duplicates, keyless


def diff_keyed(
    ours_rows: Sequence[Mapping[str, object]],
    reference_rows: Sequence[Mapping[str, object]],
    *,
    ours_key: Callable[[Mapping[str, object]], str],
    reference_key: Callable[[Mapping[str, object]], str],
    fields: Sequence[FieldSpec],
    include_rows: bool = False,
) -> dict[str, object]:
    """Compare two keyed row sets; recall = shared keys / reference keys."""
    compared = [
        spec for spec in fields if any_has(ours_rows, spec.ours) and any_has(reference_rows, spec.reference)
    ]
    skipped = [spec.name for spec in fields if spec not in compared]
    ours, ours_dup, ours_keyless = index_rows(ours_rows, ours_key, compared, "ours")
    ref, ref_dup, ref_keyless = index_rows(reference_rows, reference_key, compared, "reference")
    shared = sorted(set(ours) & set(ref))
    missing = sorted(set(ref) - set(ours))
    extra = sorted(set(ours) - set(ref))
    mismatched: list[dict[str, object]] = []
    for key in shared:
        diffs = {
            spec.name: {"ours": ours[key][spec.name], "reference": ref[key][spec.name]}
            for spec in compared
            if ours[key][spec.name] != ref[key][spec.name]
        }
        if diffs:
            mismatched.append({"key": key, "fields": diffs})
    result: dict[str, object] = {
        "recall": round(len(shared) / len(ref), 6) if ref else None,
        "matched": len(shared),
        "missing": missing[:LIST_CAP],
        "extra": extra[:LIST_CAP],
        "mismatched": mismatched[:LIST_CAP],
        "counts": {
            "reference_keys": len(ref),
            "ours_keys": len(ours),
            "matched": len(shared),
            "missing": len(missing),
            "extra": len(extra),
            "mismatched": len(mismatched),
            "reference_duplicate_keys": ref_dup,
            "ours_duplicate_keys": ours_dup,
            "reference_rows_without_key": ref_keyless,
            "ours_rows_without_key": ours_keyless,
        },
        "lists_truncated": max(len(missing), len(extra), len(mismatched)) > LIST_CAP,
        "fields_compared": [spec.name for spec in compared],
        "fields_not_compared": skipped,
    }
    if include_rows:
        mismatched_keys = {str(item["key"]) for item in mismatched}
        result["rows"] = [
            {
                "key": key,
                "status": (
                    "missing"
                    if key not in ours
                    else "extra"
                    if key not in ref
                    else "mismatched"
                    if key in mismatched_keys
                    else "matched"
                ),
            }
            for key in sorted(set(ours) | set(ref))
        ][:LIST_CAP]
    return result


# --- CLI ---------------------------------------------------------------------


def base_parser(description: str, default_tool: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--ours", "--rapid", dest="ours", required=True, type=Path, help="RapidTriage JSONL")
    parser.add_argument("--reference", required=True, type=Path, help="reference tool export")
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    parser.add_argument("--reference-tool", default=default_tool, help="name/version of the reference tool")
    parser.add_argument(
        "--reference-tz",
        default="UTC",
        help="zone of naive reference timestamps: UTC (default) or an offset like +09:00",
    )
    return parser


def envelope(kind: str, reference_tool: str, inputs: Mapping[str, Path], body: Mapping[str, object]) -> dict:
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "comparison": kind,
        "reference_tool": reference_tool,
        "release_evidence_status": "engineering_check_only",
        "timestamp_basis": "UTC, second precision",
    }
    report.update(body)
    report["inputs"] = {
        name: {"path": str(path), "sha256": file_sha256(path) if path.is_file() else ""}
        for name, path in inputs.items()
    }
    return report


def require_inputs(paths: Mapping[str, Path], *, directory: Sequence[str] = ()) -> None:
    for name, path in paths.items():
        if name in directory:
            if not path.is_dir():
                raise InputError(f"{name} folder not found: {path}")
        elif not path.is_file():
            raise InputError(f"{name} file not found: {path}")


def emit(report: Mapping[str, object], output: Path | None, as_json: bool, summary: str) -> int:
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8", newline="\n")
    if as_json:
        sys.stdout.write(text)
    else:
        print(summary)
        if output is not None:
            print(f"-> {output}")
    return 0


def run_cli(main_body: Callable[[], int]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    try:
        return main_body()
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON input ({exc.msg})", file=sys.stderr)
        return EXIT_INPUT_ERROR


def summary_line(report: Mapping[str, object]) -> str:
    counts = report.get("counts") or {}
    return (
        f"recall={report.get('recall')} matched={report.get('matched')} "
        f"missing={counts.get('missing')} extra={counts.get('extra')} "
        f"mismatched={counts.get('mismatched')} reference_tool={report.get('reference_tool')}"
    )
