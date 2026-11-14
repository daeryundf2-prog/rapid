"""Shared core of the ``scripts/*-reference-diff.py`` export comparisons (T-204..T-207).

Each comparison script turns two inputs into keyed rows and hands them here:

* ``--ours`` (alias ``--rapid``): RapidTriage output -- a per-kind artifacts output
  ``.json`` (JSONL-backed or inline; profile-hoisted rows are expanded), a JSONL of artifact
  rows, or a JSON array of flat rows.
* ``--reference``: a dedicated tool's CSV/TSV/pipe export (or a tool listing a script
  parses itself, e.g. Sleuth Kit ``fls``).

The diff matches rows by key (each row may carry alias keys, tried in order), then
compares the fields the reference row fills. The JSON report always carries the five keys
the R8 task table fixes -- ``recall``, ``matched``, ``missing``, ``mismatched``,
``reference_tool`` -- plus ``extra`` (rows only RapidTriage has) and ``counts``.

* ``matched``    -- number of reference rows found in ours (mismatched ones included).
* ``recall``     -- ``matched / reference rows`` (``None`` when the reference is empty).
* ``missing``    -- reference rows not found in ours (only_reference).
* ``extra``      -- our rows no reference row claimed (only_rapid).
* ``mismatched`` -- matched rows with at least one differing field, per field
  ``{"ours": ..., "reference": ...}``.

Timestamps are normalised to UTC and compared at whole-second precision (floor), within
``--time-tolerance`` seconds; naive timestamps take ``--ours-tz`` / ``--reference-tz``
(default UTC). Read forms: ISO-like, slashed dates (order ``--date-order mdy|dmy|ymd``, default
the script's tool profile; a day/month-ambiguous date read by the default order is warned and
counted), ``dd.MM.yyyy``, ``DD-Mon-YYYY`` and the Korean ``오전/오후`` form. A time value that
cannot be read is counted per side and field (``unparsed_time_count``,
``unparsed_time_fields``); one in a key or compared field makes the result not clean
(``status: unparsed-time``, exit 1) -- it was not compared. Exit codes: 0 every reference row
matched without field differences, 1 differences or unread times, 2 input or usage error or a
reference with 0 comparable rows ("기준 행 0개 — 비교 불가"; a Korean message names the problem).
Each input's decoding is recorded (``inputs.<name>.encoding``); the cp949 fallback and U+FFFD
replacement characters are warned.

Engineering measurement only: reports say ``engineering_check_only`` and are not release
evidence (see AGENTS.md "RapidForensic Validation Contract").
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import hashlib
import io
import json
import re
import sys
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from rapidtriage.core.artifact_profiles import (
    PROFILE_REF_KEY,
    iter_artifact_output_rows,
)

SCHEMA_VERSION = "reference-diff-v1"
EXIT_OK = 0
EXIT_DIFF = 1
EXIT_INPUT = 2
DEFAULT_MAX_LIST = 1000
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
_EMPTY = (None, "", [], (), frozenset(), set())


DATE_ORDERS = ("mdy", "dmy", "ymd")
DEFAULT_DATE_ORDER = "mdy"
NO_REFERENCE_MESSAGE = "기준 행 0개 — 비교 불가"
#: Order of a slashed date for this comparison, and whether the operator chose it.
_DATE_ORDER: ContextVar[tuple[str, bool]] = ContextVar("reference_diff_date_order", default=(DEFAULT_DATE_ORDER, False))
#: Path -> decoding used by ``read_text`` (recorded in the report's ``inputs``).
_DECODINGS: ContextVar[dict[str, str] | None] = ContextVar("reference_diff_decodings", default=None)


class ReferenceDiffInputError(Exception):
    """Input problem reported to the operator in Korean; the CLI exits 2."""


class DiffWarnings(list):
    """The warnings list plus the counts a capped list cannot carry (unread times, ambiguous dates)."""

    def __init__(self) -> None:
        super().__init__()
        self.unparsed_time: dict[str, dict[str, int]] = {"reference": {}, "ours": {}}
        self.ambiguous_dates = 0

    def count_unparsed(self, side: str, name: str) -> None:
        bucket = self.unparsed_time.setdefault(side, {})
        bucket[name] = bucket.get(name, 0) + 1

    @property
    def unparsed_total(self) -> int:
        return sum(sum(fields.values()) for fields in self.unparsed_time.values())

    def unparsed_in(self, names: Iterable[str]) -> int:
        wanted = set(names)
        return sum(count for fields in self.unparsed_time.values() for name, count in fields.items() if name in wanted)


@dataclass
class KeyedRow:
    """One comparable row: ``keys[0]`` is the primary key, the rest are aliases."""

    keys: list[str]
    fields: dict[str, object] = field(default_factory=dict)
    label: dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


def normalize_text(value: object) -> str:
    """NFC + casefold + trimmed; ``""`` for empty values."""
    if value is None:
        return ""
    return unicodedata.normalize("NFC", str(value)).strip().casefold()


def normalize_path(value: object, strip_prefix: str = "") -> str:
    r"""Volume-relative, forward-slash, casefolded path.

    Drops ``\\?\``, a drive letter and leading slashes. With ``strip_prefix`` (e.g.
    ``_e01/fs``) everything up to and including that component run is cut; a path that does
    not contain it is kept as is.
    """
    text = unicodedata.normalize("NFC", str(value or "")).strip().strip('"').replace("\\", "/")
    text = text.removeprefix("//?/")
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    text = text.strip("/")
    prefix = str(strip_prefix or "").replace("\\", "/").strip("/")
    if prefix:
        lowered, needle = text.casefold(), prefix.casefold()
        if lowered.startswith(needle + "/"):
            text = text[len(prefix) + 1 :]
        else:
            index = lowered.find("/" + needle + "/")
            if index >= 0:
                text = text[index + len(prefix) + 2 :]
    return re.sub(r"/{2,}", "/", text).casefold()


def header_key(name: object) -> str:
    """Column name compared without case, spaces or punctuation (``Last Executed`` = ``lastexecuted``)."""
    return re.sub(r"[^0-9a-z]", "", str(name or "").casefold())


def parse_tz(text: str | None) -> dt.tzinfo:
    """``UTC``/``Z``, a fixed offset (``+09:00``, ``-0500``) or an IANA name (``Asia/Seoul``)."""
    raw = str(text or "UTC").strip()
    if raw.upper() in {"UTC", "Z", "GMT"}:
        return dt.timezone.utc
    match = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})?", raw)
    if match:
        sign = -1 if match.group(1) == "-" else 1
        offset = dt.timedelta(hours=int(match.group(2)), minutes=int(match.group(3) or 0))
        return dt.timezone(sign * offset)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(raw)
    except Exception as exc:  # ZoneInfoNotFoundError, ValueError, missing tzdata
        raise ReferenceDiffInputError(
            f"시간대 '{raw}'를 알 수 없습니다. UTC 또는 +09:00 같은 고정 오프셋을 쓰세요."
        ) from exc


_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2}):(\d{2})(?:[.,:](\d+)(?::\d+)*)?\s*"
    r"(Z|UTC|[+-]\d{2}:?\d{2})?(?:\s*\(?UTC\)?)?$",
    re.IGNORECASE,
)
_SLASH_RE = re.compile(
    r"^(\d{1,4})/(\d{1,2})/(\d{1,4})\s+(AM|PM|오전|오후)?\s*(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?\s*(AM|PM|오전|오후)?$",
    re.IGNORECASE,
)
# Korean Windows / Excel: "2023-01-01 오후 3:04:05", "2023. 1. 1. 오후 3:04".
_KOREAN_RE = re.compile(
    r"^(\d{4})\s*[-./]\s*(\d{1,2})\s*[-./]\s*(\d{1,2})\.?\s+(오전|오후)\s*(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?$"
)
# "05-Mar-2019 10:00:00", "5 Mar 2019 10:00", optional AM/PM and zone.
_MON_RE = re.compile(
    r"^(\d{1,2})[- ]([A-Za-z]{3})[A-Za-z]*\.?[- ](\d{4})[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?\s*(AM|PM)?"
    r"\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)
# "05.03.2019 10:00:00" (day first by convention).
_DOTTED_RE = re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{4})[ T]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?$")
_MONTHS = {name: index for index, name in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}


def parse_timestamp(value: object, default_tz: dt.tzinfo = dt.timezone.utc) -> dt.datetime | None:
    """Aware UTC datetime from ISO/space/US text, a FILETIME integer or a datetime; ``None`` when empty.

    The FILETIME zero / Unix epoch placeholders some tools print for "no time" become ``None``.
    Unparseable text raises ``ValueError``.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, dt.datetime):
        stamp = value if value.tzinfo else value.replace(tzinfo=default_tz)
    elif isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit() and len(value.strip()) >= 15):
        filetime = int(value)
        if filetime <= 0:
            return None
        stamp = FILETIME_EPOCH + dt.timedelta(microseconds=filetime // 10)
    else:
        text = str(value).strip()
        if not text:
            return None
        stamp = _parse_timestamp_text(text, default_tz)
    stamp = stamp.astimezone(dt.timezone.utc)
    if stamp.year in {1601, 1970} and stamp.month == 1 and stamp.day == 1 and not stamp.hour and not stamp.minute and not stamp.second:
        return None
    return stamp


def _parse_timestamp_text(text: str, default_tz: dt.tzinfo) -> dt.datetime:
    match = _ISO_RE.match(text)
    if match:
        year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
        micro = int((match.group(7) or "0")[:6].ljust(6, "0"))
        zone = (match.group(8) or "").upper()
        tz = default_tz if not zone else dt.timezone.utc if zone in {"Z", "UTC"} else parse_tz(zone)
        return dt.datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    match = _SLASH_RE.match(text)
    if match:
        first, middle, last = match.group(1), int(match.group(2)), match.group(3)
        order = _DATE_ORDER.get()[0]
        if len(first) == 4:  # year first: always Y/M/D
            year, month, day = int(first), middle, int(last)
        elif len(last) == 4 and order != "ymd":
            year = int(last)
            month, day = (int(first), middle) if order == "mdy" else (middle, int(first))
        else:
            raise ValueError(f"date order {order} does not fit {text!r}")
        hour = _meridiem_hour(int(match.group(5)), match.group(4) or match.group(9))
        return dt.datetime(year, month, day, hour, int(match.group(6)), int(match.group(7) or 0), _micro(match.group(8)), tzinfo=default_tz)
    match = _KOREAN_RE.match(text)
    if match:
        year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
        hour = _meridiem_hour(int(match.group(5)), match.group(4))
        return dt.datetime(year, month, day, hour, int(match.group(6)), int(match.group(7) or 0), _micro(match.group(8)), tzinfo=default_tz)
    match = _MON_RE.match(text)
    if match and match.group(2).lower()[:3] in _MONTHS:
        day, month, year = int(match.group(1)), _MONTHS[match.group(2).lower()[:3]], int(match.group(3))
        hour = _meridiem_hour(int(match.group(4)), match.group(8))
        zone = (match.group(9) or "").upper()
        tz = default_tz if not zone else dt.timezone.utc if zone in {"Z", "UTC", "GMT"} else parse_tz(zone)
        return dt.datetime(year, month, day, hour, int(match.group(5)), int(match.group(6) or 0), _micro(match.group(7)), tzinfo=tz)
    match = _DOTTED_RE.match(text)
    if match:
        day, month, year = int(match.group(1)), int(match.group(2)), int(match.group(3))
        return dt.datetime(
            year, month, day, int(match.group(4)), int(match.group(5)), int(match.group(6) or 0), _micro(match.group(7)), tzinfo=default_tz
        )
    raise ValueError(f"unrecognised timestamp {text!r}")


def _micro(fraction: str | None) -> int:
    return int((fraction or "0")[:6].ljust(6, "0"))


def _meridiem_hour(hour: int, meridiem: str | None) -> int:
    mark = (meridiem or "").upper()
    if mark in {"PM", "오후"} and hour < 12:
        return hour + 12
    if mark in {"AM", "오전"} and hour == 12:
        return 0
    return hour


def is_ambiguous_slashed_date(value: object) -> bool:
    """A year-last slashed date whose first two parts could each be the month (``03/04/2024``)."""
    match = _SLASH_RE.match(str(value or "").strip())
    if not match or len(match.group(1)) == 4 or len(match.group(3)) != 4:
        return False
    first, middle = int(match.group(1)), int(match.group(2))
    return first <= 12 and middle <= 12 and first != middle


def format_timestamp(value: dt.datetime | None) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` (second precision, UTC) or ``""``."""
    if value is None:
        return ""
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_timestamp(
    value: object,
    default_tz: dt.tzinfo,
    warnings: list[str],
    context: str,
    field: str = "time",
    side: str | None = None,
) -> dt.datetime | None:
    """``parse_timestamp`` that records an unparseable value in ``warnings`` instead of raising.

    With a :class:`DiffWarnings` list the failure is also counted for ``side`` (default: from the
    context, "기준 ..." = reference) and ``field``, and an ambiguous slashed date read by the
    default date order is counted and warned.
    """
    which = side or ("reference" if str(context).startswith("기준") else "ours")
    try:
        stamp = parse_timestamp(value, default_tz)
    except (ValueError, OverflowError):
        add_warning(warnings, f"{context}: 시각 형식을 읽지 못했습니다 ({str(value)[:60]!r}) — 비교하지 않음")
        if isinstance(warnings, DiffWarnings):
            warnings.count_unparsed(which, field)
        return None
    order, explicit = _DATE_ORDER.get()
    if not explicit and isinstance(value, str) and is_ambiguous_slashed_date(value):
        add_warning(warnings, f"날짜 순서가 모호함 ({value.strip()[:40]!r}): {order}로 읽음 — --date-order mdy|dmy로 지정하세요")
        if isinstance(warnings, DiffWarnings):
            warnings.ambiguous_dates += 1
    return stamp


_INT_RE = re.compile(r"[+-]?\d+")


def parse_int(value: object) -> int | None:
    """Integer from int/decimal/hex text, exact for any size (MFT references > 2^53);
    ``None`` when empty or not a number."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().replace(",", "")
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if _INT_RE.fullmatch(text):
            return int(text)
        return int(float(text))
    except (ValueError, OverflowError):
        return None


def parse_bool(value: object) -> bool | None:
    """``True``/``False`` from bool or yes/no/true/false/1/0/y/n/예/아니오 text; ``None`` when empty."""
    if isinstance(value, bool):
        return value
    text = normalize_text(value)
    if text in {"1", "true", "yes", "y", "t", "예", "o"}:
        return True
    if text in {"0", "false", "no", "n", "f", "아니오", "x"}:
        return False
    return None


def add_warning(warnings: list[str], message: str, limit: int = 50) -> None:
    if len(warnings) < limit and message not in warnings:
        warnings.append(message)


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


def require_file(path: Path, flag: str) -> Path:
    if not path.is_file():
        raise ReferenceDiffInputError(f"입력 파일이 없습니다: {path} ({flag}). 경로를 확인하세요.")
    return path


def read_text(path: Path) -> str:
    """UTF-16 (BOM), UTF-8, else cp949 with replacement; the decoding used is recorded."""
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text, encoding = raw.decode("utf-16"), "utf-16"
    else:
        try:
            text, encoding = raw.decode("utf-8-sig"), "utf-8"
        except UnicodeDecodeError:
            text, encoding = raw.decode("cp949", errors="replace"), "cp949-fallback"
    if "\ufffd" in text:
        encoding += "+replacement"
    decodings = _DECODINGS.get()
    if decodings is not None:
        decodings[str(path)] = encoding
    return text


def decoding_warnings(decodings: Mapping[str, str]) -> list[str]:
    """Korean warnings for inputs read through the cp949 fallback or holding U+FFFD."""
    messages: list[str] = []
    for path, encoding in decodings.items():
        name = Path(path).name
        if encoding.startswith("cp949"):
            messages.append(f"{name}: UTF-8로 읽지 못해 cp949로 읽음 — 한글 이름이 깨졌다면 인코딩을 확인하세요")
        if encoding.endswith("+replacement"):
            messages.append(f"{name}: 읽을 수 없는 바이트가 대체 문자(U+FFFD)로 바뀜")
    return messages


def read_table(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Rows of a CSV/TSV/pipe/semicolon export keyed by ``header_key`` column names.

    The delimiter is the most frequent of ``, \\t | ;`` on the header line.
    """
    text = read_text(path)
    lines = text.splitlines()
    header_line = next((line for line in lines if line.strip()), "")
    if not header_line:
        raise ReferenceDiffInputError(f"기준 파일이 비어 있습니다: {path}")
    delimiter = max((",", "\t", "|", ";"), key=header_line.count)
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    header: list[str] = []
    rows: list[dict[str, str]] = []
    for record in reader:
        if not any(cell.strip() for cell in record):
            continue
        if not header:
            header = [header_key(cell) for cell in record]
            continue
        rows.append({name: (record[index].strip() if index < len(record) else "") for index, name in enumerate(header) if name})
    return rows, header


def pick(row: Mapping[str, object], *aliases: str) -> str:
    """First non-empty value among ``aliases`` (already ``header_key`` form)."""
    for alias in aliases:
        value = row.get(alias)
        if value not in _EMPTY:
            return str(value).strip()
    return ""


def require_columns(header: Sequence[str], source: Path, /, **groups: Sequence[str]) -> None:
    """Every named group needs at least one of its aliases in ``header``."""
    present = set(header)
    absent = [name for name, aliases in groups.items() if not present.intersection(aliases)]
    if absent:
        raise ReferenceDiffInputError(
            f"기준 파일 {source.name}에 필요한 열이 없습니다: {', '.join(absent)} "
            f"(인식한 열: {', '.join(header) or '없음'})"
        )


def iter_rapid_rows(path: Path, artifact_types: Iterable[str] | None, warnings: list[str]) -> Iterator[dict[str, object]]:
    """RapidTriage rows from a per-kind output ``.json``, a JSON array or a JSONL file.

    Rows whose ``artifact_type`` is not in ``artifact_types`` are skipped; rows without an
    ``artifact_type`` (flat exports) are kept.
    """
    wanted = {str(item) for item in artifact_types} if artifact_types else set()
    for row in _iter_raw_rows(path, warnings):
        if not isinstance(row, dict):
            continue
        kind = row.get("artifact_type")
        if wanted and kind and str(kind) not in wanted:
            continue
        if row.get(PROFILE_REF_KEY):
            add_warning(
                warnings,
                "우리 행에 profile_ref가 남아 있습니다: JSONL 대신 같은 폴더의 per-kind 출력 .json을 --ours로 주면 "
                "생략된 공통 필드까지 복원됩니다.",
            )
        yield row


def _iter_raw_rows(path: Path, warnings: list[str]) -> Iterator[object]:
    with path.open("rb") as handle:
        head = handle.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
    try:
        if head.startswith(b"["):
            yield from json.loads(read_text(path))
        elif head.startswith(b"{") and path.suffix.lower() == ".json":
            yield from iter_artifact_output_rows(path)
        else:
            for line_number, line in enumerate(read_text(path).splitlines(), start=1):
                if line.strip().startswith("{"):
                    try:
                        yield json.loads(line)
                    except ValueError:
                        add_warning(warnings, f"{path.name} {line_number}번째 줄이 JSON이 아니어서 건너뛰었습니다")
    except (ValueError, OSError) as exc:
        raise ReferenceDiffInputError(f"우리 출력 파일을 읽지 못했습니다: {path} ({exc})") from exc


def rapid_field(row: Mapping[str, object], *names: str) -> object:
    """First non-empty ``names`` value on the row, its ``details`` or ``details.raw``."""
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    raw = details.get("raw") if isinstance(details.get("raw"), Mapping) else {}
    for scope in (row, details, raw):
        for name in names:
            value = scope.get(name)  # type: ignore[union-attr]
            if value not in _EMPTY:
                return value
    return None


def drop_blank_key_part(rows_a: list[KeyedRow], rows_b: list[KeyedRow], part: int) -> bool:
    """Remove key component ``part`` (``|``-separated) from both sides when either side never fills it.

    Used for optional qualifiers (account, control set): a tool that does not export them
    must not turn every row into a miss. Returns ``True`` when the part was dropped.
    """
    def blank(rows: list[KeyedRow]) -> bool:
        return all(not row.keys[0].split("|")[part] for row in rows)

    if not (rows_a and rows_b) or not (blank(rows_a) or blank(rows_b)):
        return False
    for row in (*rows_a, *rows_b):
        row.keys = ["|".join(piece for index, piece in enumerate(key.split("|")) if index != part) for key in row.keys]
    return True


# ---------------------------------------------------------------------------
# Diff + report
# ---------------------------------------------------------------------------


@dataclass
class DiffResult:
    reference_count: int
    ours_count: int
    matched: int
    missing: list[dict[str, object]]
    extra: list[dict[str, object]]
    mismatched: list[dict[str, object]]
    duplicate_reference_keys: int
    duplicate_ours_keys: int
    field_mismatch_counts: dict[str, int]
    matched_pairs: list[tuple[KeyedRow, KeyedRow]] = field(default_factory=list, repr=False)


def _render(value: object) -> object:
    if isinstance(value, dt.datetime):
        return format_timestamp(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return value


def _values_differ(ours: object, reference: object, tolerance_s: float) -> bool:
    if isinstance(reference, dt.datetime):
        if not isinstance(ours, dt.datetime):
            return True
        delta = abs(ours.replace(microsecond=0) - reference.replace(microsecond=0)).total_seconds()
        return delta > tolerance_s
    return ours != reference


def diff_rows(ours: Sequence[KeyedRow], reference: Sequence[KeyedRow], *, time_tolerance_s: float = 0.0) -> DiffResult:
    """Match reference rows to ours by key/aliases and compare the fields the reference fills."""
    index: dict[str, list[int]] = {}
    primary_index: dict[str, int] = {}
    duplicate_ours = 0
    for position, row in enumerate(ours):
        if row.keys[0] in primary_index:
            duplicate_ours += 1
        primary_index.setdefault(row.keys[0], position)
        for key in dict.fromkeys(row.keys):
            index.setdefault(key, []).append(position)
    consumed: set[int] = set()
    seen_reference: set[str] = set()
    duplicate_reference = 0
    unique_reference: list[KeyedRow] = []
    for row in reference:
        if row.keys[0] in seen_reference:
            duplicate_reference += 1
            continue
        seen_reference.add(row.keys[0])
        unique_reference.append(row)
    # Pass 1 pairs exact primary keys so an alias can never steal a row another reference row
    # names exactly; pass 2 tries the remaining reference rows' keys and aliases in order.
    hits: dict[int, int] = {}
    for ref_position, row in enumerate(unique_reference):
        primary = primary_index.get(row.keys[0])
        if primary is not None and primary not in consumed:
            consumed.add(primary)
            hits[ref_position] = primary
    for ref_position, row in enumerate(unique_reference):
        if ref_position in hits:
            continue
        hit = next(
            (position for key in row.keys for position in index.get(key, ()) if position not in consumed),
            None,
        )
        if hit is not None:
            consumed.add(hit)
            hits[ref_position] = hit
    missing: list[dict[str, object]] = []
    mismatched: list[dict[str, object]] = []
    pairs: list[tuple[KeyedRow, KeyedRow]] = []
    field_counts: dict[str, int] = {}
    for ref_position, row in enumerate(unique_reference):
        hit = hits.get(ref_position)
        if hit is None:
            missing.append({"key": row.keys[0], **{k: _render(v) for k, v in row.label.items()}})
            continue
        mine = ours[hit]
        pairs.append((mine, row))
        differing: dict[str, object] = {}
        for name, expected in row.fields.items():
            if expected in _EMPTY:
                continue
            actual = mine.fields.get(name)
            if _values_differ(actual, expected, time_tolerance_s):
                differing[name] = {"ours": _render(actual), "reference": _render(expected)}
                field_counts[name] = field_counts.get(name, 0) + 1
        if differing:
            mismatched.append({"key": row.keys[0], "ours_key": mine.keys[0], "fields": differing})
    extra = [
        {"key": row.keys[0], **{k: _render(v) for k, v in row.label.items()}}
        for position, row in enumerate(ours)
        if position not in consumed
    ]
    return DiffResult(
        reference_count=len(unique_reference),
        ours_count=len(ours),
        matched=len(pairs),
        missing=missing,
        extra=extra,
        mismatched=mismatched,
        duplicate_reference_keys=duplicate_reference,
        duplicate_ours_keys=duplicate_ours,
        field_mismatch_counts=dict(sorted(field_counts.items())),
        matched_pairs=pairs,
    )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_report(
    *,
    comparison: str,
    reference_tool: str,
    result: DiffResult,
    inputs: Mapping[str, Path],
    settings: Mapping[str, object],
    key_fields: Sequence[str],
    compared_fields: Sequence[str],
    warnings: Sequence[str],
    max_list: int,
    extra_sections: Mapping[str, object] | None = None,
) -> dict[str, object]:
    def cap(items: list[dict[str, object]]) -> list[dict[str, object]]:
        return items if max_list <= 0 else items[:max_list]

    recall = round(result.matched / result.reference_count, 6) if result.reference_count else None
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "comparison": comparison,
        "release_evidence_status": "engineering_check_only",
        "report_use_warning": (
            "Engineering measurement of RapidTriage output against a reference tool export. "
            "Not release evidence; the reference tool's own accuracy is not established here."
        ),
        "reference_tool": reference_tool,
        "recall": recall,
        "matched": result.matched,
        "missing": cap(result.missing),
        "mismatched": cap(result.mismatched),
        "extra": cap(result.extra),
        "counts": {
            "reference": result.reference_count,
            "ours": result.ours_count,
            "matched": result.matched,
            "missing": len(result.missing),
            "extra": len(result.extra),
            "mismatched": len(result.mismatched),
            "fully_matched": result.matched - len(result.mismatched),
            "duplicate_reference_keys": result.duplicate_reference_keys,
            "duplicate_ours_keys": result.duplicate_ours_keys,
        },
        "lists_truncated": bool(max_list > 0 and max(len(result.missing), len(result.extra), len(result.mismatched)) > max_list),
        "field_mismatch_counts": result.field_mismatch_counts,
        "key_fields": list(key_fields),
        "compared_fields": list(compared_fields),
        "settings": dict(settings),
        "inputs": {name: {"path": str(path), "sha256": file_sha256(path)} for name, path in inputs.items()},
        "warnings": list(warnings),
    }
    if extra_sections:
        report.update(extra_sections)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@dataclass
class Comparison:
    """What a script returns from its builder."""

    ours: list[KeyedRow]
    reference: list[KeyedRow]
    reference_tool: str
    key_fields: list[str]
    compared_fields: list[str]
    extra_sections: Callable[[DiffResult], Mapping[str, object]] | None = None


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ours", "--rapid", dest="ours", type=Path, help="RapidTriage output (.json per-kind output, JSONL, or JSON array)")
    parser.add_argument("--reference", type=Path, help="reference tool export")
    parser.add_argument("--output", type=Path, help="write the JSON report here")
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    parser.add_argument("--reference-tool", default="", help="reference tool name/version recorded in the report (default: detected)")
    parser.add_argument("--reference-tz", default="UTC", help="time zone of naive reference timestamps (UTC, +09:00, Asia/Seoul)")
    parser.add_argument("--ours-tz", default="UTC", help="time zone of naive RapidTriage timestamps")
    parser.add_argument("--time-tolerance", type=float, default=0.0, help="allowed difference in whole seconds (default 0)")
    parser.add_argument("--max-list", type=int, default=DEFAULT_MAX_LIST, help="cap missing/extra/mismatched lists (0 = no cap)")
    parser.add_argument(
        "--date-order",
        choices=DATE_ORDERS,
        default=None,
        help="order of slashed dates such as 03/04/2024 (default: the tool profile's, usually mdy; ambiguous dates are warned)",
    )


def unparsed_time_section(warnings: list[str], unclean_fields: Iterable[str]) -> dict[str, object]:
    """Report keys for unread time values (``unparsed_time_count`` per side and field)."""
    if not isinstance(warnings, DiffWarnings):
        return {"unparsed_time_count": 0, "unparsed_time_fields": {"reference": {}, "ours": {}}, "unparsed_time_uncompared": 0}
    return {
        "unparsed_time_count": warnings.unparsed_total,
        "unparsed_time_fields": {side: dict(sorted(fields.items())) for side, fields in warnings.unparsed_time.items()},
        "unparsed_time_uncompared": warnings.unparsed_in(unclean_fields),
        "ambiguous_date_count": warnings.ambiguous_dates,
    }


def run_comparison_cli(
    argv: Sequence[str] | None,
    *,
    comparison: str,
    description: str,
    build: Callable[[argparse.Namespace, list[str]], Comparison],
    configure: Callable[[argparse.ArgumentParser], None] | None = None,
    required_inputs: Sequence[tuple[str, str]] = (("ours", "--ours"), ("reference", "--reference")),
    default_date_order: str = DEFAULT_DATE_ORDER,
) -> int:
    """Parse the uniform CLI, run ``build`` and the diff, write/print the report; return the exit code.

    ``default_date_order`` is the tool profile's slashed-date order (``--date-order`` overrides)."""
    parser = argparse.ArgumentParser(description=description)
    add_common_arguments(parser)
    if configure is not None:
        configure(parser)
    args = parser.parse_args(argv)
    warnings = DiffWarnings()
    with comparison_scope(args.date_order, default_date_order) as (date_order, decodings):
        return _run_comparison(args, comparison, build, required_inputs, warnings, date_order, decodings)


@contextlib.contextmanager
def comparison_scope(date_order_option: str | None, default_date_order: str = DEFAULT_DATE_ORDER) -> Iterator[tuple[str, dict[str, str]]]:
    """Slashed-date order and decoding record for one comparison; yields (order, decodings)."""
    date_order = date_order_option or default_date_order
    order_token = _DATE_ORDER.set((date_order, date_order_option is not None))
    decodings: dict[str, str] = {}
    decodings_token = _DECODINGS.set(decodings)
    try:
        yield date_order, decodings
    finally:
        _DATE_ORDER.reset(order_token)
        _DECODINGS.reset(decodings_token)


def _run_comparison(
    args: argparse.Namespace,
    comparison: str,
    build: Callable[[argparse.Namespace, list[str]], Comparison],
    required_inputs: Sequence[tuple[str, str]],
    warnings: DiffWarnings,
    date_order: str,
    decodings: Mapping[str, str],
) -> int:
    try:
        inputs: dict[str, Path] = {}
        for dest, flag in required_inputs:
            value = getattr(args, dest, None)
            if value is None:
                raise ReferenceDiffInputError(f"{flag} 인자가 필요합니다.")
            inputs[dest] = require_file(Path(value), flag)
        args.reference_tzinfo = parse_tz(args.reference_tz)
        args.ours_tzinfo = parse_tz(args.ours_tz)
        built = build(args, warnings)
    except ReferenceDiffInputError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return EXIT_INPUT
    result = diff_rows(built.ours, built.reference, time_tolerance_s=max(0.0, float(args.time_tolerance)))
    report = build_report(
        comparison=comparison,
        reference_tool=str(args.reference_tool or built.reference_tool),
        result=result,
        inputs=inputs,
        settings={
            "reference_tz": args.reference_tz,
            "ours_tz": args.ours_tz,
            "time_tolerance_s": args.time_tolerance,
            "time_precision": "second",
            "date_order": date_order,
            "date_order_source": "option" if args.date_order else "tool-default",
            "max_list": args.max_list,
        },
        key_fields=built.key_fields,
        compared_fields=built.compared_fields,
        warnings=[*warnings, *decoding_warnings(decodings)],
        max_list=args.max_list,
        extra_sections=built.extra_sections(result) if built.extra_sections else None,
    )
    report.update(unparsed_time_section(warnings, [*built.key_fields, *built.compared_fields]))
    for name, item in report["inputs"].items():  # type: ignore[union-attr]
        item["encoding"] = decodings.get(str(inputs[name]), "")
    if result.reference_count == 0:
        status = "no-reference"
    elif report["unparsed_time_uncompared"]:
        status = "unparsed-time"
    elif result.matched == result.reference_count and not result.mismatched:
        status = "clean"
    else:
        status = "differences"
    report["status"] = status
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    if args.json:
        sys.stdout.write(text)
    else:
        counts = report["counts"]
        print(
            f"{comparison}: reference={counts['reference']} ours={counts['ours']} matched={counts['matched']} "  # type: ignore[index]
            f"recall={report['recall']} missing={counts['missing']} extra={counts['extra']} "  # type: ignore[index]
            f"mismatched={counts['mismatched']}"  # type: ignore[index]
        )
        if report["unparsed_time_count"]:
            print(f"읽지 못한 시각 {report['unparsed_time_count']}개 (비교하지 않음): {report['unparsed_time_fields']}")
        if args.output is not None:
            print(f"-> {args.output}")
    if status == "no-reference":
        print(f"오류: {NO_REFERENCE_MESSAGE} (기준 파일의 행·열을 확인하세요)", file=sys.stderr)
        return EXIT_INPUT
    return EXIT_OK if status == "clean" else EXIT_DIFF
