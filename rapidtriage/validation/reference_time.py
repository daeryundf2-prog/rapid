"""Timestamp reading for the reference-diff comparisons (split from ``reference_diff.py``).

Forms: ISO-like (``T`` or space, fractions, ``Z``/offset/``(UTC)``), FILETIME integers, slashed
dates in the comparison's date order (``mdy``/``dmy``; year-first is always Y/M/D), the Korean
``오전/오후`` form, ``DD-Mon-YYYY`` and ``dd.MM.yyyy``. ``reference_diff`` re-exports every name.
"""

from __future__ import annotations

import datetime as dt
import re
from contextvars import ContextVar

FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
DATE_ORDERS = ("mdy", "dmy", "ymd")
DEFAULT_DATE_ORDER = "mdy"
#: Order of a slashed date for this comparison, and whether the operator chose it.
_DATE_ORDER: ContextVar[tuple[str, bool]] = ContextVar("reference_diff_date_order", default=(DEFAULT_DATE_ORDER, False))

__all__ = [
    "DATE_ORDERS",
    "DEFAULT_DATE_ORDER",
    "FILETIME_EPOCH",
    "ReferenceDiffInputError",
    "format_timestamp",
    "is_ambiguous_slashed_date",
    "parse_timestamp",
    "parse_tz",
]


class ReferenceDiffInputError(Exception):
    """Input problem reported to the operator in Korean; the CLI exits 2."""


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
