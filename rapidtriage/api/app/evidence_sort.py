"""Whole-timeline ``sort=timestamp`` order: the console's own evidence-time order, on the server.

Before ``GET /timeline`` sorted, the console grid sorted the loaded events itself with the 시각
column's comparator; the server order is that order over every (filtered) event. Mirrors, and
must stay aligned with:

* ``frontend/src/utils/time.ts`` ``utcTicksOf`` / ``evidenceSortKey`` / ``compareEvidenceSortKeys``
  (keys and their order),
* ``frontend/src/features/grid/columns/common.ts`` ``str`` / ``strOrNull`` / ``rowTimeZone`` /
  ``rowSourceTicks`` and ``evidenceTimeColumnParts`` (what a timeline row's time cell is),
* the grid's table sort (``@tanstack/table-core`` ``createSortedRowModel``): ``desc`` reverses the
  comparison, ties keep record order in both orders.

Order, ascending (``desc`` is its reverse, ties still in record order):

1. events with a time, by group: 0 = an instant (UTC FILETIME ticks: the event's
   ``details.timestamp_utc_ticks`` when it is the same instant to the microsecond, else the
   text's own ticks; text without an offset reads as UTC), 1 = a wall clock of undetermined
   zone (``timezone`` in ``LOCAL_TIMEZONE_LABELS`` and no offset in the text), 2 = text that is
   no ISO date-time; within a group by ticks, then by the text (UTF-16 code units);
2. events without a time (``timestamp`` missing, ``null`` or blank) last; in ``desc`` first.

``tests/fixtures/timeline-sort-parity.json`` pins this order for both sides.
"""

from __future__ import annotations

import json
import math
import re
from array import array
from collections.abc import Iterable, Mapping
from decimal import Decimal

from ...core.filetime import FILETIME_TICKS_PER_SECOND, LOCAL_TIMEZONE_LABELS

# ECMAScript WhiteSpace + LineTerminator: what String.prototype.trim() strips and ``\s`` matches.
JS_SPACE = "\t\n\x0b\x0c\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
# utils/time.ts TICK_TEXT_RE (``/…/i``; ``\d`` is ASCII there).
_TICK_TEXT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[.,]([0-9]+))?"
    rf"[{re.escape(JS_SPACE)}]*([Zz]|[+-][0-9]{{2}}:?[0-9]{{2}})?"
)
_DIGITS = re.compile(r"[0-9]+")
_SURROGATE = re.compile("[\ud800-\udfff]")
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")
_FILETIME_UNIX_SECONDS = 11_644_473_600
_UNTIMED = (1,)


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 of a proleptic Gregorian date (any year, ``month`` 1..12)."""
    year -= month <= 2
    era = year // 400
    year_of_era = year - era * 400
    day_of_year = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    return era * 146097 + year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year - 719468


def utc_ticks_of(value: object) -> tuple[int, bool] | None:
    """``utcTicksOf``: ``(UTC FILETIME ticks, the text named its zone)`` of ISO text, else ``None``.

    Like ``Date.setUTCFullYear`` / ``setUTCHours`` an out-of-range field carries over
    (``2025-02-30`` is March 2nd); up to seven fraction digits count; ticks may be negative."""
    if not isinstance(value, str):
        return None
    match = _TICK_TEXT.fullmatch(value.strip(JS_SPACE))
    if match is None:
        return None
    year, month, day, hours, minutes, seconds = (int(part) for part in match.groups()[:6])
    fraction = match.group(7) or ""
    zone = match.group(8) or ""
    month_index = month - 1
    days = _days_from_civil(year + month_index // 12, month_index % 12 + 1, 1) + day - 1
    total = days * 86400 + hours * 3600 + minutes * 60 + seconds + _FILETIME_UNIX_SECONDS
    if zone and zone.upper() != "Z":
        digits = zone[1:].replace(":", "", 1)
        offset = int(digits[:2]) * 60 + int(digits[2:])
        total -= (-1 if zone[0] == "-" else 1) * offset * 60
    return total * FILETIME_TICKS_PER_SECOND + int(fraction[:7].ljust(7, "0")), zone != ""


def _js_number(value: float) -> str:
    """``String(number)`` (ECMAScript Number::toString, radix 10)."""
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    sign = "-" if value < 0 else ""
    parts = Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(digit) for digit in parts.digits)
    count = len(digits)
    point = int(parts.exponent) + count
    if count <= point <= 21:
        return sign + digits + "0" * (point - count)
    if 0 < point <= 21:
        return f"{sign}{digits[:point]}.{digits[point:]}"
    if -6 < point <= 0:
        return f"{sign}0.{'0' * -point}{digits}"
    exponent = point - 1
    mantissa = digits if count == 1 else f"{digits[0]}.{digits[1:]}"
    return f"{sign}{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"


def _number(value: float) -> float:
    try:
        return float(value)
    except OverflowError:
        return math.inf if value > 0 else -math.inf


def _js_json(value: object) -> str:
    """``JSON.stringify`` of a parsed JSON value (integer-like keys first, as JavaScript orders them)."""
    if value is None or value is True or value is False:
        return json.dumps(value)
    if isinstance(value, (int, float)):
        number = _number(value)
        return _js_number(number) if math.isfinite(number) else "null"
    if isinstance(value, str):
        return _SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", json.dumps(value, ensure_ascii=False))
    if isinstance(value, Mapping):
        keys = [str(key) for key in value]
        indices = sorted((key for key in keys if _ARRAY_INDEX.fullmatch(key) and int(key) < 2**32 - 1), key=int)
        ordered = indices + [key for key in keys if key not in set(indices)]
        return "{" + ",".join(f"{_js_json(key)}:{_js_json(value[key])}" for key in ordered) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_js_json(item) for item in value) + "]"
    return json.dumps(str(value), ensure_ascii=False)


def js_text(value: object) -> str:
    """common.ts ``str``: the text the console shows for a raw value."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _js_number(_number(value))
    return _js_json(value)


def _exact_source_ticks(value: object) -> int | None:
    """``exactSourceFiletime`` of a string source value (decimal ticks text)."""
    if not isinstance(value, str):
        return None
    text = value.strip(JS_SPACE)
    return int(text) if _DIGITS.fullmatch(text) else None


def _trunc10(value: int) -> int:
    """BigInt ``value / 10n`` (truncates toward zero)."""
    return -(-value // 10) if value < 0 else value // 10


def _utf16(text: str) -> str:
    """``text`` whose code-point order is the UTF-16 code-unit order JavaScript compares by."""
    if text.isascii() or all(ord(char) < 0x10000 for char in text):
        return text
    units = []
    for char in text:
        point = ord(char)
        if point < 0x10000:
            units.append(char)
        else:
            point -= 0x10000
            units.append(chr(0xD800 + (point >> 10)) + chr(0xDC00 + (point & 0x3FF)))
    return "".join(units)


def timeline_sort_key(row: object) -> tuple[object, ...]:
    """Ascending sort key of one timeline event (module doc)."""
    raw = row if isinstance(row, Mapping) else {}
    text = js_text(raw.get("timestamp")).strip(JS_SPACE)
    if not text:
        return _UNTIMED
    zone = js_text(raw.get("timezone"))
    details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
    reading = utc_ticks_of(text)
    # The timeline's offset-free wall-clock labels (core.timeline keeps them apart from UTC
    # instants; frontend utils/time.ts WALL_CLOCK_ZONES is the same set).
    if reading is not None and zone in LOCAL_TIMEZONE_LABELS and not reading[1]:
        return (0, 1, reading[0], _utf16(text))
    exact = _exact_source_ticks(details.get("timestamp_utc_ticks"))
    if reading is not None and exact is not None and _trunc10(exact) == _trunc10(reading[0]):
        return (0, 0, exact, _utf16(text))
    if reading is not None:
        return (0, 0, reading[0], _utf16(text))
    return (0, 2, 0, _utf16(text))


def timeline_order(rows: Iterable[object], order: str) -> array:
    """Positions of the timeline ``rows`` in ``order`` (``asc`` | ``desc``); ties keep record order."""
    keys = [timeline_sort_key(row) for row in rows]
    # ``reverse`` keeps equal keys in their original (record) order.
    return array("L", sorted(range(len(keys)), key=keys.__getitem__, reverse=order == "desc"))
