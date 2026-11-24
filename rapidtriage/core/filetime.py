"""Integer timestamp conversions shared by parsers (stdlib only).

Windows FILETIME (100 ns ticks since 1601-01-01 UTC), Chrome/WebKit
(microseconds since 1601-01-01 UTC) and Unix epoch values are converted with
integer arithmetic so the 100 ns precision of FILETIME survives (a float
``datetime.fromtimestamp`` round-trip loses it and fails before 1970 on
Windows).

Canonical text form (round-1 convergence, agreed with W3): ISO 8601 UTC
with a ``+00:00`` offset and microseconds exactly as ``datetime.isoformat()``
prints them (what every provider already emits). FILETIME precision below
1 us is not put into the text. Providers whose rows feed the timeline or the
artifact grid keep it in a sibling ``<field>_100ns`` holding the 7-digit
``Z`` text (:func:`filetime_to_iso_7`; EVTX ``timestamp_100ns``, LNK and
DestList times) and, where useful, the raw ticks in ``<field>_filetime``;
:func:`precise_time_value` reads that sibling. (:func:`filetime_fields`
returns the older integer-ticks sibling form.)

Range policy: values outside ``[MIN_PLAUSIBLE, now + 1 day]`` are not
"wrong" for every parser (slack, uninitialized fields), so the converters
return the timestamp and :func:`plausibility` classifies it; timeline and
report code exclude implausible values with a count instead of silently
dropping them.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping

__all__ = [
    "FILETIME_EPOCH",
    "FILETIME_TICKS_PER_SECOND",
    "FILETIME_UNIX_OFFSET_TICKS",
    "LOCAL_TIMEZONE_LABELS",
    "MIN_PLAUSIBLE",
    "UNIX_EPOCH",
    "WEBKIT_EPOCH_OFFSET_US",
    "datetime_to_filetime",
    "event_timestamp_utc_ticks",
    "filetime_fields",
    "filetime_to_datetime",
    "filetime_to_iso",
    "filetime_to_iso_7",
    "iso_utc",
    "normalize_iso_utc",
    "parse_iso_utc",
    "plausibility",
    "precise_time_value",
    "unix_to_datetime",
    "unix_to_iso",
    "webkit_to_datetime",
    "webkit_to_iso",
]

UNIX_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
FILETIME_TICKS_PER_SECOND = 10_000_000
# FILETIME ticks between 1601-01-01 and 1970-01-01.
FILETIME_UNIX_OFFSET_TICKS = 116_444_736_000_000_000
# WebKit/Chrome microseconds between 1601-01-01 and 1970-01-01.
WEBKIT_EPOCH_OFFSET_US = 11_644_473_600_000_000
# datetime.max in FILETIME ticks (9999-12-31T23:59:59.9999999).
_MAX_FILETIME = 2_650_467_743_999_999_999
MIN_PLAUSIBLE = dt.datetime(1980, 1, 1, tzinfo=dt.timezone.utc)
# ``timezone`` labels of a wall clock whose zone the evidence does not establish:
# never converted, ordered or range-filtered as a UTC instant.
LOCAL_TIMEZONE_LABELS = frozenset({"local-unknown", "exif-local", "local", "device-local"})


def filetime_to_datetime(value: int | None) -> dt.datetime | None:
    """FILETIME ticks -> aware UTC ``datetime`` (microsecond-truncated).

    ``0`` and negative/overflowing values return ``None`` (unset field).
    """
    ticks = _int_or_none(value)
    if ticks is None or ticks <= 0 or ticks > _MAX_FILETIME:
        return None
    return FILETIME_EPOCH + dt.timedelta(microseconds=ticks // 10)


def filetime_to_iso(value: int | None) -> str | None:
    """FILETIME ticks -> canonical ISO (``+00:00``, microseconds)."""
    moment = filetime_to_datetime(value)
    return iso_utc(moment) if moment is not None else None


def filetime_fields(name: str, value: int | None) -> dict[str, object]:
    """``{name: canonical ISO, name + "_100ns": raw ticks}`` (``{}`` when unset)."""
    ticks = _int_or_none(value)
    iso = filetime_to_iso(ticks)
    if iso is None or ticks is None:
        return {}
    return {name: iso, f"{name}_100ns": ticks}


def filetime_to_iso_7(value: int | None) -> str | None:
    """FILETIME ticks -> ``YYYY-MM-DDTHH:MM:SS.fffffffZ`` (100 ns preserved)."""
    ticks = _int_or_none(value)
    moment = filetime_to_datetime(ticks)
    if moment is None or ticks is None:
        return None
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{ticks % FILETIME_TICKS_PER_SECOND:07d}Z"


def datetime_to_filetime(moment: dt.datetime) -> int:
    """Aware (or naive = UTC) ``datetime`` -> FILETIME ticks (exact integer)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    delta = moment.astimezone(dt.timezone.utc) - FILETIME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * FILETIME_TICKS_PER_SECOND + delta.microseconds * 10


def webkit_to_datetime(value: int | None) -> dt.datetime | None:
    """Chrome/WebKit microseconds since 1601 -> aware UTC ``datetime``."""
    micros = _int_or_none(value)
    if micros is None or micros <= 0 or micros * 10 > _MAX_FILETIME:
        return None
    return FILETIME_EPOCH + dt.timedelta(microseconds=micros)


def webkit_to_iso(value: int | None) -> str | None:
    moment = webkit_to_datetime(value)
    return iso_utc(moment) if moment is not None else None


def unix_to_datetime(value: float | None, *, unit: str = "s") -> dt.datetime | None:
    """Unix epoch (``s``/``ms``/``us``/``ns``) -> aware UTC ``datetime``; pre-1970 safe.

    Integers are converted exactly; floats (seconds with a fraction) are
    split into whole seconds and rounded microseconds. Negative values are
    valid (before 1970); ``None``/non-numeric return ``None``.
    """
    if value is None or isinstance(value, bool):
        return None
    divisors = {"s": 1, "ms": 1_000, "us": 1_000_000, "ns": 1_000_000_000}
    if unit not in divisors:
        raise ValueError(f"unsupported unix unit: {unit}")
    try:
        if isinstance(value, int):
            micros = value * 1_000_000 // divisors[unit]
        else:
            micros = round(float(value) * 1_000_000 / divisors[unit])
        return UNIX_EPOCH + dt.timedelta(microseconds=micros)
    except (OverflowError, ValueError, TypeError):
        return None


def unix_to_iso(value: float | None, *, unit: str = "s") -> str | None:
    moment = unix_to_datetime(value, unit=unit)
    return iso_utc(moment) if moment is not None else None


def iso_utc(moment: dt.datetime) -> str:
    """``datetime`` -> canonical ISO 8601 UTC (``+00:00``; naive input = UTC).

    Pre-1900 years are formatted correctly (``isoformat`` does not depend on
    the platform ``strftime``).
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat()


def parse_iso_utc(value: object) -> dt.datetime | None:
    """ISO text (``Z``/offset/naive=UTC, up to 7 fractional digits) -> aware UTC."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # Python 3.11 fromisoformat accepts 1-6 fractional digits; trim a 7th.
    dot = text.find(".", 10)
    if dot > 0:
        end = dot + 1
        while end < len(text) and text[end].isdigit():
            end += 1
        if end - dot - 1 > 6:
            text = text[: dot + 7] + text[end:]
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


_EVENT_TIMESTAMP_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(?:[.,](?P<fraction>\d+))?\s*(?P<zone>[Zz]|[+-]\d{2}:?\d{2})?$"
)
_FILETIME_EPOCH_NAIVE = dt.datetime(1601, 1, 1)


def event_timestamp_utc_ticks(value: object) -> tuple[int | None, str]:
    """``(UTC FILETIME ticks, basis)`` of an ISO-8601 event time, with integer 100 ns arithmetic.

    Up to seven fractional digits are kept (finer digits are below FILETIME resolution
    and dropped); a ``Z``/``+HH:MM`` offset is applied. Text without an offset is read
    as UTC and labelled ``iso-no-offset-assumed-utc``; other text is ``(None, "unparsed")``.
    """
    text = str(value or "").strip()
    match = _EVENT_TIMESTAMP_RE.match(text)
    if not match:
        return None, "unparsed"
    try:
        base = dt.datetime.fromisoformat(match.group("base").replace(" ", "T"))
    except ValueError:
        return None, "unparsed"
    zone = match.group("zone") or ""
    offset_seconds = 0
    if zone and zone.upper() != "Z":
        digits = zone[1:].replace(":", "")
        offset_seconds = (int(digits[:2]) * 3600 + int(digits[2:]) * 60) * (-1 if zone[0] == "-" else 1)
    delta = base - _FILETIME_EPOCH_NAIVE
    seconds = delta.days * 86400 + delta.seconds - offset_seconds
    ticks = seconds * FILETIME_TICKS_PER_SECOND + int((match.group("fraction") or "")[:7].ljust(7, "0"))
    if ticks <= 0:
        return None, "unparsed"
    return ticks, ("iso-offset" if zone else "iso-no-offset-assumed-utc")


def precise_time_value(container: object, key: str, value: object) -> object:
    """``container[key + "_100ns"]`` when that sibling is the 100 ns (7-digit) text of
    the same instant as ``value``, else ``value``.

    EVTX ``timestamp_100ns``, LNK ``target_*_at_100ns`` and DestList
    ``*last_modified_at_100ns`` keep the FILETIME ticks a microsecond ISO
    ``value`` drops; the timeline, the artifact grid's server sort and the
    console read the sibling so two times 600 ns apart stay apart. ``value``
    needs an explicit offset (never a wall clock of undetermined zone) and
    the sibling must agree with it to the microsecond.
    """
    if not isinstance(container, Mapping):
        return value
    precise = container.get(f"{key}_100ns")
    if not isinstance(precise, str) or not precise.strip():
        return value
    precise_ticks = event_timestamp_utc_ticks(precise)[0]
    value_ticks, basis = event_timestamp_utc_ticks(value)
    if precise_ticks is None or value_ticks is None or basis != "iso-offset":
        return value
    return precise if precise_ticks // 10 == value_ticks // 10 else value


def normalize_iso_utc(value: object) -> str | None:
    """Re-emit any ISO timestamp in the canonical form (``+00:00``, microseconds)."""
    parsed = parse_iso_utc(value)
    return iso_utc(parsed) if parsed is not None else None


def plausibility(
    moment: dt.datetime | None,
    *,
    now: dt.datetime | None = None,
    minimum: dt.datetime = MIN_PLAUSIBLE,
) -> str:
    """``"ok"``, ``"missing"``, ``"before-min"`` (< 1980-01-01) or ``"future"`` (> now + 1 day)."""
    if moment is None:
        return "missing"
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    current = now or dt.datetime.now(dt.timezone.utc)
    if moment < minimum:
        return "before-min"
    if moment > current + dt.timedelta(days=1):
        return "future"
    return "ok"


def _int_or_none(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
