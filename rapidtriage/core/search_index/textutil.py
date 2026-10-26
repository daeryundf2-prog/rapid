"""Small shared helpers: folding, timestamps, path keys, hash shapes."""

from __future__ import annotations

import datetime as dt
import re
import unicodedata

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")
_TZ_OFFSET_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def nfc(value: str) -> str:
    return value if value.isascii() else unicodedata.normalize("NFC", value)


def fold(value: object) -> str:
    """NFC + casefold (ASCII: ``lower``) -- every comparison of the index uses this."""
    text = str(value or "")
    if text.isascii():
        return text.lower()
    return unicodedata.normalize("NFC", text).casefold()


_NON_ASCII_RUN_RE = re.compile(r"[^\x00-\x7f]{2,}")


def is_bigram_term(term: str) -> bool:
    """Two characters, both non-ASCII: the ``search_bigram`` table serves it."""
    return len(term) == 2 and not term[0].isascii() and not term[1].isascii()


def bigram_tokens(text: str) -> str:
    """Distinct adjacent non-ASCII character pairs of ``text``, space separated (``search_bigram.g``)."""
    pairs: set[str] = set()
    for match in _NON_ASCII_RUN_RE.finditer(text):
        run = match.group()
        pairs.update(run[i : i + 2] for i in range(len(run) - 1))
    return " ".join(sorted(pairs))


def path_key(value: str) -> str:
    """Folded path with ``/`` separators (``\\`` and ``/`` compare equal)."""
    return fold(value).replace("\\", "/")


_LONG_PREFIX_RE = re.compile(r"^(?://[?.]/|/\?\?/)")
_DEVICE_PREFIX_RE = re.compile(r"^/(?:device/harddiskvolume\d+|volume\{[^}/]*\})(?=/|$)")
_DRIVE_RE = re.compile(r"^/?[a-z]:(?=/|$)")


def target_path_key(value: str) -> str:
    """``path_key`` of a target path as the examiner reads it.

    ``\\\\?\\``, ``\\Device\\HarddiskVolumeN``, ``\\VOLUME{…}`` and the drive
    letter are dropped (``C:\\Users\\x`` -> ``/users/x``), like the evidence
    paths of ``path_fold``.
    """
    text = path_key(nfc(value))
    text = _LONG_PREFIX_RE.sub("/", text, count=1)
    text = _DEVICE_PREFIX_RE.sub("", text, count=1)
    text = _DRIVE_RE.sub("", text, count=1)
    if text and not text.startswith(("/", "%")):
        text = "/" + text
    return text


def parse_ts_ms(value: object, *, default_offset: dt.timedelta | None = None) -> int | None:
    """ISO 8601 text -> epoch milliseconds (UTC). Naive values use ``default_offset`` (UTC when None)."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if len(text) < 10 or not text[:4].isdigit() or text[4] != "-":
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(r"\1", text)
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone(default_offset or dt.timedelta(0)))
    try:
        delta = parsed - EPOCH
    except (OverflowError, ValueError):
        return None
    millis = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
    # 1601..9999 sanity window (FILETIME zero, far-future garbage are not times).
    if millis < -11_644_473_600_000 or millis > 253_402_300_799_000:
        return None
    return millis


def ms_to_iso(millis: int | None, offset: dt.timedelta | None = None) -> str | None:
    if millis is None:
        return None
    zone = dt.timezone(offset or dt.timedelta(0))
    try:
        moment = EPOCH + dt.timedelta(milliseconds=int(millis))
        return moment.astimezone(zone).isoformat(timespec="milliseconds")
    except OverflowError:
        # The edges of datetime's range (year 1 / 9999) in a non-UTC offset: show UTC instead.
        try:
            return (EPOCH + dt.timedelta(milliseconds=int(millis))).isoformat(timespec="milliseconds")
        except OverflowError:
            return None


def parse_offset(text: object) -> dt.timedelta | None:
    """``+09:00`` / ``-0530`` / ``UTC`` -> timedelta (``None`` when not an offset)."""
    value = str(text or "").strip().upper()
    if value in {"UTC", "Z", "+00:00"}:
        return dt.timedelta(0)
    match = _TZ_OFFSET_RE.match(value)
    if match is None:
        return None
    sign = -1 if match.group(1) == "-" else 1
    hours, minutes = int(match.group(2)), int(match.group(3))
    if hours > 14 or minutes > 59:
        return None
    return sign * dt.timedelta(hours=hours, minutes=minutes)


def format_offset(offset: dt.timedelta) -> str:
    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    minutes = abs(minutes)
    return f"{sign}{minutes // 60:02d}:{minutes % 60:02d}"


def hash_algorithm(value: str) -> str | None:
    """``md5``/``sha1``/``sha256`` by hex length (Amcache ``0000``+SHA1 file ids count as SHA1)."""
    text = value.strip().lower()
    if len(text) == 44 and text.startswith("0000"):
        text = text[4:]
    if not HEX_RE.match(text):
        return None
    return HASH_LENGTHS.get(len(text))


def normalize_hash(value: str) -> tuple[str, str] | None:
    text = value.strip().lower()
    if len(text) == 44 and text.startswith("0000") and HEX_RE.match(text):
        text = text[4:]
    algorithm = hash_algorithm(text)
    if algorithm is None or set(text) == {"0"}:
        return None
    return algorithm, text
