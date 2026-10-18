"""Row conditions of the listing APIs (plan r4 §2.3 V3 필터): time window, weekday / hour-of-day
(업무 외 시간), 부분 결과, 콘텐츠 유형 and a coordinate box.

``GET /artifacts``, ``/files`` and ``/timeline`` share one parser (:func:`parse_row_conditions`)
and one predicate (:meth:`RowConditions.predicate`); every value error is a :class:`ValueError`
with a Korean message the routes answer as 422.

Query parameters (all optional, AND-ed with each other and with the listing's other filters):

* ``from`` / ``to`` -- inclusive ISO-8601 bounds on the row time (``Z`` / ``+09:00``; a value
  without an offset is read in ``tz``). ``to`` covers the whole unit it is written to: a date
  (``2025-05-30``) includes that entire day, ``…T09:00`` the whole minute 09:00:00-09:00:59.999999,
  ``…T09:00:30`` the whole second; a value with a fraction is exact. ``from`` > ``to`` is a 422.
* ``weekday`` -- repeatable or comma-joined ``mon``..``sun`` (or the full English day name,
  case-insensitive): the row's local weekday is one of them.
* ``hours`` -- ``HH-HH`` local hour window ``[start, end)``; it wraps past midnight (``18-09`` =
  18:00-08:59).
* ``offhours=1`` -- 업무 외 시간: ``hours`` (default ``18-09``) *or* ``weekday`` (default
  ``sat,sun``) -- a row passes when either matches (without ``offhours`` both must match).
* ``tz`` -- time zone of ``weekday``/``hours`` and of offset-less bounds: ``UTC``, ``±HH:MM``
  (at most ±14:00) or an IANA name (``Asia/Seoul``; needs the zoneinfo database -- the
  ``tzdata`` package on Windows; a name that cannot be loaded is a Korean 422 that suggests an
  offset). Default ``UTC``.
* ``partial=1`` -- 부분 결과: rows a parser could not read completely (:func:`row_is_partial`).
* ``content`` -- repeatable or comma-joined 콘텐츠 유형 ids (:data:`CONTENT_TYPES`): files rows by
  their scan category, artifact / timeline rows by type and the extension of the file they point at.
* ``geo`` -- ``lat_min,lon_min,lat_max,lon_max`` box on the row's coordinates (map table cluster;
  ``/artifacts`` only -- ``/files`` and ``/timeline`` answer a Korean 422). Lower edges are
  inclusive, upper edges exclusive (``lat_min <= lat < lat_max``) except at 90 / 180; a box with
  ``lon_min > lon_max`` crosses the antimeridian (``lon >= lon_min`` or ``lon < lon_max``).

Row time (keep aligned with the console's row mapping): artifacts = the first *parseable* scalar
of ``details`` among ``artifact_sort.TIME_KEYS`` (an unparseable value falls through to the next
key); files = ``fs_modified_at``, else for an acquisition copy the NTFS ``$SI`` modified time of
the joined row (none without the join; the ``/files`` route resolves it per row through
``ntfs_time``), else ``modified_at``; timeline = ``timestamp``. A row without a parseable time
never passes a time condition, nor does a time the ``tz`` cannot represent (year 1 / 9999 edges).
A row time without an offset (naive text) is read as UTC -- never in ``tz`` -- like the console's
``parseInstant``.
"""

from __future__ import annotations

import datetime as dt
import math
import re
import threading
from array import array
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .artifact_sort import TIME_KEYS

COLLECTIONS = ("artifacts", "files", "timeline")
WEEKDAYS: tuple[str, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEKDAY_LABELS: dict[str, str] = {"mon": "월", "tue": "화", "wed": "수", "thu": "목", "fri": "금", "sat": "토", "sun": "일"}
DEFAULT_OFFHOURS: tuple[int, int] = (18, 9)
DEFAULT_WEEKEND: frozenset[int] = frozenset({5, 6})
MAX_PARAM_CHARS = 200

# 콘텐츠 유형 (AXIOM content type): Korean label, files scan categories, extensions and artifact
# type prefixes. Keep aligned with frontend/src/features/filters/contentTypes.ts.


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


@dataclass(frozen=True)
class ContentType:
    label: str
    categories: tuple[str, ...]
    extensions: frozenset[str]
    types: tuple[str, ...]


CONTENT_TYPES: dict[str, ContentType] = {
    "document": ContentType(
        "문서",
        ("documents",),
        _words(
            "txt pdf doc dot docx docm dotx rtf odt ods odp xls xlt xlsx xlsm xlsb ppt pps pptx pptm ppsx "
            "hwp hwpx hwt cell show nxl csv tsv md"
        ),
        ("document-",),
    ),
    "image": ContentType(
        "이미지",
        ("images",),
        _words("jpg jpeg jfif jpe png gif bmp dib tif tiff heic heif avif webp ico dng cr2 nef arw"),
        ("media-image", "synthetic-media-image", "thumbnail-cache-media", "icon-cache-media"),
    ),
    "video": ContentType(
        "영상", (), _words("mp4 m4v mov avi mkv wmv flv webm 3gp 3g2 mpg mpeg ts mts m2ts vob asf"), ("media-video",)
    ),
    "audio": ContentType(
        "음성", (), _words("mp3 wav m4a aac flac ogg oga opus wma amr aiff aif mid midi"), ("media-audio",)
    ),
    "archive": ContentType(
        "압축",
        ("archives",),
        _words("zip 7z rar tar gz gzip tgz bz2 tbz2 xz txz zst lz lzma cpio cab alz egg z00 z01 zipx wim swm"),
        ("archive-",),
    ),
    "executable": ContentType(
        "실행",
        ("executables",),
        _words(
            "exe dll sys msi msp bat cmd ps1 psm1 sh com scr cpl ocx jar apk appimage vbs vbe js jse wsf hta "
            "elf so dylib msix appx"
        ),
        ("prefetch-file",),
    ),
    "database": ContentType(
        "DB", ("databases",), _words("db db3 sqlite sqlite3 sqlitedb mdb accdb edb sdf wal sqlite-wal db-wal"), ("sqlite-",)
    ),
    "mail": ContentType("메일", ("emails",), _words("eml msg pst ost mbox emlx"), ("email",)),
}
# The file a row points at (first present wins). ``source_path`` (the container the parser read,
# e.g. places.sqlite of a browser history row) is deliberately not one of them.
TARGET_PATH_KEYS: tuple[str, ...] = (
    "target_path",
    "local_path",
    "target_file",
    "file_path",
    "executable_path",
    "referenced_path",
    "file_name",
    "filename",
    "attachment_name",
)
# Artifact types whose own ``path`` is the content file itself (not a container such as a
# History database, an .evtx or a hive): only these fall back to the row's path extension.
PATH_IS_CONTENT_PREFIXES: tuple[str, ...] = ("media-", "document-", "synthetic-media-")
PATH_IS_CONTENT_TYPES = frozenset(
    {
        "file",
        "file-signature-mismatch",
        "ios-backup-file",
        "cloud-sync-file",
        "kakaotalk-shared-picture",
        "email-attachment",
        "android-apk",
    }
)
# Parse / decode statuses that mean the row was not read completely: whole words of the status
# (split on non-alphanumerics), unless negated by the word before ("parsed-no-errors").
PARTIAL_STATUS_WORDS = frozenset(
    {
        "fail",
        "failed",
        "failure",
        "error",
        "errors",
        "truncated",
        "truncation",
        "invalid",
        "unreadable",
        "unavailable",
        "corrupt",
        "corrupted",
        "partial",
        "partially",
        "unrecognized",
        "undecoded",
        "unparsed",
    }
)
PARTIAL_STATUS_PHRASES: tuple[tuple[str, ...], ...] = (
    ("not", "recognized"),
    ("not", "decoded"),
    ("not", "parsed"),
    ("too", "large"),
    ("out", "of", "range"),
)
_NEGATIONS = frozenset({"no", "non", "without", "zero"})
# Truncation keys that mean the parser stopped reading the source (read / scan caps). Display caps
# of a value the parser did read completely (message_text_truncated, value_truncated,
# event_data_truncated, event_message_truncated, command_line_truncated, body_truncated --
# core.timeline.PREVIEW_TRUNCATION_FLAGS) are not 부분 결과.
PARTIAL_TRUNCATION_KEYS = frozenset(
    {
        "truncated",
        "parse_truncated",
        "scan_truncated",
        "stream_truncated",
        "file_scan_truncated",
        "sqlite_scan_truncated",
        "cache_body_truncated",
        "key_truncated",
        "native_records_truncated",
        "message_rows_truncated",
        "archive_embedded_parse_truncated",
    }
)
PARTIAL_TYPE_TOKENS: tuple[str, ...] = ("invalid", "unreadable", "parse-error", "parser-error", "scan-error")
DECRYPT_OK = frozenset({"", "success", "decrypted", "not-applicable", "not-required", "not-encrypted", "unknown"})
COORDINATE_KEYS: tuple[tuple[str, str], ...] = (
    ("gps_latitude", "gps_longitude"),
    ("latitude", "longitude"),
    ("lat", "lon"),
    ("lat", "lng"),
)
_FRACTION = re.compile(r"(\.\d{6})\d+")
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CLOCK_PART = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}(:\d{2})?(:\d{2})?([.,]\d+)?")
MAX_OFFSET = dt.timedelta(hours=14)
WEEKDAY_NAMES: dict[str, int] = {
    **{key: index for index, key in enumerate(WEEKDAYS)},
    **{
        name: index
        for index, name in enumerate(("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"))
    },
}
_HOURS = re.compile(r"^(\d{1,2})-(\d{1,2})$")


# --- value helpers ------------------------------------------------------------------------


def parse_moment(value: object, default_tz: dt.tzinfo = dt.timezone.utc) -> dt.datetime | None:
    """ISO-8601 text (``Z``, 7-digit fractions, space separator) or epoch seconds -> aware datetime.

    Naive text is read in ``default_tz`` (UTC for row values, like the console's ``parseInstant``).
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            return None
        try:
            return _EPOCH + dt.timedelta(seconds=float(value))
        except OverflowError:
            return None
    text = str(value).strip()
    if len(text) < 10 or not text[:4].isdigit():
        return None
    if len(text) > 10 and text[10] == " ":
        text = f"{text[:10]}T{text[11:]}"
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(r"\1", text)
    try:
        moment = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=default_tz)


def _details(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    return details if isinstance(details, Mapping) else {}


def _scalar(value: object) -> bool:
    return value is not None and not isinstance(value, (Mapping, list)) and not (isinstance(value, str) and not value.strip())


NtfsTime = Callable[[Mapping[str, object]], object]


def needs_ntfs_time(row: object) -> bool:
    """A files row whose time is the joined NTFS ``$SI`` modified time (acquisition copy, no join yet)."""
    return (
        isinstance(row, Mapping)
        and row.get("modified_at_origin") == "acquisition-copy"
        and not _scalar(row.get("fs_modified_at"))
        and not isinstance(row.get("ntfs"), Mapping)
    )


def row_time(row: Mapping[str, object], collection: str, ntfs_time: NtfsTime | None = None) -> dt.datetime | None:
    """The row's time as the console shows it (module doc). ``ntfs_time`` (files) resolves the
    NTFS ``$SI`` modified time of an acquisition copy that carries no joined ``ntfs`` yet."""
    if collection == "artifacts":
        details = _details(row)
        for key in TIME_KEYS:
            value = details.get(key)
            if _scalar(value):
                moment = parse_moment(value)
                if moment is not None:
                    return moment
        return None
    if collection == "files":
        fs_time = row.get("fs_modified_at")
        if _scalar(fs_time):
            return parse_moment(fs_time)
        if row.get("modified_at_origin") == "acquisition-copy":
            ntfs = row.get("ntfs")
            if isinstance(ntfs, Mapping):
                value = ntfs.get("si_modified_at")
            else:
                value = ntfs_time(row) if ntfs_time is not None else None
            return parse_moment(value) if _scalar(value) else None
        value = row.get("modified_at")
        return parse_moment(value) if _scalar(value) else None
    value = row.get("timestamp")
    return parse_moment(value) if _scalar(value) else None


def _partial_status(value: object) -> bool:
    """A failing parse status: whole words (:data:`PARTIAL_STATUS_WORDS` / ``_PHRASES``) not
    negated by the word before."""
    if not isinstance(value, str) or not value:
        return False
    words = [word for word in re.split(r"[^a-z0-9]+", value.lower()) if word]
    for index, word in enumerate(words):
        if index > 0 and words[index - 1] in _NEGATIONS:
            continue
        if word in PARTIAL_STATUS_WORDS:
            return True
        if any(tuple(words[index : index + len(phrase)]) == phrase for phrase in PARTIAL_STATUS_PHRASES):
            return True
    return False


def _partial_container(container: Mapping[str, object]) -> bool:
    if container.get("parser_error") is True:
        return True
    if _partial_status(container.get("parse_status")):
        return True
    decrypt = container.get("decrypt_status")
    if isinstance(decrypt, str) and decrypt.lower() not in DECRYPT_OK:
        return True
    coverage = container.get("coverage")
    if coverage == "partial" or (isinstance(coverage, Mapping) and coverage.get("status") == "partial"):
        return True
    return any(container.get(key) is True for key in PARTIAL_TRUNCATION_KEYS)


def row_is_partial(row: Mapping[str, object]) -> bool:
    """부분 결과: ``parser_error`` or a read-cap truncation key (:data:`PARTIAL_TRUNCATION_KEYS`)
    true, a failing ``parse_status`` (:func:`_partial_status`), a ``decrypt_status`` other than
    success / unknown (:data:`DECRYPT_OK`), ``coverage`` partial -- on the row or its ``details``
    -- or an ``*-invalid*`` / ``*-unreadable`` / ``*-parse-error`` row type."""
    artifact_type = str(row.get("artifact_type") or _details(row).get("artifact_type") or "").lower()
    if any(token in artifact_type for token in PARTIAL_TYPE_TOKENS):
        return True
    return _partial_container(row) or _partial_container(_details(row))


def path_extension(value: object) -> str:
    """Lower-case extension of a path's last component (no dot), ``""`` when none."""
    if not isinstance(value, str) or not value:
        return ""
    name = re.split(r"[\\/]", value.strip())[-1]
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem or not ext or len(ext) > 12 or not ext.replace("-", "").isalnum():
        return ""
    return ext.lower()


def _type_matches(artifact_type: str, prefixes: Iterable[str]) -> bool:
    return any(artifact_type == prefix or artifact_type.startswith(prefix) for prefix in prefixes)


def path_is_content(artifact_type: str) -> bool:
    """The artifact type's own ``path`` is the content file (:data:`PATH_IS_CONTENT_TYPES`)."""
    return artifact_type in PATH_IS_CONTENT_TYPES or artifact_type.startswith(PATH_IS_CONTENT_PREFIXES)


def row_content_types(row: Mapping[str, object], collection: str) -> set[str]:
    """콘텐츠 유형 ids of a row (module doc); empty when none applies."""
    found: set[str] = set()
    if collection == "files":
        categories = row.get("categories")
        names = {str(item) for item in categories} if isinstance(categories, list) else set()
        extension = path_extension(row.get("path") or row.get("name"))
        for content_id, spec in CONTENT_TYPES.items():
            # Types without a scan category (영상 · 음성) go by extension.
            hit = names.intersection(spec.categories) if spec.categories else extension in spec.extensions
            if hit:
                found.add(content_id)
        return found
    details = _details(row)
    artifact_type = str(row.get("artifact_type") or details.get("artifact_type") or "").lower()
    target = ""
    for key in TARGET_PATH_KEYS:
        value = details.get(key)
        if isinstance(value, str) and path_extension(value):
            target = path_extension(value)
            break
    if not target and collection == "artifacts" and path_is_content(artifact_type):
        target = path_extension(row.get("path"))
    for content_id, spec in CONTENT_TYPES.items():
        if (artifact_type and _type_matches(artifact_type, spec.types)) or (target and target in spec.extensions):
            found.add(content_id)
    return found


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


def row_coordinates(row: Mapping[str, object]) -> tuple[float, float] | None:
    """``(latitude, longitude)`` of a row: ``details.gps_latitude/gps_longitude``,
    ``latitude/longitude``, ``lat/lon|lng``, then ``details.exif_gps_profile.latitude/longitude``
    and the row's own top-level pair. ``(0, 0)`` and out-of-range values count as none.
    Keep aligned with frontend/src/features/views/geo.ts ``rowCoordinates``."""
    details = _details(row)
    gps = details.get("exif_gps_profile")
    containers: list[Mapping[str, object]] = [details]
    if isinstance(gps, Mapping):
        containers.append(gps)
    containers.append(row)
    for container in containers:
        for lat_key, lon_key in COORDINATE_KEYS:
            lat, lon = _number(container.get(lat_key)), _number(container.get(lon_key))
            if lat is None or lon is None:
                continue
            if -90 <= lat <= 90 and -180 <= lon <= 180 and not (lat == 0 and lon == 0):
                return lat, lon
    return None


# --- parsing ---------------------------------------------------------------------------------


def _check_text(name: str, text: str) -> str:
    if len(text) > MAX_PARAM_CHARS:
        raise ValueError(f"{name} 값이 너무 깁니다(최대 {MAX_PARAM_CHARS}자)")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError(f"{name} 값에 제어 문자를 쓸 수 없습니다")
    return text


def parse_tz(raw: str | None) -> tuple[dt.tzinfo, str]:
    """``UTC`` / ``±HH:MM`` / IANA name -> ``(tzinfo, label)``; Korean ``ValueError`` otherwise."""
    text = _check_text("tz", (raw or "").strip())
    if not text or text.upper() in ("UTC", "Z", "GMT"):
        return dt.timezone.utc, "UTC"
    match = _OFFSET.match(text)
    if match:
        sign, hours, minutes = match.group(1), int(match.group(2)), int(match.group(3))
        delta = dt.timedelta(hours=hours, minutes=minutes)
        if minutes > 59 or delta > MAX_OFFSET:
            raise ValueError("tz 오프셋은 -14:00 ~ +14:00 범위여야 합니다")
        label = f"{sign}{hours:02d}:{minutes:02d}"
        return dt.timezone(-delta if sign == "-" else delta, label), label
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError as exc:  # pragma: no cover - stdlib on 3.9+
        raise ValueError("이 서버는 시간대 이름을 해석할 수 없습니다 — +09:00 같은 UTC 오프셋을 쓰세요") from exc
    try:
        return ZoneInfo(text), text
    except (ZoneInfoNotFoundError, ValueError, OSError, UnicodeDecodeError) as exc:
        # OSError: a directory such as "Asia" (PermissionError / IsADirectoryError on Windows) or
        # a missing zoneinfo database (tzdata); UnicodeDecodeError: a file that is not TZif.
        raise ValueError(
            f"tz '{text[:64]}'을(를) 시간대로 읽을 수 없습니다 — UTC, Asia/Seoul 같은 IANA 이름 또는 "
            "+09:00 같은 UTC 오프셋을 쓰세요(이 서버에서 시간대 이름을 못 읽으면 ±HH:MM 오프셋을 쓰세요)"
        ) from exc


def parse_bound(name: str, raw: str | None, tz: dt.tzinfo) -> dt.datetime | None:
    text = _check_text(name, (raw or "").strip())
    if not text:
        return None
    moment = parse_moment(text, tz)
    if moment is None:
        raise ValueError(f"{name} 값 '{text[:64]}'은(는) ISO-8601 시각이 아닙니다(예: 2025-05-30T09:00:00+09:00)")
    return moment


def bound_unit(raw: str | None) -> dt.timedelta:
    """The span a ``to`` value covers (module doc): a day for a date, an hour / minute / second
    for a clock written to that precision, 1 µs (exact) for a value with a fraction or another
    ISO form."""
    text = (raw or "").strip()
    if _DATE_ONLY.match(text):
        return dt.timedelta(days=1)
    match = _CLOCK_PART.match(text)
    if match is None or match.group(3):
        return dt.timedelta(microseconds=1)
    if match.group(2):
        return dt.timedelta(seconds=1)
    if match.group(1):
        return dt.timedelta(minutes=1)
    return dt.timedelta(hours=1)


def _split(values: Iterable[str]) -> list[str]:
    return [part.strip() for value in values for part in str(value).split(",") if part.strip()]


def parse_weekdays(values: Sequence[str]) -> frozenset[int] | None:
    parts = _split(values)
    if not parts:
        return None
    days: set[int] = set()
    for part in parts:
        key = _check_text("weekday", part).lower()
        if key not in WEEKDAY_NAMES:
            raise ValueError(f"weekday 값 '{part[:32]}'을(를) 알 수 없습니다 — mon, tue, wed, thu, fri, sat, sun 중에서 고르세요")
        days.add(WEEKDAY_NAMES[key])
    return frozenset(days)


def parse_hours(raw: str | None) -> tuple[int, int] | None:
    text = _check_text("hours", (raw or "").strip())
    if not text:
        return None
    match = _HOURS.match(text)
    if not match:
        raise ValueError("hours 값은 'HH-HH'(시작-끝 시, 0~24) 형식이어야 합니다 — 예: 18-09")
    start, end = int(match.group(1)), int(match.group(2))
    if start > 24 or end > 24:
        raise ValueError("hours 값의 시는 0~24여야 합니다")
    start, end = start % 24, end % 24
    if start == end:
        raise ValueError("hours 시작과 끝이 같습니다 — 하루 전체라면 hours를 빼세요")
    return start, end


def parse_content(values: Sequence[str]) -> frozenset[str] | None:
    parts = _split(values)
    if not parts:
        return None
    for part in parts:
        _check_text("content", part)
        if part not in CONTENT_TYPES:
            known = ", ".join(f"{key}({spec.label})" for key, spec in CONTENT_TYPES.items())
            raise ValueError(f"content 값 '{part[:32]}'을(를) 알 수 없습니다 — {known}")
    return frozenset(parts)


def parse_geo(raw: str | None) -> tuple[float, float, float, float] | None:
    text = _check_text("geo", (raw or "").strip())
    if not text:
        return None
    parts = [part.strip() for part in text.split(",")]
    numbers = [_number(part) for part in parts]
    if len(parts) != 4 or any(number is None for number in numbers):
        raise ValueError("geo 값은 '위도최소,경도최소,위도최대,경도최대' 숫자 4개여야 합니다")
    lat0, lon0, lat1, lon1 = (float(number) for number in numbers)  # type: ignore[arg-type]
    if not -90 <= lat0 < lat1 <= 90:
        raise ValueError("geo 위도 범위가 잘못되었습니다 — 위도는 -90~90, 위도최소 < 위도최대여야 합니다")
    if not (-180 <= lon0 <= 180 and -180 <= lon1 <= 180) or lon0 == lon1:
        raise ValueError(
            "geo 경도 범위가 잘못되었습니다 — 경도는 -180~180이고 최소와 최대가 달라야 합니다"
            "(경도최소 > 경도최대이면 날짜 변경선(180°)을 넘는 상자로 읽습니다)"
        )
    return lat0, lon0, lat1, lon1


def _in_span(value: float, low: float, high: float, limit: float) -> bool:
    """``low <= value < high`` (``high`` inclusive at the world edge ``limit``)."""
    return low <= value and (value < high or (high == limit and value <= high))


def in_geo_box(point: tuple[float, float], box: tuple[float, float, float, float]) -> bool:
    """The point in ``lat_min,lon_min,lat_max,lon_max`` (module doc: half-open, antimeridian)."""
    lat0, lon0, lat1, lon1 = box
    lat, lon = point
    if not _in_span(lat, lat0, lat1, 90):
        return False
    if lon0 < lon1:
        return _in_span(lon, lon0, lon1, 180)
    return lon >= lon0 or lon < lon1


def in_hours(hour: int, window: tuple[int, int]) -> bool:
    start, end = window
    return start <= hour < end if start < end else hour >= start or hour < end


# --- conditions -------------------------------------------------------------------------------


@dataclass(frozen=True)
class RowConditions:
    time_from: dt.datetime | None = None
    time_to: dt.datetime | None = None
    # Exclusive end: ``time_to`` + the unit it was written to (:func:`bound_unit`); None = open.
    time_until: dt.datetime | None = None
    weekdays: frozenset[int] | None = None
    hours: tuple[int, int] | None = None
    offhours: bool = False
    tz: dt.tzinfo = dt.timezone.utc
    tz_label: str = "UTC"
    partial: bool = False
    content: frozenset[str] | None = None
    geo: tuple[float, float, float, float] | None = None

    @property
    def clock(self) -> bool:
        return self.offhours or self.weekdays is not None or self.hours is not None

    @property
    def uses_time(self) -> bool:
        return self.time_from is not None or self.time_to is not None or self.clock

    def _clock_matches(self, moment: dt.datetime) -> bool:
        try:
            local = moment.astimezone(self.tz)
        except (OverflowError, ValueError):
            return False  # a year 1 / 9999 edge the zone cannot represent
        if self.offhours:
            days = self.weekdays if self.weekdays is not None else DEFAULT_WEEKEND
            window = self.hours or DEFAULT_OFFHOURS
            return local.weekday() in days or in_hours(local.hour, window)
        if self.weekdays is not None and local.weekday() not in self.weekdays:
            return False
        return self.hours is None or in_hours(local.hour, self.hours)

    def matches(self, row: Mapping[str, object], collection: str, ntfs_time: NtfsTime | None = None) -> bool:
        if self.uses_time:
            moment = row_time(row, collection, ntfs_time)
            if moment is None:
                return False
            try:
                if self.time_from is not None and moment < self.time_from:
                    return False
                if self.time_until is not None and moment >= self.time_until:
                    return False
            except (OverflowError, ValueError):
                return False
            if self.clock and not self._clock_matches(moment):
                return False
        if self.partial and not row_is_partial(row):
            return False
        if self.content is not None and self.content.isdisjoint(row_content_types(row, collection)):
            return False
        if self.geo is not None:
            point = row_coordinates(row)
            if point is None:
                return False
            if not in_geo_box(point, self.geo):
                return False
        return True

    def predicate(self, collection: str, ntfs_time: NtfsTime | None = None) -> Callable[[Mapping[str, object]], bool]:
        return lambda row: self.matches(row, collection, ntfs_time)

    def cache_key(self) -> tuple[object, ...]:
        """Hashable identity of the conditions (matched-index caches)."""
        return (
            self.time_from.isoformat() if self.time_from else None,
            self.time_until.isoformat() if self.time_until else None,
            tuple(sorted(self.weekdays)) if self.weekdays is not None else None,
            self.hours,
            self.offhours,
            self.tz_label,
            self.partial,
            tuple(sorted(self.content)) if self.content is not None else None,
            self.geo,
        )

    def describe(self) -> dict[str, object]:
        """The applied conditions, echoed in the page (``conditions``)."""
        out: dict[str, object] = {"tz": self.tz_label}
        if self.time_from is not None:
            out["from"] = self.time_from.isoformat()
        if self.time_to is not None:
            out["to"] = self.time_to.isoformat()
            if self.time_until is not None:
                out["to_exclusive"] = self.time_until.isoformat()
        if self.weekdays is not None:
            out["weekday"] = [WEEKDAYS[day] for day in sorted(self.weekdays)]
        if self.hours is not None:
            out["hours"] = f"{self.hours[0]:02d}-{self.hours[1]:02d}"
        if self.offhours:
            out["offhours"] = True
        if self.partial:
            out["partial"] = True
        if self.content is not None:
            out["content"] = sorted(self.content)
        if self.geo is not None:
            out["geo"] = list(self.geo)
        return out


def parse_row_conditions(
    *,
    time_from: str | None = None,
    time_to: str | None = None,
    weekday: Sequence[str] = (),
    hours: str | None = None,
    offhours: bool = False,
    tz: str | None = None,
    partial: bool = False,
    content: Sequence[str] = (),
    geo: str | None = None,
) -> RowConditions | None:
    """Parse the query parameters (module doc); ``None`` when no condition is given."""
    zone, label = parse_tz(tz)
    start = parse_bound("from", time_from, zone)
    end = parse_bound("to", time_to, zone)
    if start is not None and end is not None and start > end:
        raise ValueError("from이 to보다 늦습니다 — 시작 시각을 종료 시각 이전으로 지정하세요")
    until: dt.datetime | None = None
    if end is not None:
        try:
            until = end + bound_unit(time_to)
        except OverflowError:
            until = None  # 9999-12-31: no upper bound left
    conditions = RowConditions(
        time_from=start,
        time_to=end,
        time_until=until,
        weekdays=parse_weekdays(weekday),
        hours=parse_hours(hours),
        offhours=bool(offhours),
        tz=zone,
        tz_label=label,
        partial=bool(partial),
        content=parse_content(content),
        geo=parse_geo(geo),
    )
    active = (
        conditions.uses_time or conditions.partial or conditions.content is not None or conditions.geo is not None
    )
    return conditions if active else None


# --- matched-index cache -------------------------------------------------------------------------

MATCH_CACHE_MAX_ENTRIES = 16
MATCH_CACHE_MAX_INDICES = 8_000_000  # ~32 MB of uint32 across all entries


class MatchedIndexCache:
    """Small LRU of the matching row positions of a (list revision, conditions) key, so paging a
    filtered list does not rescan it per page. Keys must embed the list revision (path, size,
    mtime) and :meth:`RowConditions.cache_key`; bounded by entries and by total indices."""

    def __init__(self, *, max_entries: int = MATCH_CACHE_MAX_ENTRIES, max_indices: int = MATCH_CACHE_MAX_INDICES) -> None:
        self._entries: OrderedDict[tuple[object, ...], array] = OrderedDict()
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._max_indices = max_indices

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)

    def get_or_compute(self, key: tuple[object, ...] | None, compute: Callable[[], Iterable[int]]) -> array:
        if key is not None:
            with self._lock:
                cached = self._entries.get(key)
                if cached is not None:
                    self._entries.move_to_end(key)
                    return cached
        indices = array("L", compute())
        if key is not None and len(indices) <= self._max_indices:
            with self._lock:
                self._entries[key] = indices
                self._entries.move_to_end(key)
                total = sum(len(item) for item in self._entries.values())
                while len(self._entries) > self._max_entries or (total > self._max_indices and len(self._entries) > 1):
                    _, dropped = self._entries.popitem(last=False)
                    total -= len(dropped)
        return indices


MATCH_CACHE = MatchedIndexCache()


def output_stamp(*paths: object) -> tuple[object, ...]:
    """``(path, size, mtime_ns)`` per path (``None`` skipped): the list revision of a cache key."""
    stamp: list[object] = []
    for raw in paths:
        if not raw:
            continue
        try:
            stat = Path(str(raw)).stat()
            stamp.append((str(raw), stat.st_size, stat.st_mtime_ns))
        except OSError:
            stamp.append((str(raw), -1, -1))
    return tuple(stamp)


def matched_indices(
    rows: Sequence[object], predicate: Callable[[Mapping[str, object]], bool], cache_key: tuple[object, ...] | None = None
) -> array:
    """Positions of ``rows`` passing ``predicate`` (cached under ``cache_key`` when given)."""
    return MATCH_CACHE.get_or_compute(
        cache_key,
        lambda: (index for index, row in enumerate(rows) if isinstance(row, Mapping) and predicate(row)),
    )


def filter_rows_page(
    rows: Sequence[object],
    predicate: Callable[[Mapping[str, object]], bool],
    *,
    collection: str,
    offset: int,
    limit: int,
    cache_key: tuple[object, ...] | None = None,
) -> tuple[list[object], dict[str, object]]:
    """Rows of an in-memory list passing ``predicate`` -> ``(page rows with record_index, pagination)``.

    ``record_index`` is the row's position in ``rows``; ``matched`` is exact (the list is scanned
    to the end once per ``cache_key``: later pages reuse the matched positions, :data:`MATCH_CACHE`)."""
    indices = matched_indices(rows, predicate, cache_key)
    matched = len(indices)
    window = indices[offset : offset + limit] if limit > 0 else indices[offset:]
    page: list[object] = [{**rows[index], "record_index": index} for index in window]  # type: ignore[dict-item]
    has_more = limit > 0 and offset + len(page) < matched
    pagination: dict[str, object] = {
        "collection": collection,
        "offset": offset,
        "limit": limit,
        "returned": len(page),
        "total": matched,
        "matched": matched,
        "next_offset": offset + len(page) if has_more else None,
        "previous_offset": max(0, offset - limit) if offset > 0 and limit > 0 else None,
        "has_more": has_more,
        "filtered": True,
        "scanned": len(rows),
        "truncated": False,
    }
    return page, pagination
