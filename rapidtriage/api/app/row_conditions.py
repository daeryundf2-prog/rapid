"""Row conditions of the listing APIs (plan r4 §2.3 V3 필터): time window, weekday / hour-of-day
(업무 외 시간), 부분 결과, 콘텐츠 유형 and a coordinate box.

``GET /artifacts``, ``/files`` and ``/timeline`` share one parser (:func:`parse_row_conditions`)
and one predicate (:meth:`RowConditions.predicate`); every value error is a :class:`ValueError`
with a Korean message the routes answer as 422.

Query parameters (all optional, AND-ed with each other and with the listing's other filters):

* ``from`` / ``to`` -- inclusive ISO-8601 bounds on the row time (``Z`` / ``+09:00``; a value
  without an offset is read in ``tz``).
* ``weekday`` -- repeatable or comma-joined ``mon``..``sun``: the row's local weekday is one of them.
* ``hours`` -- ``HH-HH`` local hour window ``[start, end)``; it wraps past midnight (``18-09`` =
  18:00-08:59).
* ``offhours=1`` -- 업무 외 시간: ``hours`` (default ``18-09``) *or* ``weekday`` (default
  ``sat,sun``) -- a row passes when either matches (without ``offhours`` both must match).
* ``tz`` -- time zone of ``weekday``/``hours`` and of offset-less bounds: ``UTC``, ``+09:00`` or an
  IANA name (``Asia/Seoul``; needs the zoneinfo database). Default ``UTC``.
* ``partial=1`` -- 부분 결과: rows a parser could not read completely (:func:`row_is_partial`).
* ``content`` -- repeatable or comma-joined 콘텐츠 유형 ids (:data:`CONTENT_TYPES`): files rows by
  their scan category, artifact / timeline rows by type and the extension of the file they point at.
* ``geo`` -- ``lat_min,lon_min,lat_max,lon_max`` box on the row's coordinates (map table cluster).

Row time (keep aligned with the console's row mapping): artifacts = the first scalar of
``details`` among ``artifact_sort.TIME_KEYS``; files = ``fs_modified_at``, else for an acquisition
copy the NTFS ``$SI`` modified time of the joined row (none without the join), else
``modified_at``; timeline = ``timestamp``. A row without a parseable time never passes a time
condition.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass

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
# The file a row points at (first present wins), before the row's own path.
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
    "source_path",
)
# Parse statuses that mean the row was not read completely (substring, case-insensitive).
PARTIAL_STATUS_TOKENS: tuple[str, ...] = (
    "fail",
    "error",
    "truncat",
    "invalid",
    "not-recognized",
    "not-decoded",
    "unreadable",
    "too_large",
    "too-large",
    "unavailable",
    "corrupt",
    "partial",
)
PARTIAL_TYPE_TOKENS: tuple[str, ...] = ("invalid", "unreadable", "parse-error", "parser-error")
DECRYPT_OK = frozenset({"", "success", "decrypted", "not-applicable", "not-required", "not-encrypted"})
COORDINATE_KEYS: tuple[tuple[str, str], ...] = (
    ("gps_latitude", "gps_longitude"),
    ("latitude", "longitude"),
    ("lat", "lon"),
    ("lat", "lng"),
)
_FRACTION = re.compile(r"(\.\d{6})\d+")
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
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


def row_time(row: Mapping[str, object], collection: str) -> dt.datetime | None:
    """The row's time as the console shows it (module doc)."""
    if collection == "artifacts":
        details = _details(row)
        for key in TIME_KEYS:
            value = details.get(key)
            if _scalar(value):
                return parse_moment(value)
        return None
    if collection == "files":
        fs_time = row.get("fs_modified_at")
        if _scalar(fs_time):
            return parse_moment(fs_time)
        if row.get("modified_at_origin") == "acquisition-copy":
            ntfs = row.get("ntfs")
            value = ntfs.get("si_modified_at") if isinstance(ntfs, Mapping) else None
            return parse_moment(value) if _scalar(value) else None
        value = row.get("modified_at")
        return parse_moment(value) if _scalar(value) else None
    value = row.get("timestamp")
    return parse_moment(value) if _scalar(value) else None


def _partial_status(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    lowered = value.lower()
    return any(token in lowered for token in PARTIAL_STATUS_TOKENS)


def _partial_container(container: Mapping[str, object]) -> bool:
    if container.get("parser_error") is True or container.get("truncated") is True:
        return True
    if _partial_status(container.get("parse_status")):
        return True
    decrypt = container.get("decrypt_status")
    if isinstance(decrypt, str) and decrypt.lower() not in DECRYPT_OK:
        return True
    coverage = container.get("coverage")
    if coverage == "partial" or (isinstance(coverage, Mapping) and coverage.get("status") == "partial"):
        return True
    return any(key.endswith("_truncated") and value is True for key, value in container.items())


def row_is_partial(row: Mapping[str, object]) -> bool:
    """부분 결과: ``parser_error`` / ``truncated`` / ``*_truncated`` true, a failing ``parse_status``
    (:data:`PARTIAL_STATUS_TOKENS`), a ``decrypt_status`` other than success, ``coverage``
    partial -- on the row or its ``details`` -- or an ``*-invalid*`` / ``*-unreadable`` row type."""
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
    if not target and collection == "artifacts":
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
        if hours > 14 or minutes > 59:
            raise ValueError("tz 오프셋은 -14:00 ~ +14:00 범위여야 합니다")
        delta = dt.timedelta(hours=hours, minutes=minutes)
        label = f"{sign}{hours:02d}:{minutes:02d}"
        return dt.timezone(-delta if sign == "-" else delta, label), label
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError as exc:  # pragma: no cover - stdlib on 3.9+
        raise ValueError("이 서버는 시간대 이름을 해석할 수 없습니다 — +09:00 같은 UTC 오프셋을 쓰세요") from exc
    try:
        return ZoneInfo(text), text
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"tz '{text[:64]}'을(를) 찾을 수 없습니다 — UTC, +09:00 또는 Asia/Seoul 같은 이름을 쓰세요") from exc


def parse_bound(name: str, raw: str | None, tz: dt.tzinfo) -> dt.datetime | None:
    text = _check_text(name, (raw or "").strip())
    if not text:
        return None
    moment = parse_moment(text, tz)
    if moment is None:
        raise ValueError(f"{name} 값 '{text[:64]}'은(는) ISO-8601 시각이 아닙니다(예: 2025-05-30T09:00:00+09:00)")
    return moment


def _split(values: Iterable[str]) -> list[str]:
    return [part.strip() for value in values for part in str(value).split(",") if part.strip()]


def parse_weekdays(values: Sequence[str]) -> frozenset[int] | None:
    parts = _split(values)
    if not parts:
        return None
    days: set[int] = set()
    for part in parts:
        key = _check_text("weekday", part).lower()[:3]
        if key not in WEEKDAYS:
            raise ValueError(f"weekday 값 '{part[:32]}'을(를) 알 수 없습니다 — mon, tue, wed, thu, fri, sat, sun 중에서 고르세요")
        days.add(WEEKDAYS.index(key))
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
    if not (-90 <= lat0 <= lat1 <= 90 and -180 <= lon0 <= lon1 <= 180):
        raise ValueError("geo 범위가 잘못되었습니다 — 위도 -90~90, 경도 -180~180, 최소 ≤ 최대")
    return lat0, lon0, lat1, lon1


def in_hours(hour: int, window: tuple[int, int]) -> bool:
    start, end = window
    return start <= hour < end if start < end else hour >= start or hour < end


# --- conditions -------------------------------------------------------------------------------


@dataclass(frozen=True)
class RowConditions:
    time_from: dt.datetime | None = None
    time_to: dt.datetime | None = None
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
        local = moment.astimezone(self.tz)
        if self.offhours:
            days = self.weekdays if self.weekdays is not None else DEFAULT_WEEKEND
            window = self.hours or DEFAULT_OFFHOURS
            return local.weekday() in days or in_hours(local.hour, window)
        if self.weekdays is not None and local.weekday() not in self.weekdays:
            return False
        return self.hours is None or in_hours(local.hour, self.hours)

    def matches(self, row: Mapping[str, object], collection: str) -> bool:
        if self.uses_time:
            moment = row_time(row, collection)
            if moment is None:
                return False
            if self.time_from is not None and moment < self.time_from:
                return False
            if self.time_to is not None and moment > self.time_to:
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
            lat0, lon0, lat1, lon1 = self.geo
            if not (lat0 <= point[0] <= lat1 and lon0 <= point[1] <= lon1):
                return False
        return True

    def predicate(self, collection: str) -> Callable[[Mapping[str, object]], bool]:
        return lambda row: self.matches(row, collection)

    def describe(self) -> dict[str, object]:
        """The applied conditions, echoed in the page (``conditions``)."""
        out: dict[str, object] = {"tz": self.tz_label}
        if self.time_from is not None:
            out["from"] = self.time_from.isoformat()
        if self.time_to is not None:
            out["to"] = self.time_to.isoformat()
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
    conditions = RowConditions(
        time_from=start,
        time_to=end,
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


def filter_rows_page(
    rows: Sequence[object],
    predicate: Callable[[Mapping[str, object]], bool],
    *,
    collection: str,
    offset: int,
    limit: int,
) -> tuple[list[object], dict[str, object]]:
    """Rows of an in-memory list passing ``predicate`` -> ``(page rows with record_index, pagination)``.

    ``record_index`` is the row's position in ``rows``; ``matched`` is exact (the list is scanned
    to the end)."""
    page: list[object] = []
    matched = 0
    for record_index, row in enumerate(rows):
        if not isinstance(row, Mapping) or not predicate(row):
            continue
        if matched >= offset and (limit <= 0 or len(page) < limit):
            page.append({**row, "record_index": record_index})
        matched += 1
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
