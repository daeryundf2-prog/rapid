"""Image / video indicators: EXIF, GPS, pHash (catalogue: apps §5)."""

from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from collections.abc import Iterator, Mapping

from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    base_name,
    evidence,
    extension,
    hamming64,
    hex_hash,
    parse_local_time,
    parse_time,
    register,
    select,
    split_windows_path,
)

IMAGES = select(types={"media-image", "mobile-media", "cloud-photo"}, kinds={"media-image", "mobile-export", "cloud-export"})
EXIF_FORMATS = frozenset({"jpeg", "jpg", "heic", "heif", "tiff", "tif", "dng", "cr2", "nef", "arw"})
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_SCREENSHOT_NAME = re.compile(r"screenshot|screen shot|스크린샷|캡처|화면 캡처|capture|screen_", re.IGNORECASE)


def capture_local(row: RowView) -> dt.datetime | None:
    return parse_local_time(row.get("exif_datetime_original", "datetime_original", "DateTimeOriginal"))


def capture_offset(row: RowView) -> dt.timedelta | None:
    text = row.text("exif_offset_time_original", "offset_time_original", "OffsetTimeOriginal")
    if not text:  # the media parser keeps it in its EXIF profile (details.exif_gps_profile)
        profile = row.details.get("exif_gps_profile")
        value = profile.get("offset_time_original") if isinstance(profile, Mapping) else None
        text = str(value).strip() if isinstance(value, str) else ""
    match = _OFFSET.match(text)
    if not match:
        return None
    sign = -1 if match.group(1) == "-" else 1
    return sign * dt.timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))


def capture_utc(row: RowView, default_offset_hours: float) -> tuple[dt.datetime | None, bool]:
    """(DateTimeOriginal as UTC, offset known?) -- the default offset is assumed when OffsetTimeOriginal is absent."""
    local = capture_local(row)
    if local is None:
        return None, False
    offset = capture_offset(row)
    known = offset is not None
    utc = (local - (offset if known else dt.timedelta(hours=default_offset_hours))).replace(tzinfo=dt.timezone.utc)
    return utc, known


def file_time(row: RowView) -> dt.datetime | None:
    return row.time("source_file_mtime", "fs_modified_at", "modified_at")


def image_format(row: RowView) -> str:
    return (row.text("content_format", "source_format", "format") or extension(row.path())).lower()


def gps(row: RowView) -> tuple[float, float] | None:
    lat, lon = row.number("gps_latitude", "latitude"), row.number("gps_longitude", "longitude")
    if lat is None or lon is None or (lat == 0 and lon == 0):
        return None
    return lat, lon


@register("media.exif_vs_fs_time")
class ExifVsFsTime(Rule):
    """DateTimeOriginal more than ``max_gap_hours`` away from the file-system modification time."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        captured, known = capture_utc(row, float(self.param("tz_offset_hours", 9)))
        modified = file_time(row)
        if captured is None or modified is None:
            return None
        gap = abs((modified - captured).total_seconds()) / 3600
        if gap <= float(self.param("max_gap_hours", 24)):
            return None
        return RuleResult(evidence(datetime_original=row.text("exif_datetime_original"), offset_known=known, fs_modified=modified, gap_hours=round(gap, 1)))


@register("media.exif_future_or_pre_device")
class ExifFutureOrPreDevice(Rule):
    """Capture time after the file's own modification time (beyond a day) or before ``min_year``."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        captured, _known = capture_utc(row, float(self.param("tz_offset_hours", 9)))
        if captured is None:
            return None
        if captured.year < int(self.param("min_year", 1995)):
            return RuleResult(evidence(datetime_original=row.text("exif_datetime_original"), camera=row.text("exif_model")), note="기기 시대보다 이른 촬영 시각")
        modified = file_time(row)
        if modified is not None and captured > modified + dt.timedelta(hours=float(self.param("future_slack_hours", 24))):
            return RuleResult(evidence(datetime_original=row.text("exif_datetime_original"), fs_modified=modified), note="촬영 시각이 파일 수정 시각보다 늦음")
        return None


@register("media.gps_present")
class GpsPresent(Rule):
    """GPS coordinates embedded in the image."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        point = gps(row)
        return RuleResult(evidence(latitude=point[0], longitude=point[1], gps_timestamp=row.text("gps_timestamp"))) if point else None


@register("media.gps_time_tz_inconsistent")
class GpsTimeInconsistent(Rule):
    """GPS UTC time disagrees with DateTimeOriginal − OffsetTimeOriginal (or is off a whole-quarter-hour zone without an offset)."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        gps_time = parse_time(row.get("gps_timestamp", "gps_datetime"))
        local = capture_local(row)
        if gps_time is None or local is None:
            return None
        tolerance = float(self.param("tolerance_minutes", 2)) * 60
        offset = capture_offset(row)
        naive_gps = gps_time.replace(tzinfo=None)
        if offset is not None:
            delta = abs((local - offset - naive_gps).total_seconds())
            if delta <= tolerance:
                return None
            return RuleResult(evidence(gps_utc=gps_time, datetime_original=local, offset=str(offset), delta_seconds=int(delta)))
        difference = (local - naive_gps).total_seconds()
        remainder = abs(difference) % 900
        off_zone = min(remainder, 900 - remainder)
        if abs(difference) <= 14 * 3600 and off_zone <= tolerance:
            return None  # a plausible time-zone difference
        return RuleResult(evidence(gps_utc=gps_time, datetime_original=local, delta_hours=round(difference / 3600, 2)))


@register("media.editing_software")
class EditingSoftware(Rule):
    """EXIF Software / XMP CreatorTool names an image editor (``editors``)."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        software = row.text("exif_software", "software", "xmp_creator_tool", "creator_tool")
        lowered = software.lower()
        matched = next((str(name) for name in self.param("editors", []) if str(name).lower() in lowered), "")
        return RuleResult(evidence(software=software, editor=matched)) if matched else None


@register("media.exif_stripped")
class ExifStripped(Rule):
    """JPEG/HEIC without Make, Model and DateTimeOriginal (messenger/SNS re-encode or scrubbing)."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if image_format(row) not in EXIF_FORMATS:
            return None
        if row.text("exif_make", "exif_model", "exif_datetime_original", "make", "model"):
            return None
        return RuleResult(evidence(file=base_name(row.path()), format=image_format(row)))


@register("media.phash_dup_cross_folder")
class PhashDuplicate(Rule):
    """Images in different folders whose perceptual hashes are within ``max_distance`` bits."""

    selector = IMAGES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.images: list[tuple[int, str, RowRef, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        value = hex_hash(row.get("perceptual_hash", "phash"))
        width, height = row.number("width"), row.number("height")
        if value is None or value == 0 or (width and height and width * height < float(self.param("min_pixels", 10000))):
            return None
        _drive, rest = split_windows_path(row.path())
        self.images.append((value, rest.rsplit("\\", 1)[0], row.ref, base_name(row.path())))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        max_distance = int(self.param("max_distance", 8))
        bands = max_distance + 1
        width = max(1, 64 // bands)
        buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
        for position, (value, _folder, _ref, _name) in enumerate(self.images):
            for band in range(bands):
                buckets[(band, (value >> (band * width)) & ((1 << width) - 1))].append(position)
        partners: dict[int, tuple[int, str]] = {}
        max_bucket = int(self.param("max_bucket", 500))
        for members in buckets.values():
            if len(members) < 2 or len(members) > max_bucket:
                continue
            for index, left in enumerate(members):
                for right in members[index + 1 :]:
                    a, b = self.images[left], self.images[right]
                    if a[1] == b[1]:
                        continue
                    distance = hamming64(a[0], b[0])
                    if distance <= max_distance:
                        for mine, other in ((left, b), (right, a)):
                            if mine not in partners or distance < partners[mine][0]:
                                partners[mine] = (distance, other[3])
        for position, (distance, other) in partners.items():
            _value, folder, ref, name = self.images[position]
            yield ref, RuleResult(evidence(file=name, folder=folder, similar_file=other, distance=distance))


@register("media.thumb_mismatch")
class ThumbnailMismatch(Rule):
    """Embedded thumbnail pHash far from the main image pHash (edited without refreshing the thumbnail)."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        main = hex_hash(row.get("perceptual_hash", "phash"))
        thumb = hex_hash(row.get("thumbnail_perceptual_hash", "embedded_thumbnail_phash", "thumbnail_phash"))
        if main is None or thumb is None:
            return None
        distance = hamming64(main, thumb)
        if distance <= int(self.param("min_distance", 16)):
            return None
        return RuleResult(evidence(file=base_name(row.path()), distance=distance))


@register("media.screenshot_flag")
class ScreenshotFlag(Rule):
    """No camera Make/Model and a screenshot-like file name or a common screen resolution."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.text("exif_make", "exif_model", "make", "model"):
            return None
        name = base_name(row.path())
        size = f"{int(row.number('width') or 0)}x{int(row.number('height') or 0)}"
        screens = {str(item) for item in self.param("screen_sizes", [])}
        if _SCREENSHOT_NAME.search(name):
            return RuleResult(evidence(file=name, reason="파일 이름"))
        if size in screens:
            return RuleResult(evidence(file=name, size=size, reason="화면 해상도"))
        return None


@register("media.live_photo_orphan")
class LivePhotoOrphan(Rule):
    """HEIC whose same-name MOV (Live Photo pair) is missing from the same folder of the file listing."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if not ctx.file_paths_known or extension(row.path()) not in {"heic", "heif"}:
            return None
        _drive, rest = split_windows_path(row.path())
        stem = rest.rsplit(".", 1)[0]
        folder = stem.rsplit("\\", 1)[0] if "\\" in stem else ""
        if folder not in ctx.file_dirs:
            return None
        if f"{stem}.mov" in ctx.file_paths:
            return None
        return RuleResult(evidence(file=base_name(row.path())), note="짝 MOV 없음(메신저 전송 시 분리될 수 있음)")


@register("media.metadata_conflict")
class MetadataConflict(Rule):
    """EXIF DateTimeOriginal / DateTimeDigitized / XMP CreateDate / IPTC DateCreated disagree by more than ``tolerance_minutes``."""

    selector = IMAGES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        values = {
            "exif_datetime_original": parse_local_time(row.get("exif_datetime_original")),
            "exif_datetime_digitized": parse_local_time(row.get("exif_datetime_digitized")),
            "xmp_create_date": parse_local_time(row.get("xmp_create_date", "xmp_createdate")),
            "iptc_date_created": parse_local_time(row.get("iptc_date_created")),
        }
        present = {key: value for key, value in values.items() if value is not None}
        if len(present) < 2:
            return None
        spread = (max(present.values()) - min(present.values())).total_seconds()
        if spread <= float(self.param("tolerance_minutes", 1)) * 60:
            return None
        return RuleResult(evidence(**{key: value.isoformat() for key, value in present.items()}, spread_seconds=int(spread)))
