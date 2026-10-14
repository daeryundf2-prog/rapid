"""Parser-quality round 1 (W5 media): native EXIF, content-based format,
JPEG trailers, ISO-BMFF boxes, and image/video timestamps.

Fixtures are synthetic binaries built in-test; no Pillow is required (the
decoder-dependent assertions skip when no image decoder is importable).
"""

from __future__ import annotations

import base64
import datetime as dt
import os
import re
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts import media, synthetic_media
from rapidtriage.artifacts.media import (
    MediaImageProvider,
    build_image_record,
    build_media_av_record,
    extract_exif_gps_profile,
    scan_image_structure,
    sniff_image_format,
    steganography_suspicion_profile,
)
from rapidtriage.artifacts.synthetic_media import SyntheticMediaProvider

# 8x8 baseline JPEG (APP0 JFIF) generated once with Pillow and frozen here.
TINY_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0o"
    "MCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAAIAAgDASIA"
    "AhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0Kx"
    "wRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ip"
    "qrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREA"
    "AgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldY"
    "WVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3"
    "+Pn6/9oADAMBAAIRAxEAPwDyLwt/y9f8B/rRRRXRxr/yO6//AG7/AOkRP0Phn/kWUv8At7/0pn//2Q=="
)
HANGUL_RE = re.compile(r"[가-힣]")
HAS_DECODER = not (isinstance(media.cv2, media.PillowCv2Compat) and media.Image is None)


def _encode_value(endian: str, value_type: int, value: object) -> tuple[int, bytes]:
    if value_type == 2:
        raw = str(value).encode("utf-8") + b"\x00"
        return len(raw), raw
    if value_type in (1, 7):
        raw = bytes(value)  # type: ignore[arg-type]
        return len(raw), raw
    values = list(value)  # type: ignore[call-overload]
    if value_type == 3:
        return len(values), struct.pack(f"{endian}{len(values)}H", *values)
    if value_type == 4:
        return len(values), struct.pack(f"{endian}{len(values)}I", *values)
    if value_type == 5:
        flat = [part for pair in values for part in pair]
        return len(values), struct.pack(f"{endian}{len(flat)}I", *flat)
    raise ValueError(value_type)


def build_tiff(
    endian: str,
    ifd0: list[tuple[int, int, object]],
    exif: list[tuple[int, int, object]] | None = None,
    gps: list[tuple[int, int, object]] | None = None,
    *,
    corrupt_exif_pointer: bool = False,
) -> bytes:
    """Minimal TIFF/EXIF writer: IFD0, optional Exif and GPS sub-IFDs, data area."""
    tables: list[list[tuple[int, int, object]]] = [list(ifd0)]
    if exif is not None:
        tables[0].append((0x8769, 4, None))
        tables.append(list(exif))
    if gps is not None:
        tables[0].append((0x8825, 4, None))
        tables.append(list(gps))
    for table in tables:
        table.sort(key=lambda row: row[0])
    ifd_offsets = []
    cursor = 8
    for table in tables:
        ifd_offsets.append(cursor)
        cursor += 2 + 12 * len(table) + 4
    data_area = bytearray()
    data_start = cursor
    pointer_targets = {0x8769: ifd_offsets[1] if exif is not None else 0}
    if gps is not None:
        pointer_targets[0x8825] = ifd_offsets[-1]
    if corrupt_exif_pointer:
        pointer_targets[0x8769] = 0x7FFFFFF0
    out = bytearray(b"II*\x00" if endian == "<" else b"MM\x00*")
    out += struct.pack(endian + "I", 8)
    for table in tables:
        out += struct.pack(endian + "H", len(table))
        for tag, value_type, value in table:
            if value is None:
                out += struct.pack(endian + "HHII", tag, 4, 1, pointer_targets[tag])
                continue
            count, raw = _encode_value(endian, value_type, value)
            if len(raw) <= 4:
                out += struct.pack(endian + "HHI", tag, value_type, count) + raw.ljust(4, b"\x00")
            else:
                out += struct.pack(endian + "HHII", tag, value_type, count, data_start + len(data_area))
                data_area += raw
                if len(data_area) % 2:
                    data_area += b"\x00"
        out += struct.pack(endian + "I", 0)
    return bytes(out + data_area)


def camera_tiff(endian: str = "<", *, with_offset: bool = True, corrupt_exif_pointer: bool = False) -> bytes:
    exif = [
        (0x9003, 2, "2024:08:21 22:55:34"),
        (0x9004, 2, "2024:08:21 22:55:35"),
        (0x9291, 2, "101"),
        (0xA434, 2, "iPhone 13 Pro back triple camera 5.7mm f/1.5"),
    ]
    if with_offset:
        exif.append((0x9011, 2, "+09:00"))
    gps = [
        (1, 2, "S"),
        (2, 5, [(37, 1), (33, 1), (30, 1)]),
        (3, 2, "W"),
        (4, 5, [(127, 1), (0, 1), (0, 1)]),
        (5, 1, [1]),
        (6, 5, [(25, 1)]),
        (7, 5, [(10, 1), (20, 1), (61, 2)]),
        (29, 2, "2026:05:14"),
    ]
    ifd0 = [
        (0x010F, 2, "Apple"),
        (0x0110, 2, "iPhone 13 Pro"),
        (0x0131, 2, "18.2"),
        (0x0132, 2, "2025:02:23 22:17:38"),
        (0x0112, 3, [6]),
    ]
    return build_tiff(endian, ifd0, exif, gps, corrupt_exif_pointer=corrupt_exif_pointer)


def jpeg_with_exif(tiff: bytes, *, trailer: bytes = b"") -> bytes:
    payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    return TINY_JPEG[:2] + app1 + TINY_JPEG[2:] + trailer


def bmff_box(box_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + box_type + payload


def mp4_seconds(value: dt.datetime) -> int:
    return int((value - dt.datetime(1904, 1, 1, tzinfo=dt.timezone.utc)).total_seconds())


class MediaNativeExifTests(unittest.TestCase):
    def _profile(self, data: bytes, name: str = "photo.jpg") -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / name
            path.write_bytes(data)
            # Native parse only: Pillow must not be needed.
            with patch.object(media, "Image", None):
                return extract_exif_gps_profile(path)

    def test_sub_ifd_datetime_original_make_model_lens_both_byte_orders(self) -> None:
        for endian in ("<", ">"):
            with self.subTest(endian=endian):
                profile = self._profile(jpeg_with_exif(camera_tiff(endian)))
                self.assertEqual(profile["parser"], "native-tiff-exif")
                self.assertEqual(profile["exif_locator"], "jpeg-app1-exif")
                self.assertTrue(profile["has_exif"])
                self.assertEqual(profile["make"], "Apple")
                self.assertEqual(profile["model"], "iPhone 13 Pro")
                self.assertEqual(profile["software"], "18.2")
                self.assertEqual(profile["orientation"], 6)
                self.assertEqual(profile["lens_model"], "iPhone 13 Pro back triple camera 5.7mm f/1.5")
                self.assertEqual(profile["image_datetime_original"], "2024:08:21 22:55:34")
                self.assertEqual(profile["image_datetime"], "2025:02:23 22:17:38")
                self.assertEqual(profile["datetime_original_iso"], "2024-08-21T22:55:34.101+09:00")
                self.assertEqual(profile["offset_time_original"], "+09:00")

    def test_gps_ifd_decimal_degrees_refs_altitude_and_iso_timestamp(self) -> None:
        profile = self._profile(jpeg_with_exif(camera_tiff(">")))
        self.assertEqual(profile["status"], "parsed")
        self.assertTrue(profile["has_gps"])
        self.assertAlmostEqual(profile["latitude"], -37.5583333)
        self.assertAlmostEqual(profile["longitude"], -127.0)
        self.assertEqual(profile["altitude_meters"], -25.0)
        self.assertEqual(profile["gps_timestamp"], "2026-05-14T10:20:30.500000Z")
        self.assertEqual(profile["map_marker"]["status"], "ready")

    def test_out_of_range_exif_pointer_is_bounded_not_fatal(self) -> None:
        profile = self._profile(jpeg_with_exif(camera_tiff("<", corrupt_exif_pointer=True)))
        self.assertTrue(profile["has_exif"])
        self.assertEqual(profile["make"], "Apple")
        self.assertEqual(profile["image_datetime_original"], "")
        self.assertIn("exif-ifd-offset-out-of-range", profile["parse_notes"])

    def test_truncated_app1_and_garbage_do_not_raise(self) -> None:
        tiff = camera_tiff("<")
        truncated = TINY_JPEG[:2] + b"\xff\xe1\x00\x40Exif\x00\x00" + tiff[:40]
        profile = self._profile(truncated)
        self.assertIn(profile["status"], {"no-exif", "no-gps-ifd", "parsed", "gps-ifd-without-complete-coordinate"})
        self.assertEqual(self._profile(b"\xff\xd8\xff" + os.urandom(64))["has_gps"], False)

    def test_png_exif_chunk_and_tiff_file_are_parsed_natively(self) -> None:
        tiff = camera_tiff("<", with_offset=False)
        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)

        def chunk(kind: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + kind + data + b"\x00\x00\x00\x00"

        png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"eXIf", tiff) + chunk(b"IEND", b"")
        profile = self._profile(png, "shot.png")
        self.assertEqual(profile["exif_locator"], "png-exif-chunk")
        self.assertEqual(profile["datetime_original_iso"], "2024-08-21T22:55:34.101")
        tiff_profile = self._profile(tiff, "scan.tif")
        self.assertEqual(tiff_profile["exif_locator"], "tiff-header")
        self.assertEqual(tiff_profile["model"], "iPhone 13 Pro")


class MediaFormatSniffTests(unittest.TestCase):
    def test_magic_based_formats(self) -> None:
        heic_ftyp = struct.pack(">I", 0x1C) + b"ftypheic" + b"\x00\x00\x00\x00" + b"mif1heicmiaf"
        avif_ftyp = struct.pack(">I", 0x20) + b"ftypavif" + b"\x00\x00\x00\x00" + b"mif1miafMA1Bavif"
        generic_heif = struct.pack(">I", 0x18) + b"ftypmif1" + b"\x00\x00\x00\x00" + b"mif1miaf"
        cases = {
            "jpeg": TINY_JPEG,
            "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            "gif": b"GIF87a\x01\x00\x01\x00",
            "webp": b"RIFF\x10\x00\x00\x00WEBPVP8 ",
            "bmp": b"BM" + struct.pack("<I", 58) + b"\x00\x00\x00\x00" + b"\x36\x00\x00\x00" + b"\x28" + b"\x00" * 15,
            "tiff": b"MM\x00*\x00\x00\x00\x08",
            "heic": heic_ftyp,
            "avif": avif_ftyp,
            "heif": generic_heif,
        }
        for expected, header in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(sniff_image_format(header), expected)
        self.assertEqual(sniff_image_format(b"GIF89a\x01\x00"), "gif")
        self.assertEqual(sniff_image_format(b"II*\x00\x08\x00\x00\x00"), "tiff")
        self.assertEqual(sniff_image_format(struct.pack(">I", 0x18) + b"ftypisom\x00\x00\x02\x00isomiso2"), "")
        self.assertEqual(sniff_image_format(b"<html>"), "")

    def test_ftyp_box_size_is_honored_beyond_0x18(self) -> None:
        # 'heic' only appears as the 4th compatible brand past offset 0x18.
        header = struct.pack(">I", 0x24) + b"ftypmif1" + b"\x00\x00\x00\x00" + b"mif1miafMiHEMiPrheic"
        self.assertEqual(sniff_image_format(header), "heic")

    def test_extensions_include_jfif_heic_heif_gif_webp(self) -> None:
        for suffix in (".jfif", ".heic", ".heif", ".gif", ".webp", ".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff"):
            self.assertIn(suffix, media.IMAGE_EXTENSIONS)

    def test_provider_collects_new_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "a.jfif").write_bytes(TINY_JPEG)
            (root / "b.gif").write_bytes(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;")
            (root / "c.heic").write_bytes(struct.pack(">I", 0x18) + b"ftypheic\x00\x00\x00\x00mif1heic")
            records = list(MediaImageProvider().collect(root))
        self.assertEqual(sorted(Path(r.path).suffix for r in records), [".gif", ".heic", ".jfif"])


class MediaImageRecordTests(unittest.TestCase):
    def test_seft_trailer_is_recorded_not_unreadable(self) -> None:
        trailer = b"SEFH\x01\x00\x00\x00" + b"MZ" + b"\x00" * 40 + b"\x10\x00\x00\x00SEFT"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "20210420_224329.jpg"
            path.write_bytes(jpeg_with_exif(camera_tiff("<"), trailer=trailer))
            structure = scan_image_structure(path)
            self.assertEqual(structure["structure_status"], "parsed")
            self.assertEqual(structure["trailer_signature"], "samsung-seft")
            self.assertEqual(structure["trailing_data_bytes"], len(trailer))
            record = build_image_record(path)
            stego = steganography_suspicion_profile(path, width=8, height=8, structure=structure)
        details = record.details
        self.assertEqual(details["trailer_signature"], "samsung-seft")
        self.assertEqual(details["trailing_data_bytes"], len(trailer))
        self.assertTrue(HANGUL_RE.search(details["trailer_note"]))
        # A bare "MZ" in vendor trailer bytes is not a PE payload.
        self.assertEqual(stego["embedded_signature_candidates"], [])
        self.assertEqual(stego["suspicion_level"], "low")
        if HAS_DECODER:
            self.assertEqual(record.artifact_type, "media-image")
            self.assertTrue(details["decoded"])
            self.assertEqual(details["width"], 8)
            self.assertEqual(len(details["perceptual_hash"]), 16)
            self.assertTrue(details["thumbnail_preview"]["available"])

    def test_extension_mismatch_flagged_and_decoded_by_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "도장.png"
            path.write_bytes(TINY_JPEG)
            details = build_image_record(path).details
        self.assertEqual(details["content_format"], "jpeg")
        self.assertEqual(details["extension_format"], "png")
        self.assertTrue(details["extension_mismatch"])
        self.assertTrue(HANGUL_RE.search(details["extension_mismatch_note"]))
        if HAS_DECODER:
            self.assertTrue(details["decoded"])
            self.assertEqual(details["decode_status"], "decoded")

    def test_image_timestamp_is_datetime_original_never_host_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with_exif = Path(tmp_dir) / "camera.jpg"
            with_exif.write_bytes(jpeg_with_exif(camera_tiff("<", with_offset=False)))
            plain = Path(tmp_dir) / "plain.jpg"
            plain.write_bytes(TINY_JPEG)
            os.utime(plain, (1_790_000_000, 1_790_000_000))
            exif_details = build_image_record(with_exif).details
            plain_details = build_image_record(plain).details
        self.assertEqual(exif_details["timestamp"], "2024-08-21T22:55:34.101")
        self.assertEqual(exif_details["timestamp_kind"], "exif-datetime-original")
        self.assertEqual(exif_details["timestamp_timezone"], "exif-local")
        self.assertEqual(exif_details["exif_make"], "Apple")
        self.assertEqual(exif_details["exif_model"], "iPhone 13 Pro")
        self.assertEqual(exif_details["gps_timestamp"], "2026-05-14T10:20:30.500000Z")
        self.assertNotIn("timestamp", plain_details)
        self.assertNotIn("modified_at", plain_details)
        self.assertEqual(plain_details["source_file_mtime"], dt.datetime.fromtimestamp(1_790_000_000, tz=dt.timezone.utc).isoformat())

    def test_heic_with_exif_gets_timestamp_and_clear_decoder_reason(self) -> None:
        tiff = camera_tiff(">")
        ftyp = struct.pack(">I", 0x1C) + b"ftypheic" + b"\x00\x00\x00\x00" + b"mif1heicmiaf"
        meta = bmff_box(b"meta", b"\x00\x00\x00\x00" + bmff_box(b"hdlr", b"\x00" * 24))
        mdat = bmff_box(b"mdat", b"\x00\x00\x00\x06Exif\x00\x00" + tiff + b"\x00" * 32)
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "photo_0.heic"
            path.write_bytes(ftyp + meta + mdat)
            with patch.object(media, "Image", None):
                record = build_image_record(path)
        details = record.details
        self.assertEqual(details["content_format"], "heic")
        self.assertFalse(details["extension_mismatch"])
        self.assertEqual(details["ftyp_major_brand"], "heic")
        self.assertEqual(details["timestamp"], "2024-08-21T22:55:34.101+09:00")
        self.assertEqual(details["timestamp_timezone"], "+09:00")
        self.assertEqual(details["exif_gps_profile"]["exif_locator"], "heif-signature-scan")
        self.assertEqual(record.artifact_type, "media-image")
        self.assertEqual(details["decode_status"], "decoder-unsupported-format")
        self.assertTrue(HANGUL_RE.search(details["decode_reason"]))

    def test_non_image_content_is_the_only_unreadable_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "cache.png"
            path.write_bytes(b"c\x82\xb6\x80\xa3_C\xbe" + os.urandom(256))
            record = build_image_record(path)
        self.assertEqual(record.artifact_type, "media-image-unreadable")
        self.assertEqual(record.details["decode_status"], "content-not-image")

    def test_gif_trailer_offset(self) -> None:
        gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00" + b"\x00\x00\x00\xff\xff\xff"
        gif += b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00" + b"\x02\x02\x44\x01\x00" + b";"
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "a.gif"
            path.write_bytes(gif + b"extra")
            structure = scan_image_structure(path)
        self.assertEqual(structure["structure_status"], "parsed")
        self.assertEqual(structure["image_end_offset"], len(gif))
        self.assertEqual(structure["trailing_data_bytes"], 5)


class MediaMp4BoxTests(unittest.TestCase):
    def _mp4(self, *, version: int, creation: int, largesize_mdat: bool = True) -> bytes:
        ftyp = struct.pack(">I", 0x20) + b"ftypisom" + struct.pack(">I", 0x200) + b"isomiso2avc1mp41"
        if version == 1:
            mvhd_payload = b"\x01\x00\x00\x00" + struct.pack(">QQIQ", creation, creation + 60, 1000, 236433) + b"\x00" * 80
        else:
            mvhd_payload = b"\x00\x00\x00\x00" + struct.pack(">IIII", creation, creation, 600, 1200) + b"\x00" * 80
        moov = bmff_box(b"moov", bmff_box(b"mvhd", mvhd_payload))
        mdat_payload = b"\x00" * 64
        if largesize_mdat:
            mdat = struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", 16 + len(mdat_payload)) + mdat_payload
        else:
            mdat = bmff_box(b"mdat", mdat_payload)
        free_to_eof = struct.pack(">I", 0) + b"free" + b"\x00" * 24
        return ftyp + mdat + moov + free_to_eof

    def test_mvhd_v1_creation_time_after_largesize_mdat(self) -> None:
        creation = mp4_seconds(dt.datetime(2021, 12, 14, 11, 5, 34, tzinfo=dt.timezone.utc))
        self.assertEqual(creation, 3722324734)
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "clip.mp4"
            path.write_bytes(self._mp4(version=1, creation=creation))
            details = build_media_av_record(path, media_kind="video").details
        profile = details["container_profile"]
        self.assertEqual(profile["major_brand"], "isom")
        self.assertEqual(profile["compatible_brands"], ["isom", "iso2", "avc1", "mp41"])
        self.assertEqual([box["type"] for box in profile["box_inventory"]], ["ftyp", "mdat", "moov", "free"])
        self.assertEqual(profile["box_inventory"][1]["header_size"], 16)
        self.assertEqual(profile["box_walk_status"], "complete")
        self.assertEqual(profile["mvhd_profile"]["version"], 1)
        self.assertEqual(profile["mvhd_profile"]["creation_time"], "2021-12-14T11:05:34Z")
        self.assertEqual(profile["mvhd_profile"]["estimated_duration_seconds"], 236.433)
        self.assertEqual(details["timestamp"], "2021-12-14T11:05:34Z")
        self.assertEqual(details["timestamp_kind"], "mp4-mvhd-creation")
        self.assertEqual(details["container_modified_time"], "2021-12-14T11:06:34Z")
        self.assertNotIn("modified_at", details)
        self.assertIsInstance(details["source_file_mtime"], str)

    def test_zero_creation_time_yields_no_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "kakao.mp4"
            path.write_bytes(self._mp4(version=0, creation=0, largesize_mdat=False))
            details = build_media_av_record(path, media_kind="video").details
        self.assertEqual(details["container_profile"]["mvhd_profile"]["status"], "parsed")
        self.assertEqual(details["container_profile"]["mvhd_profile"]["creation_time"], "")
        self.assertNotIn("timestamp", details)
        self.assertEqual(details["duration_seconds"], 2.0)

    def test_truncated_box_is_reported(self) -> None:
        data = self._mp4(version=0, creation=0, largesize_mdat=False)
        broken = data[:0x20] + struct.pack(">I", 0xFFFF) + b"mdat" + b"\x00" * 8
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "broken.mov"
            path.write_bytes(broken)
            profile = build_media_av_record(path, media_kind="video").details["container_profile"]
        self.assertEqual(profile["box_walk_status"], "truncated-or-invalid-box")
        self.assertEqual(profile["mvhd_profile"]["status"], "not-found")


class SyntheticMediaImportErrorTests(unittest.TestCase):
    def test_missing_module_reports_real_import_error_and_skipped_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            with patch.dict(sys.modules, {"deepfake_lens": None}):
                records = list(SyntheticMediaProvider().collect(root))
        details = records[0].details
        self.assertEqual(details["status"], "skipped")
        self.assertEqual(details["collection_status"], "skipped")
        self.assertEqual(details["scan_status"], "skipped-optional-dependency")
        self.assertIn("ModuleNotFoundError: import of deepfake_lens halted", details["import_error_detail"])
        # The exception text stays out of the aggregated, stable skip_reason.
        self.assertEqual(details["skip_reason"], synthetic_media.SYNTHETIC_MEDIA_SKIP_REASON)
        self.assertEqual(details["reason"], details["skip_reason"])
        self.assertNotIn("ModuleNotFoundError", details["skip_reason"])
        self.assertTrue(HANGUL_RE.search(details["skip_reason"]))
        self.assertEqual(details["unscanned_candidate_count"], 1)

    def test_non_importerror_failure_text_is_preserved(self) -> None:
        def boom(_name: str) -> object:
            raise OSError("DLL load failed while importing _onnx")

        with tempfile.TemporaryDirectory() as tmp_dir, patch.object(synthetic_media.importlib, "import_module", boom):
            records = list(SyntheticMediaProvider().collect(Path(tmp_dir)))
        self.assertEqual(records[0].details["import_error_detail"], "OSError: DLL load failed while importing _onnx")


if __name__ == "__main__":
    unittest.main()
