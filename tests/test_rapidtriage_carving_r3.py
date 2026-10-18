"""R3 carving signatures (plan r3-os-depth §3.3, Q-R3-6): positive, truncated and false-positive fixtures."""

from __future__ import annotations

import tempfile
import unittest
import unittest.mock
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from rapidtriage.core import carving_formats as formats
from rapidtriage.core.carving import (
    CARVED_FAMILIES,
    SIGNATURE_KINDS,
    STATUS_REJECTED,
    carve_buffer,
    carved_family,
    run_bounded_carving,
)
from tests import carving_r3_fixtures as fx

R3_KINDS = ("wav", "mp3", "m4a", "mp4", "docx", "xlsx", "pptx", "hwp", "hwpx", "eml", "pe", "evtx")


def carve(data: bytes, kinds: tuple[str, ...] | None = None) -> list[dict[str, object]]:
    from rapidtriage.core.carving import SIGNATURES

    signatures = [s for s in SIGNATURES if kinds is None or s.kind in kinds]
    return carve_buffer(
        data,
        source_path=Path("slack.bin"),
        output_dir=Path("unused"),
        extract=False,
        max_carve_bytes=64 * 1024 * 1024,
        remaining=1000,
        signatures=signatures,
    )


def accepted(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    return [entry for entry in entries if entry["status"] != STATUS_REJECTED]


class R3SignatureRegistryTests(unittest.TestCase):
    def test_every_r3_kind_is_registered_with_a_family(self) -> None:
        for kind in R3_KINDS:
            self.assertIn(kind, SIGNATURE_KINDS)
            self.assertIn(kind, CARVED_FAMILIES)
        self.assertEqual(carved_family("mp3")["family_artifact_type"], "media-audio")
        self.assertEqual(carved_family("mp3")["recovery_method"], "carved")
        self.assertEqual(len(SIGNATURE_KINDS), len(set(SIGNATURE_KINDS)))


class R3PositiveTests(unittest.TestCase):
    """Each format embedded in slack: found once, at its offset, with its exact length."""

    CASES: ClassVar[dict[str, Callable[[], bytes]]] = {
        "wav": fx.wav,
        "mp3": fx.mp3_id3,
        "m4a": fx.m4a,
        "mp4": fx.mp4,
        "docx": lambda: fx.ooxml("docx"),
        "xlsx": lambda: fx.ooxml("xlsx"),
        "pptx": lambda: fx.ooxml("pptx"),
        "hwp": fx.hwp,
        "hwpx": fx.hwpx,
        "pe": fx.pe,
        "evtx": fx.evtx,
    }

    def test_positive_fixture_per_signature(self) -> None:
        for kind, build in self.CASES.items():
            with self.subTest(kind=kind):
                payload = build()
                data = fx.slack(payload)
                hits = [entry for entry in accepted(carve(data)) if entry["kind"] == kind]
                self.assertEqual(len(hits), 1, hits)
                hit = hits[0]
                self.assertEqual(hit["offset"], 1024)
                self.assertEqual(hit["size"], len(payload), hit)
                self.assertIn(hit["status"], ("length-field", "footer-validated"))
                self.assertEqual(hit["confidence"], "high")
                self.assertEqual(hit["recovery"]["source_offset"], 1024)

    def test_eml_ends_at_nul_with_text_boundary(self) -> None:
        data = b"\x00" * 64 + fx.EML + b"\x00" * 64
        hits = accepted(carve(data, ("eml",)))
        self.assertEqual(len(hits), 1, "Received:/Delivered-To lines inside one message are not extra candidates")
        self.assertEqual(hits[0]["offset"], 64)
        self.assertEqual(hits[0]["size"], len(fx.EML))
        self.assertEqual(hits[0]["status"], formats.STATUS_TEXT_BOUNDARY)
        self.assertEqual(hits[0]["confidence"], "medium")

    def test_mp3_sync_only_stream_is_found_once(self) -> None:
        payload = fx.mp3_frames(20)
        hits = accepted(carve(fx.slack(payload), ("mp3",)))
        self.assertEqual(len(hits), 1, "frames inside the walked stream are claimed")
        self.assertEqual(hits[0]["size"], len(payload))
        self.assertEqual(hits[0]["boundary_method"], "frame-walk")

    def test_office_container_is_not_also_a_zip_and_members_are_claimed(self) -> None:
        payload = fx.ooxml("docx")
        entries = carve(fx.slack(payload))
        kinds = [entry["kind"] for entry in accepted(entries)]
        self.assertEqual(kinds, ["docx"])
        self.assertFalse([entry for entry in entries if entry["kind"] in ("xlsx", "pptx", "hwpx")])

    def test_plain_zip_stays_a_zip(self) -> None:
        payload = fx.plain_zip()
        kinds = {entry["kind"] for entry in accepted(carve(fx.slack(payload)))}
        self.assertIn("zip", kinds)
        self.assertFalse(kinds & {"docx", "xlsx", "pptx", "hwpx"})

    def test_m4a_and_mp4_split_by_brand(self) -> None:
        entries = accepted(carve(fx.slack(fx.m4a(), fx.mp4())))
        self.assertEqual([entry["kind"] for entry in entries], ["m4a", "mp4"])

    def test_scan_source_matches_carve_buffer_across_chunks(self) -> None:
        from rapidtriage.core import carving

        payloads = [fx.wav(), fx.mp3_id3(), fx.m4a(), fx.ooxml("xlsx"), fx.hwp(), fx.hwpx(), fx.pe(), fx.evtx(), fx.EML]
        data = fx.slack(*payloads)
        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.object(carving, "SCAN_CHUNK_BYTES", 20_000):
            root = Path(tmp) / "src"
            root.mkdir()
            (root / "slack.bin").write_bytes(data)
            payload = run_bounded_carving(root, Path(tmp) / "out", kinds=list(R3_KINDS), max_candidates=100)
            kinds = sorted(entry["kind"] for entry in payload["entries"] if entry["status"] != STATUS_REJECTED)
            self.assertEqual(kinds, sorted(["wav", "mp3", "m4a", "xlsx", "hwp", "hwpx", "pe", "evtx", "eml"]))
            self.assertEqual(payload["summary"]["rejected_count"], 0)
            # R3 review B7: the chunked scan reports exactly what carve_buffer reports.
            from rapidtriage.core.carving import SIGNATURES

            def key(entries: list[dict[str, object]]) -> list[tuple[object, ...]]:
                return sorted((entry["kind"], entry["offset"], entry["size"], entry["status"]) for entry in entries)

            in_memory = carve_buffer(
                data, source_path=Path("slack.bin"), output_dir=Path("unused"), extract=False,
                max_carve_bytes=carving.DEFAULT_MAX_CARVE_BYTES, remaining=100,
                signatures=[s for s in SIGNATURES if s.kind in R3_KINDS],
            )
            self.assertEqual(key(payload["entries"]), key(in_memory))


class R3FalsePositiveTests(unittest.TestCase):
    """Truncated files are carved as truncated (medium/low); corrupt headers are rejected with a reason."""

    def assert_rejected(self, data: bytes, kind: str, reason_prefix: str) -> None:
        entries = [entry for entry in carve(data, (kind,)) if entry["kind"] == kind]
        self.assertTrue(entries, f"{kind}: no entry")
        self.assertFalse(accepted(entries), entries)
        self.assertTrue(
            any(str(entry.get("rejected_reason", "")).startswith(reason_prefix) for entry in entries),
            [entry.get("rejected_reason") for entry in entries],
        )

    def assert_silent(self, data: bytes, kind: str) -> None:
        self.assertEqual([entry for entry in carve(data, (kind,)) if entry["kind"] == kind], [])

    def assert_truncated(self, data: bytes, kind: str) -> None:
        hits = accepted([entry for entry in carve(data, (kind,)) if entry["kind"] == kind])
        self.assertEqual(len(hits), 1, hits)
        self.assertIn(hits[0]["status"], ("length-field-truncated", "bounded-no-footer"))
        self.assertNotEqual(hits[0]["confidence"], "high")

    def test_wav(self) -> None:
        good = fx.wav()
        self.assert_truncated(good[: len(good) // 2], "wav")
        broken = bytearray(good)
        broken[22:24] = (0).to_bytes(2, "little")  # zero channels
        self.assert_rejected(bytes(broken), "wav", "wav-implausible-fmt")
        self.assert_silent(b"RIFF\x10\x00\x00\x00AVI LIST" + b"\x00" * 64, "wav")

    def test_mp3(self) -> None:
        tagged = fx.mp3_id3(frames=1) + b"\x00" * 900
        self.assert_rejected(tagged, "mp3", "mp3-frame-walk-too-short")
        self.assert_rejected(fx.mp3_frames(4) + b"\x00" * 600, "mp3", "mp3-frame-walk-too-short:4")
        self.assert_silent(b"\x00\xff\xfb\x00\x00\x00" * 10, "mp3")
        self.assert_rejected(b"ID3\x03\x00\x00\x00\x00\x81\x00" + b"\x00" * 64, "mp3", "id3-invalid-syncsafe-size")

    def test_m4a_mp4(self) -> None:
        self.assert_truncated(fx.m4a()[:600], "m4a")
        self.assert_truncated(fx.mp4()[:600], "mp4")
        no_media = fx._box(b"ftyp", b"isom\x00\x00\x02\x00isom") + fx._box(b"free", b"\x00" * 16) + b"\xe5" * 64
        self.assert_rejected(no_media, "mp4", "mp4-no-moov-or-mdat")
        self.assert_silent(fx.bmff(b"heic", (b"mif1", b"heic")), "mp4")
        self.assert_rejected(b"\x00\x00\x00\x07ftypisom" + b"\x00" * 64, "mp4", "implausible-ftyp-size")

    def test_ooxml(self) -> None:
        good = fx.ooxml("docx")
        self.assert_truncated(good[:-30], "docx")
        self.assert_rejected(fx.ooxml("docx", with_app_part=False), "docx", "ooxml-missing-app-part:word/")
        self.assert_silent(fx.ooxml("docx", with_app_part=False), "xlsx")
        self.assert_silent(fx.plain_zip(), "pptx")

    def test_hwpx(self) -> None:
        self.assert_rejected(fx.hwpx(with_contents=False), "hwpx", "hwpx-missing-contents-part")
        self.assert_truncated(fx.hwpx()[:-25], "hwpx")

    def test_hwp(self) -> None:
        self.assert_silent(fx.ole("WordDocument", b"\xec\xa5" + b"\x00" * 30), "hwp")
        # R3 review B6: an OLE file cut before its FileHeader is identified is silent (it may be
        # any compound file); once the FileHeader is verified, a short window is a truncated HWP.
        self.assert_silent(fx.hwp()[:1500], "hwp")
        self.assert_truncated(fx.hwp()[:-1], "hwp")
        broken = bytearray(fx.hwp())
        broken[0x1C:0x1E] = b"\xff\xff"
        self.assert_rejected(bytes(broken), "hwp", "ole-invalid-byte-order")

    def test_eml(self) -> None:
        self.assert_rejected(fx.EML.replace(b"Date:", b"X-Date:").replace(b"Message-ID:", b"X-Id:"), "eml", "eml-missing-required-fields")
        self.assert_rejected(b"Received: from nowhere\r\nthis is not a header\r\n\r\n", "eml", "eml-invalid-header-line")

    def test_pe(self) -> None:
        good = fx.pe()
        self.assert_truncated(good[:0x500], "pe")
        self.assert_rejected(fx.pe(sections=0), "pe", "pe-implausible-section-count")
        self.assert_silent(b"MZ" + b"\x00" * 200, "pe")
        bad_machine = bytearray(good)
        bad_machine[0x84:0x86] = b"\x34\x12"
        self.assert_rejected(bytes(bad_machine), "pe", "pe-unknown-machine")

    def test_evtx(self) -> None:
        good = fx.evtx(chunks=2)
        self.assert_truncated(good[: 4096 + 70_000], "evtx")
        broken = bytearray(good)
        broken[0x10] ^= 0xFF
        self.assert_rejected(bytes(broken), "evtx", "evtx-header-checksum-mismatch")
        no_chunk = fx.evtx(chunks=1)[:4096] + b"\x00" * 65536
        self.assert_rejected(no_chunk, "evtx", "evtx-no-valid-chunk")


def scan_entries(data: bytes, kinds: tuple[str, ...] | None = None, **kwargs: object) -> tuple[list[dict[str, object]], dict]:
    """``_scan_source`` over ``data`` written to a temporary file (API path: ``count_rejected=False``)."""
    from rapidtriage.core import carving

    signatures = [s for s in carving.SIGNATURES if kinds is None or s.kind in kinds]
    stats: dict = {}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "slack.bin"
        path.write_bytes(data)
        entries: list[dict[str, object]] = []
        carving._scan_source(
            path, read_limit=len(data), source_root=path.parent, output_dir=path.parent, extract=False,
            max_carve_bytes=int(kwargs.get("max_carve_bytes", 50 * 1024 * 1024)), remaining=int(kwargs.get("remaining", 250)),
            signatures=signatures, on_entry=entries.append, count_rejected=bool(kwargs.get("count_rejected", False)), stats=stats,
        )
    return entries, stats


def hostile_cfb(difat_sectors: int, *, sector_shift: int = 9, major: int = 3) -> bytes:
    """OLE header whose fat_count/DIFAT chain claim far more FAT sectors than the file holds."""
    import struct

    size = 1 << sector_shift
    per = size // 4
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, major, 0xFFFE, sector_shift, 6)
    struct.pack_into("<I", header, 0x2C, 109 + difat_sectors * (per - 1))
    struct.pack_into("<II", header, 0x44, 1, difat_sectors)
    struct.pack_into("<109I", header, 0x4C, *([0] * 109))
    sectors = [b"\x00" * size]
    for index in range(difat_sectors):
        following = index + 2 if index < difat_sectors - 1 else 0xFFFFFFFE
        sectors.append(struct.pack(f"<{per}I", *([0] * (per - 1) + [following])))
    return bytes(header).ljust(size, b"\x00") + b"".join(sectors)


class R3CarvingReviewTests(unittest.TestCase):
    """R3 adversarial-review regressions B1-B10 (repros ``carveB/t1``-``t9``)."""

    def test_hostile_cfb_fat_is_bounded(self) -> None:
        """B1: fat_count / DIFAT claiming ~0.5 GB from a 2 MiB file is rejected without allocating."""
        import struct
        import time
        import tracemalloc

        for difat_sectors, shift, major in ((4096, 9, 3), (64, 12, 4)):
            data = hostile_cfb(difat_sectors, sector_shift=shift, major=major)
            tracemalloc.start()
            started = time.monotonic()
            result = formats.walk_hwp(data)
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            self.assertIsInstance(result, str)
            self.assertTrue(formats.is_silent(result), result)
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertLess(peak, 16 * 1024 * 1024)
        duplicate = bytearray(fx.hwp() + b"\x00" * 2048)
        struct.pack_into("<I", duplicate, 0x2C, 2)
        struct.pack_into("<2I", duplicate, 0x4C, 0, 0)
        self.assertEqual(formats.walk_hwp(bytes(duplicate)), "hwp-difat-duplicate-sector")

    def test_memory_error_is_a_rejection(self) -> None:
        from rapidtriage.core import carving

        def explode(_window: bytes) -> object:
            raise MemoryError

        signature = next(s for s in carving.SIGNATURES if s.kind == "hwp")
        patched = carving.CarvingSignature(**{**signature.__dict__, "walker": explode})
        entries = carve_buffer(
            fx.slack(fx.hwp()), source_path=Path("x"), output_dir=Path("unused"), extract=False,
            max_carve_bytes=1024 * 1024, remaining=10, signatures=[patched],
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], STATUS_REJECTED)
        self.assertTrue(str(entries[0]["rejected_reason"]).endswith("memory-exhausted"))

    def test_walkers_prewalk_a_prefix_before_reading_the_window(self) -> None:
        """B2: an MP3 frame sync in random data no longer reads its 50 MiB window."""
        import os

        from rapidtriage.core import carving

        seen: list[int] = []
        original = formats.walk_mp3_sync

        def spy(window: bytes) -> object:
            seen.append(len(window))
            return original(window)

        data = os.urandom(2 * 1024 * 1024)
        signatures = [s for s in carving.SIGNATURES if s.kind == "mp3" and s.walker is formats.walk_mp3_sync]
        patched = [carving.CarvingSignature(**{**s.__dict__, "walker": spy}) for s in signatures]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.bin"
            path.write_bytes(data)
            carving._scan_source(
                path, read_limit=len(data), source_root=path.parent, output_dir=path.parent, extract=False,
                max_carve_bytes=50 * 1024 * 1024, remaining=250, signatures=patched, on_entry=lambda _e: None,
                count_rejected=False,
            )
        self.assertTrue(seen)
        self.assertEqual(max(seen), carving.PREWALK_BYTES)
        # A real stream still gets its full window after the prefix passes.
        hits = accepted(carve(fx.slack(fx.mp3_frames(200)), ("mp3",)))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["size"], len(fx.mp3_frames(200)))

    def test_repeated_received_lines_are_not_quadratic(self) -> None:
        """B3: an unterminated header block claims what it parsed; rejections per kind are capped."""
        import time

        from rapidtriage.core import carving

        data = b"Received: from x\n" * (1024 * 1024 // 17)
        started = time.monotonic()
        entries, _stats = scan_entries(data, ("eml",))
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertLessEqual(len(entries), 20)
        self.assertTrue(all(entry["rejected_reason"] == "eml-header-unterminated" for entry in entries))
        bad_pe = bytearray(fx.pe())
        bad_pe[0x84:0x86] = b"\x34\x12"
        with unittest.mock.patch.object(carving, "MAX_UNCOUNTED_REJECTIONS_PER_KIND", 3):
            entries, stats = scan_entries(fx.slack(*([bytes(bad_pe)] * 10)), ("pe",))
        self.assertEqual(len(entries), 3)
        self.assertEqual(stats["rejection_capped_kinds"], {"pe": 1})

    def test_truncated_candidates_claim_only_verified_structures(self) -> None:
        """B4: a footerless docx / truncated mp4 no longer hides the files after it."""
        import struct

        data = fx.slack(fx.ooxml("docx")[:-30], fx.ooxml("xlsx"), fx.hwpx())
        for entries in (carve(data), scan_entries(data)[0]):
            kinds = [entry["kind"] for entry in accepted(entries)]
            self.assertIn("docx", kinds)
            self.assertIn("xlsx", kinds)
            self.assertIn("hwpx", kinds)
        movie = bytearray(fx.mp4())
        mdat = bytes(movie).find(b"mdat") - 4
        struct.pack_into(">I", movie, mdat, 1 << 20)
        entries = accepted(carve(fx.slack(bytes(movie), fx.m4a())))
        self.assertEqual([(entry["kind"], entry["status"]) for entry in entries], [("mp4", "length-field-truncated"), ("m4a", "length-field")])

    def test_container_with_a_large_first_member_is_classified_from_the_central_directory(self) -> None:
        """B5: a docx whose first member is 300 KiB is one docx, not a zip plus a mid-archive docx."""
        import io
        import os
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(zipfile.ZipInfo("word/media/image1.png"), os.urandom(300 * 1024), compress_type=zipfile.ZIP_STORED)
            archive.writestr("word/document.xml", "<doc/>")
            archive.writestr("_rels/.rels", "<r/>")
            archive.writestr(
                "[Content_Types].xml",
                '<Types><Override PartName="/word/document.xml" ContentType="application/'
                'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            )
        payload = buffer.getvalue()
        for entries in (carve(fx.slack(payload)), scan_entries(fx.slack(payload))[0]):
            hits = accepted(entries)
            self.assertEqual([(entry["kind"], entry["offset"], entry["size"]) for entry in hits], [("docx", 1024, len(payload))])
            self.assertEqual(hits[0]["status"], "footer-validated")

    def test_hwp_truncation_and_non_hwp_ole(self) -> None:
        """B6: a short last sector is a truncated HWP; a truncated .doc is silent (not an hwp row)."""
        truncated = accepted(carve(fx.hwp()[:-1], ("hwp",)))
        self.assertEqual([entry["status"] for entry in truncated], ["length-field-truncated"])
        doc = fx.ole("WordDocument", b"\xec\xa5" + b"\x00" * 30)
        self.assertEqual(carve(doc[:1500], ("hwp",)), [])

    def test_carve_buffer_matches_scan_source(self) -> None:
        """B7: no per-signature resume point in carve_buffer (an embedded PE is reported by both)."""
        import struct

        outer = bytearray(fx.pe())
        struct.pack_into("<I", outer, 0x98 + 240 + 40 + 16, 0x800)
        data = fx.slack(bytes(outer[:0x600]) + fx.pe())

        def key(entries: list[dict[str, object]]) -> list[tuple[object, ...]]:
            return sorted((entry["kind"], entry["offset"], entry["size"], entry["status"]) for entry in entries)

        self.assertEqual(key(carve(data, ("pe",))), key(scan_entries(data, ("pe",), count_rejected=True)[0]))
        self.assertEqual(len(accepted(carve(data, ("pe",)))), 2)

    def test_length_sanity_checks(self) -> None:
        """B8: wav RIFF size, BMFF size-0 box, PE SizeOfHeaders, ID3 size, evtx chunk count, ZIP comment."""
        import struct

        wav = bytearray(fx.wav())
        struct.pack_into("<I", wav, 4, 4)
        self.assertEqual([e["rejected_reason"] for e in carve(bytes(wav), ("wav",))], ["wav-riff-size-before-fmt-end"])
        movie = fx._box(b"ftyp", b"isom\x00\x00\x02\x00isom") + b"\x00\x00\x00\x00free" + b"\xe5" * 1000
        self.assertEqual([e["rejected_reason"] for e in carve(movie, ("mp4",))], ["mp4-no-moov-or-mdat"])
        pe = bytearray(fx.pe())
        struct.pack_into("<I", pe, 0x98 + 60, 0x7FFFFFFF)
        self.assertTrue(str(carve(bytes(pe) + b"\x00" * 5000, ("pe",))[0]["rejected_reason"]).startswith("pe-implausible-size-of-headers"))
        pe = bytearray(fx.pe())
        struct.pack_into("<I", pe, 0x98 + 60, 0x800)  # past the first section's raw data (0x400)
        self.assertTrue(str(carve(bytes(pe), ("pe",))[0]["rejected_reason"]).startswith("pe-size-of-headers-past-first-section"))
        id3 = b"ID3\x03\x00\x00\x7f\x7f\x7f\x7f" + b"\x00" * 100
        self.assertEqual(carve(id3, ("mp3",)), [])
        empty_log = bytearray(fx.evtx(chunks=1)[:4096])
        struct.pack_into("<H", empty_log, 0x2A, 0)
        struct.pack_into("<I", empty_log, 0x7C, formats.zlib.crc32(bytes(empty_log[:120])) & 0xFFFFFFFF)
        self.assertEqual([e["rejected_reason"] for e in carve(bytes(empty_log) + b"\x00" * 4096, ("evtx",))], ["evtx-no-chunks"])
        document = fx.ooxml("docx")
        overflow = document[:-2] + b"\x01\x00"
        hits = accepted(carve(overflow, ("docx",)))
        self.assertEqual([(hit["status"], hit["size"]) for hit in hits], [("footer-validated", len(document))])

    def test_eml_boundaries(self) -> None:
        """B9: blank-line separators, mbox From_ lines, adjacent messages, DSN bodies."""
        body_from = fx.EML + b"From the desk of Alice\r\nmore body\r\n"
        self.assertEqual([e["size"] for e in accepted(carve(body_from, ("eml",)))], [len(body_from)])
        second = fx.EML.replace(b"Return-Path: <alice@example.test>\r\n", b"")
        adjacent = accepted(carve(fx.EML + second, ("eml",)))
        self.assertEqual([(e["offset"], e["size"]) for e in adjacent], [(0, len(fx.EML)), (len(fx.EML), len(second))])
        blank = accepted(carve(fx.EML + b"\r\n" + second, ("eml",)))
        self.assertEqual([e["offset"] for e in blank], [0, len(fx.EML) + 2])
        from_line = b"From alice@example.test Tue Oct  1 09:00:00 2024\r\n"
        mbox = fx.EML + from_line + fx.EML
        hits = accepted(carve(mbox, ("eml",)))
        self.assertEqual([(e["offset"], e["size"]) for e in hits], [(0, len(fx.EML)), (len(fx.EML) + len(from_line), len(fx.EML))])
        quoted = fx.EML + b"> Return-Path: <x@example.test>\r\nReturn-Path: in prose\r\n"
        self.assertEqual(len(accepted(carve(quoted, ("eml",)))), 1)
        dsn = (
            b"Return-Path: <>\r\nFrom: MAILER-DAEMON@example.test\r\nTo: bob@example.test\r\nSubject: failure\r\n"
            b"Date: Tue, 1 Oct 2024 09:00:00 +0900\r\nContent-Type: multipart/report; report-type=delivery-status;\r\n"
            b'\tboundary="b1"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nfailed\r\n\r\n--b1\r\n'
            b"Content-Type: message/rfc822\r\n\r\n" + fx.EML + b"\r\n--b1--\r\n"
        )
        self.assertEqual([(e["offset"], e["size"]) for e in accepted(carve(dsn, ("eml",)))], [(0, len(dsn))])

    def test_truncated_headers_at_end_of_file_are_silent(self) -> None:
        """B10: a header cut by the end of the file is not a false-positive row."""
        self.assertEqual(carve(fx.slack(fx.wav()) + b"ID3\x03", ("mp3",)), [])
        self.assertEqual([e for e in carve(fx.slack(fx.wav()) + b"RIFF\x00\x00", ("wav",)) if e["status"] == STATUS_REJECTED], [])
        self.assertEqual([e for e in carve(fx.slack(b"x") + b"MZ\x90\x00", ("pe",)) if e["status"] == STATUS_REJECTED], [])


if __name__ == "__main__":
    unittest.main()
