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
        self.assert_rejected(fx.hwp()[:1500], "hwp", "hwp-")
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


if __name__ == "__main__":
    unittest.main()
