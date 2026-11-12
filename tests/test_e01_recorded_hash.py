"""T-181: read the acquisition hash recorded in an E01 (D34a) and the evidence hash verdict.

The fixtures are synthetic EWF1 segment files built at runtime in a temp directory: a valid
file header plus a chain of 76-byte section descriptors (``header`` / ``hash`` / ``digest`` /
``xhash`` / ``done``). They are not full images (no ``volume`` / ``table`` / ``sectors``), so
libewf cannot open them; the built-in section walker is what these tests exercise, and the
libewf path is covered with a stub. Real-image acceptance (IMG-A) is a QA step.
"""

from __future__ import annotations

import hashlib
import struct
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from rapidtriage.api.app.case_workspace import CaseWorkspace
from rapidtriage.core import e01_recorded_hash as recorded_hash
from rapidtriage.core.e01_recorded_hash import (
    EWF1_SIGNATURE,
    EWF2_SIGNATURE,
    RecordedHash,
    evidence_hash_verdict,
    parse_digest_section,
    parse_hash_section,
    parse_xhash_section,
    read_recorded_acquisition_hash,
)

MD5 = bytes(range(1, 17))
SHA1 = bytes(range(101, 121))


def _descriptor(section_type: str, next_offset: int, size: int) -> bytes:
    head = section_type.encode("ascii").ljust(16, b"\x00") + struct.pack("<QQ", next_offset, size) + b"\x00" * 40
    return head + struct.pack("<I", zlib.adler32(head))


def build_ewf1_segment(sections: list[tuple[str, bytes]], segment_number: int = 1) -> bytes:
    """EWF1 segment: 13-byte file header + chained sections; ``done`` points at itself."""
    out = bytearray(EWF1_SIGNATURE + b"\x01" + struct.pack("<H", segment_number) + b"\x00\x00")
    for section_type, data in sections:
        offset = len(out)
        size = 76 + len(data)
        terminal = section_type in ("done", "next")
        out += _descriptor(section_type, offset if terminal else offset + size, 0 if terminal else size) + data
    return bytes(out)


def hash_data(md5: bytes = MD5) -> bytes:
    payload = md5 + b"\x00" * 16
    return payload + struct.pack("<I", zlib.adler32(payload))


def digest_data(md5: bytes = MD5, sha1: bytes = SHA1) -> bytes:
    payload = md5 + sha1 + b"\x00" * 40
    return payload + struct.pack("<I", zlib.adler32(payload))


def xhash_data(md5_hex: str, sha1_hex: str) -> bytes:
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<xhash>\n\t<md5>{md5_hex}</md5>\n\t<sha1>{sha1_hex}</sha1>\n</xhash>\n'
    return zlib.compress(xml.encode("utf-8"))


class SectionParserTests(unittest.TestCase):
    def test_hash_digest_xhash_parsers(self) -> None:
        self.assertEqual(parse_hash_section(hash_data()), {"md5": MD5.hex()})
        self.assertEqual(parse_digest_section(digest_data()), {"md5": MD5.hex(), "sha1": SHA1.hex()})
        self.assertEqual(
            parse_xhash_section(xhash_data(MD5.hex().upper(), SHA1.hex())), {"md5": MD5.hex(), "sha1": SHA1.hex()}
        )

    def test_zero_or_short_fields_are_absent(self) -> None:
        self.assertEqual(parse_hash_section(hash_data(b"\x00" * 16)), {})
        self.assertEqual(parse_digest_section(digest_data(b"\x00" * 16, b"\x00" * 20)), {})
        self.assertEqual(parse_digest_section(MD5), {"md5": MD5.hex()})
        self.assertEqual(parse_hash_section(b"\x01\x02"), {})
        self.assertEqual(parse_xhash_section(b"not zlib"), {})
        self.assertEqual(parse_xhash_section(xhash_data("0" * 32, "zz")), {})


class ReadRecordedHashTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_reads_hash_and_digest_sections_without_touching_the_file(self) -> None:
        image = self.write(
            "case.E01",
            build_ewf1_segment([("header", b"x" * 40), ("hash", hash_data()), ("digest", digest_data()), ("done", b"")]),
        )
        before = (image.read_bytes(), image.stat().st_mtime_ns)
        result = read_recorded_acquisition_hash(image)
        self.assertEqual((result.md5, result.sha1, result.source), (MD5.hex(), SHA1.hex(), "ewf1-sections"))
        self.assertEqual(result.sections, ["hash", "digest"])
        self.assertEqual(result.reason, "")
        self.assertEqual((image.read_bytes(), image.stat().st_mtime_ns), before)
        payload = result.to_dict()
        self.assertTrue(payload["claims_acquisition_media_hash"])
        self.assertFalse(payload["recomputed"])

    def test_hash_in_last_segment_and_xhash(self) -> None:
        first = self.write("multi.E01", build_ewf1_segment([("header", b"h"), ("next", b"")]))
        self.write(
            "multi.E02",
            build_ewf1_segment([("xhash", xhash_data(MD5.hex(), SHA1.hex())), ("done", b"")], segment_number=2),
        )
        result = read_recorded_acquisition_hash(first)
        self.assertEqual((result.md5, result.sha1, result.sections), (MD5.hex(), SHA1.hex(), ["xhash"]))

    def test_no_hash_sections_gives_empty_values_with_reason(self) -> None:
        image = self.write("bare.E01", build_ewf1_segment([("header", b"h"), ("done", b"")]))
        with mock.patch.object(recorded_hash, "_read_libewf", return_value=RecordedHash()) as libewf:
            result = read_recorded_acquisition_hash(image)
        libewf.assert_called_once()  # second opinion when the walker finds nothing
        self.assertEqual((result.md5, result.sha1, result.source), ("", "", ""))
        self.assertIn("기록된 취득 해시가 없습니다", result.reason)

    def test_non_ewf_and_missing_file(self) -> None:
        raw = self.write("disk.E01", b"\x00" * 1024)
        self.assertIn("EWF(E01/Ex01) 서명이 없어", read_recorded_acquisition_hash(raw).reason)
        self.assertIn("읽지 못했습니다", read_recorded_acquisition_hash(self.root / "gone.E01").reason)

    def test_ex01_uses_libewf_and_reports_missing_pyewf(self) -> None:
        image = self.write("case.Ex01", EWF2_SIGNATURE + b"\x00" * 64)
        with mock.patch("rapidtriage.core.e01_native.pyewf", None):
            result = read_recorded_acquisition_hash(image)
        self.assertEqual((result.md5, result.sha1), ("", ""))
        self.assertIn("pyewf", result.reason)

        class FakeHandle:
            closed = False

            def get_hash_value(self, name: str) -> str | None:
                return {"MD5": MD5.hex().upper(), "SHA1": None}[name]

            def close(self) -> None:
                FakeHandle.closed = True

        with mock.patch("rapidtriage.core.e01_native.pyewf", object()), mock.patch(
            "rapidtriage.core.e01_native.open_ewf_segments", return_value=FakeHandle()
        ):
            result = read_recorded_acquisition_hash(image)
        self.assertEqual((result.md5, result.sha1, result.source), (MD5.hex(), "", "libewf"))
        self.assertTrue(FakeHandle.closed)

    def test_backward_chain_stops_and_section_cap_is_disclosed(self) -> None:
        data = bytearray(build_ewf1_segment([("header", b"h"), ("hash", hash_data()), ("done", b"")]))
        data[13 + 16 : 13 + 24] = struct.pack("<Q", 0)  # header section points back to offset 0
        looped = self.write("loop.E01", bytes(data))
        with mock.patch.object(recorded_hash, "_read_libewf", return_value=RecordedHash()):
            self.assertEqual(read_recorded_acquisition_hash(looped).md5, "")
        many = self.write("many.E01", build_ewf1_segment([("table", b"t")] * 5 + [("hash", hash_data()), ("done", b"")]))
        with mock.patch.object(recorded_hash, "MAX_SECTIONS_PER_SEGMENT", 3), mock.patch.object(
            recorded_hash, "_read_libewf", return_value=RecordedHash()
        ):
            result = read_recorded_acquisition_hash(many)
        self.assertTrue(result.sections_truncated)
        self.assertIn("섹션 상한 3개", result.reason)


class VerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.container = {"md5": "c" * 32, "sha1": "d" * 40, "sha256": "e" * 64}
        self.recorded = RecordedHash(md5="a" * 32, sha1="b" * 40, source="ewf1-sections")

    def test_recorded_match_is_computed_not_matched(self) -> None:
        status, message = evidence_hash_verdict("a" * 32, self.container, self.recorded)
        self.assertEqual(status, "computed")
        self.assertIn("입력값 = 이미지에 기록된 취득 해시(매체 재계산은 하지 않음)", message)
        self.assertEqual(evidence_hash_verdict("b" * 40, self.container, self.recorded)[0], "computed")

    def test_container_match_is_matched(self) -> None:
        status, message = evidence_hash_verdict("c" * 32, self.container, self.recorded)
        self.assertEqual(status, "matched")
        self.assertIn("컨테이너 파일 바이트", message)

    def test_mismatch_message_names_both_kinds(self) -> None:
        status, message = evidence_hash_verdict("f" * 32, self.container, self.recorded)
        self.assertEqual(status, "mismatched")
        self.assertIn("이미지에 기록된 취득 해시(MD5 " + "a" * 32 + ")와 다름", message)
        self.assertIn("컨테이너 파일 바이트 계산값(" + "c" * 32 + ")과도 다름", message)
        _, sha256_message = evidence_hash_verdict("f" * 64, self.container, self.recorded)
        self.assertIn("E01은 SHA256를 기록하지 않음", sha256_message)
        _, absent_message = evidence_hash_verdict("f" * 32, self.container, RecordedHash(reason="섹션 없음"))
        self.assertIn("대조 불가(이미지에 기록된 취득 해시 없음(섹션 없음))", absent_message)

    def test_non_ewf_messages_are_unchanged(self) -> None:
        self.assertEqual(
            evidence_hash_verdict("c" * 32, self.container, None),
            ("matched", f"파일 바이트 MD5 기대값 {'c' * 32} / 계산값 {'c' * 32}"),
        )
        self.assertEqual(evidence_hash_verdict("f" * 32, self.container, None)[0], "mismatched")
        self.assertEqual(
            evidence_hash_verdict("", self.container, None),
            ("computed", "기대 해시가 없어 계산값만 기록했습니다 (파일·컨테이너 바이트 기준)"),
        )


class HashWorkerTests(unittest.TestCase):
    """``CaseWorkspace._hash_worker`` end to end on a synthetic E01 with a stub intake."""

    def run_worker(self, image: Path, expected: str) -> dict[str, object]:
        calls: list[dict[str, object]] = []
        intake = SimpleNamespace(set_evidence_hash=lambda citation_id, **kw: calls.append({"id": citation_id, **kw}))
        out = image.parent.parent / "hash-out"  # results never inside the evidence folder
        fake = SimpleNamespace(intake=intake, hash_dir=lambda *_: out,
                               _lock=threading.Lock(), _hash_threads={})
        CaseWorkspace._hash_worker(fake, "case-1", "cit-1", image, expected)
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_worker_statuses_on_synthetic_e01(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence"
            evidence.mkdir()
            image = evidence / "img.E01"
            image.write_bytes(build_ewf1_segment([("header", b"h"), ("digest", digest_data()), ("done", b"")]))
            before = image.read_bytes()
            container_md5 = hashlib.md5(before).hexdigest()

            recorded = self.run_worker(image, MD5.hex())
            self.assertEqual(recorded["status"], "computed")
            self.assertIn("입력값 = 이미지에 기록된 취득 해시(매체 재계산은 하지 않음)", recorded["message"])
            digests = recorded["digests"]
            self.assertEqual(digests["md5"], container_md5)  # container columns stay container hashes
            self.assertEqual((digests["recorded_md5"], digests["recorded_sha1"]), (MD5.hex(), SHA1.hex()))

            self.assertEqual(self.run_worker(image, container_md5)["status"], "matched")
            mismatch = self.run_worker(image, "f" * 40)
            self.assertEqual(mismatch["status"], "mismatched")
            self.assertIn("이미지에 기록된 취득 해시(SHA1", mismatch["message"])
            self.assertIn("컨테이너 파일 바이트 계산값", mismatch["message"])
            self.assertEqual(self.run_worker(image, "")["status"], "computed")
            self.assertEqual(image.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in evidence.iterdir()), ["img.E01"])


if __name__ == "__main__":
    unittest.main()
