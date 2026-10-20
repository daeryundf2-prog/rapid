"""R6 S2 lane D (small items): eMule ``.part.met`` 0xE1 and ``p2p-parse-error`` reason labels.

Synthetic fixtures only. The 0xE1 layout follows eMule ``CPartFile::LoadPartFile`` (github.com/irwir/eMule
commit 88a8c8f2d782849642880ea616cdca60b01bd8c7, PartFile.cpp L797-848 and L1140-1151), cited in
``rapidtriage/artifacts/p2p.py``.
"""

from __future__ import annotations

import ast
import struct
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.p2p import REASON_KO, P2PArtifactsProvider, part_met_rows
from rapidtriage.core.triage_rules.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[1]
FILE_HASH = bytes(range(0x10, 0x20))
DATE = 1_700_000_000


def tag_string(tag_id: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<BB", 0x82, tag_id) + struct.pack("<H", len(raw)) + raw


def tag_u32(tag_id: int, value: int) -> bytes:
    return struct.pack("<BBI", 0x83, tag_id, value)


def tag_block() -> bytes:
    tags = [tag_string(0x01, "분할파일.avi"), tag_u32(0x02, 20_000_000), tag_u32(0x08, 1_234), tag_u32(0x05, DATE + 120)]
    return struct.pack("<I", len(tags)) + b"".join(tags)


def split_part_met(*, trailing_hashes: int = 0) -> bytes:
    """0xE1 split layout: version, one byte (skipped: eMule seeks back to offset 2), date u32,
    16-byte file hash, u32 tag count + tags, then optionally one byte + 16-byte part hashes."""
    body = b"\xe1" + b"\x01" + struct.pack("<I", DATE) + FILE_HASH + tag_block()
    if trailing_hashes:
        # eMule reads hashes while position + 16 < length, so one spare byte keeps the last one readable.
        body += b"\x00" + b"\xaa" * (16 * trailing_hashes) + b"\x00"
    return body


def split_048_part_met() -> bytes:
    """0xE1 with a zero u32 at offset 1 (eMule 0.48): MD4 hash set at offset 5, no date."""
    return b"\xe1" + struct.pack("<I", 0) + FILE_HASH + struct.pack("<H", 1) + b"\xbb" * 16 + tag_block()


class PartMetSplitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "Users" / "합성사용자" / "AppData" / "Local" / "eMule" / "Temp"
        self.dir.mkdir(parents=True)

    def write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_split_part_met_is_a_transfer(self) -> None:
        rows = part_met_rows(self.write("001.part.met", split_part_met(trailing_hashes=2)))
        self.assertEqual([row.artifact_type for row in rows], ["p2p-transfer"])
        details = rows[0].details
        self.assertEqual(details["file_name"], "분할파일.avi")
        self.assertEqual(details["file_size"], 20_000_000)
        self.assertEqual(details["ed2k_hash"], FILE_HASH.hex().upper())
        self.assertEqual(details["downloaded_bytes"], 1_234)
        self.assertEqual(details["file_date"], "2023-11-14T22:13:20Z")
        self.assertEqual((details["part_met_version"], details["part_met_layout"]), ("0xe1", "split"))
        self.assertEqual(details["part_hash_count"], 2)
        self.assertEqual(details["timestamp_kind"], "part-file-date")

    def test_split_part_met_without_trailing_hashes(self) -> None:
        details = part_met_rows(self.write("002.part.met", split_part_met()))[0].details
        self.assertEqual((details["part_met_layout"], details["part_hash_count"]), ("split", 0))

    def test_split_048_variant_reads_the_hash_set_and_has_no_date(self) -> None:
        rows = part_met_rows(self.write("003.part.met", split_048_part_met()))
        self.assertEqual(rows[0].artifact_type, "p2p-transfer")
        details = rows[0].details
        self.assertEqual((details["part_met_layout"], details["part_hash_count"]), ("split-0.48", 1))
        self.assertEqual(details["ed2k_hash"], FILE_HASH.hex().upper())
        self.assertIsNone(details["file_date"])
        self.assertIsNone(details["timestamp"])

    def test_truncated_split_part_met_is_an_error_row(self) -> None:
        data = split_part_met()
        for cut in (3, 10, len(data) - 3):
            with self.subTest(cut=cut):
                rows = part_met_rows(self.write(f"t{cut}.part.met", data[:cut]))
                self.assertEqual([row.artifact_type for row in rows], ["p2p-parse-error"])
                details = rows[0].details
                self.assertEqual((details["reason"], details["reason_code"]), ("part-met-unreadable", "part-met-unreadable"))
                self.assertEqual(details["reason_ko"], ".part.met 읽기 실패")

    def test_default_layout_unchanged_and_unknown_version_rejected(self) -> None:
        default = b"\xe0" + struct.pack("<I", DATE) + FILE_HASH + struct.pack("<H", 0) + tag_block()
        details = part_met_rows(self.write("004.part.met", default))[0].details
        self.assertEqual((details["part_met_version"], details["part_met_layout"]), ("0xe0", "default"))
        self.assertEqual(details["file_name"], "분할파일.avi")
        bad = part_met_rows(self.write("005.part.met", b"\xe3" + default[1:]))[0]
        self.assertEqual(bad.details["reason_code"], "part-met-unreadable")

    def test_provider_reads_split_part_met(self) -> None:
        self.write("006.part.met", split_part_met())
        rows = list(P2PArtifactsProvider().collect(Path(self.tmp.name)))
        self.assertEqual([row.artifact_type for row in rows], ["p2p-transfer"])
        self.assertEqual(rows[0].details["user"], "합성사용자")


class ReasonLabelTests(unittest.TestCase):
    @staticmethod
    def emitted_reason_codes() -> set[str]:
        """Every reason passed to ``_error`` in p2p.py; a non-literal reason fails the test."""
        tree = ast.parse((ROOT / "rapidtriage" / "artifacts" / "p2p.py").read_text(encoding="utf-8"))
        codes: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_error":
                argument = node.args[2]
                if not (isinstance(argument, ast.Constant) and isinstance(argument.value, str)):
                    raise AssertionError(f"_error reason must be a fixed code (line {node.lineno})")
                codes.add(argument.value)
        return codes

    def test_every_emitted_reason_has_a_korean_label(self) -> None:
        codes = self.emitted_reason_codes()
        self.assertGreaterEqual(len(codes), 13)
        family = next(item for item in load_catalog().families if item["id"] == "p2p-error")
        labels = next(column for column in family["core_columns"] if column["key"] == "reason")["value_labels"]
        self.assertEqual(codes - set(REASON_KO), set())
        self.assertEqual(codes - set(labels), set())
        for code in codes:
            self.assertEqual(labels[code], REASON_KO[code])
            self.assertTrue(any("가" <= char <= "힣" for char in labels[code]), code)
        aux = {column["key"] for column in family["aux_columns"]}
        self.assertIn("truncated_after_rows", aux)

    def test_truncated_known_met_splits_count_from_reason(self) -> None:
        entry = struct.pack("<I", DATE) + FILE_HASH + struct.pack("<H", 0) + tag_block()
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "eMule" / "config"
            config.mkdir(parents=True)
            (config / "known.met").write_bytes(b"\x0e" + struct.pack("<I", 3) + entry * 2 + b"\x00\x01")
            rows = list(P2PArtifactsProvider().collect(Path(tmp)))
        errors = [row.details for row in rows if row.artifact_type == "p2p-parse-error"]
        self.assertEqual(len([row for row in rows if row.artifact_type == "p2p-shared-file"]), 2)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["reason_code"], "known-met-truncated")
        self.assertEqual(errors[0]["reason"], "known-met-truncated")  # still startswith the pre-R6 prefix
        self.assertEqual(errors[0]["truncated_after_rows"], 2)
        self.assertEqual(errors[0]["reason_ko"], "known.met 중간에 잘림(앞 행은 유지)")


if __name__ == "__main__":
    unittest.main()
