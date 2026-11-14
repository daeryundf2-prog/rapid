"""R8 T-195: ``scripts/mft-coverage-truth.py`` truth table on a synthetic 6-record $MFT.

Every record is built here (fixup array, attributes, $FILE_NAME names); no real evidence.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "mft-coverage-truth.py"
RECORD_SIZE = 1024
USN = b"\x07\x00"


def _load_script():
    spec = importlib.util.spec_from_file_location("mft_coverage_truth", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


truth = _load_script()


def _align8(value: int) -> int:
    return (value + 7) & ~7


def resident(attribute_type: int, value: bytes, name: str = "") -> bytes:
    encoded = name.encode("utf-16le")
    value_offset = _align8(24 + len(encoded))
    length = _align8(value_offset + len(value))
    blob = bytearray(length)
    blob[0:4] = attribute_type.to_bytes(4, "little")
    blob[4:8] = length.to_bytes(4, "little")
    blob[9] = len(name)
    blob[10:12] = (24).to_bytes(2, "little")
    blob[16:20] = len(value).to_bytes(4, "little")
    blob[20:22] = value_offset.to_bytes(2, "little")
    blob[24 : 24 + len(encoded)] = encoded
    blob[value_offset : value_offset + len(value)] = value
    return bytes(blob)


def nonresident_data(size: int) -> bytes:
    runlist = bytes([0x11, 0x01, 0x10, 0x00])  # one cluster at LCN 16, then the terminator
    length = _align8(64 + len(runlist))
    blob = bytearray(length)
    blob[0:4] = (0x80).to_bytes(4, "little")
    blob[4:8] = length.to_bytes(4, "little")
    blob[8] = 1
    blob[10:12] = (64).to_bytes(2, "little")
    blob[24:32] = (0).to_bytes(8, "little")
    blob[32:34] = (64).to_bytes(2, "little")
    blob[40:48] = (4096).to_bytes(8, "little")
    blob[48:56] = size.to_bytes(8, "little")
    blob[56:64] = size.to_bytes(8, "little")
    blob[64 : 64 + len(runlist)] = runlist
    return bytes(blob)


def file_name(name: str, *, parent: int = 5, namespace: int = 1) -> bytes:
    encoded = name.encode("utf-16le")
    value = bytearray(66 + len(encoded))
    value[0:8] = parent.to_bytes(8, "little")
    value[64] = len(name)
    value[65] = namespace
    value[66:] = encoded
    return resident(0x30, bytes(value))


def record(*attributes: bytes, in_use: bool, directory: bool = False, links: int = 1, base: int = 0) -> bytes:
    blob = bytearray(RECORD_SIZE)
    blob[0:4] = b"FILE"
    blob[4:6] = (0x30).to_bytes(2, "little")  # update sequence array offset
    blob[6:8] = (3).to_bytes(2, "little")  # USN + one entry per 512-byte sector
    blob[0x10:0x12] = (1).to_bytes(2, "little")
    blob[0x12:0x14] = links.to_bytes(2, "little")
    blob[0x14:0x16] = (0x38).to_bytes(2, "little")
    blob[0x16:0x18] = ((0x01 if in_use else 0) | (0x02 if directory else 0)).to_bytes(2, "little")
    blob[0x1C:0x20] = RECORD_SIZE.to_bytes(4, "little")
    blob[0x20:0x26] = base.to_bytes(6, "little")
    body = b"".join(attributes) + b"\xff\xff\xff\xff"
    blob[0x38 : 0x38 + len(body)] = body
    blob[0x18:0x1C] = _align8(0x38 + len(body)).to_bytes(4, "little")
    blob[0x30:0x32] = USN
    for sector in (1, 2):  # move each sector's last two bytes into the array, stamp the USN
        trailer = sector * 512 - 2
        blob[0x30 + sector * 2 : 0x32 + sector * 2] = blob[trailer : trailer + 2]
        blob[trailer : trailer + 2] = USN
    return bytes(blob)


def six_record_mft() -> bytes:
    zone = resident(0x80, b"[ZoneTransfer]\r\nZoneId=3\r\n", name="Zone.Identifier")
    return b"".join(
        [
            # 0 in-use file, resident $DATA
            record(file_name("a.txt"), resident(0x80, b"hello"), in_use=True),
            # 1 in-use file, non-resident $DATA + Zone.Identifier ADS, two names (+ a DOS alias)
            record(
                file_name("report-2024.docx"),
                file_name("REPORT~1.DOC", namespace=2),
                file_name("copy.docx", parent=40),
                nonresident_data(9000),
                zone,
                in_use=True,
                links=2,
            ),
            # 2 deleted file, non-resident $DATA; long name + DOS alias = link count 2, not a hard link
            record(
                file_name("gone-for-good.bin"),
                file_name("GONE-F~1.BIN", namespace=2),
                nonresident_data(5000),
                in_use=False,
                links=2,
            ),
            # 3 deleted directory
            record(file_name("old-dir"), in_use=False, directory=True),
            # 4 in-use directory
            record(file_name("Users"), in_use=True, directory=True),
            # 5 extension record of record 1 (not a file of its own)
            record(resident(0x80, b"x", name="extra"), in_use=True, base=1),
        ]
    )


class MftCoverageTruthTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.mft = self.root / "$MFT"
        self.mft.write_bytes(six_record_mft())

    def test_header_axis(self) -> None:
        report = truth.build_report(self.mft)
        self.assertEqual(
            report["header"],
            {
                "records": 6,
                "invalid": 0,
                "extension_records": 1,
                "in_use_files": 2,
                "in_use_dirs": 1,
                "deleted_files": 1,
                "deleted_dirs": 1,
            },
        )
        self.assertEqual(report["basis"], "inferred")
        self.assertIsNone(report["extraction_table"])

    def test_detail_resident_ads_hard_links(self) -> None:
        detail = truth.build_report(self.mft)["detail"]
        files = detail["in_use_files"]
        self.assertEqual(files["records"], 2)
        self.assertEqual((files["data_resident"], files["data_nonresident"]), (1, 1))
        self.assertEqual((files["ads_streams"], files["records_with_ads"], files["zone_identifier_streams"]), (1, 1, 1))
        self.assertEqual((files["hard_link_records"], files["link_count_total"]), (1, 3))
        self.assertEqual(files["non_dos_names"], 3)  # the DOS alias is not a name of its own
        self.assertEqual(files["fixup_not_applied"], 0)
        deleted = detail["deleted_files"]
        self.assertEqual((deleted["records"], deleted["data_nonresident"], deleted["ads_streams"]), (1, 1, 0))
        self.assertEqual((deleted["hard_link_records"], deleted["link_count_total"]), (0, 2))
        self.assertEqual(detail["deleted_dirs"]["data_absent"], 1)
        self.assertEqual(detail["in_use_dirs"]["records"], 1)
        # The extension record's named stream is not counted as a file's ADS.
        self.assertEqual(sum(bucket["ads_streams"] for bucket in detail.values()), 1)

    def test_extraction_table_from_stage_status(self) -> None:
        status = self.root / "rapidtriage-e01-stage-status.json"
        status.write_text(
            json.dumps(
                {
                    "command_history": [
                        {"stage": "native-filesystem-recovery", "files": 4, "deleted_files": 1, "truncated": 0, "errors": 0}
                    ]
                }
            ),
            encoding="utf-8",
        )
        report = truth.build_report(self.mft, e01_json=status)
        rows = {row["axis"]: row for row in report["extraction_table"]}
        self.assertEqual((rows["allocated_files"]["mft"], rows["allocated_files"]["extracted"]), (2, 3))
        self.assertEqual(rows["allocated_files"]["mft_non_dos_names"], 3)
        self.assertEqual((rows["deleted_files"]["extracted"], rows["deleted_files"]["not_written"]), (1, 0))
        self.assertIsNone(rows["deleted_dirs"]["extracted"])
        self.assertTrue(report["allocated_walk_finished_inferred"])

    def test_e01_json_shape_and_cli(self) -> None:
        e01 = self.root / "rapidtriage-e01.json"
        stats = {"files": 3, "deleted_files": 0, "truncated": 5, "file_limit": 3}
        e01.write_text(json.dumps({"recovered_root_manifest": {"native_extraction_stats": stats}}), encoding="utf-8")
        output = self.root / "out" / "truth.json"
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = truth.main(["--mft", str(self.mft), "--e01-json", str(e01), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertIn("in-use files 2", printed.getvalue())
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], "mft-coverage-truth-v1")
        self.assertEqual(report["extraction_stats"]["truncated"], 5)
        self.assertFalse(report["allocated_walk_finished_inferred"])  # cap reached, nothing swept
        rows = {row["axis"]: row for row in report["extraction_table"]}
        self.assertEqual(rows["deleted_files"]["reported_truncated"], 5)

    def test_header_only_and_max_records(self) -> None:
        self.assertIsNone(truth.build_report(self.mft, header_only=True)["detail"])
        partial = truth.build_report(self.mft, max_records=2)["detail"]
        self.assertEqual(sum(bucket["records"] for bucket in partial.values()), 2)

    def test_invalid_slot_is_not_a_record(self) -> None:
        self.mft.write_bytes(six_record_mft() + bytes(RECORD_SIZE) + b"BAAD" + bytes(RECORD_SIZE - 4))
        report = truth.build_report(self.mft)
        self.assertEqual((report["header"]["records"], report["header"]["invalid"]), (8, 2))
        self.assertEqual(sum(bucket["records"] for bucket in report["detail"].values()), 5)


if __name__ == "__main__":
    unittest.main()
