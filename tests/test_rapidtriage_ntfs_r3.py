"""R3 NTFS depth (plan r3-os-depth §3.3, Q-R3-5): $SI/$FN timestamp mismatch and the bounded $LogFile parser."""

from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.ntfs_logfile import (
    FixupError,
    LogFileScan,
    apply_fixups,
    file_name_candidates,
    iter_logfile_rows,
    operation_label,
)
from rapidtriage.core.ntfs_timestamps import (
    REASON_CODES,
    mismatch_reasons,
    mismatch_row,
)
from tests import ntfs_r3_fixtures as fx

REFERENCE = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
BASE = "2024-03-01T10:00:00.123456+00:00"


def times(created: str = BASE, modified: str = BASE, accessed: str = BASE, mft: str = BASE) -> dict[str, str]:
    return {"created_at": created, "modified_at": modified, "accessed_at": accessed, "mft_modified_at": mft}


class TimestampMismatchTests(unittest.TestCase):
    def test_consistent_record_has_no_reason(self) -> None:
        reasons, _ = mismatch_reasons(times(), times(), reference=REFERENCE)
        self.assertEqual(reasons, [])

    def test_si_created_before_fn(self) -> None:
        reasons, evidence = mismatch_reasons(
            times(created="2020-01-01T00:00:00.5+00:00"), times(), reference=REFERENCE
        )
        self.assertEqual(reasons, ["si_created_before_fn"])
        self.assertGreater(evidence["si_fn_created_delta_seconds"], 60)

    def test_small_si_fn_delta_is_tolerated(self) -> None:
        reasons, _ = mismatch_reasons(times(created="2024-03-01T09:59:30.1+00:00"), times(), reference=REFERENCE)
        self.assertEqual(reasons, [])

    def test_zero_subsecond(self) -> None:
        reasons, _ = mismatch_reasons(
            times(created="2024-03-01T10:00:00+00:00", modified="2024-03-01T10:00:00+00:00"),
            times(created="2024-03-01T10:00:00.250000+00:00"),
            reference=REFERENCE,
        )
        self.assertEqual(reasons, ["zero_subsecond"])

    def test_fn_after_si_modified(self) -> None:
        reasons, evidence = mismatch_reasons(
            times(modified="2023-01-01T00:00:00.1+00:00"), times(), reference=REFERENCE
        )
        self.assertIn("fn_after_si_modified", reasons)
        self.assertGreater(evidence["fn_after_si_modified_seconds"], 0)

    def test_future_time(self) -> None:
        reasons, evidence = mismatch_reasons(times(accessed="2031-05-05T00:00:00.1+00:00"), times(), reference=REFERENCE)
        self.assertEqual(reasons, ["future_time"])
        self.assertEqual(evidence["future_fields"], ["si_accessed_at"])

    def test_row_carries_eight_times_reasons_and_cross_links(self) -> None:
        details = {
            "entry_number": 70,
            "sequence_number": 3,
            "name": "stomped.exe",
            "path": "\\Users\\stomped.exe",
            "in_use": True,
            **{f"si_{key}": value for key, value in times(created="2019-01-01T00:00:00+00:00", modified="2019-01-01T00:00:00+00:00").items()},
            **{f"fn_{key}": value for key, value in times().items()},
        }
        row = mismatch_row(details, reference=REFERENCE, mft_row_index=12)
        assert row is not None
        self.assertEqual(row["source"], "timestamp-mismatch")
        # Backdating $SI modified as well leaves $FN later than it.
        self.assertEqual(row["reasons"], ["si_created_before_fn", "zero_subsecond", "fn_after_si_modified"])
        self.assertEqual(row["related_rules"], ["ntfs.si_before_fn", "ntfs.zero_subsecond"])
        self.assertEqual(row["mft_row_index"], 12)
        for prefix in ("si", "fn"):
            for name in ("created_at", "modified_at", "accessed_at", "mft_modified_at"):
                self.assertTrue(row[f"{prefix}_{name}"], f"{prefix}_{name}")
        self.assertIn("$SI 생성이 $FN 생성보다 앞섬", row["reason"])
        self.assertEqual(set(REASON_CODES), {"si_created_before_fn", "zero_subsecond", "fn_after_si_modified", "future_time"})

    def test_missing_file_name_only_checks_future(self) -> None:
        row = mismatch_row({**{f"si_{k}": v for k, v in times().items()}}, reference=REFERENCE, mft_row_index=None)
        self.assertIsNone(row)


class LogFileTests(unittest.TestCase):
    def parse(self, data: bytes) -> tuple[list[dict[str, object]], LogFileScan]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "LogFile.bin"
            path.write_bytes(data)
            scan = LogFileScan()
            rows = list(iter_logfile_rows(path, scan=scan))
        return rows, scan

    def test_three_rcrd_pages_parse_and_bad_fixup_page_is_isolated(self) -> None:
        rows, scan = self.parse(fx.logfile())
        self.assertEqual(scan.restart_pages, 2)
        self.assertEqual(scan.record_pages, 3)
        self.assertEqual(scan.corrupt_pages, 1)
        self.assertIn("픽스업", scan.corrupt_samples[0]["reason"])
        self.assertEqual(scan.corrupt_samples[0]["page_offset"], 6 * fx.PAGE)
        self.assertEqual(scan.empty_pages, 1)
        self.assertEqual(scan.seq_number_bits, fx.SEQ_BITS)
        self.assertEqual(len(rows), 4)
        create, index, delete, forget = rows
        self.assertEqual(create["redo_op_name"], "InitializeFileRecordSegment")
        self.assertEqual(create["target_mft_entry"], 64)
        self.assertEqual(create["file_name"], "secret.docx")
        self.assertEqual(create["time_estimate"], "2024-05-01T10:00:00+00:00")
        self.assertTrue(create["lsn_page_match"])
        self.assertEqual(create["record_offset"], 2 * fx.PAGE + fx.DATA_OFFSET)
        self.assertEqual(index["redo_op_name"], "AddIndexEntryAllocation")
        self.assertEqual(index["undo_op_name"], "DeleteIndexEntryAllocation")
        self.assertNotIn("target_mft_entry", index, "index buffer targets are not MFT records")
        self.assertEqual(index["file_name_candidates"], ["secret.docx"])
        self.assertEqual(delete["target_mft_entry"], 65)  # vcn 16 ×4096 + 2×512 → record 65
        self.assertEqual(delete["file_name"], "wiped.log")
        self.assertEqual(forget["redo_op_label"], "트랜잭션 잊기(ForgetTransaction)")
        self.assertEqual(forget["previous_lsn"], delete["lsn"])
        for row in rows:
            self.assertEqual(row["source"], "logfile-transaction")
            self.assertEqual(row["recovery_method"], "parsed")
            self.assertFalse(row["spans_pages"])

    def test_row_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "LogFile.bin"
            path.write_bytes(fx.logfile())
            scan = LogFileScan()
            rows = list(iter_logfile_rows(path, scan=scan, max_rows=2))
        self.assertEqual(len(rows), 2)
        self.assertTrue(scan.row_cap_reached)

    def test_garbage_is_isolated_without_rows(self) -> None:
        rows, scan = self.parse(b"\x13" * (8 * fx.PAGE))
        self.assertEqual(rows, [])
        self.assertEqual(scan.restart_pages, 0)
        self.assertEqual(scan.corrupt_pages, 8)

    def test_record_crossing_the_page_end_is_flagged(self) -> None:
        records = fx.page_records()[0]
        page = bytearray(fx.rcrd_page(2 * fx.PAGE, records))
        # Claim far more client data than the page holds (fixups untouched: header area only).
        page[fx.DATA_OFFSET + 0x18 : fx.DATA_OFFSET + 0x1C] = (6000).to_bytes(4, "little")
        data = fx.rstr_page(1) + fx.rstr_page(1) + bytes(page)
        rows, scan = self.parse(data)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["spans_pages"])
        self.assertEqual(scan.truncated_records, 1)

    def test_fixups(self) -> None:
        page = fx.rcrd_page(0, fx.page_records()[0])
        self.assertEqual(apply_fixups(page)[510:512], b"\x00\x00")
        broken = bytearray(page)
        broken[2046:2048] = b"\x00\x07"
        with self.assertRaises(FixupError):
            apply_fixups(bytes(broken))

    def test_file_name_candidates_reject_noise(self) -> None:
        self.assertEqual(file_name_candidates(b"\x41" * 400), [])
        good = fx.file_name_value("a.txt", parent=5, created="2024-01-01T00:00:00Z")
        self.assertEqual(file_name_candidates(b"\x00" * 6 + good)[0]["name"], "a.txt")

    def test_unknown_operation_label(self) -> None:
        self.assertEqual(operation_label(0x7F), "알 수 없음(0x7F)")


if __name__ == "__main__":
    unittest.main()
