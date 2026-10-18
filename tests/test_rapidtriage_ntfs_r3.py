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
            times(modified="2023-01-01T00:00:00.1+00:00", mft="2023-01-01T00:00:00.1+00:00"), times(), reference=REFERENCE
        )
        self.assertIn("fn_after_si_modified", reasons)
        self.assertGreater(evidence["fn_after_si_modified_seconds"], 0)
        # A copy keeps an old $SI modified but a fresh $SI MFT-modified: not a mismatch.
        copied, _ = mismatch_reasons(times(modified="2023-01-01T00:00:00.1+00:00"), times(), reference=REFERENCE)
        self.assertEqual(copied, [])

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
        self.assertEqual(row["reasons"], ["si_created_before_fn", "zero_subsecond"])
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
        # R3 review C14: without $FILE_NAME only future_time can fire -- and it does.
        future = mismatch_row(
            {**{f"si_{k}": v for k, v in times(modified="2031-01-01T00:00:00.1+00:00", created="2019-01-01T00:00:00+00:00").items()}},
            reference=REFERENCE,
            mft_row_index=None,
        )
        assert future is not None
        self.assertEqual(future["reasons"], ["future_time"])
        self.assertEqual(future["future_fields"], ["si_modified_at"])


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


class LogFileReviewTests(unittest.TestCase):
    """R3 adversarial-review regressions C1, C6-C9, C14 ($LogFile) and C4/C5/C10 (mismatch)."""

    def parse(self, data: bytes, **kwargs: object) -> tuple[list[dict[str, object]], LogFileScan]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "LogFile.bin"
            path.write_bytes(data)
            scan = LogFileScan()
            rows = list(iter_logfile_rows(path, scan=scan, **kwargs))  # type: ignore[arg-type]
        return rows, scan

    def test_page_spanning_record_is_reassembled_and_next_page_records_survive(self) -> None:
        """C1: the tail at the start of page 3 is skipped; page 3's own record is not lost."""
        for at_start in (True, False):
            rows, scan = self.parse(fx.spanning_logfile(next_record_at_spanning_start=at_start))
            vcns = [row.get("target_vcn") for row in rows]
            self.assertEqual(vcns, [0, 0, 1, 2, 99, 0], at_start)
            big = rows[4]
            self.assertTrue(big["spans_pages"])
            self.assertTrue(big["spanning_reassembled"])
            self.assertEqual(big["file_name"], "spanner.exe")
            self.assertEqual(rows[5]["file_name"], "after.txt")
            self.assertEqual(scan.reassembled_records, 1)
            self.assertEqual(scan.unresolved_spanning_records, 0)
            self.assertEqual(scan.rejected_records, 0)

    def test_spanning_record_with_a_corrupt_next_page_is_flagged(self) -> None:
        """C1/C7: the continuation page fails its fixups: the record keeps what it has, counted unresolved."""
        rows, scan = self.parse(fx.spanning_logfile(broken_continuation=True))
        self.assertEqual([row.get("target_vcn") for row in rows], [0, 0, 1, 2, 99])
        big = rows[-1]
        self.assertFalse(big["spanning_reassembled"])
        self.assertTrue(big["redo_undo_data_partial"])
        self.assertEqual(big["file_name"], "spanner.exe")  # decoded from the part in page 2
        self.assertEqual(scan.unresolved_spanning_records, 1)
        self.assertEqual(scan.truncated_records, 1)
        self.assertEqual(scan.corrupt_pages, 1)

    def test_cluster_size_basis_and_index_root_vcn_target(self) -> None:
        """C6: cluster size from the boot sector (or the disclosed default); 0x11 targets an MFT record."""
        import struct

        from rapidtriage.core.ntfs_logfile import (
            MFT_TARGET_OPS,
            boot_sector_cluster_size,
        )

        self.assertIn(0x11, MFT_TARGET_OPS)
        boot = bytearray(512)
        boot[3:11] = b"NTFS    "
        struct.pack_into("<HB", boot, 0x0B, 512, 16)
        self.assertEqual(boot_sector_cluster_size(bytes(boot)), 8192)
        boot[0x0D] = 0xF4  # 2**12 sectors per cluster (large-cluster encoding)
        self.assertEqual(boot_sector_cluster_size(bytes(boot)), 2 * 1024 * 1024)
        self.assertIsNone(boot_sector_cluster_size(b"\x00" * 512))
        rows, scan = self.parse(fx.logfile(), cluster_size=8192)
        create = rows[0]
        self.assertEqual(create["target_mft_entry"], 128)  # vcn 16 x 8192 / 1024
        self.assertEqual((create["cluster_size"], create["cluster_size_basis"]), (8192, "boot-sector"))
        default_rows, default_scan = self.parse(fx.logfile())
        self.assertEqual(default_rows[0]["cluster_size_basis"], "assumed-default-4096")
        self.assertEqual(default_scan.summary()["logfile_cluster_size_basis"], "assumed-default-4096")

    def test_tail_copy_duplicates_are_not_emitted_twice(self) -> None:
        """C8: the same LSN in an early (tail-copy) page and later in the log is one row."""
        from rapidtriage.core.ntfs_logfile import TAIL_COPY_PAGES

        data = bytearray(fx.logfile(bad_fixup_page=False, empty_page=False))
        filler = b"\xff" * fx.PAGE * TAIL_COPY_PAGES
        later = fx.rcrd_page(0, fx.page_records()[0])
        rows, scan = self.parse(bytes(data) + filler + later)
        self.assertEqual(len(rows), 4)
        self.assertEqual(scan.duplicate_lsn_records, 1)

    def test_damaged_first_restart_page_falls_back_to_the_second(self) -> None:
        """C9: the first RSTR page is broken; the restart area of the second still names the layout."""
        data = bytearray(fx.logfile())
        data[0:4] = b"XXXX"
        rows, scan = self.parse(bytes(data))
        self.assertEqual(scan.restart_pages, 1)
        self.assertEqual(scan.seq_number_bits, fx.SEQ_BITS)
        self.assertEqual(len(rows), 4)

    def test_hostile_restart_values_are_contained(self) -> None:
        """C14: absurd restart-area values never crash the parse or move pages out of bounds."""
        import struct

        for field_offset, value in ((0x30 + 0x26, 0xFFFF), (0x30 + 0x26, 0x41), (0x30 + 0x10, 0xFFFFFFFF), (0x14, 0), (0x10, 3)):
            page = bytearray(fx.rstr_page(fx.lsn_for(4 * fx.PAGE)))
            struct.pack_into("<I" if field_offset in (0x10, 0x14, 0x30 + 0x10) else "<H", page, field_offset, value)
            data = bytes(page) + fx.logfile()[fx.PAGE :]
            rows, scan = self.parse(data)
            self.assertLessEqual(len(rows), 4, hex(field_offset))
            self.assertIn(scan.page_data_offset % 8, (0,))
            self.assertLess(scan.page_data_offset, scan.page_size)

    def test_filetime_out_of_range_reaches_future_time(self) -> None:
        """C5: a 0x7FFF... $SI stomp is a marker time, not "", so future_time and the generic rule see it."""
        from rapidtriage.artifacts.windows.filesystem import (
            FILETIME_OUT_OF_RANGE_ISO,
            filetime_to_iso,
            parse_standard_information,
        )

        self.assertEqual(filetime_to_iso(0x7FFFFFFFFFFFFFFF), FILETIME_OUT_OF_RANGE_ISO)
        self.assertEqual(filetime_to_iso(0), "")
        self.assertEqual(filetime_to_iso(133_000_000_000_000_007), "2022-06-18T04:26:40+00:00")
        parsed = parse_standard_information((0x7FFFFFFFFFFFFFFF).to_bytes(8, "little") * 4 + bytes(4))
        self.assertEqual(parsed["timestamps_out_of_range"], ["created_at", "modified_at", "mft_modified_at", "accessed_at"])
        reasons, evidence = mismatch_reasons(times(created=FILETIME_OUT_OF_RANGE_ISO), times(), reference=REFERENCE)
        self.assertIn("future_time", reasons)
        self.assertEqual(evidence["future_fields"], ["si_created_at"])

    def test_reference_time_is_the_acquisition_time(self) -> None:
        """C4: the image mtime is the future_time reference when it is not in the future."""
        import os

        from rapidtriage.api.app.analysis_kinds import mismatch_reference_time

        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "disk.E01"
            image.write_bytes(b"x")
            os.utime(image, (1_700_000_000, 1_700_000_000))
            moment, basis = mismatch_reference_time(image)
            self.assertEqual((int(moment.timestamp()), basis), (1_700_000_000, "image-mtime"))
            os.utime(image, (4_000_000_000, 4_000_000_000))
            self.assertEqual(mismatch_reference_time(image)[1], "analysis-start")
            self.assertEqual(mismatch_reference_time(Path(tmp) / "missing")[1], "analysis-start")

    def test_si_before_fn_threshold_comes_from_the_catalogue(self) -> None:
        """C10: one source of truth for the 60 s threshold (rule param)."""
        from rapidtriage.core.ntfs_timestamps import si_before_fn_threshold
        from rapidtriage.core.triage_rules import load_catalog

        expected = float(load_catalog().specs["ntfs.si_before_fn"].params["min_delta_seconds"])
        self.assertEqual(si_before_fn_threshold(), expected)
        close = times(created="2024-03-01T09:58:00.1+00:00")  # 120 s before $FN created
        self.assertEqual(mismatch_reasons(close, times(), reference=REFERENCE, si_before_fn_seconds=300)[0], [])
        self.assertEqual(mismatch_reasons(close, times(), reference=REFERENCE, si_before_fn_seconds=60)[0], ["si_created_before_fn"])


if __name__ == "__main__":
    unittest.main()
