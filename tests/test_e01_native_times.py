"""Native E01 extraction gives each recovered file its NTFS record's times (``_restore_record_times``).

Records are synthetic MFT records (``tests/ntfs_volume_gen.py``) parsed by dissect.ntfs, so the
times come through the same attribute API the extraction uses on an image.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core import e01_native
from tests.ntfs_volume_gen import (
    file_name_value,
    mft_record,
    resident_attr,
    standard_information,
)

# FILETIME (100 ns ticks since 1601) of 1970-01-01, and two distinct evidence-era time sets.
EPOCH_TICKS = 116_444_736_000_000_000
SI_TIMES = (132_500_000_000_000_000, 132_500_000_001_234_567, 132_500_000_002_345_678, 132_500_000_009_999_997)
FN_TIMES = (131_000_000_000_000_000, 131_000_000_007_654_321, 131_000_000_008_000_000, 131_000_000_009_000_003)
UNSET = (0, 0, 0, 0)
PRE_1970 = (EPOCH_TICKS - 10_000_000,) * 4


def ns(ticks: int) -> int:
    return (ticks - EPOCH_TICKS) * 100


def synthetic_record(si: tuple[int, ...] | None, fn: tuple[int, ...]):
    from dissect.ntfs.mft import MftRecord

    attrs = [] if si is None else [resident_attr(0x10, standard_information(si))]
    attrs += [
        resident_attr(0x30, file_name_value(5, "evidence.txt", 1, fn, size=4), instance=1, indexed=True),
        resident_attr(0x80, b"body", instance=2),
    ]
    return MftRecord.from_bytes(mft_record(40, attrs, flags=0x01))


@unittest.skipIf(e01_native.NTFS is None, "dissect.ntfs is not installed")
class RecoveredFileTimesTests(unittest.TestCase):
    def dump(self, record) -> tuple[os.stat_result, dict[str, int]]:
        stats = {"files": 0, "bytes": 0, "errors": 0}
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = e01_native._OutputNames(Path(tmp_dir), stats).root
            entry = root.child("evidence.txt", record, "evidence.txt")
            e01_native._dump_ntfs_record(record, entry, stats)
            self.assertEqual((stats["files"], stats["errors"]), (1, 0))
            status = os.stat(Path(tmp_dir) / "evidence.txt")
        return status, stats

    def test_copy_carries_the_record_times(self) -> None:
        # (case, $SI times or None, $FILE_NAME times, expected (atime, mtime) ticks or None = not restored)
        cases = (
            ("standard information", SI_TIMES, FN_TIMES, (SI_TIMES[3], SI_TIMES[1])),
            ("no standard information: file name", None, FN_TIMES, (FN_TIMES[3], FN_TIMES[1])),
            ("unset standard information: file name", UNSET, FN_TIMES, (FN_TIMES[3], FN_TIMES[1])),
            ("pre-1970 standard information: file name", PRE_1970, FN_TIMES, (FN_TIMES[3], FN_TIMES[1])),
            ("no usable time", PRE_1970, UNSET, None),
        )
        for case, si, fn, expected in cases:
            with self.subTest(case):
                status, stats = self.dump(synthetic_record(si, fn))
                if expected is None:
                    self.assertEqual(stats["time_restore_skips"], 1)
                    self.assertGreater(status.st_mtime_ns, ns(SI_TIMES[1]))  # left at extraction time
                else:
                    self.assertNotIn("time_restore_skips", stats)
                    self.assertEqual((status.st_atime_ns, status.st_mtime_ns), (ns(expected[0]), ns(expected[1])))


if __name__ == "__main__":
    unittest.main()
