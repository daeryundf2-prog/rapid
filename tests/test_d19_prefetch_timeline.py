"""D19-8: compressed Prefetch v30/v31 run slots keep their 100 ns ticks on the timeline
(synthetic fixtures only)."""

from __future__ import annotations

import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts.windows.prefetch import WindowsPrefetchProvider
from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    extract_artifact_events,
)
from tests.test_r3_prefetch_decoding import build_pf
from tests.xpress_huffman_encoder import mam

PREFETCH_BASE_TICKS = 133485408000000000  # 2024-01-01T00:00:00Z


def compressed_prefetch_timeline(version: int, first: int, second: int) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Compressed (MAM) Prefetch whose two run slots differ below one microsecond."""
    clock = datetime(2024, 1, 1, tzinfo=timezone.utc)
    directory = r"\VOLUME{00000000-0000-0000-0000-000000000001}"
    inner = bytearray(
        build_pf(
            version=version,
            executable="SAMPLE.EXE",
            paths=[directory + r"\Fixtures\SAMPLE.EXE"],
            run_times=[clock, clock],
            run_count=2,
            volumes=[(directory, 0x12345678, clock, [])],
        )
    )
    struct.pack_into("<QQ", inner, 0x80, PREFETCH_BASE_TICKS + first, PREFETCH_BASE_TICKS + second)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        folder = root / "Windows" / "Prefetch"
        folder.mkdir(parents=True)
        (folder / "SAMPLE.EXE-1A2B3C4D.pf").write_bytes(mam(bytes(inner)))
        source = next(r for r in WindowsPrefetchProvider().collect(root) if r.artifact_type == "prefetch-file")
        timeline = TimelineBuilder(TimelineStats())
        timeline.extend(
            extract_artifact_events({"kind": "prefetch", "artifacts": [source.to_dict()]}, root / "collected.json")
        )
        return source.details, timeline.events()


class CompressedPrefetchRunTimeTests(unittest.TestCase):
    """v30/v31 compressed run slots 1 and 7 ticks apart stay two timeline rows."""

    def test_sub_microsecond_runs_are_two_rows_in_v30_and_v31(self) -> None:
        for version in (30, 31):
            for first, second in ((7, 1), (1, 7)):
                with self.subTest(version=version, order=(first, second)):
                    details, events = compressed_prefetch_timeline(version, first, second)
                    self.assertEqual(details["prefetch_decompression"]["status"], "decompressed")
                    self.assertEqual(
                        details["last_run_filetimes"], [PREFETCH_BASE_TICKS + first, PREFETCH_BASE_TICKS + second]
                    )
                    self.assertEqual(
                        details["last_run_times_100ns"],
                        [f"2024-01-01T00:00:00.000000{first}Z", f"2024-01-01T00:00:00.000000{second}Z"],
                    )
                    self.assertEqual(
                        sorted(event["timestamp"] for event in events),
                        ["2024-01-01T00:00:00.0000001+00:00", "2024-01-01T00:00:00.0000007+00:00"],
                    )

    def test_same_instant_labels_still_merge(self) -> None:
        _details, events = compressed_prefetch_timeline(30, 7, 7)
        self.assertEqual([event["timestamp"] for event in events], ["2024-01-01T00:00:00.0000007+00:00"])


if __name__ == "__main__":
    unittest.main()
