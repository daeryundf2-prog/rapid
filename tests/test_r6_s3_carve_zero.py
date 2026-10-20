"""R6 S3: URL carving skips long zero runs without changing what it finds.

Wiped free space is mostly zeros (R6 S2 real image: 4 GiB of unallocated clusters at 37.5 MB/s).
``core.url_carving`` now hands only the non-zero segments of a window to the ASCII / UTF-16LE
regex scans. These tests pin that the candidates (URL, encoding, absolute offset, hit count) are
exactly those of the full-window scan, that UTF-16LE text (half zero bytes) is never skipped,
that skipped bytes are counted once per source byte, and -- as a relative micro benchmark only
-- that a zero-heavy window is scanned at least ~5x faster than by the plain regex path.
"""

from __future__ import annotations

import io
import random
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import analyses, create_app
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.ntfs_unalloc import ScanStats, iter_unallocated_chunks
from rapidtriage.core.url_carving import (
    ZERO_SPAN_MIN,
    UrlCarveState,
    _add,
    _patterns,
    _scan_window,
    nonzero_segments,
    scan_url_source,
    scan_url_windows,
)
from tests.test_r6_s2_unalloc_carve import build_ntfs_image
from tests.test_rapidtriage_analyses import write_run

TOKEN = "r6-s3-carve-zero-token"
MIB = 1024 * 1024


def reference_scan(window: bytes, base: int, cutoff: int, state: UrlCarveState, found: dict) -> None:
    """The scan before R6 S3: both regexes over the whole window."""
    for pattern, encoding in _patterns(True, True):
        for match in pattern.finditer(window):
            if match.start() >= cutoff:
                break
            text = match.group(0).decode("ascii" if encoding == "ascii" else "utf-16-le", errors="replace")
            _add(found, state, text, encoding, base + match.start())


def scan(window: bytes, cutoff: int | None = None, base: int = 0, *, reference: bool = False) -> tuple[list[tuple], int]:
    state = UrlCarveState(None, 10_000)
    found: dict = {}
    cut = len(window) if cutoff is None else cutoff
    if reference:
        reference_scan(window, base, cut, state, found)
    else:
        _scan_window(window, base, cut, _patterns(True, True), found, state)
    rows = sorted((entry["url"], entry["encoding"], entry["offset"], entry["hit_count"]) for entry in found.values())
    return rows, state.zero_bytes_skipped


def wide(text: str) -> bytes:
    return text.encode("utf-16-le")


class ZeroSegmentTests(unittest.TestCase):
    def assert_same_as_reference(self, window: bytes, cutoff: int | None = None, base: int = 0) -> list[tuple]:
        rows, _ = scan(window, cutoff, base)
        self.assertEqual(rows, scan(window, cutoff, base, reference=True)[0])
        return rows

    def test_all_zero_window_is_skipped_and_counted_to_cutoff(self) -> None:
        window = bytes(64 * 1024)
        self.assertEqual(nonzero_segments(window, len(window)), ([], len(window)))
        self.assertEqual(nonzero_segments(window, 1000), ([], 1000))  # the overlap is the next window's
        self.assertEqual(scan(window), ([], len(window)))
        # A short all-zero window is not a skippable span (nothing to gain, nothing lost).
        self.assertEqual(nonzero_segments(bytes(100), 100), ([(0, 100)], 0))

    def test_ascii_url_right_before_and_right_after_zero_span(self) -> None:
        before = b"https://before.example.com/end"
        after = b"https://after.example.org/start"
        zeros = bytes(3 * ZERO_SPAN_MIN + 5)
        window = b"x" * 100 + before + zeros + after + b" tail"
        rows = self.assert_same_as_reference(window, base=10_000)
        self.assertEqual(
            rows,
            [
                ("https://after.example.org/start", "ascii", 10_000 + 100 + len(before) + len(zeros), 1),
                ("https://before.example.com/end", "ascii", 10_000 + 100, 1),
            ],
        )
        _, skipped = scan(window)
        self.assertEqual(skipped, len(zeros) - 1)  # the run's first zero byte stays in the scan

    def test_utf16_url_ending_on_zero_span_and_starting_after_one(self) -> None:
        # A UTF-16LE match ends on its last 0x00 -- the first byte of the following zero run.
        first = wide("https://wide-before.example.com/a")
        second = wide("https://wide-after.example.net/b")
        zeros = bytes(2 * ZERO_SPAN_MIN)
        window = bytes(ZERO_SPAN_MIN + 3) + first + zeros + second + bytes(ZERO_SPAN_MIN)
        rows = self.assert_same_as_reference(window)
        self.assertEqual(
            rows,
            [
                ("https://wide-after.example.net/b", "utf-16le", ZERO_SPAN_MIN + 3 + len(first) + len(zeros), 1),
                ("https://wide-before.example.com/a", "utf-16le", ZERO_SPAN_MIN + 3, 1),
            ],
        )

    def test_utf16_text_with_zero_bytes_is_never_skipped(self) -> None:
        # Long UTF-16LE text is ~50% zero bytes and short zero gaps (< ZERO_SPAN_MIN) stay scanned.
        # The text's last 0x00 plus the gap make a zero run one byte short of ZERO_SPAN_MIN.
        text = wide("some words " * 2000) + bytes(ZERO_SPAN_MIN - 2) + wide("see https://inside.example.com/x ok")
        window = text + wide("more text " * 500)
        segments, skipped = nonzero_segments(window, len(window))
        self.assertEqual((segments, skipped), ([(0, len(window))], 0))
        rows = self.assert_same_as_reference(window)
        self.assertEqual([row[:2] for row in rows], [("https://inside.example.com/x", "utf-16le")])

    def test_cutoff_inside_and_after_zero_spans(self) -> None:
        url = b"https://cut.example.com/p"
        window = bytes(10_000) + url + bytes(10_000) + url + bytes(10_000)
        second = 10_000 + len(url) + 10_000
        for cutoff in (0, 5_000, 10_000, 10_001, second - 1, second, second + 1, len(window)):
            with self.subTest(cutoff=cutoff):
                rows = self.assert_same_as_reference(window, cutoff)
                segments, skipped = nonzero_segments(window, cutoff)
                covered = sum(max(0, min(end, cutoff) - start) for start, end in segments)
                self.assertEqual(skipped + covered, min(cutoff, len(window)))
                expected = [o for o in (10_000, second) if o < cutoff]
                self.assertEqual(sum(row[3] for row in rows), len(expected))

    def test_random_windows_match_reference(self) -> None:
        rng = random.Random(0x5EED)
        pieces = [
            b"https://a.example.com/x",
            b"http://10.0.0.1/p?q=1",
            wide("https://w.example.org/y"),
            wide("http://wide.example.kr/") + b"\x00",
            b"noise",
            wide("wide noise"),
            b"\xff\x00\xff",
        ]
        for case in range(150):
            parts: list[bytes] = []
            for _ in range(rng.randint(1, 12)):
                roll = rng.random()
                if roll < 0.35:
                    parts.append(bytes(rng.choice((1, 2, ZERO_SPAN_MIN - 1, ZERO_SPAN_MIN, ZERO_SPAN_MIN + 1, 3 * ZERO_SPAN_MIN + 7, 70_000))))
                elif roll < 0.8:
                    parts.append(rng.choice(pieces))
                else:
                    parts.append(rng.randbytes(rng.randint(1, 600)))
            window = b"".join(parts)
            cutoff = rng.randint(0, len(window))
            with self.subTest(case=case):
                self.assert_same_as_reference(window, cutoff, base=rng.randint(0, 1 << 40))


class ZeroWindowBoundaryTests(unittest.TestCase):
    def windows(self, data: bytes, chunk: int, overlap: int, stats: ScanStats):
        return iter_unallocated_chunks(io.BytesIO(data), 0, 512, [(0, len(data) // 512)], 1 << 40, stats=stats, chunk_bytes=chunk, overlap_bytes=overlap)

    def test_url_across_window_boundary_between_zero_spans_found_once(self) -> None:
        chunk, overlap = 64 * 1024, 8 * 1024
        url = b"https://straddle.example.com/across/the/edge"
        wurl = wide("https://wide-straddle.example.net/edge")
        data = bytearray(16 * chunk)
        start = 3 * chunk - 20  # the ASCII URL crosses the edge of window 3
        data[start : start + len(url)] = url
        wstart = 7 * chunk - len(wurl) + 2  # the UTF-16LE URL ends 2 bytes past the edge of window 7
        data[wstart : wstart + len(wurl)] = wurl
        after = 11 * chunk  # starts exactly where window 12's new bytes begin, after zeros
        right = url.replace(b"straddle", b"rightafter")
        data[after : after + len(right)] = right
        stats = ScanStats()
        state = UrlCarveState(None, 100)
        found = scan_url_windows(((w.data, w.image_offset, w.cutoff) for w in self.windows(bytes(data), chunk, overlap, stats)), state=state)
        rows = sorted((e["url"], e["encoding"], e["offset"], e["hit_count"]) for e in found)
        self.assertEqual(
            rows,
            [
                ("https://rightafter.example.com/across/the/edge", "ascii", after, 1),
                ("https://straddle.example.com/across/the/edge", "ascii", start, 1),
                ("https://wide-straddle.example.net/edge", "utf-16le", wstart, 1),
            ],
        )
        self.assertEqual(stats.bytes_read, len(data))
        # Every source byte is owned by one window: skipped + scanned-before-cutoff == bytes read.
        self.assertLessEqual(state.zero_bytes_skipped, len(data) - len(url) - len(right) - len(wurl))
        self.assertGreater(state.zero_bytes_skipped, len(data) - 8 * overlap)

    def test_all_zero_source_skipped_bytes_equal_bytes_read(self) -> None:
        data = bytes(10 * 64 * 1024 + 4096)
        stats = ScanStats()
        state = UrlCarveState(None, 100)
        found = scan_url_windows(((w.data, w.image_offset, w.cutoff) for w in self.windows(data, 64 * 1024, 8 * 1024, stats)), state=state)
        self.assertEqual(found, [])
        self.assertEqual(stats.bytes_read, len(data))
        self.assertEqual(state.zero_bytes_skipped, len(data))  # no overlap byte counted twice

    def test_file_source_budget_counts_read_bytes_and_zero_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "free.blkls"
            url = b"https://file.example.com/zero/edge"
            data = bytearray(20 * MIB)
            data[9 * MIB - 10 : 9 * MIB - 10 + len(url)] = url  # across the first 8 MiB window's overlap
            path.write_bytes(bytes(data))
            state = UrlCarveState(None, 100)
            found, scanned = scan_url_source(path, state=state, read_limit=16 * MIB)
        self.assertEqual(scanned, 16 * MIB)  # the budget counts bytes read, zeros included
        self.assertEqual([(e["url"], e["offset"]) for e in found], [(url.decode(), 9 * MIB - 10)])
        self.assertEqual(state.zero_bytes_skipped, 16 * MIB - len(url) - 1)


class ZeroSkipBenchmarkTests(unittest.TestCase):
    """Relative check only: the same zero-heavy window through the old regex path and the new one."""

    def test_zero_heavy_window_at_least_5x_faster(self) -> None:
        size = 32 * MIB
        data = bytearray(size)
        rng = random.Random(7)
        for index in range(64):  # a few URLs and some noise in an otherwise zero window
            offset = rng.randrange(0, size - 4096)
            data[offset : offset + 40] = b"https://bench%02d.example.com/zero/heavy" % index
        window = bytes(data)

        def best(reference: bool) -> float:
            times = []
            for _ in range(3):
                started = time.perf_counter()
                rows, _ = scan(window, reference=reference)
                times.append(time.perf_counter() - started)
            self.assertEqual(len(rows), 64)
            return min(times)

        before, after = best(True), best(False)
        print(f"\n[R6 S3] zero-heavy {size // MIB} MiB: regex path {size / MIB / before:,.0f} MiB/s, zero-skip path {size / MIB / after:,.0f} MiB/s ({before / after:,.1f}x)")
        self.assertGreaterEqual(before / after, 5.0)

    def test_dense_window_not_slower_than_twice(self) -> None:
        # Non-zero data pays only the zero-run search; generous margin for a loaded machine.
        rng = random.Random(11)
        window = rng.randbytes(16 * MIB)
        before = min(self._time(window, True) for _ in range(3))
        after = min(self._time(window, False) for _ in range(3))
        print(f"\n[R6 S3] random 16 MiB: regex path {16 / before:,.0f} MiB/s, zero-skip path {16 / after:,.0f} MiB/s")
        self.assertLess(after, before * 2.0)

    @staticmethod
    def _time(window: bytes, reference: bool) -> float:
        started = time.perf_counter()
        scan(window, reference=reference)
        return time.perf_counter() - started


class ZeroSkipSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.url = b"https://summary-zero.example.org/p"
        self.image = build_ntfs_image(
            self.evidence / "disk.dd",
            cluster_size=4096,
            total_clusters=600,
            allocated_ranges=((5, 13),),
            payloads={64 * 512 + 300 * 4096 + 9: self.url},
        )
        (self.evidence / "pagefile.sys").write_bytes(bytes(256 * 1024) + b"https://pagefile-zero.example.com/q " + bytes(256 * 1024))
        run_dir = write_run(self.base, "run", self.evidence)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def tearDown(self) -> None:
        self.client.close()
        self.temp.cleanup()

    def test_summary_reports_zero_bytes_skipped(self) -> None:
        created = self.client.post(
            f"/api/runs/{self.run_id}/analyses",
            json={"kind": "url-carve", "options": {"sources": ["pagefile", "image-unallocated"], "image_path": str(self.image.path)}},
        )
        self.assertEqual(created.status_code, 202, created.text)
        analysis_id = created.json()["analysis_id"]
        deadline = time.monotonic() + 60
        while True:
            state = self.client.get(f"/api/runs/{self.run_id}/analyses/{analysis_id}").json()
            if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                break
            self.assertLess(time.monotonic(), deadline, state)
            time.sleep(0.05)
        self.assertEqual(state["status"], "completed", state)
        summary = state["summary"]
        self.assertEqual(summary["kind_counts"], {"pagefile": 1, "image-unallocated": 1})
        free = (600 - 13) * 4096
        page = 512 * 1024 + len(b"https://pagefile-zero.example.com/q ")
        self.assertEqual(summary["scanned_byte_count"], page + free)  # read bytes, zeros included
        self.assertEqual(summary["image_unallocated_scanned_bytes"], free)
        image_zero = summary["image_unallocated_zero_bytes_skipped"]
        self.assertGreater(image_zero, free - 3 * 4096)
        self.assertLess(image_zero, free)
        self.assertGreater(summary["zero_bytes_skipped"], image_zero + 500 * 1024)
        self.assertLess(summary["zero_bytes_skipped"], summary["scanned_byte_count"])


if __name__ == "__main__":
    unittest.main()
