"""R8 todo 9: parallel carving over the unallocated clusters of an NTFS volume ($Bitmap).

Every image is synthetic (``build_ntfs_image``: cluster 1024, 600 clusters, clusters 0-12 and
100-149 allocated, so the free runs are clusters 13-99 and 150-599).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import carving
from rapidtriage.core.coverage import coverage_entries, reset_coverage
from tests.test_r6_s2_unalloc_carve import build_ntfs_image

PART = 64 * 512
CLUSTER = 1024


def jpeg(tag: int) -> bytes:
    return b"\xff\xd8\xff\xe0" + b"JFIF\x00" + bytes([tag]) * 40 + b"\xff\xd9"


def at(cluster: int, within: int = 0) -> int:
    return PART + cluster * CLUSTER + within


class UnallocatedCarvingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        reset_coverage()

    def tearDown(self) -> None:
        self.temp.cleanup()
        reset_coverage()

    def carve(self, image: Path, **kwargs):
        kwargs.setdefault("workers", 1)
        return carving.run_unallocated_carving(image, self.base / "out", **kwargs)

    def test_only_unallocated_clusters_are_scanned(self) -> None:
        image = build_ntfs_image(
            self.base / "d.raw",
            payloads={at(20): jpeg(1), at(120): jpeg(2), at(300, 5): jpeg(3)},
        )
        payload = self.carve(image.path, extract=True)
        offsets = [entry["offset"] for entry in payload["entries"]]
        self.assertEqual(offsets, [at(20), at(300, 5)])  # cluster 120 is allocated: never read
        self.assertEqual(payload["entries"][0]["cluster"], 20)
        self.assertTrue(all(Path(entry["extracted_path"]).is_file() for entry in payload["entries"]))
        self.assertEqual(payload["unallocated"]["scanned_bytes"], (87 + 450) * CLUSTER)
        self.assertEqual(coverage_entries(), [])

    def test_header_across_chunk_boundary_found_once(self) -> None:
        # chunk 8192, overlap 4096: a JPEG straddling the boundary at run start + 8192
        image = build_ntfs_image(self.base / "d.raw", payloads={at(150, 8192 - 2): jpeg(7)})
        with mock.patch.object(carving, "SCAN_CHUNK_BYTES", 8192):
            payload = self.carve(image.path)
        self.assertEqual([entry["offset"] for entry in payload["entries"]], [at(150, 8192 - 2)])
        self.assertGreater(payload["unallocated"]["chunk_count"], 50)

    def test_candidate_runs_do_not_cross_into_allocated_clusters(self) -> None:
        # header-only format (no footer) at the end of run 13-99: carved size stops at the run end
        sqlite_like = b"PK\x03\x04\x14\x00\x00\x00\x00\x00" + b"\x01" * 64
        image = build_ntfs_image(self.base / "d.raw", payloads={at(98): sqlite_like, at(100): b"\xaa" * 2048})
        payload = self.carve(image.path, kinds=["zip"])
        entry = payload["entries"][0]
        self.assertLessEqual(entry["end_offset"], at(100))

    def test_workers_match_inline(self) -> None:
        image = build_ntfs_image(
            self.base / "d.raw", payloads={at(20): jpeg(1), at(200): jpeg(2), at(590): jpeg(3)}
        )
        inline = self.carve(image.path, workers=1)
        with mock.patch.object(carving, "SCAN_CHUNK_BYTES", 16384):
            parallel = carving.run_unallocated_carving(image.path, self.base / "out2", workers=3)
            single = carving.run_unallocated_carving(image.path, self.base / "out3", workers=1)

        def key(payload):
            return [(e["offset"], e["sha256"]) for e in payload["entries"]]

        self.assertEqual(key(inline), key(parallel))
        self.assertEqual(key(single), key(parallel))
        self.assertEqual(len(key(inline)), 3)

    def test_scan_cap_records_coverage(self) -> None:
        image = build_ntfs_image(self.base / "d.raw", payloads={at(15): jpeg(1), at(200): jpeg(2)})
        payload = self.carve(image.path, max_scan_bytes=20 * CLUSTER)
        self.assertEqual([entry["offset"] for entry in payload["entries"]], [at(15)])
        self.assertTrue(payload["unallocated"]["scan_truncated"])
        self.assertEqual(
            coverage_entries(),
            [
                {
                    "area": "carving",
                    "reason_code": "scan_bytes_cap",
                    "limit": 20 * CLUSTER,
                    "observed": (87 + 450) * CLUSTER,
                    "unit": "bytes",
                }
            ],
        )

    def test_candidate_cap_records_coverage(self) -> None:
        image = build_ntfs_image(self.base / "d.raw", payloads={at(20): jpeg(1), at(30): jpeg(2), at(40): jpeg(3)})
        payload = self.carve(image.path, max_candidates=2)
        self.assertEqual(len(payload["entries"]), 2)
        self.assertTrue(payload["summary"]["candidate_cap_reached"])
        entries = coverage_entries()
        self.assertEqual([(e["reason_code"], e["limit"], e["observed"]) for e in entries], [("candidate_cap", 2, 2)])  # the scan stops at the cap

    def test_recovery_lifts_caps(self) -> None:
        image = build_ntfs_image(self.base / "d.raw", payloads={at(20): jpeg(1)})
        recovery = self.carve(image.path, recovery=True)
        self.assertIsNone(recovery["safety"]["max_scan_bytes"])
        self.assertEqual(recovery["safety"]["max_candidates"], carving.RECOVERY_MAX_CANDIDATES)
        self.assertEqual(carving.RECOVERY_MAX_CANDIDATES, 100_000)
        default = self.carve(image.path)
        self.assertEqual(default["safety"]["max_scan_bytes"], carving.DEFAULT_MAX_SCAN_BYTES)
        self.assertEqual(default["safety"]["max_candidates"], carving.DEFAULT_MAX_CANDIDATES)

    def test_non_ntfs_image_is_a_carving_error(self) -> None:
        junk = self.base / "junk.raw"
        junk.write_bytes(b"\x00" * 4096)
        with self.assertRaises(carving.CarvingError):
            self.carve(junk)

    def test_bounded_carving_cap_records_coverage(self) -> None:
        source = self.base / "src.bin"
        source.write_bytes(jpeg(1) + b"\x00" * 200 + jpeg(2))
        carving.run_bounded_carving(source, self.base / "o1", max_scan_bytes=64)
        self.assertEqual([e["reason_code"] for e in coverage_entries()], ["scan_bytes_cap"])
        reset_coverage()
        carving.run_bounded_carving(source, self.base / "o2", max_candidates=1)
        self.assertEqual([e["reason_code"] for e in coverage_entries()], ["candidate_cap"])

    def test_plan_tasks_budget(self) -> None:
        tasks, truncated = carving.plan_unallocated_tasks(
            [(0, 4), (10, 4)], partition_offset=0, cluster_size=1024, scan_limit=None, chunk_bytes=2048
        )
        self.assertFalse(truncated)
        self.assertEqual([(t[2], t[3]) for t in tasks], [(0, 2048), (2048, 4096), (10240, 12288), (12288, 14336)])
        tasks, truncated = carving.plan_unallocated_tasks(
            [(0, 4), (10, 4)], partition_offset=0, cluster_size=1024, scan_limit=4096, chunk_bytes=2048
        )
        self.assertTrue(truncated)
        self.assertEqual(len(tasks), 2)
        tasks, truncated = carving.plan_unallocated_tasks(
            [(0, 4)], partition_offset=0, cluster_size=1024, scan_limit=4096, chunk_bytes=2048
        )
        self.assertFalse(truncated)


if __name__ == "__main__":
    unittest.main()
