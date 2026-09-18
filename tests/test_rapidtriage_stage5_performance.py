from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts.windows.filesystem import (
    build_native_mft_record,
    build_native_usn_record,
    collect_native_ntfs_artifacts,
)
from rapidtriage.core import hash_cache
from rapidtriage.core.hash_cache import (
    compute_hashes_cached,
    compute_hashes_fresh,
    reset_hash_cache,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _minimal_mft_blob(record_count: int) -> bytes:
    record = bytearray(1024)
    record[0:4] = b"FILE"
    record[0x14:0x16] = (0x38).to_bytes(2, "little")
    record[0x16:0x18] = (0x01).to_bytes(2, "little")
    record[0x18:0x1C] = (0x38).to_bytes(4, "little")
    record[0x1C:0x20] = (1024).to_bytes(4, "little")
    return bytes(record) * record_count


class _IterationCountingDict(dict):
    iterations = 0

    def __iter__(self):
        type(self).iterations += 1
        return super().__iter__()


class Stage5SourceHashCallCountTests(unittest.TestCase):
    def test_mft_records_emit_constant_source_hash_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "$MFT").write_bytes(_minimal_mft_blob(5))
            calls: list[str] = []
            real_file_hashes = __import__(
                "rapidtriage.artifacts.windows.filesystem", fromlist=["file_hashes"]
            ).file_hashes

            def counting(path):
                calls.append(str(path))
                return real_file_hashes(path)

            with patch("rapidtriage.artifacts.windows.filesystem.file_hashes", side_effect=counting):
                artifacts = list(collect_native_ntfs_artifacts(root))

        mft_rows = [a for a in artifacts if a.artifact_type == "mft-record"]
        self.assertEqual(len(mft_rows), 5)
        self.assertEqual(len(calls), 1, f"expected one hash call per source, got {len(calls)}")
        digest_values = {row.details["source_hashes"].get("sha256") for row in mft_rows}
        self.assertEqual(len(digest_values), 1)
        self.assertTrue(next(iter(digest_values)))

    def test_mft_builder_reuses_supplied_source_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "$MFT"
            path.write_bytes(b"data")
            with patch(
                "rapidtriage.artifacts.windows.filesystem.file_hashes",
                side_effect=AssertionError("file_hashes must not run when source_hashes supplied"),
            ):
                record = build_native_mft_record(
                    path,
                    {"record_number_candidate": 7},
                    0,
                    source_hashes={"sha256": "precomputed"},
                )
        self.assertEqual(record.details["source_hashes"], {"sha256": "precomputed"})

    def test_usn_builder_reuses_supplied_source_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "$UsnJrnl"
            path.write_bytes(b"data")
            with patch(
                "rapidtriage.artifacts.windows.filesystem.file_hashes",
                side_effect=AssertionError("file_hashes must not run when source_hashes supplied"),
            ):
                record = build_native_usn_record(
                    path,
                    {"file_reference_number": 3},
                    0,
                    source_hashes={"sha256": "precomputed-usn"},
                )
        self.assertEqual(record.details["source_hashes"], {"sha256": "precomputed-usn"})

    def test_mft_builder_still_hashes_when_no_source_hashes_given(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "$MFT"
            path.write_bytes(b"data")
            record = build_native_mft_record(path, {"record_number_candidate": 1}, 0)
        self.assertIn("sha256", record.details["source_hashes"])


class Stage5HashCacheIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_hash_cache()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()
        reset_hash_cache()

    def test_warm_lookup_does_not_iterate_cache_entries(self) -> None:
        file_a = self.root / "a.bin"
        file_b = self.root / "b.bin"
        file_a.write_bytes(b"aaaa")
        file_b.write_bytes(b"bbbb")
        compute_hashes_cached(file_a)
        compute_hashes_cached(file_b)

        counting = _IterationCountingDict(hash_cache._HASH_CACHE)
        with patch.object(hash_cache, "_HASH_CACHE", counting):
            _IterationCountingDict.iterations = 0
            warm = compute_hashes_cached(file_a)
            self.assertEqual(_IterationCountingDict.iterations, 0)
        self.assertEqual(warm["sha256"], compute_hashes_fresh(file_a)["sha256"])

    def test_stale_invalidation_scoped_to_same_path(self) -> None:
        file_a = self.root / "a.bin"
        file_b = self.root / "b.bin"
        file_a.write_bytes(b"aaaa")
        file_b.write_bytes(b"bbbb")
        compute_hashes_cached(file_a)
        compute_hashes_cached(file_b)
        file_b.write_bytes(b"bbbb-changed")

        counting = _IterationCountingDict(hash_cache._HASH_CACHE)
        with patch.object(hash_cache, "_HASH_CACHE", counting):
            _IterationCountingDict.iterations = 0
            fresh = compute_hashes_cached(file_b)
            self.assertEqual(_IterationCountingDict.iterations, 0)
        self.assertEqual(fresh["sha256"], compute_hashes_fresh(file_b)["sha256"])
        manifest = hash_cache.build_hash_cache_manifest()
        self.assertGreaterEqual(manifest["stats"]["invalidations"], 1)

    def test_snapshot_import_registers_path_index(self) -> None:
        file_a = self.root / "a.bin"
        file_a.write_bytes(b"aaaa")
        compute_hashes_cached(file_a)
        snapshot = self.root / "snapshot.json"
        hash_cache.export_hash_cache_snapshot(snapshot)

        reset_hash_cache()
        hash_cache.import_hash_cache_snapshot(snapshot)
        file_a.write_bytes(b"aaaa-changed")
        compute_hashes_cached(file_a)
        manifest = hash_cache.build_hash_cache_manifest()
        self.assertGreaterEqual(manifest["stats"]["invalidations"], 1)


class Stage5ColumnarPaginationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "node is required for JavaScript pagination checks")
    def test_columnar_pagination_propagates_next_and_previous_offsets(self) -> None:
        script = (
            'import { columnarPagination } from "./rapidtriage/web/static/app_utils.js";\n'
            "const first = columnarPagination({offset: 0, limit: 200, total_count: 450, returned_count: 200, has_more: true, next_offset: 200});\n"
            "const middle = columnarPagination({offset: 200, limit: 200, total_count: 450, returned_count: 200, has_more: true, next_offset: 400, previous_offset: 0});\n"
            "const last = columnarPagination({offset: 400, limit: 200, total_count: 450, returned_count: 50, has_more: false, next_offset: null, previous_offset: 200});\n"
            'if (first.previous_offset !== null || first.next_offset !== 200) throw new Error("first page offsets wrong");\n'
            'if (middle.previous_offset !== 0 || middle.next_offset !== 400) throw new Error("middle page offsets wrong");\n'
            'if (last.previous_offset !== 200 || last.next_offset !== null) throw new Error("last page offsets wrong");\n'
            "const derived = columnarPagination({offset: 400, limit: 200, total_count: 450, returned_count: 50, has_more: false, next_offset: null});\n"
            'if (derived.previous_offset !== 200) throw new Error("previous_offset fallback wrong");\n'
        )
        result = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
