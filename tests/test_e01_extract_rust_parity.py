"""Python vs Rust engine parity for the native E01 -> NTFS extraction (``extract_e01_native``).

Every image is synthetic (``tests/ntfs_volume_gen.py``). Both engines must produce the same
recovered tree (relative paths, sizes, SHA-256, directories), the same stats (files, bytes,
errors, alias skips, truncation and deleted-record counters under the #44 caps), and the same
allocated/deleted split (``_deleted_mft/``). Alternate data streams are not part of the
recovered tree in either engine; the tests pin that too.

Set ``RAPIDTRIAGE_REQUIRE_RUST_E01_EXTRACT=1`` (CI) to fail instead of skip when the extension
(``python scripts/build-e01-extract-native.py``) or ``dissect.ntfs`` is missing.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from rapidtriage.core import e01_extract_engine, e01_native
from tests.ntfs_volume_gen import build_disk_image

REQUIRE = os.environ.get("RAPIDTRIAGE_REQUIRE_RUST_E01_EXTRACT") == "1"


def _missing() -> str:
    if e01_native.NTFS is None:
        return "dissect.ntfs is not installed"
    module, problem = e01_extract_engine.load_extract_extension()
    return "" if module is not None else f"rapid_extract_native unavailable: {problem}"


def tree_manifest(root: Path) -> dict[str, Any]:
    files: dict[str, tuple[int, str]] = {}
    dirs: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_file():
            files[rel] = (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            dirs.append(rel)
    return {"files": files, "dirs": dirs}


class EngineParityBase(unittest.TestCase):
    image: Path
    temp: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.image = Path(cls.temp.name) / "disk.raw"
        build_disk_image(cls.image, bulk_files=240, bulk_dirs=4, seed=7)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def run_engine(
        self,
        engine: str,
        *,
        limit: int | None = None,
        include_deleted: bool = True,
        segments: list[Path] | None = None,
        extra_env: dict[str, str] | None = None,
        blockers: tuple[str, ...] = (),
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, int]]]:
        out = Path(tempfile.mkdtemp(dir=self.temp.name))
        for blocker in blockers:
            (out / "tree" / blocker).mkdir(parents=True)
        env = {e01_extract_engine.E01_EXTRACT_ENGINE_ENV: engine, **(extra_env or {})}
        if limit is not None:
            env[e01_native.NATIVE_MAX_EXTRACT_FILES_ENV] = str(limit)
        progress: list[dict[str, int]] = []
        with patch.dict(os.environ, env):
            if segments is None:
                with patch.object(e01_native, "open_ewf_segments", lambda segs: e01_native.RawMediaHandle(segs[0])):
                    result = e01_native.extract_e01_native(
                        self.image, [self.image], out / "tree", include_deleted=include_deleted,
                        on_progress=lambda stats: progress.append(dict(stats)),
                    )
            else:
                result = e01_native.extract_e01_native(
                    segments[0], segments, out / "tree", include_deleted=include_deleted,
                    on_progress=lambda stats: progress.append(dict(stats)),
                )
        manifest = tree_manifest(out / "tree")
        shutil.rmtree(out, ignore_errors=True)
        return result, manifest, progress


class RustEngineParityTests(EngineParityBase):
    def setUp(self) -> None:
        missing = _missing()
        if missing:
            if REQUIRE:
                self.fail(missing)
            self.skipTest(missing)

    def assert_same(self, python: tuple, rust: tuple, reader: tuple[str, ...] = ("rust-ewf", "raw-file")) -> None:
        py_result, py_tree, _ = python
        rs_result, rs_tree, rs_progress = rust
        engine = rs_result["extract_engine"]
        self.assertEqual((engine["requested"], engine["active"], engine["notice_ko"]), ("rust", "rust", ""))
        self.assertIn(engine["media_reader"], reader)
        if engine["media_reader"] != "python-handle":
            self.assertEqual(engine["python_reads"], 0)
        self.assertNotIn("extract_engine", py_result)
        self.assertEqual(sorted(rs_tree["files"]), sorted(py_tree["files"]))
        self.assertEqual(rs_tree["files"], py_tree["files"])
        self.assertEqual(rs_tree["dirs"], py_tree["dirs"])
        self.assertEqual(rs_result["stats"], py_result["stats"])
        self.assertEqual(rs_progress[-1], rs_result["stats"])

    def test_full_extraction_is_identical(self) -> None:
        python = self.run_engine("python")
        rust = self.run_engine("rust")
        self.assert_same(python, rust)
        files, stats = python[1]["files"], python[0]["stats"]
        docs = "Users/alice/Documents/"
        for name in ("compressed.log", "attrlist.bin", "sparse.bin", "notes.txt", "보고서.hwp", "weird_name_.txt"):
            self.assertIn(docs + name, files)
        self.assertEqual(files[docs + "notes.txt"][0], len(b"resident body " * 10))
        self.assertEqual(files[docs + "empty.txt"][0], 0)
        self.assertEqual(files[docs + "truncated.bin"][0], 0)
        self.assertNotIn("Users/bob/Documents/hardlink-b.txt", files)
        self.assertFalse(any("Zone.Identifier" in rel or ":" in rel for rel in files))
        deleted = [rel for rel in files if rel.startswith("_deleted_mft/")]
        self.assertTrue(any(rel.endswith("-deleted-report.pdf") for rel in deleted))
        self.assertTrue(any("-record-" in rel for rel in deleted))
        self.assertEqual(len(deleted), stats["deleted_files"])
        self.assertGreater(stats["alias_skips"], 0)
        self.assertGreater(stats["deleted_read_errors"], 0)
        self.assertGreater(stats["errors"], stats["deleted_read_errors"])

    def test_caps_and_truncation_counters_are_identical(self) -> None:
        for limit in (5, 40, 300):
            python = self.run_engine("python", limit=limit)
            self.assertGreater(python[0]["stats"]["truncated"], 0)
            for threads in ("1", "4"):
                with self.subTest(limit=limit, threads=threads):
                    rust = self.run_engine("rust", limit=limit, extra_env={e01_extract_engine.E01_EXTRACT_THREADS_ENV: threads})
                    self.assert_same(python, rust)
        self.assertEqual(python[0]["stats"]["file_limit"], 300)

    def test_without_deleted_sweep_is_identical(self) -> None:
        python = self.run_engine("python", include_deleted=False)
        rust = self.run_engine("rust", include_deleted=False)
        self.assert_same(python, rust)
        self.assertEqual(python[0]["stats"]["deleted_files"], 0)

    def acquire(self, name: str, *options: str) -> list[Path]:
        ewfacquire = shutil.which("ewfacquire")
        if ewfacquire is None or e01_native.pyewf is None:
            self.skipTest("ewfacquire or pyewf unavailable")
        target = Path(self.temp.name) / name / "disk"
        target.parent.mkdir(exist_ok=True)
        subprocess.run(
            [ewfacquire, "-u", "-q", "-t", str(target), "-f", "encase6", *options,
             "-C", "synthetic", "-D", "synthetic", "-e", "synthetic", "-E", "1", "-N", "synthetic", str(self.image)],
            check=True, capture_output=True,
        )
        return sorted(target.parent.glob("disk.E*"))

    def test_e01_segment_set_is_identical(self) -> None:
        segments = self.acquire("e01", "-c", "deflate:fast", "-S", "4MiB")
        self.assertGreater(len(segments), 1)
        python = self.run_engine("python", segments=segments)
        rust = self.run_engine("rust", segments=segments)
        self.assert_same(python, rust, reader=("rust-ewf",))
        pyewf_reads = self.run_engine("rust", segments=segments, extra_env={e01_extract_engine.E01_EXTRACT_READER_ENV: "python"})
        self.assert_same(python, pyewf_reads, reader=("python-handle",))

    def test_rust_ewf_reader_returns_pyewf_bytes(self) -> None:
        module, _ = e01_extract_engine.load_extract_extension()
        for name, options in (
            ("none", ("-c", "none", "-S", "4MiB")),
            ("best", ("-c", "deflate:best", "-b", "128")),
            ("fast", ("-c", "deflate:fast", "-S", "3MiB", "-b", "64")),
        ):
            with self.subTest(compression=name):
                segments = self.acquire(f"bytes-{name}", *options)
                handle = e01_native.open_ewf_segments(segments)
                try:
                    size = int(handle.get_media_size())
                    for offset, length in ((0, size), (size - 700, 4096), (12345, 70_000)):
                        handle.seek(offset)
                        expected = handle.read(length)
                        actual = module.ewf_read([str(s) for s in segments], offset, length)
                        self.assertEqual(hashlib.sha256(actual).hexdigest(), hashlib.sha256(expected).hexdigest())
                finally:
                    handle.close()

    def test_failed_parallel_copy_is_replayed_without_rerun(self) -> None:
        blocker = ("Users/alice/Documents/notes.txt",)
        python = self.run_engine("python", blockers=blocker)
        rust = self.run_engine("rust", blockers=blocker, extra_env={e01_extract_engine.E01_EXTRACT_THREADS_ENV: "4"})
        self.assert_same(python, rust)
        self.assertIsNone(rust[0]["extract_engine"]["rerun_reason"])
        clean = self.run_engine("python")
        self.assertEqual(python[0]["stats"]["errors"], clean[0]["stats"]["errors"] + 1)

    def test_failure_that_moves_the_cap_reruns_sequentially(self) -> None:
        blocker = ("Windows/System32/config/SYSTEM",)
        python = self.run_engine("python", limit=40, blockers=blocker)
        rust = self.run_engine("rust", limit=40, blockers=blocker, extra_env={e01_extract_engine.E01_EXTRACT_THREADS_ENV: "4"})
        self.assert_same(python, rust)
        self.assertTrue(rust[0]["extract_engine"]["rerun_reason"])

    def test_undecodable_compressed_file_is_identical(self) -> None:
        image = Path(self.temp.name) / "bad-lznt1.raw"
        build_disk_image(image, bulk_files=0, bulk_dirs=1, seed=1)
        original, type(self).image = type(self).image, image
        try:
            python = self.run_engine("python")
            rust = self.run_engine("rust", extra_env={e01_extract_engine.E01_EXTRACT_THREADS_ENV: "4"})
        finally:
            type(self).image = original
        self.assert_same(python, rust)
        self.assertNotIn("Users/alice/Documents/compressed.log", python[1]["files"])
        self.assertIsNone(rust[0]["extract_engine"]["rerun_reason"])


class _FailingExtension:
    ABI_VERSION = e01_extract_engine.E01_EXTRACT_NATIVE_ABI_VERSION

    @staticmethod
    def extract_tree(handle, base, size, extract_dir, *args, **kwargs):
        partial = Path(extract_dir) / "Windows" / "partial.bin"
        partial.parent.mkdir(parents=True, exist_ok=True)
        partial.write_bytes(b"written before the failure")
        raise RuntimeError("synthetic engine failure")


class EngineFallbackTests(EngineParityBase):
    def setUp(self) -> None:
        if e01_native.NTFS is None:
            if REQUIRE:
                self.fail("dissect.ntfs is not installed")
            self.skipTest("dissect.ntfs is not installed")

    def test_rust_failure_falls_back_to_python_and_is_recorded(self) -> None:
        python = self.run_engine("python")
        with patch.object(e01_extract_engine, "load_extract_extension", return_value=(_FailingExtension, "")):
            result, tree, _ = self.run_engine("rust")
        engine = result["extract_engine"]
        self.assertEqual((engine["requested"], engine["active"]), ("rust", "python"))
        self.assertIn("synthetic engine failure", engine["notice_ko"])
        self.assertEqual(tree, python[1])
        self.assertEqual(result["stats"], python[0]["stats"])

    def test_unknown_engine_value_uses_python_with_notice(self) -> None:
        result, tree, _ = self.run_engine("fortran")
        self.assertEqual(result["extract_engine"]["active"], "python")
        self.assertIn("fortran", result["extract_engine"]["notice_ko"])
        self.assertTrue(tree["files"])


if __name__ == "__main__":
    unittest.main()
