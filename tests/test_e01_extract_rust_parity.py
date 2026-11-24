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
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, int]]]:
        out = Path(tempfile.mkdtemp(dir=self.temp.name))
        env = {e01_extract_engine.E01_EXTRACT_ENGINE_ENV: engine}
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

    def assert_same(self, python: tuple, rust: tuple) -> None:
        py_result, py_tree, _ = python
        rs_result, rs_tree, rs_progress = rust
        self.assertEqual(rs_result["extract_engine"], {"requested": "rust", "active": "rust", "notice_ko": ""})
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
            with self.subTest(limit=limit):
                python = self.run_engine("python", limit=limit)
                rust = self.run_engine("rust", limit=limit)
                self.assert_same(python, rust)
                self.assertGreater(python[0]["stats"]["truncated"], 0)
        self.assertEqual(python[0]["stats"]["file_limit"], 300)

    def test_without_deleted_sweep_is_identical(self) -> None:
        python = self.run_engine("python", include_deleted=False)
        rust = self.run_engine("rust", include_deleted=False)
        self.assert_same(python, rust)
        self.assertEqual(python[0]["stats"]["deleted_files"], 0)

    def test_e01_segment_set_is_identical(self) -> None:
        ewfacquire = shutil.which("ewfacquire")
        if ewfacquire is None or e01_native.pyewf is None:
            self.skipTest("ewfacquire or pyewf unavailable")
        target = Path(self.temp.name) / "e01" / "disk"
        target.parent.mkdir(exist_ok=True)
        subprocess.run(
            [ewfacquire, "-u", "-q", "-t", str(target), "-f", "encase6", "-c", "deflate:fast", "-S", "4MiB",
             "-C", "synthetic", "-D", "synthetic", "-e", "synthetic", "-E", "1", "-N", "synthetic", str(self.image)],
            check=True, capture_output=True,
        )
        segments = sorted(target.parent.glob("disk.E*"))
        self.assertGreater(len(segments), 1)
        self.assert_same(self.run_engine("python", segments=segments), self.run_engine("rust", segments=segments))


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
