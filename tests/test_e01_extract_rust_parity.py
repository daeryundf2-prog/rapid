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
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from rapidtriage.core import e01_extract_engine, e01_native
from tests import ntfs_volume_gen
from tests.ntfs_volume_gen import build_disk_image

REQUIRE = os.environ.get("RAPIDTRIAGE_REQUIRE_RUST_E01_EXTRACT") == "1"


def _missing() -> str:
    if e01_native.NTFS is None:
        return "dissect.ntfs is not installed"
    module, problem = e01_extract_engine.load_extract_extension()
    return "" if module is not None else f"rapid_extract_native unavailable: {problem}"


def engine_stats(stats: Mapping[str, int]) -> list[tuple[str, int]]:
    """Stats an engine produces, in order (the comparison includes key order):
    ``free_bytes_at_start`` is the output drive's state, not engine output."""
    return [(key, value) for key, value in stats.items() if key != "free_bytes_at_start"]


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
        self.assertEqual(list(rs_tree["files"].items()), list(py_tree["files"].items()))
        self.assertEqual(rs_tree["dirs"], py_tree["dirs"])
        self.assertEqual(engine_stats(rs_result["stats"]), engine_stats(py_result["stats"]))
        self.assertEqual(list(rs_progress[-1].items()), list(rs_result["stats"].items()))
        self.assertEqual(rs_result["output_name_collisions"], py_result["output_name_collisions"])


class RustEngineParityTests(EngineParityBase):
    def setUp(self) -> None:
        missing = _missing()
        if missing:
            if REQUIRE:
                self.fail(missing)
            self.skipTest(missing)

    def test_extension_version_matches_the_package(self) -> None:
        module, _ = e01_extract_engine.load_extract_extension()
        self.assertEqual(module.engine_version(), e01_extract_engine.E01_EXTRACT_NATIVE_VERSION)
        cargo = (Path(__file__).resolve().parents[1] / "engines/rust/crates/rapid-extract/Cargo.toml").read_text()
        self.assertIn(f'\nversion = "{e01_extract_engine.E01_EXTRACT_NATIVE_VERSION}"\n', cargo)

    def test_rust_run_records_engine_metadata(self) -> None:
        result = self.run_engine("rust")[0]
        metadata = e01_extract_engine.extract_engine_metadata(result["extract_engine"])
        self.assertEqual(metadata["native_e01_extract_engine"], "rust")
        self.assertEqual(metadata["native_e01_extract_engine_version"], e01_extract_engine.E01_EXTRACT_NATIVE_VERSION)
        self.assertEqual(metadata["native_e01_extract_engine_fallback_reason"], "")
        self.assertEqual(e01_extract_engine.extract_engine_metadata({}), {})

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
        # Only the priority pass records recovered segments: the walk recovers each hard-link path.
        self.assertIn("Users/bob/Documents/hardlink-b.txt", files)
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
        # Priority files are exempt from the cap but count toward it: a cap a few files above them
        # leaves the tree walk a budget that the failed SYSTEM copy (a priority file) moves.
        priority_files = self.run_engine("python", limit=1)[0]["stats"]["files"]
        limit = priority_files + 3
        blocker = ("Windows/System32/config/SYSTEM",)
        python = self.run_engine("python", limit=limit, blockers=blocker)
        rust = self.run_engine("rust", limit=limit, blockers=blocker, extra_env={e01_extract_engine.E01_EXTRACT_THREADS_ENV: "4"})
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

    def test_oversized_metadata_reads_are_refused_not_allocated(self) -> None:
        # Corrupt metadata asking for a 4 TiB read or a 2^40-cluster compressed runlist: dissect
        # attempts it (MemoryError or worse); the extension must fail the run over, not abort.
        module, _ = e01_extract_engine.load_extract_extension()
        for name, attrs in (
            ("sparse-si", lambda times: (
                ntfs_volume_gen.nonresident_attr(0x10, [(None, 1 << 30)], 1 << 42, instance=0),
                ntfs_volume_gen.resident_attr(0x80, b"small", instance=8),
            )),
            ("compressed", lambda times: (
                ntfs_volume_gen.resident_attr(0x10, ntfs_volume_gen.standard_information(times), instance=0),
                ntfs_volume_gen.nonresident_attr(0x80, [(None, 1 << 40)], 1 << 20, instance=8, compression_unit=4, flags=1),
            )),
        ):
            with self.subTest(name), tempfile.TemporaryDirectory(dir=self.temp.name) as out:
                image = Path(out) / "image.raw"
                build_disk_image(image, bulk_files=0, bulk_dirs=1, seed=5, builder=_OversizedBuilder(5, attrs))
                handle = e01_native.RawMediaHandle(image)
                try:
                    partitions, _ = e01_native.native_partition_table(handle)
                    for threads in (1, 4):
                        with self.assertRaisesRegex(RuntimeError, "^unsupported-input"):
                            module.extract_tree(
                                handle, int(partitions[0]["byte_offset"]), int(partitions[0]["size_bytes"]),
                                str(Path(out) / f"tree{threads}"), 200_000, True, [], None,
                                segments=[str(image)], media_size=handle.get_media_size(), threads=threads,
                            )
                finally:
                    handle.close()

    def test_damaged_chunk_table_is_left_to_pyewf(self) -> None:
        # libewf reads past a table whose entry checksum fails (table2); the Rust reader refuses
        # the segment set, so every read goes through pyewf and the output stays identical.
        segments = self.acquire("table-footer", "-c", "deflate:fast", "-S", "4MiB")
        first = bytearray(segments[0].read_bytes())
        table = first.index(b"table\x00")
        count = int.from_bytes(first[table + 76 : table + 80], "little")
        first[table + 76 + 24 + count * 4] ^= 0xFF
        segments[0].write_bytes(first)
        module, _ = e01_extract_engine.load_extract_extension()
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            module.ewf_read([str(s) for s in segments], 0, 4096)
        python = self.run_engine("python", segments=segments)
        rust = self.run_engine("rust", segments=segments)
        self.assert_same(python, rust, reader=("python-handle",))

    def test_free_space_reserve_falls_back_to_python_guard(self) -> None:
        # A reserve larger than any drive: Python's guard skips every file; Rust must not write
        # past it, so it hands the image to the Python engine and the fallback is recorded.
        reserve = {e01_native.NATIVE_MIN_FREE_GB_ENV: str(1 << 30)}
        python = self.run_engine("python", extra_env=reserve)
        self.assertGreater(python[0]["stats"]["disk_space_skips"], 0)
        for threads in ("1", "4"):
            with self.subTest(threads=threads):
                result, tree, _ = self.run_engine(
                    "rust", extra_env={**reserve, e01_extract_engine.E01_EXTRACT_THREADS_ENV: threads}
                )
                engine = result["extract_engine"]
                self.assertEqual((engine["requested"], engine["active"]), ("rust", "python"))
                self.assertIn(e01_extract_engine.E01_EXTRACT_SPACE_RESERVE_ERROR, engine["notice_ko"])
                self.assertEqual(tree, python[1])
                self.assertEqual(engine_stats(result["stats"]), engine_stats(python[0]["stats"]))

    def test_raising_progress_observer_does_not_fail_over(self) -> None:
        def observer(_stats: Any) -> None:
            raise RuntimeError("observer bug")

        out = Path(tempfile.mkdtemp(dir=self.temp.name))
        with (
            patch.dict(os.environ, {e01_extract_engine.E01_EXTRACT_ENGINE_ENV: "rust"}),
            patch.object(e01_native, "open_ewf_segments", lambda segs: e01_native.RawMediaHandle(segs[0])),
        ):
            result = e01_native.extract_e01_native(self.image, [self.image], out / "tree", on_progress=observer)
        self.assertEqual(result["extract_engine"]["active"], "rust")
        self.assertGreater(result["stats"]["files"], 0)


def _folds_names(directory: Path) -> bool:
    """Whether the output drive opens one file for two names of the fixture: different case
    (macOS, Windows) or different Unicode normalization (APFS, also when case-sensitive)."""
    for written, other in (("case-probe", "CASE-PROBE"), ("caf\u00e9-probe", "cafe\u0301-probe")):
        probe = directory / written
        probe.write_bytes(b"")
        try:
            if (directory / other).exists():
                return True
        finally:
            probe.unlink()
    return False


def colliding_sources(builder: ntfs_volume_gen.VolumeBuilder) -> dict[int, tuple[str, bytes, bool]]:
    """Allocated files below ``Collide/`` and the root file ``_deleted_mft``: record -> (path,
    body, reached). Not reached: a case twin or a file below one; the walk looks names up
    case-insensitively (as dissect does) and reaches one record per upper-cased name."""
    twins: dict[tuple[int, str], int] = {}
    for number, entry in builder.entries.items():
        if number != builder.root and not entry.deleted:
            link = entry.links[0]
            twins[(link.parent, link.name.upper())] = twins.get((link.parent, link.name.upper()), 0) + 1

    def source(record: int) -> tuple[str, bool]:
        parts, reached = [], True
        while record != builder.root:
            link = builder.entries[record].links[0]
            parts.append(link.name)
            reached = reached and twins[(link.parent, link.name.upper())] == 1
            record = link.parent
        return "/".join(reversed(parts)), reached

    sources = {}
    for number, entry in builder.entries.items():
        if not entry.is_dir and not entry.deleted:
            path, reached = source(number)
            if path.startswith("Collide/") or path == "_deleted_mft":
                sources[number] = (path, entry.data, reached)
    return sources


class OutputNameCollisionTests(EngineParityBase):
    """D27 #6: distinct NTFS records whose output names meet (cut at 180 characters, replaced
    characters, Win32 device names, the output drive's case or Unicode folding, the sweep folder)
    each keep their own file: the first in walk order the plain name, later ones a name tagged with
    their MFT record, listed with source path and MFT identity in ``output_name_collisions``."""

    builder: ntfs_volume_gen.VolumeBuilder
    sources: dict[int, tuple[str, bytes]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.image = Path(cls.temp.name) / "collisions.raw"
        cls.builder = ntfs_volume_gen.VolumeBuilder(3)
        build_disk_image(cls.image, bulk_files=40, bulk_dirs=2, seed=3, collisions=True, builder=cls.builder)
        cls.sources = colliding_sources(cls.builder)

    def setUp(self) -> None:
        if e01_native.NTFS is None:
            if REQUIRE:
                self.fail("dissect.ntfs is not installed")
            self.skipTest("dissect.ntfs is not installed")

    def record(self, path: str) -> int:
        return next(number for number, (source, _, _) in self.sources.items() if source == path)

    def assert_every_record_recovered(self, run: tuple) -> None:
        result, tree, _ = run
        files, stats, renames = tree["files"], result["stats"], result["output_name_collisions"]
        self.assertEqual(stats["files"], len(files))
        self.assertEqual(stats["name_collisions_unresolved"], 0)
        self.assertEqual(stats["name_collision_renames"], len(renames))
        recovered = Counter(digest for rel, (_, digest) in files.items() if rel.startswith(("Collide/", "_deleted_mft~")))
        reached = Counter(hashlib.sha256(body).hexdigest() for _, body, ok in self.sources.values() if ok)
        every = {hashlib.sha256(body).hexdigest() for _, body, _ in self.sources.values()}
        self.assertEqual(reached - recovered, Counter())
        self.assertLessEqual(set(recovered), every)
        for entry in renames:
            self.assertEqual(entry["status"], "renamed", entry)
            if entry["kind"] == "file":
                source, body, _ = self.sources[entry["mft_segment"]]
                self.assertEqual(entry["source_path"], source)
                self.assertEqual(entry["source_name"], source.rsplit("/", 1)[-1])
                self.assertEqual(entry["mft_sequence"], self.builder.entries[entry["mft_segment"]].sequence)
                self.assertEqual(files[entry["output_path"]][1], hashlib.sha256(body).hexdigest())
            else:
                self.assertEqual(entry["kind"], "directory")
                self.assertIn(entry["output_path"], tree["dirs"])
                self.assertEqual(entry["source_path"], "Collide/" + entry["source_name"])
        # Collisions every output drive has: the 180-character cut and the sweep folder's name.
        by_record = {entry["mft_segment"]: entry["output_path"] for entry in renames}
        long_b = self.record("Collide/" + "p" * 180 + "B")
        tag = f"~mft{long_b}"
        self.assertEqual(by_record[long_b], "Collide/" + "p" * (180 - len(tag)) + tag)
        self.assertEqual(files["Collide/" + "p" * 180][1], hashlib.sha256(b"A").hexdigest())
        sweep_named = self.record("_deleted_mft")
        self.assertEqual(by_record[sweep_named], f"_deleted_mft~mft{sweep_named}")
        self.assertTrue(any(rel.startswith("_deleted_mft/") for rel in files))
        # Win32 device names are renamed on Windows only, where "CON" would open the console.
        self.assertIn("Collide/_CON" if os.name == "nt" else "Collide/CON", files)

    def test_python_engine_recovers_every_record(self) -> None:
        self.assert_every_record_recovered(self.run_engine("python"))

    def test_rust_engine_matches_python_at_any_thread_count(self) -> None:
        missing = _missing()
        if missing:
            if REQUIRE:
                self.fail(missing)
            self.skipTest(missing)
        python = self.run_engine("python")
        folds = _folds_names(Path(self.temp.name))
        for threads in ("1", "4", "8"):
            with self.subTest(threads=threads):
                rust = self.run_engine("rust", extra_env={e01_extract_engine.E01_EXTRACT_THREADS_ENV: threads})
                self.assert_same(python, rust)
                self.assert_every_record_recovered(rust)
                # The plan names every record apart; only a folding drive makes two of them meet,
                # which sends the copy back to the sequential walk.
                rerun = rust[0]["extract_engine"]["rerun_reason"]
                if threads != "1" and folds:
                    self.assertTrue(rerun.startswith("output path collision"), rerun)
                else:
                    self.assertIsNone(rerun)


class _OversizedBuilder(ntfs_volume_gen.VolumeBuilder):
    """Adds ``Edge/victim.bin`` whose $STANDARD_INFORMATION and $DATA come from ``attrs(times)``."""

    def __init__(self, seed: int, attrs: Any) -> None:
        super().__init__(seed)
        self.victim_attrs = attrs

    def build_volume(self, label: str = "SYNTHETIC") -> bytes:
        self.add_file(self.makedirs("Edge"), "victim.bin", b"x")
        return super().build_volume(label)

    def _file_record(self, entry: Any) -> bytes:
        if not entry.links or entry.links[0].name != "victim.bin":
            return super()._file_record(entry)
        si, data = self.victim_attrs(entry.times)
        names = [
            ntfs_volume_gen.resident_attr(0x30, value, instance=1 + i, indexed=True)
            for i, (_link, value) in enumerate(self._fn_values(entry))
        ]
        return ntfs_volume_gen.mft_record(entry.record, [si, *names, data], flags=1)


class PanicException(BaseException):
    """Stands in for ``pyo3_runtime.PanicException``: a ``BaseException``, not an ``Exception``."""


class _PanickingExtension:
    ABI_VERSION = e01_extract_engine.E01_EXTRACT_NATIVE_ABI_VERSION

    @staticmethod
    def extract_tree(handle, base, size, extract_dir, *args, **kwargs):
        partial = Path(extract_dir) / "Windows" / "partial.bin"
        partial.parent.mkdir(parents=True, exist_ok=True)
        partial.write_bytes(b"written before the panic")
        raise PanicException("index out of bounds: the len is 3 but the index is 7")


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
        self.assertEqual(engine_stats(result["stats"]), engine_stats(python[0]["stats"]))

    def test_rust_panic_falls_back_to_python_and_is_recorded_in_run_metadata(self) -> None:
        python = self.run_engine("python")
        with patch.object(e01_extract_engine, "load_extract_extension", return_value=(_PanickingExtension, "")):
            result, tree, _ = self.run_engine("rust")
        engine = result["extract_engine"]
        self.assertEqual((engine["requested"], engine["active"]), ("rust", "python"))
        self.assertTrue(engine["fallback_reason"].startswith("panic: PanicException: index out of bounds"))
        self.assertEqual(tree, python[1])  # the partial Rust output was discarded
        self.assertEqual(engine_stats(result["stats"]), engine_stats(python[0]["stats"]))
        metadata = e01_extract_engine.extract_engine_metadata(engine)
        self.assertEqual(
            list(metadata),
            [
                "native_e01_extract_engine",
                "native_e01_extract_engine_requested",
                "native_e01_extract_engine_version",
                "native_e01_extract_engine_fallback_reason",
                "native_e01_extract_engine_notice_ko",
            ],
        )
        self.assertEqual(metadata["native_e01_extract_engine"], "python")
        self.assertEqual(metadata["native_e01_extract_engine_requested"], "rust")
        self.assertIsNone(metadata["native_e01_extract_engine_version"])
        self.assertEqual(metadata["native_e01_extract_engine_fallback_reason"], engine["fallback_reason"])

    def test_failed_rust_run_leaves_nothing_below_existing_directories(self) -> None:
        # A rerun into an extraction folder that already holds directories (an interrupted run):
        # what the failed Rust run wrote inside them must go too, not only new top-level entries.
        python = self.run_engine("python", blockers=("Windows",))
        with patch.object(e01_extract_engine, "load_extract_extension", return_value=(_FailingExtension, "")):
            result, tree, _ = self.run_engine("rust", blockers=("Windows",))
        self.assertEqual(result["extract_engine"]["active"], "python")
        self.assertNotIn("Windows/partial.bin", tree["files"])
        self.assertEqual(tree, python[1])

    def test_windows_device_names(self) -> None:
        for name in ("CON", "con.txt", "Nul", "COM1.log", "lpt9 .txt", "COM\u00b9", "CONIN$"):
            self.assertTrue(e01_native._is_windows_device_name(name), name)
        for name in ("CONSOLE", "COM10", "xCON", "aux_", "COM", "LPT0x.txt"):
            self.assertFalse(e01_native._is_windows_device_name(name), name)

    def test_keyboard_interrupt_is_not_an_engine_failure(self) -> None:
        class _Interrupted(_PanickingExtension):
            @staticmethod
            def extract_tree(*args, **kwargs):
                raise KeyboardInterrupt

        with (
            patch.object(e01_extract_engine, "load_extract_extension", return_value=(_Interrupted, "")),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.run_engine("rust")

    def test_stale_extension_build_is_refused(self) -> None:
        stale = SimpleNamespace(
            ABI_VERSION=e01_extract_engine.E01_EXTRACT_NATIVE_ABI_VERSION, engine_version=lambda: "0.0.0"
        )
        unversioned = SimpleNamespace(ABI_VERSION=e01_extract_engine.E01_EXTRACT_NATIVE_ABI_VERSION)
        for module, built in ((stale, "0.0.0"), (unversioned, "None")):
            with (
                self.subTest(built=built),
                patch.object(e01_extract_engine, "_extension", None),
                patch.object(e01_extract_engine.importlib, "import_module", return_value=module),
                patch.dict(os.environ, {e01_extract_engine.E01_EXTRACT_ENGINE_ENV: "rust"}),
            ):
                status = e01_extract_engine.e01_extract_engine_status()
                self.assertEqual(status["active"], "python")
                self.assertEqual(
                    status["fallback_reason"],
                    f"extension-unavailable: stale-build: built {built}, "
                    f"expected {e01_extract_engine.E01_EXTRACT_NATIVE_VERSION}",
                )

    def test_unknown_engine_value_uses_python_with_notice(self) -> None:
        result, tree, _ = self.run_engine("fortran")
        self.assertEqual(result["extract_engine"]["active"], "python")
        self.assertIn("fortran", result["extract_engine"]["notice_ko"])
        self.assertTrue(tree["files"])


if __name__ == "__main__":
    unittest.main()
