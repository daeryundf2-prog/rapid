"""Review fixes for the native E01 extractor: per-file errors, path collisions, short reads, caps."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from concurrent.futures import Future
from pathlib import Path
from typing import Any
from unittest import mock

from rapidtriage.core import coverage, e01_native
from tests.test_r8_extract import _Dir, _File, _Handle, _make_ntfs


class _ShortFile(_File):
    """Declares ``declared`` bytes but its stream ends after ``len(content)``."""

    def __init__(self, segment: int, content: bytes, declared: int) -> None:
        super().__init__(segment, content)
        self._declared = declared

    def size(self) -> int:
        return self._declared


def _ntfs_with_mft(files: dict[int, _File], root: _Dir):
    """``_make_ntfs`` whose filesystem also accepts the ``mft=`` local-copy handle."""
    base = _make_ntfs(files, root)

    class _Fs(base):  # type: ignore[misc, valid-type]
        def __init__(self, reader: Any, mft: Any = None) -> None:
            super().__init__(reader)

    return _Fs


def _extract(files, root, out: Path, *, env: dict[str, str] | None = None, run_mode: str | None = None, ntfs=None):
    environ = {e01_native.NATIVE_E01_WORKERS_ENV: "2", **(env or {})}
    with (
        mock.patch.object(e01_native, "open_ewf_segments", lambda _segs: _Handle()),
        mock.patch.object(e01_native, "NTFS", ntfs or _make_ntfs(files, root)),
        mock.patch.dict("os.environ", environ),
    ):
        return e01_native.extract_e01_native(Path("x.E01"), [Path("x.E01")], out, run_mode=run_mode)


class ReviewNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        coverage.reset_coverage()

    def test_mkdir_failure_is_a_per_file_error_not_a_run_abort(self) -> None:  # f2 B1
        files = {20: _File(20, b"ok"), 21: _File(21, b"a"), 22: _File(22, b"b")}
        root = _Dir({"ok.txt": files[20], "sub": _Dir({"a.txt": files[21], "b.txt": files[22]})})
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            (out / "sub").write_bytes(b"in the way")  # the output directory cannot be created
            result = _extract(files, root, out)
            self.assertEqual(sorted(result["file_digests"]), ["ok.txt"])
        self.assertEqual(result["stats"]["errors"], 2)
        self.assertEqual(result["stats"]["files"], 1)

    def test_output_path_collisions_are_renamed_and_disclosed(self) -> None:  # f2 M1
        files = {seg: _File(seg, f"content-{seg}".encode()) for seg in (20, 21, 22, 23, 24, 25)}
        root = _Dir(
            {
                "a": files[20],
                "a.": files[21],  # trailing dot is stripped: same output name as "a"
                "Up.txt": files[22],
                "up.txt": files[23],  # differs only in case
                "x": files[24],
                "x.": _Dir({"in.txt": files[25]}),  # a directory that clashes with a file
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = _extract(files, root, out)
            on_disk = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
            digests = result["file_digests"]
            self.assertEqual(sorted(digests), on_disk)
            self.assertEqual(len(on_disk), 6)
            self.assertEqual(len({rel.casefold() for rel in on_disk}), 6)
            for rel, entry in digests.items():
                data = (out / rel).read_bytes()
                self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(entry["size_bytes"], len(data))
        self.assertEqual(result["stats"]["files"], 6)
        self.assertEqual(result["stats"]["errors"], 0)
        self.assertEqual(result["stats"]["path_renames"], 3)
        self.assertEqual(
            [e for e in coverage.coverage_entries() if e["reason_code"] == "output-path-collision"],
            [
                {
                    "area": "e01_native.paths",
                    "reason_code": "output-path-collision",
                    "limit": None,
                    "observed": 3,
                    "unit": "files",
                }
            ],
        )

    def test_short_read_is_an_error_never_a_complete_digest(self) -> None:  # f2 M7
        files = {20: _File(20, b"whole"), 21: _ShortFile(21, b"x" * 40, 100)}
        root = _Dir({"ok.txt": files[20], "short.bin": files[21]})
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = _extract(files, root, out)
            self.assertEqual(sorted(result["file_digests"]), ["ok.txt"])
            self.assertFalse((out / "short.bin").exists())
        self.assertEqual(result["stats"]["errors"], 1)
        self.assertEqual(result["stats"]["files"], 1)

    def test_short_local_mft_copy_falls_back_with_coverage(self) -> None:  # f2 M7, MINOR 9
        class _Fs:
            class mft:
                @staticmethod
                def get(_index: int) -> _ShortFile:
                    return _ShortFile(0, b"m" * 10, 4096)

        stats = e01_native._new_stats()
        made: list[str] = []
        real = tempfile.mkstemp

        def _tracked(**kwargs: Any):
            fd, name = real(**kwargs)
            made.append(name)
            return fd, name

        with mock.patch.object(e01_native.tempfile, "mkstemp", _tracked):
            path, is_temp = e01_native._write_local_mft(_Fs(), None, stats, 2048)
        self.assertEqual((path, is_temp), (None, False))
        self.assertTrue(made and not Path(made[0]).exists())
        self.assertEqual(
            coverage.coverage_entries(),
            [
                {
                    "area": "e01_native.mft",
                    "reason_code": "mft-local-copy-failed",
                    "limit": None,
                    "observed": None,
                    "unit": "partition",
                    "detail": {"start_sector": 2048},
                }
            ],
        )

    def test_explicit_cap_uses_the_parsed_valid_value(self) -> None:  # f2 MINOR 3
        files = {20: _File(20, b"x")}
        root = _Dir({"a.txt": files[20]})
        for raw, expected in (("abc", sys.maxsize), ("0", sys.maxsize), ("5", 5)):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as tmp:
                result = _extract(
                    files, root, Path(tmp), env={e01_native.NATIVE_MAX_EXTRACT_FILES_ENV: raw}, run_mode="recovery"
                )
                self.assertEqual(result["stats"]["file_limit"], expected)

    def test_temp_mft_copy_is_unlinked_when_planning_fails(self) -> None:  # f2 MINOR 5
        files = {0: _File(0, b"M" * 2048), 20: _File(20, b"x")}
        root = _Dir({"a.txt": files[20]})
        copies: list[Path] = []
        real = e01_native._write_local_mft

        def _spy(*args: Any, **kwargs: Any):
            result = real(*args, **kwargs)
            if result[0] is not None:
                copies.append(result[0])
            return result

        try:
            with (
                mock.patch.object(e01_native, "_write_local_mft", _spy),
                mock.patch.object(e01_native, "_plan_ntfs_dir", side_effect=RuntimeError("planning failed")),
                tempfile.TemporaryDirectory() as tmp,
                self.assertRaises(RuntimeError),
            ):
                _extract(files, root, Path(tmp), ntfs=_ntfs_with_mft(files, root))
            self.assertEqual(len(copies), 1)
            self.assertFalse(copies[0].exists())
        finally:
            for copy in copies:
                copy.unlink(missing_ok=True)

    def test_submission_window_bounds_live_futures(self) -> None:  # f2 MINOR 6
        class _Tracker:
            outstanding = 0
            peak = 0

        class _CountedFuture(Future):  # type: ignore[type-arg]
            def result(self, timeout: float | None = None) -> Any:
                _Tracker.outstanding -= 1
                return super().result(timeout)

        class _InlinePool:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def submit(self, fn: Any, *args: Any) -> Future:  # type: ignore[type-arg]
                _Tracker.outstanding += 1
                _Tracker.peak = max(_Tracker.peak, _Tracker.outstanding)
                future = _CountedFuture()
                future.set_result(fn(*args))
                return future

            def shutdown(self, wait: bool = True, cancel_futures: bool = False) -> None:
                pass

        files = {20 + i: _File(20 + i, f"n{i}".encode()) for i in range(300)}
        root = _Dir({f"f{i}.txt": files[20 + i] for i in range(300)})
        with mock.patch.object(e01_native, "ThreadPoolExecutor", _InlinePool), tempfile.TemporaryDirectory() as tmp:
            result = _extract(files, root, Path(tmp), env={e01_native.NATIVE_E01_WORKERS_ENV: "1"})
        self.assertEqual(result["stats"]["files"], 300)
        self.assertEqual(_Tracker.outstanding, 0)
        self.assertLessEqual(_Tracker.peak, e01_native._SUBMIT_WINDOW_PER_WORKER)

    def test_record_coverage_detail_is_optional_and_copied(self) -> None:  # coverage.py detail argument
        detail = {"start_sector": 2048}
        coverage.record_coverage("a", "r", None, None, "partition", detail=detail)
        coverage.record_coverage("b", "r", 1, 2, "files")
        detail["start_sector"] = 0
        first, second = coverage.coverage_entries()
        self.assertEqual(first["detail"], {"start_sector": 2048})
        self.assertNotIn("detail", second)
        first["detail"]["start_sector"] = 1  # type: ignore[index]
        self.assertEqual(coverage.coverage_entries()[0]["detail"], {"start_sector": 2048})


if __name__ == "__main__":
    unittest.main()
