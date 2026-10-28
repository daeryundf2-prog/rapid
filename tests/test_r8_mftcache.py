from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import e01_native
from rapidtriage.core.coverage import coverage_entries
from tests.test_r8_extract import _Dir, _File, _Handle, _make_ntfs

MFT_BYTES = b"MFT-LOCAL-COPY" * 70


class _Call:
    def __init__(self, mft) -> None:
        self.mft = mft
        self.is_local = mft is not None
        self.path = Path(mft.name) if mft is not None else None
        self.content = None
        if mft is not None:
            mft.seek(0)
            self.content = mft.read()
            mft.seek(0)


def _recording_ntfs(files, root, calls):
    base = _make_ntfs(files, root)

    class _Fs(base):
        def __init__(self, reader, mft=None) -> None:
            super().__init__(reader)
            calls.append(_Call(mft))

    return _Fs


class LocalMftTests(unittest.TestCase):
    def _fixture(self, *, with_mft_record: bool):
        files = {20 + i: _File(20 + i, f"data-{i}".encode() * 40) for i in range(8)}
        files[40] = _File(40, b"deleted" * 9, deleted=True)
        if with_mft_record:
            files[0] = _File(0, MFT_BYTES)
        root = _Dir({f"f{seg}.txt": files[seg] for seg in range(20, 28)})
        return files, root

    def _run(self, files, root, calls, system_dir: Path | None, out: Path):
        _Handle.opened = []
        with (
            mock.patch.object(e01_native, "open_ewf_segments", lambda _segs: _Handle()),
            mock.patch.object(e01_native, "NTFS", _recording_ntfs(files, root, calls)),
            mock.patch.dict("os.environ", {e01_native.NATIVE_E01_WORKERS_ENV: "3"}),
        ):
            return e01_native.extract_e01_native(Path("x.E01"), [Path("x.E01")], out, system_dir=system_dir)

    def test_planning_and_workers_get_a_local_mft_handle(self) -> None:
        files, root = self._fixture(with_mft_record=True)
        calls: list[_Call] = []
        with tempfile.TemporaryDirectory() as tmp:
            out, system = Path(tmp) / "out", Path(tmp) / "_system"
            result = self._run(files, root, calls, system, out)
            mft_file = system / "MFT.bin"
            self.assertEqual(mft_file.read_bytes(), MFT_BYTES)
            self.assertEqual(result["system_artifacts"]["mft"], str(mft_file))
            self.assertFalse(calls[0].is_local)  # the one fs that reads $MFT from the image
            local = calls[1:]
            self.assertGreaterEqual(len(local), 2)  # planning fs + at least one worker fs
            for call in local:
                self.assertTrue(call.is_local)
                self.assertEqual(call.path, mft_file)
                self.assertEqual(call.content, MFT_BYTES)
                self.assertEqual(call.mft.size, len(MFT_BYTES))
            self.assertEqual(len({id(call.mft) for call in local}), len(local))  # a handle per fs
            self.assertTrue(all(call.mft.closed for call in local))
            self.assertEqual(result["stats"]["files"], 9)
            self.assertEqual(result["stats"]["errors"], 0)

    def test_temp_copy_is_used_and_removed_without_system_dir(self) -> None:
        files, root = self._fixture(with_mft_record=True)
        calls: list[_Call] = []
        with tempfile.TemporaryDirectory() as tmp:
            self._run(files, root, calls, None, Path(tmp))
        local = calls[1:]
        self.assertTrue(local and all(call.is_local and call.content == MFT_BYTES for call in local))
        self.assertFalse(local[0].path.exists())

    def test_failed_copy_falls_back_and_records_coverage(self) -> None:
        files, root = self._fixture(with_mft_record=False)  # get(0) raises: the copy cannot be made
        calls: list[_Call] = []
        before = len(coverage_entries())
        with tempfile.TemporaryDirectory() as tmp:
            out, system = Path(tmp) / "out", Path(tmp) / "_system"
            result = self._run(files, root, calls, system, out)
            self.assertFalse((system / "MFT.bin").exists())
            self.assertNotIn("mft", result["system_artifacts"])
        self.assertTrue(calls and not any(call.is_local for call in calls))
        new = coverage_entries()[before:]
        self.assertEqual(
            [(e["area"], e["reason_code"]) for e in new if e["reason_code"] == "mft-local-copy-failed"],
            [("e01_native.mft", "mft-local-copy-failed")],
        )
        self.assertEqual(result["stats"]["files"], 9)  # extraction itself is unchanged


if __name__ == "__main__":
    unittest.main()
