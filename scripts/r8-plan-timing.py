#!/usr/bin/env python3
"""Time NTFS planning on an E01 partition: local sequential $MFT copy vs random EWF reads.

Prints counts and seconds only (no file names). The local $MFT copy goes to a temp file that
is deleted on exit; point TMPDIR/TEMP/TMP at a scratch directory to control where.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rapidtriage.core import e01_native
from rapidtriage.core.e01 import discover_e01_segments


class PlanTimeLimit(BaseException):
    """Wall-clock budget exhausted; a BaseException so ``_plan_ntfs_dir``'s ``except Exception`` cannot eat it."""


class _Deadline:
    def __init__(self, seconds: float) -> None:
        self.end = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() > self.end:
            raise PlanTimeLimit


class _Jobs(list):
    def __init__(self, deadline: _Deadline) -> None:
        super().__init__()
        self._deadline = deadline

    def append(self, item) -> None:
        self._deadline.check()
        super().append(item)

    def __len__(self) -> int:
        self._deadline.check()
        return super().__len__()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--start-sector", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=240.0)
    parser.add_argument("--mode", choices=("local-mft", "ewf"), required=True)
    args = parser.parse_args()

    segments = discover_e01_segments(Path(args.image))
    handle = e01_native.open_ewf_segments(segments)
    local_path: Path | None = None
    mft_handle = None
    result: dict[str, object] = {"mode": args.mode}
    try:
        offset = args.start_sector * e01_native.ewf_sector_size(handle)
        size = int(handle.get_media_size()) - offset

        def reader() -> e01_native.EwfSectorReader:
            return e01_native.EwfSectorReader(handle, base=offset, size=size)

        copy_seconds = 0.0
        t0 = time.monotonic()
        fs = e01_native.NTFS(reader())
        if args.mode == "local-mft":
            stats = {"errors": 0}
            local_path, _ = e01_native._write_local_mft(fs, None, stats)
            copy_seconds = time.monotonic() - t0
            if local_path is None:
                print(json.dumps({**result, "error": "local-copy-failed"}))
                return 1
            result["mft_bytes"] = local_path.stat().st_size
            mft_handle = e01_native._LocalMft(local_path)
            fs = e01_native.NTFS(reader(), mft=mft_handle)
        result["copy_seconds"] = round(copy_seconds, 2)

        deadline = _Deadline(args.seconds)
        real_get = fs.mft.get

        def checked_get(ref, *a, **k):
            deadline.check()
            return real_get(ref, *a, **k)

        fs.mft.get = checked_get  # type: ignore[method-assign]
        jobs = _Jobs(deadline)
        stats = e01_native._new_stats()
        phase = "dir-walk"
        completed = False
        t1 = time.monotonic()
        try:
            e01_native._plan_ntfs_dir(fs.mft.get(5), Path("out"), stats, jobs, limit=10**9)
            result["dir_walk_jobs"] = list.__len__(jobs)
            phase = "deleted-sweep"
            e01_native._plan_deleted_mft_records(fs, Path("out"), stats, jobs, None, recovery=False)
            completed = True
        except PlanTimeLimit:
            pass
        plan_seconds = time.monotonic() - t1
        planned = list.__len__(jobs)
        total = copy_seconds + plan_seconds
        result.update(
            completed=completed,
            stopped_in=None if completed else phase,
            jobs=planned,
            plan_seconds=round(plan_seconds, 2),
            jobs_per_s_plan_only=round(planned / plan_seconds, 1) if plan_seconds else None,
            total_seconds=round(total, 2),
            jobs_per_s_incl_copy=round(planned / total, 1) if total else None,
            errors=stats["errors"],
        )
        print(json.dumps(result))
        return 0
    finally:
        if mft_handle is not None:
            with contextlib.suppress(Exception):
                mft_handle.close()
        if local_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(local_path)
        with contextlib.suppress(Exception):
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
