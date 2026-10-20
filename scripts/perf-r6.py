#!/usr/bin/env python3
"""R6 step 3 performance measurements (plan docs/plans/r6-followups-2026-10-19.md §3.4).

One entry point, one module per mode, so each lane owns its own file:

    python scripts/perf-r6.py --geo [--synthetic | --run DIR] ...       -> perf_r6_geo.py
    python scripts/perf-r6.py --files [ROWS] [--synthetic | --run DIR]  -> perf_r6_files.py
    python scripts/perf-r6.py --timeline ...                            -> perf_r6_timeline.py

All arguments are passed through unchanged to the chosen module's ``main``. Each module exits 1
when a target is missed. Not part of the unit tests; long runs go to Antigravity.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

MODES = {"--geo": "perf_r6_geo", "--files": "perf_r6_files", "--timeline": "perf_r6_timeline"}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    chosen = [flag for flag in MODES if flag in args]
    if len(chosen) != 1:
        print(f"usage: perf-r6.py one of {', '.join(MODES)} [options]", file=sys.stderr)
        return 2
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        module = importlib.import_module(MODES[chosen[0]])
    except ModuleNotFoundError:
        print(f"{chosen[0]}: this mode is not available in this checkout", file=sys.stderr)
        return 2
    return int(module.main(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
