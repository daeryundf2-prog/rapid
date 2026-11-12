"""E2E fixture of the R8 screens (T-004): a SYNTHETIC rich result folder written by
``scripts/make-r8-fixture.py`` (fake values only, every Tier 1 card has rows, known counts in
``<output>/r8-fixture-manifest.json`` = ``tests/fixtures/r8_rich/manifest.json``).

Usage: ``python frontend/e2e/r8_fixture.py <output-dir> [seed]`` (run from the repo root), then
``POST /api/runs/import {"output_dir": "<output-dir>"}``. No pipeline run, no evidence read.
CI gate data only — never completion evidence (IS-121).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def main() -> int:
    output = Path(sys.argv[1])
    seed = sys.argv[2] if len(sys.argv) > 2 else "8"
    command = [
        sys.executable,
        str(REPO / "scripts" / "make-r8-fixture.py"),
        "--output",
        str(output),
        "--seed",
        seed,
        "--check" if seed == "8" else "--json",
    ]
    return subprocess.run(command, cwd=REPO, check=False, stdout=subprocess.DEVNULL).returncode


if __name__ == "__main__":
    raise SystemExit(main())
