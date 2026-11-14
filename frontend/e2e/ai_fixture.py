"""E2E fixture of the AI 사용 console (R7 AI lane D): a SYNTHETIC home folder (tests/fixtures/
ai_agents/make_fixtures.py: user ``u1``, invented sessions, assembled fake secrets) run once through
the real pipeline (``rapidtriage run --mode seizure --read-only``) into ``<out>``.

Usage: ``python frontend/e2e/ai_fixture.py <evidence-dir> <output-dir>`` (run from the repo root).
Nothing is read from this PC's home folder.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def main() -> int:
    evidence = Path(sys.argv[1])
    output = Path(sys.argv[2])
    sys.path.insert(0, str(REPO / "tests" / "fixtures" / "ai_agents"))
    import make_fixtures  # noqa: PLC0415 - fixture module lives outside the package

    make_fixtures.build_all(evidence)
    command = [
        sys.executable,
        "-m",
        "rapidtriage",
        "run",
        "--mode",
        "seizure",
        "--read-only",
        str(evidence),
        "--output-dir",
        str(output),
    ]
    return subprocess.run(command, cwd=REPO, check=False, stdout=subprocess.DEVNULL).returncode


if __name__ == "__main__":
    raise SystemExit(main())
