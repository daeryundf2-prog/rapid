#!/usr/bin/env python3
"""Regenerate docs/rapidtriage-output-samples/*.json from the sample tests.

Runs the contract-sample tests of ``tests/test_rapidtriage_output_samples.py``
with ``RAPIDTRIAGE_UPDATE_OUTPUT_SAMPLES=1``: each test writes its normalized
``actual`` payload to the expected sample file, then compares as usual.
Review the resulting ``git diff docs/rapidtriage-output-samples`` before
committing (new keys expected, no host paths, no NUL bytes, no copy-time
events).

Usage: python scripts/update-output-samples.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_CLASS = "tests.test_rapidtriage_output_samples.RapidTriageOutputSamplesTests"
SAMPLE_TESTS = (
    "test_docs_sample_matches_contract_fixture",
    "test_files_sample_matches_contract_fixture",
    "test_extract_files_sample_matches_contract_fixture",
    "test_extract_docs_sample_matches_contract_fixture",
    "test_manifest_windows_sample_matches_fixture",
)


def main() -> int:
    env = {**os.environ, "RAPIDTRIAGE_UPDATE_OUTPUT_SAMPLES": "1"}
    command = [sys.executable, "-m", "unittest", *(f"{TEST_CLASS}.{name}" for name in SAMPLE_TESTS)]
    return subprocess.run(command, cwd=REPO_ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
