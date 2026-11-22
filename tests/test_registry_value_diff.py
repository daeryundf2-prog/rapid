"""Denominator and row-stream checks for the Windows image comparison."""

from __future__ import annotations

import json
import runpy
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/registry-value-diff.py"))


class RegistryValueDiffTests(unittest.TestCase):
    def test_compare_preserves_duplicates_types_and_distinct_value_slots(self):
        left, right = defaultdict(Counter), defaultdict(Counter)
        for value in ("old", "old", 1):
            SCRIPT["add"](left, "Run", "sample", (value,))
        for value in ("old", "1"):
            SCRIPT["add"](right, "run", "SAMPLE", (value,))
        SCRIPT["add"](right, "run", "another", ("old",))
        self.assertEqual(SCRIPT["summarize"](left, right), {
            "matched": 1, "differing": 1, "rapid_only": 1, "reference_only": 1,
        })

    def test_rejects_truncated_provider_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "artifacts"
            folder.mkdir()
            head = folder / "rapidtriage-artifacts-windows-os-account.json"
            head.write_text(json.dumps({
                "root": str(root), "record_count": 1, "artifacts": [],
                "summary": {"parser_error_count": 0, "artifact_count": 1},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incomplete windows-os-account"):
                SCRIPT["rapid_tables"](root)
