"""Denominator and row-stream checks for the Windows image comparison."""

from __future__ import annotations

import json
import runpy
import struct
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path
from unittest.mock import Mock, patch

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

    def test_extra_free_index_pointer_does_not_hide_allocated_siblings(self):
        from tests.test_parser_quality_registry import HiveWriter, Key

        root = Key("ROOT")
        for name in ("before", "stale", "valid"):
            root.key(name)
        data = bytearray(HiveWriter().build(root))
        parent = 4100 + struct.unpack_from("<I", data, 36)[0]
        index = 4100 + struct.unpack_from("<I", data, parent + 28)[0]
        cells = [4096 + struct.unpack_from("<I", data, index + 4 + slot * 8)[0] for slot in range(3)]
        stale_size = struct.unpack_from("<i", data, cells[1])[0]
        struct.pack_into("<i", data, cells[1], -stale_size)
        struct.pack_into("<I", data, parent + 20, 2)
        self.assertEqual(SCRIPT["live_uninstall_offsets"](data, parent, index), ([cells[0], cells[2]], 1))
        struct.pack_into("<I", data, parent + 20, 3)
        with self.assertRaisesRegex(ValueError, "unreconciled"):
            SCRIPT["live_uninstall_offsets"](data, parent, index)

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

    def test_cancelled_collector_with_zero_parser_errors_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "artifacts"
            folder.mkdir()
            for provider, status in (("windows-os-account", "cancelled-partial"),
                                     ("windows-registry", "completed")):
                (folder / f"rapidtriage-artifacts-{provider}.json").write_text(json.dumps({
                    "root": str(root), "artifacts": [], "summary": {
                        "parser_error_count": 0, "artifact_count": 0, "collection_status": status,
                    },
                }), encoding="utf-8")
            sam = root / "Windows/System32/config/SAM"
            sam.parent.mkdir(parents=True)
            sam.touch()
            with patch.dict("sys.modules", {"Registry": Mock()}), patch.dict(
                SCRIPT["compare"].__globals__, {"reference_rows": lambda *_: []}
            ):
                report = SCRIPT["compare"](root, root)
            self.assertEqual(report["families"]["accounts"]["status"], "partial")
