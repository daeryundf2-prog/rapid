"""Regression checks for joins over retained EVTX rows and independent XML rows."""

import io
import json
import runpy
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

diff = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/public-evtx-diff.py"))


class PublicEvtxDiffTests(unittest.TestCase):
    def test_missing_and_duplicate_offsets_and_repeated_xml_values(self):
        xml = ET.fromstring(
            '<Event xmlns="urn:example"><System><EventID>7045</EventID><EventRecordID>8</EventRecordID>'
            '<Provider Name="Service Control Manager"/><Computer>example</Computer><Channel>System</Channel>'
            '<TimeCreated SystemTime="2024-01-01T00:00:00.000100Z"/></System><EventData>'
            '<Data Name="ServiceName">first</Data><Data Name="ServiceName">second</Data></EventData></Event>'
        )
        expected = diff["xml_fields"](xml)
        actual = diff["rapid_fields"]({
            "record_id": "8", "event_id": "7045", "channel": "System", "provider_name": "Service Control Manager",
            "computer": "example", "timestamp": "2024-01-01T01:00:00.000101+01:00", "event_data": {"ServiceName": "first"},
        })
        counts = {name: Counter() for name in diff["FAMILIES"]}
        diff["compare"]({1: [actual], 2: [actual, actual], 3: [actual]},
                        {1: [expected], 2: [expected], 4: [expected]}, counts)
        group = counts["service-install"]
        self.assertEqual(group["ServiceName.mismatch"], 1)
        self.assertEqual(group["timestamp.match"], 1)
        self.assertEqual(group["timestamp.sub_ms_difference"], 1)
        self.assertEqual(group["mismatched_or_missing"], 1)
        self.assertEqual(group["rapid_ambiguous"], 2)
        self.assertEqual(group["reference_ambiguous"], 1)
        self.assertEqual(group["rapid_only"], 1)
        self.assertEqual(group["reference_only"], 1)

    def test_rendering_and_recovery_diagnostics_preserve_exact_mismatches(self):
        details = {
            "record_id": "1", "event_id": "4104", "channel": "Windows PowerShell",
            "provider_name": "PowerShell", "computer": "example", "timestamp": "2024-01-01T00:00:00.001000Z",
            "event_data": {"ScriptBlockText": "first\r\nsecond"}, "evtx_record_state": "inactive-chunk",
        }
        actual = diff["rapid_fields"](details)
        expected = diff["rapid_fields"]({
            **details, "timestamp": "2024-01-01T00:00:00.000999Z", "event_data": {"ScriptBlockText": "first\nsecond"},
        })
        counts = {name: Counter() for name in diff["FAMILIES"]}
        unknown = diff["rapid_fields"]({**details, "evtx_record_state": None})
        diff["compare"]({1: [actual], 2: [actual], 3: [unknown], 4: [actual, actual]},
                        {1: [expected], 4: [expected]}, counts)
        group = counts["powershell"]
        self.assertEqual(group["timestamp.mismatch"], 1)
        self.assertEqual(group["timestamp.max_mismatch_delta_us"], 1)
        self.assertEqual(group["ScriptBlockText.mismatch"], 1)
        self.assertEqual(group["ScriptBlockText.same_after_xml_newline_normalization"], 1)
        self.assertEqual(group["mismatched_or_missing"], 1)
        self.assertEqual(group["matched"], 0)
        self.assertEqual(group["rapid_only"], 2)
        self.assertEqual(group["rapid_only_state.inactive-chunk"], 1)
        self.assertEqual(group["rapid_only_state.unknown"], 1)
        self.assertEqual(group["rapid_ambiguous"], 2)

    def test_cli_distinguishes_unreadable_reference_and_missing_decoder_from_one_sided_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            head = root / "artifacts/rapidtriage-artifacts-eventlog.json"
            head.parent.mkdir()
            head.write_text(json.dumps({"root": str(root), "artifacts": [],
                                        "summary": {"collection_status": "completed", "parser_error_count": 0}}))
            logs = root / diff["LOGS"]
            logs.mkdir(parents=True)
            args = ["--run", str(root)]
            def run():
                out = io.StringIO()
                with redirect_stdout(out):
                    rc = diff["main"](args)
                return rc, json.loads(out.getvalue())

            rc, report = run()
            self.assertNotEqual(rc, 0)
            self.assertIn("no selected reference log files", report["issues"])
            (logs / "Security.evtx").touch()
            with patch.dict(sys.modules, {"Evtx.Evtx": None}):
                rc, report = run()
            self.assertNotEqual(rc, 0)
            self.assertIn("ModuleNotFoundError", report["issues"][0])
            with patch.dict(diff["main"].__globals__, {"reference_rows": Mock(side_effect=ValueError("synthetic unreadable log"))}):
                rc, report = run()
            self.assertNotEqual(rc, 0)
            self.assertEqual(report["files"]["security.evtx"]["reference_errors"], {"file.ValueError": 1})
            self.assertEqual(report["files"]["security.evtx"]["reference_file_error"], "synthetic unreadable log")
            with patch.dict(diff["main"].__globals__, {"reference_rows": lambda *args: ({42: [{}]}, set())}):
                rc, report = run()
            self.assertEqual(rc, 0)
            self.assertEqual(report["families"]["other"]["reference_only"], 1)

    def test_usb_predicate_distinguishes_other_disks_on_the_same_channel(self):
        fields = {"channel": "Microsoft-Windows-Partition/Diagnostic"}
        self.assertEqual(diff["family"]({**fields, "BusType": ("11",)}), "other")
        self.assertEqual(diff["family"]({**fields, "BusType": ("7",)}), "usb")
        self.assertEqual(diff["family"]({**fields, "ParentId": ("USB\\SYNTHETIC",)}), "usb")

    def test_conflicting_summary_and_record_count_rejects_partial_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / diff["LOGS"]).mkdir(parents=True)
            head = root / "artifacts/rapidtriage-artifacts-eventlog.json"
            head.parent.mkdir()
            head.write_text(json.dumps({
                "root": str(root), "record_count": 0, "artifacts": [],
                "summary": {"artifact_count": 1, "collection_status": "completed", "parser_error_count": 0},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incomplete eventlog collector stream"):
                diff["compare_run"](root)
