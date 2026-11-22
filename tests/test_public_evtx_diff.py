"""Regression checks for joins over retained EVTX rows and independent XML rows."""

import runpy
import unittest
from collections import Counter
from pathlib import Path
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

    def test_usb_predicate_distinguishes_other_disks_on_the_same_channel(self):
        fields = {"channel": "Microsoft-Windows-Partition/Diagnostic"}
        self.assertEqual(diff["family"]({**fields, "BusType": ("11",)}), "other")
        self.assertEqual(diff["family"]({**fields, "BusType": ("7",)}), "usb")
        self.assertEqual(diff["family"]({**fields, "ParentId": ("USB\\SYNTHETIC",)}), "usb")
