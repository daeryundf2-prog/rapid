"""Regression checks for joins over retained EVTX rows and independent XML rows."""

import io
import json
import runpy
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import nullcontext, redirect_stdout
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

    def test_unnamed_and_repeated_payloads_count_retained_values(self):
        details = {
            "record_id": "1", "event_id": "400", "channel": "Windows PowerShell", "provider_name": "sample",
            "computer": "example", "timestamp": "2024-01-01T00:00:00Z",
            "event_data": {"data_1": "different", "Payload": "first", "Payload_2": "second"},
        }
        xml = ET.fromstring(
            '<Event><System><EventRecordID>1</EventRecordID><EventID>400</EventID><Channel>Windows PowerShell</Channel>'
            '<Provider Name="sample"/><Computer>example</Computer><TimeCreated SystemTime="2024-01-01T00:00:00Z"/>'
            '</System><EventData><Data>original</Data><Data Name="Payload">first</Data>'
            '<Data Name="Payload">second</Data></EventData></Event>'
        )
        expected = diff["xml_fields"](xml)
        corrected = {**details, "event_data": {**details["event_data"], "data_1": "original"}}
        counts = {name: Counter() for name in diff["FAMILIES"]}
        diff["compare"]({1: [diff["rapid_fields"](details)], 2: [diff["rapid_fields"](corrected)]},
                        {1: [expected], 2: [expected]}, counts)
        group = counts["powershell"]
        self.assertEqual(group["Payload.match"], 2)
        self.assertEqual(group["matched"], 1)
        self.assertEqual(group["mismatched_or_missing"], 1)

    def test_unnamed_payload_mismatch_without_any_projected_fields(self):
        details = {
            "record_id": "2", "event_id": "400", "channel": "Windows PowerShell", "provider_name": "sample",
            "computer": "example", "timestamp": "2024-01-01T00:00:00Z",
        }
        xml = ET.fromstring(
            '<Event><System><EventRecordID>2</EventRecordID><EventID>400</EventID><Channel>Windows PowerShell</Channel>'
            '<Provider Name="sample"/><Computer>example</Computer><TimeCreated SystemTime="2024-01-01T00:00:00Z"/>'
            '</System><EventData><Data>original</Data></EventData></Event>'
        )
        counts = {name: Counter() for name in diff["FAMILIES"]}
        diff["compare"]({1: [diff["rapid_fields"]({**details, "event_data": {"data_1": "different"}})]},
                        {1: [diff["xml_fields"](xml)]}, counts)
        group = counts["powershell"]
        self.assertEqual(group["mismatched_or_missing"], 1)
        self.assertEqual(group["matched"], 0)

    def test_reference_non_usb_pair_exposes_rapid_only_usb_classification(self):
        details = {
            "record_id": "8", "event_id": "88", "channel": "System", "provider_name": "sample",
            "computer": "example", "timestamp": "2024-01-01T00:00:00Z",
        }
        actual = diff["rapid_fields"]({**details, "event_data": {"BusType": "7"}})
        expected = diff["rapid_fields"]({**details, "event_data": {"BusType": "11"}})
        counts = {name: Counter() for name in diff["FAMILIES"]}
        diff["compare"]({1: [actual]}, {1: [expected]}, counts)
        self.assertEqual(counts["other"]["mismatched_or_missing"], 1)
        self.assertEqual(counts["other"]["matched"], 0)

    def test_usb_instance_id_spelling_from_kernel_pnp(self):
        details = {
            "record_id": "8", "event_id": "400", "channel": "Microsoft-Windows-Kernel-PnP/Configuration",
            "provider_name": "sample", "computer": "example", "timestamp": "2024-01-01T00:00:00Z",
            "event_data": {"DeviceInstanceID": r"USB\sample"},
        }
        self.assertEqual(diff["family"](diff["rapid_fields"](details)), "usb")

    def test_padded_decimal_logon_id_preserves_strict_mismatch_and_identifies_equal_integer(self):
        details = {
            "record_id": "8", "event_id": "4624", "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing", "computer": "example",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        actual = diff["rapid_fields"]({**details, "event_data": {"TargetLogonId": "00010"}})
        expected = diff["rapid_fields"]({**details, "event_data": {"TargetLogonId": "0xA"}})
        counts = {name: Counter() for name in diff["FAMILIES"]}
        diff["compare"]({1: [actual]}, {1: [expected]}, counts)
        self.assertEqual(counts["logon"]["TargetLogonId.same_integer_different_text"], 1)
        self.assertEqual(counts["logon"]["TargetLogonId.mismatch"], 1)

    def test_python_numeric_separators_are_not_event_id_rendering(self):
        details = {
            "record_id": "8", "event_id": "4624", "channel": "Security",
            "provider_name": "Microsoft-Windows-Security-Auditing", "computer": "example",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        actual = diff["rapid_fields"]({**details, "event_data": {"TargetLogonId": "1_0"}})
        expected = diff["rapid_fields"]({**details, "event_data": {"TargetLogonId": "0xA"}})
        counts = {name: Counter() for name in diff["FAMILIES"]}
        diff["compare"]({1: [actual]}, {1: [expected]}, counts)
        self.assertEqual(counts["logon"]["TargetLogonId.same_integer_different_text"], 0)
        self.assertEqual(counts["logon"]["TargetLogonId.mismatch"], 1)

    def test_recovery_only_state_cannot_confirm_active_reference_record(self):
        details = {
            "record_id": "1", "event_id": "1", "channel": "System", "provider_name": "sample",
            "computer": "example", "timestamp": "2024-01-01T00:00:00Z",
        }
        expected = diff["rapid_fields"](details)
        counts = {name: Counter() for name in diff["FAMILIES"]}
        for state in ("slack-recovered", "inactive-chunk", "outside-chunk", "live", "unknown"):
            actual = diff["rapid_fields"]({**details, "evtx_record_state": state})
            diff["compare"]({1: [actual]}, {1: [expected]}, counts)
        group = counts["other"]
        self.assertEqual(group["matched"], 2)
        self.assertEqual(group["mismatched_or_missing"], 3)
        self.assertEqual(group["record_state.non_live"], 3)

    def test_incomplete_payload_flags_preclude_agreement(self):
        details = {
            "record_id": "8", "event_id": "400", "channel": "Windows PowerShell", "provider_name": "sample",
            "computer": "example", "timestamp": "2024-01-01T00:00:00Z",
        }
        for flag in ({"event_data_truncated": True}, {"event_data_key_status": "template-undecoded"},
                     {"evtx_binxml_status": "partial-tokenized"}, {"event_data_values": ["sample"]}):
            with self.subTest(flag=flag):
                actual = diff["rapid_fields"]({**details, **flag})
                expected = diff["rapid_fields"](details)
                counts = {name: Counter() for name in diff["FAMILIES"]}
                diff["compare"]({1: [actual]}, {1: [expected]}, counts)
                self.assertEqual(counts["powershell"]["mismatched_or_missing"], 1)
                self.assertEqual(counts["powershell"]["matched"], 0)
                self.assertEqual(counts["powershell"]["payload.incomplete"], 1)

    def test_truncated_reference_header_cannot_verify_empty_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "System.evtx"
            path.write_bytes(b"ElfFile\0" + bytes(120))
            header = Mock()
            header.check_magic.return_value = True
            header.chunk_count.return_value = 0
            header.header_chunk_size.return_value = 4096
            log = Mock()
            log.get_file_header.return_value = header
            log.chunks.return_value = []
            with patch.dict(sys.modules, {"Evtx.Evtx": Mock(Evtx=lambda _path: nullcontext(log))}):
                with self.assertRaisesRegex(ValueError, "header"):
                    diff["reference_rows"](path, Counter())

    def test_reference_chunk_honors_record_bounds_and_archive_zero_padding(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "System.evtx"
            path.write_bytes(bytes(4096 + 65536))
            header = Mock()
            header.check_magic.return_value = True
            header.chunk_count.return_value = 1
            header.header_chunk_size.return_value = 4096
            record = Mock()
            record.offset.return_value = 4096 + 512
            record.length.return_value = 64
            record.magic.return_value = 0x2A2A
            record.verify.return_value = True
            record.xml.return_value = "<Event><System/></Event>"
            chunk = Mock()
            chunk.offset.return_value = 4096
            chunk.check_magic.return_value = True
            chunk.records.return_value = [record]
            chunk.last_record_offset.return_value = 512
            chunk.file_first_record_number.return_value = 1
            chunk.file_last_record_number.return_value = 1
            log = Mock()
            log.get_file_header.return_value = header
            log.chunks.return_value = [chunk]
            with patch.dict(sys.modules, {"Evtx.Evtx": Mock(Evtx=lambda _path: nullcontext(log))}):
                for free, fill, usable, clean in ((65536, 0, True, True), (65536, 1, True, False),
                                                   (550, 0, False, False), (70000, 0, False, False)):
                    with self.subTest(free=free, fill=fill):
                        chunk.next_record_offset.return_value = free
                        chunk.unpack_binary.side_effect = lambda _offset, size, fill=fill: bytes([fill]) * size
                        errors = Counter()
                        rows, _ = diff["reference_rows"](path, errors)
                        self.assertEqual(bool(rows), usable)
                        self.assertEqual(not errors, clean)

    def test_reference_iterator_not_advanced_past_full_final_chunk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "System.evtx"
            path.write_bytes(bytes(4096 + 65536))
            log = Mock()
            header = log.get_file_header()
            header.check_magic.return_value = True
            header.header_chunk_size.return_value = 4096
            header.chunk_count.return_value = 1
            chunk = Mock()
            log.chunks.return_value = [chunk]
            chunk.check_magic.return_value = True
            chunk.next_record_offset.return_value = 65536
            chunk.offset.return_value = 4096
            record = Mock()
            record.offset.return_value = 4608
            record.length.return_value = 65536 - 512
            record.magic.return_value = 0x2A2A
            record.verify.return_value = True
            record.xml.return_value = "<Event><System/></Event>"

            def records():
                yield record
                raise AssertionError("decoder read beyond final chunk")

            chunk.records.side_effect = records
            errors = Counter()
            with patch.dict(sys.modules, {"Evtx.Evtx": Mock(Evtx=lambda _path: nullcontext(log))}):
                rows, _ = diff["reference_rows"](path, errors)
            self.assertEqual(list(rows), [4608])
            self.assertEqual(errors, {})
