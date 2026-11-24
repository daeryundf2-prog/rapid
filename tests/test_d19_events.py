"""D19 review: event messages, SRUM counters, SetupAPI bounds and submission times.

- A built-in message template applies only to the (provider, EventID) it was
  written for: a third-party provider's 104 is not "An event log was
  cleared", while the Eventlog service's 104 still is (item 4).
- SRUM exports map the Network Data Usage column ``BytesRecvd`` and cite it;
  Application Resource Usage counters keep their own names and units
  (item 5).
- SetupAPI reads the whole log: a device installed after the first 4 MiB
  still yields a row (item 6), and the summary device count is every device
  read, only the listed sample stops at 100 (item 14).
- Host file times 100 ns and 200 ns past a second stay distinct from the
  files CLI through the bookmark, the submission manifest and the case
  report HTML (item 9).
- An exported XML event's RenderingInfo/Message is its message; an EventData
  item that is only named ``Message`` stays a data column (item 11).
- A recycled folder's ``$R`` directory, and a ``$R`` whose name differs only
  in case, are the paired payload; only a truly absent ``$R`` is missing
  (item 7).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from xml.etree import ElementTree as ET

from rapidtriage.artifacts.windows.eventlog import WindowsEventLogProvider
from rapidtriage.artifacts.windows.execution import WindowsExecutionProvider
from rapidtriage.artifacts.windows.filesystem import collect_recycle_bin_artifacts
from rapidtriage.artifacts.windows.system import collect_setupapi_usb_artifacts
from rapidtriage.cli import main
from rapidtriage.core.case import create_or_update_case_payload, save_case_payload
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    write_case_report_exports,
)
from rapidtriage.core.filetime import unix_ns_to_iso
from rapidtriage.core.submission import build_submission_manifest

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def xml_event(
    record_id: int,
    provider: str,
    event_id: int,
    channel: str,
    *,
    rendered: str = "",
    payload_message: str = "",
) -> ET.Element:
    event = ET.Element("Event", xmlns=EVENT_NS)
    system = ET.SubElement(event, "System")
    ET.SubElement(system, "Provider", Name=provider)
    ET.SubElement(system, "EventID").text = str(event_id)
    ET.SubElement(system, "TimeCreated", SystemTime="2024-03-15T08:00:00Z")
    ET.SubElement(system, "EventRecordID").text = str(record_id)
    ET.SubElement(system, "Channel").text = channel
    ET.SubElement(system, "Computer").text = "fixture.invalid"
    data = ET.SubElement(event, "EventData")
    ET.SubElement(data, "Data", Name="Action").text = "print-finished"
    if payload_message:
        ET.SubElement(data, "Data", Name="Message").text = payload_message
    if rendered:
        ET.SubElement(ET.SubElement(event, "RenderingInfo", Culture="en-US"), "Message").text = rendered
    return event


def collect_xml_events(events: list[ET.Element]) -> dict[str, dict]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        document = ET.Element("Events")
        document.extend(events)
        ET.ElementTree(document).write(root / "events.xml", encoding="utf-8", xml_declaration=True)
        rows = list(WindowsEventLogProvider().collect(root))
    return {row.details["record_id"]: row.details for row in rows if row.artifact_type == "eventlog-event"}


class EventMessageTemplateTests(unittest.TestCase):
    """Item 4: template lookup is keyed by provider and EventID, not EventID alone."""

    def test_third_party_104_is_not_a_log_clear(self) -> None:
        events = collect_xml_events(
            [
                xml_event(1, "Sample-Printer", 104, "Application"),
                xml_event(5, "Sample-Printer", 104, "Sample-Printer/Operational"),
                xml_event(6, "Sample-Printer", 4624, "Application"),
            ]
        )
        for record_id in ("1", "5", "6"):
            details = events[record_id]
            self.assertEqual(details["event_category"], "event")
            self.assertNotEqual(details["message_rendering"]["status"], "rendered-builtin-template")
            self.assertNotIn("event log was cleared", details["event_message"])
            self.assertNotIn("logged on", details["event_message"])

    def test_eventlog_service_104_still_renders_log_clear(self) -> None:
        events = collect_xml_events(
            [
                xml_event(7, "Microsoft-Windows-Eventlog", 104, "System"),
                xml_event(8, "Microsoft-Windows-Eventlog", 1102, "Security"),
            ]
        )
        cleared = events["7"]
        self.assertEqual(cleared["event_category"], "system-log-cleared")
        self.assertEqual(cleared["message_rendering"]["status"], "rendered-builtin-template")
        self.assertTrue(cleared["event_message"].startswith("An event log was cleared."))
        audit = events["8"]
        self.assertEqual(audit["event_category"], "audit-log-cleared")
        self.assertTrue(audit["event_message"].startswith("The Security audit log was cleared."))


class RenderedXmlMessageTests(unittest.TestCase):
    """Item 11: RenderingInfo/Message outranks a payload item named Message."""

    def test_rendered_message_shown_and_payload_column_kept(self) -> None:
        sentence = "Print finished in tray 2."
        events = collect_xml_events(
            [
                xml_event(3, "Sample-Printer", 104, "Application", rendered=sentence),
                xml_event(4, "Sample-Printer", 104, "Application", rendered=sentence, payload_message="tray-2"),
            ]
        )
        for record_id in ("3", "4"):
            rendering = events[record_id]["message_rendering"]
            self.assertEqual(events[record_id]["event_message"], sentence)
            self.assertEqual(rendering["status"], "external-message")
            self.assertEqual(rendering["message_source"], "xml-renderinginfo-message")
            self.assertEqual(rendering["source_xml_path"], "Event/RenderingInfo/Message")
        self.assertEqual(events["4"]["data"]["Message"], "tray-2")
        # The rendered sentence is not passed off as an EventData column.
        self.assertNotIn("Message", events["3"]["data"])


def collect_srum_csv(rows: list[list[str]]) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with (root / "srum-export.csv").open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows(rows)
        records = list(WindowsExecutionProvider().collect(root))
    return [record.details for record in records if Path(record.path).name == "srum-export.csv"]


class SrumCounterMappingTests(unittest.TestCase):
    """Item 5: BytesRecvd is the received counter; app-resource counters are not dropped."""

    def assert_network_row(self, received_column: str) -> None:
        (details,) = collect_srum_csv(
            [
                ["TimeStamp", "AppId", "UserId", "InterfaceLuid", "BytesSent", received_column],
                ["2024-02-03T00:00:00Z", "7", "3", "13", "4", "100"],
            ]
        )
        self.assertEqual((details["bytes_sent"], details["bytes_received"], details["bytes_total"]), (4, 100, 104))
        cited = details["srum_report_citation_manifest"]["row_identity"]["counter_values"]
        self.assertEqual(cited, {"bytes_sent": 4, "bytes_received": 100, "bytes_total": 104})
        self.assertEqual(details["srum_counter_source_columns"]["bytes_received"], received_column)

    def test_native_bytesrecvd_column(self) -> None:
        self.assert_network_row("BytesRecvd")

    def test_bytesreceived_column(self) -> None:
        self.assert_network_row("BytesReceived")

    def test_app_resource_counters_keep_names_and_units(self) -> None:
        (details,) = collect_srum_csv(
            [
                ["TimeStamp", "AppId", "UserId", "ForegroundCycleTime", "BackgroundCycleTime", "FaceTime"],
                ["2024-02-03T00:00:00Z", "7", "3", "90", "10", "50"],
            ]
        )
        counters = details["srum_app_resource_counters"]
        self.assertEqual(counters["foreground_cycle_time"], {"value": 90, "unit": "cpu-cycles", "source_column": "ForegroundCycleTime"})
        self.assertEqual(counters["background_cycle_time"]["value"], 10)
        self.assertEqual(counters["face_time"]["unit"], "source-unit-unverified")
        # Cycle counts are never reported as CPU time.
        self.assertEqual(details["cpu_time"], "")
        cited = details["srum_report_citation_manifest"]["row_identity"]["counter_values"]
        self.assertEqual(cited, {"foreground_cycle_time": 90, "background_cycle_time": 10, "face_time": 50})


def setupapi_section(number: int) -> bytes:
    return (
        f">>>  [Device Install - USB\\VID_1234&PID_0001\\UNIT{number}]\r\n"
        ">>>  Section start 2024/01/01 09:00:00.000\r\n"
        "<<<  Section end 2024/01/01 09:01:00.000\r\n"
        "<<<  [Exit status: SUCCESS]\r\n"
    ).encode("ascii")


def setupapi_rows(content: bytes) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "setupapi.dev.log").write_bytes(content)
        return [row.details for row in collect_setupapi_usb_artifacts(root)]


LOG_LINE = b"     dvi: Processing device installation step.\r\n"
PAST_4_MIB = LOG_LINE * (1 + (4 * 1024 * 1024) // len(LOG_LINE))


def recycle_metadata(name: str, size: int) -> bytes:
    path = ("C:\\docs\\" + name + "\0").encode("utf-16le")
    return struct.pack("<QQQI", 2, size, 133485408000000000, len(path) // 2) + path


class RecycleBinPayloadKindTests(unittest.TestCase):
    """Item 7: file, directory and absent $R payloads are told apart."""

    def test_directory_and_case_variant_payloads_pair(self) -> None:
        file_payload = b"control"
        with tempfile.TemporaryDirectory() as tmp:
            sid = Path(tmp) / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
            sid.mkdir(parents=True)
            (sid / "$IABC123.TXT").write_bytes(recycle_metadata("manual.txt", len(file_payload)))
            (sid / "$Rabc123.txt").write_bytes(file_payload)
            (sid / "$IDEF456").write_bytes(recycle_metadata("folder", 0))
            (sid / "$RDEF456").mkdir()
            (sid / "$RDEF456" / "note.txt").write_bytes(b"directory child")
            (sid / "$IGHI789").write_bytes(recycle_metadata("other-folder", 0))
            (sid / "$Rghi789").mkdir()
            (sid / "$IJKL012.txt").write_bytes(recycle_metadata("gone.txt", 4))
            rows = {Path(record.path).name: record.details for record in collect_recycle_bin_artifacts(Path(tmp))}

        case_file = rows["$IABC123.TXT"]
        self.assertEqual(case_file["coverage_status"], "i-r-pair-mapped")
        self.assertEqual(case_file["paired_payload_kind"], "file")
        self.assertEqual(Path(case_file["paired_payload_path"]).name, "$Rabc123.txt")
        self.assertEqual(case_file["paired_payload_hashes"]["sha256"], hashlib.sha256(file_payload).hexdigest())

        for name, real_name, entries in (("$IDEF456", "$RDEF456", 1), ("$IGHI789", "$Rghi789", 0)):
            with self.subTest(name):
                folder = rows[name]
                self.assertEqual(folder["coverage_status"], "i-r-pair-mapped")
                self.assertEqual(folder["paired_payload_kind"], "directory")
                self.assertEqual(Path(folder["paired_payload_path"]).name, real_name)
                self.assertEqual(Path(folder["paired_payload_path"]).parent.name, "S-1-5-21-1-2-3-1001")
                self.assertEqual(folder["paired_payload_hashes"], {})
                self.assertEqual(folder["paired_payload_entry_count"], entries)
                self.assertIn("folder was recycled", " ".join(folder["recovery"]["limitations"]))

        missing = rows["$IJKL012.txt"]
        self.assertEqual(missing["coverage_status"], "i-file-only")
        self.assertEqual(missing["paired_payload_kind"], "")
        self.assertEqual(missing["paired_payload_path"], "")


class SetupApiBoundsTests(unittest.TestCase):
    def test_device_after_4_mib_is_found(self) -> None:
        """Item 6: same section before and after the old 4 MiB window."""
        self.assertGreater(len(PAST_4_MIB), 4 * 1024 * 1024)
        for label, content, units in (
            ("compact", setupapi_section(1) + setupapi_section(2), {"UNIT1", "UNIT2"}),
            ("one-beyond", setupapi_section(1) + PAST_4_MIB + setupapi_section(2), {"UNIT1", "UNIT2"}),
            ("all-beyond", PAST_4_MIB + setupapi_section(2), {"UNIT2"}),
        ):
            with self.subTest(label):
                (details,) = setupapi_rows(content)
                found = {device_id.rsplit("\\", 1)[-1] for device_id in details["device_id_candidates"]}
                self.assertEqual(found, units)
                self.assertEqual(details["usb_device_review_profile"]["device_count"], len(units))
                self.assertEqual(details["scan_window_bytes"], len(content))
                self.assertFalse(details["scan_truncated"])
                self.assertEqual(details["unscanned_bytes"], 0)

    def test_device_count_is_not_capped_by_sample(self) -> None:
        """Item 14: 100, 101 and 102 devices are counted; only the list stops at 100."""
        for count in (100, 101, 102):
            with self.subTest(count):
                (details,) = setupapi_rows(b"".join(setupapi_section(index) for index in range(1, count + 1)))
                profile = details["usb_device_review_profile"]
                self.assertEqual(profile["device_count"], count)
                self.assertEqual(details["device_id_count"], count)
                self.assertEqual(details["install_entry_count"], count)
                self.assertEqual(profile["devices_listed"], 100)
                self.assertEqual(len(details["device_id_candidates"]), 100)
                self.assertEqual(profile["devices_truncated"], count > 100)


class SubmissionClockTests(unittest.TestCase):
    """Item 9: host mtimes are serialized from st_mtime_ns end to end."""

    BASE_NS = 1_704_067_200 * 10**9

    def test_unix_ns_to_iso(self) -> None:
        self.assertEqual(unix_ns_to_iso(self.BASE_NS), "2024-01-01T00:00:00+00:00")
        self.assertEqual(unix_ns_to_iso(self.BASE_NS + 100), "2024-01-01T00:00:00.0000001+00:00")
        self.assertEqual(unix_ns_to_iso(self.BASE_NS + 1_000), "2024-01-01T00:00:00.000001+00:00")
        self.assertEqual(unix_ns_to_iso(self.BASE_NS + 1_234_567_899), "2024-01-01T00:00:01.2345678+00:00")
        self.assertEqual(unix_ns_to_iso(-100), "1969-12-31T23:59:59.9999999+00:00")

    def test_100ns_and_200ns_reach_the_submission_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inputs = root / "inputs"
            inputs.mkdir()
            for name, delta in (("first", 100), ("second", 200), ("control", 1_000)):
                path = inputs / f"{name}.txt"
                path.write_bytes(name.encode())
                os.utime(path, ns=(self.BASE_NS, self.BASE_NS + delta))
            stat_iso = {path.name: unix_ns_to_iso(path.stat().st_mtime_ns) for path in inputs.iterdir()}
            # The filesystem kept distinct 100 ns values (the oracle is the host stat).
            self.assertEqual(len(set(stat_iso.values())), 3)

            source = root / "files.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["files", str(inputs), "--output", str(source)]), 0)
            candidates = json.loads(source.read_text(encoding="utf-8"))["candidates"]
            self.assertEqual({row["name"]: row["modified_at"] for row in candidates}, stat_iso)

            case_file = root / "case.json"
            case: dict = {}
            for index in range(len(candidates)):
                case = create_or_update_case_payload(
                    case_file, source_path=source, source_pointer=f"/candidates/{index}", include_in_report=True
                )
                save_case_payload(case_file, case)
            manifest = build_submission_manifest(case, allowed_roots=[root])
            markdown = build_case_report_markdown(run_summary={}, case_payload=case, submission_manifest=manifest)
            html = Path(write_case_report_exports(markdown, root / "report.md")["html"]).read_text(encoding="utf-8")

            self.assertEqual(len(manifest["items"]), 3)
            for item in manifest["items"]:
                evidence = item["evidence"]
                expected = stat_iso[evidence["name"]]
                self.assertEqual(evidence["modified_at"], expected)
                self.assertEqual(evidence["modified_at_source"], "fresh-stat-st_mtime_ns")
                self.assertIn(expected, html)
            self.assertIn("2024-01-01T00:00:00.0000001+00:00", html)
            self.assertIn("2024-01-01T00:00:00.0000002+00:00", html)
            self.assertIn("2024-01-01T00:00:00.000001+00:00", html)


if __name__ == "__main__":
    unittest.main()
