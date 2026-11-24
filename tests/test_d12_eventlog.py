"""D12 adversarial-review regressions for the Windows event-log provider.

Synthetic inputs only: EVTX bytes come from ``EvtxWriter`` (with header/chunk
CRCs filled in) and XML/JSON rows are written in-test.

* recovered (slack) records never close, time or extend live logon sessions or
  the summary time range; they are listed as recovery candidates with state,
  source file and offset;
* the trusted-tool record diff keys records by source file, channel, computer
  and record id and keeps duplicate rows;
* event times from mixed UTC offsets are ordered by an integer 100 ns UTC
  instant and keep their seventh fractional digit;
* an EVTX file shorter than its header-declared chunk range reports a partial
  chunk walk with the loss location.
"""

from __future__ import annotations

import datetime as dt
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from xml.etree import ElementTree as ET

from rapidtriage.artifacts.windows.eventlog import (
    WindowsEventLogProvider,
    build_evtx_trusted_tool_record_diff,
)
from rapidtriage.core.filetime import event_timestamp_utc_ticks
from rapidtriage.core.reporting import REPORT_DECISION_LIMIT, report_decision_lines
from tests.test_parser_quality_eventlog import (
    SECURITY,
    Event,
    EvtxWriter,
    filetime,
    wstr,
)

START = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
SECOND = 10_000_000
HEADER = 4096
CHUNK = 65536


def finalized(writer: EvtxWriter) -> bytes:
    """``writer`` bytes with chunk data/header CRCs and the file header CRC filled in."""
    data = bytearray(writer.file_bytes())
    last = 0
    for pos in range(HEADER, len(data), CHUNK):
        free = struct.unpack_from("<I", data, pos + 48)[0]
        last = max(last, struct.unpack_from("<Q", data, pos + 32)[0])
        struct.pack_into("<I", data, pos + 52, zlib.crc32(data[pos + 512 : pos + free]))
        struct.pack_into("<I", data, pos + 124, zlib.crc32(data[pos : pos + 120] + data[pos + 128 : pos + 512]))
    struct.pack_into("<Q", data, 24, last + 1)
    struct.pack_into("<I", data, 124, zlib.crc32(data[:120]))
    return bytes(data)


def session_event(record_id: int, event_id: int, when: int, *, user: str = "synthetic", logon_id: str = "0x12") -> Event:
    return Event(
        record_id=record_id,
        provider=SECURITY,
        event_id=event_id,
        channel="Security",
        when=when,
        computer="D12-SYNTH",
        data=[("TargetUserName", wstr(user)), ("TargetLogonId", wstr(logon_id))],
    )


def collect(root: Path) -> list:
    return list(WindowsEventLogProvider(record_detail="triage", structure_rows=False).collect(root))


def details_of(rows: list, artifact_type: str) -> list[dict]:
    return [row.details for row in rows if row.artifact_type == artifact_type]


def write_xml_events(path: Path, events: list[dict[str, object]]) -> None:
    root = ET.Element("Events")
    for index, spec in enumerate(events, 1):
        event = ET.SubElement(root, "Event")
        system = ET.SubElement(event, "System")
        ET.SubElement(system, "Provider", Name=str(spec.get("provider", "D12Fixture")))
        ET.SubElement(system, "EventID").text = str(spec.get("event_id", 1))
        ET.SubElement(system, "EventRecordID").text = str(spec.get("record_id", index))
        ET.SubElement(system, "Channel").text = str(spec.get("channel", "Application"))
        ET.SubElement(system, "Computer").text = "D12-SYNTH"
        ET.SubElement(system, "TimeCreated", SystemTime=str(spec["time"]))
        data = ET.SubElement(event, "EventData")
        for name, value in dict(spec.get("data", {"Item": "alpha"})).items():
            ET.SubElement(data, "Data", Name=name).text = value
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


class RecoveredRecordsStayOutOfLiveSessionsTests(unittest.TestCase):
    def collect_live_logon_with_slack_logoff(self) -> tuple[list, bytes]:
        writer = EvtxWriter()
        writer.build_chunk(
            [session_event(51, 4624, filetime(START, 7))],
            slack=[session_event(7, 4634, filetime(START, 7) + SECOND)],
        )
        raw = finalized(writer)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "events.evtx").write_bytes(raw)
            return collect(root), raw

    def test_slack_logoff_does_not_close_live_session(self) -> None:
        rows, _ = self.collect_live_logon_with_slack_logoff()
        events = {item["record_id"]: item for item in details_of(rows, "eventlog-event")}
        self.assertEqual(events["51"]["evtx_record_state"], "live")
        self.assertEqual(events["7"]["evtx_record_state"], "slack-recovered")

        session, = details_of(rows, "eventlog-logon-session")
        self.assertEqual(session["session_status"], "open-or-not-observed")
        self.assertEqual(session["ended_at"], "")
        self.assertIsNone(session["duration_seconds"])
        self.assertEqual(session["event_ids"], ["4624"])
        self.assertEqual([item["record_id"] for item in session["events"]], ["51"])
        self.assertEqual([item["evtx_record_state"] for item in session["events"]], ["live"])
        self.assertEqual(session["events"][0]["evtx_record_offset"], events["51"]["evtx_record_offset"])
        self.assertEqual(session["active_event_count"], 1)
        self.assertEqual(session["recovery_candidate_count"], 1)
        self.assertTrue(session["validation_checks"]["recovery_candidates_excluded"])
        candidate, = session["recovery_candidate_events"]
        self.assertEqual(candidate["record_id"], "7")
        self.assertEqual(candidate["event_id"], "4634")
        self.assertEqual(candidate["evtx_record_state"], "slack-recovered")
        self.assertEqual(candidate["evtx_record_offset"], events["7"]["evtx_record_offset"])
        self.assertEqual(candidate["source_path"], events["7"]["source_path"])
        self.assertEqual(session["recovery_candidate_state_counts"], [{"value": "slack-recovered", "count": 1}])

    def test_summary_time_range_uses_live_records_only(self) -> None:
        rows, _ = self.collect_live_logon_with_slack_logoff()
        events = {item["record_id"]: item for item in details_of(rows, "eventlog-event")}
        summary, = details_of(rows, "eventlog-summary")
        self.assertEqual(summary["first_event_at"], "2024-01-01T00:00:00+00:00")
        self.assertEqual(summary["last_event_at"], "2024-01-01T00:00:00+00:00")
        self.assertEqual(summary["last_event_at_100ns"], "2024-01-01T00:00:00.0000007Z")
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["active_event_count"], 1)
        self.assertEqual(summary["recovery_candidate_event_count"], 1)
        candidate, = summary["recovery_candidate_events"]
        self.assertEqual(
            (candidate["record_id"], candidate["evtx_record_state"], candidate["evtx_record_offset"], candidate["source_path"]),
            ("7", "slack-recovered", events["7"]["evtx_record_offset"], events["7"]["source_path"]),
        )
        self.assertEqual(candidate["timestamp_100ns"], "2024-01-01T00:00:01.0000007Z")

    def test_recovered_only_session_is_labelled_and_untimed(self) -> None:
        writer = EvtxWriter()
        writer.build_chunk(
            [session_event(60, 4624, filetime(START), user="live-user", logon_id="0x20")],
            slack=[
                session_event(8, 4624, filetime(START) + SECOND, user="old-user", logon_id="0x30"),
                session_event(9, 4634, filetime(START) + 2 * SECOND, user="old-user", logon_id="0x30"),
            ],
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "events.evtx").write_bytes(finalized(writer))
            rows = collect(root)
        sessions = {item["user_name"]: item for item in details_of(rows, "eventlog-logon-session")}
        recovered = sessions["old-user"]
        self.assertEqual(recovered["session_status"], "recovery-candidates-only")
        self.assertEqual((recovered["started_at"], recovered["ended_at"], recovered["timestamp"]), ("", "", ""))
        self.assertIsNone(recovered["duration_seconds"])
        self.assertEqual(recovered["events"], [])
        self.assertEqual([item["record_id"] for item in recovered["recovery_candidate_events"]], ["8", "9"])
        self.assertIn("recovery-candidates-only", recovered["risk_flags"])
        self.assertEqual(sessions["live-user"]["session_status"], "open-or-not-observed")
        self.assertEqual(sessions["live-user"]["recovery_candidate_count"], 0)

    def test_independent_reader_returns_only_the_live_record(self) -> None:
        try:
            from Evtx.Evtx import Evtx
        except ImportError as exc:
            raise unittest.SkipTest("python-evtx comparison reader unavailable") from exc
        rows, raw = self.collect_live_logon_with_slack_logoff()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.evtx"
            path.write_bytes(raw)
            with Evtx(str(path)) as reference:
                reference_ids = [record.record_num() for record in reference.records()]
        live_ids = [int(item["record_id"]) for item in details_of(rows, "eventlog-event") if item["evtx_record_state"] == "live"]
        self.assertEqual(reference_ids, live_ids)
        session, = details_of(rows, "eventlog-logon-session")
        self.assertEqual([int(item["record_id"]) for item in session["events"]], reference_ids)


class TrustedToolRecordDiffIdentityTests(unittest.TestCase):
    def test_same_record_id_in_two_channels_is_two_records(self) -> None:
        rapid = [
            {"record_id": "8", "channel": "SyntheticA", "event_id": "2"},
            {"record_id": "8", "channel": "SyntheticB", "event_id": "4"},
        ]
        diff = build_evtx_trusted_tool_record_diff(rapid, [rapid[1]], trusted_tool="Hayabusa")
        self.assertEqual(diff["rapid_input_row_count"], 2)
        self.assertEqual(diff["trusted_input_row_count"], 1)
        self.assertEqual(diff["rapid_record_count"], 2)
        self.assertEqual(diff["trusted_record_count"], 1)
        self.assertEqual(diff["record_key_fields"], ["channel", "record_id"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["missing_in_trusted_count"], 1)
        self.assertEqual(diff["missing_in_trusted"], ["8"])
        self.assertEqual(diff["missing_in_trusted_records"], [{"record_id": "8", "channel": "SyntheticA"}])
        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])

    def test_duplicate_rows_are_counted_separately(self) -> None:
        row = {"record_id": "5", "channel": "Security", "computer": "D12-SYNTH", "event_id": "4624"}
        diff = build_evtx_trusted_tool_record_diff([row, dict(row)], [dict(row)], trusted_tool="EvtxECmd")
        self.assertEqual(diff["rapid_record_count"], 2)
        self.assertEqual(diff["rapid_duplicate_key_row_count"], 1)
        self.assertEqual(diff["trusted_duplicate_key_row_count"], 0)
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["missing_in_trusted_count"], 1)
        self.assertEqual(diff["status"], "diffs-present")

        balanced = build_evtx_trusted_tool_record_diff([row, dict(row)], [dict(row), dict(row)], trusted_tool="EvtxECmd")
        self.assertEqual((balanced["matched_count"], balanced["status"]), (2, "pass"))
        self.assertTrue(balanced["commercial_grade_evidence"])

    def test_host_and_source_file_separate_records(self) -> None:
        rapid = [
            {"record_id": "1", "channel": "Security", "computer": "HOST-A", "source_path": "/case/a/Security.evtx", "event_id": "4624"},
            {"record_id": "1", "channel": "Security", "computer": "HOST-B", "source_path": "/case/b/Security.evtx", "event_id": "4625"},
            {"record_id": "1", "channel": "Security", "computer": "HOST-A", "source_path": "/case/a/Archive.evtx", "event_id": "4634"},
        ]
        trusted = [
            {"EventRecordID": "1", "record_id": "1", "log_name": "Security", "hostname": "host-a", "SourceFile": "C:\\x\\SECURITY.EVTX", "eventid": "4624"},
            {"record_id": "1", "log_name": "Security", "hostname": "HOST-B", "SourceFile": "C:\\y\\Security.evtx", "eventid": "4625"},
        ]
        diff = build_evtx_trusted_tool_record_diff(rapid, trusted, trusted_tool="EvtxECmd")
        self.assertEqual(diff["record_key_fields"], ["source_file", "channel", "computer", "record_id"])
        self.assertEqual(diff["missing_in_trusted_count"], 1)
        self.assertEqual(diff["missing_in_trusted_records"][0]["source_file"], "/case/a/Archive.evtx")
        self.assertEqual(diff["extra_in_trusted_count"], 0)
        # The host name case differs; the record still pairs and the field diff is reported.
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["record_identity"]["computer"], "HOST-A")
        self.assertEqual(diff["status"], "diffs-present")

    def test_rows_without_record_id_block_a_pass(self) -> None:
        row = {"record_id": "3", "channel": "System", "event_id": "7045"}
        diff = build_evtx_trusted_tool_record_diff([row, {"channel": "System", "event_id": "7036"}], [dict(row)], trusted_tool="Chainsaw")
        self.assertEqual(diff["rapid_unkeyed_row_count"], 1)
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])


class UtcInstantOrderingTests(unittest.TestCase):
    def test_parser_keeps_100ns_and_applies_offsets(self) -> None:
        base = filetime(START)
        self.assertEqual(event_timestamp_utc_ticks("2024-01-01T09:00:00.0000007+09:00"), (base + 7, "iso-offset"))
        self.assertEqual(event_timestamp_utc_ticks("2024-01-01T01:00:00.0000001Z"), (base + 3600 * SECOND + 1, "iso-offset"))
        self.assertEqual(event_timestamp_utc_ticks("2023-12-31T19:00:00.5-0500"), (base + SECOND // 2, "iso-offset"))
        self.assertEqual(event_timestamp_utc_ticks("2024-01-01 00:00:00.123456789"), (base + 1234567, "iso-no-offset-assumed-utc"))
        self.assertEqual(event_timestamp_utc_ticks("01/01/2024 00:00"), (None, "unparsed"))

    def test_mixed_offset_xml_events_order_by_utc_instant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_xml_events(
                root / "events.xml",
                [{"time": "2024-01-01T09:00:00.0000007+09:00"}, {"time": "2024-01-01T01:00:00.0000001Z"}],
            )
            rows = collect(root)
        events = {item["record_id"]: item for item in details_of(rows, "eventlog-event")}
        self.assertEqual(events["1"]["timestamp_original"], "2024-01-01T09:00:00.0000007+09:00")
        self.assertEqual(events["1"]["timestamp_100ns"], "2024-01-01T00:00:00.0000007Z")
        self.assertEqual(events["1"]["timestamp_utc_ticks"], filetime(START, 7))
        self.assertEqual(events["2"]["timestamp_original"], "2024-01-01T01:00:00.0000001Z")
        self.assertEqual(events["2"]["timestamp_100ns"], "2024-01-01T01:00:00.0000001Z")
        self.assertEqual(events["2"]["timestamp_utc_ticks"], filetime(START + dt.timedelta(hours=1), 1))
        summary, = details_of(rows, "eventlog-summary")
        self.assertEqual(summary["first_event_at"], events["1"]["timestamp"])
        self.assertEqual(summary["last_event_at"], events["2"]["timestamp"])
        self.assertEqual(summary["first_event_at_100ns"], "2024-01-01T00:00:00.0000007Z")
        self.assertEqual(summary["last_event_at_100ns"], "2024-01-01T01:00:00.0000001Z")

    def test_session_math_uses_utc_instant_across_offsets(self) -> None:
        logon = {"TargetUserName": "synthetic", "TargetLogonId": "0x44", "LogonType": "10"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_xml_events(
                root / "events.xml",
                [
                    {"provider": SECURITY, "channel": "Security", "event_id": 4624, "time": "2024-01-01T09:00:00.0000007+09:00", "data": logon},
                    {"provider": SECURITY, "channel": "Security", "event_id": 4634, "time": "2024-01-01T00:30:00.0000007Z", "data": logon},
                ],
            )
            rows = collect(root)
        session, = details_of(rows, "eventlog-logon-session")
        self.assertEqual(session["event_ids"], ["4624", "4634"])
        self.assertEqual(session["session_status"], "closed")
        self.assertEqual(session["duration_seconds"], 1800)
        self.assertEqual([item["timestamp_100ns"] for item in session["events"]], ["2024-01-01T00:00:00.0000007Z", "2024-01-01T00:30:00.0000007Z"])


class DeclaredChunkRangeTests(unittest.TestCase):
    def two_chunk_file(self) -> bytes:
        writer = EvtxWriter()
        writer.build_chunk([session_event(51, 4624, filetime(START))])
        writer.build_chunk([session_event(52, 4634, filetime(START) + SECOND)])
        return finalized(writer)

    def file_row(self, blob: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "events.evtx").write_bytes(blob)
            file_row, = details_of(collect(root), "eventlog-file")
        return file_row

    def test_intact_two_chunk_file_is_a_complete_walk(self) -> None:
        row = self.file_row(self.two_chunk_file())
        self.assertEqual(row["native_record_count"], 2)
        self.assertEqual(row["native_parse_status"], "complete-chunk-walk-decoded")
        self.assertFalse(row["native_records_truncated"])
        self.assertEqual(row["native_declared_chunk_count"], 2)
        self.assertEqual(row["native_missing_declared_chunk_count"], 0)
        self.assertEqual(row["native_chunk_walk_status"], "declared-range-complete")
        self.assertIsNone(row["native_first_missing_chunk_offset"])

    def test_missing_declared_chunk_is_a_partial_walk(self) -> None:
        row = self.file_row(self.two_chunk_file()[: HEADER + CHUNK])
        self.assertEqual(row["native_record_count"], 1)
        self.assertEqual(row["native_chunk_count"], 1)
        self.assertEqual(row["native_parse_status"], "partial-chunk-walk-decoded")
        self.assertTrue(row["native_records_truncated"])
        self.assertEqual(row["native_chunk_walk_status"], "declared-range-incomplete")
        self.assertEqual(row["native_missing_declared_chunk_count"], 1)
        self.assertEqual(row["native_first_missing_chunk_index"], 1)
        self.assertEqual(row["native_first_missing_chunk_offset"], HEADER + CHUNK)
        self.assertEqual(row["native_declared_end_offset"], HEADER + 2 * CHUNK)
        self.assertEqual(row["native_data_end_offset"], HEADER + CHUNK)
        self.assertEqual(row["native_missing_declared_byte_count"], CHUNK)
        self.assertIn("누락 청크 1개", row["native_truncation_note_ko"])

    def test_chunk_cut_mid_way_is_a_partial_walk(self) -> None:
        row = self.file_row(self.two_chunk_file()[: HEADER + CHUNK + 2048])
        self.assertTrue(row["native_records_truncated"])
        self.assertTrue(row["native_parse_status"].startswith("partial-chunk-walk"))
        self.assertEqual(row["native_missing_declared_chunk_count"], 0)
        self.assertEqual(row["native_short_active_chunk_count"], 1)
        self.assertEqual(row["native_missing_declared_byte_count"], CHUNK - 2048)


class RunReportDecisionCapTests(unittest.TestCase):
    """A truncation warning adds a processing decision; the report's 30-row cap must still show
    skips and warnings ahead of informational notices and count what it leaves out."""

    def test_notices_never_push_out_skips_or_loss_warnings(self) -> None:
        notices = [f"`artifacts-p{index}` notice: No p{index} artifact rows were collected." for index in range(40)]
        warning = "`artifacts-eventlog` warning: eventlog-file.native_records_truncated 1"
        skipped = "`docs-extract` status=`skipped` output=`out`."
        lines = report_decision_lines([*notices[:20], warning, *notices[20:], skipped])
        self.assertIn(f"- {warning}", lines)
        self.assertIn(f"- {skipped}", lines)
        self.assertEqual(len(lines), REPORT_DECISION_LIMIT + 1)
        self.assertEqual(lines[-1].split()[2], "12")
        self.assertEqual(report_decision_lines(["a", "b"]), ["- a", "- b"])


if __name__ == "__main__":
    unittest.main()
