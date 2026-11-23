"""D12: exported XML/JSONL event inputs keep their structure, locations and hashes.

- Same-named ``EventData/Data`` elements keep every value in document order.
- JSONL rows carry their physical line; unparsable lines are counted with
  their positions instead of disappearing.
- An unreadable export file is reported (file name, cause, missing rows)
  and counted as a parser error while its readable sibling keeps its rows.
- The triage projection links every event to an ``eventlog-file`` row that
  carries the export file's SHA-256.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows import eventlog
from rapidtriage.artifacts.windows.eventlog import WindowsEventLogProvider
from rapidtriage.core.artifacts import run_artifact_collection

LOGS = Path("Windows/System32/winevt/Logs")


def triage_rows(root: Path) -> list:
    return list(WindowsEventLogProvider(record_detail="triage", structure_rows=False).collect(root))


def of_type(rows: list, artifact_type: str) -> list[dict]:
    return [row.details for row in rows if row.artifact_type == artifact_type]


def xml_event(record_id: int, data: str = "") -> str:
    return (
        f"<Event><System><Provider Name=\"D12Fixture\"/><EventID>1</EventID><EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>Application</Channel></System><EventData>{data}</EventData></Event>"
    )


class EventlogExportCompletenessTests(unittest.TestCase):
    def test_xml_data_keeps_order_duplicates_and_unnamed_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = (
                '<Data Name="Item">alpha</Data><Data Name="Item">beta</Data><Data>gamma</Data>'
                '<Data Name="">delta</Data><Data Name="Other">x</Data>'
            )
            (root / "events.xml").write_text(f"<Events>{xml_event(1, data)}</Events>", encoding="utf-8")
            (event,) = of_type(triage_rows(root), "eventlog-event")
        self.assertEqual(
            event["event_data_items"],
            [
                {"name": "Item", "value": "alpha"},
                {"name": "Item", "value": "beta"},
                {"name": "", "value": "gamma"},
                {"name": "", "value": "delta"},
                {"name": "Other", "value": "x"},
            ],
        )
        self.assertEqual(event["event_data_duplicate_names"], ["Item"])

    def test_jsonl_rows_keep_physical_lines_and_failed_lines_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "events.jsonl"
            path.write_text(
                '{"EventID": 1, "EventRecordID": 1}\n{"EventID":\n{"EventID": 2, "EventRecordID": 3}\n',
                encoding="utf-8",
            )
            rows = triage_rows(root)
        events = of_type(rows, "eventlog-event")
        self.assertEqual([event["record_id"] for event in events], ["1", "3"])
        self.assertEqual([event["source_line_number"] for event in events], [1, 3])
        self.assertEqual([event["source_index"] for event in events], [0, 1])
        (file_row,) = of_type(rows, "eventlog-file")
        self.assertEqual(file_row["export_read_status"], "partial")
        self.assertEqual(file_row["export_row_count"], 2)
        self.assertEqual(file_row["export_failed_row_count"], 1)
        self.assertEqual(file_row["export_missing_row_count"], 1)
        self.assertEqual([item["line"] for item in file_row["export_failed_locations"]], [2])
        self.assertTrue(file_row["parser_error"])

    def test_unreadable_export_is_reported_and_sibling_rows_are_kept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / LOGS
            logs.mkdir(parents=True)
            unreadable, readable = logs / "events0.xml", logs / "events1.xml"
            unreadable.write_text(f"<Events>{xml_event(1)}</Events>", encoding="ascii")
            readable.write_text(f"<Events>{xml_event(2)}</Events>", encoding="ascii")
            parse = eventlog.safe_xml_parse

            def sharing_violation(path):
                if Path(path).name == unreadable.name:
                    raise PermissionError("synthetic sharing violation")
                return parse(path)

            with mock.patch.object(eventlog, "safe_xml_parse", side_effect=sharing_violation):
                payload = run_artifact_collection(root, kind="eventlog", use_cache=False)

        events = [row for row in payload["artifacts"] if row["artifact_type"] == "eventlog-event"]
        self.assertEqual([row["details"]["record_id"] for row in events], ["2"])
        self.assertEqual(payload["summary"]["parser_error_count"], 1)
        (error,) = payload["parser_errors"]
        self.assertTrue(error["path"].endswith("events0.xml"))
        self.assertEqual(error["error_type"], "PermissionError")
        self.assertIn("events0.xml", error["message"])
        self.assertIn("synthetic sharing violation", error["message"])
        self.assertIn("unknown number", error["message"])
        files = {
            Path(row["details"]["source_path"]).name: row["details"]
            for row in payload["artifacts"]
            if row["artifact_type"] == "eventlog-file"
        }
        self.assertEqual(files["events0.xml"]["export_read_status"], "unreadable")
        self.assertIsNone(files["events0.xml"]["export_missing_row_count"])
        self.assertEqual(files["events1.xml"]["export_read_status"], "complete")
        (summary,) = [row["details"] for row in payload["artifacts"] if row["artifact_type"] == "eventlog-summary"]
        self.assertEqual(summary["export_read_error_count"], 1)

    def test_triage_events_link_to_a_file_row_with_the_export_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "events.xml"
            path.write_text(f"<Events>{xml_event(1)}{xml_event(2)}</Events>", encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            rows = triage_rows(root)
        file_rows = {row["source_path"]: row for row in of_type(rows, "eventlog-file")}
        events = of_type(rows, "eventlog-event")
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertNotIn("source_hashes", event)
            self.assertEqual(file_rows[event["source_path"]]["source_hashes"]["sha256"], expected)
        self.assertEqual(next(iter(file_rows.values()))["export_read_status"], "complete")


if __name__ == "__main__":
    unittest.main()
