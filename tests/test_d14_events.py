"""D14 adversarial review: event/time/export/completeness findings 1, 7, 12, 13, 15, 16, 17.

Every fixture is synthetic and built in-test (no case data). Item numbers refer to the D14
review table "신규 및 잔존 발견"; items 8 and 11 (selection CSV / FILETIME tooltip) are pinned
by the frontend test ``frontend/src/utils/d14Time.test.ts``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows import browser
from rapidtriage.artifacts.windows.execution import collect_srum_dat_inventory
from rapidtriage.artifacts.windows.recent_files import (
    MAX_OLE_STREAM_BYTES,
    RECENT_ROOT,
    WindowsRecentFilesProvider,
)
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.case_export import export_case_uco_jsonld
from rapidtriage.core.run.incremental_indexing import (
    build_run_evidence_identity,
    build_run_input_fingerprint,
    incremental_fingerprints_equivalent,
)
from rapidtriage.core.timeline import (
    TimelineBuilder,
    TimelineStats,
    event_sort_key,
    extract_artifact_events,
    write_timeline_result,
)
from rapidtriage.core.timeline_export import build_unified_timeline_export
from tests.test_d12_eventlog import (
    SECOND,
    START,
    collect,
    details_of,
    finalized,
    session_event,
)
from tests.test_parser_quality_eventlog import EvtxWriter, filetime
from tests.test_rapidtriage_case_export import _build_case_db
from tests.windows_artifact_fixtures import (
    build_minimal_ese_database_with_lv,
    cfb_directory_entry,
)


def eventlog_timeline(rows: list, root: Path) -> list[dict]:
    builder = TimelineBuilder(TimelineStats())
    builder.extend(extract_artifact_events({"kind": "eventlog", "artifacts": [row.to_dict() for row in rows]}, root))
    return sorted(builder.events(), key=event_sort_key)


class SlackLogoffIsARecoveryCandidateTests(unittest.TestCase):
    """#1: a slack-recovered logoff never appears as a normal timeline event or live count."""

    def setUp(self) -> None:
        writer = EvtxWriter()
        writer.build_chunk(
            [session_event(51, 4624, filetime(START, 7))],
            slack=[session_event(7, 4634, filetime(START, 7) + SECOND)],
        )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "events.evtx").write_bytes(finalized(writer))
        self.rows = collect(self.root)

    def test_summary_states_live_and_candidate_counts_apart(self) -> None:
        summary, = details_of(self.rows, "eventlog-summary")
        self.assertEqual(summary["live_event_count"], 1)
        self.assertEqual(summary["recovery_candidate_event_count"], 1)
        self.assertEqual(summary["event_count"], 2)
        self.assertEqual(summary["event_count_scope"], "live-and-recovery-candidate-rows")
        self.assertEqual(summary["event_id_counts"], [{"value": "4624", "count": 1}])
        self.assertEqual(summary["recovery_candidate_event_id_counts"], [{"value": "4634", "count": 1}])

    def test_timeline_marks_the_slack_logoff_with_state_and_offset(self) -> None:
        raw = {row["record_id"]: row for row in details_of(self.rows, "eventlog-event")}
        events = eventlog_timeline(self.rows, self.root)
        live = [event for event in events if not event["details"].get("recovery_candidate")]
        candidates = [event for event in events if event["details"].get("recovery_candidate")]
        self.assertEqual([event["details"]["record_id"] for event in live], ["51"])
        self.assertEqual([event["details"]["record_id"] for event in candidates], ["7"])
        candidate = candidates[0]
        self.assertEqual(candidate["event_type"], "eventlog-recovery-candidate")
        self.assertEqual(candidate["details"]["record_state"], "slack-recovered")
        self.assertEqual(candidate["details"]["record_offset"], raw["7"]["evtx_record_offset"])
        self.assertIn("recovery candidate", candidate["summary"])
        self.assertNotIn("logoff", live[0]["event_type"])
        self.assertEqual(live[0]["event_type"], "eventlog-logon-success")
        self.assertEqual(live[0]["details"]["record_state"], "live")

    def test_timeline_export_carries_the_candidate_state(self) -> None:
        events = eventlog_timeline(self.rows, self.root)
        timeline = self.root / "timeline.json"
        write_timeline_result({"command": "timeline", "events": events}, timeline)
        summary = self.root / "run-summary.json"
        summary.write_text(json.dumps({"outputs": {"timeline": str(timeline)}}), encoding="utf-8")
        exported = build_unified_timeline_export(summary)
        by_record = {event["details"]["record_id"]: event for event in exported["events"]}
        self.assertTrue(by_record["7"]["details"]["recovery_candidate"])
        self.assertEqual(by_record["7"]["details"]["record_state"], "slack-recovered")
        self.assertNotIn("recovery_candidate", by_record["51"]["details"])


class HundredNanosecondTimelineOrderTests(unittest.TestCase):
    """#7: derived timeline and timeline-export order by integer 100 ns ticks, 7 digits kept."""

    def test_six_hundred_nanoseconds_apart_keep_order_and_digits(self) -> None:
        writer = EvtxWriter()
        writer.build_chunk([session_event(50, 4624, filetime(START, 7)), session_event(51, 4624, filetime(START, 1))])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "events.evtx").write_bytes(finalized(writer))
            events = eventlog_timeline(collect(root), root)
            self.assertEqual(
                [(event["details"]["record_id"], event["timestamp"]) for event in events],
                [("51", "2024-01-01T00:00:00.0000001+00:00"), ("50", "2024-01-01T00:00:00.0000007+00:00")],
            )
            self.assertEqual(
                [event["details"]["timestamp_utc_ticks"] for event in events],
                [str(filetime(START, 1)), str(filetime(START, 7))],
            )
            timeline = root / "timeline.json"
            # Written in source order: the export must re-order by ticks itself.
            write_timeline_result({"command": "timeline", "events": events[::-1]}, timeline)
            summary = root / "run-summary.json"
            summary.write_text(json.dumps({"outputs": {"timeline": str(timeline)}}), encoding="utf-8")
            exported = build_unified_timeline_export(summary)
            self.assertEqual([event["details"]["record_id"] for event in exported["events"]], ["51", "50"])
            self.assertEqual(exported["summary"]["earliest_event_at"], "2024-01-01T00:00:00.0000001+00:00")
            # Range bounds compare as ticks too: a bound between the two keeps only #50.
            between = build_unified_timeline_export(summary, start="2024-01-01T00:00:00.0000005Z")
            self.assertEqual([event["details"]["record_id"] for event in between["events"]], ["50"])
            up_to = build_unified_timeline_export(summary, end="2024-01-01T00:00:00.0000005Z")
            self.assertEqual([event["details"]["record_id"] for event in up_to["events"]], ["51"])


def destlist_v4(declared: int, present: int) -> bytes:
    """DestList v4 header declaring ``declared`` entries followed by ``present`` entries."""
    header = bytearray(32)
    struct.pack_into("<IIIII", header, 0, 4, declared, 0, 0, declared)
    entries = []
    for index in range(1, present + 1):
        path = rf"C:\sample\item-{index:05}.txt"
        entry = bytearray(0x82)
        struct.pack_into("<Q", entry, 0x58, index)
        struct.pack_into("<Qi", entry, 0x64, 133513093240000000, -1)
        struct.pack_into("<H", entry, 0x80, len(path))
        entries.append(bytes(entry) + path.encode("utf-16le") + bytes(4))
    return bytes(header) + b"".join(entries)


def cfb_v4(payload: bytes) -> bytes:
    """CFB v4 (4096-byte sectors) holding one regular ``DestList`` stream of any size."""
    size, end, free, fat_id = 4096, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    sectors = (len(payload) + size - 1) // size
    fats = 1
    while fats * (size // 4) < sectors + fats + 1:
        fats += 1
    assert fats <= 109
    directory_sid, payload_sid = fats, fats + 1
    header = bytearray(size)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<5H", header, 24, 0x3E, 4, 0xFFFE, 12, 6)
    struct.pack_into("<9I", header, 40, 1, fats, directory_sid, 0, 4096, end, 0, end, 0)
    struct.pack_into("<109I", header, 76, *range(fats), *([free] * (109 - fats)))
    chain = [fat_id] * fats + [end] + list(range(payload_sid + 1, payload_sid + sectors)) + [end]
    fat = struct.pack(f"<{len(chain)}I", *chain).ljust(fats * size, b"\xff")
    directory = cfb_directory_entry("Root Entry", 5, child_id=1, start_sector=end)
    directory += cfb_directory_entry("DestList", 2, start_sector=payload_sid, stream_size=len(payload))
    return bytes(header) + fat + directory.ljust(size, b"\0") + payload.ljust(sectors * size, b"\0")


def collect_jumplist(container: bytes) -> tuple[dict, list[dict]]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        folder = root.joinpath("Users", "sample", *RECENT_ROOT, "AutomaticDestinations")
        folder.mkdir(parents=True)
        (folder / "0000000000000001.automaticDestinations-ms").write_bytes(container)
        rows = list(WindowsRecentFilesProvider().collect(root))
    header = next(row.details for row in rows if row.artifact_type == "jumplist-automatic")
    entries = [row.details for row in rows if row.artifact_type == "jumplist-entry"]
    return header, entries


class LargeDestListTests(unittest.TestCase):
    """#12: a v4 DestList past the 8 MiB OLE parse cap is parsed whole, or reported partial."""

    def test_fifty_thousand_entries_are_all_parsed_and_reconciled(self) -> None:
        payload = destlist_v4(50_000, 50_000)
        self.assertGreater(len(payload), MAX_OLE_STREAM_BYTES)
        header, entries = collect_jumplist(cfb_v4(payload))
        stream, = header["ole_streams"]
        self.assertEqual(stream["parsed_bytes"], len(payload))
        self.assertEqual(stream["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(header["destlist_declared_entry_count"], 50_000)
        self.assertEqual(header["destlist_parsed_entry_count"], 50_000)
        self.assertEqual(header["destlist_unparsed_entry_count"], 0)
        self.assertEqual(header["destlist_entry_coverage"], "complete")
        self.assertEqual(len(entries), 50_000)
        self.assertEqual(
            {(entry["destlist_entry_number"], entry["destlist_path"]) for entry in entries},
            {(index, rf"C:\sample\item-{index:05}.txt") for index in range(1, 50_001)},
        )

    def test_missing_declared_entries_are_reported_as_partial(self) -> None:
        header, entries = collect_jumplist(cfb_v4(destlist_v4(40, 32).ljust(4096, b"\0")))
        self.assertEqual(len(entries), 32)
        self.assertEqual(header["destlist_declared_entry_count"], 40)
        self.assertEqual(header["destlist_unparsed_entry_count"], 8)
        self.assertEqual(header["destlist_entry_coverage"], "partial")


class UnreadableEseLongValueTests(unittest.TestCase):
    """#13: an unreadable separated long value is unknown, its reference key kept apart."""

    def srum_row(self, cut: int) -> dict:
        complete = build_minimal_ese_database_with_lv(lv_chunks=[b"column-value"])
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "SRUDB.dat").write_bytes(complete[: len(complete) - cut])
            records = list(collect_srum_dat_inventory(folder))
        return next(record.details for record in records if record.artifact_type == "srum-schema-row")

    def test_control_resolves_the_long_value(self) -> None:
        row = self.srum_row(0)
        self.assertEqual(row["row_fields"]["Blob"]["hex"], b"column-value".hex())
        self.assertEqual(row["unreadable_fields"], {})
        self.assertFalse(row["validation_checks"]["requires_unreadable_value_review"])

    def test_lost_long_value_page_leaves_the_value_unknown(self) -> None:
        for label, cut in (("page-missing", 4096), ("page-short", 1)):
            with self.subTest(label):
                row = self.srum_row(cut)
                self.assertEqual(row["row_fields"]["Counter"], 42)
                self.assertEqual(row["row_fields"]["Label"], "hello")
                self.assertNotIn("Blob", row["row_fields"])
                blob = row["unreadable_fields"]["Blob"]
                self.assertEqual(blob["status"], "long-value-unreadable")
                self.assertEqual(blob["long_value_reference_keys_hex"], ["01020304"])
                self.assertTrue(blob["unreadable_pages"])
                self.assertIn("Blob:lv-key-unresolved", row["decode_markers"])
                self.assertTrue(row["validation_checks"]["has_long_value_marker"])
                self.assertTrue(row["validation_checks"]["requires_unreadable_value_review"])


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CaseUcoExportReceiptTests(unittest.TestCase):
    """#15: the CASE/UCO export records generator version, applied limits and output hashes."""

    def test_receipt_lets_a_recipient_check_output_and_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "case.db"
            _build_case_db(db_path)
            database = open_case_database(db_path)
            for max_rows, truncated in ((1, True), (100_000, False)):
                with self.subTest(max_rows=max_rows):
                    payload = export_case_uco_jsonld(database, case_id="CASE-UCO-1", max_rows=max_rows)
                    output = Path(payload["output"])
                    receipt_path = Path(payload["receipt"])
                    self.assertEqual(receipt_path.parent, output.parent)
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    self.assertEqual(receipt["generator"]["name"], "rapidtriage")
                    self.assertTrue(receipt["generator"]["version"])
                    self.assertEqual(len(receipt["generator"]["build_module_sha256"]), 64)
                    self.assertEqual(receipt["options"]["max_rows_requested"], max_rows)
                    self.assertEqual(receipt["options"]["max_rows_per_table"], max_rows)
                    self.assertEqual(receipt["truncated"], truncated)
                    self.assertEqual(receipt["output"]["sha256"], sha256_file(output))
                    self.assertEqual(receipt["output"]["size_bytes"], output.stat().st_size)
                    self.assertEqual(payload["output_sha256"], sha256_file(output))
                    self.assertEqual(payload["receipt_sha256"], sha256_file(receipt_path))
                    document = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(
                        document["rapidtriage:exportSummary"]["applied_limits"]["max_rows_per_table"], max_rows
                    )


class BrowserLinkTransitionTests(unittest.TestCase):
    """#16: Chromium transition 0 (LINK) is not NULL in the latest-visit summary."""

    def test_zero_one_and_null_stay_distinct(self) -> None:
        _name, parts = browser.CHROMIUM_BROWSER_ROOTS[0]
        stamp = 13350000000123457
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root.joinpath("Users", "sample", *parts, "Default")
            profile.mkdir(parents=True)
            connection = sqlite3.connect(profile / "History")
            try:
                connection.executescript(
                    """
                    CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                                      typed_count INTEGER, last_visit_time INTEGER);
                    CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                                        transition INTEGER, visit_duration INTEGER);
                    """
                )
                for url_id, transition in ((1, 0), (2, 1), (3, None)):
                    connection.execute(
                        "INSERT INTO urls VALUES(?,?,?,1,0,?)",
                        (url_id, f"https://example.test/{url_id}", f"page {url_id}", stamp + url_id),
                    )
                    connection.execute(
                        "INSERT INTO visits VALUES(?,?,?,?,100)", (10 + url_id, url_id, stamp + url_id, transition)
                    )
                connection.commit()
            finally:
                connection.close()
            records = list(browser.WindowsBrowserArtifactsProvider().collect(root))
        aggregate = next(record.details for record in records if record.artifact_type == "browser-history-downloads")
        latest = {row["url"]: (row["transition"], row["transition_core"]) for row in aggregate["unified_timeline"]}
        self.assertEqual(latest["https://example.test/1"], ("0", "LINK"))
        self.assertEqual(latest["https://example.test/2"], ("1", "TYPED"))
        self.assertEqual(latest["https://example.test/3"], ("", ""))
        visits = {
            record.details["source_row_id"]: record.details["transition_core"]
            for record in records
            if record.artifact_type == "browser-visit"
        }
        self.assertEqual(visits, {11: "LINK", 12: "TYPED", 13: ""})


class FingerprintFileLimitBoundaryTests(unittest.TestCase):
    """#17: exactly max_files files is a complete scan; one more file is truncated."""

    def fingerprint(self, count: int) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(count):
                (root / f"sample-{index:04}.txt").touch()
            identity = build_run_evidence_identity(str(root), input_kind="folder", scan_root=root)
            return build_run_input_fingerprint(root, evidence_identity=identity)

    def test_five_thousand_files_are_complete_and_reusable(self) -> None:
        fingerprint = self.fingerprint(5000)
        self.assertEqual(fingerprint["summary"]["max_files"], 5000)
        self.assertEqual(fingerprint["summary"]["scanned_file_count"], 5000)
        self.assertFalse(fingerprint["summary"]["truncated"])
        self.assertTrue(incremental_fingerprints_equivalent(fingerprint, fingerprint))

    def test_five_thousand_and_one_files_are_truncated(self) -> None:
        fingerprint = self.fingerprint(5001)
        self.assertEqual(fingerprint["summary"]["scanned_file_count"], 5000)
        self.assertTrue(fingerprint["summary"]["truncated"])
        self.assertFalse(incremental_fingerprints_equivalent(fingerprint, fingerprint))


if __name__ == "__main__":
    unittest.main()
