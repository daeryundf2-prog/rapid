"""D16 review: resume, receipt, browser, RDP, task, Defender and history regressions.

- A resumed run fingerprints the whole input root the artifact providers read,
  so a revised event log outside the profile's scan scope is collected again
  (item 1).
- Browser timeline comparison carries the acquisition identity (source
  SHA-256/path and SQLite row id): two copies of one acquisition's row no
  longer pass for the same visit from two acquisitions (item 3, D14-2).
- An RDP logon whose address sits in XML UserData/EventXML classifies like the
  native EVTX row; LOCAL stays local and a missing address is undetermined
  (item 7).
- The scheduled-task summary is one Exec action, never a splice of two
  (item 8).
- The run audit lists the case DB, input fingerprint, checkpoints, columnar
  outputs and every other file in the output folder (item 15, D14-9).
- The run audit records every setting and the known-good feed revision; a
  replay from the audit reproduces the run and stops before starting when the
  feed was revised (item 16).
- Firefox visit citations resolve to the places.sqlite + WAL file set
  (item 17, D14-14).
- ActivitiesCache rows read from the WAL cite the WAL bytes (item 18).
- Defender MPLog summary counts cover every line (item 22).
- PSReadLine multi-line commands stay one history entry (item 23).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rapidtriage.artifacts.windows import browser, eventlog, execution, system
from rapidtriage.cli import main
from tests.test_d12_eventlog import collect, finalized
from tests.test_d14_artefacts import (
    URL,
    WEBKIT_STAMP,
    build_wal_only_history,
    read_json,
    sha256,
)
from tests.test_parser_quality_eventlog import Event, EvtxWriter, wstr

RUN_ARGS = ["--mode", "seizure", "--read-only", "--skip-group", "messaging", "--skip-group", "mobile"]


def run_cli(root: Path, output_dir: Path, *extra: str) -> None:
    args = ["run", str(root), "--output-dir", str(output_dir), *extra]
    if main(args) != 0:
        raise AssertionError(f"run failed: {args}")


def eventlog_record_ids(output_dir: Path) -> list[str]:
    summary = output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.json"
    rows_path = summary.parent / read_json(summary)["records_file"]
    rows = [json.loads(line) for line in rows_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [str(row["details"]["record_id"]) for row in rows if row["artifact_type"] == "eventlog-event"]


class ResumeInputScopeTests(unittest.TestCase):
    def test_revised_log_outside_scan_scope_is_collected_again_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "input"
            (source / "Users" / "sample").mkdir(parents=True)
            (source / "Users" / "sample" / "note.txt").write_text("synthetic document", encoding="utf-8")
            logs = source / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            export = logs / "events.xml"

            def write_event(record_id: int) -> None:
                export.write_text(
                    "<Events><Event><System><EventID>42</EventID>"
                    f"<EventRecordID>{record_id}</EventRecordID><Channel>System</Channel>"
                    "</System></Event></Events>",
                    encoding="utf-8",
                )

            write_event(11)
            output = base / "output"
            run_cli(source, output, *RUN_ARGS, "--no-case-db")
            self.assertEqual(eventlog_record_ids(output), ["11"])
            fingerprinted = [row["relative_path"] for row in read_json(output / "rapidtriage-run-fingerprint.json")["files"]]
            self.assertIn("Windows/System32/winevt/Logs/events.xml", fingerprinted)

            write_event(123)
            run_cli(source, output, *RUN_ARGS, "--no-case-db", "--resume")
            self.assertEqual(eventlog_record_ids(output), ["123"])
            summary = read_json(output / "rapidtriage-run-summary.json")
            self.assertNotIn("artifacts-eventlog", summary["safety"]["reused_outputs"])

            fresh = base / "fresh"
            run_cli(source, fresh, *RUN_ARGS, "--no-case-db")
            self.assertEqual(eventlog_record_ids(fresh), ["123"])

    def test_unchanged_input_is_still_reused_on_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "input"
            (source / "Users" / "sample").mkdir(parents=True)
            (source / "Users" / "sample" / "note.txt").write_text("synthetic document", encoding="utf-8")
            output = Path(temp) / "output"
            run_cli(source, output, *RUN_ARGS, "--no-case-db")
            run_cli(source, output, *RUN_ARGS, "--no-case-db", "--resume")
            summary = read_json(output / "rapidtriage-run-summary.json")
            self.assertIn("artifacts-eventlog", summary["safety"]["reused_outputs"])


def browser_aggregate(root: Path) -> dict:
    records = list(browser.WindowsBrowserArtifactsProvider().collect(root))
    return next(r.details for r in records if r.artifact_type == "browser-history-downloads")


class BrowserAcquisitionIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for tag in ("A", "B"):
            (self.root / tag).mkdir()
            build_wal_only_history(self.root / tag, ("profile-a",))
        database = next((self.root / "B" / "inputs").rglob("History"))
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE urls SET id=2 WHERE id=1")
            connection.execute("UPDATE visits SET url=2 WHERE url=1")
            connection.commit()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def oracle(self, tag: str, *, with_sha: bool = False) -> dict:
        """Independent SQLite read of a copy of acquisition ``tag``."""
        database = next((self.root / tag / "inputs").rglob("History"))
        copy = self.root / f"oracle-{tag}"
        shutil.copytree(database.parent, copy, dirs_exist_ok=True)
        with closing(sqlite3.connect(copy / "History")) as connection:
            row_id, url, title, visits, stamp = connection.execute(
                "SELECT id, url, title, visit_count, last_visit_time FROM urls"
            ).fetchone()
        row = {
            "user": "profile-a",
            "browser": "chrome",
            "profile": "Default",
            "timeline_type": "visit",
            "url": url,
            "title": title,
            "visit_count": visits,
            "source_table": "urls",
            "source_index": 0,
            "source_row_id": row_id,
            "source_path": str(database.resolve()),
            "timestamp": (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=stamp)).isoformat(),
        }
        if with_sha:
            row["source_sha256"] = sha256(database)
        return row

    def diff(self, rapid: list[dict], trusted: list[dict]) -> tuple[str, bool]:
        result = browser.build_browser_timeline_trusted_diff(rapid, trusted, trusted_tool="sqlite")
        return result["status"], result["commercial_grade_evidence"]

    def test_one_acquisition_twice_does_not_pass_for_two_acquisitions(self) -> None:
        a = browser_aggregate(self.root / "A" / "inputs")["unified_timeline"][0]
        b = browser_aggregate(self.root / "B" / "inputs")["unified_timeline"][0]
        oracle_a, oracle_b = self.oracle("A"), self.oracle("B")
        self.assertEqual(self.diff([a, a], [oracle_a, oracle_b]), ("diffs-present", False))
        self.assertEqual(self.diff([a], [oracle_b]), ("diffs-present", False))
        self.assertEqual(self.diff([a, b], [oracle_a, oracle_b]), ("pass", True))
        self.assertEqual(self.diff([b, a], [oracle_a, oracle_b]), ("pass", True))

    def test_relocated_copy_of_one_acquisition_matches_by_sha256(self) -> None:
        relocated = self.root / "relocated"
        shutil.copytree(self.root / "A" / "inputs", relocated)
        moved = browser_aggregate(relocated)["unified_timeline"][0]
        result = browser.build_browser_timeline_trusted_diff(
            [moved], [self.oracle("A", with_sha=True)], trusted_tool="sqlite"
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["acquisition_identity"]["compared_by_sha256"], 1)
        other = browser.build_browser_timeline_trusted_diff(
            [moved], [{**self.oracle("B", with_sha=True), "source_row_id": 1}], trusted_tool="sqlite"
        )
        self.assertEqual(other["status"], "diffs-present")

    def test_rows_without_acquisition_mapping_are_reported_unresolved(self) -> None:
        row = {"browser": "chrome", "profile": "Default", "timestamp": "2024-04-01T09:10:11+00:00", "url": URL}
        result = browser.build_browser_timeline_trusted_diff([row], [dict(row)], trusted_tool="sqlite")
        self.assertEqual(result["acquisition_identity"]["status"], "acquisition-identity-unresolved")
        self.assertEqual(result["acquisition_identity"]["unresolved_count"], 1)


class FirefoxWalCitationTests(unittest.TestCase):
    def test_summary_citation_resolves_to_database_and_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "inputs"
            database = root.joinpath("Users", "profile-a", *browser.FIREFOX_PROFILE_ROOT, "Default", "places.sqlite")
            database.parent.mkdir(parents=True)
            writer = Path(temp) / "writer"
            with closing(sqlite3.connect(writer)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.executescript(
                    "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);"
                    "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER,"
                    " visit_type INTEGER);"
                )
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                stamp = WEBKIT_STAMP - 11644473600000000
                connection.execute("INSERT INTO moz_places VALUES(1,?,?,2)", (URL, "manual"))
                connection.executemany(
                    "INSERT INTO moz_historyvisits VALUES(?,1,?,1)", [(11, stamp - 1000), (12, stamp)]
                )
                connection.commit()
                for suffix in ("", "-wal"):
                    shutil.copyfile(str(writer) + suffix, str(database) + suffix)
            with closing(sqlite3.connect(f"{database.as_uri()}?immutable=1", uri=True)) as base_only:
                self.assertEqual(base_only.execute("SELECT COUNT(*) FROM moz_historyvisits").fetchone()[0], 0)
            expected = {name: sha256(database.parent / name) for name in ("places.sqlite", "places.sqlite-wal")}

            records = list(browser.WindowsBrowserArtifactsProvider().collect(root))
            aggregate = next(
                r.details
                for r in records
                if r.artifact_type in {"browser-history-downloads", "browser-history"} and r.details["browser"] == "firefox"
            )
            manifest = aggregate["browser_history_download_citation_manifest"]
            snapshots = {item["snapshot_id"]: item for item in manifest["source_snapshots"]}
            self.assertEqual(len(snapshots), 1)
            visits = [r.details for r in records if r.artifact_type == "browser-visit" and r.details["browser"] == "firefox"]
            self.assertEqual(sorted(v["source_row_id"] for v in visits), [11, 12])
            for item in [*manifest["history_citations"], *visits]:
                snapshot = snapshots[item["source_snapshot_id"]]
                self.assertEqual({f["name"]: f["sha256"] for f in snapshot["files"]}, expected)


class ActivitiesWalCitationTests(unittest.TestCase):
    def test_wal_only_rows_cite_the_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            database = root.joinpath(
                "Users", "profile-a", "AppData", "Local", "ConnectedDevicesPlatform", "sample", "ActivitiesCache.db"
            )
            database.parent.mkdir(parents=True)
            writer = Path(temp) / "writer"
            with closing(sqlite3.connect(writer)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.execute(
                    "CREATE TABLE Activity(Id INTEGER PRIMARY KEY, AppId TEXT, StartTime INTEGER,"
                    " ExpirationTime INTEGER, Payload TEXT)"
                )
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                connection.executemany(
                    "INSERT INTO Activity VALUES(?, 'sample-app', ?, 1800000000, 'fixture')",
                    [(n, 1704067200 + n) for n in range(1, 4)],
                )
                connection.commit()
                for suffix in ("", "-wal"):
                    shutil.copyfile(str(writer) + suffix, str(database) + suffix)
            wal = Path(str(database) + "-wal")
            with closing(sqlite3.connect(f"{database.as_uri()}?immutable=1", uri=True)) as base_only:
                self.assertEqual(base_only.execute("SELECT COUNT(*) FROM Activity").fetchone()[0], 0)
            expected = {"ActivitiesCache.db": sha256(database), "ActivitiesCache.db-wal": sha256(wal)}

            rows = [
                r.details
                for r in system.collect_activity_notification_uwp_artifacts(root)
                if r.artifact_type == "activities-cache-row-candidate"
            ]
            self.assertEqual(sorted(row["rowid"] for row in rows), [1, 2, 3])
            for row in rows:
                cited = {item["name"]: item["sha256"] for item in row["source_locator"]["source_snapshot_files"]}
                self.assertEqual(cited, expected)
                self.assertTrue(row["source_locator"]["source_snapshot_id"])
                self.assertEqual(row["source_snapshot_id"], row["source_locator"]["source_snapshot_id"])


LSM = eventlog.PROVIDER_TERMINAL_LSM


def xml_logon(record_id: int, body: str) -> str:
    return (
        f'<Event><System><Provider Name="{LSM}"/><EventID>21</EventID><EventRecordID>{record_id}</EventRecordID>'
        f'<Channel>{LSM}/Operational</Channel><TimeCreated SystemTime="2024-01-01T00:00:00Z"/></System>{body}</Event>'
    )


class RdpUserDataAddressTests(unittest.TestCase):
    def test_xml_and_native_evtx_classify_the_same_logon_alike(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            events = [
                xml_logon(1, '<EventData><Data Name="Address">192.0.2.1</Data></EventData>'),
                xml_logon(
                    2,
                    "<UserData><EventXML><User>profile-a</User><SessionID>2</SessionID>"
                    "<Address>192.0.2.1</Address></EventXML></UserData>",
                ),
                xml_logon(3, "<UserData><EventXML><Address>LOCAL</Address></EventXML></UserData>"),
                xml_logon(4, "<UserData><EventXML><User>profile-a</User></EventXML></UserData>"),
            ]
            export = root / "Events.xml"
            export.write_text("<Events>" + "".join(events) + "</Events>", encoding="utf-8")
            categories = {
                r.details["record_id"]: r.details["event_category"] for r in eventlog.collect_xml_events(export)
            }
            self.assertEqual(
                categories,
                {"1": "rdp-session-logon", "2": "rdp-session-logon", "3": "local-session-logon", "4": "terminal-session-logon"},
            )
            row = next(r.details for r in eventlog.collect_xml_events(export) if r.details["record_id"] == "2")
            self.assertEqual(row["data"]["UserData.Address.4"], "192.0.2.1")
            self.assertEqual(row["data"]["Address"], "192.0.2.1")

            writer = EvtxWriter()
            writer.build_chunk(
                [
                    Event(
                        record_id=2,
                        provider=LSM,
                        event_id=21,
                        channel=LSM + "/Operational",
                        when=133485408000000000,
                        user_data=(
                            "EventXML",
                            [("User", wstr("profile-a")), ("SessionID", wstr("2")), ("Address", wstr("192.0.2.1"))],
                        ),
                    )
                ]
            )
            native_dir = root / "native"
            native_dir.mkdir()
            (native_dir / "events.evtx").write_bytes(finalized(writer))
            native = next(r.details for r in collect(native_dir) if r.artifact_type == "eventlog-event")
            self.assertEqual(native["event_category"], categories["2"])

    def test_missing_address_is_neither_remote_nor_local(self) -> None:
        category, description = eventlog.event_category_for("21", f"{LSM}/Operational", LSM, {})
        self.assertEqual(category, "terminal-session-logon")
        self.assertIn("origin not recorded", description)
        self.assertIn(category, eventlog.EVENT_CATEGORY_LABELS_KO)
        self.assertIn(category, eventlog.EVENT_FAMILY_BY_CATEGORY)


class TaskActionSummaryTests(unittest.TestCase):
    def test_summary_is_one_exec_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root.joinpath(*system.TASKS_ROOT, "fixture")
            path.parent.mkdir(parents=True)
            xml = (
                '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions>'
                "<Exec><Command>viewer-one.exe</Command></Exec>"
                "<Exec><Command>viewer-two.exe</Command><Arguments>sample.txt</Arguments>"
                "<WorkingDirectory>C:\\work</WorkingDirectory></Exec>"
                "</Actions></Task>"
            )
            path.write_bytes(xml.encode("utf-16"))
            (task,) = system.collect_task_scheduler(root)
            details = task.details
            actions = [action["command_line"] for action in details["actions"]]
            self.assertEqual(actions, ["viewer-one.exe", "viewer-two.exe sample.txt"])
            self.assertEqual(details["command_line"], "viewer-one.exe")
            self.assertEqual((details["arguments"], details["working_directory"]), ("", ""))
            self.assertEqual(details["actions"][1]["working_directory"], "C:\\work")


class DefenderLogCountTests(unittest.TestCase):
    def test_marker_after_line_400_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            support = root.joinpath(*system.DEFENDER_SUPPORT_ROOT)
            support.mkdir(parents=True)
            for count in (400, 401):
                lines = ["Routine scan status"] * (count - 1) + ["Threat test fixture"]
                (support / f"MPLog-{count}.log").write_bytes(("\r\n".join(lines) + "\r\n").encode("utf-16"))
            rows = {Path(r.path).name: r.details for r in system.collect_defender_support(root)}
            for count in (400, 401):
                details = rows[f"MPLog-{count}.log"]
                self.assertEqual(details["entry_count"], count)
                self.assertEqual(details["interesting_entry_count"], 1)
                self.assertFalse(details["interesting_entries_truncated"])

    def test_excerpt_bound_is_stated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            support = Path(temp).joinpath(*system.DEFENDER_SUPPORT_ROOT)
            support.mkdir(parents=True)
            (support / "MPLog-many.log").write_text("\n".join(["Threat line"] * 30) + "\n", encoding="utf-8")
            (details,) = [r.details for r in system.collect_defender_support(Path(temp))]
            self.assertEqual(details["interesting_entry_count"], 30)
            self.assertEqual(len(details["interesting_entries"]), details["interesting_entries_limit"])
            self.assertTrue(details["interesting_entries_truncated"])


class PowerShellHistoryContinuationTests(unittest.TestCase):
    def test_multiline_command_is_one_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root.joinpath("Users", "profile-a", *execution.POWERSHELL_HISTORY)
            path.parent.mkdir(parents=True)
            path.write_bytes(b"Get-Date\nWrite-Output first `\n second\n")
            rows = [r.details for r in execution.collect_powershell_history(root)]
            self.assertEqual(
                [(r["source_index"], r["command_line"], r["source_line_start"], r["source_line_end"]) for r in rows],
                [(0, "Get-Date", 1, 1), (1, "Write-Output first \n second", 2, 3)],
            )


class RunAuditReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "input"
        self.source.mkdir()
        note = self.source / "note.txt"
        note.write_text("synthetic document", encoding="utf-8")
        (self.source / "other.txt").write_text("another synthetic document", encoding="utf-8")
        self.feed = self.base / "catalog.txt"
        self.feed.write_text(sha256(note) + "\n", encoding="utf-8")
        self.output = self.base / "output"
        self.args = [*RUN_ARGS, "--known-good-hash-feed", str(self.feed), "--hide-known-good", "--columnar-store"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def assert_receipt_covers_output_folder(self, folder: Path) -> dict:
        receipt = read_json(folder / "rapidtriage-run-audit.json")
        listed = {Path(row["path"]): row for row in receipt["integrity"]["generated_outputs"]}
        for path, row in listed.items():
            self.assertEqual((path.stat().st_size, sha256(path)), (row["size"], row["sha256"]), path)
        on_disk = {
            path.resolve()
            for path in folder.rglob("*")
            if path.is_file() and path.name not in {"rapidtriage-run-audit.json", "rapidtriage-run-progress.json"}
        }
        self.assertEqual(on_disk - set(listed), set())
        labels = {row["label"] for row in listed.values()}
        self.assertTrue({"case-db", "run-fingerprint", "run-checkpoints", "columnar-artifacts-sidecar"} <= labels)
        return receipt

    def test_fresh_and_resumed_receipts_cover_every_output_file(self) -> None:
        run_cli(self.source, self.output, *self.args)
        self.assert_receipt_covers_output_folder(self.output)
        run_cli(self.source, self.output, *self.args, "--resume")
        receipt = self.assert_receipt_covers_output_folder(self.output)
        self.assertTrue(any("감사 기록 직전" in note for note in receipt["provenance"]["notes"]))

    def test_receipt_records_settings_and_replays_the_audited_feed(self) -> None:
        feed_sha = sha256(self.feed)
        run_cli(self.source, self.output, *self.args)
        receipt = read_json(self.output / "rapidtriage-run-audit.json")
        options = receipt["provenance"]["options"]
        self.assertTrue(options["columnar_store"])
        self.assertTrue(options["case_db"])
        self.assertEqual(options["known_good_hash_feed_files"][0]["sha256"], feed_sha)
        self.assertEqual(options["tool_build"]["name"], "rapidtriage")
        self.assertEqual(len(options["tool_build"]["package_source_sha256"]), 64)
        self.assertIn(("known-good-feed", feed_sha), [(r["label"], r["sha256"]) for r in receipt["provenance"]["input_files"]])
        original = read_json(self.output / "rapidtriage-files.json")

        # The list is revised in place after the run.
        self.feed.write_text(hashlib.sha256(b"updated reference").hexdigest() + "\n", encoding="utf-8")
        replay = self.base / "replay"
        run_cli(self.source, replay, "--replay-audit", str(self.output / "rapidtriage-run-audit.json"))
        replayed = read_json(replay / "rapidtriage-files.json")
        self.assertEqual(
            sorted(c["relative_path"] for c in replayed["candidates"]),
            sorted(c["relative_path"] for c in original["candidates"]),
        )
        self.assertTrue((replay / "rapidtriage-columnar-artifacts-sidecar.json").is_file())
        self.assertTrue((replay / "rapidtriage-case.db").is_file())
        replay_options = read_json(replay / "rapidtriage-run-audit.json")["provenance"]["options"]
        self.assertEqual(replay_options["known_good_hash_feed_files"][0]["sha256"], feed_sha)

        # Without the archived copy the revised list is identified before the run starts.
        shutil.rmtree(self.output / "rapidtriage-known-good-feeds")
        refused = self.base / "refused"
        with redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit):
            main(["run", str(self.source), "--output-dir", str(refused), "--replay-audit", str(self.output / "rapidtriage-run-audit.json")])
        self.assertIn(feed_sha, errors.getvalue())
        self.assertFalse(refused.exists())

    def test_mode_is_required_without_replay(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["run", str(self.source), "--output-dir", os.fspath(self.output)])


if __name__ == "__main__":
    unittest.main()
