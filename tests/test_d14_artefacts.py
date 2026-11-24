"""D14 review: browser, MFT/USN, USB, audit and stage-cache regressions.

- Browser timeline comparison keys rows by user and keeps multiplicity, so a
  missing user's identical URL/time fails the comparison (item 2).
- Revising a known-good hash feed in place invalidates the resumed
  extraction plan (item 3).
- 4 KiB MFT records take their slot from offset / record length (item 4).
- A USN record links to a cached MFT path only when the sequence number
  (generation) matches (item 5).
- USBSTOR devices sharing a serial are told apart by ContainerID; without one
  the join is reported as ambiguous (item 6).
- The run audit lists the final bytes of the eventlog JSONL, indicators JSON
  and run plan (item 9).
- SetupAPI install times stay inside their own section (item 10).
- Visits found only in the WAL cite the WAL fingerprint (item 14).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rapidtriage.artifacts.windows import browser, filesystem, registry, system
from rapidtriage.cli import main
from tests.test_parser_quality_registry import REG_SZ, HiveWriter, Key, sz, write_hive
from tests.windows_artifact_fixtures import build_minimal_mft, build_minimal_usn_journal

RUN_ARGS = [
    "--mode",
    "seizure",
    "--read-only",
    "--no-case-db",
    "--skip-group",
    "messaging",
    "--skip-group",
    "mobile",
]


def run_cli(root: Path, output_dir: Path, *extra: str) -> None:
    args = ["run", str(root), *RUN_ARGS, "--output-dir", str(output_dir), *extra]
    if main(args) != 0:
        raise AssertionError(f"run failed: {args}")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


WEBKIT_STAMP = 13350000000123457
URL = "https://example.test/manual"


def build_wal_only_history(root: Path, users: tuple[str, ...]) -> Path:
    """Chromium History whose visits exist only in the -wal file, copied per user."""
    _name, parts = browser.CHROMIUM_BROWSER_ROOTS[0]
    source = root / "writer"
    connection = sqlite3.connect(source)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.executescript(
            """
            CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                              typed_count INTEGER, last_visit_time INTEGER);
            CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
                                transition INTEGER, visit_duration INTEGER);
            """
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO urls VALUES(1,?,?,2,0,?)", (URL, "manual", WEBKIT_STAMP))
        connection.executemany(
            "INSERT INTO visits VALUES(?,1,?,?,?)",
            [(11, WEBKIT_STAMP - 1000, 1, 250), (12, WEBKIT_STAMP, 0, 500)],
        )
        connection.commit()
        inputs = root / "inputs"
        for user in users:
            profile_dir = inputs.joinpath("Users", user, *parts, "Default")
            profile_dir.mkdir(parents=True)
            for suffix in ("", "-wal"):
                shutil.copyfile(str(source) + suffix, profile_dir / ("History" + suffix))
    finally:
        connection.close()
    return inputs


class BrowserTimelineDiffUserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_missing_user_rows_fail_and_complete_rows_pass(self) -> None:
        inputs = build_wal_only_history(self.root, ("profile-a", "profile-b"))
        records = list(browser.WindowsBrowserArtifactsProvider().collect(inputs))
        aggregates = [r.details for r in records if r.artifact_type == "browser-history-downloads"]
        self.assertEqual(sorted(d["user"] for d in aggregates), ["profile-a", "profile-b"])
        name, _parts = browser.CHROMIUM_BROWSER_ROOTS[0]
        oracle_time = (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=WEBKIT_STAMP)).isoformat()
        # The reference names each row's acquisition (D22-4: rows without one stay unresolved).
        databases = {d["user"]: d["source_path"] for d in aggregates}
        reference = [
            {
                "browser": name,
                "profile": "Default",
                "user": user,
                "timeline_type": "visit",
                "timestamp": oracle_time,
                "url": URL,
                "visit_count": 2,
                "source_table": "urls",
                "source_index": 0,
                "source_path": databases[user],
            }
            for user in ("profile-a", "profile-b")
        ]
        one_user = [d["unified_timeline"][0] for d in aggregates if d["user"] == "profile-b"]
        both_users = [d["unified_timeline"][0] for d in aggregates]

        missing = browser.build_browser_timeline_trusted_diff(one_user, reference, trusted_tool="sqlite")
        self.assertEqual(missing["status"], "diffs-present")
        self.assertFalse(missing["commercial_grade_evidence"])
        self.assertEqual(missing["rapid_indexed_count"], 1)
        self.assertEqual(missing["trusted_indexed_count"], 2)
        self.assertEqual(missing["extra_in_trusted_count"], 1)

        complete = browser.build_browser_timeline_trusted_diff(both_users, reference, trusted_tool="sqlite")
        self.assertEqual(complete["status"], "pass")
        self.assertEqual(complete["rapid_indexed_count"], 2)

    def test_duplicate_rows_are_counted_not_collapsed(self) -> None:
        row = {"browser": "Chrome", "profile": "Default", "user": "u", "timeline_type": "visit",
               "timestamp": "2024-01-01T00:00:00+00:00", "url": URL}
        result = browser.build_browser_timeline_trusted_diff([row], [row, dict(row)], trusted_tool="sqlite")
        self.assertEqual(result["status"], "diffs-present")
        self.assertEqual(result["trusted_indexed_count"], 2)

    def test_wal_only_visits_cite_wal_fingerprint(self) -> None:
        inputs = build_wal_only_history(self.root, ("profile-a",))
        records = list(browser.WindowsBrowserArtifactsProvider().collect(inputs))
        aggregate = next(r.details for r in records if r.artifact_type == "browser-history-downloads")
        database = Path(aggregate["source_path"])
        wal = database.with_name(database.name + "-wal")
        with closing(sqlite3.connect(f"{database.as_uri()}?immutable=1", uri=True)) as base_only:
            self.assertEqual(base_only.execute("SELECT COUNT(*) FROM visits").fetchone()[0], 0)
        wal_sha = sha256(wal)
        manifest = aggregate["browser_history_download_citation_manifest"]
        snapshots = {item["snapshot_id"]: item for item in manifest["source_snapshots"]}
        for citation in manifest["history_citations"]:
            self.assertIn(wal_sha, [item["sha256"] for item in citation["source_snapshot_files"]])
            snapshot = snapshots[citation["source_snapshot_id"]]
            self.assertEqual(
                {item["name"]: item["sha256"] for item in snapshot["files"]},
                {database.name: sha256(database), wal.name: wal_sha},
            )
        visits = [r.details for r in records if r.artifact_type == "browser-visit"]
        self.assertEqual(sorted(v["source_row_id"] for v in visits), [11, 12])
        for visit in visits:
            self.assertIn(visit["source_snapshot_id"], snapshots)
            self.assertIn(wal_sha, [item["sha256"] for item in visit["source_snapshot_files"]])


def mft_record(size: int, header_number: int) -> bytes:
    original = build_minimal_mft()
    attr_end = struct.unpack_from("<I", original, 0x18)[0]
    attributes = original[0x38:attr_end]
    sectors = size // 512
    record = bytearray(size)
    record[:0x30] = original[:0x30]
    struct.pack_into("<I", record, 0x2C, header_number)
    struct.pack_into("<H", record, 6, 1 + sectors)
    first_attribute = (0x30 + 2 * (1 + sectors) + 7) // 8 * 8
    struct.pack_into("<H", record, 0x14, first_attribute)
    struct.pack_into("<II", record, 0x18, first_attribute + len(attributes), size)
    record[0x30:0x32] = b"RT"
    record[first_attribute : first_attribute + len(attributes)] = attributes
    for end in range(512, size + 1, 512):
        record[end - 2 : end] = b"RT"
    return bytes(record)


class MftAndUsnTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_record_number_follows_record_length(self) -> None:
        for size in (1024, 4096):
            with self.subTest(size=size):
                folder = self.root / str(size)
                folder.mkdir()
                (folder / "$MFT").write_bytes(bytes(42 * size) + mft_record(size, 42))
                row = next(
                    r.details
                    for r in filesystem.WindowsFilesystemProvider().collect(folder)
                    if r.artifact_type == "mft-record"
                )
                self.assertEqual(row["record_number"], "42")
                self.assertEqual(row["record_number_header"], 42)
                self.assertFalse(row["record_number_header_mismatch"])
                self.assertEqual(row["allocated_size"], size)

    def test_header_number_disagreement_is_flagged(self) -> None:
        (self.root / "$MFT").write_bytes(bytes(3 * 4096) + mft_record(4096, 9))
        row = next(
            r.details
            for r in filesystem.WindowsFilesystemProvider().collect(self.root)
            if r.artifact_type == "mft-record"
        )
        self.assertEqual(row["record_number"], "3")
        self.assertEqual(row["record_number_header"], 9)
        self.assertTrue(row["record_number_header_mismatch"])

    def test_usn_links_mft_path_only_for_matching_generation(self) -> None:
        mft = bytearray(build_minimal_mft())
        mft[0x300:0x3F0] = bytes(0xF0)
        struct.pack_into("<I", mft, 0x2C, 42)
        start = mft.index("deleted.txt".encode("utf-16le"))
        mft[start : start + 22] = "current.txt".encode("utf-16le")
        (self.root / "$MFT").write_bytes(bytes(42 * 1024) + mft)
        journal = bytearray()
        for generation, label, reason in ((2, "former.txt", 0x200), (3, "current.txt", 0x100)):
            record = bytearray(
                build_minimal_usn_journal(label, datetime(2024, 1, generation, tzinfo=timezone.utc), reason)
            )
            struct.pack_into("<Q", record, 8, generation << 48 | 42)
            struct.pack_into("<Q", record, 16, 1 << 48 | 5)
            struct.pack_into("<q", record, 24, len(journal))
            journal.extend(record)
        (self.root / "$J").write_bytes(bytes(journal))
        rows = {
            r.details["file_path"]: r.details["usn_bounded_mft_path"]
            for r in filesystem.WindowsFilesystemProvider().collect(self.root)
            if r.artifact_type == "usn-record"
        }
        former = rows["former.txt"]
        self.assertEqual(former["path_candidate"], "")
        self.assertEqual(former["status"], "unresolved-mft-sequence-mismatch")
        self.assertFalse(former["complete_within_bounded_mft_cache"])
        self.assertFalse(former["file_reference_link"]["file_sequence_match"])
        self.assertIn(
            "file-reference-sequence-mismatch:usn=2,mft=3", former["file_reference_link"]["unresolved_reasons"]
        )
        current = rows["current.txt"]
        self.assertEqual(current["path_candidate"], "\\current.txt")
        self.assertEqual(current["status"], "matched-file-reference-cache")
        self.assertTrue(current["file_reference_link"]["file_sequence_match"])


class UsbTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_setupapi_time_stays_in_its_section(self) -> None:
        setup = self.root / "Windows/inf/setupapi.dev.log"
        setup.parent.mkdir(parents=True)
        text = ""
        for number, day in ((1, "01"), (2, "03")):
            text += (
                f">>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_000{number}\\UNIT{number}]\n"
                f">>>  Section start 2024/01/{day} 10:00:00.000\n"
                f"<<<  Section end 2024/01/{day} 10:01:00.000\n"
                "<<<  [Exit status: SUCCESS]\n\n"
            )
        text += ">>>  [Device Install (Hardware initiated) - USB\\VID_1234&PID_0003\\UNIT3]\n"
        setup.write_text(text, encoding="ascii")
        details = next(system.collect_setupapi_usb_artifacts(self.root)).details
        self.assertEqual(
            [(e["device_profile"]["serial_number_candidate"], e["timestamp_hint"]) for e in details["install_entries"]],
            [("UNIT1", "2024-01-01T10:00:00.000"), ("UNIT2", "2024-01-03T10:00:00.000"), ("UNIT3", "")],
        )
        self.assertEqual(details["install_entries"][1]["section_end"], "2024-01-03T10:01:00.000")
        self.assertEqual(details["install_entries"][2]["timestamp_source"], "setupapi-section-start-missing")

    def write_system_hive(self, *, containers: bool) -> list[dict]:
        hive = Key("ROOT")
        hive.path("Select").value("Current", 4, (1).to_bytes(4, "little"))
        enum = "ControlSet001\\Enum"
        for index in (1, 2):
            container = "{00000000-0000-0000-0000-00000000000" + str(index) + "}"
            usb = hive.path(f"{enum}\\USB\\VID_1234&PID_000{index}\\UNIT")
            storage = hive.path(f"{enum}\\USBSTOR\\Disk&Ven_Test&Prod_Unit{index}&Rev_1\\UNIT&0")
            if containers:
                usb.value("ContainerID", REG_SZ, sz(container))
                storage.value("ContainerID", REG_SZ, sz(container))
            else:
                storage.value("FriendlyName", REG_SZ, sz(f"Unit{index}"))
        write_hive(self.root, "Windows/System32/config/SYSTEM", HiveWriter().build(hive))
        return sorted(
            (r.details for r in registry.WindowsRegistryProvider().collect(self.root)
             if r.artifact_type == "windows-usb-device"),
            key=lambda row: row["product"],
        )

    def test_shared_serial_is_resolved_by_container_id(self) -> None:
        rows = self.write_system_hive(containers=True)
        self.assertEqual([(r["product"], r["pid"]) for r in rows], [("Unit1", "0001"), ("Unit2", "0002")])
        self.assertEqual({r["usb_join_method"] for r in rows}, {"serial+container-id"})

    def test_shared_serial_without_container_id_is_ambiguous(self) -> None:
        rows = self.write_system_hive(containers=False)
        for row in rows:
            self.assertEqual(row["pid"], "")
            self.assertEqual(row["usb_join_method"], "ambiguous-serial")
            self.assertEqual(sorted(c["pid"] for c in row["usb_join_ambiguous_candidates"]), ["0001", "0002"])


class RunAuditAndCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_known_good_feed_revision_invalidates_resumed_extract(self) -> None:
        source = self.root / "source"
        source.mkdir()
        note = source / "note.txt"
        note.write_bytes(b"sample document")
        feed = self.root / "catalog.txt"
        args = ("--extract", "--known-good-hash-feed", str(feed), "--hide-known-good")
        feed.write_text(sha256(note) + "\n", encoding="utf-8")
        resumed = self.root / "prior"
        run_cli(source, resumed, *args)
        feed.write_text(hashlib.sha256(b"new catalog sample").hexdigest() + "\n", encoding="utf-8")
        fresh = self.root / "fresh"
        run_cli(source, resumed, *args, "--resume")
        run_cli(source, fresh, *args)
        summaries = []
        for output in (resumed, fresh):
            (extract_manifest,) = (output / "files-extract").glob("*manifest*.json")
            record = read_json(extract_manifest)
            safety = read_json(output / "rapidtriage-run-summary.json")["safety"]
            self.assertNotIn("files-extract", safety["reused_outputs"])
            summaries.append(
                (
                    {k: v for k, v in record["summary"].items() if isinstance(v, int)},
                    [item.get("reason") for item in record["skipped"]],
                )
            )
        self.assertEqual(summaries[0], summaries[1])
        self.assertEqual(summaries[1][0]["selected_count"], 1)

    def test_audit_lists_final_bytes_of_core_outputs(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "note.txt").write_text("sample", encoding="utf-8")
        (source / "events.xml").write_text(
            '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID>'
            '<TimeCreated SystemTime="2024-01-01T00:00:00.0000000Z"/><EventRecordID>1</EventRecordID>'
            "<Channel>Security</Channel><Computer>HOST</Computer></System></Event></Events>",
            encoding="utf-8",
        )
        resumed = self.root / "prior"
        run_cli(source, resumed)
        fresh = self.root / "fresh"
        for output, extra in ((fresh, ()), (resumed, ("--resume",))):
            run_cli(source, output, *extra)
            audited = read_json(output / "rapidtriage-run-audit.json")["integrity"]["generated_outputs"]
            by_path = {item["path"]: item for item in audited}
            required = [
                output / "rapidtriage-run-plan.json",
                output / "rapidtriage-indicators.json",
                output / "rapidtriage-run-report.md",
                output / "artifacts" / "rapidtriage-artifacts-eventlog.jsonl",
            ]
            for path in required:
                with self.subTest(output=output.name, path=path.name):
                    self.assertIn(str(path.resolve()), by_path)
                    entry = by_path[str(path.resolve())]
                    self.assertEqual(entry["sha256"], sha256(path))
                    self.assertEqual(entry["size"], path.stat().st_size)
            for item in audited:
                with self.subTest(output=output.name, listed=item["label"]):
                    self.assertEqual(item["sha256"], sha256(Path(item["path"])))


if __name__ == "__main__":
    unittest.main()
