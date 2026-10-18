"""Desktop cloud sync clients (R2 M4, ``rapidtriage.artifacts.cloud_sync``): OneDrive, Dropbox, DriveFS, MYBOX, iCloud.

Fixtures are synthetic (``tests/cloud_sync_fixtures.py``): client schemas built in code.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts import cloud_sync
from rapidtriage.artifacts.cloud_sync import (
    NO_CLIENT_NOTICE,
    CloudSyncClientsProvider,
    classify_client_path,
    load_odl_body,
    parse_odl_record,
)
from rapidtriage.cli import main
from rapidtriage.core.triage_rules import load_catalog
from tests.cloud_sync_fixtures import (
    BASE_MS,
    appdata_local,
    build_drivefs,
    build_dropbox,
    build_icloud,
    build_mybox,
    build_onedrive,
    build_prefetch_only,
    odl_file,
    odl_record,
)

ROW_CONTRACT = ("recovery_method", "parser_version", "source_path", "source_offset", "source_locator", "client", "client_label")


def collect(root: Path) -> tuple[list, CloudSyncClientsProvider]:
    provider = CloudSyncClientsProvider()
    return list(provider.collect(root)), provider


def of(rows: list, artifact_type: str, client: str | None = None) -> list:
    return [row for row in rows if row.artifact_type == artifact_type and (client is None or row.details["client"] == client)]


class CloudSyncOneDriveTests(unittest.TestCase):
    def test_onedrive_settings_sync_db_and_odl_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root)
            rows, provider = collect(root)
        self.assertEqual(provider.collection_notes, [])
        accounts = of(rows, "cloud-sync-account", "onedrive")
        self.assertEqual(len(accounts), 1)
        account = accounts[0].details
        self.assertEqual(account["account"], "alice@example.com")
        self.assertEqual(account["actor"], "alice@example.com")
        self.assertEqual(account["account_id"], "1a2b3c4d5e6f7788")
        self.assertEqual(account["account_type"], "personal")
        self.assertEqual(account["sync_roots"], ["D:\\Sync\\OneDrive"])
        self.assertEqual(account["user_profile"], "alice")
        self.assertEqual(account["recovery_method"], "config-file")

        files = {row.details["file_name"]: row.details for row in of(rows, "cloud-sync-file", "onedrive")}
        budget = files["budget.xlsx"]
        self.assertEqual(budget["item_path"], "D:\\Sync\\OneDrive\\Projects\\2024\\budget.xlsx")
        self.assertEqual(budget["path_basis"], "sync-root")
        self.assertEqual(budget["size"], 48213)
        self.assertTrue(budget["shared"])
        self.assertEqual(budget["timestamp"], "2024-05-01T09:00:00+00:00")
        self.assertEqual(budget["timestamp_kind"], "cloud-modified")
        self.assertEqual(budget["site_url"], "https://onedrive.live.com/?cid=1a2b3c4d5e6f7788")
        self.assertEqual(budget["sync_state"], "2")
        self.assertEqual(budget["sync_state_semantics"], "unvalidated-raw-value")
        self.assertEqual(budget["content_hash"], "010203")
        self.assertEqual(budget["source_locator"], "table=od_ClientFile_Records rowid=1")
        self.assertIsNone(budget["source_offset"])
        self.assertEqual(budget["actor"], "alice@example.com")
        # A folder cycle stops the chain: flagged, never prefixed with the sync root.
        cycle = files["cycle.bin"]
        self.assertTrue(cycle["path_truncated"])
        self.assertFalse(cycle["item_path"].startswith("D:\\"))

        events = of(rows, "cloud-sync-event", "onedrive")
        operations = Counter(row.details["operation"] for row in events)
        self.assertEqual(operations, Counter({"upload": 3, "delete": 1, "rename": 1, "download": 1}))
        upload = next(row.details for row in events if row.details["operation"] == "upload")
        self.assertEqual(upload["recovery_method"], "log-record-carved")
        self.assertEqual(upload["operation_basis"], "log-function-name")
        self.assertEqual(upload["log_function"], "UploadFileComplete")
        self.assertEqual(upload["timestamp_kind"], "cloud-upload")
        self.assertTrue(upload["bulk_rule_eligible"])
        self.assertIsInstance(upload["source_offset"], int)
        self.assertEqual(upload["source_offset_space"], "inflated-stream")
        self.assertEqual(upload["actor"], "alice@example.com")
        # ObfuscationStringMap.txt resolves the obfuscated parameter; UTF-16 Hangul names are read.
        delete = next(row.details for row in events if row.details["operation"] == "delete")
        self.assertEqual(delete["item_path"], "contract_final.pdf")
        rename = next(row.details for row in events if row.details["operation"] == "rename")
        self.assertEqual(rename["item_path"], "C:\\Users\\alice\\OneDrive\\보고서.hwp")
        # A function that names no operation is not an event even when a parameter says "Upload…".
        self.assertNotIn("Flush", {row.details.get("log_function") for row in events})
        self.assertNotIn("HeartbeatTick", {row.details.get("log_function") for row in events})

        inventory = of(rows, "cloud-sync-inventory", "onedrive")
        self.assertEqual(len(inventory), 1)
        details = inventory[0].details
        self.assertEqual(details["inventory_status"], "parsed")
        self.assertEqual(details["parsed_counts"], {"accounts": 1, "files": 3, "events": 6})
        self.assertTrue(details["source_path"].endswith("settings\\Personal") or details["source_path"].endswith("settings/Personal"))
        self.assertTrue(any(".dat" in reason for reason in details["inventory_reasons"]))
        self.assertTrue(any("ObfuscationStringMap" in reason for reason in details["inventory_reasons"]))

    def test_business_account_prefers_the_user_email_and_reads_the_tenant(self) -> None:
        from tests.cloud_sync_fixtures import utf16_text

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            business = appdata_local(root) / "Microsoft" / "OneDrive" / "settings" / "Business1"
            utf16_text(
                business / "ClientPolicy_0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0.ini",
                "SupportUrl = mailto:help@contoso.example\r\nTenantName = Contoso\r\n",
            )
            utf16_text(business / "global.ini", "UserEmail = bob@contoso.example\r\n")
            utf16_text(business / "b1.ini", 'libraryScope = 1 0 "C:\\Users\\bob\\OneDrive - Contoso" 4\r\n')
            rows, _provider = collect(root)
        account = of(rows, "cloud-sync-account", "onedrive")[0].details
        self.assertEqual(account["account"], "bob@contoso.example")
        self.assertEqual(account["account_emails"], ["help@contoso.example"])
        self.assertEqual(account["account_type"], "business")
        self.assertEqual(account["tenant"], "Contoso")
        self.assertEqual(account["tenant_id"], "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
        self.assertEqual(account["sync_roots"], ["C:\\Users\\bob\\OneDrive - Contoso"])

    def test_keystore_is_disclosed_not_decrypted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root)
            logs = appdata_local(root) / "Microsoft" / "OneDrive" / "logs" / "Personal"
            (logs / "general.keystore").write_text('[{"Key":"synthetic","Version":1}]', encoding="utf-8")
            rows, _provider = collect(root)
        reasons = of(rows, "cloud-sync-inventory", "onedrive")[0].details["inventory_reasons"]
        self.assertTrue(any("general.keystore" in reason and "복호하지 않음" in reason for reason in reasons))

    def test_odl_reader_handles_plain_whole_gzip_and_rejects_unknown(self) -> None:
        record = odl_record(BASE_MS, "SyncEngine.cpp", "UploadFile", ["C:\\Users\\a\\OneDrive\\x.txt"])
        version, body, offset, inflated, truncated = load_odl_body(odl_file([record], compressed=False))
        self.assertEqual((version, offset, inflated, truncated), (2, 0x100, False, False))
        self.assertIn(record, body)
        import gzip

        version, body, offset, inflated, _truncated = load_odl_body(gzip.compress(odl_file([record], compressed=False)))
        self.assertEqual((version, offset, inflated), (2, 0x100, True))
        with self.assertRaises(cloud_sync.CloudSyncParseError):
            load_odl_body(b"not an odl log at all")
        parsed = parse_odl_record(record, {})
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], "upload")
        self.assertEqual(parsed[5], "C:\\Users\\a\\OneDrive\\x.txt")
        shared_folder = odl_record(BASE_MS, "SyncEngine.cpp", "SharedFolderRefresh", [])
        self.assertIsNone(parse_odl_record(shared_folder, {}))


class CloudSyncOtherClientTests(unittest.TestCase):
    def test_dropbox_info_host_encrypted_dbx_and_sync_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_dropbox(root)
            rows, _provider = collect(root)
        accounts = of(rows, "cloud-sync-account", "dropbox")
        self.assertEqual(len(accounts), 1)  # host.db repeats info.json's root: no second row
        self.assertEqual(accounts[0].details["sync_roots"], ["E:\\Dropbox"])
        self.assertEqual(accounts[0].details["account_id"], "4242")
        self.assertEqual(accounts[0].details["subscription_type"], "Basic")
        self.assertNotIn("account", accounts[0].details)  # info.json has no e-mail: nothing invented
        events = of(rows, "cloud-sync-event", "dropbox")
        self.assertEqual(Counter(row.details["operation"] for row in events), Counter({"upload": 4, "delete": 1}))
        delete = next(row.details for row in events if row.details["operation"] == "delete")
        self.assertEqual(delete["actor"], "bob@example.net")
        self.assertEqual(delete["item_path"], "E:\\Dropbox\\out\\old.pdf")
        folder = next(row.details for row in events if row.details["item_path"].endswith("folder"))
        self.assertFalse(folder["bulk_rule_eligible"])
        inventory = of(rows, "cloud-sync-inventory", "dropbox")[0].details
        self.assertEqual(inventory["encrypted_store_count"], 2)
        self.assertTrue(any("암호화된 Dropbox" in reason for reason in inventory["inventory_reasons"]))

    def test_dropbox_host_db_alone_gives_the_sync_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = build_dropbox(root)
            paths["info"].unlink()
            rows, _provider = collect(root)
        accounts = of(rows, "cloud-sync-account", "dropbox")
        self.assertEqual([row.details["sync_roots"] for row in accounts], [["E:\\Dropbox"]])
        self.assertEqual(accounts[0].details["source_format"], "dropbox-host-db")

    def test_drivefs_metadata_mirror_cache_and_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_drivefs(root)
            rows, _provider = collect(root)
        files = of(rows, "cloud-sync-file", "google-drive")
        metadata = {row.details["file_name"]: row.details for row in files if row.details["source_format"] == "google-drivefs-metadata"}
        self.assertEqual(set(metadata), {"salary.xlsx", "deleted.docx", "from-partner.pdf"})
        self.assertEqual(metadata["salary.xlsx"]["item_path"], "My Drive/인사/salary.xlsx")
        self.assertEqual(metadata["salary.xlsx"]["timestamp"], "2024-05-01T09:00:00+00:00")
        self.assertEqual(metadata["salary.xlsx"]["viewed_at"], "2024-05-01T09:16:40+00:00")
        self.assertTrue(metadata["deleted.docx"]["deleted"])
        self.assertEqual(metadata["deleted.docx"]["sync_state"], "trashed")
        self.assertTrue(metadata["from-partner.pdf"]["shared"])
        self.assertFalse(metadata["from-partner.pdf"]["is_owner"])
        self.assertEqual(metadata["salary.xlsx"]["actor"], "alice.drive@example.com")
        mirror = [row.details for row in files if row.details["source_format"] == "google-drivefs-mirror"]
        self.assertEqual([item["file_name"] for item in mirror], ["salary.xlsx"])  # folders skipped
        accounts = {row.details.get("account_id") or "root": row.details for row in of(rows, "cloud-sync-account", "google-drive")}
        self.assertEqual(accounts["117000000000000000001"]["account"], "alice.drive@example.com")
        self.assertEqual(accounts["root"]["sync_roots"], ["C:\\Users\\alice\\Desktop"])
        account_inventory = next(
            row.details for row in of(rows, "cloud-sync-inventory", "google-drive") if row.details.get("account_folder") == "117000000000000000001"
        )
        self.assertEqual(account_inventory["extra_counts"]["content_cache_files"], 2)
        self.assertEqual(account_inventory["extra_counts"]["content_cache_bytes"], 150)

    def test_backup_and_sync_snapshot_and_config(self) -> None:
        from tests.cloud_sync_fixtures import sqlite_db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = appdata_local(root) / "Google" / "Drive" / "user_default"
            sqlite_db(
                base / "sync_config.db",
                ["CREATE TABLE data (entry_key TEXT, data_key TEXT, data_value TEXT)"],
                [
                    # Real Backup and Sync shape: entry_key names the setting, data_key is the literal "value".
                    ("INSERT INTO data VALUES (?, ?, ?)", ("user_email", "value", "legacy@example.com")),
                    ("INSERT INTO data VALUES (?, ?, ?)", ("local_sync_root_path", "value","\\\\?\\F:\\Google Drive")),
                ],
            )
            sqlite_db(
                base / "snapshot.db",
                [
                    "CREATE TABLE cloud_entry (doc_id TEXT, filename TEXT, modified INTEGER, size INTEGER, removed INTEGER, shared INTEGER, doc_type INTEGER, checksum TEXT)",
                    "CREATE TABLE cloud_relations (child_doc_id TEXT, parent_doc_id TEXT)",
                ],
                [
                    ("INSERT INTO cloud_entry VALUES (?,?,?,?,?,?,?,?)", ("root", "내 드라이브", 1714554000, 0, 0, 0, 0, "")),
                    ("INSERT INTO cloud_entry VALUES (?,?,?,?,?,?,?,?)", ("d1", "plan.docx", 1714554000, 77, 1, 1, 1, "abc")),
                    ("INSERT INTO cloud_relations VALUES (?, ?)", ("d1", "root")),
                ],
            )
            rows, _provider = collect(root)
        account = of(rows, "cloud-sync-account", "google-drive")[0].details
        self.assertEqual(account["account"], "legacy@example.com")
        self.assertEqual(account["sync_roots"], ["F:\\Google Drive"])
        files = of(rows, "cloud-sync-file", "google-drive")
        self.assertEqual([row.details["item_path"] for row in files], ["내 드라이브/plan.docx"])
        self.assertTrue(files[0].details["deleted"])
        self.assertTrue(files[0].details["shared"])

    def test_mybox_is_inventoried_and_the_web_origin_is_not_a_client(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_mybox(root)
            rows, _provider = collect(root)
            browser_origin = next(root.rglob("https_mybox.naver.com_0.indexeddb.leveldb")) / "000003.log"
            self.assertIsNone(classify_client_path(browser_origin, root))
        self.assertEqual([row.artifact_type for row in rows], ["cloud-sync-inventory"])
        details = rows[0].details
        self.assertEqual(details["client_label"], "네이버 MYBOX")
        self.assertEqual(details["inventory_status"], "inventory-only")
        self.assertEqual(details["sqlite_databases"][0]["tables"][0]["table"], "sync_item")
        self.assertTrue(any("인벤토리만" in reason for reason in details["inventory_reasons"]))

    def test_icloud_sync_root_is_volume_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_icloud(root)
            rows, _provider = collect(root)
        account = of(rows, "cloud-sync-account", "icloud")[0].details
        self.assertEqual(account["sync_roots"], ["\\Users\\alice\\iCloudDrive"])
        self.assertEqual(account["path_basis"], "evidence-root-relative")
        inventory = of(rows, "cloud-sync-inventory", "icloud")[0].details
        self.assertEqual(inventory["sqlite_databases"][0]["tables"][0]["table"], "zones")

    def test_a_root_inside_the_profile_still_finds_the_client(self) -> None:
        # The examiner points the run at the user's AppData\Local copy (no Users segment below the root).
        with tempfile.TemporaryDirectory() as tmp:
            build_onedrive(Path(tmp), user="carol")
            local = appdata_local(Path(tmp), "carol")
            rows, _provider = collect(local)
        account = of(rows, "cloud-sync-account", "onedrive")[0].details
        self.assertEqual(account["account"], "alice@example.com")
        self.assertEqual(account["user_profile"], "carol")

    def test_drivefs_virtual_drive_is_not_a_sync_root(self) -> None:
        from tests.cloud_sync_fixtures import sqlite_db

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = build_drivefs(root)
            paths["root_preference"].unlink()
            sqlite_db(
                paths["root_preference"],
                ["CREATE TABLE roots (media_id TEXT, root_path TEXT, account_token TEXT)"],
                [("INSERT INTO roots VALUES (?, ?, ?)", ("m1", "G:\\", "alice.drive@example.com"))],
            )
            rows, _provider = collect(root)
        roots = [root for row in of(rows, "cloud-sync-account", "google-drive") for root in row.details.get("sync_roots") or []]
        self.assertEqual(roots, [])

    def test_examiner_temp_paths_never_look_like_a_profile(self) -> None:
        # The evidence copy lives under C:\Users\<examiner>\AppData\Local\Temp: the profile is the evidence user.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_dropbox(root, user="suspect")
            rows, _provider = collect(root)
        self.assertEqual({row.details.get("user_profile") for row in rows}, {"suspect"})


class CloudSyncInventoryAndCapTests(unittest.TestCase):
    def test_no_client_and_prefetch_only_disclose_a_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Users" / "alice" / "Documents").mkdir(parents=True)
            rows, provider = collect(root)
            self.assertEqual(rows, [])
            self.assertEqual(provider.collection_notes, [NO_CLIENT_NOTICE])
            build_prefetch_only(root)
            rows, provider = collect(root)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].details["inventory_status"], "executable-trace-only")
        self.assertEqual(rows[0].details["client"], "onedrive")
        self.assertIn("실행 흔적(Prefetch)만", rows[0].details["inventory_reason"])
        self.assertEqual(provider.collection_notes[0], NO_CLIENT_NOTICE)
        self.assertIn("OneDrive", provider.collection_notes[1])

    def test_corrupt_inputs_are_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root, corrupt_log=True)
            paths = build_dropbox(root)
            paths["info"].write_text("{not json", encoding="utf-8")
            drivefs = build_drivefs(root)
            # A SQLite header followed by garbage: the snapshot opens, every query fails.
            drivefs["metadata"].write_bytes(b"SQLite format 3\x00" + b"\xff" * 4000)
            rows, _provider = collect(root)
        inventories = {row.details["client"] + "|" + str(row.details.get("account_folder", "")): row.details for row in of(rows, "cloud-sync-inventory")}
        onedrive = inventories["onedrive|personal"]
        self.assertEqual(onedrive["inventory_status"], "partial-errors")
        self.assertIn("gzip", onedrive["source_errors"][0]["error"])
        self.assertTrue(of(rows, "cloud-sync-event", "onedrive"))  # the readable logs still parse
        dropbox = inventories["dropbox|"]
        self.assertTrue(any("info.json" in item["error"] for item in dropbox["source_errors"]))
        self.assertTrue(of(rows, "cloud-sync-event", "dropbox"))
        google = inventories["google-drive|117000000000000000001"]
        self.assertTrue(google["source_errors"])
        self.assertTrue(of(rows, "cloud-sync-file", "google-drive"))  # mirror_sqlite_db still parses

    def test_row_and_log_caps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root, uploads=5)
            build_dropbox(root, uploads=5)
            with mock.patch.object(cloud_sync, "MAX_FILE_ROWS_PER_SOURCE", 1), mock.patch.object(
                cloud_sync, "MAX_LOG_EVENTS_PER_FILE", 2
            ), mock.patch.object(cloud_sync, "MAX_EVENT_ROWS_PER_SOURCE", 3):
                rows, _provider = collect(root)
            self.assertEqual(len(of(rows, "cloud-sync-file", "onedrive")), 1)
            self.assertEqual(len(of(rows, "cloud-sync-event", "dropbox")), 3)
            self.assertLessEqual(len(of(rows, "cloud-sync-event", "onedrive")), 3)  # 2 from the .odlgz + 1 from the .odl
            reasons = " ".join(of(rows, "cloud-sync-inventory", "onedrive")[0].details["inventory_reasons"])
            self.assertIn("상한", reasons)
            with mock.patch.object(cloud_sync, "MAX_ROWS_TOTAL", 4):
                rows, provider = collect(root)
            self.assertEqual(len([row for row in rows if row.artifact_type != "cloud-sync-inventory"]), 4)
            self.assertTrue(any("행 상한" in note for note in provider.collection_notes))
            with mock.patch.object(cloud_sync, "MAX_LOG_FILE_BYTES", 64), mock.patch.object(cloud_sync, "MAX_SQLITE_BYTES", 64):
                rows, _provider = collect(root)
            errors = of(rows, "cloud-sync-inventory", "onedrive")[0].details["source_errors"]
            self.assertTrue(all("상한" in item["error"] for item in errors))
            self.assertFalse(of(rows, "cloud-sync-event", "onedrive"))

    def test_every_row_carries_the_provenance_contract_and_maps_to_the_catalogue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root)
            build_dropbox(root)
            build_drivefs(root)
            build_mybox(root)
            build_icloud(root)
            rows, _provider = collect(root)
        catalog = load_catalog()
        self.assertEqual(
            {row.artifact_type for row in rows}, {"cloud-sync-account", "cloud-sync-file", "cloud-sync-event", "cloud-sync-inventory"}
        )
        self.assertEqual({row.details["client"] for row in rows}, set(cloud_sync.CLIENT_LABELS))
        for row in rows:
            for key in ROW_CONTRACT:
                self.assertIn(key, row.details, (row.artifact_type, key))
            self.assertEqual(row.details["parser_version"], cloud_sync.PARSER_VERSION)
            # Accounts and inventory rows have their own families (console fix m1); files/events share ``cloud-sync``.
            expected_family = row.artifact_type if row.artifact_type in ("cloud-sync-account", "cloud-sync-inventory") else "cloud-sync"
            self.assertEqual(catalog.family_for(row.artifact_type, "cloud-sync"), expected_family)
            json.dumps(row.to_dict(), ensure_ascii=False)  # serialisable (no bytes / sqlite rows)

    def test_sqlite_sources_are_never_modified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = build_onedrive(root)
            before = paths["sync_db"].read_bytes()
            collect(root)
            self.assertEqual(paths["sync_db"].read_bytes(), before)
            self.assertFalse(paths["sync_db"].with_name(paths["sync_db"].name + "-wal").exists())
            connection = sqlite3.connect(paths["sync_db"])
            connection.close()


class CloudSyncPipelineTests(unittest.TestCase):
    def test_cli_artifacts_kind_cloud_sync(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            build_onedrive(root)
            output = Path(tmp) / "cloud-sync.json"
            self.assertEqual(main(["artifacts", str(root), "--kind", "cloud-sync", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
        types = Counter(item["artifact_type"] for item in payload["artifacts"])
        self.assertEqual(types["cloud-sync-account"], 1)
        self.assertGreaterEqual(types["cloud-sync-event"], 5)

    def test_run_pipeline_emits_rows_timeline_and_bulk_upload_flag(self) -> None:
        from rapidtriage.artifacts import clear_collect_cache
        from rapidtriage.core.run import run_triage_mode
        from rapidtriage.core.triage_rules.engine import FLAGS_FILE_NAME

        clear_collect_cache()
        self.addCleanup(clear_collect_cache)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case-root"
            root.mkdir()
            build_dropbox(root, uploads=55, upload_step_seconds=20)
            output_dir = Path(tmp) / "run-out"
            started = time.monotonic()
            summary = run_triage_mode(root, mode="seizure", output_dir=output_dir)
            elapsed = time.monotonic() - started
            payload_path = output_dir / "artifacts" / "rapidtriage-artifacts-cloud-sync.json"
            self.assertTrue(payload_path.is_file(), sorted(path.name for path in (output_dir / "artifacts").iterdir()))
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
            self.assertGreaterEqual(int(payload.get("record_count") or len(payload.get("artifacts") or [])), 57)
            step = next(item for item in summary["steps"] if item["name"] == "triage-flags")
            self.assertEqual(step["status"], "completed", step)
            flags_path = output_dir / "analyses" / str(step["analysis_id"]) / FLAGS_FILE_NAME
            lines = [json.loads(line) for line in flags_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            bulk = [line for line in lines if line["kind"] == "cloud-sync" and any(flag["id"] == "cloud.bulk_upload" for flag in line["flags"])]
            self.assertEqual(len(bulk), 55)
            outside = [
                line for line in lines if any(flag["id"] == "cloud.sync_folder_outside_user_profile" for flag in line["flags"])
            ]
            self.assertEqual(len(outside), 1)  # info.json E:\Dropbox
            timeline = json.loads((output_dir / "rapidtriage-timeline.json").read_text(encoding="utf-8"))
            kinds = Counter(
                event.get("timestamp_kind") for event in timeline.get("events") or [] if (event.get("details") or {}).get("kind") == "cloud-sync"
            )
            self.assertEqual(kinds["upload"], 56)  # 55 files + the folder event (not counted by the rule)
            self.assertEqual(kinds["delete"], 1)
        self.assertLess(elapsed, 120)


class CloudSyncReviewRegressionTests(unittest.TestCase):
    """R2 review findings (M6, M7, M16, M17, M20, URL redaction, minors): one test per item."""

    def test_m6_infinite_size_and_a_poisoned_source_do_not_drop_other_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = build_onedrive(root)
            connection = sqlite3.connect(paths["sync_db"])
            connection.execute(
                "INSERT INTO od_ClientFile_Records (resourceID, parentResourceID, fileName, size) VALUES ('X', 'F1', 'bad.bin', 9e999)"
            )
            connection.commit()
            connection.close()
            rows, _provider = collect(root)
            self.assertIsNone(cloud_sync.as_int(float("inf")))
            self.assertIsNone(cloud_sync.as_int(float("nan")))
            files = {row.details["file_name"]: row.details for row in of(rows, "cloud-sync-file", "onedrive")}
            self.assertNotIn("size", files["bad.bin"])
            self.assertEqual(len(of(rows, "cloud-sync-event", "onedrive")), 6)  # the logs still parse
            # Any exception inside one database is recorded on the inventory row; logs still parse.
            with mock.patch.object(cloud_sync.CloudSyncCollector, "onedrive_sync_db", side_effect=RuntimeError("poisoned")):
                rows, _provider = collect(root)
        inventory = of(rows, "cloud-sync-inventory", "onedrive")[0].details
        self.assertEqual(inventory["inventory_status"], "partial-errors")
        self.assertTrue(any("poisoned" in item["error"] for item in inventory["source_errors"]))
        self.assertEqual(len(of(rows, "cloud-sync-event", "onedrive")), 6)
        self.assertEqual(len(of(rows, "cloud-sync-account", "onedrive")), 1)

    def test_m7_folder_chain_caps_iterations_and_memoises_prefixes(self) -> None:
        count = 200_000
        parents = {index: index + 1 for index in range(count)}
        names = {index: "" for index in range(count)}
        started = time.monotonic()
        for _ in range(50):
            segments, _top, cut = cloud_sync.chain_from_parent(0, parents, names)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(segments, [])
        self.assertTrue(cut)

        class Counting(dict):
            lookups = 0

            def get(self, key, default=None):
                Counting.lookups += 1
                return super().get(key, default)

        depth = 40
        tree = Counting({index: index - 1 for index in range(1, depth)})
        tree[0] = None
        folder_names = {index: f"d{index}" for index in range(depth)}
        cache: dict = {}
        expected = cloud_sync.chain_from_parent(depth - 1, dict(tree), folder_names)
        Counting.lookups = 0
        for _ in range(1000):
            self.assertEqual(cloud_sync.chain_from_parent(depth - 1, tree, folder_names, cache), expected)
        self.assertLessEqual(Counting.lookups, depth)  # one walk, then cache hits
        # A sibling folder reuses its parent's memoised prefix.
        tree[depth] = depth - 1
        folder_names[depth] = "leaf"
        Counting.lookups = 0
        segments, _top, cut = cloud_sync.chain_from_parent(depth, tree, folder_names, cache)
        self.assertEqual(segments, [*expected[0], "leaf"])
        self.assertFalse(cut)
        self.assertEqual(Counting.lookups, 1)

    def test_m16_icloud_root_is_anchored_at_the_users_segment(self) -> None:
        from rapidtriage.core.triage_rules.cloud import within_user_profile

        cases = {("C", "Users", "bob"): ("\\Users\\bob\\iCloudDrive", True), ("Users", "bob"): ("\\Users\\bob\\iCloudDrive", True)}
        for layout, (expected_root, inside) in cases.items():
            with tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp, "kape")
                drive = base.joinpath(*layout, "iCloudDrive")
                drive.mkdir(parents=True)
                for index in range(3):
                    (drive / f"doc{index}.txt").write_text("x", encoding="utf-8")
                with mock.patch.object(cloud_sync, "MAX_CLIENT_FILES", 1):
                    rows, _provider = collect(base)
            account = of(rows, "cloud-sync-account", "icloud")[0].details
            self.assertEqual(account["sync_roots"], [expected_root], layout)
            self.assertIs(within_user_profile(account["sync_roots"][0]), inside)
            self.assertEqual(account["synced_file_count"], 3)  # a real count, not the listed sample
        # The evidence root is the profile itself: the machine location is unknown, never "outside".
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp, "Users", "bob")
            (profile / "iCloudDrive").mkdir(parents=True)
            (profile / "iCloudDrive" / "doc.txt").write_text("x", encoding="utf-8")
            rows, _provider = collect(profile)
        account = of(rows, "cloud-sync-account", "icloud")[0].details
        self.assertEqual(account["sync_roots"], ["iCloudDrive"])
        self.assertEqual(account["path_basis"], "evidence-root-relative-unanchored")
        self.assertIsNone(within_user_profile(account["sync_roots"][0]))
        self.assertIsNone(within_user_profile("\\iCloudDrive"))
        self.assertTrue(within_user_profile("\\C\\Users\\bob\\iCloudDrive"))

    def test_m17_bulk_upload_counts_distinct_items_and_caps_log_only_bursts(self) -> None:
        import datetime as dt

        from rapidtriage.core.triage_rules.base import RowView
        from rapidtriage.core.triage_rules.cloud import LOG_ONLY_NOTE, BulkUpload

        start = dt.datetime(2024, 5, 1, 9, 0, tzinfo=dt.timezone.utc)

        def run(rows: list[dict]) -> list:
            rule = BulkUpload({"window_minutes": 60, "min_count": 5, "min_bytes": 1_000_000})
            for index, details in enumerate(rows):
                view = RowView(kind="cloud-sync", collection="artifacts", source_kind="cloud-sync", index=index, row={"artifact_type": "cloud-sync-event", "details": details})
                rule.apply(view, None)  # type: ignore[arg-type]
            return list(rule.finalize(None))  # type: ignore[arg-type]

        def upload(item: str, second: int, size: int = 10, **extra: object) -> dict:
            at = (start + dt.timedelta(seconds=second)).isoformat()
            return {"client": "onedrive", "operation": "upload", "timestamp": at, "actor": "a@x", "item_path": item, "size": size, **extra}

        # One item re-uploaded many times: one distinct item, never a burst (count and bytes).
        self.assertEqual(run([upload("C:\\a.bin", second * 5, size=900_000) for second in range(20)]), [])
        # A single huge item: bytes alone need two distinct items.
        self.assertEqual(run([upload("C:\\big.iso", 0, size=5_000_000_000)]), [])
        # Two distinct items over min_bytes: flagged; each item's size counted once.
        flags = run([upload("C:\\a.iso", 0, size=600_000), upload("C:\\a.iso", 1, size=600_000), upload("C:\\b.iso", 2, size=600_000)])
        self.assertEqual(flags[-1][1].evidence["upload_count"], 2)
        self.assertEqual(flags[-1][1].evidence["upload_bytes"], 1_200_000)
        self.assertIsNone(flags[-1][1].note)
        self.assertNotIn("grade_cap", flags[-1][1].evidence)
        # Log-carved rows only: still flagged, with a note and grade_cap B.
        carved = run([upload(f"C:\\f{index}.docx", index, recovery_method="log-record-carved", parser_confidence="low") for index in range(6)])
        self.assertEqual(len(carved), 6)
        self.assertEqual(carved[0][1].note, LOG_ONLY_NOTE)
        self.assertEqual(carved[0][1].evidence["grade_cap"], "B")
        self.assertEqual(carved[0][1].grade, "B")  # the engine downgrades the flag to B
        # One structured (SQLite) row in the window keeps the catalogue grade.
        mixed = run([upload(f"C:\\f{index}.docx", index, recovery_method="log-record-carved") for index in range(5)] + [upload("C:\\g.docx", 9, recovery_method="sqlite-row")])
        self.assertIsNone(mixed[-1][1].note)

    def test_m20_backup_and_sync_prefers_entry_key(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE data (entry_key TEXT, data_key TEXT, data_value TEXT)")
        connection.execute("INSERT INTO data VALUES ('user_email', 'value', 'legacy@example.com')")
        connection.execute("INSERT INTO data VALUES ('local_sync_root_path', 'value', ?)", ("\\\\?\\F:\\Google Drive",))
        emails, roots = cloud_sync.google_account_hints(connection, cloud_sync.sqlite_tables(connection))
        connection.close()
        self.assertEqual(emails, ["legacy@example.com"])
        self.assertEqual(roots, ["F:\\Google Drive"])

    def test_url_redaction_of_site_url_and_log_strings(self) -> None:
        from rapidtriage.artifacts.url_redaction import url_sha256

        signed = "https://contoso.sharepoint.com/personal/a/_layouts/15/download.aspx?UniqueId=1&tempauth=SECRET123"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = build_onedrive(root)
            connection = sqlite3.connect(paths["sync_db"])
            connection.execute("UPDATE od_ScopeInfo_Records SET webURL = ?", (signed,))
            connection.commit()
            connection.close()
            logs = appdata_local(root) / "Microsoft" / "OneDrive" / "logs" / "Personal"
            record = odl_record(BASE_MS, "SyncEngineUpload.cpp", "UploadFileComplete", ["C:\\Users\\alice\\OneDrive\\x.docx", signed])
            (logs / "SyncEngine-2024-05-03.odl").write_bytes(odl_file([record], compressed=False))
            rows, _provider = collect(root)
        budget = next(row.details for row in of(rows, "cloud-sync-file", "onedrive") if row.details["file_name"] == "budget.xlsx")
        self.assertNotIn("SECRET123", budget["site_url"])
        self.assertEqual(budget["site_url_sha256"], url_sha256(signed))
        self.assertTrue(budget["url_tokens_redacted"])
        event = next(row.details for row in of(rows, "cloud-sync-event", "onedrive") if row.details["source_path"].endswith("2024-05-03.odl"))
        self.assertFalse(any("SECRET123" in value for value in event["log_strings"]))
        self.assertIn(url_sha256(signed), event["log_strings_sha256"])
        self.assertTrue(event["url_tokens_redacted"])
        for row in rows:
            self.assertNotIn("SECRET123", json.dumps(row.to_dict(), ensure_ascii=False))

    def test_minor_operation_classification_uses_word_tokens(self) -> None:
        expected = {
            "DehydrateFile": None,
            "FileDehydrated": None,
            "HydrateFileComplete": "download",
            "SharePointUploadSession": "upload",
            "UploadSharePointItem": "upload",
            "MovementTracker": None,
            "RemoveFromCache": None,
            "OnSharingStateChanged": "share",
            "SharedItemUpload": "upload",
            "SharedFolderRefresh": None,
            "DeleteUploadedFile": "delete",
            "RenameItem": "rename",
            "SyncEngineUpload.cpp UploadFileComplete": "upload",
        }
        self.assertEqual({name: cloud_sync.classify_operation(name) for name in expected}, expected)

    def test_minor_within_user_profile_handles_device_prefixes(self) -> None:
        from rapidtriage.core.triage_rules.cloud import within_user_profile

        self.assertIs(within_user_profile("\\\\?\\UNC\\srv\\share\\OneDrive"), False)
        self.assertIs(within_user_profile("\\\\srv\\share"), False)
        self.assertIs(within_user_profile("\\\\?\\C:\\Users\\bob\\x"), True)
        self.assertIs(within_user_profile("\\\\.\\C:\\Users\\bob"), True)
        self.assertIs(within_user_profile("\\\\.\\E:\\Data"), False)

    def test_minor_log_budget_is_exact_and_gzip_members_are_all_read(self) -> None:
        import gzip

        multi = gzip.compress(b"A" * 10) + gzip.compress(cloud_sync.ODL_RECORD_SIGNATURE + b"upload")
        out, truncated = cloud_sync.bounded_gunzip(multi)
        self.assertEqual(out, b"A" * 10 + cloud_sync.ODL_RECORD_SIGNATURE + b"upload")
        self.assertFalse(truncated)
        out, truncated = cloud_sync.bounded_gunzip(multi, 12)
        self.assertEqual((len(out), truncated), (12, True))
        out, truncated = cloud_sync.bounded_gunzip(multi, 10)
        self.assertEqual((out, truncated), (b"A" * 10, True))
        # A plain (not gzip) log body is cut at the remaining run budget, never overshooting it.
        record = odl_record(BASE_MS, "SyncEngine.cpp", "UploadFile", ["C:\\Users\\a\\OneDrive\\x.txt"])
        _version, body, _offset, _inflated, truncated = load_odl_body(odl_file([record] * 50, compressed=False), 300)
        self.assertEqual((len(body), truncated), (300, True))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root)
            budget = 400
            with mock.patch.object(cloud_sync, "MAX_LOG_TOTAL_BYTES", budget):
                collector = cloud_sync.CloudSyncCollector(root)
                list(collector.run())
        self.assertLessEqual(collector.log_bytes, budget)
        # Record offsets are found lazily (a generator, no list of every offset).
        spans = cloud_sync.odl_record_spans(cloud_sync.ODL_RECORD_SIGNATURE * 3)
        self.assertEqual(next(spans), (0, 8))

    def test_minor_common_logs_borrow_the_single_account_email(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_onedrive(root)
            common = appdata_local(root) / "Microsoft" / "OneDrive" / "logs" / "Common"
            common.mkdir(parents=True)
            record = odl_record(BASE_MS + 5_000, "SyncEngine.cpp", "DownloadFileComplete", ["C:\\Users\\alice\\OneDrive\\c.txt"])
            (common / "SyncEngine-common.odl").write_bytes(odl_file([record], compressed=False))
            rows, _provider = collect(root)
        event = next(row.details for row in of(rows, "cloud-sync-event", "onedrive") if "Common" in row.details["source_path"])
        self.assertEqual(event["account"], "alice@example.com")
        self.assertEqual(event["account_basis"], "sibling-account-folder")

    def test_minor_onedrive_disk_times_reach_the_timeline(self) -> None:
        from rapidtriage.core.timeline import iter_artifact_detail_events

        details = {
            "timestamp": "2024-05-01T09:00:00+00:00",
            "timestamp_kind": "cloud-modified",
            "disk_created_at": "2024-04-01T08:00:00+00:00",
            "disk_accessed_at": "2024-04-02T08:00:00+00:00",
            "item_path": "D:\\Sync\\OneDrive\\a.txt",
        }
        events = list(iter_artifact_detail_events("cloud-sync-file", details))
        by_field = {event["field_path"]: event for event in events}
        self.assertEqual(by_field["details.disk_created_at"]["timestamp"], "2024-04-01T08:00:00+00:00")
        self.assertEqual(by_field["details.disk_created_at"]["timestamp_kind"], "local-created")
        self.assertEqual(by_field["details.disk_accessed_at"]["timestamp_kind"], "local-accessed")


if __name__ == "__main__":
    unittest.main()
