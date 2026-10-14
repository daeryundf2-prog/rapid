"""Parser-quality round 1: cloud export / mobile acquisition gating and evidence-safe SQLite.

Synthetic fixtures only (built in temporary directories):

* A Windows triage tree (Edge extension ``_locales`` messages, extension
  ``manifest.json``, Task Manager ``settings.json``, payslip ZIPs) must yield
  zero cloud and zero mobile rows.
* Real export signatures (Takeout ``archive_browser.html``, Purview EDRM
  ``Manifest.xml``, iOS backup ``Manifest.db`` + ``Info.plist``, Cellebrite
  ``.ufd``) still yield correct rows.
* Evidence SQLite databases are never opened in place (no ``-wal``/``-shm``).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import plistlib
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.artifacts.android import build_android_sqlite_schema_inventory
from rapidtriage.artifacts.cloud import (
    CloudExportProvider,
    detect_export_type,
    zip_datetime_iso,
)
from rapidtriage.artifacts.mobile import (
    MobileExportProvider,
    detect_artifact_type,
    detect_chat_service,
)
from rapidtriage.artifacts.mobile.roots import NO_MOBILE_ACQUISITION_NOTICE

EDGE_EXTENSION = Path(
    "Users/user/AppData/Local/Microsoft/Edge/User Data/Default/Extensions/ghbmnnjooekpmoecnnnilnnbdlolhkhi/1.91.1_0"
)


def write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def write_windows_triage_noise(root: Path) -> None:
    """The shapes that produced 130 cloud / 236 mobile false positives."""

    extension = root / EDGE_EXTENSION
    write_json(
        extension / "_locales" / "en" / "messages.json",
        {
            "appName": {"message": "Docs offline", "description": "name"},
            "appDesc": {"message": "Edit documents offline", "description": "desc"},
        },
    )
    write_json(
        extension / "manifest.json",
        {"name": "__MSG_appName__", "version": "1.91.1", "manifest_version": 3, "created": "2024-01-01"},
    )
    write_json(
        extension / "_metadata" / "computed_hashes.json",
        {"file_hashes": [{"path": "page_embed_script.js", "block_hashes": ["abc"], "block_size": 4096}]},
    )
    write_json(
        root / "Users/user/AppData/Local/Microsoft/Windows/TaskManager/settings.json",
        [{"app": "Microsoft Edge", "name": "msedge.exe", "version": "1.0", "path": "C:/Program Files/edge.exe"}],
    )
    write_json(
        root / "Users/user/AppData/Local/Microsoft/Edge/User Data/Default/default_cloud_config.json",
        {"app_name": "edge", "package": "com.microsoft.emmx", "name": "Edge", "email": "user@example.com"},
    )
    desktop = root / "Users/user/Desktop/새 폴더"
    desktop.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(desktop / "11월 임금명세서.zip", "w") as archive:
        archive.writestr("임금명세서.pdf", b"%PDF-1.4 payslip")
        archive.writestr("messages.json", json.dumps([{"name": "x", "message": "hello"}]))
    with zipfile.ZipFile(desktop / "NPKI.zip", "w") as archive:
        archive.writestr("NPKI/signCert.der", b"\x30\x82")
    # A generic CSV a user keeps on the desktop: has "message"/"name" columns.
    (desktop / "messages.csv").write_text("name,message,time\n홍길동,안녕하세요,2024-05-01\n", encoding="utf-8")


def make_wal_mode_database(path: Path) -> None:
    """A database whose header says WAL: opening it ``mode=ro`` in place creates -wal/-shm."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
        connection.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?)",
            ("3d0d7e5fb2ce288813306e4d4636395e047a3d28", "HomeDomain", "Library/SMS/sms.db", 1),
        )
        connection.commit()


def sidecars(path: Path) -> list[str]:
    return sorted(
        candidate.name
        for candidate in path.parent.iterdir()
        if candidate.name.startswith(path.name) and candidate.name != path.name
    )


class CloudExportRootGateTests(unittest.TestCase):
    def test_windows_triage_tree_yields_no_cloud_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_windows_triage_noise(root)
            provider = CloudExportProvider()

            rows = list(provider.collect(root))

            self.assertEqual([(row.artifact_type, row.path) for row in rows], [])
            self.assertEqual(provider.collection_notes, ["클라우드 내보내기 루트 없음"])

    def test_unknown_provider_zip_with_takeout_like_entries_is_not_inventoried(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            with zipfile.ZipFile(root / "export.zip", "w") as archive:
                archive.writestr("Takeout/Mail/messages.json", json.dumps([{"subject": "s", "from": "a@b.c", "date": "x"}]))
            self.assertEqual(list(CloudExportProvider().collect(root)), [])

    def test_generic_name_message_keys_do_not_classify_inside_export_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "Takeout").mkdir()
            (root / "Takeout" / "archive_browser.html").write_text("<html></html>", encoding="utf-8")
            write_json(root / "Takeout" / "Chrome" / "messages.json", {"appName": {"message": "x"}})
            write_json(root / "Takeout" / "Chrome" / "manifest.json", {"name": "ext", "version": "1", "created": "2024"})

            rows = list(CloudExportProvider().collect(root))

            self.assertEqual([row.artifact_type for row in rows], [])
            self.assertEqual(detect_export_type("google-takeout/x/manifest.json", {"name": "x", "created": "y"}, family="google"), "")
            self.assertEqual(
                detect_export_type("google-takeout/x/a.json", {"email": "alice@example.com", "name": "Alice"}, family="google"),
                "cloud-account",
            )
            self.assertEqual(detect_export_type("x/messages.json", [{"name": "a", "message": "b"}]), "")

    def test_takeout_directory_with_archive_browser_yields_google_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            takeout = root / "takeout-20260501" / "Takeout"
            takeout.mkdir(parents=True)
            (takeout / "archive_browser.html").write_text("<html>Takeout</html>", encoding="utf-8")
            write_json(
                takeout / "Mail" / "gmail-export.json",
                [{"date": "2026-04-26T04:00:00Z", "from": "alice@example.com", "to": "bob@example.com", "subject": "Invoice", "messageId": "m-1"}],
            )
            write_json(
                takeout / "My Activity" / "Search" / "MyActivity.json",
                [{"header": "Search", "title": "Searched for x", "time": "2026-04-26T01:02:03Z", "products": ["Search"]}],
            )
            write_json(
                takeout / "Location History" / "Records.json",
                {"locations": [{"timestampMs": "1714093200000", "latitudeE7": 374220000, "longitudeE7": -1220840575}]},
            )

            rows = list(CloudExportProvider().collect(root))
            by_type = {row.artifact_type: row for row in rows}

            self.assertEqual(set(by_type), {"cloud-mail", "cloud-activity", "cloud-location"})
            mail = by_type["cloud-mail"].details
            self.assertEqual(mail["service"], "gmail-takeout")
            self.assertEqual(mail["cloud_family"], "google")
            self.assertEqual(mail["cloud_export_root"], "takeout-20260501/Takeout")
            self.assertEqual(mail["cloud_export_root_signature"], "google-takeout:archive_browser.html")
            self.assertEqual(mail["cloud_export_provider_family"], "google")
            self.assertEqual(by_type["cloud-location"].details["latitude"], 37.422)

    def test_takeout_zip_inventory_uses_local_unknown_zip_times(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            archive_path = root / "takeout-20260501T000000Z-001.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                info = zipfile.ZipInfo("Takeout/archive_browser.html", date_time=(2026, 5, 1, 9, 30, 0))
                archive.writestr(info, "<html></html>")
                mail = zipfile.ZipInfo("Takeout/Mail/messages.json", date_time=(2026, 5, 1, 9, 31, 2))
                archive.writestr(
                    mail,
                    json.dumps([{"subject": "Exported", "from": "alice@example.com", "date": "2026-05-01T00:00:00Z", "messageId": "m"}]),
                )

            rows = list(CloudExportProvider().collect(root))
            archive_row = next(row for row in rows if row.artifact_type == "cloud-export-archive")
            mail_row = next(row for row in rows if row.artifact_type == "cloud-mail")

            details = archive_row.details
            self.assertEqual(details["service"], "google-takeout")
            self.assertEqual(details["archive_entry_timezone"], "local-unknown")
            entry = details["cloud_archive_manifest"]["entry_manifest"][0]
            self.assertEqual(entry["modified_at"], "2026-05-01T09:30:00")
            self.assertEqual(entry["modified_at_timezone"], "local-unknown")
            self.assertEqual(details["archive_embedded_parse_entry_limit"], 25)
            self.assertFalse(details["archive_embedded_parse_truncated"])
            self.assertEqual(mail_row.details["archive_entry_modified_at"], "2026-05-01T09:31:02")
            self.assertEqual(mail_row.details["archive_entry_modified_at_timezone"], "local-unknown")
            self.assertEqual(mail_row.details["cloud_export_root_signature"], "google-takeout:archive_browser.html")

    def test_zip_datetime_is_naive_never_utc(self) -> None:
        info = zipfile.ZipInfo("a.txt", date_time=(2024, 2, 3, 4, 5, 6))
        value = zip_datetime_iso(info)
        self.assertEqual(value, "2024-02-03T04:05:06")
        self.assertIsNone(dt.datetime.fromisoformat(value).tzinfo)

    def test_m365_purview_manifest_root_classifies_teams_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            export = root / "Case-001 Export"
            export.mkdir()
            (export / "Manifest.xml").write_text(
                '<?xml version="1.0"?><Root MajorVersion="1" DataInterchangeType="Update" Description="EDRM"><Batch/></Root>',
                encoding="utf-8",
            )
            write_json(
                export / "Teams" / "messages.json",
                [{"createdDateTime": "2026-04-26T06:00:00Z", "chatId": "chat-1", "id": "t-1", "messageText": "hello"}],
            )
            write_json(
                export / "Audit" / "audit.json",
                [{"creationTime": "2026-04-26T07:00:00Z", "operation": "UserLoggedIn", "userId": "alice@example.com"}],
            )

            rows = list(CloudExportProvider().collect(root))
            by_type = {row.artifact_type: row.details for row in rows}

            self.assertEqual(set(by_type), {"cloud-message", "cloud-audit"})
            self.assertEqual(by_type["cloud-message"]["service"], "microsoft-teams")
            self.assertEqual(by_type["cloud-message"]["cloud_family"], "microsoft-365")
            self.assertEqual(by_type["cloud-audit"]["cloud_export_root_signature"], "m365-purview-export:Manifest.xml")
            self.assertTrue(by_type["cloud-audit"]["service"].startswith("microsoft"))

    def test_microsoft_path_without_root_is_not_m365(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_json(
                root / "Users/user/Documents/Microsoft/Teams/messages.json",
                [{"createdDateTime": "2026-04-26T06:00:00Z", "chatId": "chat-1", "messageText": "hello"}],
            )
            self.assertEqual(list(CloudExportProvider().collect(root)), [])

    def test_standalone_cloudtrail_is_self_describing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_json(
                root / "logs" / "trail.json",
                {"Records": [{"eventTime": "2026-05-01T01:02:03Z", "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"}]},
            )
            # Path tokens alone ("aws") are not a schema.
            write_json(root / "aws" / "notes.json", [{"name": "x", "operation": "y"}])

            rows = list(CloudExportProvider().collect(root))

            self.assertEqual([row.artifact_type for row in rows], ["cloud-iaas-audit"])
            self.assertEqual(rows[0].details["service"], "aws-cloudtrail")
            self.assertEqual(rows[0].details["cloud_export_root_signature"], "aws-cloudtrail:record-schema")


class MobileAcquisitionRootGateTests(unittest.TestCase):
    def test_windows_triage_tree_yields_no_mobile_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_windows_triage_noise(root)
            # A macOS app bundle Info.plist and a chat-named SQLite are not an acquisition.
            bundle = root / "Users/user/Downloads/KakaoTalk.app/Contents"
            bundle.mkdir(parents=True)
            (bundle / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "KakaoTalk"}))
            make_wal_mode_database(root / "Users/user/AppData/Local/WhatsApp/msgstore.db")
            provider = MobileExportProvider()

            rows = list(provider.collect(root))

            self.assertEqual([(row.artifact_type, row.path) for row in rows], [])
            self.assertEqual(provider.collection_notes, [NO_MOBILE_ACQUISITION_NOTICE])
            self.assertEqual(NO_MOBILE_ACQUISITION_NOTICE, "모바일 추출물 없음")

    def test_app_token_does_not_match_appdata(self) -> None:
        row = {"appname": "Edge", "version": "1.0", "name": "msedge"}
        self.assertEqual(detect_artifact_type(row, Path("Users/user/AppData/Local/TaskManager/settings.json")), "")
        self.assertEqual(detect_artifact_type(row, Path("Cellebrite/Installed Apps/apps.json")), "mobile-app")

    def test_chat_alias_is_whole_token(self) -> None:
        self.assertEqual(detect_chat_service({"text": "online by the deadline"}, Path("notes.csv")), "")
        self.assertEqual(detect_chat_service({"service": "LINE"}, Path("export.csv")), "LINE")

    def test_ios_backup_root_yields_rows_without_touching_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            backup = root / "Users/user/AppData/Roaming/Apple Computer/MobileSync/Backup/00008030-001"
            backup.mkdir(parents=True)
            (backup / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "iPhone", "Product Version": "18.4"}))
            (backup / "Status.plist").write_bytes(plistlib.dumps({"SnapshotState": "finished"}))
            manifest = backup / "Manifest.db"
            make_wal_mode_database(manifest)
            before = hashlib.sha256(manifest.read_bytes()).hexdigest()
            self.assertEqual(sidecars(manifest), [])

            rows = list(MobileExportProvider().collect(root))
            types = sorted({row.artifact_type for row in rows})

            self.assertEqual(types, ["ios-backup-file", "ios-backup-metadata", "ios-backup-source"])
            source = next(row for row in rows if row.artifact_type == "ios-backup-source").details
            self.assertTrue(source["validation_checks"]["opened_readonly"])
            self.assertEqual(source["mobile_acquisition_root_kind"], "ios-backup")
            self.assertEqual(source["mobile_acquisition_root_signature"], "Manifest.db")
            self.assertEqual(source["sqlite_snapshot_provenance"]["profile_version"], "sqlite-working-snapshot-v1")
            file_row = next(row for row in rows if row.artifact_type == "ios-backup-file").details
            self.assertEqual(file_row["domain"], "HomeDomain")
            self.assertEqual(sidecars(manifest), [])
            self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), before)

    def test_cellebrite_ufd_root_classifies_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            export = root / "Case 7" / "Phone"
            export.mkdir(parents=True)
            (export / "Phone.ufd").write_text("[General]\nVersion=7.66\n", encoding="utf-8")
            (export / "Messages.csv").write_text(
                "Timestamp,From,To,Body,Direction\n2026-04-26T01:02:03Z,+15550100,+15550200,hello,outgoing\n",
                encoding="utf-8",
            )

            rows = list(MobileExportProvider().collect(root))
            message = next(row for row in rows if row.artifact_type == "mobile-message").details

            self.assertEqual(message["source_tool"], "cellebrite")
            self.assertEqual(message["sender"], "+15550100")
            self.assertEqual(message["mobile_acquisition_root"], "Case 7/Phone")
            self.assertEqual(message["mobile_acquisition_root_kind"], "cellebrite-ufed")

    def test_android_data_tree_and_adb_backup_are_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_json(
                root / "extraction" / "data" / "data" / "com.example.contacts" / "files" / "contacts.json",
                [{"Display Name": "Alice", "Phone Number": "+15550100"}],
            )
            (root / "backup.ab").write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + b"\x00" * 16)

            rows = list(MobileExportProvider().collect(root))
            types = {row.artifact_type for row in rows}

            self.assertIn("mobile-contact", types)
            contact = next(row for row in rows if row.artifact_type == "mobile-contact").details
            self.assertEqual(contact["mobile_acquisition_root_kind"], "android-data-tree")
            self.assertEqual(contact["mobile_acquisition_root"], "extraction")


class AndroidSqliteSnapshotTests(unittest.TestCase):
    def test_schema_inventory_never_opens_evidence_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = Path(tmp_dir) / "data" / "data" / "com.example" / "databases" / "app.db"
            make_wal_mode_database(database)
            before = hashlib.sha256(database.read_bytes()).hexdigest()

            inventory = build_android_sqlite_schema_inventory(database)

            self.assertTrue(inventory["opened_readonly"])
            self.assertEqual(inventory["table_count"], 1)
            self.assertEqual(inventory["total_row_count"], 1)
            self.assertEqual(inventory["sqlite_snapshot_provenance"]["profile_version"], "sqlite-working-snapshot-v1")
            self.assertEqual(sidecars(database), [])
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
