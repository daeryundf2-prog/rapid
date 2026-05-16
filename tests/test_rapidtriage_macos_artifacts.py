from __future__ import annotations

import json
import hashlib
import os
import plistlib
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rapidtriage.cli import main
from rapidtriage.artifacts.kakaotalk_macos import (
    derive_kakaotalk_macos_database_name,
    derive_kakaotalk_macos_secure_key,
    extract_kakaotalk_macos_user_id_candidates,
    env_user_id_overrides,
    hashed_macos_device_uuid,
    recover_user_id_from_sha512_directory_hash,
)


class RapidTriageMacOsArtifactsTests(unittest.TestCase):
    def test_kakaotalk_macos_public_derivation_vectors_are_stable(self) -> None:
        uuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
        user_id = 12345

        self.assertEqual(
            hashed_macos_device_uuid(uuid),
            "nimoAVPKEChfYbT+0fQ9rqnv84dfSdAmfUERfn8ODHCuZqqkpDv1VDDltK5kAvIyIeZ3KA==",
        )
        self.assertEqual(
            derive_kakaotalk_macos_database_name(user_id, uuid),
            "41d955f9bda54b4af4c5ef87c2954421e0fc1efb939c01b77077b29dd8d55364706a0e98db7259",
        )
        self.assertEqual(
            hashlib.sha256(derive_kakaotalk_macos_secure_key(user_id, uuid).encode("utf-8")).hexdigest(),
            "fe3ccd86a1fbc9d088f1fd52f85000e609efd630411cd35bd273b764789746a1",
        )

    def test_kakaotalk_macos_plist_extracts_alert_ids_without_raw_key_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plist_path = Path(tmp_dir) / "com.kakao.KakaoTalkMac.test.plist"
            plist_path.write_bytes(plistlib.dumps({"AlertKakaoIDsList": [12345, "67890", 0]}))

            candidates, active_hashes, sources = extract_kakaotalk_macos_user_id_candidates([plist_path])

            self.assertEqual(candidates, [12345, 67890])
            self.assertEqual(active_hashes, [])
            self.assertEqual(sources, {"AlertKakaoIDsList"})

    def test_kakaotalk_macos_user_directory_hash_recovery_is_opt_in(self) -> None:
        user_id = 4242
        directory_hash = hashlib.sha512(str(user_id).encode("utf-8")).digest()[20:40].hex()

        with patch.dict(os.environ, {"RAPIDTRIAGE_KAKAO_MAC_SHA512_BRUTE_MAX": "0"}):
            self.assertIsNone(recover_user_id_from_sha512_directory_hash(directory_hash))
        with patch.dict(os.environ, {"RAPIDTRIAGE_KAKAO_MAC_SHA512_BRUTE_MAX": "5000"}):
            self.assertEqual(recover_user_id_from_sha512_directory_hash(directory_hash), user_id)

    def test_kakaotalk_macos_user_id_file_is_read_without_serializing_raw_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            user_id_file = Path(tmp_dir) / "uid.txt"
            user_id_file.write_text("12345\n", encoding="utf-8")

            with patch.dict(os.environ, {"RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE": str(user_id_file)}, clear=False):
                self.assertIn(12345, env_user_id_overrides())

    def test_macos_system_collector_imports_user_browser_quarantine_and_launch_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_macos_fixture(root)
            output = root / "macos-system.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "macos-system", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {item["artifact_type"] for item in payload["artifacts"]}

            self.assertEqual(payload["kind"], "macos-system")
            self.assertIn("macos-user-profile", artifact_types)
            self.assertIn("macos-browser-history-downloads", artifact_types)
            self.assertIn("macos-quarantine-event", artifact_types)
            self.assertIn("macos-tcc-permission", artifact_types)
            self.assertIn("macos-launch-agent", artifact_types)
            self.assertIn("macos-unified-log-file", artifact_types)
            self.assertIn("macos-spotlight-store", artifact_types)
            self.assertIn("macos-fsevents-file", artifact_types)
            self.assertIn("macos-apfs-snapshot-hint", artifact_types)
            self.assertIn("ai-service-export-conversation", artifact_types)

            browser = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-browser-history-downloads")
            self.assertEqual(browser["details"]["browser"], "safari")
            self.assertEqual(browser["details"]["history"][0]["url"], "https://example.test/mac-download")
            self.assertEqual(browser["details"]["download_count"], 1)
            safari_download = browser["details"]["downloads"][0]
            self.assertEqual(safari_download["download_evidence"], "macos-quarantine")
            self.assertEqual(safari_download["source_table"], "LSQuarantineEvent")
            self.assertEqual(safari_download["source_database"], "com.apple.LaunchServices.QuarantineEventsV2")
            self.assertEqual(safari_download["source_url"], "https://example.test/mac-download/payload.zip")
            self.assertEqual(safari_download["agent_name"], "Safari")
            download_timeline = [
                row for row in browser["details"]["unified_timeline"] if row["timeline_type"] == "download"
            ]
            self.assertEqual(len(download_timeline), 1)
            self.assertEqual(download_timeline[0]["download_evidence"], "macos-quarantine")
            self.assertEqual(download_timeline[0]["source_table"], "LSQuarantineEvent")
            self.assertEqual(
                download_timeline[0]["source_database"],
                "com.apple.LaunchServices.QuarantineEventsV2",
            )
            browser_gates = {gate["gap_id"]: gate for gate in browser["details"]["core_accuracy_gates"]}
            self.assertIn("macOS Safari quarantine download correlation", browser_gates["#20"]["satisfied_checks"])
            self.assertTrue(browser["details"]["browser_timeline_depth_manifest"]["native_depth"]["macos_safari_quarantine_downloads"])
            citation_manifest = browser["details"]["browser_history_download_citation_manifest"]
            self.assertEqual(citation_manifest["download_row_count"], 1)
            self.assertIn("com.apple.LaunchServices.QuarantineEventsV2", citation_manifest["download_citations"][0]["source_viewer_locator"]["source_path"])
            self.assertEqual(citation_manifest["download_citations"][0]["source_database"], "com.apple.LaunchServices.QuarantineEventsV2")
            self.assertIn(
                "macos-safari-quarantine-downloads-correlated",
                browser["details"]["commercial_uplift_evidence"]["functional_priority_profiles"][0]["passed_validation_check_ids"],
            )

            quarantine = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-quarantine-event")
            self.assertEqual(quarantine["details"]["agent_name"], "Safari")
            self.assertEqual(quarantine["details"]["origin_url"], "https://example.test")

            launch_agent = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-launch-agent")
            self.assertEqual(launch_agent["details"]["label"], "com.example.persist")
            self.assertEqual(launch_agent["details"]["program_arguments"][0], "/usr/bin/osascript")

            tcc = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-tcc-permission")
            self.assertEqual(tcc["details"]["service"], "kTCCServiceSystemPolicyAllFiles")
            self.assertEqual(tcc["details"]["client"], "/Users/alice/Library/Application Support/persist/helper")
            self.assertTrue(tcc["details"]["allowed"])
            self.assertIn("high-value-privacy-permission", tcc["details"]["risk_flags"])
            self.assertIn("user-writable-client-path", tcc["details"]["risk_flags"])

            unified_log = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-unified-log-file")
            self.assertIn("/Users/alice/Library/LaunchAgents/com.example.persist.plist", unified_log["details"]["path_candidates"])
            self.assertIn("macos-string:osascript", unified_log["details"]["risk_flags"])
            self.assertTrue(unified_log["details"]["validation_required"])

            spotlight = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-spotlight-store")
            self.assertIn("https://example.test/mac-download", spotlight["details"]["url_candidates"])

            fsevents = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-fsevents-file")
            self.assertIn("/Users/alice/Documents/mac-report.txt", fsevents["details"]["path_candidates"])

            snapshot_hint = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-apfs-snapshot-hint")
            self.assertTrue(snapshot_hint["details"]["is_directory"])

            ai_export = next(item for item in payload["artifacts"] if item["artifact_type"] == "ai-service-export-conversation")
            self.assertEqual(ai_export["provider"], "macos-system-artifacts")
            self.assertEqual(ai_export["details"]["parser"], "ai-service-export-parser")
            self.assertEqual(ai_export["details"]["profile"], "ChatGPT")
            self.assertEqual(ai_export["details"]["complete_pair_count"], 1)
            self.assertEqual(ai_export["details"]["transcript_pairs"][0]["question"], "How do we preserve citations?")
            self.assertIn("ai_service_export_parser_manifest", ai_export["details"])

    def test_macos_system_collector_is_wired_into_run_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_root = root / "mac-case"
            output_dir = root / "run-out"
            build_macos_fixture(evidence_root)
            (evidence_root / "Users" / "alice" / "Documents" / "mac-report.txt").write_text(
                "powershell password",
                encoding="utf-8",
            )

            self.assertEqual(
                main(["run", str(evidence_root), "--mode", "hacking", "--output-dir", str(output_dir), "--read-only"]),
                0,
            )

            summary = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertIn("macos-system", summary["summary"]["artifacts"])
            self.assertIn("artifacts_macos-system", summary["outputs"])
            self.assertTrue(Path(summary["outputs"]["artifacts_macos-system"]).is_file())
            self.assertGreaterEqual(summary["summary"]["artifacts"]["macos-system"]["artifact_count"], 1)

    def test_macos_system_collector_parses_ai_service_export_zip_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_root = root / "mac-case"
            output = root / "macos-system-ai-zip.json"
            user_docs = evidence_root / "Users" / "alice" / "Documents"
            user_docs.mkdir(parents=True)
            (evidence_root / "System" / "Library").mkdir(parents=True)
            archive_path = user_docs / "ChatGPT-export.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "conversations.json",
                    json.dumps(
                        [
                            {
                                "title": "Mac export ZIP",
                                "messages": [
                                    {"role": "user", "content": "Can ZIP exports keep citations?"},
                                    {"role": "assistant", "content": "Yes, keep archive and entry hashes."},
                                ],
                            }
                        ]
                    ),
                )

            self.assertEqual(main(["artifacts", str(evidence_root), "--kind", "macos-system", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            ai_export = next(item for item in payload["artifacts"] if item["artifact_type"] == "ai-service-export-conversation")
            details = ai_export["details"]
            self.assertEqual(ai_export["provider"], "macos-system-artifacts")
            self.assertEqual(details["source_format"], "zip-json-entry")
            self.assertEqual(details["coverage_status"], "service-export-zip-json-candidate")
            self.assertEqual(details["archive_entry_name"], "conversations.json")
            self.assertEqual(details["profile"], "ChatGPT")
            self.assertEqual(details["complete_pair_count"], 1)
            self.assertEqual(details["conversation_candidates"][0]["source_storage_kind"], "service-export-zip-json")
            self.assertIn("::conversations.json", details["conversation_candidates"][0]["source_path"])
            self.assertEqual(
                details["ai_service_export_parser_manifest"]["source_format"],
                "zip-json-entry",
            )
            self.assertEqual(
                details["ai_service_export_parser_manifest"]["archive_context"]["archive_entry_name"],
                "conversations.json",
            )
            self.assertIn("archive completeness", details["validation_guidance"])

    def test_kakaotalk_macos_collector_reports_db_openability_and_message_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_macos_fixture(root)
            output = root / "kakaotalk-macos.json"

            self.assertEqual(main(["artifacts", str(root), "--kind", "kakaotalk-macos", "--output", str(output)]), 0)

            payload = json.loads(output.read_text(encoding="utf-8"))
            artifact_types = {item["artifact_type"] for item in payload["artifacts"]}
            self.assertEqual(payload["kind"], "kakaotalk-macos")
            self.assertIn("kakaotalk-macos-database", artifact_types)
            self.assertIn("kakaotalk-macos-summary", artifact_types)

            opened = next(
                item
                for item in payload["artifacts"]
                if item["artifact_type"] == "kakaotalk-macos-database"
                and item["details"]["sqlite_access"]["open_status"] == "opened-read-only"
            )
            analysis = opened["details"]["kakaotalk_macos_db_analysis"]
            identity = opened["details"]["kakaotalk_macos_identity_context"]
            self.assertTrue(analysis["db_opened"])
            self.assertEqual(analysis["db_access_status"], "plain-sqlite-opened")
            self.assertEqual(analysis["message_row_count_estimate"], 2)
            self.assertEqual(analysis["message_table_candidates"][0]["table"], "messages")
            self.assertIn("message", analysis["message_table_candidates"][0]["content_columns_detected"])
            self.assertFalse(analysis["content_exported"])
            self.assertFalse(analysis["sqlcipher_probe"]["attempted"])
            self.assertGreaterEqual(identity["user_id_candidate_count"], 1)
            self.assertEqual(identity["user_directory_hash_count"], 1)
            self.assertFalse(identity["sqlcipher_key_material_exported"])
            self.assertIn("plain-sqlite-opened", opened["details"]["risk_flags"])
            self.assertFalse(opened["details"]["commercial_grade_ready"])

            encrypted = next(
                item
                for item in payload["artifacts"]
                if item["artifact_type"] == "kakaotalk-macos-database"
                and item["details"]["kakaotalk_macos_db_analysis"]["requires_sqlcipher_or_custom_decoder"]
            )
            self.assertEqual(
                encrypted["details"]["kakaotalk_macos_db_analysis"]["db_access_status"],
                "encrypted-or-custom-store-validation-required",
            )
            self.assertIn("sqlcipher_probe", encrypted["details"]["kakaotalk_macos_db_analysis"])

            summary = next(item for item in payload["artifacts"] if item["artifact_type"] == "kakaotalk-macos-summary")
            self.assertEqual(summary["details"]["plain_sqlite_opened_count"], 1)
            self.assertEqual(summary["details"]["encrypted_or_custom_store_count"], 1)
            self.assertEqual(summary["details"]["message_row_count_estimate"], 2)
            self.assertTrue(summary["details"]["db_analysis_supported"])

    def test_kakaotalk_macos_report_exports_review_package_with_opt_in_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_macos_fixture(root)
            output_dir = root / "kakaotalk-macos-report"

            self.assertEqual(
                main(
                    [
                        "kakaotalk-macos-report",
                        str(root),
                        "--output-dir",
                        str(output_dir),
                        "--include-message-text",
                        "--max-messages",
                        "10",
                    ]
                ),
                0,
            )

            report_path = output_dir / "kakaotalk_macos_report.json"
            summary_path = output_dir / "kakaotalk_macos_summary.json"
            messages_csv = output_dir / "kakaotalk_macos_messages.csv"
            rooms_csv = output_dir / "kakaotalk_macos_rooms.csv"
            media_csv = output_dir / "kakaotalk_macos_media.csv"
            viewer_html = output_dir / "kakaotalk_macos_viewer.html"
            audit_path = output_dir / "kakaotalk_macos_report.audit.json"

            for path in (report_path, summary_path, messages_csv, rooms_csv, media_csv, viewer_html, audit_path):
                self.assertTrue(path.is_file(), path)

            payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["parser"], "kakaotalk-macos-report")
            self.assertEqual(payload["summary"]["message_count"], 2)
            self.assertEqual(payload["summary"]["plain_sqlite_opened_count"], 1)
            self.assertTrue(payload["privacy"]["message_text_exported"])
            self.assertFalse(payload["privacy"]["raw_user_id_exported"])
            self.assertFalse(payload["privacy"]["sqlcipher_key_exported"])

            csv_text = messages_csv.read_text(encoding="utf-8-sig")
            self.assertIn("hello", csv_text)
            self.assertIn("world", csv_text)
            self.assertIn(hashlib.sha256("hello".encode("utf-8")).hexdigest(), csv_text)

            html_text = viewer_html.read_text(encoding="utf-8")
            self.assertIn("RapidTriage macOS KakaoTalk Viewer", html_text)
            self.assertIn("hello", html_text)
            self.assertNotIn("sqlcipher_key", html_text)

            audit = json.loads(audit_path.read_text(encoding="utf-8"))
            self.assertEqual(audit["command"], "kakaotalk-macos-report")
            self.assertFalse(audit["provenance"]["options"]["raw_user_id_exported"])
            self.assertFalse(audit["provenance"]["options"]["sqlcipher_key_exported"])

    def test_kakaotalk_macos_report_redacts_message_text_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_macos_fixture(root)
            output_dir = root / "kakaotalk-macos-report"

            self.assertEqual(
                main(["kakaotalk-macos-report", str(root), "--output-dir", str(output_dir), "--max-messages", "10"]),
                0,
            )

            payload = json.loads((output_dir / "kakaotalk_macos_report.json").read_text(encoding="utf-8"))
            csv_text = (output_dir / "kakaotalk_macos_messages.csv").read_text(encoding="utf-8-sig")
            html_text = (output_dir / "kakaotalk_macos_viewer.html").read_text(encoding="utf-8")

            self.assertEqual(payload["summary"]["message_count"], 2)
            self.assertFalse(payload["privacy"]["message_text_exported"])
            self.assertNotIn("hello", csv_text)
            self.assertNotIn("world", csv_text)
            self.assertIn(hashlib.sha256("hello".encode("utf-8")).hexdigest(), csv_text)
            self.assertIn("[redacted]", html_text)

    def test_kakaotalk_macos_report_warns_when_context_rows_are_capped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_macos_fixture(root)
            db_path = next(root.rglob("chat_messages.db"))
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE chat_rooms (id INTEGER PRIMARY KEY, name TEXT)")
                for index in range(7):
                    connection.execute(
                        "INSERT INTO chat_rooms (name) VALUES (?)",
                        (f"room-{index}",),
                    )
                connection.commit()
            finally:
                connection.close()
            output_dir = root / "kakaotalk-macos-report"

            self.assertEqual(
                main(
                    [
                        "kakaotalk-macos-report",
                        str(root),
                        "--output-dir",
                        str(output_dir),
                        "--max-messages",
                        "10",
                        "--max-context-rows",
                        "5",
                    ]
                ),
                0,
            )

            payload = json.loads((output_dir / "kakaotalk_macos_report.json").read_text(encoding="utf-8"))
            html_text = (output_dir / "kakaotalk_macos_viewer.html").read_text(encoding="utf-8")
            coverage = payload["context_row_coverage"][0]

            self.assertTrue(payload["summary"]["context_limit_reached"])
            self.assertEqual(payload["summary"]["context_truncated_table_count"], 1)
            self.assertEqual(payload["summary"]["room_context_row_count"], 5)
            self.assertEqual(payload["summary"]["room_context_row_estimate"], 7)
            self.assertEqual(coverage["source_table"], "chat_rooms")
            self.assertEqual(coverage["row_count"], 7)
            self.assertEqual(coverage["exported_rows"], 5)
            self.assertEqual(coverage["row_limit"], 5)
            self.assertTrue(coverage["truncated"])
            self.assertIn("Context export warning", html_text)


def build_macos_fixture(root: Path) -> None:
    user_root = root / "Users" / "alice"
    (user_root / "Documents").mkdir(parents=True, exist_ok=True)
    safari_dir = user_root / "Library" / "Safari"
    preferences_dir = user_root / "Library" / "Preferences"
    launch_agents_dir = user_root / "Library" / "LaunchAgents"
    tcc_dir = user_root / "Library" / "Application Support" / "com.apple.TCC"
    for directory in (safari_dir, preferences_dir, launch_agents_dir, tcc_dir):
        directory.mkdir(parents=True, exist_ok=True)

    create_safari_history(safari_dir / "History.db")
    create_quarantine_db(preferences_dir / "com.apple.LaunchServices.QuarantineEventsV2")
    create_tcc_db(tcc_dir / "TCC.db")
    (launch_agents_dir / "com.example.persist.plist").write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.persist",
                "ProgramArguments": ["/usr/bin/osascript", "-e", "display dialog \"hi\""],
                "RunAtLoad": True,
            }
        )
    )
    diagnostics_dir = root / "private" / "var" / "db" / "diagnostics" / "Persist"
    spotlight_dir = root / ".Spotlight-V100" / "Store-V2" / "ABCDEF"
    fsevents_dir = root / ".fseventsd"
    snapshots_dir = root / ".snapshots" / "com.apple.TimeMachine.localsnapshots" / "2024-04-01-010203"
    for directory in (diagnostics_dir, spotlight_dir, fsevents_dir, snapshots_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (diagnostics_dir / "system.tracev3").write_bytes(
        b"\x00\x01/Users/alice/Library/LaunchAgents/com.example.persist.plist\x00osascript persistence\x00"
    )
    (spotlight_dir / "store.db").write_bytes(
        b"\x00/Users/alice/Documents/mac-report.txt\x00https://example.test/mac-download\x00"
    )
    (fsevents_dir / "0000000000000001.fseventsd").write_bytes(
        b"\x00/Users/alice/Documents/mac-report.txt\x00/Applications/Safari.app\x00"
    )
    (user_root / "Documents" / "ChatGPT-conversations.json").write_text(
        json.dumps(
            [
                {
                    "title": "Citation workflow",
                    "messages": [
                        {"role": "user", "content": "How do we preserve citations?"},
                        {"role": "assistant", "content": "Keep source hashes and stable locators."},
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    create_kakaotalk_macos_fixture(user_root)


def create_safari_history(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
        connection.execute(
            "CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL)"
        )
        connection.execute(
            "INSERT INTO history_items (id, url, title) VALUES (?, ?, ?)",
            (1, "https://example.test/mac-download", "Mac Download"),
        )
        connection.execute(
            "INSERT INTO history_visits (history_item, visit_time) VALUES (?, ?)",
            (1, 735000000.0),
        )
        connection.commit()
    finally:
        connection.close()


def create_tcc_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE access (
                service TEXT,
                client TEXT,
                client_type INTEGER,
                auth_value INTEGER,
                auth_reason INTEGER,
                auth_version INTEGER,
                indirect_object_identifier TEXT,
                flags INTEGER,
                last_modified INTEGER
            )
            """
        )
        connection.execute(
            """
            INSERT INTO access (
                service,
                client,
                client_type,
                auth_value,
                auth_reason,
                auth_version,
                indirect_object_identifier,
                flags,
                last_modified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "kTCCServiceSystemPolicyAllFiles",
                "/Users/alice/Library/Application Support/persist/helper",
                1,
                2,
                4,
                1,
                "UNUSED",
                0,
                1_700_000_000,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def create_quarantine_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE LSQuarantineEvent (
                LSQuarantineTimeStamp REAL,
                LSQuarantineAgentName TEXT,
                LSQuarantineDataURLString TEXT,
                LSQuarantineOriginURLString TEXT,
                LSQuarantineSenderName TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO LSQuarantineEvent (
                LSQuarantineTimeStamp,
                LSQuarantineAgentName,
                LSQuarantineDataURLString,
                LSQuarantineOriginURLString,
                LSQuarantineSenderName
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                735000060.0,
                "Safari",
                "https://example.test/mac-download/payload.zip",
                "https://example.test",
                "example.test",
            ),
        )
        connection.commit()
    finally:
        connection.close()


def create_kakaotalk_macos_fixture(user_root: Path) -> None:
    user_id = 12345
    container_root = (
        user_root
        / "Library"
        / "Containers"
        / "com.kakao.KakaoTalkMac"
        / "Data"
    )
    user_hash = hashlib.sha512(str(user_id).encode("utf-8")).hexdigest()[40:80]
    (container_root / "Library" / "Application Support" / "com.kakao.KakaoTalkMac" / user_hash).mkdir(
        parents=True,
        exist_ok=True,
    )
    preferences_root = container_root / "Library" / "Preferences"
    preferences_root.mkdir(parents=True, exist_ok=True)
    (preferences_root / "com.kakao.KakaoTalkMac.ABCDEF.plist").write_bytes(
        plistlib.dumps({"AlertKakaoIDsList": [user_id]})
    )
    kakao_root = (
        container_root
        / "Library"
        / "Application Support"
        / "KakaoTalk"
        / "users"
        / "profile-001"
    )
    kakao_root.mkdir(parents=True, exist_ok=True)
    db_path = kakao_root / "chat_messages.db"
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            """
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY,
                chat_id TEXT,
                sender TEXT,
                message TEXT,
                created_at INTEGER
            )
            """
        )
        connection.execute(
            "INSERT INTO messages (chat_id, sender, message, created_at) VALUES (?, ?, ?, ?)",
            ("room-1", "alice", "hello", 1_700_000_100),
        )
        connection.execute(
            "INSERT INTO messages (chat_id, sender, message, created_at) VALUES (?, ?, ?, ?)",
            ("room-1", "bob", "world", 1_700_000_200),
        )
        connection.commit()
    finally:
        connection.close()
    (kakao_root / "chat_messages.db-wal").write_bytes(b"fixture wal companion")
    (kakao_root / "chatLogs_1.edb").write_bytes(b"\x01\x02encrypted-or-custom-kakao-macos-db")


if __name__ == "__main__":
    unittest.main()
