from __future__ import annotations

import json
import plistlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main


class RapidTriageMacOsArtifactsTests(unittest.TestCase):
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

            browser = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-browser-history-downloads")
            self.assertEqual(browser["details"]["browser"], "safari")
            self.assertEqual(browser["details"]["history"][0]["url"], "https://example.test/mac-download")

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


if __name__ == "__main__":
    unittest.main()
