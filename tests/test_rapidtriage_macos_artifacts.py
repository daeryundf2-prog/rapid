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
            self.assertIn("macos-launch-agent", artifact_types)

            browser = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-browser-history-downloads")
            self.assertEqual(browser["details"]["browser"], "safari")
            self.assertEqual(browser["details"]["history"][0]["url"], "https://example.test/mac-download")

            quarantine = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-quarantine-event")
            self.assertEqual(quarantine["details"]["agent_name"], "Safari")
            self.assertEqual(quarantine["details"]["origin_url"], "https://example.test")

            launch_agent = next(item for item in payload["artifacts"] if item["artifact_type"] == "macos-launch-agent")
            self.assertEqual(launch_agent["details"]["label"], "com.example.persist")
            self.assertEqual(launch_agent["details"]["program_arguments"][0], "/usr/bin/osascript")

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
    for directory in (safari_dir, preferences_dir, launch_agents_dir):
        directory.mkdir(parents=True, exist_ok=True)

    create_safari_history(safari_dir / "History.db")
    create_quarantine_db(preferences_dir / "com.apple.LaunchServices.QuarantineEventsV2")
    (launch_agents_dir / "com.example.persist.plist").write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.persist",
                "ProgramArguments": ["/usr/bin/osascript", "-e", "display dialog \"hi\""],
                "RunAtLoad": True,
            }
        )
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
