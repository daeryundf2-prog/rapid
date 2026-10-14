from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.artifact_store import artifact_record_with_fields
from tests.windows_artifact_fixtures import build_minimal_lnk

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapidtriage" / "windows_artifacts"


class RapidTriageArtifactsCliTests(unittest.TestCase):
    def test_parser_exposes_artifacts_subcommand_and_examples(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("artifacts", commands)
        help_text = commands["artifacts"].format_help()
        self.assertIn("--kind", help_text)
        self.assertIn("rapidtriage artifacts . --kind browser", help_text)
        self.assertIn("recent-files", help_text)
        self.assertIn("windows-registry", help_text)
        self.assertIn("windows-shellbags", help_text)

    def test_browser_artifacts_command_writes_expected_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "browser.json"

            exit_code = main(["artifacts", str(FIXTURE_ROOT), "--kind", "browser", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "artifacts")
            self.assertEqual(payload["kind"], "browser")
            self.assertEqual(payload["provider"]["name"], "windows-browser-artifacts")
            # Parser-quality r1: History/places rows expand per URL/visit/download
            # (Chrome, Edge and Firefox all emit ``browser-history`` rows).
            self.assertEqual(
                payload["summary"]["artifact_type_counts"],
                {"browser-history-downloads": 2, "browser-history": 5, "browser-download": 2, "browser-visit": 1},
            )
            self.assertEqual(len(payload["artifacts"]), 10)
            self.assertEqual(payload["artifact_record_contract"]["schema"], "ArtifactRecordV1")
            self.assertEqual(payload["artifact_record_contract"]["valid_count"], 10)
            self.assertEqual(payload["artifact_record_contract"]["invalid_count"], 0)
            self.assertTrue(payload["artifact_record_contract"]["gui_usable"])
            first_record = payload["artifacts"][0]["artifact_record"]
            self.assertEqual(first_record["schema"], "ArtifactRecordV1")
            self.assertEqual(first_record["artifact_family"], "browser")
            # Rows are serialized once: the envelope omits ``fields`` and it is
            # rebuilt from ``details`` on demand.
            self.assertNotIn("fields", first_record)
            self.assertEqual(first_record["fields_source"], "details")
            rebuilt = artifact_record_with_fields(payload["artifacts"][0])
            self.assertEqual(rebuilt["fields"]["gui_contract"]["primary_tab"], "artifacts")
            self.assertEqual(rebuilt["fields"]["details"], payload["artifacts"][0]["details"])

    def test_recent_files_artifacts_command_writes_expected_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "recent.json"
            # The repo fixture's ``Case Notes.lnk`` is plain text (reported as
            # ``recent-shortcut-invalid-content``); write a real Shell Link so
            # the CLI path still exercises LNK parsing.
            root = Path(tmp_dir) / "evidence"
            shutil.copytree(FIXTURE_ROOT, root)
            lnk_path = root / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "Case Notes.lnk"
            lnk_path.write_bytes(
                build_minimal_lnk(r"C:\Users\alice\Documents\Case Notes.docx", datetime(2024, 3, 5, 6, 7, 8, tzinfo=timezone.utc))
            )

            exit_code = main(["artifacts", str(root), "--kind", "recent-files", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "recent-files")
            self.assertEqual(payload["provider"]["name"], "windows-recent-files")
            self.assertEqual(payload["summary"]["artifact_count"], 3)
            self.assertEqual(
                set(payload["summary"]["artifact_type_counts"]),
                {"recent-shortcut", "jumplist-automatic", "jumplist-custom"},
            )
            shortcut = next(item for item in payload["artifacts"] if item["artifact_type"] == "recent-shortcut")
            self.assertIn("Case Notes.docx", json.dumps(shortcut["details"], ensure_ascii=False))

    def test_registry_artifacts_command_is_exposed_and_writes_user_activity_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "registry.json"

            exit_code = main(["artifacts", str(FIXTURE_ROOT), "--kind", "windows-registry", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "windows-registry")
            self.assertEqual(payload["provider"]["name"], "windows-registry")
            self.assertIn("registry-summary", payload["summary"]["artifact_type_counts"])
            self.assertGreater(payload["summary"]["artifact_type_counts"].get("registry-run-key", 0), 0)
            self.assertGreater(payload["summary"]["artifact_type_counts"].get("registry-user-activity", 0), 0)

    def test_shellbags_artifacts_command_is_exposed_and_writes_review_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "shellbags.json"

            exit_code = main(["artifacts", str(FIXTURE_ROOT), "--kind", "windows-shellbags", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "windows-shellbags")
            self.assertEqual(payload["provider"]["name"], "windows-shellbags")
            self.assertGreater(payload["summary"]["artifact_count"], 0)
            self.assertIn("shellbag", json.dumps(payload["artifacts"], ensure_ascii=False).lower())


if __name__ == "__main__":
    unittest.main()
