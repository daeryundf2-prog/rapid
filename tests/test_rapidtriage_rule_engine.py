from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from rapidtriage.cli import main
from tests.test_rapidtriage_run import build_run_fixture
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


def sha256_for(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_rules(path: Path, target_hash: str) -> None:
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "credential-doc-hash",
                        "description": "Credential-bearing text document with a known hash",
                        "ext": [".txt"],
                        "path": ["documents"],
                        "date": {"after": "2024-01-01T00:00:00+00:00"},
                        "keyword": ["credential"],
                        "hash": [target_hash],
                    },
                    {
                        "id": "downloads-executable",
                        "description": "Executable found under downloads",
                        "ext": [".exe"],
                        "path": ["downloads"],
                    },
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def write_yaml_rules(path: Path) -> None:
    path.write_text(
        """version: 1
rules:
  - id: browser-domain
    description: Browser history or downloads with a known suspicious domain
    artifact:
      - browser-history
      - browser-history-downloads
    domain:
      - download.example
      - contoso.example
  - id: recent-shortcut
    description: Recent shortcut activity after the case cutoff
    artifact:
      - recent-shortcut
    path:
      - recent
    date:
      after: 2024-03-01T00:00:00+00:00
""",
        encoding="utf-8",
    )


class RapidTriageRuleEngineTests(unittest.TestCase):
    def test_json_rules_annotate_files_docs_and_run_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            target = root / "Users" / "alice" / "Documents" / "wire-transfer-notes.txt"
            rules_path = Path(tmp_dir) / "rules.json"
            write_json_rules(rules_path, sha256_for(target))

            files_output = Path(tmp_dir) / "files.json"
            docs_output = Path(tmp_dir) / "docs.json"
            run_output = Path(tmp_dir) / "run-out"

            self.assertEqual(main(["files", str(root), "--rules", str(rules_path), "--output", str(files_output)]), 0)
            self.assertEqual(
                main(["docs", str(root), "-k", "credential", "--rules", str(rules_path), "--output", str(docs_output)]),
                0,
            )
            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--rules", str(rules_path), "--output-dir", str(run_output)]), 0)

            files_payload: dict[str, Any] = json.loads(files_output.read_text(encoding="utf-8"))
            docs_payload: dict[str, Any] = json.loads(docs_output.read_text(encoding="utf-8"))
            run_payload: dict[str, Any] = json.loads((run_output / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))

            note_candidate = next(item for item in files_payload["candidates"] if item["path"].endswith("wire-transfer-notes.txt"))
            self.assertIn("credential-doc-hash", note_candidate["matched_rules"])
            self.assertEqual({hit["type"] for hit in note_candidate["ioc_hits"]}, {"hash", "keyword"})

            exe_candidate = next(item for item in files_payload["candidates"] if item["path"].endswith("payload-installer.exe"))
            self.assertIn("downloads-executable", exe_candidate["matched_rules"])
            self.assertNotIn("ioc_hits", exe_candidate)

            note_result = next(item for item in docs_payload["results"] if item["path"].endswith("wire-transfer-notes.txt"))
            self.assertIn("credential-doc-hash", note_result["matched_rules"])
            self.assertEqual({hit["type"] for hit in note_result["ioc_hits"]}, {"hash", "keyword"})

            self.assertEqual(run_payload["rule_set"]["rule_count"], 2)
            self.assertIn("credential-doc-hash", run_payload["matched_rules"])
            self.assertIn("downloads-executable", run_payload["matched_rules"])
            self.assertGreaterEqual(run_payload["summary"]["matched_rule_count"], 2)
            self.assertGreaterEqual(run_payload["summary"]["ioc_hit_count"], 2)
            self.assertTrue(any(hit["type"] == "hash" for hit in run_payload["ioc_hits"]))
            self.assertTrue(any(hit["type"] == "keyword" for hit in run_payload["ioc_hits"]))

    def test_yaml_rules_annotate_artifacts_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_windows_artifact_fixture(root)

            rules_path = Path(tmp_dir) / "rules.yaml"
            write_yaml_rules(rules_path)

            browser_output = Path(tmp_dir) / "browser.json"
            recent_output = Path(tmp_dir) / "recent.json"
            timeline_output = Path(tmp_dir) / "timeline.json"
            timeline_report = Path(tmp_dir) / "timeline.md"

            self.assertEqual(
                main(["artifacts", str(root), "--kind", "browser", "--rules", str(rules_path), "--output", str(browser_output)]),
                0,
            )
            self.assertEqual(
                main(["artifacts", str(root), "--kind", "recent-files", "--rules", str(rules_path), "--output", str(recent_output)]),
                0,
            )
            self.assertEqual(
                main([
                    "timeline",
                    str(root),
                    "--rules",
                    str(rules_path),
                    "--output",
                    str(timeline_output),
                    "--report",
                    str(timeline_report),
                ]),
                0,
            )

            browser_payload: dict[str, Any] = json.loads(browser_output.read_text(encoding="utf-8"))
            recent_payload: dict[str, Any] = json.loads(recent_output.read_text(encoding="utf-8"))
            timeline_payload: dict[str, Any] = json.loads(timeline_output.read_text(encoding="utf-8"))

            browser_hits = [item for item in browser_payload["artifacts"] if "browser-domain" in item.get("matched_rules", [])]
            self.assertGreaterEqual(len(browser_hits), 1)
            self.assertTrue(any(hit["type"] == "domain" for item in browser_hits for hit in item.get("ioc_hits", [])))

            recent_hit = next(item for item in recent_payload["artifacts"] if item["artifact_type"] == "recent-shortcut")
            self.assertIn("recent-shortcut", recent_hit["matched_rules"])
            self.assertNotIn("ioc_hits", recent_hit)

            self.assertIn("browser-domain", timeline_payload["matched_rules"])
            self.assertIn("recent-shortcut", timeline_payload["matched_rules"])
            self.assertGreaterEqual(timeline_payload["summary"]["matched_rule_count"], 2)
            self.assertGreaterEqual(timeline_payload["summary"]["ioc_hit_count"], 1)
            self.assertTrue(
                any(
                    "browser-domain" in event.get("matched_rules", []) and any(hit["type"] == "domain" for hit in event.get("ioc_hits", []))
                    for event in timeline_payload["events"]
                )
            )
            self.assertTrue(any("recent-shortcut" in event.get("matched_rules", []) for event in timeline_payload["events"]))
            self.assertTrue(timeline_report.is_file())


if __name__ == "__main__":
    unittest.main()
