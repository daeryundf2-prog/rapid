from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from rapidtriage.cli import build_parser, main
from tests.test_rapidtriage_run import build_run_fixture


def set_mtime(path: Path, value: datetime) -> None:
    timestamp = value.timestamp()
    os.utime(path, (timestamp, timestamp))


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def iter_objects(value: object) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from iter_objects(nested)
        return
    if isinstance(value, list):
        for item in value:
            yield from iter_objects(item)


class RapidTriageRuleEngineTests(unittest.TestCase):
    def test_parser_exposes_rules_option_for_rule_aware_commands(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        for name in ("files", "docs", "artifacts", "timeline", "run"):
            with self.subTest(command=name):
                self.assertIn("--rules", commands[name].format_help())

    def test_json_rules_annotate_files_docs_artifacts_timeline_and_run_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            payload_installer, credential_note = self.add_rule_fixture_content(root)
            json_rules, _yaml_rules = self.write_rule_files(Path(tmp_dir), payload_installer)

            files_output = Path(tmp_dir) / "rapidtriage-files.json"
            docs_output = Path(tmp_dir) / "rapidtriage-docs.json"
            artifacts_output = Path(tmp_dir) / "rapidtriage-artifacts-browser.json"
            timeline_output = Path(tmp_dir) / "rapidtriage-timeline.json"

            self.assertEqual(
                main(["files", str(root), "--rules", str(json_rules), "--output", str(files_output)]),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "docs",
                        str(root),
                        "-k",
                        "credential",
                        "-k",
                        "password",
                        "--rules",
                        str(json_rules),
                        "--output",
                        str(docs_output),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "artifacts",
                        str(root),
                        "--kind",
                        "browser",
                        "--rules",
                        str(json_rules),
                        "--output",
                        str(artifacts_output),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "timeline",
                        str(root),
                        "--files",
                        str(files_output),
                        "--docs",
                        str(docs_output),
                        "--artifacts",
                        str(artifacts_output),
                        "--rules",
                        str(json_rules),
                        "--output",
                        str(timeline_output),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(["run", str(root), "--mode", "hacking", "--rules", str(json_rules), "--output-dir", str(output_dir)]),
                0,
            )

            files_payload = json.loads(files_output.read_text(encoding="utf-8"))
            docs_payload = json.loads(docs_output.read_text(encoding="utf-8"))
            artifacts_payload = json.loads(artifacts_output.read_text(encoding="utf-8"))
            timeline_payload = json.loads(timeline_output.read_text(encoding="utf-8"))
            summary_payload = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            report_text = (output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8")

            self.assertPayloadHasRule(files_payload, "downloads-exe-sha256")
            self.assertPayloadHasIoc(files_payload, sha256_hex(payload_installer))

            self.assertPayloadHasRule(docs_payload, "credential-url-hit")
            self.assertPayloadHasIoc(docs_payload, "malicious.example")
            self.assertPayloadHasIoc(docs_payload, "https://malicious.example/login")

            self.assertPayloadHasRule(artifacts_payload, "browser-download-ioc")
            self.assertPayloadHasIoc(artifacts_payload, "download.example")
            self.assertPayloadHasIoc(artifacts_payload, "https://download.example/tools/installer.exe")

            self.assertPayloadHasRule(timeline_payload, "browser-download-ioc")
            self.assertPayloadHasIoc(timeline_payload, "malicious.example")

            self.assertPayloadHasRule(summary_payload, "downloads-exe-sha256")
            self.assertPayloadHasRule(summary_payload, "credential-url-hit")
            self.assertPayloadHasIoc(summary_payload, "download.example")
            self.assertPayloadHasIoc(summary_payload, "malicious.example")
            self.assertIn("matched rules", report_text.lower())
            self.assertIn("ioc hits", report_text.lower())
            self.assertIn("downloads-exe-sha256", report_text)
            self.assertIn("malicious.example", report_text)

    def test_run_accepts_yaml_rules_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            payload_installer, _credential_note = self.add_rule_fixture_content(root)
            _json_rules, yaml_rules = self.write_rule_files(Path(tmp_dir), payload_installer)

            self.assertEqual(
                main(["run", str(root), "--mode", "hacking", "--rules", str(yaml_rules), "--output-dir", str(output_dir)]),
                0,
            )

            summary_payload = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertPayloadHasRule(summary_payload, "downloads-exe-sha256")
            self.assertPayloadHasIoc(summary_payload, "malicious.example")

    def add_rule_fixture_content(self, root: Path) -> tuple[Path, Path]:
        downloads_dir = root / "Users" / "alice" / "Downloads"
        payload_installer = downloads_dir / "payload-installer.exe"
        set_mtime(payload_installer, datetime(2024, 2, 6, 7, 8, 9, tzinfo=timezone.utc))

        docs_dir = root / "Users" / "alice" / "Documents"
        credential_note = docs_dir / "credential-note.txt"
        credential_note.write_text(
            "credential password reset evidence https://malicious.example/login",
            encoding="utf-8",
        )
        set_mtime(credential_note, datetime(2024, 2, 7, 8, 9, 10, tzinfo=timezone.utc))
        return payload_installer, credential_note

    def write_rule_files(self, directory: Path, payload_installer: Path) -> tuple[Path, Path]:
        payload_hash = sha256_hex(payload_installer)
        rule_payload = {
            "rules": [
                {
                    "id": "downloads-exe-sha256",
                    "description": "Match downloaded executables by extension, path, date, and sha256.",
                    "ext": [".exe"],
                    "path": ["downloads"],
                    "date": {"after": "2024-02-01T00:00:00+00:00"},
                    "hash": [payload_hash],
                },
                {
                    "id": "credential-url-hit",
                    "description": "Match credential-themed document hits and IOC strings.",
                    "keyword": ["credential", "password"],
                    "domain": ["malicious.example"],
                    "url": ["https://malicious.example/login"],
                },
                {
                    "id": "browser-download-ioc",
                    "description": "Match browser download artifacts with IOC domains and URLs.",
                    "artifact": ["browser-history-downloads"],
                    "domain": ["download.example"],
                    "url": ["https://download.example/tools/installer.exe"],
                },
            ]
        }

        json_rules = directory / "rapidtriage-rules.sample.json"
        json_rules.write_text(json.dumps(rule_payload, indent=2), encoding="utf-8")

        yaml_rules = directory / "rapidtriage-rules.sample.yaml"
        yaml_rules.write_text(
            """
rules:
  - id: downloads-exe-sha256
    description: Match downloaded executables by extension, path, date, and sha256.
    ext:
      - .exe
    path:
      - downloads
    date:
      after: 2024-02-01T00:00:00+00:00
    hash:
      - __PAYLOAD_SHA256__
  - id: credential-url-hit
    description: Match credential-themed document hits and IOC strings.
    keyword:
      - credential
      - password
    domain:
      - malicious.example
    url:
      - https://malicious.example/login
  - id: browser-download-ioc
    description: Match browser download artifacts with IOC domains and URLs.
    artifact:
      - browser-history-downloads
    domain:
      - download.example
    url:
      - https://download.example/tools/installer.exe
""".strip().replace("__PAYLOAD_SHA256__", payload_hash)
            + "\n",
            encoding="utf-8",
        )
        return json_rules, yaml_rules

    def assertPayloadHasRule(self, payload: object, rule_id: str) -> None:
        for node in iter_objects(payload):
            matched_rules = node.get("matched_rules")
            if isinstance(matched_rules, list) and rule_id in [str(item) for item in matched_rules]:
                return
        self.fail(f"expected matched_rules to include {rule_id!r}: {json.dumps(payload, ensure_ascii=False, indent=2)}")

    def assertPayloadHasIoc(self, payload: object, expected: str) -> None:
        for node in iter_objects(payload):
            ioc_hits = node.get("ioc_hits")
            if not isinstance(ioc_hits, list):
                continue
            for hit in ioc_hits:
                if expected in json.dumps(hit, ensure_ascii=False):
                    return
        self.fail(f"expected ioc_hits to include {expected!r}: {json.dumps(payload, ensure_ascii=False, indent=2)}")


if __name__ == "__main__":
    unittest.main()
