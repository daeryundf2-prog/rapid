from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any

from rapidtriage.cli import build_parser, main
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


def write_minimal_docx(path: Path, text: str) -> None:
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "")
        archive.writestr("word/document.xml", xml)


def write_minimal_pdf(path: Path, text: str) -> None:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1")
    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n")
    objects.append(f"4 0 obj << /Length {len(stream)} >> stream\n".encode("latin-1") + stream + b"\nendstream endobj\n")
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for item in objects:
        offsets.append(len(output))
        output.extend(item)
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    output.extend(
        (
            f"trailer << /Root 1 0 R /Size {len(offsets)} >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("latin-1")
    )
    path.write_bytes(bytes(output))


def build_run_fixture(root: Path) -> None:
    build_windows_artifact_fixture(root)
    suspicious_blob = (
        "invoice payment wire transfer payroll login password credential phishing "
        "powershell remote access persistence ransomware browser history shellbags"
    )

    docs_dir = root / "Documents"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "wire-transfer-notes.txt").write_text(suspicious_blob, encoding="utf-8")
    write_minimal_docx(docs_dir / "breach-summary.docx", suspicious_blob)
    write_minimal_pdf(docs_dir / "attacker-activity.pdf", suspicious_blob)

    downloads_dir = root / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    (downloads_dir / "evidence-bundle.zip").write_bytes(b"PK\x03\x04")

    startup_dir = root / "Startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    (startup_dir / "startup-dropper.ps1").write_text("Write-Host compromised", encoding="utf-8")

    db_dir = root / "Databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "browser-cache.sqlite").write_text("SQLite format 3", encoding="utf-8")


def classify_payload(payload: dict[str, Any]) -> str | None:
    command = payload.get("command")
    if command in {"docs", "files", "extract"}:
        return str(command)
    if {"generated_at", "root", "platform", "providers"}.issubset(payload):
        return "manifest"
    if payload.get("mode") and "summary" in payload:
        return "mode-summary"
    if "report" in payload and payload.get("mode"):
        return "report-json"
    return None


class RapidTriageRunTests(unittest.TestCase):
    def test_parser_exposes_run_subcommand_and_examples(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("run", commands)

        root_help = parser.format_help()
        run_help = commands["run"].format_help()

        self.assertIn("rapidtriage run", root_help)
        self.assertIn("--mode", run_help)
        self.assertIn("fraud", run_help)
        self.assertIn("hacking", run_help)

    def test_run_fraud_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("fraud")

    def test_run_hacking_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("hacking")

    def assert_run_mode_outputs(self, mode: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            exit_code = main(["run", str(root), "--mode", mode, "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_dir.is_dir())

            json_payloads: dict[str, dict[str, Any]] = {}
            summary_payloads: list[dict[str, Any]] = []
            for path in output_dir.rglob("*.json"):
                payload = json.loads(path.read_text(encoding="utf-8"))
                kind = classify_payload(payload)
                if kind is None:
                    continue
                if kind == "mode-summary":
                    summary_payloads.append(payload)
                    continue
                json_payloads[kind] = payload

            self.assertIn("manifest", json_payloads)
            self.assertIn("files", json_payloads)
            self.assertIn("docs", json_payloads)
            self.assertIn("extract", json_payloads)

            manifest = json_payloads["manifest"]
            provider_names = {provider["name"] for provider in manifest["providers"]}
            self.assertIn("windows-browser-artifacts", provider_names)
            self.assertIn("windows-recent-files", provider_names)

            files_payload = json_payloads["files"]
            self.assertGreaterEqual(files_payload["summary"]["candidate_count"], 4)

            docs_payload = json_payloads["docs"]
            self.assertGreaterEqual(docs_payload["summary"]["candidate_count"], 3)
            self.assertGreaterEqual(docs_payload["summary"]["match_count"], 1)

            extract_payload = json_payloads["extract"]
            self.assertGreaterEqual(extract_payload["summary"]["selected_count"], 1)
            self.assertGreaterEqual(extract_payload["summary"]["extracted_count"], 1)
            for entry in extract_payload["entries"]:
                self.assertTrue(Path(entry["extracted_path"]).is_file())
                self.assertTrue(Path(entry["extracted_path"]).is_relative_to(output_dir.resolve()))

            matching_summaries = [payload for payload in summary_payloads if payload.get("mode") == mode]
            self.assertTrue(matching_summaries, f"missing mode summary JSON for {mode}")

            report_paths = [
                path
                for path in output_dir.rglob("*")
                if path.is_file() and "report" in path.name.lower() and path.suffix.lower() in {".md", ".txt", ".json"}
            ]
            self.assertTrue(report_paths, f"missing execution report for {mode}")
            report_path = report_paths[0]
            if report_path.suffix.lower() == ".json":
                report_payload = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(report_payload.get("mode"), mode)
            else:
                report_text = report_path.read_text(encoding="utf-8")
                self.assertIn(mode, report_text.lower())
                self.assertIn("files", report_text.lower())
                self.assertIn("docs", report_text.lower())


if __name__ == "__main__":
    unittest.main()
