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
        "powershell remote access persistence ransomware browser history shellbags "
        "download recent evidence restore deleted"
    )
    user_root = root / "Users" / "alice"

    docs_dir = user_root / "Documents"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "wire-transfer-notes.txt").write_text(suspicious_blob, encoding="utf-8")
    write_minimal_docx(docs_dir / "breach-summary.docx", suspicious_blob)
    write_minimal_pdf(docs_dir / "attacker-activity.pdf", suspicious_blob)

    downloads_dir = user_root / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    (downloads_dir / "evidence-bundle.zip").write_bytes(b"PK\x03\x04" + (b"A" * 262144))
    (downloads_dir / "payload-installer.exe").write_bytes(b"MZ\x90\x00")

    desktop_dir = user_root / "Desktop"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    (desktop_dir / "persistence-runner.bat").write_text("@echo off\r\npowershell -enc AAA=", encoding="utf-8")
    (desktop_dir / "screen-capture.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    startup_dir = user_root / "Startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    (startup_dir / "startup-dropper.ps1").write_text("Write-Host compromised", encoding="utf-8")

    db_dir = user_root / "Databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "browser-cache.sqlite").write_text("SQLite format 3", encoding="utf-8")

    recycle_dir = root / "$Recycle.Bin" / "alice"
    recycle_dir.mkdir(parents=True, exist_ok=True)
    (recycle_dir / "deleted-wallet-note.txt").write_text("deleted recovery note with recent restore hints", encoding="utf-8")
    (recycle_dir / "deleted-bundle.zip").write_bytes(b"PK\x03\x04" + (b"B" * 131072))
    (recycle_dir / "deleted-photo.jpg").write_bytes(b"\xff\xd8\xff" + (b"\x00" * 4096))


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

    def test_run_seizure_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("seizure")

    def test_run_recovery_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("recovery")

    def test_run_supports_read_only_extract_safety(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            exit_code = main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir), "--read-only"])

            self.assertEqual(exit_code, 0)
            summary_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary_payload["safety"]["read_only"], True)

            docs_extract_payload = json.loads(
                (output_dir / "docs-extract" / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8")
            )
            files_extract_payload = json.loads(
                (output_dir / "files-extract" / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(docs_extract_payload["summary"]["extracted_count"], 0)
            self.assertGreaterEqual(docs_extract_payload["summary"]["skipped_count"], 1)
            self.assertEqual(files_extract_payload["summary"]["extracted_count"], 0)
            self.assertGreaterEqual(files_extract_payload["summary"]["skipped_count"], 1)

    def assert_run_mode_outputs(self, mode: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            exit_code = main(["run", str(root), "--mode", mode, "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_dir.is_dir())

            manifest_path = output_dir / "rapidtriage-manifest.json"
            docs_path = output_dir / "rapidtriage-docs.json"
            files_path = output_dir / "rapidtriage-files.json"
            docs_extract_manifest_path = output_dir / "docs-extract" / "rapidtriage-extract-manifest.json"
            files_extract_manifest_path = output_dir / "files-extract" / "rapidtriage-extract-manifest.json"
            summary_path = output_dir / "rapidtriage-run-summary.json"
            report_path = output_dir / "rapidtriage-run-report.md"
            artifact_paths = {
                path.name: path
                for path in (output_dir / "artifacts").glob("rapidtriage-artifacts-*.json")
            }

            expected_output_paths = [
                manifest_path,
                docs_path,
                files_path,
                docs_extract_manifest_path,
                files_extract_manifest_path,
                summary_path,
                report_path,
            ]
            for path in expected_output_paths:
                self.assertTrue(path.is_file(), f"missing expected output: {path}")

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provider_names = {provider["name"] for provider in manifest["providers"]}
            self.assertIn("windows-browser-artifacts", provider_names)
            self.assertIn("windows-recent-files", provider_names)

            docs_payload = json.loads(docs_path.read_text(encoding="utf-8"))
            files_payload = json.loads(files_path.read_text(encoding="utf-8"))
            docs_extract_payload = json.loads(docs_extract_manifest_path.read_text(encoding="utf-8"))
            files_extract_payload = json.loads(files_extract_manifest_path.read_text(encoding="utf-8"))
            summary_payload: dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))

            min_file_candidates = {"fraud": 4, "hacking": 3, "seizure": 4, "recovery": 3}[mode]
            min_doc_matches = {"fraud": 1, "hacking": 1, "seizure": 1, "recovery": 1}[mode]

            self.assertGreaterEqual(files_payload["summary"]["candidate_count"], min_file_candidates)
            self.assertGreaterEqual(docs_payload["summary"]["candidate_count"], 1)
            self.assertGreaterEqual(docs_payload["summary"]["match_count"], min_doc_matches)

            self.assertGreaterEqual(docs_extract_payload["summary"]["selected_count"], 1)
            self.assertGreaterEqual(docs_extract_payload["summary"]["extracted_count"], 1)
            self.assertGreaterEqual(files_extract_payload["summary"]["selected_count"], 1)
            self.assertGreaterEqual(files_extract_payload["summary"]["extracted_count"], 1)
            for extract_payload in (docs_extract_payload, files_extract_payload):
                for entry in extract_payload["entries"]:
                    self.assertTrue(Path(entry["extracted_path"]).is_file())
                    self.assertTrue(Path(entry["extracted_path"]).is_relative_to(output_dir.resolve()))

            self.assertEqual(summary_payload["mode"], mode)
            self.assertEqual(summary_payload["command"], "run")
            self.assertEqual(Path(summary_payload["outputs"]["manifest"]).resolve(), manifest_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["docs"]).resolve(), docs_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["files"]).resolve(), files_path.resolve())
            self.assertEqual(
                Path(summary_payload["outputs"]["docs_extract_manifest"]).resolve(),
                docs_extract_manifest_path.resolve(),
            )
            self.assertEqual(
                Path(summary_payload["outputs"]["files_extract_manifest"]).resolve(),
                files_extract_manifest_path.resolve(),
            )
            self.assertEqual(Path(summary_payload["outputs"]["summary"]).resolve(), summary_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["report"]).resolve(), report_path.resolve())
            self.assertIn("recent_file_candidates", summary_payload["highlights"])
            self.assertIn("large_file_candidates", summary_payload["highlights"])

            if mode == "recovery":
                self.assertIn("recent-files", summary_payload["summary"]["artifacts"])
                self.assertIn("images", files_payload["summary"]["category_counts"])
            else:
                self.assertIn("browser", summary_payload["summary"]["artifacts"])
                self.assertIn("recent-files", summary_payload["summary"]["artifacts"])
            for artifact_path in artifact_paths.values():
                self.assertTrue(artifact_path.is_file())

            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn(mode, report_text.lower())
            self.assertIn("files-extract", report_text.lower())
            self.assertIn("docs-extract", report_text.lower())
            self.assertIn("largest file candidates", report_text.lower())


if __name__ == "__main__":
    unittest.main()
