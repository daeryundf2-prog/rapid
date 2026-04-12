from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from pathlib import Path

from rapidtriage.cli import main
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


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class RapidTriageRunTests(unittest.TestCase):
    def test_run_fraud_mode_writes_summary_report_and_component_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_dir = root / "fraud-run"

            (root / "incident-notes.txt").write_text("invoice payment transfer bank account", encoding="utf-8")
            write_minimal_docx(root / "ledger.docx", "refund receipt payment record")
            write_minimal_pdf(root / "evidence.pdf", "fraud transfer receipt")
            (root / "records.sqlite").write_text("SQLite format 3", encoding="utf-8")
            with zipfile.ZipFile(root / "bundle.zip", "w") as archive:
                archive.writestr("receipt.txt", "invoice")

            exit_code = main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)

            summary_path = output_dir / "rapidtriage-run-summary.json"
            report_path = output_dir / "rapidtriage-run-report.md"
            docs_extract_manifest = output_dir / "docs-extract" / "rapidtriage-extract-manifest.json"
            files_extract_manifest = output_dir / "files-extract" / "rapidtriage-extract-manifest.json"

            for path in (
                output_dir / "rapidtriage-manifest.json",
                output_dir / "rapidtriage-docs.json",
                output_dir / "rapidtriage-files.json",
                docs_extract_manifest,
                files_extract_manifest,
                summary_path,
                report_path,
            ):
                self.assertTrue(path.is_file(), path)

            summary = load_json(summary_path)
            self.assertEqual(summary["command"], "run")
            self.assertEqual(summary["mode"], "fraud")
            self.assertEqual(Path(summary["root"]), root.resolve())
            self.assertEqual(Path(summary["output_dir"]), output_dir.resolve())
            self.assertGreaterEqual(summary["summary"]["document_match_count"], 3)
            self.assertGreaterEqual(summary["summary"]["file_candidate_count"], 5)
            self.assertGreaterEqual(summary["summary"]["docs_extracted_count"], 3)
            self.assertGreaterEqual(summary["summary"]["files_extracted_count"], 5)
            self.assertIn("invoice", summary["summary"]["matched_keyword_counts"])

            docs_extract = load_json(docs_extract_manifest)
            files_extract = load_json(files_extract_manifest)
            self.assertEqual(docs_extract["source_command"], "docs")
            self.assertEqual(files_extract["source_command"], "files")

            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("# rapidtriage run report", report_text)
            self.assertIn("Mode: `fraud`", report_text)
            self.assertIn("## Summary", report_text)

    def test_run_hacking_mode_surfaces_windows_artifacts_and_suspicious_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_dir = root / "hacking-run"

            build_windows_artifact_fixture(root)
            (root / "operator-note.txt").write_text("powershell persistence credential malware", encoding="utf-8")
            (root / "payload.exe").write_bytes(b"MZ\x90\x00")
            (root / "collect.ps1").write_text("Invoke-WebRequest", encoding="utf-8")
            (root / "loot.sqlite").write_text("SQLite format 3", encoding="utf-8")
            with zipfile.ZipFile(root / "tooling.zip", "w") as archive:
                archive.writestr("script.ps1", "powershell")

            exit_code = main(["run", str(root), "--mode", "hacking", "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)

            summary = load_json(output_dir / "rapidtriage-run-summary.json")
            self.assertEqual(summary["mode"], "hacking")
            self.assertGreater(summary["summary"]["windows_provider_artifact_counts"]["windows-browser-artifacts"], 0)
            self.assertGreater(summary["summary"]["windows_provider_artifact_counts"]["windows-recent-files"], 0)
            self.assertGreater(summary["summary"]["artifact_type_counts"]["browser-history-downloads"], 0)
            self.assertGreater(summary["summary"]["artifact_type_counts"]["recent-shortcut"], 0)
            self.assertGreaterEqual(summary["summary"]["document_match_count"], 1)
            self.assertGreaterEqual(summary["summary"]["files_extracted_count"], 3)

            report_text = (output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8")
            self.assertIn("Mode: `hacking`", report_text)
            self.assertIn("windows-browser-artifacts", report_text)
            self.assertIn("windows-recent-files", report_text)

    def test_run_rejects_modes_not_yet_implemented(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main(["run", str(root), "--mode", "seizure"])

            self.assertEqual(exc.exception.code, 2)
            self.assertIn("not implemented yet", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
