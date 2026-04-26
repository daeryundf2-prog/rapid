from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.cli import main


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


def write_minimal_xlsx(path: Path, text: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/sharedStrings.xml", f"<sst><si><t>{text}</t></si></sst>")


def write_minimal_pptx(path: Path, text: str) -> None:
    xml = (
        '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        f"<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("ppt/slides/slide1.xml", xml)


def write_minimal_odt(path: Path, text: str) -> None:
    xml = (
        '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">'
        f"<office:body><office:text><text:p>{text}</text:p></office:text></office:body></office:document-content>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("content.xml", xml)


def write_minimal_msg(path: Path, text: str) -> None:
    path.write_bytes(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        + b"\x00" * 64
        + "Subject: Outlook Fixture".encode("utf-16le")
        + b"\x00\x00"
        + text.encode("utf-16le")
    )


class RapidTriageDocsTests(unittest.TestCase):
    def test_docs_command_scans_supported_document_extensions_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "note.txt").write_text("incident alpha secret", encoding="utf-8")
            (root / "events.log").write_text("keyword in log", encoding="utf-8")
            (root / "table.csv").write_text("name,value\nhit,keyword\n", encoding="utf-8")
            (root / "page.html").write_text("<html><body>secret html</body></html>", encoding="utf-8")
            (root / "brief.rtf").write_text(r"{\rtf1 keyword rtf}", encoding="utf-8")
            write_minimal_docx(root / "report.docx", "registry artifact keyword hit")
            write_minimal_pdf(root / "evidence.pdf", "shellbags keyword hit")
            write_minimal_xlsx(root / "ledger.xlsx", "secret spreadsheet")
            write_minimal_pptx(root / "deck.pptx", "keyword slide")
            write_minimal_odt(root / "memo.odt", "secret open document")
            (root / "message.eml").write_text(
                "From: alice@example.test\n"
                "To: bob@example.test\n"
                "Subject: secret mail\n"
                "\n"
                "email body keyword\n",
                encoding="utf-8",
            )
            (root / "mailbox.mbox").write_text(
                "From alice@example.test Mon Apr 01 00:00:00 2024\n"
                "From: alice@example.test\n"
                "To: bob@example.test\n"
                "Subject: mbox fixture\n"
                "\n"
                "secret mailbox keyword\n",
                encoding="utf-8",
            )
            write_minimal_msg(root / "outlook.msg", "secret outlook msg keyword")
            output = root / "results.json"

            exit_code = main(
                [
                    "docs",
                    str(root),
                    "-k",
                    "secret",
                    "-k",
                    "keyword",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["candidate_count"], 13)
            self.assertEqual(payload["summary"]["match_count"], 13)
            result_paths = {Path(item["path"]).name for item in payload["results"]}
            self.assertEqual(
                result_paths,
                {
                    "brief.rtf",
                    "deck.pptx",
                    "events.log",
                    "evidence.pdf",
                    "ledger.xlsx",
                    "memo.odt",
                    "message.eml",
                    "note.txt",
                    "mailbox.mbox",
                    "outlook.msg",
                    "page.html",
                    "report.docx",
                    "table.csv",
                },
            )
            self.assertIn(".xlsx", payload["summary"]["supported_extensions"])
            self.assertIn(".odt", payload["summary"]["supported_extensions"])
            self.assertIn(".msg", payload["summary"]["supported_extensions"])

    def test_docs_command_can_write_processed_text_index_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "note.txt").write_text("Incident alpha alpha https://example.test/login", encoding="utf-8")
            output = root / "results.json"
            index_output = root / "docs-index.json"

            exit_code = main(
                [
                    "docs",
                    str(root),
                    "-k",
                    "alpha",
                    "--output",
                    str(output),
                    "--index-output",
                    str(index_output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            index_payload = json.loads(index_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["index"]["command"], "docs-index")
            self.assertEqual(Path(payload["index"]["path"]), index_output.resolve())
            self.assertEqual(index_payload["command"], "docs-index")
            self.assertEqual(index_payload["strategy"], "processed-text-inverted-index")
            self.assertFalse(index_payload["analyzer"]["stores_full_text"])
            self.assertEqual(index_payload["summary"]["indexed_document_count"], 1)
            self.assertGreaterEqual(index_payload["summary"]["term_count"], 3)
            self.assertEqual(index_payload["terms"]["alpha"][0]["count"], 2)
            self.assertIn("https://example.test/login", index_payload["terms"])

    def test_manifest_reports_windows_modules_as_separate_providers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "manifest.json"

            exit_code = main(["manifest", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            provider_names = {item["name"] for item in payload["providers"]}
            self.assertIn("windows-eventlog", provider_names)
            self.assertIn("windows-registry", provider_names)
            self.assertIn("windows-shellbags", provider_names)


if __name__ == "__main__":
    unittest.main()
