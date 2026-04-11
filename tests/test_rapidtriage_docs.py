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


class RapidTriageDocsTests(unittest.TestCase):
    def test_docs_command_scans_txt_pdf_docx_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "note.txt").write_text("incident alpha secret", encoding="utf-8")
            write_minimal_docx(root / "report.docx", "registry artifact keyword hit")
            write_minimal_pdf(root / "evidence.pdf", "shellbags keyword hit")
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
            self.assertEqual(payload["summary"]["candidate_count"], 3)
            self.assertEqual(payload["summary"]["match_count"], 3)
            result_paths = {Path(item["path"]).name for item in payload["results"]}
            self.assertEqual(result_paths, {"note.txt", "report.docx", "evidence.pdf"})

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
