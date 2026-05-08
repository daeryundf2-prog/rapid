from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


class RapidTriageExtractTests(unittest.TestCase):
    def test_extract_command_copies_selected_files_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            note_path = evidence_dir / "case-notes.txt"
            note_path.write_text("incident notes", encoding="utf-8")
            mtime = datetime(2024, 3, 4, 5, 6, 7).timestamp()
            os.utime(note_path, (mtime, mtime))
            (root / "bundle.zip").write_bytes(b"PK\x03\x04")
            input_json = root / "files.json"
            extract_dir = root / "extract-out"
            manifest_json = root / "extract-manifest.json"

            self.assertEqual(main(["files", str(root), "--output", str(input_json)]), 0)
            exit_code = main(
                [
                    "extract",
                    str(input_json),
                    str(extract_dir),
                    "--manifest",
                    str(manifest_json),
                    "--category",
                    "documents",
                    "--ext",
                    "txt",
                ]
            )

            self.assertEqual(exit_code, 0)
            manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
            self.assertEqual(manifest["command"], "extract")
            self.assertEqual(manifest["source_command"], "files")
            self.assertEqual(manifest["summary"]["selected_count"], 1)
            self.assertEqual(manifest["summary"]["extracted_count"], 1)
            self.assertEqual(manifest["summary"]["skipped_count"], 0)

            entry = manifest["entries"][0]
            extracted_path = Path(entry["extracted_path"])
            self.assertEqual(Path(entry["original_path"]), note_path.resolve())
            self.assertEqual(extracted_path, (extract_dir / "evidence" / "case-notes.txt").resolve())
            self.assertEqual(extracted_path.read_text(encoding="utf-8"), "incident notes")
            self.assertEqual(entry["sha256"], sha256_file(note_path))
            self.assertEqual(entry["modified_at"], datetime.fromtimestamp(mtime).isoformat())
            self.assertIn("documents", entry["categories"])

    def test_extract_command_uses_docs_results_and_kind_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "note.txt").write_text("incident keyword hit", encoding="utf-8")
            write_minimal_docx(root / "report.docx", "registry keyword hit")
            pdf_path = root / "evidence.pdf"
            write_minimal_pdf(pdf_path, "shellbags keyword hit")
            docs_json = root / "docs.json"
            extract_dir = root / "docs-extract"

            self.assertEqual(
                main(["docs", str(root), "-k", "keyword", "--output", str(docs_json)]),
                0,
            )
            exit_code = main(["extract", str(docs_json), str(extract_dir), "--kind", "pdf"])

            self.assertEqual(exit_code, 0)
            manifest = json.loads((extract_dir / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["source_command"], "docs")
            self.assertEqual(manifest["summary"]["input_count"], 3)
            self.assertEqual(manifest["summary"]["selected_count"], 1)
            self.assertEqual(manifest["summary"]["extracted_count"], 1)
            entry = manifest["entries"][0]
            self.assertEqual(entry["kind"], "pdf")
            self.assertEqual(entry["matched_keywords"], ["keyword"])
            self.assertEqual(Path(entry["original_path"]), pdf_path.resolve())
            self.assertTrue((extract_dir / "evidence.pdf").is_file())

    def test_extract_command_records_missing_source_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            note_path = root / "note.txt"
            note_path.write_text("to be removed", encoding="utf-8")
            input_json = root / "files.json"
            extract_dir = root / "extract-out"

            self.assertEqual(main(["files", str(root), "--output", str(input_json)]), 0)
            note_path.unlink()

            exit_code = main(["extract", str(input_json), str(extract_dir)])

            self.assertEqual(exit_code, 0)
            manifest = json.loads((extract_dir / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"]["selected_count"], 1)
            self.assertEqual(manifest["summary"]["extracted_count"], 0)
            self.assertEqual(manifest["summary"]["skipped_count"], 1)
            self.assertEqual(manifest["skipped"][0]["original_path"], str(note_path.resolve()))
            self.assertEqual(manifest["skipped"][0]["reason"], "missing")

    def test_extract_command_supports_dry_run_and_preserves_source_files_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            note_path = root / "note.txt"
            note_path.write_text("dry run note", encoding="utf-8")
            input_json = root / "files.json"
            extract_dir = root / "extract-out"

            self.assertEqual(main(["files", str(root), "--output", str(input_json)]), 0)
            exit_code = main(["extract", str(input_json), str(extract_dir), "--dry-run"])

            self.assertEqual(exit_code, 0)
            manifest = json.loads((extract_dir / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["safety"]["dry_run"], True)
            self.assertEqual(manifest["summary"]["selected_count"], 1)
            self.assertEqual(manifest["summary"]["extracted_count"], 0)
            self.assertEqual(manifest["summary"]["skipped_count"], 1)
            self.assertEqual(manifest["skipped"][0]["reason"], "dry-run")
            self.assertFalse((extract_dir / "note.txt").exists())

    def test_extract_command_blocks_overwrite_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            note_path = root / "note.txt"
            note_path.write_text("original", encoding="utf-8")
            input_json = root / "files.json"
            extract_dir = root / "extract-out"
            extract_dir.mkdir()
            (extract_dir / "note.txt").write_text("existing", encoding="utf-8")

            self.assertEqual(main(["files", str(root), "--output", str(input_json)]), 0)
            exit_code = main(["extract", str(input_json), str(extract_dir)])

            self.assertEqual(exit_code, 0)
            manifest = json.loads((extract_dir / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(manifest["summary"]["skipped_count"], 1)
            self.assertIn("destination-exists", {item["reason"] for item in manifest["skipped"]})
            self.assertEqual((extract_dir / "note.txt").read_text(encoding="utf-8"), "existing")


if __name__ == "__main__":
    unittest.main()
