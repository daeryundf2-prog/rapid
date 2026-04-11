from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from rapidtriage.cli import build_parser, main


INPUT_DESTS = {
    "input",
    "input_json",
    "input_path",
    "json",
    "json_path",
    "source",
    "source_json",
    "results",
    "results_json",
    "report",
    "report_json",
}
OUTPUT_DIR_DESTS = {
    "output_dir",
    "destination",
    "destination_dir",
    "dest",
    "dest_dir",
    "target_dir",
    "extract_dir",
    "directory",
}
MANIFEST_DESTS = {
    "manifest",
    "manifest_path",
    "manifest_output",
    "manifest_json",
    "output_manifest",
}
SOURCE_PATH_KEYS = ("original_path", "source_path", "path")
EXTRACTED_PATH_KEYS = ("extracted_path", "output_path", "destination_path", "copied_path", "target_path")
HASH_KEYS = ("hash", "sha256", "md5")
MODIFIED_AT_KEYS = ("modified_at", "source_modified_at", "mtime")


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


def choose_option(option_strings: list[str]) -> str:
    long_options = [item for item in option_strings if item.startswith("--")]
    return long_options[0] if long_options else option_strings[0]


def build_extract_argv(input_json: Path, output_dir: Path, manifest_path: Path) -> list[str]:
    parser = build_parser()
    subparser_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    extract_parser = subparser_action.choices.get("extract")
    if extract_parser is None:
        return [
            "extract",
            str(input_json),
            "--output-dir",
            str(output_dir),
            "--manifest",
            str(manifest_path),
        ]

    argv = ["extract"]
    positional_actions = [
        action
        for action in extract_parser._actions
        if not action.option_strings and action.dest != "help"
    ]
    positional_values = [input_json, output_dir, manifest_path]
    positional_index = 0

    for action in positional_actions:
        if action.dest in INPUT_DESTS:
            argv.append(str(input_json))
        elif action.dest in OUTPUT_DIR_DESTS:
            argv.append(str(output_dir))
        elif action.dest in MANIFEST_DESTS:
            argv.append(str(manifest_path))
        else:
            argv.append(str(positional_values[positional_index]))
            positional_index += 1

    for action in extract_parser._actions:
        if not action.option_strings:
            continue
        if action.dest in INPUT_DESTS:
            argv.extend([choose_option(action.option_strings), str(input_json)])
        elif action.dest in OUTPUT_DIR_DESTS:
            argv.extend([choose_option(action.option_strings), str(output_dir)])
        elif action.dest in MANIFEST_DESTS:
            argv.extend([choose_option(action.option_strings), str(manifest_path)])

    return argv


def find_record_list(payload: dict[str, object]) -> list[dict[str, object]]:
    for key in ("records", "results", "entries", "items", "files", "extractions"):
        value = payload.get(key)
        if isinstance(value, list) and all(isinstance(item, dict) for item in value):
            return value
    raise AssertionError(f"Could not find extraction records list in manifest keys: {sorted(payload)}")


def get_value(record: dict[str, object], candidates: tuple[str, ...]) -> object:
    for key in candidates:
        if key in record:
            return record[key]
    raise AssertionError(f"Missing any of {candidates} in record keys: {sorted(record)}")


def resolve_output_path(raw_path: str, output_dir: Path) -> Path:
    path = Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    return (output_dir / path).resolve()


class RapidTriageExtractTests(unittest.TestCase):
    def test_extract_accepts_files_json_and_copies_candidates_with_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            alpha_dir = root / "Users" / "alice" / "Desktop"
            beta_dir = root / "Users" / "bob" / "Downloads"
            alpha_dir.mkdir(parents=True)
            beta_dir.mkdir(parents=True)

            alpha = alpha_dir / "report.txt"
            beta = beta_dir / "report.txt"
            alpha.write_text("alpha incident", encoding="utf-8")
            beta.write_text("beta incident", encoding="utf-8")

            alpha_mtime = datetime(2024, 1, 2, 3, 4, 5).timestamp()
            beta_mtime = datetime(2024, 2, 3, 4, 5, 6).timestamp()
            os.utime(alpha, (alpha_mtime, alpha_mtime))
            os.utime(beta, (beta_mtime, beta_mtime))

            files_json = root / "files.json"
            extract_dir = root / "extracted-files"
            manifest_json = root / "extract-files-manifest.json"

            files_exit_code = main(["files", str(root), "--output", str(files_json)])
            self.assertEqual(files_exit_code, 0)

            extract_exit_code = main(build_extract_argv(files_json, extract_dir, manifest_json))
            self.assertEqual(extract_exit_code, 0)
            self.assertTrue(manifest_json.exists())

            manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
            records = find_record_list(manifest)
            self.assertEqual(len(records), 2)

            by_source = {
                Path(str(get_value(record, SOURCE_PATH_KEYS))).resolve(): record
                for record in records
            }
            self.assertEqual(set(by_source), {alpha.resolve(), beta.resolve()})

            extracted_paths: set[Path] = set()
            for source_path, expected_mtime in (
                (alpha.resolve(), datetime.fromtimestamp(alpha_mtime).isoformat()),
                (beta.resolve(), datetime.fromtimestamp(beta_mtime).isoformat()),
            ):
                record = by_source[source_path]
                extracted_path = resolve_output_path(str(get_value(record, EXTRACTED_PATH_KEYS)), extract_dir)
                extracted_paths.add(extracted_path)
                self.assertTrue(extracted_path.exists())
                self.assertTrue(str(extracted_path).startswith(str(extract_dir.resolve())))
                self.assertEqual(extracted_path.read_bytes(), source_path.read_bytes())
                self.assertEqual(get_value(record, MODIFIED_AT_KEYS), expected_mtime)

                digest = str(get_value(record, HASH_KEYS))
                source_bytes = source_path.read_bytes()
                self.assertIn(
                    digest,
                    {
                        hashlib.md5(source_bytes).hexdigest(),
                        hashlib.sha256(source_bytes).hexdigest(),
                    },
                )

            self.assertEqual(len(extracted_paths), 2)

    def test_extract_uses_docs_results_instead_of_all_doc_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            matched = root / "matched.txt"
            unmatched = root / "unmatched.pdf"
            matched.write_text("incident keyword hit", encoding="utf-8")
            write_minimal_pdf(unmatched, "background text only")

            docs_json = root / "docs.json"
            extract_dir = root / "extracted-docs"
            manifest_json = root / "extract-docs-manifest.json"

            docs_exit_code = main(["docs", str(root), "-k", "keyword", "--output", str(docs_json)])
            self.assertEqual(docs_exit_code, 0)

            payload = json.loads(docs_json.read_text(encoding="utf-8"))
            result_paths = {Path(item["path"]).resolve() for item in payload["results"]}
            self.assertEqual(result_paths, {matched.resolve()})

            extract_exit_code = main(build_extract_argv(docs_json, extract_dir, manifest_json))
            self.assertEqual(extract_exit_code, 0)

            manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
            records = find_record_list(manifest)
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(Path(str(get_value(record, SOURCE_PATH_KEYS))).resolve(), matched.resolve())

            extracted_path = resolve_output_path(str(get_value(record, EXTRACTED_PATH_KEYS)), extract_dir)
            self.assertTrue(extracted_path.exists())
            self.assertEqual(extracted_path.read_bytes(), matched.read_bytes())
            self.assertTrue(str(extracted_path).startswith(str(extract_dir.resolve())))


if __name__ == "__main__":
    unittest.main()
