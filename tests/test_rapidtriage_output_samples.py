from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rapidtriage.cli import build_parser, main
from tests.windows_artifact_fixtures import build_minimal_lnk

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "docs" / "rapidtriage-output-samples"
WINDOWS_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "rapidtriage" / "windows_artifacts"


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


def set_mtime(path: Path, value: datetime) -> None:
    timestamp = value.timestamp()
    os.utime(path, (timestamp, timestamp))


def build_windows_collector_sample_fixture(root: Path) -> None:
    shutil.copytree(WINDOWS_FIXTURE_ROOT, root, dirs_exist_ok=True)
    lnk_path = root / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent" / "Case Notes.lnk"
    lnk_path.write_bytes(
        build_minimal_lnk(
            r"C:\Users\alice\Documents\Case Notes.docx",
            datetime(2024, 3, 5, 6, 7, 8, tzinfo=timezone.utc),
        )
    )
    search_csv = root / "analysis" / "windows-search-index.csv"
    search_csv.parent.mkdir(parents=True, exist_ok=True)
    search_csv.write_text(
        "DocID,System.ItemPathDisplay,System.FileName,System.Title,System.Search.Contents,System.DateModified,System.Size\n"
        '7,C:\\Users\\alice\\Documents\\Case Notes.docx,Case Notes.docx,Case Notes,"rapid forensic case notes",2024-03-05T06:07:08Z,2048\n',
        encoding="utf-8",
    )
    search_edb = root / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows" / "Windows.edb"
    search_edb.parent.mkdir(parents=True, exist_ok=True)
    search_edb.write_bytes(b"sample windows search edb")
    default_rdp = root / "Users" / "alice" / "Documents" / "Default.rdp"
    default_rdp.parent.mkdir(parents=True, exist_ok=True)
    default_rdp.write_text(
        "full address:s:10.0.0.50\nusername:s:CORP\\alice\ngatewayhostname:s:rd-gateway.example\n",
        encoding="utf-8",
    )
    rdp_cache = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache" / "Cache0000.bin"
    rdp_cache.parent.mkdir(parents=True, exist_ok=True)
    rdp_cache.write_bytes(b"sample rdp cache")
    rdp_reg = root / "Windows" / "System32" / "config" / "rdp.reg"
    rdp_reg.write_text(
        """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\\10.0.0.50]
"MRU0"="10.0.0.50"
""",
        encoding="utf-16",
    )
    wmi_objects = root / "Windows" / "System32" / "wbem" / "Repository" / "OBJECTS.DATA"
    wmi_objects.parent.mkdir(parents=True, exist_ok=True)
    wmi_objects.write_bytes(b"sample wmi repository objects")
    set_mtime(
        lnk_path,
        datetime(2024, 3, 5, 6, 7, 8, tzinfo=timezone.utc),
    )
    set_mtime(search_csv, datetime(2024, 3, 5, 6, 7, 9, tzinfo=timezone.utc))
    set_mtime(search_edb, datetime(2024, 3, 5, 6, 7, 10, tzinfo=timezone.utc))
    set_mtime(default_rdp, datetime(2024, 3, 5, 6, 7, 11, tzinfo=timezone.utc))
    set_mtime(rdp_cache, datetime(2024, 3, 5, 6, 7, 12, tzinfo=timezone.utc))
    set_mtime(rdp_reg, datetime(2024, 3, 5, 6, 7, 13, tzinfo=timezone.utc))
    set_mtime(wmi_objects, datetime(2024, 3, 5, 6, 7, 14, tzinfo=timezone.utc))
    set_mtime(
        root
        / "Users"
        / "alice"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Recent"
        / "AutomaticDestinations"
        / "5f7b5f1e01b83767.automaticDestinations-ms",
        datetime(2024, 3, 5, 6, 8, 9, tzinfo=timezone.utc),
    )
    set_mtime(
        root
        / "Users"
        / "alice"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Recent"
        / "CustomDestinations"
        / "9b9cdc69c1c24e2b.customDestinations-ms",
        datetime(2024, 3, 5, 6, 9, 10, tzinfo=timezone.utc),
    )
    stable_artifact_times = {
        root / "Users" / "alice": datetime(2024, 3, 5, 6, 6, 6, tzinfo=timezone.utc),
        root / "Windows" / "System32" / "winevt" / "Logs" / "Security.xml": datetime(2024, 3, 5, 6, 10, 11, tzinfo=timezone.utc),
        root / "Windows" / "System32" / "config" / "software.reg": datetime(2024, 3, 5, 6, 11, 12, tzinfo=timezone.utc),
        root / "Users" / "alice" / "NTUSER-shellbags.reg": datetime(2024, 3, 5, 6, 12, 13, tzinfo=timezone.utc),
        root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf": datetime(2024, 3, 5, 6, 13, 14, tzinfo=timezone.utc),
        root
        / "Windows"
        / "System32"
        / "Tasks"
        / "Microsoft"
        / "Windows"
        / "UpdateOrchestrator"
        / "SecurityUpdater": datetime(2024, 3, 5, 6, 14, 15, tzinfo=timezone.utc),
        root
        / "ProgramData"
        / "Microsoft"
        / "Windows Defender"
        / "Support"
        / "MPLog-20260426.log": datetime(2024, 3, 5, 6, 15, 16, tzinfo=timezone.utc),
        root / "Windows" / "System32" / "LogFiles" / "Firewall" / "pfirewall.log": datetime(2024, 3, 5, 6, 16, 17, tzinfo=timezone.utc),
        root
        / "ProgramData"
        / "Microsoft"
        / "Windows"
        / "WER"
        / "ReportArchive"
        / "AppCrash_powershell.exe_123"
        / "Report.wer": datetime(2024, 3, 5, 6, 17, 18, tzinfo=timezone.utc),
        root / "Users" / "alice" / "Downloads" / "report.zip.Zone.Identifier": datetime(2024, 3, 5, 6, 18, 19, tzinfo=timezone.utc),
    }
    for path, timestamp in stable_artifact_times.items():
        if path.exists():
            set_mtime(path, timestamp)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_payload(payload: Any, root: Path) -> Any:
    root_text = str(root.resolve())
    if isinstance(payload, dict):
        normalized = {}
        for key, value in payload.items():
            if key == "generated_at" and isinstance(value, str):
                normalized[key] = "<GENERATED_AT>"
                continue
            if key == "platform" and isinstance(value, str):
                normalized[key] = "<PLATFORM>"
                continue
            normalized[key] = normalize_payload(value, root)
        return normalized
    if isinstance(payload, list):
        return [normalize_payload(item, root) for item in payload]
    if isinstance(payload, str):
        return payload.replace(root_text, "<ROOT>")
    return payload


def canonicalize_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = dict(payload)
    providers = [dict(item) for item in canonical["providers"]]
    for provider in providers:
        provider["artifacts"] = sorted(
            provider["artifacts"],
            key=lambda artifact: (
                artifact["artifact_type"],
                artifact["path"],
                json.dumps(artifact["details"], ensure_ascii=False, sort_keys=True),
            ),
        )
    canonical["providers"] = providers
    return canonical


def canonicalize_docs(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = dict(payload)
    canonical["manifest"] = canonicalize_manifest(dict(canonical["manifest"]))
    canonical["candidates"] = sorted(canonical["candidates"], key=lambda item: item["path"])
    canonical["results"] = sorted(canonical["results"], key=lambda item: item["path"])
    return canonical


def canonicalize_files(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = dict(payload)
    canonical["candidates"] = sorted(canonical["candidates"], key=lambda item: item["path"])
    return canonical


def canonicalize_extract(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = dict(payload)
    canonical["entries"] = sorted(canonical["entries"], key=lambda item: item["original_path"])
    canonical["skipped"] = sorted(canonical["skipped"], key=lambda item: item["original_path"])
    return canonical


class RapidTriageOutputSamplesTests(unittest.TestCase):
    def test_root_help_includes_current_examples(self) -> None:
        help_text = build_parser().format_help()

        self.assertIn("Examples:", help_text)
        self.assertIn("rapidtriage manifest . --output rapidtriage-manifest.json", help_text)
        self.assertIn("rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json", help_text)
        self.assertIn(
            "rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json",
            help_text,
        )
        self.assertIn("rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf", help_text)
        self.assertIn("rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json", help_text)

    def test_subcommand_help_includes_files_and_extract_examples(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        files_help = commands["files"].format_help()
        extract_help = commands["extract"].format_help()
        artifacts_help = commands["artifacts"].format_help()
        run_help = commands["run"].format_help()

        self.assertIn("rapidtriage files . --output rapidtriage-files.json", files_help)
        self.assertIn("--modified-after 2025-01-01", files_help)
        self.assertIn("rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt", extract_help)
        self.assertIn("rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf", extract_help)
        self.assertIn("rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json", artifacts_help)
        self.assertIn("rapidtriage run /cases/image-mount --mode seizure --output-dir ./rapidtriage-run", run_help)

    def test_docs_sample_matches_contract_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            note = root / "note.txt"
            report = root / "report.docx"
            evidence = root / "evidence.pdf"
            output = root / "rapidtriage-docs.json"

            note.write_text("incident alpha secret", encoding="utf-8")
            write_minimal_docx(report, "registry artifact keyword hit")
            write_minimal_pdf(evidence, "shellbags keyword hit")
            set_mtime(note, datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
            set_mtime(report, datetime(2024, 1, 2, 3, 5, 6, tzinfo=timezone.utc))
            set_mtime(evidence, datetime(2024, 1, 2, 3, 6, 7, tzinfo=timezone.utc))

            self.assertEqual(main(["docs", str(root), "-k", "secret", "-k", "keyword", "--output", str(output)]), 0)

            actual = canonicalize_docs(normalize_payload(load_json(output), root))
            expected = load_json(SAMPLES_DIR / "docs-keyword-search.json")
            self.assertEqual(actual, expected)

    def test_files_sample_matches_contract_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            notes = root / "notes.txt"
            bundle = root / "bundle.zip"
            records = root / "records.sqlite"
            tool = root / "tool.exe"
            output = root / "rapidtriage-files.json"

            notes.write_text("incident notes", encoding="utf-8")
            bundle.write_bytes(b"PK\x03\x04")
            records.write_text("SQLite format 3", encoding="utf-8")
            tool.write_bytes(b"MZ\x90\x00")
            set_mtime(notes, datetime(2024, 2, 3, 4, 5, 6, tzinfo=timezone.utc))
            set_mtime(bundle, datetime(2024, 2, 3, 4, 5, 7, tzinfo=timezone.utc))
            set_mtime(records, datetime(2024, 2, 3, 4, 5, 8, tzinfo=timezone.utc))
            set_mtime(tool, datetime(2024, 2, 3, 4, 5, 9, tzinfo=timezone.utc))

            self.assertEqual(main(["files", str(root), "--output", str(output)]), 0)

            actual = canonicalize_files(normalize_payload(load_json(output), root))
            expected = load_json(SAMPLES_DIR / "files-default-scan.json")
            self.assertEqual(actual, expected)

    def test_extract_files_sample_matches_contract_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            note = evidence_dir / "case-notes.txt"
            archive = root / "bundle.zip"
            files_json = root / "rapidtriage-files.json"
            extract_dir = root / "extract-out"
            manifest_json = root / "extract-manifest.json"

            note.write_text("incident notes", encoding="utf-8")
            archive.write_bytes(b"PK\x03\x04")
            set_mtime(note, datetime(2024, 3, 4, 5, 6, 7, tzinfo=timezone.utc))
            set_mtime(archive, datetime(2024, 3, 4, 5, 6, 8, tzinfo=timezone.utc))

            self.assertEqual(main(["files", str(root), "--output", str(files_json)]), 0)
            self.assertEqual(
                main(
                    [
                        "extract",
                        str(files_json),
                        str(extract_dir),
                        "--manifest",
                        str(manifest_json),
                        "--category",
                        "documents",
                        "--ext",
                        "txt",
                    ]
                ),
                0,
            )

            actual = canonicalize_extract(normalize_payload(load_json(manifest_json), root))
            expected = load_json(SAMPLES_DIR / "extract-from-files.json")
            self.assertEqual(actual, expected)

    def test_extract_docs_sample_matches_contract_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            note = root / "note.txt"
            report = root / "report.docx"
            evidence = root / "evidence.pdf"
            docs_json = root / "rapidtriage-docs.json"
            extract_dir = root / "docs-out"

            note.write_text("incident alpha secret", encoding="utf-8")
            write_minimal_docx(report, "registry artifact keyword hit")
            write_minimal_pdf(evidence, "shellbags keyword hit")
            set_mtime(note, datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
            set_mtime(report, datetime(2024, 1, 2, 3, 5, 6, tzinfo=timezone.utc))
            set_mtime(evidence, datetime(2024, 1, 2, 3, 6, 7, tzinfo=timezone.utc))

            self.assertEqual(main(["docs", str(root), "-k", "secret", "-k", "keyword", "--output", str(docs_json)]), 0)
            self.assertEqual(main(["extract", str(docs_json), str(extract_dir), "--kind", "pdf"]), 0)

            actual = canonicalize_extract(
                normalize_payload(load_json(extract_dir / "rapidtriage-extract-manifest.json"), root)
            )
            expected = load_json(SAMPLES_DIR / "extract-from-docs.json")
            self.assertEqual(actual, expected)

    def test_manifest_windows_sample_matches_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output = root / "rapidtriage-manifest.json"

            build_windows_collector_sample_fixture(root)
            self.assertEqual(main(["manifest", str(root), "--output", str(output)]), 0)

            actual = canonicalize_manifest(normalize_payload(load_json(output), root))
            expected = load_json(SAMPLES_DIR / "manifest-windows-artifacts.json")
            self.assertEqual(actual, expected)

    def test_repo_windows_fixture_still_matches_documented_collector_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "repo-fixture-manifest.json"

            self.assertEqual(main(["manifest", str(WINDOWS_FIXTURE_ROOT), "--output", str(output)]), 0)

            payload = canonicalize_manifest(normalize_payload(load_json(output), WINDOWS_FIXTURE_ROOT))
            providers = {item["name"]: item for item in payload["providers"]}
            browser = providers["windows-browser-artifacts"]
            recent = providers["windows-recent-files"]

            self.assertEqual({artifact["artifact_type"] for artifact in browser["artifacts"]}, {"browser-history", "browser-history-downloads"})
            self.assertEqual(
                {artifact["artifact_type"] for artifact in recent["artifacts"]},
                {"recent-shortcut", "jumplist-automatic", "jumplist-custom"},
            )


if __name__ == "__main__":
    unittest.main()
