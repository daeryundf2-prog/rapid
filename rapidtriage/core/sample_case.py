from __future__ import annotations

import datetime as dt
import json
import shutil
import sqlite3
import zipfile
from pathlib import Path
from typing import Dict

from .run import run_triage_mode


DEFAULT_SAMPLE_DIR = "rapidtriage-sample"
DEFAULT_SAMPLE_MODE = "fraud"


class SampleCaseError(ValueError):
    """Raised when the synthetic sample case cannot be created or run."""


def create_sample_case(output_dir: Path, *, overwrite: bool = False) -> Dict[str, object]:
    root = output_dir.expanduser().resolve()
    evidence_root = root / "evidence"
    expected_path = root / "rapidtriage-sample-expected.json"
    if root.exists() and any(root.iterdir()):
        if not overwrite:
            raise SampleCaseError(f"sample output already exists and is not empty: {root}")
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    build_sample_evidence(evidence_root)
    expected = build_expected_payload(root, evidence_root)
    expected_path.write_text(json.dumps(expected, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "command": "sample",
        "sample_root": str(root),
        "evidence_root": str(evidence_root),
        "expected": str(expected_path),
        "summary": {
            "document_count": 5,
            "browser_profile_count": 1,
            "recent_artifact_count": 3,
            "keywords": expected["keywords"],
        },
    }


def run_sample_workflow(
    output_dir: Path,
    *,
    mode: str = DEFAULT_SAMPLE_MODE,
    overwrite: bool = False,
    read_only: bool = False,
) -> Dict[str, object]:
    sample_payload = create_sample_case(output_dir, overwrite=overwrite)
    sample_root = Path(sample_payload["sample_root"])
    evidence_root = Path(sample_payload["evidence_root"])
    run_output = sample_root / "run-output"
    run_payload = run_triage_mode(
        evidence_root,
        mode=mode,
        output_dir=run_output,
        read_only=read_only,
        overwrite=True,
    )
    return {
        **sample_payload,
        "run": {
            "mode": mode,
            "output_dir": str(run_output),
            "summary": run_payload["outputs"]["summary"],
            "report": run_payload["outputs"]["report"],
            "timeline": run_payload["outputs"]["timeline"],
            "docs": run_payload["outputs"]["docs"],
            "files": run_payload["outputs"]["files"],
        },
    }


def build_sample_evidence(root: Path) -> None:
    user_root = root / "Users" / "alice"
    docs_dir = user_root / "Documents"
    downloads_dir = user_root / "Downloads"
    desktop_dir = user_root / "Desktop"
    logs_dir = user_root / "AppData" / "Local" / "RapidTriageSample" / "Logs"
    chrome_profile = (
        user_root
        / "AppData"
        / "Local"
        / "Google"
        / "Chrome"
        / "User Data"
        / "Default"
    )
    recent_dir = user_root / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    automatic_destinations = recent_dir / "AutomaticDestinations"
    custom_destinations = recent_dir / "CustomDestinations"
    recycle_dir = root / "$Recycle.Bin" / "alice"
    for directory in (
        docs_dir,
        downloads_dir,
        desktop_dir,
        logs_dir,
        chrome_profile,
        recent_dir,
        automatic_destinations,
        custom_destinations,
        recycle_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    sample_text = (
        "RapidTriage sample evidence. Invoice INV-2026-0424 shows a wire transfer, "
        "account review, password reset, credential exposure, browser download, "
        "PowerShell persistence, and recovery of a deleted note."
    )
    (docs_dir / "invoice-wire-transfer.txt").write_text(sample_text, encoding="utf-8")
    (docs_dir / "incident-notes.log").write_text(
        "2026-04-24T09:12:00Z login failure\n"
        "2026-04-24T09:15:00Z password reset requested\n"
        "2026-04-24T09:20:00Z suspicious powershell persistence observed\n",
        encoding="utf-8",
    )
    write_minimal_docx(docs_dir / "breach-summary.docx", sample_text)
    write_minimal_pdf(docs_dir / "attacker-activity.pdf", sample_text)

    (downloads_dir / "payload-installer.exe").write_bytes(b"MZ\x90\x00" + b"rapidtriage sample executable")
    (downloads_dir / "evidence-bundle.zip").write_bytes(b"PK\x03\x04" + b"rapidtriage sample archive")
    (desktop_dir / "persistence-runner.ps1").write_text(
        "Write-Host 'sample persistence command'\n",
        encoding="utf-8",
    )
    (desktop_dir / "screen-capture.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"rapidtriage sample image")
    (logs_dir / "web-activity.log").write_text(
        "download https://example.test/tools/payload-installer.exe\n"
        "login https://bank.example.test/account\n",
        encoding="utf-8",
    )
    (recent_dir / "Invoice Review.lnk").write_bytes(b"L\x00\x00\x00rapidtriage sample shortcut")
    (automatic_destinations / "5f7b5f1e01b83767.automaticDestinations-ms").write_bytes(b"automatic destinations")
    (custom_destinations / "9b9cdc69c1c24e2b.customDestinations-ms").write_bytes(b"custom destinations")
    (recycle_dir / "deleted-wallet-note.txt").write_text(
        "deleted recovery note with wallet transfer and account clues",
        encoding="utf-8",
    )
    create_chromium_history(chrome_profile / "History")


def create_chromium_history(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                target_path TEXT,
                current_path TEXT,
                tab_url TEXT,
                total_bytes INTEGER,
                state INTEGER,
                start_time INTEGER,
                end_time INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE downloads_url_chains (
                id INTEGER,
                chain_index INTEGER,
                url TEXT
            )
            """
        )
        visited_at = webkit_micros(dt.datetime(2026, 4, 24, 9, 30, tzinfo=dt.timezone.utc))
        downloaded_at = webkit_micros(dt.datetime(2026, 4, 24, 9, 35, tzinfo=dt.timezone.utc))
        connection.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            ("https://bank.example.test/account", "Sample Bank Account", 3, visited_at),
        )
        connection.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            ("https://example.test/tools/payload-installer.exe", "Payload Download", 1, downloaded_at),
        )
        connection.execute(
            """
            INSERT INTO downloads
                (id, target_path, current_path, tab_url, total_bytes, state, start_time, end_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                r"C:\Users\alice\Downloads\payload-installer.exe",
                r"C:\Users\alice\Downloads\payload-installer.exe",
                "https://example.test/tools",
                32768,
                1,
                downloaded_at,
                downloaded_at + 2_000_000,
            ),
        )
        connection.execute(
            "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?, ?, ?)",
            (1, 0, "https://example.test/tools/payload-installer.exe"),
        )
        connection.commit()
    finally:
        connection.close()


def webkit_micros(moment: dt.datetime) -> int:
    base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return int((moment - base).total_seconds() * 1_000_000)


def write_minimal_docx(path: Path, text: str) -> None:
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{escape_xml(text)}</w:t></w:r></w:p></w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "")
        archive.writestr("word/document.xml", xml)


def write_minimal_pdf(path: Path, text: str) -> None:
    pdf_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 72 720 Td ({pdf_text}) Tj ET".encode("latin-1", errors="replace")
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n",
        f"4 0 obj << /Length {len(stream)} >> stream\n".encode("latin-1") + stream + b"\nendstream endobj\n",
    ]
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


def escape_xml(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def build_expected_payload(sample_root: Path, evidence_root: Path) -> Dict[str, object]:
    return {
        "sample_root": str(sample_root),
        "evidence_root": str(evidence_root),
        "recommended_mode": DEFAULT_SAMPLE_MODE,
        "keywords": ["invoice", "wire", "password", "credential", "powershell", "download", "recovery"],
        "expected_outputs_when_run": [
            "run-output/rapidtriage-run-summary.json",
            "run-output/rapidtriage-run-report.md",
            "run-output/rapidtriage-docs.json",
            "run-output/rapidtriage-files.json",
            "run-output/rapidtriage-timeline.json",
            "run-output/artifacts/rapidtriage-artifacts-browser.json",
            "run-output/artifacts/rapidtriage-artifacts-recent-files.json",
        ],
        "not_real_evidence": True,
    }
