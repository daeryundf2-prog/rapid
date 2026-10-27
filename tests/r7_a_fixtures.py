"""Synthetic run for R7 갈래 A (계열·중복·예외): 3 mails + 5 attachments in one PST container, one ZIP
with 4 entries (+ one encrypted EGG), one adb backup (2 members + 1 extracted app row), 2 carved
rows of a pagefile, files / docs outputs with every irregular category and a timeline whose
events point at the mail rows. No real evidence: every value is made up."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = r"C:\ev"
PST = rf"{ROOT}\mail\box.pst"
ZIP = rf"{ROOT}\docs\bundle.zip"
EGG = rf"{ROOT}\docs\locked.egg"
AB = rf"{ROOT}\phone\backup.ab"
PAGEFILE = rf"{ROOT}\pagefile.sys"
HWP = rf"{ROOT}\docs\secret.hwp"


def sha(ch: str) -> str:
    return ch * 64


S1, S2, S3, S4, S5, Z, B1, B2, AB_SHA, EGG_SHA = (sha(c) for c in "123456789a")


def mail(msgid: str, item: str, *, subject: str, body: str, date: str = "Mon, 26 May 2025 10:15:42 +0900") -> dict[str, object]:
    return {
        "provider": "email-pst",
        "artifact_type": "email-message",
        "path": PST,
        "supported": True,
        "details": {
            "source_path": PST,
            "message_id": msgid,
            "export_item": item,
            "folder": "Inbox",
            "subject": subject,
            "from": "Kim <kim@example.com>",
            "to": "lee@example.com, Park <park@example.com>",
            "cc": "",
            "date": date,
            "body_sha256": body,
            "timestamp": "2025-05-26T01:15:42+00:00",
        },
    }


def attachment(msgid: str, item: str, name: str, digest: str, *, inline: bool = False, size: int = 1024) -> dict[str, object]:
    return {
        "provider": "email-pst",
        "artifact_type": "email-attachment",
        "path": PST,
        "supported": True,
        "details": {
            "source_path": PST,
            "filename": name,
            "size": size,
            "sha256": digest,
            "inline": inline,
            "message_id": msgid,
            "export_item": item,
            "folder": "Inbox",
        },
    }


EMAIL_ROWS: list[dict[str, object]] = [
    {"provider": "email-pst", "artifact_type": "email-container-inventory", "path": PST, "supported": True, "details": {"source_path": PST, "status": "normalized", "message_count": 3}},  # 0
    mail("<m1@example.com>", "Inbox/1", subject="견적서 송부", body=B1),  # 1
    attachment("<m1@example.com>", "Inbox/1", "견적서.pdf", S1),  # 2
    attachment("<m1@example.com>", "Inbox/1", "logo.png", S2, inline=True),  # 3 (signature image: immaterial)
    mail("<m2@example.com>", "Inbox/2", subject="계약서", body=B2),  # 4
    attachment("<m2@example.com>", "Inbox/2", "견적서 사본.pdf", S1),  # 5 (same bytes as 2)
    attachment("<m2@example.com>", "Inbox/2", "계약서.docx", S3),  # 6
    # The same message as 1 (another copy of the mail) with only one attachment.
    mail("<m1@example.com>", "Inbox/3", subject="  견적서   송부 ", body=B1),  # 7
    attachment("<m1@example.com>", "Inbox/3", "견적서.pdf", S1),  # 8
]


def entry(index: int, name: str, *, is_dir: bool = False, encrypted: bool = False, size: int = 100) -> dict[str, object]:
    return {
        "source_index": index,
        "name": name,
        "is_dir": is_dir,
        "compressed_size": size // 2,
        "uncompressed_size": size,
        "encrypted": encrypted,
        "crc32": f"{index:08x}",
        "risk_flags": ["archive-encrypted-entry"] if encrypted else [],
    }


DOC_ROWS: list[dict[str, object]] = [
    {
        "provider": "generic-documents",
        "artifact_type": "archive-file-inventory",
        "path": ZIP,
        "supported": True,
        "details": {
            "source_path": ZIP,
            "source_hashes": {"sha256": Z},
            "archive_format": "zip",
            "entry_count": 4,
            "encrypted_entry_count": 0,
            "archive_inventory_profile": {
                "analysis_status": "zip-central-directory-parsed",
                "entry_count": 4,
                "sample_entries": [entry(0, "보고서/", is_dir=True), entry(1, "보고서/1분기.xlsx"), entry(2, "보고서/2분기.xlsx"), entry(3, "readme.txt")],
            },
        },
    },  # 0
    {
        "provider": "generic-documents",
        "artifact_type": "archive-file-inventory",
        "path": EGG,
        "supported": True,
        "details": {
            "source_path": EGG,
            "source_hashes": {"sha256": EGG_SHA},
            "archive_format": "egg",
            "entry_count": 1,
            "encrypted_entry_count": 1,
            "archive_inventory_profile": {"analysis_status": "egg-listed", "entry_count": 1, "sample_entries": [entry(0, "급여.xlsx", encrypted=True)]},
            "risk_flags": ["archive-encrypted-entry"],
        },
    },  # 1
    {
        "provider": "generic-documents",
        "artifact_type": "document-metadata-risk",
        "path": HWP,
        "supported": True,
        "details": {"source_path": HWP, "document_format": "hwp", "encryption": {"encrypted": True, "encryption_reason": "hwp-password"}},
    },  # 2
    {
        "provider": "generic-documents",
        "artifact_type": "document-metadata-risk",
        "path": rf"{ROOT}\docs\plain.docx",
        "supported": True,
        "details": {"source_path": rf"{ROOT}\docs\plain.docx", "encryption": {"encrypted": False}, "parse_status": "parsed-no-errors"},
    },  # 3
    {
        "provider": "generic-documents",
        "artifact_type": "document-metadata-risk",
        "path": rf"{ROOT}\docs\broken.docx",
        "supported": True,
        "details": {"source_path": rf"{ROOT}\docs\broken.docx", "parser_error": True},
    },  # 4 (corrupted)
    {"provider": "generic-documents", "artifact_type": "document-unknown-format", "path": rf"{ROOT}\docs\x.qqq", "supported": False, "details": {}},  # 5
]

MOBILE_ROWS: list[dict[str, object]] = [
    {"provider": "mobile-export-artifacts", "artifact_type": "android-backup", "path": AB, "supported": True, "details": {"source_hashes": {"sha256": AB_SHA}, "status": "completed"}},  # 0
    {
        "provider": "mobile-export-artifacts",
        "artifact_type": "android-backup-member",
        "path": AB,
        "supported": True,
        "details": {"member_name": "apps/com.example.chat/db/chat.db", "member_path": "db/chat.db", "member_type": "file", "size": 4096, "sha256": S4},
    },  # 1
    {
        "provider": "mobile-export-artifacts",
        "artifact_type": "android-backup-member",
        "path": AB,
        "supported": True,
        "details": {"member_name": "apps/com.example.chat/f/empty.txt", "member_path": "f/empty.txt", "member_type": "file", "size": 0, "sha256": None},
    },  # 2 (empty)
    {
        "provider": "mobile-export-artifacts",
        "artifact_type": "android-app-data",
        "path": AB,
        "supported": True,
        "details": {"container_backup_path": AB, "container_member": "apps/com.example.chat/db/chat.db", "package": "com.example.chat"},
    },  # 3
]

FILES_CANDIDATES: list[dict[str, object]] = [
    {"path": PAGEFILE, "name": "pagefile.sys", "size": 8192, "categories": ["system"], "file_signature": {"status": "not-applicable", "mismatch": False}},  # 0
    {"path": ZIP, "name": "bundle.zip", "size": 2048, "categories": ["archives"], "hashes": {"sha256": Z}, "file_signature": {"status": "signature-matches-extension", "mismatch": False}},  # 1
    {"path": rf"{ROOT}\copy\견적서.pdf", "name": "견적서.pdf", "size": 1024, "categories": ["documents"], "hashes": {"sha256": S1}, "file_signature": {"status": "signature-matches-extension", "mismatch": False}},  # 2
    {"path": rf"{ROOT}\docs\scan.pdf", "name": "scan.pdf", "size": 4096, "categories": ["documents"], "file_signature": {"status": "signature-matches-extension", "mismatch": False}},  # 3
    {"path": HWP, "name": "secret.hwp", "size": 3000, "categories": ["documents"], "file_signature": {"status": "signature-matches-extension", "mismatch": False}},  # 4
    {"path": rf"{ROOT}\pics\photo.jpg", "name": "photo.jpg", "size": 5000, "categories": ["images"], "file_signature": {"status": "extension-signature-mismatch", "mismatch": True, "mismatch_direction": "magic-not-expected-for-extension", "detected": "png"}},  # 5
    {"path": rf"{ROOT}\empty.txt", "name": "empty.txt", "size": 0, "categories": ["documents"], "file_signature": {"status": "not-applicable", "mismatch": False}},  # 6
    {"path": rf"{ROOT}\docs\binary.doc", "name": "binary.doc", "size": 7000, "categories": ["documents"], "file_signature": {"status": "signature-matches-extension", "mismatch": False}},  # 7
    {"path": rf"{ROOT}\docs\old.wpd", "name": "old.wpd", "size": 700, "categories": ["documents"], "file_signature": {"status": "not-applicable", "mismatch": False}},  # 8
    {"path": rf"{ROOT}\gone\deleted.txt", "name": "deleted.txt", "size": 10, "categories": ["documents"], "is_deleted": True, "file_signature": {"status": "not-applicable", "mismatch": False}},  # 9
    {"path": rf"{ROOT}\copy2\견적서.pdf", "name": "견적서.pdf", "size": 1024, "categories": ["documents"], "hashes": {"sha256": S1}, "file_signature": {"status": "signature-matches-extension", "mismatch": False}},  # 10
]
FILES_INVENTORY: list[dict[str, object]] = [
    {"path": rf"{ROOT}\misc\data.xlsx", "name": "data.xlsx", "size": 900, "categories": [], "inventory_only": True, "file_signature": {"status": "extension-signature-mismatch", "mismatch": True, "mismatch_direction": "extension-expected-signature-missing"}},  # 0
    {"path": rf"{ROOT}\misc\notes.txt", "name": "notes.txt", "size": 50, "categories": [], "inventory_only": True},  # 1
]
DOCS_CANDIDATES: list[dict[str, object]] = [
    {"path": rf"{ROOT}\docs\scan.pdf", "kind": "pdf", "size": 4096, "text_status": "no-text", "text_length": 0, "encrypted": False},
    {"path": HWP, "kind": "hwp", "size": 3000, "text_status": "encrypted", "text_length": 0, "encrypted": True},
    {"path": rf"{ROOT}\docs\binary.doc", "kind": "doc", "size": 7000, "text_status": "binary-rejected", "text_length": 0, "encrypted": False},
    {"path": rf"{ROOT}\docs\old.wpd", "kind": "wpd", "size": 700, "text_status": "unsupported", "text_length": 0, "encrypted": False},
    {"path": rf"{ROOT}\copy\견적서.pdf", "kind": "pdf", "size": 1024, "text_status": "ok", "text_length": 300, "encrypted": False},
]
CARVE_ROWS: list[dict[str, object]] = [
    {"artifact_type": "carve-row", "path": PAGEFILE, "details": {"signature_kind": "pdf", "source_path": PAGEFILE, "offset": 4096, "sha256": S5, "recovery_method": "carved", "status": "footer-validated"}},
    {"artifact_type": "carve-row", "path": PAGEFILE, "details": {"signature_kind": "pdf", "source_path": PAGEFILE, "offset": 8192, "sha256": S1, "recovery_method": "carved", "status": "footer-validated"}},
]
CARVE_ID = "20260101T000000-carve001"


def event(output: str, row_index: int, when: str, kind: str = "email") -> dict[str, object]:
    return {
        "timestamp": when,
        "source": "artifacts",
        "event_type": f"artifact-{kind}",
        "path": PST,
        "summary": f"{kind} {row_index}",
        "details": {"kind": kind, "source_record": {"output": output, "row_index": row_index}},
    }


TIMELINE_EVENTS: list[dict[str, object]] = [
    event("artifacts_email", 1, "2025-05-26T01:15:42+00:00"),
    event("artifacts_email", 2, "2025-05-26T01:15:43+00:00"),
    event("artifacts_email", 4, "2025-05-27T01:00:00+00:00"),
    event("artifacts_email", 7, "2025-05-28T01:00:00+00:00"),
    event("artifacts_generic-documents", 4, "2025-05-29T01:00:00+00:00", "generic-documents"),
    {"timestamp": "2025-05-30T00:00:00+00:00", "source": "files", "event_type": "file-modified", "path": rf"{ROOT}\empty.txt", "summary": "f", "details": {}},
]

KINDS = {"email": EMAIL_ROWS, "generic-documents": DOC_ROWS, "mobile-export": MOBILE_ROWS}

# Expected relations (parent ref, child ref, relation), by rule.
EXPECTED_EDGES: list[tuple[str, str, str]] = [
    ("artifacts:email:/artifacts/0", "artifacts:email:/artifacts/1", "message"),
    ("artifacts:email:/artifacts/0", "artifacts:email:/artifacts/4", "message"),
    ("artifacts:email:/artifacts/0", "artifacts:email:/artifacts/7", "message"),
    ("artifacts:email:/artifacts/1", "artifacts:email:/artifacts/2", "attachment"),
    ("artifacts:email:/artifacts/1", "artifacts:email:/artifacts/3", "attachment"),
    ("artifacts:email:/artifacts/4", "artifacts:email:/artifacts/5", "attachment"),
    ("artifacts:email:/artifacts/4", "artifacts:email:/artifacts/6", "attachment"),
    ("artifacts:email:/artifacts/7", "artifacts:email:/artifacts/8", "attachment"),
    *(("artifacts:generic-documents:/artifacts/0", f"artifacts:generic-documents:/artifacts/0#entry:{i}", "member") for i in range(4)),
    ("artifacts:generic-documents:/artifacts/1", "artifacts:generic-documents:/artifacts/1#entry:0", "member"),
    ("artifacts:mobile-export:/artifacts/0", "artifacts:mobile-export:/artifacts/1", "backup-member"),
    ("artifacts:mobile-export:/artifacts/0", "artifacts:mobile-export:/artifacts/2", "backup-member"),
    ("artifacts:mobile-export:/artifacts/1", "artifacts:mobile-export:/artifacts/3", "extracted"),
    ("files::/candidates/0", f"analysis:{CARVE_ID}:/rows/0", "carved"),
    ("files::/candidates/0", f"analysis:{CARVE_ID}:/rows/1", "carved"),
]


def write_run(run_dir: Path, *, with_carve: bool = True) -> dict[str, str]:
    """Write the run outputs under ``run_dir``; returns the summary ``outputs`` map."""
    run_dir.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, str] = {}
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    for kind, rows in KINDS.items():
        records = artifacts_dir / f"rapidtriage-artifacts-{kind}.jsonl"
        records.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8", newline="\n")
        counts: dict[str, int] = {}
        for row in rows:
            counts[str(row["artifact_type"])] = counts.get(str(row["artifact_type"]), 0) + 1
        payload = {
            "command": "artifacts",
            "kind": kind,
            "record_count": len(rows),
            "records_path": str(records),
            "artifacts": [],
            "summary": {"artifact_count": len(rows), "artifact_type_counts": counts},
        }
        path = artifacts_dir / f"rapidtriage-artifacts-{kind}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        outputs[f"artifacts_{kind}"] = str(path)
    files = run_dir / "rapidtriage-files.json"
    files.write_text(
        json.dumps({"command": "files", "root": ROOT, "summary": {}, "candidates": FILES_CANDIDATES, "inventory": FILES_INVENTORY}, ensure_ascii=False),
        encoding="utf-8",
    )
    outputs["files"] = str(files)
    docs = run_dir / "rapidtriage-docs.json"
    docs.write_text(json.dumps({"command": "docs", "candidates": DOCS_CANDIDATES, "results": []}, ensure_ascii=False), encoding="utf-8")
    outputs["docs"] = str(docs)
    timeline = run_dir / "rapidtriage-timeline.json"
    timeline.write_text(json.dumps({"command": "timeline", "summary": {}, "events": TIMELINE_EVENTS}, ensure_ascii=False), encoding="utf-8")
    outputs["timeline"] = str(timeline)
    if with_carve:
        carve = run_dir / "analyses" / CARVE_ID
        carve.mkdir(parents=True, exist_ok=True)
        (carve / "rows.jsonl").write_text("".join(json.dumps(row) + "\n" for row in CARVE_ROWS), encoding="utf-8", newline="\n")
        (carve / "analysis.json").write_text(
            json.dumps({"analysis_id": CARVE_ID, "kind": "carve", "status": "completed", "row_count": len(CARVE_ROWS)}), encoding="utf-8"
        )
    summary_path = run_dir / "rapidtriage-run-summary.json"
    outputs["summary"] = str(summary_path)
    summary_path.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": ROOT,
                "output_dir": str(run_dir),
                "source": {"type": "directory", "analysis_root": ROOT},
                "outputs": outputs,
                "summary": {"counts": {"artifacts": sum(len(rows) for rows in KINDS.values())}},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return outputs
