from __future__ import annotations

import datetime as dt
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Mapping

from .case_db import SCHEMA_VERSION
from .forensic_accuracy import build_accuracy_gate
from .submission import compute_hashes


class BackupError(ValueError):
    """Raised when a case backup or restore operation is invalid."""


BACKUP_MANIFEST_NAME = "rapidtriage-case-backup-manifest.json"
BACKUP_RESTORE_MIGRATION_GAP_ID = "#111"
BACKUP_RESTORE_TRUSTED_DIFF_BLOCKER_111 = "trusted-backup-restore-rehearsal-diff-missing"
BACKUP_RESTORE_TRUSTED_TOOLS = {"backup-restore-rehearsal-log", "migration-corpus-run", "scheduled-backup-drill"}


def build_case_backup(
    *,
    database_path: Path,
    output_dir: Path,
    overwrite: bool = False,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    source = database_path.expanduser().resolve()
    if not source.is_file():
        raise BackupError(f"case database not found: {source}")
    destination_dir = output_dir.expanduser().resolve()
    if destination_dir.exists() and any(destination_dir.iterdir()) and not overwrite:
        raise BackupError(f"backup output directory is not empty: {destination_dir}")
    destination_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for path in [source, source.with_name(source.name + "-wal"), source.with_name(source.name + "-shm")]:
        if not path.is_file():
            continue
        destination = destination_dir / path.name
        shutil.copy2(path, destination)
        copied.append(
            {
                "label": "case_database" if path == source else path.name.rsplit("-", 1)[-1],
                "source_path": str(path),
                "backup_path": str(destination),
                "hashes": compute_hashes(destination),
                "size_bytes": destination.stat().st_size,
            }
        )
    if trusted_diff is None:
        trusted_diff = missing_backup_restore_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(BACKUP_RESTORE_TRUSTED_DIFF_BLOCKER_111)
    manifest = {
        "command": "case-backup",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "database": str(source),
        "output_dir": str(destination_dir),
        "schema": inspect_case_database_schema(source),
        "migration_readiness": build_migration_readiness(source),
        "trusted_backup_restore_diff": trusted_diff,
        "blockers": blockers,
        "core_accuracy_gates": backup_restore_core_accuracy_gates(
            copied=copied,
            schema=inspect_case_database_schema(source),
            restored=False,
            hash_verified=False,
            trusted_diff=trusted_diff,
        ),
        "copied_count": len(copied),
        "files": copied,
        "restore_guidance": "Run rapidtriage case-restore BACKUP_MANIFEST --output restored-case.db, then verify hashes.",
    }
    (destination_dir / BACKUP_MANIFEST_NAME).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def restore_case_backup(
    *,
    manifest_path: Path,
    output_path: Path,
    overwrite: bool = False,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest_file = manifest_path.expanduser().resolve()
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError(f"failed to read backup manifest: {exc}") from exc
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BackupError("backup manifest does not contain files")
    database_file = next((item for item in files if isinstance(item, dict) and item.get("label") == "case_database"), None)
    if not isinstance(database_file, dict):
        raise BackupError("backup manifest does not include case_database")
    source = Path(str(database_file.get("backup_path") or "")).expanduser().resolve()
    if not source.is_file():
        raise BackupError(f"backup database file not found: {source}")
    destination = output_path.expanduser().resolve()
    if destination.exists() and not overwrite:
        raise BackupError(f"restore output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    hashes = compute_hashes(destination)
    source_hashes = dict(database_file.get("hashes", {}))
    if trusted_diff is None:
        trusted_diff = missing_backup_restore_trusted_diff()
    blockers = []
    if trusted_diff.get("status") != "pass":
        blockers.append(BACKUP_RESTORE_TRUSTED_DIFF_BLOCKER_111)
    return {
        "command": "case-restore",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "manifest": str(manifest_file),
        "restored_database": str(destination),
        "hashes": hashes,
        "source_hashes": source_hashes,
        "hash_verified": hashes.get("sha256") == source_hashes.get("sha256"),
        "schema": inspect_case_database_schema(destination),
        "migration_readiness": manifest.get("migration_readiness", {}),
        "trusted_backup_restore_diff": trusted_diff,
        "blockers": blockers,
        "core_accuracy_gates": backup_restore_core_accuracy_gates(
            copied=[database_file],
            schema=inspect_case_database_schema(destination),
            restored=True,
            hash_verified=hashes.get("sha256") == source_hashes.get("sha256"),
            trusted_diff=trusted_diff,
        ),
    }


def inspect_case_database_schema(path: Path) -> dict[str, object]:
    try:
        with sqlite3.connect(path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT value FROM schema_info WHERE key = 'schema_version'").fetchone()
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            tables = [str(item["name"]) for item in table_rows]
    except sqlite3.DatabaseError:
        return {
            "current_schema_version": None,
            "expected_schema_version": SCHEMA_VERSION,
            "schema_supported": False,
            "tables": [],
        }
    current = int(row["value"]) if row and str(row["value"]).isdigit() else None
    return {
        "current_schema_version": current,
        "expected_schema_version": SCHEMA_VERSION,
        "schema_supported": current in (SCHEMA_VERSION, None),
        "tables": tables,
        "table_count": len(tables),
    }


def build_migration_readiness(path: Path) -> dict[str, object]:
    schema = inspect_case_database_schema(path)
    current = schema.get("current_schema_version")
    expected = schema.get("expected_schema_version")
    return {
        "status": "ready" if current == expected else "review-required",
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "current_schema_version": current,
        "expected_schema_version": expected,
        "backup_before_migration": True,
        "restore_rehearsal_required": True,
        "rehearsal_steps": [
            "Restore this manifest to a temporary database.",
            "Open the restored database with the target RapidTriage version.",
            "Run case-db list/report smoke checks against the restored copy.",
            "Compare source/restored SHA256 and record any schema migration warnings.",
        ],
        "core_accuracy_gates": [
            build_accuracy_gate(
                111,
                satisfied_checks=[
                    "backup manifest generated",
                    "database hashes captured",
                    "schema inventory captured",
                    "migration rehearsal requirement recorded",
                ],
                evidence_refs=[f"current_schema_version:{current}", f"expected_schema_version:{expected}"],
            )
        ],
    }


def backup_restore_core_accuracy_gates(
    *,
    copied: list[dict[str, object]],
    schema: dict[str, object],
    restored: bool,
    hash_verified: bool,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["backup manifest generated", "migration rehearsal requirement recorded"]
    if any(item.get("hashes") for item in copied):
        satisfied.append("database hashes captured")
    if schema.get("table_count") is not None:
        satisfied.append("schema inventory captured")
    if restored and hash_verified:
        satisfied.append("restore hash verified")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted backup/restore rehearsal diff pass")
    return [
        build_accuracy_gate(
            111,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"copied_count:{len(copied)}",
                f"schema_version:{schema.get('current_schema_version')}",
                f"restored:{restored}",
                f"hash_verified:{hash_verified}",
            ],
        )
    ]


def missing_backup_restore_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "blocker": BACKUP_RESTORE_TRUSTED_DIFF_BLOCKER_111,
        "required_trusted_tools": sorted(BACKUP_RESTORE_TRUSTED_TOOLS),
    }


def build_backup_restore_trusted_diff(
    rapid_payload: Mapping[str, object],
    trusted_payload: Mapping[str, object],
    *,
    trusted_tool: str = "backup-restore-rehearsal-log",
) -> dict[str, object]:
    compared_fields = ["hash_verified", "schema", "migration_readiness", "files"]
    mismatches = []
    for field in compared_fields:
        rapid_value = normalize_backup_restore_value(rapid_payload.get(field))
        trusted_value = normalize_backup_restore_value(trusted_payload.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in BACKUP_RESTORE_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "compared_fields": compared_fields,
        "mismatches": mismatches,
        "blocker": None if status == "pass" else BACKUP_RESTORE_TRUSTED_DIFF_BLOCKER_111,
    }


def normalize_backup_restore_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value
