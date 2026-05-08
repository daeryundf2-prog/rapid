from __future__ import annotations

import datetime as dt
import contextlib
import hashlib
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
FUNCTIONAL_OPS_BATCH_ID = "commercial-uplift-061-065"


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
        "functional_priority_profile": backup_restore_functional_profile(
            command="case-backup",
            copied=copied,
            schema=inspect_case_database_schema(source),
            restored=False,
            hash_verified=False,
            trusted_diff=trusted_diff,
        ),
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
    backup_evidence_manifest = build_backup_restore_evidence_manifest(
        manifest,
        trusted_diff=trusted_diff,
        restored=False,
        hash_verified=False,
    )
    continuity_manifest = build_backup_restore_continuity_manifest(
        command="case-backup",
        source_database=str(source),
        backup_manifest_path=str((destination_dir / BACKUP_MANIFEST_NAME).resolve()),
        files=copied,
        schema=manifest["schema"],
        migration_readiness=manifest["migration_readiness"],
        restored_database="",
        hash_verified=False,
    )
    manifest["backup_restore_evidence_manifest"] = backup_evidence_manifest
    manifest["backup_restore_evidence_manifest_hash"] = backup_evidence_manifest["manifest_hash"]
    manifest["backup_restore_evidence_matrix_hash"] = backup_evidence_manifest["rehearsal_evidence_matrix_hash"]
    manifest["backup_restore_continuity_manifest"] = continuity_manifest
    manifest["backup_restore_continuity_manifest_hash"] = continuity_manifest["manifest_hash"]
    manifest["rehearsal_evidence_slots"] = backup_evidence_manifest["rehearsal_evidence_slots"]
    manifest["core_accuracy_gates"] = backup_restore_core_accuracy_gates(
        copied=copied,
        schema=inspect_case_database_schema(source),
        restored=False,
        hash_verified=False,
        trusted_diff=trusted_diff,
        evidence_manifest=backup_evidence_manifest,
        continuity_manifest=continuity_manifest,
    )
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
    payload = {
        "command": "case-restore",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "functional_priority_profile": backup_restore_functional_profile(
            command="case-restore",
            copied=[database_file],
            schema=inspect_case_database_schema(destination),
            restored=True,
            hash_verified=hashes.get("sha256") == source_hashes.get("sha256"),
            trusted_diff=trusted_diff,
        ),
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
    backup_evidence_manifest = build_backup_restore_evidence_manifest(
        payload,
        trusted_diff=trusted_diff,
        restored=True,
        hash_verified=bool(payload["hash_verified"]),
    )
    continuity_manifest = build_backup_restore_continuity_manifest(
        command="case-restore",
        source_database=str(source),
        backup_manifest_path=str(manifest_file),
        files=[database_file],
        schema=payload["schema"],
        migration_readiness=payload["migration_readiness"],
        restored_database=str(destination),
        hash_verified=bool(payload["hash_verified"]),
    )
    payload["backup_restore_evidence_manifest"] = backup_evidence_manifest
    payload["backup_restore_evidence_manifest_hash"] = backup_evidence_manifest["manifest_hash"]
    payload["backup_restore_evidence_matrix_hash"] = backup_evidence_manifest["rehearsal_evidence_matrix_hash"]
    payload["backup_restore_continuity_manifest"] = continuity_manifest
    payload["backup_restore_continuity_manifest_hash"] = continuity_manifest["manifest_hash"]
    payload["rehearsal_evidence_slots"] = backup_evidence_manifest["rehearsal_evidence_slots"]
    payload["core_accuracy_gates"] = backup_restore_core_accuracy_gates(
        copied=[database_file],
        schema=inspect_case_database_schema(destination),
        restored=True,
        hash_verified=hashes.get("sha256") == source_hashes.get("sha256"),
        trusted_diff=trusted_diff,
        evidence_manifest=backup_evidence_manifest,
        continuity_manifest=continuity_manifest,
    )
    return payload


def inspect_case_database_schema(path: Path) -> dict[str, object]:
    try:
        with contextlib.closing(sqlite3.connect(path)) as connection:
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


def backup_restore_functional_profile(
    *,
    command: str,
    copied: list[dict[str, object]],
    schema: Mapping[str, object],
    restored: bool,
    hash_verified: bool,
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    copied_labels = {str(item.get("label") or "") for item in copied if isinstance(item, Mapping)}
    failed_checks = [
        "trusted-backup-restore-rehearsal-diff-required",
        "migration-corpus-not-attached",
    ]
    if restored and not hash_verified:
        failed_checks.append("restored-database-hash-mismatch")
    if trusted_diff and trusted_diff.get("status") == "pass":
        failed_checks = [item for item in failed_checks if item != "trusted-backup-restore-rehearsal-diff-required"]
    return {
        "batch_id": FUNCTIONAL_OPS_BATCH_ID,
        "item_number": 62,
        "implementation_track": "backup-restore-migration",
        "command": command,
        "status": "usable-local-backup-restore-migration-corpus-required",
        "implemented_controls": {
            "case_database_backup_manifest": True,
            "wal_copy_attempted": True,
            "shm_copy_attempted": True,
            "database_hashes_captured": any(item.get("hashes") for item in copied),
            "schema_version_recorded": schema.get("current_schema_version") is not None,
            "table_inventory_recorded": schema.get("table_count") is not None,
            "restore_hash_verified": bool(restored and hash_verified),
            "backup_restore_continuity_manifest_emitted": True,
            "migration_rehearsal_required": True,
        },
        "evidence_counts": {
            "copied_file_count": len(copied),
            "wal_present": "wal" in copied_labels,
            "shm_present": "shm" in copied_labels,
            "table_count": int(schema.get("table_count") or 0),
        },
        "failed_validation_check_ids": failed_checks,
        "ready_for_commercial_release": False,
    }


def backup_restore_core_accuracy_gates(
    *,
    copied: list[dict[str, object]],
    schema: dict[str, object],
    restored: bool,
    hash_verified: bool,
    trusted_diff: Mapping[str, object] | None = None,
    evidence_manifest: Mapping[str, object] | None = None,
    continuity_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["backup manifest generated", "migration rehearsal requirement recorded"]
    if any(item.get("hashes") for item in copied):
        satisfied.append("database hashes captured")
    if schema.get("table_count") is not None:
        satisfied.append("schema inventory captured")
    if restored and hash_verified:
        satisfied.append("restore hash verified")
    if evidence_manifest:
        if evidence_manifest.get("manifest_hash"):
            satisfied.append("backup restore evidence manifest hash emitted")
        if evidence_manifest.get("rehearsal_evidence_slots"):
            satisfied.append("backup restore rehearsal evidence slots emitted")
        if evidence_manifest.get("rehearsal_evidence_matrix_hash"):
            satisfied.append("backup restore rehearsal evidence matrix hash emitted")
    if continuity_manifest:
        if continuity_manifest.get("manifest_hash"):
            satisfied.append("backup restore continuity manifest hash emitted")
        if continuity_manifest.get("hash_verified") is True:
            satisfied.append("continuity hash verification recorded")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted backup/restore rehearsal diff pass")
    evidence_refs = [
        f"copied_count:{len(copied)}",
        f"schema_version:{schema.get('current_schema_version')}",
        f"restored:{restored}",
        f"hash_verified:{hash_verified}",
    ]
    if continuity_manifest and continuity_manifest.get("manifest_hash"):
        evidence_refs.append(f"backup_restore_continuity_manifest_sha256:{continuity_manifest['manifest_hash']}")
    return [
        build_accuracy_gate(
            111,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
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
    compared_fields = [
        "hash_verified",
        "schema",
        "migration_readiness",
        "files",
        "backup_restore_evidence_manifest_hash",
        "backup_restore_evidence_matrix_hash",
        "backup_restore_continuity_manifest_hash",
        "rehearsal_evidence_slots",
    ]
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


def stable_backup_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def build_backup_restore_continuity_manifest(
    *,
    command: str,
    source_database: str,
    backup_manifest_path: str,
    files: list[dict[str, object]],
    schema: Mapping[str, object],
    migration_readiness: Mapping[str, object],
    restored_database: str,
    hash_verified: bool,
) -> dict[str, object]:
    file_hashes = [
        {
            "label": item.get("label", ""),
            "backup_path": item.get("backup_path", ""),
            "sha256": dict(item.get("hashes", {})).get("sha256", "") if isinstance(item.get("hashes"), Mapping) else "",
            "size_bytes": item.get("size_bytes", 0),
        }
        for item in files
        if isinstance(item, Mapping)
    ]
    labels = {str(item.get("label") or "") for item in files if isinstance(item, Mapping)}
    manifest: dict[str, object] = {
        "profile_version": "backup-restore-continuity-manifest-v1",
        "item_number": 62,
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "command": command,
        "source_database": source_database,
        "restored_database": restored_database,
        "backup_manifest_path": backup_manifest_path,
        "file_hashes": file_hashes,
        "file_count": len(file_hashes),
        "wal_present": "wal" in labels,
        "shm_present": "shm" in labels,
        "hash_verified": bool(hash_verified),
        "schema_snapshot": dict(schema),
        "schema_snapshot_hash": stable_backup_sha256(schema),
        "migration_readiness": dict(migration_readiness),
        "migration_readiness_hash": stable_backup_sha256(migration_readiness),
        "continuity_controls": {
            "source_backup_hash_linked": any(item.get("sha256") for item in file_hashes),
            "restore_hash_verification_recorded": command == "case-restore",
            "schema_version_recorded": schema.get("current_schema_version") is not None,
            "migration_rehearsal_required": bool(migration_readiness.get("restore_rehearsal_required")),
        },
        "external_evidence_required": [
            "restore drill transcript",
            "multi-version migration corpus run",
            "scheduled backup drill on production-scale case",
            "trusted backup/restore rehearsal diff",
        ],
        "validation_status": "implemented-usable-external-rehearsal-required",
    }
    manifest["manifest_hash"] = stable_backup_sha256(manifest)
    return manifest


def build_backup_restore_evidence_manifest(
    payload: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object],
    restored: bool,
    hash_verified: bool,
) -> dict[str, object]:
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    if not files and isinstance(payload.get("source_hashes"), Mapping):
        files = [{"label": "restored_database", "hashes": payload.get("source_hashes")}]
    schema = payload.get("schema") if isinstance(payload.get("schema"), Mapping) else {}
    rehearsal_evidence_slots = {
        "restore_drill_log": {
            "status": "not-attached",
            "expected_material": "Restore rehearsal transcript and restored database hash comparison",
            "required_before_commercial_claim": True,
        },
        "migration_corpus_run": {
            "status": "not-attached",
            "expected_material": "Multi-version migration corpus run log",
            "required_before_commercial_claim": True,
        },
        "scheduled_backup_drill": {
            "status": "not-attached",
            "expected_material": "Scheduled backup and restore drill evidence from a production-scale case",
            "required_before_commercial_claim": True,
        },
    }
    rehearsal_evidence_matrix = build_backup_restore_rehearsal_evidence_matrix(
        payload=payload,
        slots=rehearsal_evidence_slots,
    )
    manifest: dict[str, object] = {
        "profile_version": "backup-restore-rehearsal-manifest-v1",
        "item_number": 111,
        "commercial_gap_ids": [BACKUP_RESTORE_MIGRATION_GAP_ID],
        "commercial_claim_allowed": False,
        "command": payload.get("command"),
        "copied_or_verified_file_count": len(files),
        "schema_snapshot_hash": stable_backup_sha256(schema),
        "migration_readiness_hash": stable_backup_sha256(payload.get("migration_readiness", {})),
        "restored": restored,
        "hash_verified": hash_verified,
        "rehearsal_evidence_slots": rehearsal_evidence_slots,
        "rehearsal_evidence_matrix": rehearsal_evidence_matrix,
        "rehearsal_evidence_matrix_hash": rehearsal_evidence_matrix["matrix_hash"],
        "trusted_diff_status": trusted_diff.get("status"),
        "trusted_diff_blocker": trusted_diff.get("blocker"),
        "blockers": [BACKUP_RESTORE_TRUSTED_DIFF_BLOCKER_111],
    }
    manifest["manifest_hash"] = stable_backup_sha256(manifest)
    return manifest


def build_backup_restore_rehearsal_evidence_matrix(
    *,
    payload: Mapping[str, object],
    slots: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    rows = []
    for slot_name, slot in sorted(slots.items()):
        row_core = {
            "slot": slot_name,
            "status": slot.get("status", ""),
            "attached": slot.get("status") not in {"not-attached", "missing", ""},
            "required_before_commercial_claim": bool(slot.get("required_before_commercial_claim")),
            "expected_material_hash": stable_backup_sha256(slot.get("expected_material", "")),
        }
        rows.append({**row_core, "row_hash": stable_backup_sha256(row_core)})
    matrix: dict[str, object] = {
        "profile_version": "backup-restore-rehearsal-evidence-matrix-v1",
        "item_number": 111,
        "command": payload.get("command"),
        "payload_hash": stable_backup_sha256(
            {
                "command": payload.get("command"),
                "schema": payload.get("schema", {}),
                "migration_readiness": payload.get("migration_readiness", {}),
                "copied_count": payload.get("copied_count", 0),
                "hash_verified": payload.get("hash_verified", False),
            }
        ),
        "slot_count": len(rows),
        "required_slot_count": sum(1 for row in rows if row["required_before_commercial_claim"]),
        "attached_slot_count": sum(1 for row in rows if row["attached"]),
        "missing_required_slot_count": sum(
            1 for row in rows if row["required_before_commercial_claim"] and not row["attached"]
        ),
        "rows": rows,
        "commercial_claim_allowed": False,
    }
    matrix["matrix_hash"] = stable_backup_sha256(matrix)
    return matrix
