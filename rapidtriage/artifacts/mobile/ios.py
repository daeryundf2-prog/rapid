from __future__ import annotations

import datetime as dt
import plistlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from .constants import (
    FUNCTIONAL_EXPANSION_BATCH_ID,
    IOS_BACKUP_REPORT_GRADE_BLOCKERS,
    IOS_BACKUP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    IOS_KEYCHAIN_REPORT_GRADE_BLOCKERS,
    IOS_KEYCHAIN_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    IOS_KEYCHAIN_SENSITIVE_COLUMN_TOKENS,
    IOS_KEYCHAIN_TABLE_CLASSES,
    IOS_QC_PREP_CONTRACT,
    IOS_QC_PREP_GOAL,
    IOS_QC_PREP_ITEM_NUMBER,
    MAX_IOS_BACKUP_FILES,
    MAX_SQLITE_TABLES,
    PARSER_VERSION,
)
from .helpers import (
    _mobile_vendor_export_validation_command,
    compute_file_sha256,
    first_truthy,
    ios_backup_file_risk_flags,
    looks_like_ios_backup_path,
    normalize_timestamp,
    optional_text,
    sha256_text,
    source_record_id,
    stable_mobile_sha256,
)


def build_ios_backup_scope_profile(
    rows: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
) -> dict[str, object]:
    domain_counts: dict[str, int] = {}
    risk_counts: dict[str, int] = {}
    for row in rows:
        domain = optional_text(row.get("domain"))
        relative_path = optional_text(row.get("relativePath"))
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        for flag in ios_backup_file_risk_flags(domain, relative_path):
            risk_counts[flag] = risk_counts.get(flag, 0) + 1
    return {
        "profile_version": "ios-backup-scope-v1",
        "manifest_row_count": len(rows),
        "row_limit": validation.get("row_limit", MAX_IOS_BACKUP_FILES),
        "truncated_by_row_limit": len(rows) >= int(validation.get("row_limit", MAX_IOS_BACKUP_FILES) or 0),
        "domain_count": len(domain_counts),
        "top_domains": [
            {"domain": domain, "file_count": count}
            for domain, count in sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))[:25]
        ],
        "risk_counts": dict(sorted(risk_counts.items())),
        "protected_payload_decode": "not-performed",
        "encrypted_backup_unlock": "not-performed",
        "reporting_status": "manifest-inventory-validation-required",
    }


def build_ios_backup_root_profile(
    manifest_path: Path,
    rows: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
) -> dict[str, object]:
    backup_root = manifest_path.parent
    required = ("Manifest.db", "Info.plist", "Status.plist")
    root_files = {name: ios_backup_root_file_profile(backup_root / name) for name in required}
    keychain_profile = ios_backup_root_file_profile(backup_root / "keychain-2.db")
    info_metadata = load_ios_plist_metadata(backup_root / "Info.plist")
    status_metadata = load_ios_plist_metadata(backup_root / "Status.plist")
    encrypted_hint = first_truthy(
        info_metadata.get("encrypted"),
        info_metadata.get("isencrypted"),
        status_metadata.get("encrypted"),
        status_metadata.get("isencrypted"),
    )
    domain_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for row in rows:
        domain = optional_text(row.get("domain"))
        relative_path = optional_text(row.get("relativePath"))
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        category = build_ios_backup_file_profile(domain, relative_path, optional_text(row.get("fileID")), row.get("flags"))["category"]
        category_counts[category] = category_counts.get(category, 0) + 1
    missing_required = [name for name, profile in root_files.items() if not profile.get("present")]
    return {
        "profile_version": "ios-backup-root-profile-v1",
        "backup_root": str(backup_root.resolve()),
        "required_files": root_files,
        "keychain_file": keychain_profile,
        "required_files_present": not missing_required,
        "missing_required_files": missing_required,
        "manifest_opened_readonly": bool(validation.get("opened_readonly")),
        "files_table_present": bool(validation.get("files_table_present")),
        "manifest_row_count": len(rows),
        "domain_count": len(domain_counts),
        "top_domains": [
            {"domain": domain, "file_count": count}
            for domain, count in sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))[:25]
        ],
        "category_counts": dict(sorted(category_counts.items())),
        "device_name": optional_text(info_metadata.get("device_name")),
        "product_version": optional_text(info_metadata.get("product_version")),
        "last_backup_date": normalize_timestamp(info_metadata.get("last_backup_date", "")),
        "snapshot_state": optional_text(status_metadata.get("snapshot_state")),
        "is_full_backup": bool(status_metadata.get("is_full_backup")),
        "encrypted_backup_state": "encrypted-or-unknown" if encrypted_hint else "not-indicated",
        "encrypted_backup_unlock": "authority-required-if-encrypted",
        "validation_status": "inventory-ready" if not missing_required and validation.get("opened_readonly") else "review-required",
        "reporting_status": "backup-root-inventory-not-content-decode",
    }


def build_ios_backup_deep_parser_manifest(
    *,
    manifest_path: Path,
    source_hashes: Mapping[str, str],
    manifest_rows: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
    scope_profile: Mapping[str, object],
    root_profile: Mapping[str, object],
) -> dict[str, object]:
    backup_root = manifest_path.parent
    candidate_rows: list[dict[str, object]] = []
    category_counts: dict[str, int] = {}
    app_domain_count = 0
    for index, row in enumerate(manifest_rows[:MAX_IOS_BACKUP_FILES]):
        domain = optional_text(row.get("domain"))
        relative_path = optional_text(row.get("relativePath"))
        file_id = optional_text(row.get("fileID"))
        file_profile = build_ios_backup_file_profile(domain, relative_path, file_id, row.get("flags"))
        category = optional_text(file_profile.get("category")) or "other"
        category_counts[category] = category_counts.get(category, 0) + 1
        if domain.startswith("AppDomain-"):
            app_domain_count += 1
        lowered_path = relative_path.lower()
        suffix = Path(relative_path).suffix.lower()
        is_app_db_candidate = (
            suffix in {".db", ".sqlite", ".sqlite3"}
            or category in {"message-or-chat-store", "credential-or-account-candidate"}
            or any(token in lowered_path for token in ("sms", "chat", "message", "browser", "history", "contacts"))
        )
        if is_app_db_candidate:
            candidate_rows.append(
                {
                    "source_index": index,
                    "file_id_sha256": sha256_text(file_id) if file_id else "",
                    "domain": domain,
                    "relative_path": relative_path,
                    "logical_path": f"{domain}/{relative_path}".strip("/"),
                    "category": category,
                    "payload_decode_status": "not-decoded",
                    "schema_validation_status": "candidate-needs-app-version-fixture",
                }
            )
    manifest: dict[str, object] = {
        "manifest_version": "ios-backup-deep-parser-manifest-v1",
        "item_number": 27,
        "gap_id": "#27",
        "artifact_goal": "iOS backup Manifest.db, plist metadata, app database candidates, and encrypted/protected-data gates",
        "parser_version": PARSER_VERSION,
        "source_path": str(manifest_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "backup_root": str(backup_root.resolve()),
        "source_viewer_locator": {
            "viewer": "ios-backup-deep-parser-source",
            "source_path": str(manifest_path.resolve()),
            "artifact_type": "ios-backup-source",
        },
        "manifest_db": {
            "opened_readonly": bool(validation.get("opened_readonly")),
            "files_table_present": bool(validation.get("files_table_present")),
            "manifest_row_count": len(manifest_rows),
            "row_limit": MAX_IOS_BACKUP_FILES,
            "truncated_by_row_limit": len(manifest_rows) >= int(validation.get("row_limit", MAX_IOS_BACKUP_FILES) or 0),
        },
        "root_integrity": {
            "required_files_present": bool(root_profile.get("required_files_present")),
            "missing_required_files": list(root_profile.get("missing_required_files") or []),
            "required_files": root_profile.get("required_files", {}),
            "keychain_file": root_profile.get("keychain_file", {}),
        },
        "device_metadata": {
            "device_name": optional_text(root_profile.get("device_name")),
            "product_version": optional_text(root_profile.get("product_version")),
            "last_backup_date": optional_text(root_profile.get("last_backup_date")),
            "snapshot_state": optional_text(root_profile.get("snapshot_state")),
            "is_full_backup": bool(root_profile.get("is_full_backup")),
            "encrypted_backup_state": optional_text(root_profile.get("encrypted_backup_state")),
        },
        "domain_and_category_summary": {
            "domain_count": scope_profile.get("domain_count"),
            "top_domains": scope_profile.get("top_domains", []),
            "category_counts": dict(sorted(category_counts.items())),
            "risk_counts": scope_profile.get("risk_counts", {}),
            "app_domain_count": app_domain_count,
        },
        "app_database_candidates": {
            "candidate_count": len(candidate_rows),
            "candidate_sample": candidate_rows[:50],
            "message_store_candidate_count": category_counts.get("message-or-chat-store", 0),
            "credential_or_account_candidate_count": category_counts.get("credential-or-account-candidate", 0),
        },
        "capability_statement": {
            "manifest_db_domain_file_mapping": True,
            "info_status_plist_inventory": True,
            "app_database_candidate_detection": True,
            "file_payload_decode": False,
            "encrypted_backup_unlock": False,
            "deleted_record_recovery": False,
            "protected_data_class_decode": False,
        },
        "validation": {
            "implemented": True,
            "usable": True,
            "internal_fixture_validated": True,
            "manifest_opened_readonly": bool(validation.get("opened_readonly")),
            "required_backup_files_present": bool(root_profile.get("required_files_present")),
            "encrypted_backup_authority_attached": False,
            "trusted_ios_backup_diff_attached": False,
            "app_db_schema_known_answer_attached": False,
            "commercial_grade": False,
        },
        "commercial_blockers": [
            "encrypted-backup-unlock-workflow-evidence-required",
            "application-database-schema-known-answer-required",
            "deleted-record-semantics-known-answer-required",
            "trusted-ios-backup-parser-diff-required",
        ],
        "reporting_status": "ios-backup-deep-parser-inventory-not-content-decode",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_ios_backup_report_grade_validation_plan(
    *,
    manifest_path: Path,
    source_hashes: Mapping[str, str],
    manifest_rows: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
    scope_profile: Mapping[str, object],
    root_profile: Mapping[str, object],
    deep_parser_manifest: Mapping[str, object],
) -> dict[str, object]:
    backup_root = manifest_path.parent
    output_root = backup_root / "ios-backup-rapidtriage-validation"
    encrypted_state = optional_text(root_profile.get("encrypted_backup_state"))
    encrypted_or_unknown = encrypted_state not in {"", "not-indicated"}
    required_files = root_profile.get("required_files") if isinstance(root_profile.get("required_files"), Mapping) else {}
    keychain_file = root_profile.get("keychain_file") if isinstance(root_profile.get("keychain_file"), Mapping) else {}
    manifest_row_count = int(scope_profile.get("manifest_row_count") or len(manifest_rows))
    app_candidates = (
        deep_parser_manifest.get("app_database_candidates")
        if isinstance(deep_parser_manifest.get("app_database_candidates"), Mapping)
        else {}
    )
    validation_commands = [
        _mobile_vendor_export_validation_command(
            "source-backup-manifest",
            ["rapidtriage", "manifest", str(backup_root), "--output", str(output_root / "source-backup-manifest.json")],
            purpose="Hash the authorized iOS backup root and preserve Manifest.db/plist/keychain source inventory.",
            expected_output=str(output_root / "source-backup-manifest.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "ios-backup-import",
            [
                "rapidtriage",
                "artifacts",
                str(backup_root),
                "--kind",
                "mobile-export",
                "--output",
                str(output_root / "rapidtriage-ios-backup.json"),
            ],
            purpose="Regenerate RapidTriage iOS backup Manifest.db, plist, and keychain inventory rows.",
            expected_output=str(output_root / "rapidtriage-ios-backup.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "encrypted-backup-authority-review",
            [
                "<analyst>",
                "attach-encrypted-backup-authority-and-unlock-log",
                str(backup_root),
            ],
            purpose="Attach lawful authority and unlock transcript only if the backup is encrypted or protected payloads are decoded.",
            expected_output=str(output_root / "encrypted-backup-authority-review.json"),
            trusted_tool=True,
            status="complete" if not encrypted_or_unknown else "authority-required",
        ),
        _mobile_vendor_export_validation_command(
            "trusted-ios-backup-parser-diff",
            [
                "rapidtriage",
                "cross-tool-validate",
                "--rapid-output",
                str(output_root / "rapidtriage-ios-backup.json"),
                "--reference-output",
                "ileapp=<iLEAPP-ios-backup.csv-or-json>",
                "--reference-output",
                "cellebrite=<Cellebrite-ios-backup.csv-or-json>",
                "--backlog-item",
                "27",
                "--source-evidence",
                str(manifest_path),
                "--tool-version",
                "ileapp=<version>",
                "--tool-command",
                "ileapp=<command>",
                "--corpus-scope",
                "<ios-version-encrypted-unencrypted-deleted-record-known-answer-scope>",
                "--output",
                str(output_root / "ios-backup-trusted-diff.json"),
                "--json",
            ],
            purpose="Compare Manifest.db file/domain/path rows and app database candidates against trusted iOS parsers.",
            expected_output=str(output_root / "ios-backup-trusted-diff.json"),
            trusted_tool=True,
            status="pending-cross-tool-validate",
        ),
    ]
    evidence_slots = [
        {
            "id": "manifest-db-source-integrity",
            "label": "Manifest.db SHA-256 and read-only source identity",
            "status": "complete" if source_hashes.get("sha256") else "pending-source-hash",
            "required_before_report": True,
            "sha256": source_hashes.get("sha256", ""),
        },
        {
            "id": "manifest-files-table-readonly-open",
            "label": "Manifest.db Files table opened read-only",
            "status": "complete"
            if validation.get("opened_readonly") and validation.get("files_table_present")
            else "review-required",
            "required_before_report": True,
            "manifest_row_count": manifest_row_count,
            "row_limit": MAX_IOS_BACKUP_FILES,
            "truncated_by_row_limit": bool(scope_profile.get("truncated_by_row_limit")),
        },
        {
            "id": "backup-root-required-files",
            "label": "Manifest.db, Info.plist, and Status.plist presence and hashes",
            "status": "complete" if root_profile.get("required_files_present") else "missing-required-files",
            "required_before_report": True,
            "required_files": dict(required_files),
            "missing_required_files": list(root_profile.get("missing_required_files") or []),
        },
        {
            "id": "plist-device-status-metadata",
            "label": "Info/Status plist device and backup status metadata",
            "status": "complete"
            if validation.get("info_plist_present") and validation.get("status_plist_present")
            else "review-required",
            "required_before_report": True,
            "device_name": optional_text(root_profile.get("device_name")),
            "product_version": optional_text(root_profile.get("product_version")),
            "snapshot_state": optional_text(root_profile.get("snapshot_state")),
            "is_full_backup": bool(root_profile.get("is_full_backup")),
        },
        {
            "id": "keychain-linkage-inventory",
            "label": "keychain-2.db presence recorded without secret reveal",
            "status": "complete" if keychain_file.get("present") else "not-present-or-not-exported",
            "required_before_report": False,
            "keychain_file": dict(keychain_file),
            "secret_values_revealed": False,
        },
        {
            "id": "app-database-candidate-map",
            "label": "App database/message/media candidate map from Manifest.db",
            "status": "complete" if deep_parser_manifest.get("manifest_sha256") else "pending-deep-parser-manifest",
            "required_before_report": True,
            "deep_parser_manifest_sha256": optional_text(deep_parser_manifest.get("manifest_sha256")),
            "candidate_count": int(app_candidates.get("candidate_count") or 0),
            "message_store_candidate_count": int(app_candidates.get("message_store_candidate_count") or 0),
        },
        {
            "id": "encrypted-backup-authority",
            "label": "Encrypted/protected backup lawful authority and unlock transcript",
            "status": "complete" if not encrypted_or_unknown else "authority-required",
            "required_before_report": encrypted_or_unknown,
            "encrypted_backup_state": encrypted_state or "not-indicated",
            "protected_payload_decode_performed": False,
        },
        {
            "id": "trusted-ios-backup-parser-diff",
            "label": "Trusted iLEAPP/Cellebrite/AXIOM Manifest.db row diff",
            "status": "pending-cross-tool-validate",
            "required_before_report": True,
            "required_fields": [
                "file_id",
                "domain",
                "relative_path",
                "logical_path",
                "protection_class",
                "file_size",
                "app_database_candidate",
            ],
        },
        {
            "id": "app-database-schema-known-answer",
            "label": "SMS/media/app DB schema known-answer corpus",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["sms.db", "Photos/media", "Safari/browser", "third-party AppDomain database"],
        },
        {
            "id": "deleted-record-semantics-corpus",
            "label": "Deleted/edited row and protected-data class known-answer corpus",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["live row", "deleted row", "WAL/SHM residue", "protected class boundary"],
        },
        {
            "id": "independent-ios-backup-review",
            "label": "Independent review of backup acquisition, unlock, and parser diff procedure",
            "status": "external-review-required",
            "required_before_commercial_grade": True,
            "required_materials": ["backup acquisition log", "Manifest.db hash", "trusted diff", "authority record if encrypted"],
        },
    ]
    ready_slots = [slot["id"] for slot in evidence_slots if str(slot.get("status", "")).startswith("complete")]
    blocker_slots = [
        slot["id"]
        for slot in evidence_slots
        if slot.get("required_before_report") and not str(slot.get("status", "")).startswith("complete")
    ]
    payload: dict[str, object] = {
        "profile_version": IOS_BACKUP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 27,
        "gap_id": "#27",
        "source_path": str(manifest_path.resolve()),
        "backup_root": str(backup_root.resolve()),
        "source_hashes": dict(source_hashes),
        "status": "report-validation-blocked" if blocker_slots else "ready-for-report-review",
        "commercial_grade_ready": False,
        "scope_profile": dict(scope_profile),
        "root_profile": dict(root_profile),
        "ios_backup_deep_parser_manifest_hash": optional_text(deep_parser_manifest.get("manifest_sha256")),
        "validation_commands": validation_commands,
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slots,
        "blocking_slot_ids": blocker_slots,
        "report_claim_boundary": (
            "This plan can make Manifest.db/plist inventory reviewable when report-required slots pass; "
            "it is not proof of decrypted protected file content, app database semantics, deleted-record recovery, "
            "or complete device acquisition without trusted parser diffs and authority evidence."
        ),
        "commercial_grade_blockers": list(IOS_BACKUP_REPORT_GRADE_BLOCKERS),
        "operator_next_steps": [
            "Preserve the original iOS backup folder and hash Manifest.db before import.",
            "Regenerate RapidTriage iOS backup rows from the backup root.",
            "Run trusted iLEAPP/Cellebrite/AXIOM diff for Manifest.db file/domain/path rows.",
            "Attach encrypted-backup authority and unlock logs only when protected payload decoding is performed.",
            "Attach app DB/deleted-record known-answer fixtures before commercial-grade wording.",
        ],
    }
    payload["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    return payload


def ios_backup_root_file_profile(path: Path) -> dict[str, object]:
    profile: dict[str, object] = {
        "path": str(path.resolve()),
        "name": path.name,
        "present": path.is_file(),
    }
    if path.is_file():
        stat = path.stat()
        profile.update({"size": stat.st_size, "sha256": compute_file_sha256(path)})
    return profile


def load_ios_plist_metadata(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    return sanitize_ios_plist(payload) if isinstance(payload, Mapping) else {}


def build_ios_backup_file_profile(
    domain: str,
    relative_path: str,
    file_id: str,
    flags: object,
) -> dict[str, object]:
    lowered = f"{domain}/{relative_path}".lower()
    category = "other"
    if any(token in lowered for token in ("sms", "message", "chat", "whatsapp", "telegram", "line", "kakao")):
        category = "message-or-chat-store"
    elif any(token in lowered for token in ("photo", "camera", "dcim", ".jpg", ".mov", ".mp4")):
        category = "media"
    elif any(token in lowered for token in ("cookie", "account", "credential", "keychain")):
        category = "credential-or-account-candidate"
    return {
        "profile_version": "ios-backup-file-v1",
        "domain": domain,
        "relative_path": relative_path,
        "file_id_present": bool(file_id),
        "category": category,
        "flags_raw": optional_text(flags),
        "payload_decode_status": "not-decoded",
        "deleted_record_recovery_status": "not-validated",
        "required_before_report": [
            "validate fileID/domain/path mapping against a trusted iOS backup parser",
            "decode the target app database with schema-version fixtures before content conclusions",
            "attach encrypted-backup unlock authority and logs if protected data is required",
        ],
    }


def build_ios_keychain_table_profile(table_name: str, columns: Sequence[str]) -> dict[str, object]:
    lowered_table = table_name.lower()
    sensitive_columns = [
        column
        for column in columns
        if any(token in column.lower() for token in IOS_KEYCHAIN_SENSITIVE_COLUMN_TOKENS)
    ]
    return {
        "profile_version": "ios-keychain-table-v1",
        "table": table_name,
        "table_class": IOS_KEYCHAIN_TABLE_CLASSES.get(lowered_table, "other-keychain-table"),
        "sensitive_columns": sorted(dict.fromkeys(sensitive_columns)),
        "protected_value_column_count": len(sensitive_columns),
    }


def build_ios_keychain_authority_gate(
    table_summaries: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
) -> dict[str, object]:
    blocked_table_classes = sorted(
        {
            str(summary.get("table_class") or IOS_KEYCHAIN_TABLE_CLASSES.get(str(summary.get("table") or "").lower(), "other-keychain-table"))
            for summary in table_summaries
            if int(summary.get("protected_value_column_count") or 0) > 0
            or str(summary.get("table") or "").lower() in IOS_KEYCHAIN_TABLE_CLASSES
        }
    )
    blocked_columns = sorted(
        {
            str(column)
            for summary in table_summaries
            for column in (summary.get("sensitive_columns") or [])
            if str(column)
        }
    )
    return {
        "profile_version": "ios-keychain-authority-gate-v1",
        "secret_reveal_allowed": False,
        "audit_required_before_reveal": True,
        "lawful_authority_required": True,
        "specialized_keybag_validation_required": True,
        "opened_readonly": bool(validation.get("opened_readonly")),
        "blocked_table_classes": blocked_table_classes[:25],
        "blocked_sensitive_columns": blocked_columns[:50],
        "default_action": "inventory-only-redact-values",
        "reason": "Keychain tables can contain passwords, tokens, keys, certificates, or account identifiers; RapidTriage records schema/row inventory only.",
        "required_before_reveal": [
            "case-level legal authority recorded",
            "analyst identity and reason captured in immutable audit log",
            "validated keybag/protected-data class handling attached",
            "known-answer fixture confirms decrypted value semantics",
        ],
    }


def build_ios_keychain_scope_profile(
    table_summaries: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
) -> dict[str, object]:
    total_rows = sum(int(summary.get("row_count") or 0) for summary in table_summaries)
    sensitive_tables = [
        str(summary.get("table"))
        for summary in table_summaries
        if str(summary.get("table") or "").lower() in {"genp", "inet", "cert", "keys"}
    ]
    column_names = sorted(
        {
            str(column)
            for summary in table_summaries
            for column in (summary.get("columns") or [])
            if str(column)
        }
    )
    table_class_counts: dict[str, int] = {}
    sensitive_column_names = sorted(
        {
            str(column)
            for summary in table_summaries
            for column in (summary.get("sensitive_columns") or [])
            if str(column)
        }
    )
    protected_value_column_count = 0
    for summary in table_summaries:
        table_class = str(summary.get("table_class") or IOS_KEYCHAIN_TABLE_CLASSES.get(str(summary.get("table") or "").lower(), "other-keychain-table"))
        table_class_counts[table_class] = table_class_counts.get(table_class, 0) + 1
        protected_value_column_count += int(summary.get("protected_value_column_count") or 0)
    return {
        "profile_version": "ios-keychain-scope-v1",
        "table_count": len(table_summaries),
        "total_row_count": total_rows,
        "sensitive_table_names": sensitive_tables,
        "table_class_counts": dict(sorted(table_class_counts.items())),
        "sensitive_column_names": sensitive_column_names[:50],
        "protected_value_column_count": protected_value_column_count,
        "column_sample": column_names[:50],
        "opened_readonly": bool(validation.get("opened_readonly")),
        "values_redacted": bool(validation.get("values_redacted", True)),
        "redaction_policy": {
            "values_redacted": bool(validation.get("values_redacted", True)),
            "secrets_extracted": bool(validation.get("secrets_extracted")),
            "column_names_only": True,
            "row_values_read": False,
            "reveal_requires_authority": True,
        },
        "secret_decryption_status": "not-performed",
        "access_group_semantics_status": "inventory-only",
        "controlled_reveal_required": True,
        "table_inventory_validation_status": "inventory-ready"
        if validation.get("opened_readonly") and bool(validation.get("values_redacted", True))
        else "review-required",
        "reporting_status": "redacted-inventory-validation-required",
        "required_before_report": [
            "attach authority record before any protected-data reveal",
            "validate keybag/protected-data class interpretation with known-answer corpus",
            "diff table inventory and row counts against a trusted iOS keychain parser",
            "preserve controlled-reveal audit event if any secret value is exposed outside RapidTriage",
        ],
    }


def build_ios_keychain_deep_inventory_manifest(
    *,
    source_path: Path,
    source_hashes: Mapping[str, str],
    table_summaries: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
    scope_profile: Mapping[str, object],
    authority_gate: Mapping[str, object],
) -> dict[str, object]:
    table_class_counts = dict(scope_profile.get("table_class_counts") or {})
    table_inventory = []
    for summary in table_summaries[:MAX_SQLITE_TABLES]:
        table_inventory.append(
            {
                "table": optional_text(summary.get("table")),
                "table_class": optional_text(summary.get("table_class")),
                "row_count": int(summary.get("row_count") or 0),
                "column_count": len(summary.get("columns") or []) if isinstance(summary.get("columns"), list) else 0,
                "sensitive_columns": list(summary.get("sensitive_columns") or [])[:25],
                "protected_value_column_count": int(summary.get("protected_value_column_count") or 0),
                "row_values_read": False,
                "row_sample_policy": optional_text(summary.get("row_sample_policy")) or "redacted-schema-only-no-values-read",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "ios-keychain-deep-inventory-manifest-v1",
        "item_number": 28,
        "gap_id": "#28",
        "artifact_goal": "iOS keychain redacted inventory, table class mapping, protected-value boundary, and authority workflow",
        "parser_version": PARSER_VERSION,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_viewer_locator": {
            "viewer": "ios-keychain-deep-inventory",
            "source_path": str(source_path.resolve()),
            "artifact_type": "ios-keychain-inventory",
        },
        "scope": {
            "opened_readonly": bool(validation.get("opened_readonly")),
            "table_count": int(scope_profile.get("table_count") or len(table_summaries)),
            "total_row_count": int(scope_profile.get("total_row_count") or 0),
            "table_class_counts": table_class_counts,
            "sensitive_table_names": list(scope_profile.get("sensitive_table_names") or []),
            "sensitive_column_names": list(scope_profile.get("sensitive_column_names") or [])[:50],
            "protected_value_column_count": int(scope_profile.get("protected_value_column_count") or 0),
            "table_inventory": table_inventory,
        },
        "redaction_policy": {
            "values_redacted": bool(validation.get("values_redacted", True)),
            "secrets_extracted": bool(validation.get("secrets_extracted")),
            "row_values_read": False,
            "schema_only": True,
            "controlled_reveal_required": True,
            "controlled_reveal_performed": False,
        },
        "authority_gate": {
            "secret_reveal_allowed": bool(authority_gate.get("secret_reveal_allowed")),
            "lawful_authority_required": bool(authority_gate.get("lawful_authority_required", True)),
            "audit_required_before_reveal": bool(authority_gate.get("audit_required_before_reveal", True)),
            "specialized_keybag_validation_required": bool(
                authority_gate.get("specialized_keybag_validation_required", True)
            ),
            "blocked_table_classes": list(authority_gate.get("blocked_table_classes") or []),
            "blocked_sensitive_columns": list(authority_gate.get("blocked_sensitive_columns") or [])[:50],
        },
        "capability_statement": {
            "table_inventory": True,
            "sensitive_column_detection": True,
            "table_class_mapping": True,
            "secret_value_decryption": False,
            "access_group_semantics": False,
            "protected_data_class_decode": False,
            "known_answer_keychain_corpus": False,
        },
        "validation": {
            "implemented": True,
            "usable": True,
            "internal_fixture_validated": True,
            "opened_readonly": bool(validation.get("opened_readonly")),
            "values_redacted": bool(validation.get("values_redacted", True)),
            "secrets_not_extracted": not bool(validation.get("secrets_extracted")),
            "controlled_reveal_authority_attached": False,
            "trusted_keychain_diff_attached": False,
            "commercial_grade": False,
        },
        "commercial_blockers": [
            "lawful-authority-and-controlled-reveal-audit-required",
            "keybag-protected-data-class-validation-required",
            "access-group-semantics-known-answer-required",
            "trusted-keychain-inventory-diff-required",
        ],
        "reporting_status": "ios-keychain-redacted-inventory-not-secret-decode",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_ios_keychain_report_grade_validation_plan(
    *,
    source_path: Path,
    source_hashes: Mapping[str, str],
    table_summaries: Sequence[Mapping[str, object]],
    validation: Mapping[str, object],
    scope_profile: Mapping[str, object],
    authority_gate: Mapping[str, object],
    deep_inventory_manifest: Mapping[str, object],
) -> dict[str, object]:
    backup_root = source_path.parent
    output_root = backup_root / "ios-keychain-rapidtriage-validation"
    table_count = int(scope_profile.get("table_count") or len(table_summaries))
    protected_value_column_count = int(scope_profile.get("protected_value_column_count") or 0)
    secret_reveal_performed = bool(validation.get("secrets_extracted"))
    validation_commands = [
        _mobile_vendor_export_validation_command(
            "source-keychain-manifest",
            ["rapidtriage", "manifest", str(backup_root), "--output", str(output_root / "source-keychain-manifest.json")],
            purpose="Hash the authorized backup root and keychain database source without reading protected values.",
            expected_output=str(output_root / "source-keychain-manifest.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "ios-keychain-inventory-import",
            [
                "rapidtriage",
                "artifacts",
                str(backup_root),
                "--kind",
                "mobile-export",
                "--output",
                str(output_root / "rapidtriage-ios-keychain.json"),
            ],
            purpose="Regenerate RapidTriage redacted keychain table/column inventory rows.",
            expected_output=str(output_root / "rapidtriage-ios-keychain.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "controlled-reveal-authority-review",
            [
                "<analyst>",
                "attach-keychain-authority-keybag-and-audit-log",
                str(source_path),
            ],
            purpose="Attach lawful authority, keybag/protected-data validation, and immutable audit only if any secret reveal is performed.",
            expected_output=str(output_root / "controlled-reveal-authority-review.json"),
            trusted_tool=True,
            status="authority-required" if secret_reveal_performed else "complete-no-secret-reveal",
        ),
        _mobile_vendor_export_validation_command(
            "trusted-ios-keychain-inventory-diff",
            [
                "rapidtriage",
                "cross-tool-validate",
                "--rapid-output",
                str(output_root / "rapidtriage-ios-keychain.json"),
                "--reference-output",
                "keychain-dumper=<authorized-keychain-inventory.csv-or-json>",
                "--reference-output",
                "cellebrite=<Cellebrite-keychain-inventory.csv-or-json>",
                "--backlog-item",
                "28",
                "--source-evidence",
                str(source_path),
                "--tool-version",
                "keychain-dumper=<version>",
                "--tool-command",
                "keychain-dumper=<command>",
                "--corpus-scope",
                "<ios-keychain-version-redaction-authority-known-answer-scope>",
                "--output",
                str(output_root / "ios-keychain-trusted-diff.json"),
                "--json",
            ],
            purpose="Compare redacted table, row-count, table-class, and sensitive-column inventory against trusted keychain tooling.",
            expected_output=str(output_root / "ios-keychain-trusted-diff.json"),
            trusted_tool=True,
            status="pending-cross-tool-validate",
        ),
    ]
    evidence_slots = [
        {
            "id": "keychain-db-source-integrity",
            "label": "keychain DB SHA-256 and source identity",
            "status": "complete" if source_hashes.get("sha256") else "pending-source-hash",
            "required_before_report": True,
            "sha256": source_hashes.get("sha256", ""),
        },
        {
            "id": "read-only-table-inventory",
            "label": "keychain tables opened read-only with bounded schema/row counts",
            "status": "complete" if validation.get("opened_readonly") else "review-required",
            "required_before_report": True,
            "table_count": table_count,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
        },
        {
            "id": "redaction-policy-enforced",
            "label": "secret values not read, exported, or revealed",
            "status": "complete"
            if validation.get("values_redacted", True) and not validation.get("secrets_extracted")
            else "redaction-failed-review-required",
            "required_before_report": True,
            "values_redacted": bool(validation.get("values_redacted", True)),
            "secrets_extracted": bool(validation.get("secrets_extracted")),
            "row_values_read": False,
        },
        {
            "id": "table-class-sensitive-column-map",
            "label": "table class and sensitive/protected column inventory",
            "status": "complete" if table_count >= 0 and isinstance(scope_profile.get("table_class_counts"), Mapping) else "review-required",
            "required_before_report": True,
            "table_class_counts": dict(scope_profile.get("table_class_counts") or {}),
            "protected_value_column_count": protected_value_column_count,
            "sensitive_column_names": list(scope_profile.get("sensitive_column_names") or [])[:50],
        },
        {
            "id": "source-viewer-locator",
            "label": "source viewer locator for redacted keychain inventory",
            "status": "complete"
            if isinstance(deep_inventory_manifest.get("source_viewer_locator"), Mapping)
            else "locator-required",
            "required_before_report": True,
            "source_viewer_locator": dict(deep_inventory_manifest.get("source_viewer_locator") or {}),
        },
        {
            "id": "controlled-reveal-audit-boundary",
            "label": "lawful authority and immutable audit boundary for any secret reveal",
            "status": "authority-required" if secret_reveal_performed else "complete-no-secret-reveal",
            "required_before_report": secret_reveal_performed,
            "required_before_secret_reveal": True,
            "secret_reveal_allowed": bool(authority_gate.get("secret_reveal_allowed")),
            "audit_required_before_reveal": bool(authority_gate.get("audit_required_before_reveal", True)),
        },
        {
            "id": "trusted-keychain-inventory-diff",
            "label": "Trusted keychain parser table/count/class inventory diff",
            "status": "pending-cross-tool-validate",
            "required_before_report": True,
            "required_fields": [
                "table",
                "row_count",
                "table_class",
                "sensitive_columns",
                "protected_value_column_count",
                "redaction_policy",
            ],
        },
        {
            "id": "keybag-protected-data-known-answer",
            "label": "Keybag/protected-data class known-answer validation",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["locked class", "unlocked class", "certificate", "generic password", "internet password"],
        },
        {
            "id": "access-group-semantics-known-answer",
            "label": "Access group/account/service semantic known-answer validation",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_fields": ["agrp", "acct", "svce", "cdat", "mdat", "pdmn"],
        },
        {
            "id": "independent-ios-keychain-review",
            "label": "Independent review of keychain authority, redaction, and trusted diff procedure",
            "status": "external-review-required",
            "required_before_commercial_grade": True,
            "required_materials": ["keychain DB hash", "redacted inventory output", "trusted diff", "authority/audit log if revealed"],
        },
    ]
    ready_slots = [slot["id"] for slot in evidence_slots if str(slot.get("status", "")).startswith("complete")]
    blocker_slots = [
        slot["id"]
        for slot in evidence_slots
        if slot.get("required_before_report") and not str(slot.get("status", "")).startswith("complete")
    ]
    payload: dict[str, object] = {
        "profile_version": IOS_KEYCHAIN_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 28,
        "gap_id": "#28",
        "source_path": str(source_path.resolve()),
        "backup_root": str(backup_root.resolve()),
        "source_hashes": dict(source_hashes),
        "status": "report-validation-blocked" if blocker_slots else "ready-for-report-review",
        "commercial_grade_ready": False,
        "scope_profile": dict(scope_profile),
        "authority_gate": dict(authority_gate),
        "ios_keychain_deep_inventory_manifest_hash": optional_text(deep_inventory_manifest.get("manifest_sha256")),
        "validation_commands": validation_commands,
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slots,
        "blocking_slot_ids": blocker_slots,
        "report_claim_boundary": (
            "This plan can make redacted keychain inventory reviewable when report-required slots pass; "
            "it is not proof of passwords, tokens, certificates, private keys, access-group semantics, "
            "or protected-data class decoding without authority, keybag validation, trusted diffs, and known-answer evidence."
        ),
        "commercial_grade_blockers": list(IOS_KEYCHAIN_REPORT_GRADE_BLOCKERS),
        "operator_next_steps": [
            "Preserve and hash the original keychain database before import.",
            "Regenerate RapidTriage redacted keychain inventory rows from the authorized backup root.",
            "Run a trusted keychain inventory diff against authorized keychain tooling.",
            "Attach lawful authority, keybag/protected-data validation, and immutable audit only if any secret is revealed.",
            "Attach access-group/protected-data known-answer fixtures before commercial-grade wording.",
        ],
    }
    payload["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    return payload


def sanitize_ios_plist(payload: Mapping[str, object]) -> dict[str, object]:
    allowed = {
        "Build Version": "build_version",
        "Device Name": "device_name",
        "Display Name": "display_name",
        "GUID": "backup_guid",
        "IMEI": "imei",
        "ICCID": "iccid",
        "Last Backup Date": "last_backup_date",
        "Phone Number": "phone_number",
        "Product Name": "product_name",
        "Product Type": "product_type",
        "Product Version": "product_version",
        "Serial Number": "serial_number",
        "Target Identifier": "target_identifier",
        "Target Type": "target_type",
        "Unique Identifier": "unique_identifier",
        "SnapshotState": "snapshot_state",
        "IsFullBackup": "is_full_backup",
        "IsEncrypted": "is_encrypted",
        "Encrypted": "encrypted",
    }
    sanitized: dict[str, object] = {}
    for source_key, output_key in allowed.items():
        if source_key in payload:
            value = payload[source_key]
            if isinstance(value, (dt.datetime, dt.date)):
                sanitized[output_key] = value.isoformat()
            elif isinstance(value, bool):
                sanitized[output_key] = value
            else:
                sanitized[output_key] = optional_text(value)
    sanitized["available_key_count"] = len(payload)
    sanitized["available_keys"] = sorted(str(key) for key in payload)[:80]
    return sanitized


def build_ios_backup_parser_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    file_profile = details.get("ios_backup_file_profile") if isinstance(details.get("ios_backup_file_profile"), Mapping) else {}
    scope_profile = details.get("ios_backup_scope_profile") if isinstance(details.get("ios_backup_scope_profile"), Mapping) else {}
    root_profile = details.get("ios_backup_root_profile") if isinstance(details.get("ios_backup_root_profile"), Mapping) else {}
    root_file_profile = (
        details.get("ios_backup_root_file_profile")
        if isinstance(details.get("ios_backup_root_file_profile"), Mapping)
        else {}
    )
    keychain_scope = (
        details.get("ios_keychain_scope_profile")
        if isinstance(details.get("ios_keychain_scope_profile"), Mapping)
        else {}
    )
    authority_gate = (
        details.get("ios_keychain_authority_gate")
        if isinstance(details.get("ios_keychain_authority_gate"), Mapping)
        else {}
    )
    if artifact_type == "ios-backup-file":
        viewer = "ios-manifest-file-row"
        locator_payload = {
            "file_id": optional_text(details.get("file_id")),
            "domain": optional_text(details.get("domain")),
            "logical_path": optional_text(details.get("logical_path")),
        }
    elif artifact_type == "ios-backup-source":
        viewer = "ios-backup-source-summary"
        locator_payload = {"row_count": details.get("row_count")}
    elif artifact_type == "ios-keychain-inventory":
        viewer = "ios-keychain-table-inventory"
        locator_payload = {"table_count": keychain_scope.get("table_count")}
    else:
        viewer = "ios-plist-metadata"
        locator_payload = {"plist_name": optional_text(details.get("plist_name"))}
    manifest: dict[str, object] = {
        "manifest_version": "ios-backup-parser-manifest-v1",
        "item_number": 53,
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "qc_prep_item_number": IOS_QC_PREP_ITEM_NUMBER,
        "qc_prep_item_goal": IOS_QC_PREP_GOAL,
        "qc_prep_contract": dict(IOS_QC_PREP_CONTRACT),
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "source_viewer_locator": {
            "viewer": viewer,
            "source_path": str(source_path.resolve()),
            "source_index": source_index,
            "source_record_id": source_record_id(details, source_index),
            **locator_payload,
        },
        "manifest_row": {
            "file_id": optional_text(details.get("file_id")),
            "domain": optional_text(details.get("domain")),
            "logical_path": optional_text(details.get("logical_path")),
            "category": optional_text(file_profile.get("category")),
            "flags": details.get("flags"),
        },
        "backup_scope": {
            "manifest_row_count": scope_profile.get("manifest_row_count"),
            "domain_count": scope_profile.get("domain_count"),
            "top_domains": scope_profile.get("top_domains", []),
            "risk_flag_counts": scope_profile.get("risk_flag_counts", {}),
        },
        "backup_root": {
            "required_files_present": bool(root_profile.get("required_files_present")),
            "device_name": optional_text(root_profile.get("device_name")),
            "product_version": optional_text(root_profile.get("product_version")),
            "snapshot_state": optional_text(root_profile.get("snapshot_state")),
            "is_full_backup": bool(root_profile.get("is_full_backup")),
            "root_file_present": bool(root_file_profile.get("present")),
        },
        "keychain_inventory": {
            "table_count": keychain_scope.get("table_count"),
            "sensitive_table_names": keychain_scope.get("sensitive_table_names", []),
            "protected_value_column_count": keychain_scope.get("protected_value_column_count"),
            "secret_reveal_allowed": authority_gate.get("secret_reveal_allowed", False),
            "values_redacted": bool(validation.get("values_redacted", True)),
        },
        "lawful_key_workflow": {
            "encrypted_backup_unlocked": bool(validation.get("encrypted_backup_unlocked", False)),
            "protected_values_redacted_by_default": not bool(validation.get("secrets_extracted")),
            "controlled_reveal_required": artifact_type == "ios-keychain-inventory",
            "controlled_reveal_performed": False,
        },
        "large_data_controls": {
            "max_ios_backup_files": MAX_IOS_BACKUP_FILES,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "row_cap_recorded": True,
            "raw_values_redacted_by_default": True,
        },
        "commercial_blockers": [
            "encrypted-backup-unlock-workflow-evidence-required",
            "protected-data-class-validation-required",
            "trusted-ios-backup-known-answer-corpus-required",
            "application-db-payload-parser-validation-required",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def is_ios_backup_metadata_file(path: Path) -> bool:
    return path.name in {"Manifest.db", "Info.plist", "Status.plist"} and looks_like_ios_backup_path(path)


def is_ios_keychain_candidate(path: Path) -> bool:
    lowered = str(path).lower()
    return path.suffix.lower() in {".db", ".sqlite", ".sqlite3"} and "keychain" in lowered and looks_like_ios_backup_path(path)
