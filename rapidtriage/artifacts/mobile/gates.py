from __future__ import annotations
import contextlib
import csv
import datetime as dt
import hashlib
import json
import plistlib
import shlex
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from ...core.submission import compute_hashes
from ..review import build_forensic_review

from .constants import (
    FUNCTIONAL_EXPANSION_BATCH_ID,
    IOS_QC_PREP_CONTRACT,
    IOS_QC_PREP_ITEM_NUMBER,
    MAX_CHAT_DB_SAMPLE_ROWS,
    MAX_IOS_BACKUP_FILES,
    MAX_ROWS_PER_SOURCE,
    MAX_SQLITE_TABLES,
    MOBILE_NATIVE_CAPABILITIES,
    MOBILE_REPORT_GRADE_BLOCKERS,
    MOBILE_TRUSTED_DIFF_BLOCKERS,
    MOBILE_TRUSTED_TOOLS,
    PARSER_VERSION,
)
from .helpers import (
    mobile_artifact_goal,
    mobile_commercial_gap_ids,
    mobile_validation_matrix,
    normalize_keys,
    optional_text,
    source_record_id,
)
from .vendor import (
    build_vendor_schema_registry_profile,
)
from .manifests import (
    index_mobile_trusted_rows,
)


def build_mobile_export_source_profile(
    *,
    path: Path,
    source_format: str,
    source_tool: str,
    rows: Sequence[Mapping[str, object]],
    emitted: int,
    detected_types: set[str],
    vendor_manifest_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    key_counts: dict[str, int] = {}
    for row in rows[: min(len(rows), 500)]:
        for key in normalize_keys(row):
            key_counts[key] = key_counts.get(key, 0) + 1
    common_keys = [
        {"key": key, "observed_in_sample_rows": count}
        for key, count in sorted(key_counts.items(), key=lambda item: (-item[1], item[0]))[:50]
    ]
    input_rows = len(rows)
    unclassified = max(input_rows - emitted, 0)
    warnings: list[str] = []
    if unclassified:
        warnings.append(f"{unclassified} input rows were not classified into supported mobile artifact types.")
    if input_rows > MAX_ROWS_PER_SOURCE:
        warnings.append(f"Input has {input_rows} rows; per-source processing is capped at {MAX_ROWS_PER_SOURCE} emitted artifacts.")
    if source_tool == "mobile-export":
        warnings.append("Vendor tool family was inferred as generic mobile-export; attach export metadata before reporting.")
    manifest_profile = dict(vendor_manifest_profile or {})
    schema_registry_profile = build_vendor_schema_registry_profile(
        source_tool=source_tool,
        rows=rows,
        detected_types=detected_types,
        vendor_manifest_profile=manifest_profile,
    )
    return {
        "profile_version": "mobile-export-source-schema-v1",
        "source_path": str(path.resolve()),
        "source_tool": source_tool,
        "source_format": source_format,
        "input_row_count": input_rows,
        "emitted_row_count": emitted,
        "unclassified_or_skipped_row_count": unclassified,
        "detected_artifact_types": sorted(detected_types),
        "detected_artifact_type_count": len(detected_types),
        "sampled_key_count": len(key_counts),
        "common_keys": common_keys,
        "max_rows_per_source": MAX_ROWS_PER_SOURCE,
        "truncated_by_row_cap": input_rows > MAX_ROWS_PER_SOURCE,
        "schema_registry_status": "candidate-needs-vendor-version-map",
        "vendor_schema_registry_profile": schema_registry_profile,
        "vendor_export_manifest_profile": manifest_profile,
        "vendor_export_manifest_present": bool(manifest_profile.get("manifest_present")),
        "vendor_tool_version": optional_text(manifest_profile.get("vendor_tool_version")),
        "vendor_parser_version": optional_text(manifest_profile.get("parser_version")),
        "original_acquisition_hash_verified": bool(manifest_profile.get("original_acquisition_hash_present")),
        "source_hash_matches_manifest": bool(manifest_profile.get("source_hash_matches_manifest")),
        "vendor_tool_hint_present": source_tool in {"cellebrite", "xry", "graykey", "axiom"},
        "warnings": warnings,
        "reporting_status": "triage-import-not-commercial-schema-validation",
    }


def build_mobile_trusted_diff(
    number: int,
    rapid_rows: list[Mapping[str, object]],
    trusted_rows: list[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blocker = MOBILE_TRUSTED_DIFF_BLOCKERS.get(number, "mobile-trusted-diff-required")
    rapid_index = index_mobile_trusted_rows(rapid_rows)
    trusted_index = index_mobile_trusted_rows(trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in MOBILE_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        "mobile_row_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "mobile-trusted-diff-v1",
        "gap_id": f"#{number}",
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(common) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-mobile-output-as-final",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def mobile_native_capabilities(artifact_type: str) -> dict[str, object]:
    capabilities = dict(MOBILE_NATIVE_CAPABILITIES)
    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata"}:
        capabilities.update(
            {
                "ios_manifest_db_inventory": True,
                "ios_backup_file_payload_decode": False,
                "ios_backup_encryption_unlock": False,
            }
        )
    if artifact_type == "ios-keychain-inventory":
        capabilities.update(
            {
                "ios_keychain_inventory_redacted": True,
                "ios_keychain_secret_decryption": False,
                "ios_keychain_access_group_semantics": False,
            }
        )
    return capabilities


def mobile_functional_expansion_profiles(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    item_numbers: list[int],
    validation_checks: Mapping[str, object],
    details: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> list[dict[str, object]]:
    vendor_import_manifest = (
        details.get("mobile_vendor_import_manifest")
        if isinstance(details.get("mobile_vendor_import_manifest"), Mapping)
        else {}
    )
    vendor_schema_mapper_manifest = (
        details.get("mobile_vendor_schema_mapper_manifest")
        if isinstance(details.get("mobile_vendor_schema_mapper_manifest"), Mapping)
        else {}
    )
    ios_parser_manifest = (
        details.get("ios_backup_parser_manifest")
        if isinstance(details.get("ios_backup_parser_manifest"), Mapping)
        else {}
    )
    ios_deep_parser_manifest = (
        details.get("ios_backup_deep_parser_manifest")
        if isinstance(details.get("ios_backup_deep_parser_manifest"), Mapping)
        else {}
    )
    ios_validation_plan = (
        details.get("ios_backup_report_grade_validation_plan")
        if isinstance(details.get("ios_backup_report_grade_validation_plan"), Mapping)
        else {}
    )
    ios_keychain_deep_manifest = (
        details.get("ios_keychain_deep_inventory_manifest")
        if isinstance(details.get("ios_keychain_deep_inventory_manifest"), Mapping)
        else {}
    )
    ios_keychain_validation_plan = (
        details.get("ios_keychain_report_grade_validation_plan")
        if isinstance(details.get("ios_keychain_report_grade_validation_plan"), Mapping)
        else {}
    )
    vendor_manifest_hash = optional_text(vendor_import_manifest.get("manifest_sha256"))
    vendor_schema_mapper_hash = optional_text(vendor_schema_mapper_manifest.get("manifest_sha256"))
    profiles: list[dict[str, object]] = [
        {
            "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
            "item_number": 52,
            "implementation_track": "mobile-vendor-export-import",
            "status": "usable-internal-triage-not-commercial-grade",
            "source_tool": source_tool,
            "source_format": source_format,
            "source_index": source_index,
            "source_sha256": source_hashes.get("sha256", ""),
            "implemented_controls": {
                "cellebrite_xry_graykey_axiom_source_hinting": True,
                "schema_version_registry_present": bool(details.get("schema_version") or details.get("source_schema")),
                "source_row_identity_preserved": bool(details.get("source_row_id") or details.get("row_id") or source_index >= 0),
                "source_hash_preserved": bool(source_hashes.get("sha256")),
                "vendor_export_settings_verified": bool(validation_checks.get("vendor_export_settings_verified")),
                "mobile_vendor_import_manifest_hash": vendor_manifest_hash,
                "mobile_vendor_import_manifest_emitted": bool(vendor_import_manifest),
                "source_viewer_locator_emitted": isinstance(
                    vendor_import_manifest.get("source_viewer_locator"), Mapping
                ),
                "vendor_schema_registry_profile_present": bool(vendor_import_manifest.get("schema_registry")),
                "vendor_schema_mapper_manifest_hash": vendor_schema_mapper_hash,
                "vendor_schema_mapper_manifest_emitted": bool(vendor_schema_mapper_manifest),
            },
            "trusted_diff_status": str(trusted_diff.get("status") or "not-attached"),
            "failed_validation_check_ids": [
                check
                for check, failed in {
                    "vendor-export-settings-not-verified": not validation_checks.get("vendor_export_settings_verified"),
                    "vendor-schema-not-validated": not validation_checks.get("vendor_schema_validated"),
                    "mobile-vendor-import-manifest-not-emitted": not vendor_import_manifest,
                    "mobile-vendor-schema-mapper-manifest-not-emitted": not vendor_schema_mapper_manifest,
                    "trusted-vendor-export-diff-required": trusted_diff.get("status") != "pass",
                }.items()
                if failed
            ],
            "passed_validation_check_ids": [
                check
                for check, passed in {
                    "mobile-vendor-import-manifest-emitted": bool(vendor_import_manifest),
                    "mobile-vendor-source-row-locator-emitted": isinstance(
                        vendor_import_manifest.get("source_viewer_locator"), Mapping
                    ),
                    "mobile-vendor-schema-mapper-manifest-emitted": bool(vendor_schema_mapper_manifest),
                    "mobile-vendor-source-hash-preserved": bool(source_hashes.get("sha256")),
                }.items()
                if passed
            ],
            "ready_for_court_report": False,
        }
    ]
    if artifact_type.startswith("ios-") or any(number in item_numbers for number in (27, 28)):
        ios_parser_manifest = (
            details.get("ios_backup_parser_manifest")
            if isinstance(details.get("ios_backup_parser_manifest"), Mapping)
            else {}
        )
        ios_deep_parser_manifest = (
            details.get("ios_backup_deep_parser_manifest")
            if isinstance(details.get("ios_backup_deep_parser_manifest"), Mapping)
            else {}
        )
        ios_keychain_deep_manifest = (
            details.get("ios_keychain_deep_inventory_manifest")
            if isinstance(details.get("ios_keychain_deep_inventory_manifest"), Mapping)
            else {}
        )
        ios_keychain_validation_plan = (
            details.get("ios_keychain_report_grade_validation_plan")
            if isinstance(details.get("ios_keychain_report_grade_validation_plan"), Mapping)
            else {}
        )
        profiles.append(
            {
                "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
                "item_number": 53,
                "qc_prep_item_numbers": [IOS_QC_PREP_ITEM_NUMBER],
                "qc_prep_contracts": [dict(IOS_QC_PREP_CONTRACT)],
                "implementation_track": "ios-backup-keychain-parser",
                "status": "usable-internal-inventory-not-decrypted-commercial-grade",
                "implemented_controls": {
                    "manifest_db_domain_file_mapping": bool(details.get("domain") or artifact_type == "ios-backup-metadata"),
                    "info_status_plist_inventory": artifact_type == "ios-backup-metadata" or bool(details.get("plist_name")),
                    "sms_media_app_db_candidate_detection": bool(details.get("risk_flags") or details.get("database_name")),
                    "keychain_redacted_inventory": artifact_type == "ios-keychain-inventory",
                    "encrypted_backup_lawful_key_workflow_required": True,
                    "secret_values_exported": bool(validation_checks.get("secrets_extracted")),
                    "ios_backup_parser_manifest_hash": optional_text(ios_parser_manifest.get("manifest_sha256")),
                    "ios_backup_parser_manifest_emitted": bool(ios_parser_manifest),
                    "ios_backup_deep_parser_manifest_hash": optional_text(
                        ios_deep_parser_manifest.get("manifest_sha256")
                    ),
                    "ios_backup_deep_parser_manifest_emitted": bool(ios_deep_parser_manifest),
                    "ios_backup_report_grade_validation_plan_hash": optional_text(
                        ios_validation_plan.get("manifest_sha256")
                    ),
                    "ios_backup_report_grade_validation_plan_emitted": bool(ios_validation_plan),
                    "ios_keychain_deep_inventory_manifest_hash": optional_text(
                        ios_keychain_deep_manifest.get("manifest_sha256")
                    ),
                    "ios_keychain_deep_inventory_manifest_emitted": bool(ios_keychain_deep_manifest),
                    "ios_keychain_report_grade_validation_plan_hash": optional_text(
                        ios_keychain_validation_plan.get("manifest_sha256")
                    ),
                    "ios_keychain_report_grade_validation_plan_emitted": bool(ios_keychain_validation_plan),
                    "source_viewer_locator_emitted": isinstance(
                        ios_parser_manifest.get("source_viewer_locator"), Mapping
                    ),
                },
                "failed_validation_check_ids": [
                    check
                    for check, failed in {
                        "encrypted-ios-backup-not-unlocked": not validation_checks.get("encrypted_backup_unlocked", True),
                        "known-answer-ios-backup-corpus-required": not validation_checks.get("known_answer_validated"),
                        "ios-backup-parser-manifest-not-emitted": not ios_parser_manifest,
                        "ios-backup-deep-parser-manifest-not-emitted": artifact_type == "ios-backup-source"
                        and not ios_deep_parser_manifest,
                        "ios-backup-report-grade-validation-plan-not-emitted": artifact_type == "ios-backup-source"
                        and not ios_validation_plan,
                        "ios-keychain-deep-inventory-manifest-not-emitted": artifact_type == "ios-keychain-inventory"
                        and not ios_keychain_deep_manifest,
                        "ios-keychain-report-grade-validation-plan-not-emitted": artifact_type == "ios-keychain-inventory"
                        and not ios_keychain_validation_plan,
                        "keychain-secret-reveal-authority-not-attached": artifact_type == "ios-keychain-inventory"
                        and not validation_checks.get("controlled_reveal_authorized"),
                    }.items()
                    if failed
                ],
                "passed_validation_check_ids": [
                    check
                    for check, passed in {
                        "ios-backup-parser-manifest-emitted": bool(ios_parser_manifest),
                        "ios-backup-source-locator-emitted": isinstance(
                            ios_parser_manifest.get("source_viewer_locator"), Mapping
                        ),
                        "ios-backup-deep-parser-manifest-emitted": bool(ios_deep_parser_manifest),
                        "ios-backup-report-grade-validation-plan-emitted": bool(ios_validation_plan),
                        "ios-keychain-deep-inventory-manifest-emitted": bool(ios_keychain_deep_manifest),
                        "ios-keychain-report-grade-validation-plan-emitted": bool(ios_keychain_validation_plan),
                        "ios-protected-values-redacted": not validation_checks.get("secrets_extracted"),
                    }.items()
                    if passed
                ],
                "ready_for_court_report": False,
            }
        )
    if artifact_type.startswith("android-") or any(number in item_numbers for number in (29, 30)):
        profiles.append(
            {
                "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
                "item_number": 54,
                "implementation_track": "android-backup-app-data-parser",
                "status": "usable-internal-inventory-not-app-specific-commercial-grade",
                "package": optional_text(details.get("package")),
                "data_category": optional_text(details.get("data_category")),
                "implemented_controls": {
                    "sms_call_contact_browser_media_app_db_inventory": True,
                    "package_path_attribution": bool(details.get("package") or details.get("relative_path")),
                    "apk_manifest_permission_inventory": artifact_type in {"android-apk", "android-app-data"},
                    "secret_values_extracted": bool(validation_checks.get("secret_values_extracted")),
                    "encrypted_store_limitation_recorded": True,
                },
                "failed_validation_check_ids": [
                    check
                    for check, failed in {
                        "android-backup-payload-not-natively-decoded": not validation_checks.get("android_backup_payload_decoded"),
                        "app-specific-schema-not-validated": not validation_checks.get("app_schema_validated"),
                        "deleted-record-known-answer-corpus-required": not validation_checks.get("known_answer_validated"),
                    }.items()
                    if failed
                ],
                "ready_for_court_report": False,
            }
        )
    return profiles


def mobile_commercial_uplift_evidence(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    gap_ids: list[str],
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    matrix = mobile_validation_matrix(
        artifact_type=artifact_type,
        source_tool=source_tool,
        validation_checks=validation_checks,
    )
    item_numbers = sorted(
        {
            int(gap_id.lstrip("#"))
            for gap_id in gap_ids
            if gap_id.startswith("#") and gap_id.lstrip("#").isdigit() and 26 <= int(gap_id.lstrip("#")) <= 30
        }
    )
    if not item_numbers:
        item_numbers = [26]
    objectives = {
        26: "Expose vendor mobile export import evidence, source hashes, normalized row identity, and vendor-setting blockers.",
        27: "Expose iOS backup Manifest/plist evidence, domain/file mapping, and protected/encrypted backup blockers.",
        28: "Expose iOS keychain inventory evidence with redaction, authority gate, and no-secret-reveal blockers.",
        29: "Expose Android backup/app-data evidence with package attribution and encrypted-store/schema blockers.",
        30: "Expose Android APK/app package evidence with manifest, permission, DEX/native inventory, and signature-analysis blockers.",
    }
    source_refs = [
        f"source_tool:{source_tool}",
        f"source_format:{source_format}",
        f"source_index:{source_index}",
        f"source_sha256:{source_hashes.get('sha256', '')}",
        f"artifact_type:{artifact_type}",
    ]
    for key in ("service", "package", "domain", "relative_path", "database_name", "plist_name"):
        value = optional_text(details.get(key))
        if value:
            source_refs.append(f"{key}:{value}")
    passed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
    ]
    failed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
    ]
    trusted_diff = (
        details.get("mobile_trusted_diff")
        if isinstance(details.get("mobile_trusted_diff"), Mapping)
        else {"status": "not-attached", "commercial_grade_evidence": False}
    )
    source_profile = (
        details.get("mobile_export_source_profile")
        if isinstance(details.get("mobile_export_source_profile"), Mapping)
        else {}
    )
    vendor_import_manifest = (
        details.get("mobile_vendor_import_manifest")
        if isinstance(details.get("mobile_vendor_import_manifest"), Mapping)
        else {}
    )
    vendor_schema_mapper_manifest = (
        details.get("mobile_vendor_schema_mapper_manifest")
        if isinstance(details.get("mobile_vendor_schema_mapper_manifest"), Mapping)
        else {}
    )
    vendor_validation_plan = (
        details.get("mobile_vendor_export_validation_plan")
        if isinstance(details.get("mobile_vendor_export_validation_plan"), Mapping)
        else {}
    )
    ios_parser_manifest = (
        details.get("ios_backup_parser_manifest")
        if isinstance(details.get("ios_backup_parser_manifest"), Mapping)
        else {}
    )
    ios_deep_parser_manifest = (
        details.get("ios_backup_deep_parser_manifest")
        if isinstance(details.get("ios_backup_deep_parser_manifest"), Mapping)
        else {}
    )
    ios_validation_plan = (
        details.get("ios_backup_report_grade_validation_plan")
        if isinstance(details.get("ios_backup_report_grade_validation_plan"), Mapping)
        else {}
    )
    ios_keychain_deep_manifest = (
        details.get("ios_keychain_deep_inventory_manifest")
        if isinstance(details.get("ios_keychain_deep_inventory_manifest"), Mapping)
        else {}
    )
    ios_keychain_validation_plan = (
        details.get("ios_keychain_report_grade_validation_plan")
        if isinstance(details.get("ios_keychain_report_grade_validation_plan"), Mapping)
        else {}
    )
    functional_priority_profiles = mobile_functional_expansion_profiles(
        artifact_type=artifact_type,
        source_tool=source_tool,
        source_format=source_format,
        source_index=source_index,
        source_hashes=source_hashes,
        item_numbers=item_numbers,
        validation_checks=validation_checks,
        details=details,
        trusted_diff=trusted_diff,
    )
    return {
        "batch_id": "commercial-uplift-026-030",
        "item_numbers": item_numbers,
        "qc_prep_item_numbers": mobile_qc_prep_item_numbers(artifact_type, item_numbers),
        "qc_prep_contracts": mobile_qc_prep_contracts(artifact_type, item_numbers),
        "implementation_track": "mobile-and-app-import-validation",
        "objective": " ".join(objectives[number] for number in item_numbers if number in objectives),
        "reportability_decision": mobile_reportability_decision(
            artifact_type=artifact_type,
            item_numbers=item_numbers,
            source_tool=source_tool,
            source_index=source_index,
            validation_checks=validation_checks,
            report_grade=report_grade,
            failed_validation_matrix_ids=failed_validation_matrix_ids,
            details=details,
            trusted_diff=trusted_diff,
        ),
        "mobile_trusted_diff": trusted_diff,
        "functional_priority_profiles": functional_priority_profiles,
        "source_refs": source_refs,
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
            "max_ios_backup_files": MAX_IOS_BACKUP_FILES,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "max_chat_db_sample_rows": MAX_CHAT_DB_SAMPLE_ROWS,
            "source_index": source_index,
            "input_row_count": source_profile.get("input_row_count"),
            "emitted_row_count": source_profile.get("emitted_row_count"),
            "unclassified_or_skipped_row_count": source_profile.get("unclassified_or_skipped_row_count"),
            "source_schema_profile_emitted": bool(source_profile),
            "mobile_vendor_import_manifest_hash": optional_text(vendor_import_manifest.get("manifest_sha256")),
            "mobile_vendor_source_row_locator_present": isinstance(
                vendor_import_manifest.get("source_viewer_locator"), Mapping
            ),
            "mobile_vendor_schema_mapper_manifest_hash": optional_text(
                vendor_schema_mapper_manifest.get("manifest_sha256")
            ),
            "mobile_vendor_schema_mapper_source_locator_present": isinstance(
                vendor_schema_mapper_manifest.get("source_viewer_locator"), Mapping
            ),
            "mobile_vendor_export_validation_plan_hash": optional_text(
                vendor_validation_plan.get("manifest_sha256")
            ),
            "mobile_vendor_export_validation_ready_slot_count": len(
                vendor_validation_plan.get("ready_slot_ids") or []
            )
            if isinstance(vendor_validation_plan.get("ready_slot_ids"), list)
            else 0,
            "mobile_vendor_export_validation_blocking_slot_count": len(
                vendor_validation_plan.get("blocking_slot_ids") or []
            )
            if isinstance(vendor_validation_plan.get("blocking_slot_ids"), list)
            else 0,
            "ios_backup_parser_manifest_hash": optional_text(ios_parser_manifest.get("manifest_sha256")),
            "ios_backup_source_locator_present": isinstance(
                ios_parser_manifest.get("source_viewer_locator"), Mapping
            ),
            "ios_backup_deep_parser_manifest_hash": optional_text(
                ios_deep_parser_manifest.get("manifest_sha256")
            ),
            "ios_backup_deep_parser_source_locator_present": isinstance(
                ios_deep_parser_manifest.get("source_viewer_locator"), Mapping
            ),
            "ios_backup_report_grade_validation_plan_hash": optional_text(
                ios_validation_plan.get("manifest_sha256")
            ),
            "ios_backup_report_grade_validation_ready_slot_count": len(
                ios_validation_plan.get("ready_slot_ids") or []
            )
            if isinstance(ios_validation_plan.get("ready_slot_ids"), list)
            else 0,
            "ios_backup_report_grade_validation_blocking_slot_count": len(
                ios_validation_plan.get("blocking_slot_ids") or []
            )
            if isinstance(ios_validation_plan.get("blocking_slot_ids"), list)
            else 0,
            "ios_keychain_deep_inventory_manifest_hash": optional_text(
                ios_keychain_deep_manifest.get("manifest_sha256")
            ),
            "ios_keychain_deep_inventory_source_locator_present": isinstance(
                ios_keychain_deep_manifest.get("source_viewer_locator"), Mapping
            ),
            "ios_keychain_report_grade_validation_plan_hash": optional_text(
                ios_keychain_validation_plan.get("manifest_sha256")
            ),
            "ios_keychain_report_grade_validation_ready_slot_count": len(
                ios_keychain_validation_plan.get("ready_slot_ids") or []
            )
            if isinstance(ios_keychain_validation_plan.get("ready_slot_ids"), list)
            else 0,
            "ios_keychain_report_grade_validation_blocking_slot_count": len(
                ios_keychain_validation_plan.get("blocking_slot_ids") or []
            )
            if isinstance(ios_keychain_validation_plan.get("blocking_slot_ids"), list)
            else 0,
            "vendor_export_manifest_present": bool(source_profile.get("vendor_export_manifest_present")),
            "vendor_tool_version": source_profile.get("vendor_tool_version"),
            "vendor_parser_version": source_profile.get("vendor_parser_version"),
            "source_hash_matches_manifest": bool(source_profile.get("source_hash_matches_manifest")),
            "vendor_export_settings_verified": bool(validation_checks.get("vendor_export_settings_verified")),
            "original_acquisition_hash_verified": bool(validation_checks.get("original_acquisition_hash_verified")),
            "protected_values_redacted_by_default": not bool(validation_checks.get("secrets_extracted")),
            "known_answer_mobile_corpus_required": True,
        },
        "next_internal_step": "Add vendor schema/version mappers, iOS protected-data validation, Android backup payload decoding, and mobile known-answer FP/FN corpora.",
        "external_evidence_required": True,
    }


def mobile_reportability_decision(
    *,
    artifact_type: str,
    item_numbers: list[int],
    source_tool: str,
    source_index: int,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    failed_validation_matrix_ids: list[str],
    details: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers") or [] if str(item)}
    if not validation_checks.get("vendor_export_settings_verified"):
        blockers.add("vendor-export-settings-not-verified")
    if not validation_checks.get("original_acquisition_hash_verified"):
        blockers.add("original-acquisition-hash-not-verified")
    if not validation_checks.get("vendor_schema_validated"):
        blockers.add("vendor-or-app-schema-not-validated")
    if not validation_checks.get("encrypted_backup_unlocked", True):
        blockers.add("encrypted-backup-not-unlocked")
    if validation_checks.get("secrets_extracted"):
        blockers.add("secret-values-extracted-authority-review-required")
    if "known-answer-mobile-validation" in failed_validation_matrix_ids:
        blockers.add("known-answer-mobile-corpus-not-attached")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        for number in item_numbers:
            blocker = MOBILE_TRUSTED_DIFF_BLOCKERS.get(number)
            if blocker:
                blockers.add(blocker)
    allowed = {
        26: "vendor-mobile-export-triage-pivot",
        27: "ios-backup-inventory-triage-pivot",
        28: "ios-keychain-redacted-inventory-pivot",
        29: "android-app-data-inventory-triage-pivot",
        30: "android-apk-risk-inventory-triage-pivot",
    }
    primary_item = item_numbers[0] if item_numbers else 26
    decision = {
        26: "do-not-report-vendor-mobile-export-as-source-complete",
        27: "do-not-report-ios-backup-as-decrypted-complete",
        28: "do-not-report-ios-keychain-secrets-or-access-semantics",
        29: "do-not-report-android-app-data-as-decoded-content",
        30: "do-not-report-android-apk-as-malware-or-signature-validated",
    }.get(primary_item, "do-not-report-mobile-artifact-as-commercial-grade")
    return {
        "profile_version": "mobile-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}" for number in item_numbers],
        "qc_prep_item_numbers": mobile_qc_prep_item_numbers(artifact_type, item_numbers),
        "qc_prep_contracts": mobile_qc_prep_contracts(artifact_type, item_numbers),
        "decision": decision,
        "allowed_use": allowed.get(primary_item, "mobile-artifact-triage-pivot"),
        "blockers": sorted(blockers),
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "source_tool": source_tool,
        "artifact_type": artifact_type,
        "source_record_id": source_record_id(details, source_index),
        "secret_values_redacted_by_default": not bool(validation_checks.get("secrets_extracted")),
        "ready_for_court_report": False,
        "required_before_report": [
            "attach original acquisition/export hashes and vendor export settings",
            "validate parser behavior against vendor/app/schema-version known-answer corpora",
            "document deleted-record, encrypted-store, and protected-data boundaries",
            "preserve lawful authority and reviewer audit evidence for any protected data reveal",
        ],
    }


def mobile_qc_prep_item_numbers(artifact_type: str, item_numbers: Sequence[int]) -> list[int]:
    if artifact_type.startswith("ios-") or any(number in (27, 28) for number in item_numbers):
        return [IOS_QC_PREP_ITEM_NUMBER]
    return []


def mobile_qc_prep_contracts(artifact_type: str, item_numbers: Sequence[int]) -> list[dict[str, object]]:
    return [dict(IOS_QC_PREP_CONTRACT)] if mobile_qc_prep_item_numbers(artifact_type, item_numbers) else []


def mobile_core_accuracy_gates(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> list[dict[str, object]]:
    evidence_refs = [
        f"source_path:{optional_text(details.get('source_path'))}",
        f"source_tool:{source_tool}",
        f"source_format:{source_format}",
        f"source_index:{source_index}",
    ]
    if source_hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{source_hashes['sha256']}")
    vendor_manifest = details.get("mobile_vendor_import_manifest")
    if isinstance(vendor_manifest, Mapping):
        manifest_hash = optional_text(vendor_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"mobile_vendor_manifest_sha256:{manifest_hash}")
    vendor_schema_mapper = details.get("mobile_vendor_schema_mapper_manifest")
    if isinstance(vendor_schema_mapper, Mapping):
        mapper_hash = optional_text(vendor_schema_mapper.get("manifest_sha256"))
        if mapper_hash:
            evidence_refs.append(f"mobile_vendor_schema_mapper_manifest_sha256:{mapper_hash}")
    vendor_validation_plan = details.get("mobile_vendor_export_validation_plan")
    if isinstance(vendor_validation_plan, Mapping):
        plan_hash = optional_text(vendor_validation_plan.get("manifest_sha256"))
        if plan_hash:
            evidence_refs.append(f"mobile_vendor_export_validation_plan_sha256:{plan_hash}")
    schema_matrix = details.get("mobile_schema_compatibility_matrix")
    if isinstance(schema_matrix, Mapping):
        matrix_hash = optional_text(schema_matrix.get("manifest_sha256"))
        if matrix_hash:
            evidence_refs.append(f"mobile_schema_compatibility_matrix_sha256:{matrix_hash}")
    record_id = source_record_id(details, source_index)
    if record_id:
        evidence_refs.append(f"source_record_id:{record_id}")
    ios_manifest = details.get("ios_backup_parser_manifest")
    if isinstance(ios_manifest, Mapping):
        manifest_hash = optional_text(ios_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"ios_backup_manifest_sha256:{manifest_hash}")
    ios_deep_manifest = details.get("ios_backup_deep_parser_manifest")
    if isinstance(ios_deep_manifest, Mapping):
        manifest_hash = optional_text(ios_deep_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"ios_backup_deep_parser_manifest_sha256:{manifest_hash}")
    ios_validation_plan = details.get("ios_backup_report_grade_validation_plan")
    if isinstance(ios_validation_plan, Mapping):
        manifest_hash = optional_text(ios_validation_plan.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"ios_backup_report_grade_validation_plan_sha256:{manifest_hash}")
    ios_keychain_manifest = details.get("ios_keychain_deep_inventory_manifest")
    if isinstance(ios_keychain_manifest, Mapping):
        manifest_hash = optional_text(ios_keychain_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"ios_keychain_deep_inventory_manifest_sha256:{manifest_hash}")
    ios_keychain_validation_plan = details.get("ios_keychain_report_grade_validation_plan")
    if isinstance(ios_keychain_validation_plan, Mapping):
        manifest_hash = optional_text(ios_keychain_validation_plan.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"ios_keychain_report_grade_validation_plan_sha256:{manifest_hash}")

    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    trusted_diff = details.get("chat_app_trusted_diff") if isinstance(details.get("chat_app_trusted_diff"), Mapping) else {}
    trusted_diff = details.get("mobile_trusted_diff") if isinstance(details.get("mobile_trusted_diff"), Mapping) else {}
    gates: list[dict[str, object]] = []
    if "#26" in mobile_commercial_gap_ids(artifact_type, source_tool):
        satisfied = []
        if source_tool and source_format and PARSER_VERSION:
            satisfied.append("source tool/version/profile detection")
        if source_index is not None and record_id:
            satisfied.append("row count and source ID preservation")
        if "deleted_state" in details or validation.get("row_count_nonzero") or validation.get("detected_artifact_type_count"):
            satisfied.append("duplicate/deleted semantics")
        if source_hashes.get("sha256"):
            satisfied.append("source hash and acquisition linkage")
        if details.get("mobile_report_grade_assessment") or details.get("commercial_grade_blockers") or not validation.get("vendor_schema_validated", False):
            satisfied.append("schema version compatibility warning")
        if details.get("mobile_export_source_profile") or validation.get("schema_profile_emitted"):
            satisfied.append("export schema/source profile")
        if isinstance(vendor_manifest, Mapping):
            satisfied.append("mobile vendor import manifest")
            if isinstance(vendor_manifest.get("source_viewer_locator"), Mapping):
                satisfied.append("mobile vendor source row locator")
        if isinstance(vendor_schema_mapper, Mapping):
            satisfied.append("vendor schema mapper manifest")
            if isinstance(vendor_schema_mapper.get("source_viewer_locator"), Mapping):
                satisfied.append("vendor schema mapper source locator")
        if isinstance(vendor_validation_plan, Mapping):
            satisfied.append("vendor export validation plan")
            if vendor_validation_plan.get("ready_slot_ids"):
                satisfied.append("vendor export validation ready slots")
        if isinstance(schema_matrix, Mapping) and schema_matrix.get("matrix_rows"):
            satisfied.append("mobile schema compatibility matrix")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted vendor mobile export diff pass")
        gates.append(build_accuracy_gate(26, satisfied_checks=satisfied, evidence_refs=evidence_refs))

    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata"}:
        satisfied = []
        if details.get("file_id") and details.get("domain") and details.get("logical_path"):
            satisfied.append("Manifest.db domain/fileID mapping")
        if details.get("ios_backup_file_profile") or details.get("ios_backup_scope_profile"):
            satisfied.append("iOS backup scope/file profile")
        if details.get("ios_backup_root_profile") or validation.get("backup_root_profile_emitted"):
            satisfied.append("backup root integrity/status profile")
        if isinstance(ios_manifest, Mapping):
            satisfied.append("iOS backup parser manifest")
            if isinstance(ios_manifest.get("source_viewer_locator"), Mapping):
                satisfied.append("iOS backup source locator")
        if isinstance(ios_deep_manifest, Mapping):
            satisfied.append("iOS backup deep parser manifest")
            if isinstance(ios_deep_manifest.get("source_viewer_locator"), Mapping):
                satisfied.append("iOS backup deep parser source locator")
        if isinstance(ios_validation_plan, Mapping):
            satisfied.append("iOS backup report-grade validation plan")
            if ios_validation_plan.get("ready_slot_ids"):
                satisfied.append("iOS backup validation ready slots")
        if isinstance(schema_matrix, Mapping) and schema_matrix.get("matrix_rows"):
            satisfied.append("mobile schema compatibility matrix")
        if artifact_type == "ios-backup-source" and validation.get("manifest_db_present"):
            satisfied.append("Manifest.db domain/fileID mapping")
        if artifact_type == "ios-backup-metadata" and validation.get("plist_parseable"):
            satisfied.append("Info/Status plist consistency")
        if details.get("legal_warning") or details.get("commercial_grade_blockers") or not validation.get("encrypted_backup_unlocked", False):
            satisfied.append("encrypted backup authority gate")
        if "message-store-candidate" in details.get("risk_flags", []) or "structured-data-file" in details.get("risk_flags", []):
            satisfied.append("app database schema detection")
        if details.get("commercial_grade_blockers"):
            satisfied.append("deleted-record limitation warning")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted iOS backup manifest diff pass")
        gates.append(build_accuracy_gate(27, satisfied_checks=satisfied, evidence_refs=evidence_refs))

    if artifact_type == "ios-keychain-inventory":
        table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
        satisfied = []
        if validation.get("values_redacted") and not validation.get("secrets_extracted"):
            satisfied.append("secret values redacted by default")
        if details.get("ios_keychain_scope_profile"):
            satisfied.append("keychain scope/table profile")
        if details.get("protected_data_class_handling"):
            satisfied.append("protected-data class labeling")
        if details.get("legal_warning") and details.get("controlled_reveal_audit"):
            satisfied.append("authority gate before reveal/decrypt")
        authority_gate = details.get("ios_keychain_authority_gate")
        if isinstance(authority_gate, Mapping) and authority_gate.get("secret_reveal_allowed") is False:
            satisfied.append("secret reveal authority profile")
        if table_summaries or validation.get("opened_readonly"):
            satisfied.append("record count/table inventory")
        if isinstance(ios_manifest, Mapping):
            satisfied.append("iOS backup parser manifest")
            if isinstance(ios_manifest.get("source_viewer_locator"), Mapping):
                satisfied.append("iOS keychain source locator")
        if isinstance(ios_keychain_manifest, Mapping):
            satisfied.append("iOS keychain deep inventory manifest")
            if isinstance(ios_keychain_manifest.get("source_viewer_locator"), Mapping):
                satisfied.append("iOS keychain deep inventory source locator")
        if isinstance(ios_keychain_validation_plan, Mapping):
            satisfied.append("iOS keychain report-grade validation plan")
            if ios_keychain_validation_plan.get("ready_slot_ids"):
                satisfied.append("iOS keychain validation ready slots")
        if details.get("controlled_reveal_audit"):
            satisfied.append("audit log for any controlled reveal")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted iOS keychain inventory diff pass")
        gates.append(build_accuracy_gate(28, satisfied_checks=satisfied, evidence_refs=evidence_refs))

    return gates


def mobile_report_grade_assessment(
    *,
    artifact_type: str,
    source_tool: str,
    gap_ids: list[str],
    validation_checks: Mapping[str, object],
) -> dict[str, object]:
    matrix = mobile_validation_matrix(
        artifact_type=artifact_type,
        source_tool=source_tool,
        validation_checks=validation_checks,
    )
    failed = [item for item in matrix if not item["passed"]]
    return {
        "status": "validation-required",
        "commercial_gap_ids": list(gap_ids),
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "failed_check_ids": [str(item["id"]) for item in failed],
        "blockers": list(MOBILE_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Preserve original device/acquisition hashes, extraction settings, vendor parser version, and export logs.",
            "Validate important rows against the original vendor tool view and known-answer fixtures before testimony.",
        ],
    }


def build_mobile_forensic_review(
    *,
    artifact_type: str,
    source_tool: str,
    gap_ids: list[str],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    primary = [
        f"artifact_type={artifact_type}",
        f"source_tool={source_tool}",
        f"event_type={optional_text(details.get('event_type'))}",
    ]
    for key in ("service", "package", "conversation_id", "file_path", "domain", "relative_path", "plist_name"):
        value = optional_text(details.get(key))
        if value:
            primary.append(f"{key}={value}")
    return build_forensic_review(
        gap_id=gap_ids[0] if gap_ids else "#26",
        artifact_goal=mobile_artifact_goal(artifact_type),
        primary_evidence=primary,
        validation_required=True,
        report_grade_assessment=report_grade,
        blockers=MOBILE_REPORT_GRADE_BLOCKERS,
        caveats=[
            "Mobile rows are normalized from authorized exports/backups and require original acquisition/export metadata.",
            "Protected/encrypted stores and deleted-record recovery are not report-grade in this parser.",
        ],
    )
