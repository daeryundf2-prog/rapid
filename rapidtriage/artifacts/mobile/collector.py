from __future__ import annotations

import contextlib
import plistlib
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path

from ...core.models import ArtifactRecord
from ...core.submission import compute_hashes
from .constants import (
    MAX_IOS_BACKUP_FILES,
    MAX_ROWS_PER_SOURCE,
    MAX_SQLITE_TABLES,
    MOBILE_EXPORT_SUFFIXES,
    PARSER_VERSION,
)
from .correlation import (
    build_mobile_correlation_summary,
)
from .detect import (
    build_mobile_analyst_review_profile,
    chat_profile_message_tables,
    detect_artifact_type,
    detect_chat_service,
    detect_source_tool,
    is_chat_app_database_candidate,
    service_family,
)
from .gates import (
    build_mobile_export_source_profile,
    build_mobile_forensic_review,
    mobile_commercial_uplift_evidence,
    mobile_core_accuracy_gates,
    mobile_native_capabilities,
    mobile_report_grade_assessment,
)
from .helpers import (
    chat_app_blockers,
    chat_app_gap_ids,
    chat_table_is_message_candidate,
    mobile_commercial_gap_ids,
    mobile_correlation_core_accuracy_gates,
    mobile_export_blockers,
    mobile_validation_matrix,
    normalize_keys,
    normalize_timestamp,
    optional_text,
    source_format_for,
    source_record_id,
    source_validation_checks,
    sqlite_columns,
    sqlite_row_count,
    sqlite_table_names,
)
from .ios import (
    build_ios_backup_deep_parser_manifest,
    build_ios_backup_parser_manifest,
    build_ios_backup_report_grade_validation_plan,
    build_ios_backup_root_profile,
    build_ios_backup_scope_profile,
    build_ios_keychain_authority_gate,
    build_ios_keychain_deep_inventory_manifest,
    build_ios_keychain_report_grade_validation_plan,
    build_ios_keychain_scope_profile,
    build_ios_keychain_table_profile,
    ios_backup_root_file_profile,
    is_ios_backup_metadata_file,
    is_ios_keychain_candidate,
    sanitize_ios_plist,
)
from .loaders import (
    load_rows,
)
from .messengers import (
    build_extended_messenger_parser_manifest,
    build_extended_messenger_report_grade_validation_plan,
    build_kakaotalk_parser_manifest,
    build_kakaotalk_report_grade_validation_plan,
    build_messenger_export_framework_manifest,
    build_signal_parser_manifest,
    build_signal_report_grade_validation_plan,
    build_telegram_parser_manifest,
    build_telegram_report_grade_validation_plan,
    build_whatsapp_parser_manifest,
    build_whatsapp_report_grade_validation_plan,
    chat_app_core_accuracy_gates,
    chat_app_issue_matrix,
    chat_app_native_capabilities,
    chat_app_report_grade_assessment,
    chat_app_review_payload,
    chat_app_scope_profile,
    chat_app_strategy_profile,
    extended_messenger_database_review_payload,
    kakaotalk_compatibility_payload,
    kakaotalk_database_review_payload,
    signal_database_review_payload,
    telegram_database_review_payload,
    whatsapp_database_review_payload,
)
from .normalize import (
    normalize_ios_backup_file,
    normalize_mobile_row,
)
from .vendor import (
    build_mobile_schema_compatibility_matrix,
    build_mobile_vendor_export_report_grade_validation_plan,
    build_mobile_vendor_import_manifest,
    build_mobile_vendor_schema_mapper_manifest,
    build_vendor_export_manifest_profile,
)


class MobileExportProvider:
    collector_kind = "mobile-export"
    name = "mobile-export-artifacts"
    description = "Cellebrite/XRY/GrayKey/AXIOM-style mobile export CSV/JSON normalization"
    target_platform = "mobile"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            if is_ios_keychain_candidate(path):
                yield collect_ios_keychain_inventory(path)
            elif is_ios_backup_metadata_file(path):
                yield from collect_ios_backup_metadata(path)
            elif is_chat_app_database_candidate(path):
                yield collect_chat_app_database_inventory(path)
            elif path.suffix.lower() in MOBILE_EXPORT_SUFFIXES:
                yield from collect_mobile_export(path)


def collect_mobile_export(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    source_tool = detect_source_tool(path)
    rows = load_rows(path)
    source_format = source_format_for(path)
    vendor_manifest_profile = build_vendor_export_manifest_profile(
        path,
        source_hashes=source_hashes,
        source_tool=source_tool,
        rows=rows,
    )
    emitted = 0
    detected_types: set[str] = set()
    detected_type_counts: dict[str, int] = {}
    normalized_details: list[Mapping[str, object]] = []
    for index, row in enumerate(rows):
        if emitted >= MAX_ROWS_PER_SOURCE:
            break
        normalized = normalize_keys(row)
        artifact_type = detect_artifact_type(normalized, path)
        if not artifact_type:
            continue
        detected_types.add(artifact_type)
        detected_type_counts[artifact_type] = detected_type_counts.get(artifact_type, 0) + 1
        emitted += 1
        details = normalize_mobile_row(artifact_type, normalized, path)
        normalized_details.append(
            {
                "artifact_type": artifact_type,
                "source_index": index,
                "source_record_id": source_record_id(details, index),
                **details,
            }
        )
        yield build_record(
            path,
            artifact_type=artifact_type,
            source_index=index,
            source_hashes=source_hashes,
            source_format=source_format,
            source_tool=source_tool,
            details=details,
        )
    if emitted:
        source_profile = build_mobile_export_source_profile(
            path=path,
            source_format=source_format,
            source_tool=source_tool,
            rows=rows,
            emitted=emitted,
            detected_types=detected_types,
            vendor_manifest_profile=vendor_manifest_profile,
        )
        mapper_manifest = build_mobile_vendor_schema_mapper_manifest(
            path=path,
            source_format=source_format,
            source_tool=source_tool,
            source_hashes=source_hashes,
            rows=rows,
            detected_type_counts=detected_type_counts,
            source_profile=source_profile,
            vendor_manifest_profile=vendor_manifest_profile,
        )
        validation_plan = build_mobile_vendor_export_report_grade_validation_plan(
            path=path,
            source_format=source_format,
            source_tool=source_tool,
            source_hashes=source_hashes,
            rows=rows,
            detected_type_counts=detected_type_counts,
            source_profile=source_profile,
            vendor_manifest_profile=vendor_manifest_profile,
            mapper_manifest=mapper_manifest,
        )
        yield build_record(
            path,
            artifact_type="mobile-export-source",
            source_index=0,
            source_hashes=source_hashes,
            source_format=source_format,
            source_tool=source_tool,
            details={
                "event_type": "export-source",
                "timestamp": "",
                "row_count": emitted,
                "input_row_count": len(rows),
                "artifact_types": sorted(detected_types),
                "coverage_status": "vendor-export-import",
                "commercial_grade_ready": False,
                "mobile_export_source_profile": source_profile,
                "mobile_vendor_schema_mapper_manifest": mapper_manifest,
                "mobile_vendor_schema_mapper_manifest_hash": mapper_manifest["manifest_sha256"],
                "mobile_vendor_export_validation_plan": validation_plan,
                "mobile_vendor_export_validation_plan_hash": validation_plan["manifest_sha256"],
                "validation_checks": source_validation_checks(
                    source_format,
                    source_tool,
                    emitted,
                    detected_types,
                    input_rows=len(rows),
                    vendor_manifest_profile=vendor_manifest_profile,
                ),
                "vendor_export_manifest_profile": vendor_manifest_profile,
                "commercial_grade_blockers": mobile_export_blockers(source_tool),
                "reporting_guidance": "Validate source export settings and original device/acquisition hashes before final reporting.",
                "legal_warning": "Import only exports produced from authorized mobile acquisitions. RapidTriage preserves row text for review but does not validate proprietary extraction fidelity.",
                "risk_flags": ["mobile-export"],
            },
        )
        yield build_record(
            path,
            artifact_type="mobile-correlation-summary",
            source_index=0,
            source_hashes=source_hashes,
            source_format=source_format,
            source_tool=source_tool,
            details=build_mobile_correlation_summary(normalized_details),
        )


def build_record(
    path: Path,
    *,
    artifact_type: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_format: str,
    source_tool: str,
    details: Mapping[str, object],
) -> ArtifactRecord:
    detail_payload = dict(details)
    detail_payload.setdefault("source_path", str(path.resolve()))
    service = optional_text(detail_payload.get("service"))
    if artifact_type in {"mobile-message", "mobile-chat-database"} and service:
        detail_payload.setdefault(
            "chat_app_strategy_profile",
            chat_app_strategy_profile(
                service,
                artifact_type=artifact_type,
                details=detail_payload,
            ),
        )
        if service == "KakaoTalk":
            detail_payload.setdefault(
                "kakaotalk_parser_manifest",
                build_kakaotalk_parser_manifest(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "kakaotalk_parser_manifest_hash",
                detail_payload["kakaotalk_parser_manifest"]["manifest_sha256"],
            )
        if service == "WhatsApp":
            detail_payload.setdefault(
                "whatsapp_parser_manifest",
                build_whatsapp_parser_manifest(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "whatsapp_parser_manifest_hash",
                detail_payload["whatsapp_parser_manifest"]["manifest_sha256"],
            )
            detail_payload.setdefault(
                "whatsapp_report_grade_validation_plan",
                build_whatsapp_report_grade_validation_plan(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "whatsapp_report_grade_validation_plan_hash",
                detail_payload["whatsapp_report_grade_validation_plan"]["manifest_sha256"],
            )
        if service == "Telegram":
            detail_payload.setdefault(
                "telegram_parser_manifest",
                build_telegram_parser_manifest(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "telegram_parser_manifest_hash",
                detail_payload["telegram_parser_manifest"]["manifest_sha256"],
            )
            detail_payload.setdefault(
                "telegram_report_grade_validation_plan",
                build_telegram_report_grade_validation_plan(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "telegram_report_grade_validation_plan_hash",
                detail_payload["telegram_report_grade_validation_plan"]["manifest_sha256"],
            )
        if service == "Signal":
            detail_payload.setdefault(
                "signal_parser_manifest",
                build_signal_parser_manifest(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "signal_parser_manifest_hash",
                detail_payload["signal_parser_manifest"]["manifest_sha256"],
            )
            detail_payload.setdefault(
                "signal_report_grade_validation_plan",
                build_signal_report_grade_validation_plan(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "signal_report_grade_validation_plan_hash",
                detail_payload["signal_report_grade_validation_plan"]["manifest_sha256"],
            )
        if chat_app_gap_ids(service) == ["#35"]:
            detail_payload.setdefault(
                "extended_messenger_parser_manifest",
                build_extended_messenger_parser_manifest(
                    artifact_type=artifact_type,
                    service=service,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "extended_messenger_parser_manifest_hash",
                detail_payload["extended_messenger_parser_manifest"]["manifest_sha256"],
            )
            detail_payload.setdefault(
                "extended_messenger_report_grade_validation_plan",
                build_extended_messenger_report_grade_validation_plan(
                    artifact_type=artifact_type,
                    service=service,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "extended_messenger_report_grade_validation_plan_hash",
                detail_payload["extended_messenger_report_grade_validation_plan"]["manifest_sha256"],
            )
        detail_payload.setdefault(
            "messenger_export_framework_manifest",
            build_messenger_export_framework_manifest(
                artifact_type=artifact_type,
                service=service,
                source_tool=source_tool,
                source_format=source_format,
                source_index=source_index,
                source_hashes=source_hashes,
                source_path=path,
                details=detail_payload,
            ),
        )
        detail_payload.setdefault(
            "messenger_export_framework_manifest_hash",
            detail_payload["messenger_export_framework_manifest"]["manifest_sha256"],
        )
        if service == "KakaoTalk":
            detail_payload.setdefault(
                "kakaotalk_report_grade_validation_plan",
                build_kakaotalk_report_grade_validation_plan(
                    artifact_type=artifact_type,
                    source_tool=source_tool,
                    source_format=source_format,
                    source_index=source_index,
                    source_hashes=source_hashes,
                    source_path=path,
                    details=detail_payload,
                ),
            )
            detail_payload.setdefault(
                "kakaotalk_report_grade_validation_plan_hash",
                detail_payload["kakaotalk_report_grade_validation_plan"]["manifest_sha256"],
            )
    gap_ids = mobile_commercial_gap_ids(artifact_type, source_tool)
    if "#26" in gap_ids:
        detail_payload.setdefault(
            "mobile_vendor_import_manifest",
            build_mobile_vendor_import_manifest(
                artifact_type=artifact_type,
                source_tool=source_tool,
                source_format=source_format,
                source_index=source_index,
                source_hashes=source_hashes,
                source_path=path,
                details=detail_payload,
            ),
        )
        detail_payload.setdefault(
            "mobile_vendor_import_manifest_hash",
            detail_payload["mobile_vendor_import_manifest"]["manifest_sha256"],
        )
    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata", "ios-keychain-inventory"}:
        detail_payload.setdefault(
            "ios_backup_parser_manifest",
            build_ios_backup_parser_manifest(
                artifact_type=artifact_type,
                source_tool=source_tool,
                source_format=source_format,
                source_index=source_index,
                source_hashes=source_hashes,
                source_path=path,
                details=detail_payload,
            ),
        )
        detail_payload.setdefault(
            "ios_backup_parser_manifest_hash",
            detail_payload["ios_backup_parser_manifest"]["manifest_sha256"],
        )
    schema_gap_ids = list(dict.fromkeys([*gap_ids, *(chat_app_gap_ids(service) if service else [])]))
    schema_compatibility_matrix = build_mobile_schema_compatibility_matrix(
        artifact_type=artifact_type,
        source_tool=source_tool,
        source_format=source_format,
        source_index=source_index,
        source_hashes=source_hashes,
        source_path=path,
        details=detail_payload,
        gap_ids=schema_gap_ids,
    )
    detail_payload.setdefault("mobile_schema_compatibility_matrix", schema_compatibility_matrix)
    detail_payload.setdefault(
        "mobile_schema_compatibility_matrix_hash",
        schema_compatibility_matrix["manifest_sha256"],
    )
    if "#26" in schema_gap_ids:
        detail_payload.setdefault("mobile_vendor_schema_compatibility_matrix", schema_compatibility_matrix)
        detail_payload.setdefault(
            "mobile_vendor_schema_compatibility_matrix_hash",
            schema_compatibility_matrix["manifest_sha256"],
        )
    if service:
        detail_payload.setdefault("messenger_schema_compatibility_matrix", schema_compatibility_matrix)
        detail_payload.setdefault(
            "messenger_schema_compatibility_matrix_hash",
            schema_compatibility_matrix["manifest_sha256"],
        )
    if any(gap_id in schema_gap_ids for gap_id in ("#27", "#28")):
        detail_payload.setdefault("mobile_backup_schema_compatibility_matrix", schema_compatibility_matrix)
        detail_payload.setdefault(
            "mobile_backup_schema_compatibility_matrix_hash",
            schema_compatibility_matrix["manifest_sha256"],
        )
    validation_checks = detail_payload.get("validation_checks")
    if not isinstance(validation_checks, Mapping):
        validation_checks = {}
    report_grade = mobile_report_grade_assessment(
        artifact_type=artifact_type,
        source_tool=source_tool,
        gap_ids=gap_ids,
        validation_checks=validation_checks,
    )
    core_accuracy_gates = [
        *mobile_core_accuracy_gates(
            artifact_type=artifact_type,
            source_tool=source_tool,
            source_format=source_format,
            source_index=source_index,
            source_hashes=source_hashes,
            details=detail_payload,
        ),
        *chat_app_core_accuracy_gates(
            artifact_type=artifact_type,
            source_tool=source_tool,
            source_format=source_format,
            source_index=source_index,
            source_hashes=source_hashes,
            details=detail_payload,
        ),
        *mobile_correlation_core_accuracy_gates(
            artifact_type=artifact_type,
            source_tool=source_tool,
            source_format=source_format,
            source_index=source_index,
            source_hashes=source_hashes,
            details=detail_payload,
        ),
    ]
    return ArtifactRecord(
        provider=MobileExportProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "mobile-export",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_format": source_format,
            "source_tool": source_tool,
            "source_index": source_index,
            "source_hashes": dict(source_hashes),
            "source_record_id": source_record_id(details, source_index),
            "commercial_grade_ready": False,
            "commercial_gap_ids": gap_ids,
            "mobile_validation_matrix": mobile_validation_matrix(
                artifact_type=artifact_type,
                source_tool=source_tool,
                validation_checks=validation_checks,
            ),
            "mobile_report_grade_assessment": report_grade,
            "commercial_uplift_evidence": mobile_commercial_uplift_evidence(
                artifact_type=artifact_type,
                source_tool=source_tool,
                source_format=source_format,
                source_index=source_index,
                source_hashes=source_hashes,
                gap_ids=gap_ids,
                validation_checks=validation_checks,
                report_grade=report_grade,
                details=detail_payload,
            ),
            "mobile_native_capabilities": mobile_native_capabilities(artifact_type),
            "core_accuracy_gates": core_accuracy_gates,
            "forensic_review": build_mobile_forensic_review(
                artifact_type=artifact_type,
                source_tool=source_tool,
                gap_ids=gap_ids,
                report_grade=report_grade,
                details=detail_payload,
            ),
            "mobile_analyst_review_profile": build_mobile_analyst_review_profile(
                artifact_type=artifact_type,
                source_tool=source_tool,
                source_format=source_format,
                source_index=source_index,
                source_hashes=source_hashes,
                gap_ids=gap_ids,
                report_grade=report_grade,
                details=detail_payload,
            ),
            **chat_app_review_payload(
                artifact_type,
                detail_payload,
                source_tool=source_tool,
                source_format=source_format,
                source_index=source_index,
                source_hashes=source_hashes,
            ),
            "legal_warning": "Use only with authorized mobile exports. Correlate with original acquisition logs and hashes before testimony.",
            **detail_payload,
        },
    )


def collect_chat_app_database_inventory(path: Path) -> ArtifactRecord:
    service = detect_chat_service({}, path) or "Mobile chat app"
    source_hashes = compute_hashes(path)
    table_summaries: list[dict[str, object]] = []
    validation: dict[str, object] = {
        "chat_database_candidate": True,
        "opened_readonly": False,
        "message_table_candidate_count": 0,
        "sample_values_redacted": True,
        "decryption_attempted": False,
        "app_schema_validated": False,
    }
    try:
        with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            validation["opened_readonly"] = True
            profile_tables = chat_profile_message_tables(service)
            for table_name in sqlite_table_names(connection)[:MAX_SQLITE_TABLES]:
                columns = sqlite_columns(connection, table_name)
                is_message_candidate = chat_table_is_message_candidate(table_name, columns, profile_tables)
                if is_message_candidate:
                    validation["message_table_candidate_count"] = int(validation["message_table_candidate_count"]) + 1
                table_summaries.append(
                    {
                        "table": table_name,
                        "row_count": sqlite_row_count(connection, table_name),
                        "columns": columns[:50],
                        "message_table_candidate": is_message_candidate,
                        "timestamp_column_candidates": [column for column in columns if "time" in column.lower() or "date" in column.lower()][:10],
                        "participant_column_candidates": [
                            column
                            for column in columns
                            if any(token in column.lower() for token in ("sender", "author", "from", "user", "contact", "jid"))
                        ][:10],
                        "media_column_candidates": [
                            column
                            for column in columns
                            if any(token in column.lower() for token in ("media", "attach", "file", "path", "thumb"))
                        ][:10],
                    }
                )
    except sqlite3.Error as error:
        validation["sqlite_error"] = str(error)[:240]
    return build_record(
        path,
        artifact_type="mobile-chat-database",
        source_index=0,
        source_hashes=source_hashes,
        source_format="sqlite-chat-database",
        source_tool="authorized-app-backup",
        details={
            "event_type": "mobile-chat-database",
            "timestamp": "",
            "service": service,
            "service_family": service_family(service),
            "database_name": path.name,
            "table_summaries": table_summaries,
            **kakaotalk_database_review_payload(service, table_summaries),
            **whatsapp_database_review_payload(service, table_summaries),
            **telegram_database_review_payload(service, table_summaries),
            **signal_database_review_payload(service, table_summaries),
            **extended_messenger_database_review_payload(service, table_summaries),
            "validation_checks": validation,
            "chat_app_gap_ids": chat_app_gap_ids(service),
            "chat_app_report_grade_assessment": chat_app_report_grade_assessment(service),
            "chat_app_native_capabilities": chat_app_native_capabilities(service),
            "chat_app_scope_profile": chat_app_scope_profile(service),
            "chat_app_issue_matrix": chat_app_issue_matrix(service, artifact_type="mobile-chat-database", app_version=""),
            **kakaotalk_compatibility_payload(service, ""),
            "commercial_grade_blockers": chat_app_blockers(service),
            "legal_warning": (
                "Authorized export/backup inventory only. RapidTriage does not bypass app encryption, decrypt protected stores, "
                "or expose secret material from chat databases."
            ),
            "risk_flags": ["mobile-chat-database", f"{service_family(service)}-candidate"],
            "reporting_guidance": "Use this row to decide which authorized export/database needs app-specific validation before report-grade conclusions.",
        },
    )


def collect_ios_backup_metadata(path: Path) -> Iterable[ArtifactRecord]:
    if path.name == "Manifest.db":
        yield from collect_ios_manifest_db(path)
        return
    yield collect_ios_plist_metadata(path)


def collect_ios_manifest_db(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    emitted = 0
    manifest_rows: list[dict[str, object]] = []
    validation = {
        "manifest_db_present": True,
        "opened_readonly": False,
        "files_table_present": False,
        "row_limit": MAX_IOS_BACKUP_FILES,
    }
    try:
        with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            validation["opened_readonly"] = True
            columns = sqlite_columns(connection, "Files")
            validation["files_table_present"] = bool(columns)
            if columns:
                selected = [name for name in ("fileID", "domain", "relativePath", "flags") if name in columns]
                if selected:
                    query = f"SELECT {', '.join(selected)} FROM Files LIMIT ?"
                    for index, row in enumerate(connection.execute(query, (MAX_IOS_BACKUP_FILES,))):
                        row_dict = {key: row[key] for key in selected}
                        manifest_rows.append(row_dict)
                        emitted += 1
                        yield build_record(
                            path,
                            artifact_type="ios-backup-file",
                            source_index=index,
                            source_hashes=source_hashes,
                            source_format="ios-manifest-db",
                            source_tool="ios-backup",
                            details=normalize_ios_backup_file(row_dict, validation),
                        )
    except sqlite3.Error as error:
        validation["sqlite_error"] = str(error)[:240]
    root_profile = build_ios_backup_root_profile(path, manifest_rows, validation)
    scope_profile = build_ios_backup_scope_profile(manifest_rows, validation)
    deep_parser_manifest = build_ios_backup_deep_parser_manifest(
        manifest_path=path,
        source_hashes=source_hashes,
        manifest_rows=manifest_rows,
        validation=validation,
        scope_profile=scope_profile,
        root_profile=root_profile,
    )
    validation["backup_root_profile_emitted"] = True
    validation["info_plist_present"] = bool(root_profile["required_files"].get("Info.plist", {}).get("present"))
    validation["status_plist_present"] = bool(root_profile["required_files"].get("Status.plist", {}).get("present"))
    validation["required_backup_files_present"] = bool(root_profile.get("required_files_present"))
    validation["ios_backup_deep_parser_manifest_emitted"] = True
    report_grade_validation_plan = build_ios_backup_report_grade_validation_plan(
        manifest_path=path,
        source_hashes=source_hashes,
        manifest_rows=manifest_rows,
        validation=validation,
        scope_profile=scope_profile,
        root_profile=root_profile,
        deep_parser_manifest=deep_parser_manifest,
    )
    yield build_record(
        path,
        artifact_type="ios-backup-source",
        source_index=0,
        source_hashes=source_hashes,
        source_format="ios-manifest-db",
        source_tool="ios-backup",
        details={
            "event_type": "ios-backup-source",
            "timestamp": "",
            "row_count": emitted,
            "ios_backup_scope_profile": scope_profile,
            "ios_backup_root_profile": root_profile,
            "ios_backup_deep_parser_manifest": deep_parser_manifest,
            "ios_backup_deep_parser_manifest_hash": deep_parser_manifest["manifest_sha256"],
            "ios_backup_report_grade_validation_plan": report_grade_validation_plan,
            "ios_backup_report_grade_validation_plan_hash": report_grade_validation_plan["manifest_sha256"],
            "validation_checks": validation,
            "commercial_grade_blockers": [
                "Requires known-answer validation across encrypted/unencrypted backup variants.",
                "Does not decrypt protected files or parse application databases in-place.",
                "Must be correlated with acquisition logs and original backup hash manifests.",
            ],
            "risk_flags": ["ios-backup-inventory"],
            "reporting_guidance": "Use as an authorized backup inventory and pivot list, not as final app-artifact testimony.",
        },
    )


def collect_ios_plist_metadata(path: Path) -> ArtifactRecord:
    source_hashes = compute_hashes(path)
    metadata: dict[str, object] = {}
    validation = {"plist_present": True, "plist_parseable": False, "secret_values_redacted": True}
    try:
        payload = plistlib.loads(path.read_bytes())
        if isinstance(payload, Mapping):
            validation["plist_parseable"] = True
            metadata = sanitize_ios_plist(payload)
    except (OSError, plistlib.InvalidFileException, ValueError):
        metadata = {}
    return build_record(
        path,
        artifact_type="ios-backup-metadata",
        source_index=0,
        source_hashes=source_hashes,
        source_format="ios-plist",
        source_tool="ios-backup",
        details={
            "event_type": "ios-backup-metadata",
            "timestamp": normalize_timestamp(metadata.get("last_backup_date", "")),
            "plist_name": path.name,
            "metadata": metadata,
            "ios_backup_root_file_profile": ios_backup_root_file_profile(path),
            "validation_checks": validation,
            "commercial_grade_blockers": [
                "Selected plist fields only; full backup/application semantic decoding is not implemented.",
                "Requires independent validation against known iOS backup fixtures before testimony.",
            ],
            "risk_flags": ["ios-backup-metadata"],
            "reporting_guidance": "Review device identifiers and backup status against the acquisition worksheet before reporting.",
        },
    )


def collect_ios_keychain_inventory(path: Path) -> ArtifactRecord:
    source_hashes = compute_hashes(path)
    table_summaries: list[dict[str, object]] = []
    validation: dict[str, object] = {
        "keychain_candidate": True,
        "opened_readonly": False,
        "secrets_extracted": False,
        "values_redacted": True,
    }
    try:
        with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
            validation["opened_readonly"] = True
            for table_name in sqlite_table_names(connection)[:MAX_SQLITE_TABLES]:
                columns = sqlite_columns(connection, table_name)[:50]
                keychain_table_profile = build_ios_keychain_table_profile(table_name, columns)
                table_summaries.append(
                    {
                        "table": table_name,
                        "row_count": sqlite_row_count(connection, table_name),
                        "columns": columns,
                        "table_class": keychain_table_profile["table_class"],
                        "sensitive_columns": keychain_table_profile["sensitive_columns"],
                        "protected_value_column_count": keychain_table_profile["protected_value_column_count"],
                        "row_sample_policy": "redacted-schema-only-no-values-read",
                    }
                )
    except sqlite3.Error as error:
        validation["sqlite_error"] = str(error)[:240]
    keychain_scope_profile = build_ios_keychain_scope_profile(table_summaries, validation)
    keychain_authority_gate = build_ios_keychain_authority_gate(table_summaries, validation)
    keychain_deep_manifest = build_ios_keychain_deep_inventory_manifest(
        source_path=path,
        source_hashes=source_hashes,
        table_summaries=table_summaries,
        validation=validation,
        scope_profile=keychain_scope_profile,
        authority_gate=keychain_authority_gate,
    )
    keychain_report_grade_validation_plan = build_ios_keychain_report_grade_validation_plan(
        source_path=path,
        source_hashes=source_hashes,
        table_summaries=table_summaries,
        validation=validation,
        scope_profile=keychain_scope_profile,
        authority_gate=keychain_authority_gate,
        deep_inventory_manifest=keychain_deep_manifest,
    )
    return build_record(
        path,
        artifact_type="ios-keychain-inventory",
        source_index=0,
        source_hashes=source_hashes,
        source_format="ios-keychain-db",
        source_tool="ios-backup",
        details={
            "event_type": "ios-keychain-inventory",
            "timestamp": "",
            "table_summaries": table_summaries,
            "ios_keychain_scope_profile": keychain_scope_profile,
            "ios_keychain_authority_gate": keychain_authority_gate,
            "ios_keychain_deep_inventory_manifest": keychain_deep_manifest,
            "ios_keychain_deep_inventory_manifest_hash": keychain_deep_manifest["manifest_sha256"],
            "ios_keychain_report_grade_validation_plan": keychain_report_grade_validation_plan,
            "ios_keychain_report_grade_validation_plan_hash": keychain_report_grade_validation_plan[
                "manifest_sha256"
            ],
            "protected_data_class_handling": {
                "status": "redacted-inventory-only",
                "default_label": "protected-data-redacted",
                "class_values_revealed": False,
                "column_values_revealed": False,
                "class_semantics_status": "requires-specialized-keybag-validation",
            },
            "controlled_reveal_audit": {
                "required_before_reveal": True,
                "reveal_performed": False,
                "audit_event_recorded": "not-applicable-no-secret-reveal",
            },
            "validation_checks": validation,
            "commercial_grade_blockers": [
                "Inventory only: RapidTriage does not decrypt or expose keychain secret values.",
                "Requires explicit legal authority and specialized validation before any protected-data analysis.",
            ],
            "legal_warning": "Do not use this row to infer passwords, tokens, or secrets. It records table/column inventory only.",
            "risk_flags": ["ios-keychain-inventory", "sensitive-artifact-redacted"],
            "reporting_guidance": "Document authorization and preserve original keychain database hash; use dedicated validated tooling for protected-data conclusions.",
        },
    )
