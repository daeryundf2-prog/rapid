from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from ...core.forensic_accuracy import build_accuracy_gate
from ..review import build_forensic_review
from .constants import (
    CHAT_APP_GAP_IDS,
    CHAT_APP_NATIVE_CAPABILITIES,
    CHAT_APP_PROFILES,
    CHAT_APP_TRUSTED_DIFF_CHECKS,
    CHAT_APP_TRUSTED_TOOLS,
    EXTENDED_MESSENGER_REPORT_GRADE_BLOCKERS,
    EXTENDED_MESSENGER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    EXTENDED_MESSENGER_REVIEW_SERVICES,
    FUNCTIONAL_SOURCE_BATCH_ID,
    KAKAOTALK_BIGBANG_RELEASE_BUILD,
    KAKAOTALK_BIGBANG_RELEASE_DATE,
    KAKAOTALK_BIGBANG_VERSION,
    KAKAOTALK_REPORT_GRADE_BLOCKERS,
    KAKAOTALK_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    MAX_CHAT_DB_SAMPLE_ROWS,
    MAX_SQLITE_TABLES,
    QC_PREP_CHAT_APP_CONTRACTS,
    QC_PREP_CHAT_APP_GOALS,
    QC_PREP_CHAT_APP_ITEMS,
    SIGNAL_REPORT_GRADE_BLOCKERS,
    SIGNAL_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    TELEGRAM_REPORT_GRADE_BLOCKERS,
    TELEGRAM_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    WHATSAPP_REPORT_GRADE_BLOCKERS,
    WHATSAPP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
)
from .detect import (
    first_mobile_alias,
    service_family,
)
from .helpers import (
    chat_app_blockers,
    chat_app_gap_ids,
    classify_extended_messenger_attachment,
    classify_kakaotalk_export_attachment,
    classify_signal_attachment,
    classify_telegram_media,
    classify_whatsapp_media,
    extended_messenger_source_track,
    first_value,
    is_whatsapp_jid,
    normalized_mobile_diff_value,
    optional_text,
    source_record_id,
    stable_mobile_sha256,
    version_at_least,
    whatsapp_actor_shape,
)


def build_chat_app_trusted_diff(
    number: int,
    rapid_rows: list[Mapping[str, object]],
    trusted_rows: list[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    _, blocker = CHAT_APP_TRUSTED_DIFF_CHECKS.get(number, ("trusted messenger diff pass", "messenger-trusted-diff-required"))
    rapid_index = index_chat_app_trusted_rows(rapid_rows)
    trusted_index = index_chat_app_trusted_rows(trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in CHAT_APP_TRUSTED_TOOLS
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
                        "chat_row_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "chat-app-trusted-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-messenger-output-as-final",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def index_chat_app_trusted_rows(rows: list[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        service = normalized_mobile_diff_value(first_mobile_alias(row, "service", "app", "platform"))
        conversation_id = normalized_mobile_diff_value(first_mobile_alias(row, "conversation_id", "chat_id", "room_id", "thread_id"))
        message_id = normalized_mobile_diff_value(first_mobile_alias(row, "message_id", "msg_id", "guid", "id"))
        timestamp = normalized_mobile_diff_value(first_mobile_alias(row, "timestamp", "date", "sent_at", "created_at"))
        sender = normalized_mobile_diff_value(first_mobile_alias(row, "sender", "from", "author"))
        recipient = normalized_mobile_diff_value(first_mobile_alias(row, "recipient", "to"))
        text_hash = normalized_mobile_diff_value(first_mobile_alias(row, "message_text_sha256", "text_sha256", "body_sha256"))
        media_hash = normalized_mobile_diff_value(first_mobile_alias(row, "media_reference_sha256", "attachment_sha256", "media_sha256"))
        reaction = normalized_mobile_diff_value(first_mobile_alias(row, "reaction", "emoji", "reactions"))
        deleted_state = normalized_mobile_diff_value(first_mobile_alias(row, "deleted_state", "deleted", "is_deleted"))
        key = "|".join(
            item
            for item in (
                service,
                conversation_id,
                message_id,
                timestamp,
                sender,
                recipient,
            )
            if item
        )
        if not key:
            continue
        indexed[key] = {
            "service": service,
            "conversation_id": conversation_id,
            "message_id": message_id,
            "timestamp": timestamp,
            "sender": sender,
            "recipient": recipient,
            "message_text_sha256": text_hash,
            "media_reference_sha256": media_hash,
            "reaction": reaction,
            "deleted_state": deleted_state,
        }
    return indexed


def kakaotalk_message_review_profile(
    *,
    service: str,
    row: Mapping[str, object],
    app_version: str,
    text: str,
    media_reference: str,
    reaction: str,
    deleted_state: str,
) -> dict[str, object]:
    if service != "KakaoTalk":
        return {}
    read_state = optional_text(first_value(row, ("readstate", "readstatus", "readat", "readtime", "unreadcount")))
    message_type = optional_text(first_value(row, ("messagetype", "type", "kind", "chatlogtype")))
    attachment_name = optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename")))
    attachment_class = classify_kakaotalk_export_attachment(media_reference, attachment_name, message_type)
    compatibility = kakaotalk_compatibility_assessment(app_version)
    return {
        "profile_version": "kakaotalk-message-review-v1",
        "source_track": compatibility["strategy_profile"]["selected_track"],
        "app_version": app_version or "unknown",
        "bigbang_status": compatibility["status"],
        "message_text_present": bool(text),
        "message_text_sha256_present": bool(text),
        "attachment_metadata_present": bool(media_reference or attachment_name),
        "attachment_class": attachment_class,
        "attachment_local_bytes_verified": False,
        "reaction_present": bool(reaction),
        "read_state_present": bool(read_state),
        "deleted_state_present": bool(deleted_state),
        "message_type_present": bool(message_type),
        "review_display_mode": "chat-bubble-row-with-metadata-collapsed",
        "content_source_status": "authorized-export-row-not-native-decrypt",
        "native_database_decode_status": "not-performed-by-mobile-export-normalizer",
        "validation_status": "triage-ready-known-answer-required",
        "required_before_report": [
            "diff this row against the original KakaoTalk export or native database parser output",
            "verify KakaoTalk app version/build and BigBang compatibility against case acquisition notes",
            "verify attachment bytes/hash locally before treating media metadata as recovered media",
            "validate read/deleted/message-type semantics with versioned KakaoTalk known-answer data",
        ],
    }


def kakaotalk_database_review_payload(service: str, table_summaries: Sequence[Mapping[str, object]]) -> dict[str, object]:
    if service != "KakaoTalk":
        return {}
    table_names = [optional_text(summary.get("table")) for summary in table_summaries]
    message_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if summary.get("message_table_candidate")
    ]
    media_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(column for column in summary.get("media_column_candidates", []) or [])
    ]
    participant_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(column for column in summary.get("participant_column_candidates", []) or [])
    ]
    return {
        "kakaotalk_database_review_profile": {
            "profile_version": "kakaotalk-database-review-v1",
            "table_count": len(table_summaries),
            "message_table_candidates": [name for name in message_tables if name][:25],
            "media_table_candidates": [name for name in media_tables if name][:25],
            "participant_table_candidates": [name for name in participant_tables if name][:25],
            "chatlogs_table_present": any("chat" in name.lower() for name in table_names),
            "read_policy": "schema-row-counts-only-no-secret-values",
            "native_decode_status": "inventory-only",
            "required_before_report": [
                "attach decrypted/native KakaoTalk DB known-answer fixture before message claims",
                "validate post-BigBang appstate/key-store behavior when app version is 25.7.2 or newer",
                "diff table and row counts against a trusted KakaoTalk parser/export",
            ],
        }
    }


def build_kakaotalk_parser_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    """KakaoTalk-specific review manifest for export rows and DB inventories."""
    compatibility = (
        details.get("kakaotalk_compatibility_assessment")
        if isinstance(details.get("kakaotalk_compatibility_assessment"), Mapping)
        else kakaotalk_compatibility_assessment(optional_text(details.get("app_version")))
    )
    database_profile = (
        details.get("kakaotalk_database_review_profile")
        if isinstance(details.get("kakaotalk_database_review_profile"), Mapping)
        else {}
    )
    message_profile = (
        details.get("kakaotalk_message_review_profile")
        if isinstance(details.get("kakaotalk_message_review_profile"), Mapping)
        else {}
    )
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    row_payload = {
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "service": "KakaoTalk",
        "timestamp": optional_text(details.get("timestamp")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "conversation_title": optional_text(details.get("conversation_title")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
        "database_name": optional_text(details.get("database_name")),
    }
    selected_track = optional_text(
        compatibility.get("strategy_profile", {}).get("selected_track")
        if isinstance(compatibility.get("strategy_profile"), Mapping)
        else ""
    )
    table_inventory = [
        {
            "table": optional_text(table.get("table")) if isinstance(table, Mapping) else "",
            "row_count": table.get("row_count") if isinstance(table, Mapping) else None,
            "message_table_candidate": bool(table.get("message_table_candidate")) if isinstance(table, Mapping) else False,
            "timestamp_column_candidates": list(table.get("timestamp_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
            "participant_column_candidates": list(table.get("participant_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
            "media_column_candidates": list(table.get("media_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
        }
        for table in table_summaries[:MAX_SQLITE_TABLES]
    ]
    parser_tracks = [
        {
            "track": "authorized-export-row-normalization",
            "status": "implemented" if artifact_type == "mobile-message" else "not-applicable",
            "reportable_as": "message-row-triage-pivot",
        },
        {
            "track": "sqlite-database-inventory",
            "status": "implemented" if artifact_type == "mobile-chat-database" else "not-applicable",
            "reportable_as": "schema-and-row-count-inventory",
        },
        {
            "track": "legacy-deviceinfo-userdir-edb-decrypt",
            "status": "separate-authority-gated-pc-workflow",
            "reportable_as": "validated-decrypt-only-after-known-answer-and-trusted-diff",
        },
        {
            "track": "post-bigbang-memory-key-store-correlation",
            "status": "validation-required",
            "reportable_as": "not-message-content-complete",
        },
    ]
    manifest: dict[str, object] = {
        "manifest_version": "kakaotalk-parser-manifest-v1",
        "item_number": 31,
        "batch_id": "commercial-uplift-031-035",
        "gap_id": "#31",
        "qc_prep_item_number": 37,
        "qc_prep_item_goal": QC_PREP_CHAT_APP_GOALS[37],
        "qc_prep_contract": dict(QC_PREP_CHAT_APP_CONTRACTS[37]),
        "artifact_type": artifact_type,
        "service": "KakaoTalk",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "row_citation": {
            **row_payload,
            "row_hash": stable_mobile_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "kakaotalk-message-row" if artifact_type == "mobile-message" else "kakaotalk-database-inventory",
                "source_path": str(source_path.resolve()),
                "source_index": source_index,
                "source_record_id": source_record_id(details, source_index),
                "database_name": optional_text(details.get("database_name")),
            },
        },
        "compatibility": {
            "status": optional_text(compatibility.get("status")),
            "app_version": optional_text(compatibility.get("app_version")),
            "selected_track": selected_track,
            "legacy_method_applicable": compatibility.get("legacy_method_applicable"),
            "report_grade_ready": bool(compatibility.get("report_grade_ready")),
            "bigbang_minimum_version": optional_text(compatibility.get("bigbang_minimum_version")),
            "bigbang_release_date": optional_text(compatibility.get("bigbang_release_date")),
        },
        "parser_tracks": parser_tracks,
        "message_review": {
            "present": bool(message_profile),
            "message_text_sha256_present": bool(message_profile.get("message_text_sha256_present")),
            "attachment_metadata_present": bool(message_profile.get("attachment_metadata_present")),
            "attachment_class": optional_text(message_profile.get("attachment_class")),
            "read_state_present": bool(message_profile.get("read_state_present")),
            "deleted_state_present": bool(message_profile.get("deleted_state_present")),
            "message_type_present": bool(message_profile.get("message_type_present")),
            "content_source_status": optional_text(message_profile.get("content_source_status")),
        },
        "database_review": {
            "present": bool(database_profile),
            "table_count": database_profile.get("table_count", len(table_inventory)) if isinstance(database_profile, Mapping) else len(table_inventory),
            "message_table_candidates": list(database_profile.get("message_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "media_table_candidates": list(database_profile.get("media_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "participant_table_candidates": list(database_profile.get("participant_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "table_inventory": table_inventory,
            "native_decode_status": optional_text(database_profile.get("native_decode_status"))
            if isinstance(database_profile, Mapping)
            else "not-applicable",
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "service_detected": bool(validation.get("service_detected", True)),
            "message_id_present": bool(details.get("message_id")),
            "conversation_id_present": bool(details.get("conversation_id")),
            "app_version_present": bool(details.get("app_version")),
            "schema_version_present": bool(details.get("schema_version")),
            "attachment_bytes_verified": False,
            "trusted_export_or_native_db_diff_attached": False,
            "known_answer_corpus_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "raw_text_hash_only_by_default": True,
            "metadata_collapsed_by_default": True,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "table_inventory_count": len(table_inventory),
            "table_inventory_capped": len(table_summaries) >= MAX_SQLITE_TABLES,
            "viewer_default": "conversation-grouped-virtualized-chat-review",
        },
        "commercial_blockers": [
            "post-bigbang-kakaotalk-known-answer-corpus-required",
            "trusted-kakaotalk-export-or-native-db-diff-required",
            "schema-version-specific-parser-map-required",
            "attachment-bytes-and-deleted-record-validation-required",
            "encrypted-store-authority-workflow-required",
        ],
        "reporting_status": "kakaotalk-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_kakaotalk_report_grade_validation_plan(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    parser_manifest = (
        details.get("kakaotalk_parser_manifest")
        if isinstance(details.get("kakaotalk_parser_manifest"), Mapping)
        else {}
    )
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    database_profile = (
        details.get("kakaotalk_database_review_profile")
        if isinstance(details.get("kakaotalk_database_review_profile"), Mapping)
        else {}
    )
    compatibility = (
        details.get("kakaotalk_compatibility_assessment")
        if isinstance(details.get("kakaotalk_compatibility_assessment"), Mapping)
        else kakaotalk_compatibility_assessment(optional_text(details.get("app_version")))
    )
    row_citation = (
        parser_manifest.get("row_citation")
        if isinstance(parser_manifest.get("row_citation"), Mapping)
        else {}
    )
    source_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    issue_ids = {
        str(item.get("id"))
        for item in details.get("chat_app_issue_matrix", [])
        if isinstance(item, Mapping)
    }
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    source_sha256 = optional_text(source_hashes.get("sha256"))
    message_hash_present = bool(optional_text(details.get("message_text_sha256")))
    message_pivots_present = any(
        optional_text(details.get(key))
        for key in ("conversation_id", "conversation_title", "message_id", "sender", "recipient")
    )
    database_inventory_present = bool(database_profile) or bool(table_summaries)
    evidence_slots = [
        {
            "id": "source-export-row-integrity",
            "label": "Source export/native DB row has hashable source provenance",
            "status": "complete" if source_sha256 else "missing-source-hash",
            "blocking": not bool(source_sha256),
            "evidence_refs": [
                f"source_tool:{source_tool}",
                f"source_format:{source_format}",
                f"source_index:{source_index}",
                f"source_sha256:{source_sha256}",
            ],
        },
        {
            "id": "service-profile-row-citation",
            "label": "KakaoTalk service profile and source row citation are fixed",
            "status": "complete" if row_citation.get("row_hash") else "missing-row-citation",
            "blocking": not bool(row_citation.get("row_hash")),
            "evidence_refs": [
                f"kakaotalk_parser_manifest:{parser_manifest.get('manifest_sha256', '')}",
                f"row_hash:{row_citation.get('row_hash', '')}",
            ],
        },
        {
            "id": "message-pivot-normalization",
            "label": "Conversation/message/participant/media pivots are normalized without claiming native decrypt completeness",
            "status": "complete" if artifact_type == "mobile-message" and (message_hash_present or message_pivots_present) else "not-applicable",
            "blocking": artifact_type == "mobile-message" and not (message_hash_present or message_pivots_present),
            "evidence_refs": [
                f"artifact_type:{artifact_type}",
                f"message_text_sha256_present:{message_hash_present}",
                f"message_pivots_present:{message_pivots_present}",
            ],
        },
        {
            "id": "database-inventory-boundary",
            "label": "KakaoTalk DB candidates are inventory-only until validated native decode evidence is attached",
            "status": "complete" if artifact_type == "mobile-chat-database" and database_inventory_present else "not-applicable",
            "blocking": False,
            "evidence_refs": [
                f"database_inventory_present:{database_inventory_present}",
                f"table_summary_count:{len(table_summaries)}",
            ],
        },
        {
            "id": "bigbang-compatibility-classification",
            "label": "Legacy/post-BigBang compatibility and selected parser track are recorded",
            "status": "complete" if isinstance(compatibility.get("strategy_profile"), Mapping) else "missing-compatibility-profile",
            "blocking": not isinstance(compatibility.get("strategy_profile"), Mapping),
            "evidence_refs": [
                f"status:{compatibility.get('status', '')}",
                f"selected_track:{compatibility.get('strategy_profile', {}).get('selected_track', '') if isinstance(compatibility.get('strategy_profile'), Mapping) else ''}",
                f"post_bigbang_issue:{'kakaotalk-post-2025-08-bigbang' in issue_ids}",
            ],
        },
        {
            "id": "hash-only-text-policy",
            "label": "Message text is represented with hash/citation controls before report selection",
            "status": "complete" if parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default") else "missing-hash-only-policy",
            "blocking": not bool(parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")),
            "evidence_refs": [
                f"raw_text_hash_only_by_default:{parser_manifest.get('large_data_controls', {}).get('raw_text_hash_only_by_default', False)}",
                f"message_text_sha256_present:{message_hash_present}",
            ],
        },
        {
            "id": "source-viewer-locator",
            "label": "GUI/report can pivot back to the KakaoTalk source row or DB inventory",
            "status": "complete" if source_locator else "missing-source-viewer-locator",
            "blocking": not bool(source_locator),
            "evidence_refs": [
                f"viewer:{source_locator.get('viewer', '') if isinstance(source_locator, Mapping) else ''}",
                f"messenger_manifest:{messenger_manifest.get('manifest_sha256', '')}",
            ],
        },
        {
            "id": "trusted-kakaotalk-export-native-db-diff",
            "label": "RapidTriage KakaoTalk rows are diffed against an authorized export or validated native DB parser",
            "status": "pending-cross-tool-validate",
            "blocking": True,
            "evidence_refs": ["command:rapidtriage cross-tool-validate --backlog-item 31"],
        },
        {
            "id": "post-bigbang-known-answer-corpus",
            "label": "KakaoTalk 25.7.2 / 2025-08-13+ behavior is validated with known-answer data",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:post-BigBang KakaoTalk known-answer corpus"],
        },
        {
            "id": "schema-version-parser-map",
            "label": "Version-specific KakaoTalk export/native schema mapping is validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:KakaoTalk schema/version matrix"],
        },
        {
            "id": "encrypted-store-key-authority-boundary",
            "label": "Encrypted store or key material handling is authority-gated and never embedded as static secrets",
            "status": "authority-workflow-required",
            "blocking": True,
            "evidence_refs": ["required:case authority, key provenance, no hardcoded proprietary key"],
        },
        {
            "id": "deleted-read-state-known-answer",
            "label": "Deleted/read/message-type semantics are validated before report claims",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:deleted/read-state known-answer corpus"],
        },
        {
            "id": "attachment-byte-media-validation",
            "label": "Attachment metadata is linked to recovered local bytes and hashes before media claims",
            "status": "external-media-validation-required",
            "blocking": True,
            "evidence_refs": ["required:attachment byte/hash validation"],
        },
        {
            "id": "independent-kakaotalk-review",
            "label": "Independent reviewer signs off on KakaoTalk scope, version, decrypt limits, and report wording",
            "status": "external-review-required",
            "blocking": True,
            "evidence_refs": ["required:independent KakaoTalk validation review"],
        },
    ]
    ready_slot_ids = [
        str(slot.get("id"))
        for slot in evidence_slots
        if str(slot.get("status", "")).startswith("complete")
    ]
    blocking_slot_ids = [str(slot.get("id")) for slot in evidence_slots if slot.get("blocking")]
    plan: dict[str, object] = {
        "profile_version": KAKAOTALK_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 31,
        "gap_id": "#31",
        "status": "report-validation-blocked",
        "commercial_grade": False,
        "artifact_goal": "KakaoTalk authorized export/native DB message, media, version, and decrypt-boundary validation",
        "artifact_type": artifact_type,
        "service": "KakaoTalk",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_sha256,
        "source_record_id": source_record_id(details, source_index),
        "app_version": optional_text(details.get("app_version")),
        "schema_version": optional_text(details.get("schema_version")),
        "compatibility_status": optional_text(compatibility.get("status")),
        "selected_track": optional_text(
            compatibility.get("strategy_profile", {}).get("selected_track")
            if isinstance(compatibility.get("strategy_profile"), Mapping)
            else ""
        ),
        "validation_commands": [
            {
                "id": "source-kakaotalk-export-manifest",
                "purpose": "Freeze source export/native DB hashes and acquisition metadata",
                "command": "rapidtriage manifest <kakaotalk-export-or-db-folder> --output <case>/kakaotalk-source-manifest.json",
            },
            {
                "id": "kakaotalk-export-import",
                "purpose": "Recreate RapidTriage KakaoTalk normalized rows and DB inventory",
                "command": "rapidtriage artifacts <mobile-export> --kind mobile-export --output <case>/kakaotalk-mobile-export.json",
            },
            {
                "id": "trusted-kakaotalk-diff",
                "purpose": "Compare KakaoTalk message/DB rows with an authorized export or validated native parser output",
                "command": "rapidtriage cross-tool-validate --rapid-output <case>/kakaotalk-mobile-export.json --reference-output kakaotalk=<trusted-kakaotalk-output.json> --backlog-item 31 --json",
            },
            {
                "id": "kakaotalk-version-known-answer-run",
                "purpose": "Attach version-specific legacy/post-BigBang schema and deleted/read-state known-answer evidence",
                "command": "rapidtriage commercial-readiness --validation-package <kakaotalk-known-answer.json> --limit 31 --json",
            },
        ],
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slot_ids,
        "blocking_slot_ids": blocking_slot_ids,
        "ready_slot_count": len(ready_slot_ids),
        "blocking_slot_count": len(blocking_slot_ids),
        "commercial_grade_blockers": list(KAKAOTALK_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use KakaoTalk rows as authorized export/native inventory triage until trusted diff, version corpus, encrypted-store authority, deleted/read-state validation, media byte proof, and independent review are attached.",
    }
    plan["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def whatsapp_message_review_profile(
    *,
    service: str,
    row: Mapping[str, object],
    app_version: str,
    text: str,
    media_reference: str,
    reaction: str,
    deleted_state: str,
) -> dict[str, object]:
    if service != "WhatsApp":
        return {}
    sender = optional_text(first_value(row, ("sender", "from", "author", "remotejid", "keyremotejid")))
    recipient = optional_text(first_value(row, ("recipient", "to", "jid", "contactjid")))
    quoted_id = optional_text(first_value(row, ("quotedmessageid", "quotedrowid", "replyto", "parentmessageid")))
    read_state = optional_text(first_value(row, ("readstate", "readstatus", "status", "receipt", "ack")))
    crypt_source = optional_text(first_value(row, ("cryptversion", "backupcrypt", "backupfile", "sourcefile", "database")))
    attachment_name = optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename")))
    return {
        "profile_version": "whatsapp-message-review-v1",
        "source_track": "whatsapp-export-msgstore-crypt-validation",
        "app_version": app_version or "unknown",
        "message_text_present": bool(text),
        "message_text_sha256_present": bool(text),
        "jid_attribution_present": is_whatsapp_jid(sender) or is_whatsapp_jid(recipient),
        "sender_shape": whatsapp_actor_shape(sender),
        "recipient_shape": whatsapp_actor_shape(recipient),
        "media_metadata_present": bool(media_reference or attachment_name),
        "media_class": classify_whatsapp_media(media_reference, attachment_name),
        "media_local_bytes_verified": False,
        "reaction_present": bool(reaction),
        "quoted_message_present": bool(quoted_id),
        "read_state_present": bool(read_state),
        "deleted_state_present": bool(deleted_state),
        "crypt_source_present": bool(crypt_source),
        "crypt_key_authority_status": "not-attached",
        "msgstore_decode_status": "authorized-export-row-not-native-msgstore-decode",
        "deleted_row_recovery_status": "not-validated",
        "review_display_mode": "chat-bubble-row-with-media-and-crypt-metadata-collapsed",
        "validation_status": "triage-ready-known-answer-required",
        "required_before_report": [
            "diff this row against a trusted WhatsApp export or msgstore parser output",
            "validate JID, timestamp, ack/read, quoted-message, and deleted-state semantics against known-answer data",
            "attach lawful crypt backup key workflow before relying on encrypted msgstore contents",
            "verify media bytes/hash locally before treating media metadata as recovered media",
        ],
    }


def whatsapp_database_review_payload(service: str, table_summaries: Sequence[Mapping[str, object]]) -> dict[str, object]:
    if service != "WhatsApp":
        return {}
    table_names = [optional_text(summary.get("table")) for summary in table_summaries]
    message_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if summary.get("message_table_candidate") or optional_text(summary.get("table")).lower() in {"messages", "message"}
    ]
    jid_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any("jid" in str(column).lower() for column in summary.get("columns", []) or [])
        or optional_text(summary.get("table")).lower() in {"jid", "wa_contacts", "chat_list"}
    ]
    media_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(column for column in summary.get("media_column_candidates", []) or [])
    ]
    return {
        "whatsapp_database_review_profile": {
            "profile_version": "whatsapp-database-review-v1",
            "table_count": len(table_summaries),
            "message_table_candidates": [name for name in message_tables if name][:25],
            "jid_table_candidates": [name for name in jid_tables if name][:25],
            "media_table_candidates": [name for name in media_tables if name][:25],
            "msgstore_shape_present": any("message" in name.lower() for name in table_names),
            "wa_contacts_shape_present": any(name.lower() in {"wa_contacts", "jid", "chat_list"} for name in table_names),
            "read_policy": "schema-row-counts-only-no-secret-values",
            "crypt_key_authority_status": "not-attached",
            "deleted_row_recovery_status": "not-validated",
            "native_decode_status": "inventory-only",
            "required_before_report": [
                "attach crypt backup key authority and extraction log if encrypted backups are decoded",
                "validate msgstore/wa.db schema version with known-answer WhatsApp fixtures",
                "diff table and row counts against ALEAPP/vendor/native WhatsApp parser output",
                "validate deleted-row and media locality semantics before report-grade claims",
            ],
        }
    }


def build_whatsapp_parser_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    """WhatsApp-specific review manifest for exports and msgstore inventory."""
    message_profile = (
        details.get("whatsapp_message_review_profile")
        if isinstance(details.get("whatsapp_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("whatsapp_database_review_profile")
        if isinstance(details.get("whatsapp_database_review_profile"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    row_payload = {
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "service": "WhatsApp",
        "timestamp": optional_text(details.get("timestamp")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
        "database_name": optional_text(details.get("database_name")),
    }
    table_inventory = [
        {
            "table": optional_text(table.get("table")) if isinstance(table, Mapping) else "",
            "row_count": table.get("row_count") if isinstance(table, Mapping) else None,
            "message_table_candidate": bool(table.get("message_table_candidate")) if isinstance(table, Mapping) else False,
            "jid_column_candidates": [
                str(column)
                for column in (table.get("columns") or [])
                if isinstance(table, Mapping) and "jid" in str(column).lower()
            ][:10],
            "media_column_candidates": list(table.get("media_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
        }
        for table in table_summaries[:MAX_SQLITE_TABLES]
    ]
    manifest: dict[str, object] = {
        "manifest_version": "whatsapp-parser-manifest-v1",
        "item_number": 32,
        "batch_id": "commercial-uplift-031-035",
        "gap_id": "#32",
        "qc_prep_item_number": 38,
        "qc_prep_item_goal": QC_PREP_CHAT_APP_GOALS[38],
        "qc_prep_contract": dict(QC_PREP_CHAT_APP_CONTRACTS[38]),
        "artifact_type": artifact_type,
        "service": "WhatsApp",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "row_citation": {
            **row_payload,
            "row_hash": stable_mobile_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "whatsapp-message-row" if artifact_type == "mobile-message" else "whatsapp-msgstore-inventory",
                "source_path": str(source_path.resolve()),
                "source_index": source_index,
                "source_record_id": source_record_id(details, source_index),
                "database_name": optional_text(details.get("database_name")),
            },
        },
        "parser_tracks": [
            {
                "track": "authorized-export-row-normalization",
                "status": "implemented" if artifact_type == "mobile-message" else "not-applicable",
                "reportable_as": "message-row-triage-pivot",
            },
            {
                "track": "msgstore-wa-db-inventory",
                "status": "implemented" if artifact_type == "mobile-chat-database" else "not-applicable",
                "reportable_as": "schema-and-row-count-inventory",
            },
            {
                "track": "crypt-backup-key-workflow",
                "status": "authority-gated-validation-required",
                "reportable_as": "not-crypt-complete-without-key-evidence",
            },
            {
                "track": "deleted-row-and-media-locality-validation",
                "status": "known-answer-required",
                "reportable_as": "not-deleted-or-media-complete",
            },
        ],
        "message_review": {
            "present": bool(message_profile),
            "message_text_sha256_present": bool(message_profile.get("message_text_sha256_present")),
            "jid_attribution_present": bool(message_profile.get("jid_attribution_present")),
            "sender_shape": optional_text(message_profile.get("sender_shape")),
            "recipient_shape": optional_text(message_profile.get("recipient_shape")),
            "media_metadata_present": bool(message_profile.get("media_metadata_present")),
            "media_class": optional_text(message_profile.get("media_class")),
            "quoted_message_present": bool(message_profile.get("quoted_message_present")),
            "read_state_present": bool(message_profile.get("read_state_present")),
            "deleted_state_present": bool(message_profile.get("deleted_state_present")),
            "crypt_key_authority_status": optional_text(message_profile.get("crypt_key_authority_status")),
        },
        "database_review": {
            "present": bool(database_profile),
            "table_count": database_profile.get("table_count", len(table_inventory)) if isinstance(database_profile, Mapping) else len(table_inventory),
            "message_table_candidates": list(database_profile.get("message_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "jid_table_candidates": list(database_profile.get("jid_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "media_table_candidates": list(database_profile.get("media_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "msgstore_shape_present": bool(database_profile.get("msgstore_shape_present")) if isinstance(database_profile, Mapping) else False,
            "wa_contacts_shape_present": bool(database_profile.get("wa_contacts_shape_present")) if isinstance(database_profile, Mapping) else False,
            "native_decode_status": optional_text(database_profile.get("native_decode_status"))
            if isinstance(database_profile, Mapping)
            else "not-applicable",
            "table_inventory": table_inventory,
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "service_detected": bool(validation.get("service_detected", True)),
            "jid_attribution_present": bool(message_profile.get("jid_attribution_present") or database_profile.get("jid_table_candidates")),
            "crypt_key_authority_attached": False,
            "trusted_export_or_native_db_diff_attached": False,
            "deleted_row_known_answer_attached": False,
            "media_bytes_verified": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "raw_text_hash_only_by_default": True,
            "metadata_collapsed_by_default": True,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "table_inventory_count": len(table_inventory),
            "table_inventory_capped": len(table_summaries) >= MAX_SQLITE_TABLES,
            "viewer_default": "conversation-grouped-virtualized-chat-review",
        },
        "commercial_blockers": [
            "whatsapp-crypt-key-authority-workflow-required",
            "trusted-whatsapp-export-or-native-db-diff-required",
            "msgstore-wa-db-schema-version-known-answer-required",
            "deleted-row-and-media-locality-validation-required",
            "timezone-ack-read-state-semantics-validation-required",
        ],
        "reporting_status": "whatsapp-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_whatsapp_report_grade_validation_plan(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    parser_manifest = (
        details.get("whatsapp_parser_manifest")
        if isinstance(details.get("whatsapp_parser_manifest"), Mapping)
        else {}
    )
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    message_profile = (
        details.get("whatsapp_message_review_profile")
        if isinstance(details.get("whatsapp_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("whatsapp_database_review_profile")
        if isinstance(details.get("whatsapp_database_review_profile"), Mapping)
        else {}
    )
    row_citation = (
        parser_manifest.get("row_citation")
        if isinstance(parser_manifest.get("row_citation"), Mapping)
        else {}
    )
    source_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    source_sha256 = optional_text(source_hashes.get("sha256"))
    message_hash_present = bool(optional_text(details.get("message_text_sha256")))
    jid_or_media_present = bool(
        message_profile.get("jid_attribution_present")
        or message_profile.get("media_metadata_present")
        or optional_text(details.get("sender"))
        or optional_text(details.get("recipient"))
        or optional_text(details.get("media_reference_sha256"))
    )
    database_inventory_present = bool(database_profile) or bool(table_summaries)
    parser_track_present = bool(parser_manifest.get("parser_tracks"))
    evidence_slots = [
        {
            "id": "source-export-row-integrity",
            "label": "Source export/msgstore row has hashable source provenance",
            "status": "complete" if source_sha256 else "missing-source-hash",
            "blocking": not bool(source_sha256),
            "evidence_refs": [
                f"source_tool:{source_tool}",
                f"source_format:{source_format}",
                f"source_index:{source_index}",
                f"source_sha256:{source_sha256}",
            ],
        },
        {
            "id": "service-profile-row-citation",
            "label": "WhatsApp service profile and source row citation are fixed",
            "status": "complete" if row_citation.get("row_hash") else "missing-row-citation",
            "blocking": not bool(row_citation.get("row_hash")),
            "evidence_refs": [
                f"whatsapp_parser_manifest:{parser_manifest.get('manifest_sha256', '')}",
                f"row_hash:{row_citation.get('row_hash', '')}",
            ],
        },
        {
            "id": "message-jid-media-normalization",
            "label": "Message/JID/media pivots are normalized without claiming crypt or deleted completeness",
            "status": "complete"
            if artifact_type == "mobile-message" and (message_hash_present or jid_or_media_present)
            else "not-applicable",
            "blocking": artifact_type == "mobile-message" and not (message_hash_present or jid_or_media_present),
            "evidence_refs": [
                f"artifact_type:{artifact_type}",
                f"message_text_sha256_present:{message_hash_present}",
                f"jid_or_media_present:{jid_or_media_present}",
            ],
        },
        {
            "id": "msgstore-database-inventory-boundary",
            "label": "msgstore/wa.db candidates are inventory-only until validated native decode evidence is attached",
            "status": "complete" if artifact_type == "mobile-chat-database" and database_inventory_present else "not-applicable",
            "blocking": False,
            "evidence_refs": [
                f"database_inventory_present:{database_inventory_present}",
                f"table_summary_count:{len(table_summaries)}",
            ],
        },
        {
            "id": "crypt-export-strategy-classification",
            "label": "Export, msgstore inventory, crypt-key, and deleted/media validation tracks are recorded",
            "status": "complete" if parser_track_present else "missing-parser-track",
            "blocking": not parser_track_present,
            "evidence_refs": [
                f"parser_track_count:{len(parser_manifest.get('parser_tracks') or [])}",
                f"crypt_key_authority_status:{message_profile.get('crypt_key_authority_status') or database_profile.get('crypt_key_authority_status') or 'not-attached'}",
            ],
        },
        {
            "id": "hash-only-text-policy",
            "label": "Message text is represented with hash/citation controls before report selection",
            "status": "complete"
            if parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")
            else "missing-hash-only-policy",
            "blocking": not bool(parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")),
            "evidence_refs": [
                f"raw_text_hash_only_by_default:{parser_manifest.get('large_data_controls', {}).get('raw_text_hash_only_by_default', False)}",
                f"message_text_sha256_present:{message_hash_present}",
            ],
        },
        {
            "id": "source-viewer-locator",
            "label": "GUI/report can pivot back to the WhatsApp source row or msgstore inventory",
            "status": "complete" if source_locator else "missing-source-viewer-locator",
            "blocking": not bool(source_locator),
            "evidence_refs": [
                f"viewer:{source_locator.get('viewer', '') if isinstance(source_locator, Mapping) else ''}",
                f"messenger_manifest:{messenger_manifest.get('manifest_sha256', '')}",
            ],
        },
        {
            "id": "trusted-whatsapp-export-native-db-diff",
            "label": "RapidTriage WhatsApp rows are diffed against authorized export/msgstore output",
            "status": "pending-cross-tool-validate",
            "blocking": True,
            "evidence_refs": ["command:rapidtriage cross-tool-validate --backlog-item 32"],
        },
        {
            "id": "crypt-backup-key-authority-workflow",
            "label": "crypt* backup or SQLCipher key handling is authority-gated and audited",
            "status": "authority-workflow-required",
            "blocking": True,
            "evidence_refs": ["required:lawful key provenance, no raw key exposure, controlled reveal audit"],
        },
        {
            "id": "msgstore-wa-db-schema-version-known-answer",
            "label": "msgstore.db and wa.db schema versions are validated with known-answer data",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:WhatsApp schema/version matrix"],
        },
        {
            "id": "deleted-row-known-answer",
            "label": "Deleted row, quoted message, and recovery semantics are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:deleted-row known-answer corpus"],
        },
        {
            "id": "contact-call-media-recovery-validation",
            "label": "Contacts, calls, media rows, and export/msgstore joins are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:contact/call/media known-answer corpus"],
        },
        {
            "id": "timezone-ack-read-state-semantics",
            "label": "Timestamp, timezone, ack, delivery, and read-state semantics are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:timestamp/ack/read-state fixture matrix"],
        },
        {
            "id": "attachment-byte-media-validation",
            "label": "Media metadata is linked to recovered local bytes and hashes before media claims",
            "status": "external-media-validation-required",
            "blocking": True,
            "evidence_refs": ["required:attachment byte/hash validation"],
        },
        {
            "id": "independent-whatsapp-review",
            "label": "Independent reviewer signs off on WhatsApp scope, crypt limits, schema version, and report wording",
            "status": "external-review-required",
            "blocking": True,
            "evidence_refs": ["required:independent WhatsApp validation review"],
        },
    ]
    ready_slot_ids = [
        str(slot.get("id"))
        for slot in evidence_slots
        if str(slot.get("status", "")).startswith("complete")
    ]
    blocking_slot_ids = [str(slot.get("id")) for slot in evidence_slots if slot.get("blocking")]
    plan: dict[str, object] = {
        "profile_version": WHATSAPP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 32,
        "gap_id": "#32",
        "status": "report-validation-blocked",
        "commercial_grade": False,
        "artifact_goal": "WhatsApp authorized export/msgstore message, contact, call, media, crypt, and deleted-row validation",
        "artifact_type": artifact_type,
        "service": "WhatsApp",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_sha256,
        "source_record_id": source_record_id(details, source_index),
        "app_version": optional_text(details.get("app_version")),
        "schema_version": optional_text(details.get("schema_version")),
        "database_name": optional_text(details.get("database_name")),
        "validation_commands": [
            {
                "id": "source-whatsapp-export-manifest",
                "purpose": "Freeze source export/msgstore hashes and acquisition metadata",
                "command": "rapidtriage manifest <whatsapp-export-or-db-folder> --output <case>/whatsapp-source-manifest.json",
            },
            {
                "id": "whatsapp-export-import",
                "purpose": "Recreate RapidTriage WhatsApp normalized rows and msgstore inventory",
                "command": "rapidtriage artifacts <mobile-export> --kind mobile-export --output <case>/whatsapp-mobile-export.json",
            },
            {
                "id": "trusted-whatsapp-diff",
                "purpose": "Compare WhatsApp message/DB rows with authorized export or validated native parser output",
                "command": "rapidtriage cross-tool-validate --rapid-output <case>/whatsapp-mobile-export.json --reference-output whatsapp=<trusted-whatsapp-output.json> --backlog-item 32 --json",
            },
            {
                "id": "whatsapp-crypt-authority-review",
                "purpose": "Attach lawful key provenance and controlled-reveal audit evidence before crypt backup claims",
                "command": "rapidtriage forensic-validation-pack --case <case> --artifact whatsapp-crypt-authority --json",
            },
            {
                "id": "whatsapp-version-known-answer-run",
                "purpose": "Attach schema, deleted-row, ack/read, and media-byte known-answer evidence",
                "command": "rapidtriage commercial-readiness --validation-package <whatsapp-known-answer.json> --limit 32 --json",
            },
        ],
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slot_ids,
        "blocking_slot_ids": blocking_slot_ids,
        "ready_slot_count": len(ready_slot_ids),
        "blocking_slot_count": len(blocking_slot_ids),
        "commercial_grade_blockers": list(WHATSAPP_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use WhatsApp rows as authorized export/msgstore triage until trusted diff, lawful crypt authority, schema corpus, deleted/read-state validation, media byte proof, and independent review are attached.",
    }
    plan["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def telegram_message_review_profile(
    *,
    service: str,
    row: Mapping[str, object],
    app_version: str,
    text: str,
    media_reference: str,
    reaction: str,
    deleted_state: str,
) -> dict[str, object]:
    if service != "Telegram":
        return {}
    account_id = optional_text(first_value(row, ("accountid", "userid", "user_id", "ownerid", "profileid")))
    dialog_id = optional_text(first_value(row, ("dialogid", "chatid", "conversationid", "peerid", "channelid", "threadid")))
    author = optional_text(first_value(row, ("author", "sender", "from", "username")))
    attachment_name = optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename")))
    edit_state = optional_text(first_value(row, ("edited", "editedat", "updated", "editdate")))
    secret_state = optional_text(first_value(row, ("secretchat", "issecret", "ttl", "selfdestruct", "ephemeral")))
    source_hint = optional_text(first_value(row, ("sourcefile", "database", "exportpath", "cachepath", "path")))
    return {
        "profile_version": "telegram-message-review-v1",
        "source_track": "telegram-export-cache-account-attribution",
        "app_version": app_version or "unknown",
        "message_text_present": bool(text),
        "message_text_sha256_present": bool(text),
        "account_or_dialog_attribution_present": bool(account_id or dialog_id or author),
        "account_id_present": bool(account_id),
        "dialog_id_present": bool(dialog_id),
        "author_present": bool(author),
        "media_cache_metadata_present": bool(media_reference or attachment_name),
        "media_class": classify_telegram_media(media_reference, attachment_name),
        "media_local_bytes_verified": False,
        "reaction_present": bool(reaction),
        "edited_state_present": bool(edit_state),
        "deleted_state_present": bool(deleted_state),
        "secret_or_ephemeral_hint_present": bool(secret_state),
        "source_hint_present": bool(source_hint),
        "local_store_decryption_status": "not-performed",
        "cache_recovery_status": "metadata-only-not-recovered",
        "secret_chat_reportability": "not-reportable-without-known-answer-validation",
        "review_display_mode": "chat-bubble-row-with-account-cache-metadata-collapsed",
        "validation_status": "triage-ready-known-answer-required",
        "required_before_report": [
            "diff this row against a trusted Telegram export/native parser output",
            "validate account, dialog, peer, edited, deleted, and secret-chat semantics with known-answer data",
            "verify cache/media bytes locally before treating media metadata as recovered media",
            "document whether the source is official export JSON, mobile app database, desktop tdata, or cache-only evidence",
        ],
    }


def telegram_database_review_payload(service: str, table_summaries: Sequence[Mapping[str, object]]) -> dict[str, object]:
    if service != "Telegram":
        return {}
    table_names = [optional_text(summary.get("table")) for summary in table_summaries]
    message_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if summary.get("message_table_candidate")
        or optional_text(summary.get("table")).lower() in {"messages", "message", "dialogs", "chats"}
    ]
    account_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(token in str(column).lower() for column in summary.get("columns", []) or [] for token in ("user", "peer", "account", "dialog"))
    ]
    media_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(column for column in summary.get("media_column_candidates", []) or [])
        or optional_text(summary.get("table")).lower() in {"media", "media_v2", "files", "cache"}
    ]
    return {
        "telegram_database_review_profile": {
            "profile_version": "telegram-database-review-v1",
            "table_count": len(table_summaries),
            "message_table_candidates": [name for name in message_tables if name][:25],
            "account_or_peer_table_candidates": [name for name in account_tables if name][:25],
            "media_cache_table_candidates": [name for name in media_tables if name][:25],
            "dialog_shape_present": any(name.lower() in {"dialogs", "chats"} for name in table_names),
            "media_cache_shape_present": bool(media_tables),
            "read_policy": "schema-row-counts-only-no-secret-values",
            "local_store_decryption_status": "not-performed",
            "secret_chat_semantics_status": "not-validated",
            "cache_recovery_status": "metadata-only",
            "native_decode_status": "inventory-only",
            "required_before_report": [
                "identify official export, mobile DB, desktop tdata, or cache-only source before conclusions",
                "validate message/dialog/media schema version against known-answer Telegram fixtures",
                "diff table and row counts against a trusted Telegram parser/export",
                "validate secret-chat, edited/deleted, and cache/media locality semantics before report-grade claims",
            ],
        }
    }


def build_telegram_parser_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    """Telegram-specific review manifest for export, cache, and DB inventory."""
    message_profile = (
        details.get("telegram_message_review_profile")
        if isinstance(details.get("telegram_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("telegram_database_review_profile")
        if isinstance(details.get("telegram_database_review_profile"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    row_payload = {
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "service": "Telegram",
        "timestamp": optional_text(details.get("timestamp")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "conversation_title": optional_text(details.get("conversation_title")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
        "database_name": optional_text(details.get("database_name")),
    }
    table_inventory = [
        {
            "table": optional_text(table.get("table")) if isinstance(table, Mapping) else "",
            "row_count": table.get("row_count") if isinstance(table, Mapping) else None,
            "message_table_candidate": bool(table.get("message_table_candidate")) if isinstance(table, Mapping) else False,
            "account_or_peer_column_candidates": [
                str(column)
                for column in (table.get("columns") or [])
                if isinstance(table, Mapping)
                and any(token in str(column).lower() for token in ("user", "peer", "account", "dialog"))
            ][:10],
            "media_column_candidates": list(table.get("media_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
        }
        for table in table_summaries[:MAX_SQLITE_TABLES]
    ]
    manifest: dict[str, object] = {
        "manifest_version": "telegram-parser-manifest-v1",
        "item_number": 33,
        "batch_id": "commercial-uplift-031-035",
        "gap_id": "#33",
        "qc_prep_item_number": 39,
        "qc_prep_item_goal": QC_PREP_CHAT_APP_GOALS[39],
        "qc_prep_contract": dict(QC_PREP_CHAT_APP_CONTRACTS[39]),
        "artifact_type": artifact_type,
        "service": "Telegram",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "row_citation": {
            **row_payload,
            "row_hash": stable_mobile_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "telegram-message-row" if artifact_type == "mobile-message" else "telegram-database-cache-inventory",
                "source_path": str(source_path.resolve()),
                "source_index": source_index,
                "source_record_id": source_record_id(details, source_index),
                "database_name": optional_text(details.get("database_name")),
            },
        },
        "parser_tracks": [
            {
                "track": "official-export-json-normalization",
                "status": "implemented" if artifact_type == "mobile-message" else "not-applicable",
                "reportable_as": "message-row-triage-pivot",
            },
            {
                "track": "cache-or-database-inventory",
                "status": "implemented" if artifact_type == "mobile-chat-database" else "not-applicable",
                "reportable_as": "schema-and-row-count-inventory",
            },
            {
                "track": "desktop-tdata-local-store-decode",
                "status": "encrypted-local-store-validation-required",
                "reportable_as": "not-local-store-complete",
            },
            {
                "track": "secret-chat-deleted-cache-recovery",
                "status": "known-answer-required",
                "reportable_as": "not-secret-chat-or-deleted-complete",
            },
        ],
        "message_review": {
            "present": bool(message_profile),
            "message_text_sha256_present": bool(message_profile.get("message_text_sha256_present")),
            "account_or_dialog_attribution_present": bool(message_profile.get("account_or_dialog_attribution_present")),
            "account_id_present": bool(message_profile.get("account_id_present")),
            "dialog_id_present": bool(message_profile.get("dialog_id_present")),
            "author_present": bool(message_profile.get("author_present")),
            "media_cache_metadata_present": bool(message_profile.get("media_cache_metadata_present")),
            "media_class": optional_text(message_profile.get("media_class")),
            "edited_state_present": bool(message_profile.get("edited_state_present")),
            "deleted_state_present": bool(message_profile.get("deleted_state_present")),
            "secret_or_ephemeral_hint_present": bool(message_profile.get("secret_or_ephemeral_hint_present")),
            "local_store_decryption_status": optional_text(message_profile.get("local_store_decryption_status")),
        },
        "database_review": {
            "present": bool(database_profile),
            "table_count": database_profile.get("table_count", len(table_inventory)) if isinstance(database_profile, Mapping) else len(table_inventory),
            "message_table_candidates": list(database_profile.get("message_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "account_or_peer_table_candidates": list(database_profile.get("account_or_peer_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "media_cache_table_candidates": list(database_profile.get("media_cache_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "dialog_shape_present": bool(database_profile.get("dialog_shape_present")) if isinstance(database_profile, Mapping) else False,
            "media_cache_shape_present": bool(database_profile.get("media_cache_shape_present")) if isinstance(database_profile, Mapping) else False,
            "native_decode_status": optional_text(database_profile.get("native_decode_status"))
            if isinstance(database_profile, Mapping)
            else "not-applicable",
            "table_inventory": table_inventory,
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "service_detected": bool(validation.get("service_detected", True)),
            "account_or_dialog_attribution_present": bool(
                message_profile.get("account_or_dialog_attribution_present")
                or database_profile.get("account_or_peer_table_candidates")
            ),
            "local_store_decryption_complete": False,
            "trusted_export_or_native_db_diff_attached": False,
            "secret_chat_deleted_known_answer_attached": False,
            "cache_media_bytes_verified": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "raw_text_hash_only_by_default": True,
            "metadata_collapsed_by_default": True,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "table_inventory_count": len(table_inventory),
            "table_inventory_capped": len(table_summaries) >= MAX_SQLITE_TABLES,
            "viewer_default": "conversation-grouped-virtualized-chat-review",
        },
        "commercial_blockers": [
            "telegram-local-store-decryption-validation-required",
            "trusted-telegram-export-or-native-db-diff-required",
            "account-dialog-peer-attribution-known-answer-required",
            "secret-chat-edited-deleted-semantics-validation-required",
            "cache-media-locality-validation-required",
        ],
        "reporting_status": "telegram-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_telegram_report_grade_validation_plan(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    parser_manifest = (
        details.get("telegram_parser_manifest")
        if isinstance(details.get("telegram_parser_manifest"), Mapping)
        else {}
    )
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    message_profile = (
        details.get("telegram_message_review_profile")
        if isinstance(details.get("telegram_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("telegram_database_review_profile")
        if isinstance(details.get("telegram_database_review_profile"), Mapping)
        else {}
    )
    row_citation = (
        parser_manifest.get("row_citation")
        if isinstance(parser_manifest.get("row_citation"), Mapping)
        else {}
    )
    source_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    source_sha256 = optional_text(source_hashes.get("sha256"))
    message_hash_present = bool(optional_text(details.get("message_text_sha256")))
    account_dialog_or_media_present = bool(
        message_profile.get("account_or_dialog_attribution_present")
        or message_profile.get("dialog_id_present")
        or message_profile.get("author_present")
        or message_profile.get("media_cache_metadata_present")
        or optional_text(details.get("conversation_id"))
        or optional_text(details.get("sender"))
        or optional_text(details.get("media_reference_sha256"))
    )
    database_inventory_present = bool(database_profile) or bool(table_summaries)
    parser_track_present = bool(parser_manifest.get("parser_tracks"))
    evidence_slots = [
        {
            "id": "source-export-cache-row-integrity",
            "label": "Source Telegram export/cache/database row has hashable provenance",
            "status": "complete" if source_sha256 else "missing-source-hash",
            "blocking": not bool(source_sha256),
            "evidence_refs": [
                f"source_tool:{source_tool}",
                f"source_format:{source_format}",
                f"source_index:{source_index}",
                f"source_sha256:{source_sha256}",
            ],
        },
        {
            "id": "service-profile-row-citation",
            "label": "Telegram service profile and source row citation are fixed",
            "status": "complete" if row_citation.get("row_hash") else "missing-row-citation",
            "blocking": not bool(row_citation.get("row_hash")),
            "evidence_refs": [
                f"telegram_parser_manifest:{parser_manifest.get('manifest_sha256', '')}",
                f"row_hash:{row_citation.get('row_hash', '')}",
            ],
        },
        {
            "id": "message-account-dialog-media-normalization",
            "label": "Message/account/dialog/media-cache pivots are normalized without local-store completeness claims",
            "status": "complete"
            if artifact_type == "mobile-message" and (message_hash_present or account_dialog_or_media_present)
            else "not-applicable",
            "blocking": artifact_type == "mobile-message" and not (message_hash_present or account_dialog_or_media_present),
            "evidence_refs": [
                f"artifact_type:{artifact_type}",
                f"message_text_sha256_present:{message_hash_present}",
                f"account_dialog_or_media_present:{account_dialog_or_media_present}",
            ],
        },
        {
            "id": "telegram-database-cache-inventory-boundary",
            "label": "Telegram DB/cache candidates are inventory-only until native decode evidence is attached",
            "status": "complete" if artifact_type == "mobile-chat-database" and database_inventory_present else "not-applicable",
            "blocking": False,
            "evidence_refs": [
                f"database_inventory_present:{database_inventory_present}",
                f"table_summary_count:{len(table_summaries)}",
            ],
        },
        {
            "id": "export-cache-strategy-classification",
            "label": "Export, cache/DB inventory, local-store, and secret/deleted validation tracks are recorded",
            "status": "complete" if parser_track_present else "missing-parser-track",
            "blocking": not parser_track_present,
            "evidence_refs": [
                f"parser_track_count:{len(parser_manifest.get('parser_tracks') or [])}",
                f"local_store_decryption_status:{message_profile.get('local_store_decryption_status') or database_profile.get('native_decode_status') or 'not-performed'}",
            ],
        },
        {
            "id": "hash-only-text-policy",
            "label": "Message text is represented with hash/citation controls before report selection",
            "status": "complete"
            if parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")
            else "missing-hash-only-policy",
            "blocking": not bool(parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")),
            "evidence_refs": [
                f"raw_text_hash_only_by_default:{parser_manifest.get('large_data_controls', {}).get('raw_text_hash_only_by_default', False)}",
                f"message_text_sha256_present:{message_hash_present}",
            ],
        },
        {
            "id": "source-viewer-locator",
            "label": "GUI/report can pivot back to the Telegram source row or cache inventory",
            "status": "complete" if source_locator else "missing-source-viewer-locator",
            "blocking": not bool(source_locator),
            "evidence_refs": [
                f"viewer:{source_locator.get('viewer', '') if isinstance(source_locator, Mapping) else ''}",
                f"messenger_manifest:{messenger_manifest.get('manifest_sha256', '')}",
            ],
        },
        {
            "id": "trusted-telegram-export-native-db-diff",
            "label": "RapidTriage Telegram rows are diffed against authorized export/native DB output",
            "status": "pending-cross-tool-validate",
            "blocking": True,
            "evidence_refs": ["command:rapidtriage cross-tool-validate --backlog-item 33"],
        },
        {
            "id": "local-store-decryption-authority-workflow",
            "label": "Telegram local tdata/cache DB decryption is authority-gated and audited",
            "status": "authority-workflow-required",
            "blocking": True,
            "evidence_refs": ["required:lawful local-store authority, no raw key exposure, controlled reveal audit"],
        },
        {
            "id": "export-schema-version-known-answer",
            "label": "Telegram desktop/mobile export schema versions are validated with known-answer data",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:Telegram export/cache schema-version matrix"],
        },
        {
            "id": "account-dialog-peer-attribution-known-answer",
            "label": "Account, dialog, peer, author, and participant attribution semantics are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:account/dialog/peer attribution corpus"],
        },
        {
            "id": "secret-chat-edited-deleted-semantics",
            "label": "Secret chat, edited message, deleted message, and ephemeral semantics are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:secret/edited/deleted known-answer corpus"],
        },
        {
            "id": "cache-media-locality-validation",
            "label": "Media/cache metadata is linked to recovered local bytes and hashes before media claims",
            "status": "external-media-validation-required",
            "blocking": True,
            "evidence_refs": ["required:Telegram cache/media byte and locality validation"],
        },
        {
            "id": "independent-telegram-review",
            "label": "Independent reviewer signs off on Telegram scope, local-store limits, schema version, and report wording",
            "status": "external-review-required",
            "blocking": True,
            "evidence_refs": ["required:independent Telegram validation review"],
        },
    ]
    ready_slot_ids = [
        str(slot.get("id"))
        for slot in evidence_slots
        if str(slot.get("status", "")).startswith("complete")
    ]
    blocking_slot_ids = [str(slot.get("id")) for slot in evidence_slots if slot.get("blocking")]
    plan: dict[str, object] = {
        "profile_version": TELEGRAM_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 33,
        "gap_id": "#33",
        "status": "report-validation-blocked",
        "commercial_grade": False,
        "artifact_goal": "Telegram authorized export/cache message, account, dialog, media, local-store, and deleted-state validation",
        "artifact_type": artifact_type,
        "service": "Telegram",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_sha256,
        "source_record_id": source_record_id(details, source_index),
        "app_version": optional_text(details.get("app_version")),
        "schema_version": optional_text(details.get("schema_version")),
        "database_name": optional_text(details.get("database_name")),
        "validation_commands": [
            {
                "id": "source-telegram-export-cache-manifest",
                "purpose": "Freeze source export/cache/database hashes and acquisition metadata",
                "command": "rapidtriage manifest <telegram-export-or-cache-folder> --output <case>/telegram-source-manifest.json",
            },
            {
                "id": "telegram-export-import",
                "purpose": "Recreate RapidTriage Telegram normalized rows and cache/DB inventory",
                "command": "rapidtriage artifacts <mobile-export> --kind mobile-export --output <case>/telegram-mobile-export.json",
            },
            {
                "id": "trusted-telegram-diff",
                "purpose": "Compare Telegram message/cache rows with authorized export or validated native parser output",
                "command": "rapidtriage cross-tool-validate --rapid-output <case>/telegram-mobile-export.json --reference-output telegram=<trusted-telegram-output.json> --backlog-item 33 --json",
            },
            {
                "id": "telegram-local-store-authority-review",
                "purpose": "Attach lawful local-store/key provenance and controlled-reveal audit evidence before local-store claims",
                "command": "rapidtriage forensic-validation-pack --case <case> --artifact telegram-local-store-authority --json",
            },
            {
                "id": "telegram-known-answer-run",
                "purpose": "Attach export schema, account/dialog, secret/deleted/edit, and cache-media known-answer evidence",
                "command": "rapidtriage commercial-readiness --validation-package <telegram-known-answer.json> --limit 33 --json",
            },
        ],
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slot_ids,
        "blocking_slot_ids": blocking_slot_ids,
        "ready_slot_count": len(ready_slot_ids),
        "blocking_slot_count": len(blocking_slot_ids),
        "commercial_grade_blockers": list(TELEGRAM_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use Telegram rows as authorized export/cache triage until trusted diff, lawful local-store authority, schema/account corpus, secret/deleted/edit validation, media byte proof, and independent review are attached.",
    }
    plan["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def signal_message_review_profile(
    *,
    service: str,
    row: Mapping[str, object],
    app_version: str,
    text: str,
    media_reference: str,
    reaction: str,
    deleted_state: str,
) -> dict[str, object]:
    if service != "Signal":
        return {}
    thread_id = optional_text(first_value(row, ("threadid", "thread_id", "conversationid", "chatid")))
    recipient_id = optional_text(first_value(row, ("recipientid", "recipient_id", "recipient", "to", "address", "uuid")))
    sender = optional_text(first_value(row, ("sender", "from", "author", "source")))
    attachment_name = optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename")))
    quoted_id = optional_text(first_value(row, ("quotedmessageid", "quoteid", "replyto", "parentmessageid")))
    read_state = optional_text(first_value(row, ("readstate", "readstatus", "deliveryreceipt", "readreceipt", "status")))
    expires = optional_text(first_value(row, ("expiresin", "expiretimer", "disappearing", "expiration", "ttl")))
    return {
        "profile_version": "signal-message-review-v1",
        "source_track": "signal-sqlcipher-authority-gated-inventory",
        "app_version": app_version or "unknown",
        "message_text_present": bool(text),
        "message_text_sha256_present": bool(text),
        "thread_or_recipient_attribution_present": bool(thread_id or recipient_id or sender),
        "thread_id_present": bool(thread_id),
        "recipient_id_present": bool(recipient_id),
        "sender_present": bool(sender),
        "attachment_metadata_present": bool(media_reference or attachment_name),
        "attachment_class": classify_signal_attachment(media_reference, attachment_name),
        "attachment_local_bytes_verified": False,
        "reaction_present": bool(reaction),
        "quoted_message_present": bool(quoted_id),
        "read_or_delivery_state_present": bool(read_state),
        "deleted_state_present": bool(deleted_state),
        "disappearing_timer_present": bool(expires),
        "sqlcipher_key_authority_status": "not-attached",
        "sqlcipher_decode_status": "not-performed",
        "deleted_row_recovery_status": "not-validated",
        "review_display_mode": "chat-bubble-row-with-recipient-sqlcipher-metadata-collapsed",
        "validation_status": "triage-ready-known-answer-required",
        "required_before_report": [
            "attach lawful SQLCipher/key authority workflow before relying on Signal database contents",
            "diff this row against a trusted Signal parser/export or known-answer fixture",
            "validate thread, recipient, delivery/read, disappearing-message, quote, and deleted-state semantics",
            "verify attachment bytes/hash locally before treating attachment metadata as recovered media",
        ],
    }


def signal_database_review_payload(service: str, table_summaries: Sequence[Mapping[str, object]]) -> dict[str, object]:
    if service != "Signal":
        return {}
    table_names = [optional_text(summary.get("table")) for summary in table_summaries]
    message_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if summary.get("message_table_candidate")
        or optional_text(summary.get("table")).lower() in {"message", "sms", "mms"}
    ]
    recipient_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if optional_text(summary.get("table")).lower() in {"recipient", "thread", "groups"}
        or any(token in str(column).lower() for column in summary.get("columns", []) or [] for token in ("recipient", "thread", "address", "uuid"))
    ]
    attachment_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if optional_text(summary.get("table")).lower() in {"attachment", "part", "mms"}
        or any(column for column in summary.get("media_column_candidates", []) or [])
    ]
    return {
        "signal_database_review_profile": {
            "profile_version": "signal-database-review-v1",
            "table_count": len(table_summaries),
            "message_table_candidates": [name for name in message_tables if name][:25],
            "recipient_thread_table_candidates": [name for name in recipient_tables if name][:25],
            "attachment_table_candidates": [name for name in attachment_tables if name][:25],
            "signal_schema_shape_present": any(name.lower() in {"message", "sms", "mms", "recipient", "thread"} for name in table_names),
            "read_policy": "schema-row-counts-only-no-secret-values",
            "sqlcipher_key_authority_status": "not-attached",
            "sqlcipher_decode_status": "not-performed",
            "disappearing_message_semantics_status": "not-validated",
            "deleted_row_recovery_status": "not-validated",
            "native_decode_status": "inventory-only",
            "required_before_report": [
                "attach lawful SQLCipher/key authority and extraction logs before decrypting Signal stores",
                "validate recipient/thread/message/attachment schema version against known-answer Signal fixtures",
                "diff table and row counts against a trusted Signal parser/export",
                "validate disappearing-message, deleted-row, and attachment locality semantics before report-grade claims",
            ],
        }
    }


def build_signal_parser_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    """Signal-specific review manifest for export rows and SQLCipher inventories."""
    message_profile = (
        details.get("signal_message_review_profile")
        if isinstance(details.get("signal_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("signal_database_review_profile")
        if isinstance(details.get("signal_database_review_profile"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    row_payload = {
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "service": "Signal",
        "timestamp": optional_text(details.get("timestamp")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
        "database_name": optional_text(details.get("database_name")),
    }
    table_inventory = [
        {
            "table": optional_text(table.get("table")) if isinstance(table, Mapping) else "",
            "row_count": table.get("row_count") if isinstance(table, Mapping) else None,
            "message_table_candidate": bool(table.get("message_table_candidate")) if isinstance(table, Mapping) else False,
            "recipient_thread_column_candidates": [
                str(column)
                for column in (table.get("columns") or [])
                if isinstance(table, Mapping)
                and any(token in str(column).lower() for token in ("recipient", "thread", "address", "uuid"))
            ][:10],
            "media_column_candidates": list(table.get("media_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
        }
        for table in table_summaries[:MAX_SQLITE_TABLES]
    ]
    manifest: dict[str, object] = {
        "manifest_version": "signal-parser-manifest-v1",
        "item_number": 34,
        "batch_id": "commercial-uplift-031-035",
        "gap_id": "#34",
        "qc_prep_item_number": 40,
        "qc_prep_item_goal": QC_PREP_CHAT_APP_GOALS[40],
        "qc_prep_contract": dict(QC_PREP_CHAT_APP_CONTRACTS[40]),
        "artifact_type": artifact_type,
        "service": "Signal",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "row_citation": {
            **row_payload,
            "row_hash": stable_mobile_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "signal-message-row" if artifact_type == "mobile-message" else "signal-sqlcipher-inventory",
                "source_path": str(source_path.resolve()),
                "source_index": source_index,
                "source_record_id": source_record_id(details, source_index),
                "database_name": optional_text(details.get("database_name")),
            },
        },
        "parser_tracks": [
            {
                "track": "authorized-export-row-normalization",
                "status": "implemented" if artifact_type == "mobile-message" else "not-applicable",
                "reportable_as": "message-row-triage-pivot",
            },
            {
                "track": "signal-sqlcipher-database-inventory",
                "status": "implemented" if artifact_type == "mobile-chat-database" else "not-applicable",
                "reportable_as": "schema-and-row-count-inventory",
            },
            {
                "track": "sqlcipher-key-authority-workflow",
                "status": "authority-gated-validation-required",
                "reportable_as": "not-sqlcipher-complete-without-key-evidence",
            },
            {
                "track": "attachment-disappearing-deleted-validation",
                "status": "known-answer-required",
                "reportable_as": "not-attachment-or-deleted-complete",
            },
        ],
        "message_review": {
            "present": bool(message_profile),
            "message_text_sha256_present": bool(message_profile.get("message_text_sha256_present")),
            "thread_or_recipient_attribution_present": bool(message_profile.get("thread_or_recipient_attribution_present")),
            "thread_id_present": bool(message_profile.get("thread_id_present")),
            "recipient_id_present": bool(message_profile.get("recipient_id_present")),
            "sender_present": bool(message_profile.get("sender_present")),
            "attachment_metadata_present": bool(message_profile.get("attachment_metadata_present")),
            "attachment_class": optional_text(message_profile.get("attachment_class")),
            "read_or_delivery_state_present": bool(message_profile.get("read_or_delivery_state_present")),
            "deleted_state_present": bool(message_profile.get("deleted_state_present")),
            "disappearing_timer_present": bool(message_profile.get("disappearing_timer_present")),
            "sqlcipher_key_authority_status": optional_text(message_profile.get("sqlcipher_key_authority_status")),
            "sqlcipher_decode_status": optional_text(message_profile.get("sqlcipher_decode_status")),
        },
        "database_review": {
            "present": bool(database_profile),
            "table_count": database_profile.get("table_count", len(table_inventory)) if isinstance(database_profile, Mapping) else len(table_inventory),
            "message_table_candidates": list(database_profile.get("message_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "recipient_thread_table_candidates": list(database_profile.get("recipient_thread_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "attachment_table_candidates": list(database_profile.get("attachment_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "signal_schema_shape_present": bool(database_profile.get("signal_schema_shape_present")) if isinstance(database_profile, Mapping) else False,
            "native_decode_status": optional_text(database_profile.get("native_decode_status"))
            if isinstance(database_profile, Mapping)
            else "not-applicable",
            "table_inventory": table_inventory,
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "service_detected": bool(validation.get("service_detected", True)),
            "thread_or_recipient_attribution_present": bool(
                message_profile.get("thread_or_recipient_attribution_present")
                or database_profile.get("recipient_thread_table_candidates")
            ),
            "sqlcipher_key_authority_attached": False,
            "sqlcipher_decode_complete": False,
            "trusted_export_or_native_db_diff_attached": False,
            "attachment_bytes_verified": False,
            "deleted_disappearing_known_answer_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "raw_text_hash_only_by_default": True,
            "metadata_collapsed_by_default": True,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "table_inventory_count": len(table_inventory),
            "table_inventory_capped": len(table_summaries) >= MAX_SQLITE_TABLES,
            "viewer_default": "conversation-grouped-virtualized-chat-review",
        },
        "commercial_blockers": [
            "signal-sqlcipher-key-authority-workflow-required",
            "trusted-signal-export-or-native-db-diff-required",
            "recipient-thread-schema-known-answer-required",
            "attachment-locality-validation-required",
            "deleted-and-disappearing-message-validation-required",
        ],
        "reporting_status": "signal-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_signal_report_grade_validation_plan(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    parser_manifest = (
        details.get("signal_parser_manifest")
        if isinstance(details.get("signal_parser_manifest"), Mapping)
        else {}
    )
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    message_profile = (
        details.get("signal_message_review_profile")
        if isinstance(details.get("signal_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("signal_database_review_profile")
        if isinstance(details.get("signal_database_review_profile"), Mapping)
        else {}
    )
    row_citation = (
        parser_manifest.get("row_citation")
        if isinstance(parser_manifest.get("row_citation"), Mapping)
        else {}
    )
    source_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    source_sha256 = optional_text(source_hashes.get("sha256"))
    message_hash_present = bool(optional_text(details.get("message_text_sha256")))
    thread_recipient_or_attachment_present = bool(
        message_profile.get("thread_or_recipient_attribution_present")
        or message_profile.get("thread_id_present")
        or message_profile.get("recipient_id_present")
        or message_profile.get("attachment_metadata_present")
        or optional_text(details.get("conversation_id"))
        or optional_text(details.get("sender"))
        or optional_text(details.get("media_reference_sha256"))
    )
    database_inventory_present = bool(database_profile) or bool(table_summaries)
    parser_track_present = bool(parser_manifest.get("parser_tracks"))
    evidence_slots = [
        {
            "id": "source-export-sqlcipher-row-integrity",
            "label": "Source Signal export or SQLCipher inventory row has hashable provenance",
            "status": "complete" if source_sha256 else "missing-source-hash",
            "blocking": not bool(source_sha256),
            "evidence_refs": [
                f"source_tool:{source_tool}",
                f"source_format:{source_format}",
                f"source_index:{source_index}",
                f"source_sha256:{source_sha256}",
            ],
        },
        {
            "id": "service-profile-row-citation",
            "label": "Signal service profile and source row citation are fixed",
            "status": "complete" if row_citation.get("row_hash") else "missing-row-citation",
            "blocking": not bool(row_citation.get("row_hash")),
            "evidence_refs": [
                f"signal_parser_manifest:{parser_manifest.get('manifest_sha256', '')}",
                f"row_hash:{row_citation.get('row_hash', '')}",
            ],
        },
        {
            "id": "thread-recipient-message-attachment-normalization",
            "label": "Thread, recipient, message, and attachment pivots are normalized without SQLCipher completeness claims",
            "status": "complete"
            if artifact_type == "mobile-message" and (message_hash_present or thread_recipient_or_attachment_present)
            else "not-applicable",
            "blocking": artifact_type == "mobile-message"
            and not (message_hash_present or thread_recipient_or_attachment_present),
            "evidence_refs": [
                f"artifact_type:{artifact_type}",
                f"message_text_sha256_present:{message_hash_present}",
                f"thread_recipient_or_attachment_present:{thread_recipient_or_attachment_present}",
            ],
        },
        {
            "id": "signal-database-sqlcipher-inventory-boundary",
            "label": "Signal SQLite/SQLCipher candidates are inventory-only until key authority evidence is attached",
            "status": "complete" if artifact_type == "mobile-chat-database" and database_inventory_present else "not-applicable",
            "blocking": False,
            "evidence_refs": [
                f"database_inventory_present:{database_inventory_present}",
                f"table_summary_count:{len(table_summaries)}",
            ],
        },
        {
            "id": "sqlcipher-strategy-classification",
            "label": "Export, SQLCipher inventory, key authority, attachment, and deleted/disappearing validation tracks are recorded",
            "status": "complete" if parser_track_present else "missing-parser-track",
            "blocking": not parser_track_present,
            "evidence_refs": [
                f"parser_track_count:{len(parser_manifest.get('parser_tracks') or [])}",
                f"sqlcipher_key_authority_status:{message_profile.get('sqlcipher_key_authority_status') or database_profile.get('sqlcipher_key_authority_status') or 'not-attached'}",
                f"sqlcipher_decode_status:{message_profile.get('sqlcipher_decode_status') or database_profile.get('sqlcipher_decode_status') or 'not-performed'}",
            ],
        },
        {
            "id": "hash-only-text-policy",
            "label": "Message text is represented with hash/citation controls before report selection",
            "status": "complete"
            if parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")
            else "missing-hash-only-policy",
            "blocking": not bool(parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")),
            "evidence_refs": [
                f"raw_text_hash_only_by_default:{parser_manifest.get('large_data_controls', {}).get('raw_text_hash_only_by_default', False)}",
                f"message_text_sha256_present:{message_hash_present}",
            ],
        },
        {
            "id": "source-viewer-locator",
            "label": "GUI/report can pivot back to the Signal source row or SQLCipher inventory",
            "status": "complete" if source_locator else "missing-source-viewer-locator",
            "blocking": not bool(source_locator),
            "evidence_refs": [
                f"viewer:{source_locator.get('viewer', '') if isinstance(source_locator, Mapping) else ''}",
                f"messenger_manifest:{messenger_manifest.get('manifest_sha256', '')}",
            ],
        },
        {
            "id": "trusted-signal-export-native-db-diff",
            "label": "RapidTriage Signal rows are diffed against authorized export/native SQLCipher output",
            "status": "pending-cross-tool-validate",
            "blocking": True,
            "evidence_refs": ["command:rapidtriage cross-tool-validate --backlog-item 34"],
        },
        {
            "id": "sqlcipher-key-authority-workflow",
            "label": "Signal SQLCipher key handling is authority-gated, audited, and secret-safe",
            "status": "authority-workflow-required",
            "blocking": True,
            "evidence_refs": ["required:lawful SQLCipher key authority, no raw key exposure, controlled reveal audit"],
        },
        {
            "id": "recipient-thread-schema-known-answer",
            "label": "Recipient, thread, group, message, and attachment schema semantics are known-answer validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:Signal recipient/thread/schema-version corpus"],
        },
        {
            "id": "attachment-locality-validation",
            "label": "Attachment metadata is linked to recovered local bytes and hashes before media claims",
            "status": "external-media-validation-required",
            "blocking": True,
            "evidence_refs": ["required:Signal attachment byte and locality validation"],
        },
        {
            "id": "deleted-disappearing-message-semantics",
            "label": "Deleted rows, disappearing timers, quote links, and ephemeral semantics are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:deleted/disappearing/quote known-answer corpus"],
        },
        {
            "id": "delivery-read-state-semantics",
            "label": "Delivery, read, receipt, and device-sync status semantics are validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:Signal delivery/read receipt known-answer corpus"],
        },
        {
            "id": "independent-signal-review",
            "label": "Independent reviewer signs off on Signal scope, SQLCipher/key limits, schema version, and report wording",
            "status": "external-review-required",
            "blocking": True,
            "evidence_refs": ["required:independent Signal validation review"],
        },
    ]
    ready_slot_ids = [
        str(slot.get("id"))
        for slot in evidence_slots
        if str(slot.get("status", "")).startswith("complete")
    ]
    blocking_slot_ids = [str(slot.get("id")) for slot in evidence_slots if slot.get("blocking")]
    plan: dict[str, object] = {
        "profile_version": SIGNAL_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 34,
        "gap_id": "#34",
        "status": "report-validation-blocked",
        "commercial_grade": False,
        "artifact_goal": "Signal authorized export/SQLCipher message, recipient, thread, attachment, key authority, and deleted-state validation",
        "artifact_type": artifact_type,
        "service": "Signal",
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_sha256,
        "source_record_id": source_record_id(details, source_index),
        "app_version": optional_text(details.get("app_version")),
        "schema_version": optional_text(details.get("schema_version")),
        "database_name": optional_text(details.get("database_name")),
        "validation_commands": [
            {
                "id": "source-signal-export-sqlcipher-manifest",
                "purpose": "Freeze source export/SQLCipher inventory hashes and acquisition metadata",
                "command": "rapidtriage manifest <signal-export-or-store-folder> --output <case>/signal-source-manifest.json",
            },
            {
                "id": "signal-export-import",
                "purpose": "Recreate RapidTriage Signal normalized rows and SQLCipher inventory",
                "command": "rapidtriage artifacts <mobile-export> --kind mobile-export --output <case>/signal-mobile-export.json",
            },
            {
                "id": "trusted-signal-diff",
                "purpose": "Compare Signal message/inventory rows with authorized export or validated SQLCipher parser output",
                "command": "rapidtriage cross-tool-validate --rapid-output <case>/signal-mobile-export.json --reference-output signal=<trusted-signal-output.json> --backlog-item 34 --json",
            },
            {
                "id": "signal-sqlcipher-authority-review",
                "purpose": "Attach lawful key provenance and controlled-reveal audit evidence before SQLCipher content claims",
                "command": "rapidtriage forensic-validation-pack --case <case> --artifact signal-sqlcipher-authority --json",
            },
            {
                "id": "signal-known-answer-run",
                "purpose": "Attach schema, recipient/thread, attachment, delivery/read, deleted/disappearing known-answer evidence",
                "command": "rapidtriage commercial-readiness --validation-package <signal-known-answer.json> --limit 34 --json",
            },
        ],
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slot_ids,
        "blocking_slot_ids": blocking_slot_ids,
        "ready_slot_count": len(ready_slot_ids),
        "blocking_slot_count": len(blocking_slot_ids),
        "commercial_grade_blockers": list(SIGNAL_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use Signal rows as authorized export/SQLCipher-inventory triage until trusted diff, lawful key authority, schema/recipient corpus, attachment byte proof, deleted/disappearing validation, delivery/read semantics, and independent review are attached.",
    }
    plan["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def extended_messenger_message_review_profile(
    *,
    service: str,
    row: Mapping[str, object],
    app_version: str,
    text: str,
    media_reference: str,
    reaction: str,
    deleted_state: str,
) -> dict[str, object]:
    if service not in EXTENDED_MESSENGER_REVIEW_SERVICES:
        return {}
    thread_or_channel = optional_text(
        first_value(
            row,
            (
                "threadid",
                "thread_id",
                "conversationid",
                "chatid",
                "roomid",
                "channelid",
                "guildid",
                "groupid",
            ),
        )
    )
    account_or_actor = optional_text(
        first_value(row, ("accountid", "userid", "user_id", "sender", "from", "author", "username", "profileid"))
    )
    recipient_or_peer = optional_text(first_value(row, ("recipient", "to", "peerid", "memberid", "contactid", "target")))
    attachment_name = optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename")))
    read_state = optional_text(first_value(row, ("readstate", "readstatus", "seen", "seenat", "readat", "readtime")))
    edit_state = optional_text(first_value(row, ("edited", "editedat", "lastedited", "updated", "editdate")))
    ephemeral_state = optional_text(first_value(row, ("ephemeral", "vanish", "disappearing", "ttl", "expiresin", "story", "temporary")))
    export_hint = optional_text(first_value(row, ("sourcefile", "exportpath", "database", "path", "packagepath", "jsonfile")))
    return {
        "profile_version": "extended-messenger-message-review-v1",
        "service": service,
        "source_track": extended_messenger_source_track(service),
        "app_version": app_version or "unknown",
        "message_text_present": bool(text),
        "message_text_sha256_present": bool(text),
        "service_attribution_present": bool(service),
        "thread_or_channel_attribution_present": bool(thread_or_channel),
        "account_or_actor_attribution_present": bool(account_or_actor),
        "recipient_or_peer_attribution_present": bool(recipient_or_peer),
        "attachment_metadata_present": bool(media_reference or attachment_name),
        "attachment_class": classify_extended_messenger_attachment(media_reference, attachment_name),
        "attachment_local_bytes_verified": False,
        "reaction_present": bool(reaction),
        "read_state_present": bool(read_state),
        "edited_state_present": bool(edit_state),
        "deleted_state_present": bool(deleted_state),
        "ephemeral_or_vanish_hint_present": bool(ephemeral_state),
        "export_or_package_source_hint_present": bool(export_hint),
        "native_decode_status": "not-performed",
        "deleted_or_ephemeral_semantics_status": "not-validated",
        "review_display_mode": "chat-bubble-row-with-service-specific-metadata-collapsed",
        "validation_status": "triage-ready-known-answer-required",
        "required_before_report": [
            f"validate {service} export/native schema version against known-answer fixtures",
            f"diff important {service} rows against a trusted export or native database parser",
            "verify attachment bytes/hash locally before treating attachment metadata as recovered media",
            "document edited, deleted, read, and ephemeral-message limitations in the report wording",
        ],
    }


def extended_messenger_database_review_payload(service: str, table_summaries: Sequence[Mapping[str, object]]) -> dict[str, object]:
    if service not in EXTENDED_MESSENGER_REVIEW_SERVICES:
        return {}
    profile = chat_app_profile(service) or {}
    message_table_names = {str(item).lower() for item in profile.get("message_tables", ())}
    message_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if summary.get("message_table_candidate") or optional_text(summary.get("table")).lower() in message_table_names
    ]
    actor_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(
            token in str(column).lower()
            for column in summary.get("columns", []) or []
            for token in ("user", "member", "contact", "author", "sender", "recipient", "channel", "thread", "room")
        )
    ]
    attachment_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(column for column in summary.get("media_column_candidates", []) or [])
        or optional_text(summary.get("table")).lower() in {"attachments", "attachment", "media", "files", "appmessage"}
    ]
    state_tables = [
        optional_text(summary.get("table"))
        for summary in table_summaries
        if any(
            token in str(column).lower()
            for column in summary.get("columns", []) or []
            for token in ("deleted", "edit", "reaction", "read", "seen", "ttl", "expire", "vanish")
        )
    ]
    return {
        "extended_messenger_database_review_profile": {
            "profile_version": "extended-messenger-database-review-v1",
            "service": service,
            "source_track": extended_messenger_source_track(service),
            "table_count": len(table_summaries),
            "message_table_candidates": [name for name in message_tables if name][:25],
            "actor_or_thread_table_candidates": [name for name in actor_tables if name][:25],
            "attachment_table_candidates": [name for name in attachment_tables if name][:25],
            "state_semantics_table_candidates": [name for name in state_tables if name][:25],
            "read_policy": "schema-row-counts-only-no-secret-values",
            "native_decode_status": "inventory-only",
            "deleted_or_ephemeral_semantics_status": "not-validated",
            "required_before_report": [
                f"identify {service} source type: official export, app database, cache, or vendor normalized export",
                f"validate {service} table semantics with versioned known-answer fixtures",
                "diff table and row counts against a trusted parser/export before report-grade claims",
                "verify attachment locality, edited/deleted/read-state semantics, and timezone handling",
            ],
        }
    }


def build_extended_messenger_parser_manifest(
    *,
    artifact_type: str,
    service: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    """Extended messenger review manifest for service-specific export/schema triage."""
    message_profile = (
        details.get("extended_messenger_message_review_profile")
        if isinstance(details.get("extended_messenger_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("extended_messenger_database_review_profile")
        if isinstance(details.get("extended_messenger_database_review_profile"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    row_payload = {
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_sha256": source_hashes.get("sha256", ""),
        "service": service,
        "timestamp": optional_text(details.get("timestamp")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
        "database_name": optional_text(details.get("database_name")),
    }
    table_inventory = [
        {
            "table": optional_text(table.get("table")) if isinstance(table, Mapping) else "",
            "row_count": table.get("row_count") if isinstance(table, Mapping) else None,
            "message_table_candidate": bool(table.get("message_table_candidate")) if isinstance(table, Mapping) else False,
            "actor_or_thread_column_candidates": [
                str(column)
                for column in (table.get("columns") or [])
                if isinstance(table, Mapping)
                and any(
                    token in str(column).lower()
                    for token in ("user", "member", "contact", "author", "sender", "recipient", "channel", "thread", "room")
                )
            ][:10],
            "media_column_candidates": list(table.get("media_column_candidates") or [])[:10]
            if isinstance(table, Mapping)
            else [],
        }
        for table in table_summaries[:MAX_SQLITE_TABLES]
    ]
    manifest: dict[str, object] = {
        "manifest_version": "extended-messenger-parser-manifest-v1",
        "item_number": 35,
        "batch_id": "commercial-uplift-031-035",
        "gap_id": "#35",
        "qc_prep_item_number": 41,
        "qc_prep_item_goal": QC_PREP_CHAT_APP_GOALS[41],
        "qc_prep_contract": dict(QC_PREP_CHAT_APP_CONTRACTS[41]),
        "artifact_type": artifact_type,
        "service": service or "unknown",
        "service_family": service_family(service),
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "row_citation": {
            **row_payload,
            "row_hash": stable_mobile_sha256(row_payload),
            "source_viewer_locator": {
                "viewer": "extended-messenger-message-row"
                if artifact_type == "mobile-message"
                else "extended-messenger-database-inventory",
                "source_path": str(source_path.resolve()),
                "source_index": source_index,
                "source_record_id": source_record_id(details, source_index),
                "service": service,
                "database_name": optional_text(details.get("database_name")),
            },
        },
        "parser_tracks": [
            {
                "track": extended_messenger_source_track(service),
                "status": "implemented" if artifact_type == "mobile-message" else "inventory-only",
                "reportable_as": "service-export-or-schema-inventory-triage-pivot",
            },
            {
                "track": "service-specific-native-store-decode",
                "status": "schema-and-authority-validation-required",
                "reportable_as": "not-native-store-complete",
            },
            {
                "track": "media-reaction-read-deleted-ephemeral-validation",
                "status": "known-answer-required",
                "reportable_as": "not-state-or-media-complete",
            },
        ],
        "message_review": {
            "present": bool(message_profile),
            "message_text_sha256_present": bool(message_profile.get("message_text_sha256_present")),
            "service_attribution_present": bool(message_profile.get("service_attribution_present", service)),
            "thread_or_channel_attribution_present": bool(message_profile.get("thread_or_channel_attribution_present")),
            "account_or_actor_attribution_present": bool(message_profile.get("account_or_actor_attribution_present")),
            "recipient_or_peer_attribution_present": bool(message_profile.get("recipient_or_peer_attribution_present")),
            "attachment_metadata_present": bool(message_profile.get("attachment_metadata_present")),
            "attachment_class": optional_text(message_profile.get("attachment_class")),
            "reaction_present": bool(message_profile.get("reaction_present")),
            "read_state_present": bool(message_profile.get("read_state_present")),
            "edited_state_present": bool(message_profile.get("edited_state_present")),
            "deleted_state_present": bool(message_profile.get("deleted_state_present")),
            "ephemeral_or_vanish_hint_present": bool(message_profile.get("ephemeral_or_vanish_hint_present")),
            "native_decode_status": optional_text(message_profile.get("native_decode_status")),
        },
        "database_review": {
            "present": bool(database_profile),
            "table_count": database_profile.get("table_count", len(table_inventory)) if isinstance(database_profile, Mapping) else len(table_inventory),
            "message_table_candidates": list(database_profile.get("message_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "actor_or_thread_table_candidates": list(database_profile.get("actor_or_thread_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "attachment_table_candidates": list(database_profile.get("attachment_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "state_semantics_table_candidates": list(database_profile.get("state_semantics_table_candidates") or [])[:25]
            if isinstance(database_profile, Mapping)
            else [],
            "native_decode_status": optional_text(database_profile.get("native_decode_status"))
            if isinstance(database_profile, Mapping)
            else "not-applicable",
            "table_inventory": table_inventory,
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "service_detected": bool(validation.get("service_detected", True)),
            "schema_version_present": bool(details.get("schema_version")),
            "thread_or_channel_present": bool(message_profile.get("thread_or_channel_attribution_present")),
            "trusted_export_or_native_db_diff_attached": False,
            "media_bytes_verified": False,
            "deleted_or_ephemeral_known_answer_attached": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "raw_text_hash_only_by_default": True,
            "metadata_collapsed_by_default": True,
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "table_inventory_count": len(table_inventory),
            "table_inventory_capped": len(table_summaries) >= MAX_SQLITE_TABLES,
            "viewer_default": "service-grouped-virtualized-chat-review",
        },
        "commercial_blockers": [
            "extended-messenger-service-schema-known-answer-required",
            "trusted-extended-messenger-export-or-native-db-diff-required",
            "media-locality-validation-required",
            "reaction-read-edited-deleted-state-validation-required",
            "ephemeral-or-encrypted-store-boundary-validation-required",
        ],
        "reporting_status": "extended-messenger-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_extended_messenger_report_grade_validation_plan(
    *,
    artifact_type: str,
    service: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    parser_manifest = (
        details.get("extended_messenger_parser_manifest")
        if isinstance(details.get("extended_messenger_parser_manifest"), Mapping)
        else {}
    )
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    message_profile = (
        details.get("extended_messenger_message_review_profile")
        if isinstance(details.get("extended_messenger_message_review_profile"), Mapping)
        else {}
    )
    database_profile = (
        details.get("extended_messenger_database_review_profile")
        if isinstance(details.get("extended_messenger_database_review_profile"), Mapping)
        else {}
    )
    row_citation = (
        parser_manifest.get("row_citation")
        if isinstance(parser_manifest.get("row_citation"), Mapping)
        else {}
    )
    source_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    source_sha256 = optional_text(source_hashes.get("sha256"))
    message_hash_present = bool(optional_text(details.get("message_text_sha256")))
    media_or_reaction_present = bool(
        optional_text(details.get("media_reference_sha256"))
        or optional_text(details.get("reaction"))
        or message_profile.get("attachment_metadata_present")
        or message_profile.get("reaction_present")
    )
    service_pivot_present = bool(
        service
        or message_profile.get("service_attribution_present")
        or message_profile.get("thread_or_channel_attribution_present")
        or message_profile.get("account_or_actor_attribution_present")
    )
    database_inventory_present = bool(database_profile) or bool(table_summaries)
    parser_track_present = bool(parser_manifest.get("parser_tracks"))
    evidence_slots = [
        {
            "id": "source-export-native-row-integrity",
            "label": "Source extended messenger export/native inventory row has hashable provenance",
            "status": "complete" if source_sha256 else "missing-source-hash",
            "blocking": not bool(source_sha256),
            "evidence_refs": [
                f"source_tool:{source_tool}",
                f"source_format:{source_format}",
                f"source_index:{source_index}",
                f"source_sha256:{source_sha256}",
            ],
        },
        {
            "id": "service-profile-row-citation",
            "label": "Extended messenger service profile and source row citation are fixed",
            "status": "complete" if row_citation.get("row_hash") else "missing-row-citation",
            "blocking": not bool(row_citation.get("row_hash")),
            "evidence_refs": [
                f"extended_messenger_parser_manifest:{parser_manifest.get('manifest_sha256', '')}",
                f"row_hash:{row_citation.get('row_hash', '')}",
            ],
        },
        {
            "id": "message-media-reaction-normalization",
            "label": "Message, media, reaction, actor, and thread pivots are normalized for review",
            "status": "complete"
            if artifact_type == "mobile-message" and (message_hash_present or media_or_reaction_present or service_pivot_present)
            else "not-applicable",
            "blocking": artifact_type == "mobile-message"
            and not (message_hash_present or media_or_reaction_present or service_pivot_present),
            "evidence_refs": [
                f"artifact_type:{artifact_type}",
                f"message_text_sha256_present:{message_hash_present}",
                f"media_or_reaction_present:{media_or_reaction_present}",
                f"service_pivot_present:{service_pivot_present}",
            ],
        },
        {
            "id": "extended-database-schema-inventory-boundary",
            "label": "Native or app database candidates are schema/row-count inventory until service validation exists",
            "status": "complete" if artifact_type == "mobile-chat-database" and database_inventory_present else "not-applicable",
            "blocking": False,
            "evidence_refs": [
                f"database_inventory_present:{database_inventory_present}",
                f"table_summary_count:{len(table_summaries)}",
            ],
        },
        {
            "id": "service-source-track-classification",
            "label": "Service-specific source track, native decode boundary, and state-validation track are recorded",
            "status": "complete" if parser_track_present else "missing-parser-track",
            "blocking": not parser_track_present,
            "evidence_refs": [
                f"service:{service or 'unknown'}",
                f"parser_track_count:{len(parser_manifest.get('parser_tracks') or [])}",
                f"source_track:{extended_messenger_source_track(service)}",
            ],
        },
        {
            "id": "hash-only-text-policy",
            "label": "Message text is represented with hash/citation controls before report selection",
            "status": "complete"
            if parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")
            else "missing-hash-only-policy",
            "blocking": not bool(parser_manifest.get("large_data_controls", {}).get("raw_text_hash_only_by_default")),
            "evidence_refs": [
                f"raw_text_hash_only_by_default:{parser_manifest.get('large_data_controls', {}).get('raw_text_hash_only_by_default', False)}",
                f"message_text_sha256_present:{message_hash_present}",
            ],
        },
        {
            "id": "source-viewer-locator",
            "label": "GUI/report can pivot back to the extended messenger source row or database inventory",
            "status": "complete" if source_locator else "missing-source-viewer-locator",
            "blocking": not bool(source_locator),
            "evidence_refs": [
                f"viewer:{source_locator.get('viewer', '') if isinstance(source_locator, Mapping) else ''}",
                f"messenger_manifest:{messenger_manifest.get('manifest_sha256', '')}",
            ],
        },
        {
            "id": "trusted-extended-messenger-export-native-db-diff",
            "label": "RapidTriage rows are diffed against service export or trusted native parser output",
            "status": "pending-cross-tool-validate",
            "blocking": True,
            "evidence_refs": ["command:rapidtriage cross-tool-validate --backlog-item 35"],
        },
        {
            "id": "service-schema-version-known-answer",
            "label": "Service, app version, export schema, and native DB schema semantics are known-answer validated",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:per-service schema-version fixtures for WeChat/LINE/Discord/Instagram/etc."],
        },
        {
            "id": "encrypted-ephemeral-store-authority-workflow",
            "label": "Encrypted or ephemeral stores are authority-gated and limitation-safe",
            "status": "authority-workflow-required",
            "blocking": True,
            "evidence_refs": ["required:lawful authority workflow for encrypted/native stores and ephemeral content"],
        },
        {
            "id": "media-locality-validation",
            "label": "Media metadata is linked to recovered local bytes and hashes before attachment claims",
            "status": "external-media-validation-required",
            "blocking": True,
            "evidence_refs": ["required:attachment byte, cache, CDN/export, and local path validation"],
        },
        {
            "id": "reaction-read-edit-delete-semantics",
            "label": "Reaction, read, edit, delete, vanish, and ephemeral semantics are validated per service",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:service-specific state semantics corpus"],
        },
        {
            "id": "service-coverage-matrix",
            "label": "Supported service coverage matrix records tested export/native variants and unsupported variants",
            "status": "external-corpus-required",
            "blocking": True,
            "evidence_refs": ["required:WeChat/LINE/Discord/Instagram plus extended-service coverage matrix"],
        },
        {
            "id": "independent-extended-messenger-review",
            "label": "Independent reviewer signs off on service scope, schema versions, state semantics, media locality, and wording",
            "status": "external-review-required",
            "blocking": True,
            "evidence_refs": ["required:independent extended messenger validation review"],
        },
    ]
    ready_slot_ids = [
        str(slot.get("id"))
        for slot in evidence_slots
        if str(slot.get("status", "")).startswith("complete")
    ]
    blocking_slot_ids = [str(slot.get("id")) for slot in evidence_slots if slot.get("blocking")]
    plan: dict[str, object] = {
        "profile_version": EXTENDED_MESSENGER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 35,
        "gap_id": "#35",
        "batch_id": "commercial-uplift-031-035",
        "qc_prep_item_number": 41,
        "service": service or "unknown",
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "status": "report-validation-blocked",
        "commercial_grade": False,
        "artifact_goal": "Extended messenger service export/native schema, state, media, and coverage validation",
        "validation_commands": [
            {
                "id": "source-extended-messenger-manifest",
                "purpose": "Hash source export/native DB inventory and preserve service/source locator",
                "command": "rapidtriage manifest <mobile-export> --json",
            },
            {
                "id": "extended-messenger-import",
                "purpose": "Recreate RapidTriage extended messenger normalized rows and database inventory",
                "command": "rapidtriage artifacts <mobile-export> --kind mobile-export --output <case>/extended-messenger-export.json",
            },
            {
                "id": "trusted-extended-messenger-diff",
                "purpose": "Compare service rows with trusted export/native parser output",
                "command": "rapidtriage cross-tool-validate --rapid-output <case>/extended-messenger-export.json --reference-output <service>=<trusted-service-output.json> --backlog-item 35 --json",
            },
            {
                "id": "extended-messenger-authority-review",
                "purpose": "Attach lawful authority and controlled-reveal evidence before encrypted/native-store claims",
                "command": "rapidtriage forensic-validation-pack --case <case> --artifact extended-messenger-authority --json",
            },
            {
                "id": "extended-messenger-known-answer-run",
                "purpose": "Attach per-service schema, state, media, and coverage known-answer evidence",
                "command": "rapidtriage commercial-readiness --validation-package <extended-messenger-known-answer.json> --limit 35 --json",
            },
        ],
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slot_ids,
        "blocking_slot_ids": blocking_slot_ids,
        "ready_slot_count": len(ready_slot_ids),
        "blocking_slot_count": len(blocking_slot_ids),
        "commercial_grade_blockers": list(EXTENDED_MESSENGER_REPORT_GRADE_BLOCKERS),
        "report_guidance": "Use extended messenger rows as service export/native-inventory triage until trusted diff, per-service schema corpus, encrypted/ephemeral authority workflow, media locality, state semantics, service coverage matrix, and independent review are attached.",
    }
    plan["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def chat_app_core_accuracy_gates(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> list[dict[str, object]]:
    service = optional_text(details.get("service"))
    gap_ids = chat_app_gap_ids(service)
    if artifact_type not in {"mobile-message", "mobile-chat-database"} or not gap_ids:
        return []
    evidence_refs = [
        f"source_path:{optional_text(details.get('source_path'))}",
        f"source_tool:{source_tool}",
        f"source_format:{source_format}",
        f"source_index:{source_index}",
        f"service:{service}",
    ]
    if source_hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{source_hashes['sha256']}")
    manifest = details.get("messenger_export_framework_manifest")
    if isinstance(manifest, Mapping):
        manifest_hash = optional_text(manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"messenger_manifest_sha256:{manifest_hash}")
    kakaotalk_manifest = details.get("kakaotalk_parser_manifest")
    if isinstance(kakaotalk_manifest, Mapping):
        manifest_hash = optional_text(kakaotalk_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"kakaotalk_parser_manifest_sha256:{manifest_hash}")
    kakaotalk_validation_plan = details.get("kakaotalk_report_grade_validation_plan")
    if isinstance(kakaotalk_validation_plan, Mapping):
        validation_plan_hash = optional_text(kakaotalk_validation_plan.get("manifest_sha256"))
        if validation_plan_hash:
            evidence_refs.append(f"kakaotalk_report_grade_validation_plan_sha256:{validation_plan_hash}")
    whatsapp_manifest = details.get("whatsapp_parser_manifest")
    if isinstance(whatsapp_manifest, Mapping):
        manifest_hash = optional_text(whatsapp_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"whatsapp_parser_manifest_sha256:{manifest_hash}")
    whatsapp_validation_plan = details.get("whatsapp_report_grade_validation_plan")
    if isinstance(whatsapp_validation_plan, Mapping):
        validation_plan_hash = optional_text(whatsapp_validation_plan.get("manifest_sha256"))
        if validation_plan_hash:
            evidence_refs.append(f"whatsapp_report_grade_validation_plan_sha256:{validation_plan_hash}")
    telegram_manifest = details.get("telegram_parser_manifest")
    if isinstance(telegram_manifest, Mapping):
        manifest_hash = optional_text(telegram_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"telegram_parser_manifest_sha256:{manifest_hash}")
    telegram_validation_plan = details.get("telegram_report_grade_validation_plan")
    if isinstance(telegram_validation_plan, Mapping):
        validation_plan_hash = optional_text(telegram_validation_plan.get("manifest_sha256"))
        if validation_plan_hash:
            evidence_refs.append(f"telegram_report_grade_validation_plan_sha256:{validation_plan_hash}")
    signal_manifest = details.get("signal_parser_manifest")
    if isinstance(signal_manifest, Mapping):
        manifest_hash = optional_text(signal_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"signal_parser_manifest_sha256:{manifest_hash}")
    signal_validation_plan = details.get("signal_report_grade_validation_plan")
    if isinstance(signal_validation_plan, Mapping):
        validation_plan_hash = optional_text(signal_validation_plan.get("manifest_sha256"))
        if validation_plan_hash:
            evidence_refs.append(f"signal_report_grade_validation_plan_sha256:{validation_plan_hash}")
    extended_messenger_manifest = details.get("extended_messenger_parser_manifest")
    if isinstance(extended_messenger_manifest, Mapping):
        manifest_hash = optional_text(extended_messenger_manifest.get("manifest_sha256"))
        if manifest_hash:
            evidence_refs.append(f"extended_messenger_parser_manifest_sha256:{manifest_hash}")
    extended_messenger_validation_plan = details.get("extended_messenger_report_grade_validation_plan")
    if isinstance(extended_messenger_validation_plan, Mapping):
        validation_plan_hash = optional_text(extended_messenger_validation_plan.get("manifest_sha256"))
        if validation_plan_hash:
            evidence_refs.append(f"extended_messenger_report_grade_validation_plan_sha256:{validation_plan_hash}")
    messenger_schema_matrix = details.get("messenger_schema_compatibility_matrix")
    if isinstance(messenger_schema_matrix, Mapping):
        matrix_hash = optional_text(messenger_schema_matrix.get("manifest_sha256"))
        if matrix_hash:
            evidence_refs.append(f"messenger_schema_compatibility_matrix_sha256:{matrix_hash}")
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    trusted_diff = details.get("chat_app_trusted_diff") if isinstance(details.get("chat_app_trusted_diff"), Mapping) else {}
    issue_ids = {
        str(item.get("id"))
        for item in details.get("chat_app_issue_matrix", [])
        if isinstance(item, Mapping)
    }
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    gates: list[dict[str, object]] = []
    for gap_id in gap_ids:
        number = int(gap_id.strip("#"))
        satisfied: list[str] = []
        if isinstance(manifest, Mapping):
            satisfied.append("messenger export framework manifest")
            row_citation = manifest.get("row_citation")
            if isinstance(row_citation, Mapping) and row_citation.get("row_hash"):
                satisfied.append("messenger source row citation")
            if manifest.get("table_citation_count"):
                satisfied.append("messenger table citation inventory")
        if isinstance(messenger_schema_matrix, Mapping) and messenger_schema_matrix.get("matrix_rows"):
            satisfied.append("messenger schema compatibility matrix")
        if service and details.get("chat_app_scope_profile", {}).get("known_profile"):
            label = {
                31: "KakaoTalk service/profile detection",
                32: "WhatsApp service/profile detection",
                33: "Telegram service/profile detection",
                34: "Signal service/profile detection",
                35: "extended service/profile detection",
            }.get(number)
            if label:
                satisfied.append(label)
        if number == 31:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("chat/message participant/media normalization")
            if details.get("kakaotalk_message_review_profile"):
                satisfied.append("KakaoTalk message review profile")
            if details.get("kakaotalk_database_review_profile"):
                satisfied.append("KakaoTalk database schema review profile")
            if details.get("validation_checks", {}).get("kakaotalk_attachment_metadata_present"):
                satisfied.append("KakaoTalk attachment metadata tracking")
            if details.get("validation_checks", {}).get("kakaotalk_read_or_deleted_state_tracked"):
                satisfied.append("KakaoTalk read/deleted state tracking")
            if details.get("kakaotalk_compatibility_assessment") or details.get("schema_version") or details.get("app_version"):
                satisfied.append("schema/app version and BigBang compatibility tracking")
            if details.get("kakaotalk_compatibility_assessment", {}).get("strategy_profile"):
                satisfied.append("KakaoTalk legacy/post-BigBang strategy profile")
            if isinstance(details.get("kakaotalk_parser_manifest"), Mapping):
                satisfied.append("KakaoTalk parser manifest")
                if details.get("kakaotalk_parser_manifest", {}).get("row_citation", {}).get("row_hash"):
                    satisfied.append("KakaoTalk source row citation")
                if details.get("kakaotalk_parser_manifest", {}).get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("KakaoTalk review viewer controls")
            if isinstance(kakaotalk_validation_plan, Mapping):
                satisfied.append("KakaoTalk report-grade validation plan")
                if int(kakaotalk_validation_plan.get("ready_slot_count") or 0) >= 6:
                    satisfied.append("KakaoTalk validation ready slots")
            if "kakaotalk-post-2025-08-bigbang" in issue_ids or details.get("commercial_grade_blockers"):
                satisfied.append("encrypted/deleted limitation warning")
            if source_hashes.get("sha256") and source_tool:
                satisfied.append("source hash and legal provenance")
        elif number == 32:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("chat/contact/media normalization")
            if details.get("whatsapp_message_review_profile"):
                satisfied.append("WhatsApp message review profile")
            if details.get("whatsapp_database_review_profile"):
                satisfied.append("WhatsApp database schema review profile")
            if details.get("validation_checks", {}).get("whatsapp_jid_attribution_present"):
                satisfied.append("WhatsApp JID attribution tracking")
            if details.get("validation_checks", {}).get("whatsapp_media_metadata_present"):
                satisfied.append("WhatsApp media metadata tracking")
            if details.get("chat_app_strategy_profile"):
                satisfied.append("WhatsApp crypt/export strategy profile")
            if isinstance(details.get("whatsapp_parser_manifest"), Mapping):
                satisfied.append("WhatsApp parser manifest")
                if details.get("whatsapp_parser_manifest", {}).get("row_citation", {}).get("row_hash"):
                    satisfied.append("WhatsApp source row citation")
                if details.get("whatsapp_parser_manifest", {}).get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("WhatsApp review viewer controls")
            if isinstance(whatsapp_validation_plan, Mapping):
                satisfied.append("WhatsApp report-grade validation plan")
                if int(whatsapp_validation_plan.get("ready_slot_count") or 0) >= 6:
                    satisfied.append("WhatsApp validation ready slots")
            if details.get("commercial_grade_blockers") or not validation.get("decryption_attempted", True):
                satisfied.append("crypt backup authority workflow warning")
            if details.get("commercial_grade_blockers"):
                satisfied.append("deleted-row limitation warning")
            if source_hashes.get("sha256") and (details.get("app_version") is not None or details.get("chat_app_issue_matrix")):
                satisfied.append("source hash and app-version provenance")
        elif number == 33:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("chat/user/media attribution")
            if details.get("telegram_message_review_profile"):
                satisfied.append("Telegram message review profile")
            if details.get("telegram_database_review_profile"):
                satisfied.append("Telegram database/cache schema review profile")
            if details.get("validation_checks", {}).get("telegram_account_or_dialog_attribution_present"):
                satisfied.append("Telegram account/dialog attribution tracking")
            if details.get("validation_checks", {}).get("telegram_media_cache_metadata_present"):
                satisfied.append("Telegram media/cache metadata tracking")
            if details.get("chat_app_strategy_profile"):
                satisfied.append("Telegram export/cache strategy profile")
            if isinstance(details.get("telegram_parser_manifest"), Mapping):
                satisfied.append("Telegram parser manifest")
                if details.get("telegram_parser_manifest", {}).get("row_citation", {}).get("row_hash"):
                    satisfied.append("Telegram source row citation")
                if details.get("telegram_parser_manifest", {}).get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("Telegram review viewer controls")
            if isinstance(telegram_validation_plan, Mapping):
                satisfied.append("Telegram report-grade validation plan")
                if int(telegram_validation_plan.get("ready_slot_count") or 0) >= 6:
                    satisfied.append("Telegram validation ready slots")
            if source_hashes.get("sha256") and (details.get("message_id") or details.get("database_name") or table_summaries):
                satisfied.append("account/cache provenance")
            if details.get("commercial_grade_blockers"):
                satisfied.append("encrypted local store warning")
                satisfied.append("deleted/cache recovery limitation")
        elif number == 34:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("thread/recipient/message inventory")
            if details.get("signal_message_review_profile"):
                satisfied.append("Signal message review profile")
            if details.get("signal_database_review_profile"):
                satisfied.append("Signal database schema review profile")
            if details.get("validation_checks", {}).get("signal_thread_or_recipient_attribution_present"):
                satisfied.append("Signal thread/recipient attribution tracking")
            if details.get("validation_checks", {}).get("signal_attachment_metadata_present"):
                satisfied.append("Signal attachment metadata tracking")
            if details.get("chat_app_strategy_profile"):
                satisfied.append("Signal SQLCipher strategy profile")
            if isinstance(details.get("signal_parser_manifest"), Mapping):
                satisfied.append("Signal parser manifest")
                if details.get("signal_parser_manifest", {}).get("row_citation", {}).get("row_hash"):
                    satisfied.append("Signal source row citation")
                if details.get("signal_parser_manifest", {}).get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("Signal review viewer controls")
            if isinstance(signal_validation_plan, Mapping):
                satisfied.append("Signal report-grade validation plan")
                if int(signal_validation_plan.get("ready_slot_count") or 0) >= 6:
                    satisfied.append("Signal validation ready slots")
            if details.get("commercial_grade_blockers") or not validation.get("decryption_attempted", True):
                satisfied.append("SQLCipher/key authority gate")
            if details.get("commercial_grade_blockers"):
                satisfied.append("attachment/deleted limitation warning")
            if source_hashes.get("sha256") and source_tool:
                satisfied.append("secret-safe legal provenance")
        elif number == 35:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("message/media/reaction normalization")
            if details.get("extended_messenger_message_review_profile"):
                satisfied.append("extended messenger message review profile")
            if details.get("extended_messenger_database_review_profile"):
                satisfied.append("extended messenger database schema review profile")
            if details.get("validation_checks", {}).get("extended_messenger_thread_or_channel_present"):
                satisfied.append("extended messenger thread/channel attribution tracking")
            if details.get("validation_checks", {}).get("extended_messenger_attachment_metadata_present"):
                satisfied.append("extended messenger attachment metadata tracking")
            if details.get("chat_app_strategy_profile"):
                satisfied.append("extended messenger schema/ephemeral strategy profile")
            if isinstance(details.get("extended_messenger_parser_manifest"), Mapping):
                satisfied.append("extended messenger parser manifest")
                if details.get("extended_messenger_parser_manifest", {}).get("row_citation", {}).get("row_hash"):
                    satisfied.append("extended messenger source row citation")
                if details.get("extended_messenger_parser_manifest", {}).get("large_data_controls", {}).get("viewer_default"):
                    satisfied.append("extended messenger review viewer controls")
            if isinstance(extended_messenger_validation_plan, Mapping):
                satisfied.append("extended messenger report-grade validation plan")
                if int(extended_messenger_validation_plan.get("ready_slot_count") or 0) >= 6:
                    satisfied.append("extended messenger validation ready slots")
            if details.get("schema_version") is not None or details.get("chat_app_issue_matrix"):
                satisfied.append("schema/app version registry")
            if details.get("commercial_grade_blockers"):
                satisfied.append("encrypted/ephemeral limitation warning")
            if source_hashes.get("sha256") and source_tool:
                satisfied.append("source hash and legal provenance")
        trusted_check = CHAT_APP_TRUSTED_DIFF_CHECKS.get(number)
        if trusted_check and trusted_diff.get("status") == "pass":
            satisfied.append(trusted_check[0])
        gates.append(build_accuracy_gate(number, satisfied_checks=satisfied, evidence_refs=evidence_refs))
    return gates


def chat_app_review_payload(
    artifact_type: str,
    details: Mapping[str, object],
    *,
    source_tool: str = "",
    source_format: str = "",
    source_index: int = 0,
    source_hashes: Mapping[str, str] | None = None,
) -> dict[str, object]:
    service = optional_text(details.get("service"))
    if artifact_type == "mobile-message" and service not in CHAT_APP_GAP_IDS:
        return {}
    if artifact_type != "mobile-chat-database" and service not in CHAT_APP_GAP_IDS:
        return {}
    gap_ids = chat_app_gap_ids(service)
    report_grade = chat_app_report_grade_assessment(service)
    hashes = source_hashes or {}
    return {
        "chat_app_forensic_review": build_forensic_review(
            gap_id=gap_ids[0] if gap_ids else "#31",
            artifact_goal=f"{service or 'Chat app'} authorized export/database message evidence",
            primary_evidence=[
                f"artifact_type={artifact_type}",
                f"service={service or 'unknown'}",
                f"conversation_id={optional_text(details.get('conversation_id'))}",
                f"message_id={optional_text(details.get('message_id'))}",
                f"schema_version={optional_text(details.get('schema_version'))}",
            ],
            validation_required=True,
            report_grade_assessment=report_grade,
            blockers=chat_app_blockers(service),
            caveats=[
                "Service-specific encrypted stores, deleted rows, attachment recovery, and sync semantics remain validation-gated.",
                "Use original acquisition/export logs, app version, timezone, and account ownership before reporting message conclusions.",
            ],
        ),
        "chat_app_commercial_uplift_evidence": chat_app_commercial_uplift_evidence(
            artifact_type=artifact_type,
            service=service,
            source_tool=source_tool,
            source_format=source_format,
            source_index=source_index,
            source_hashes=hashes,
            details=details,
            report_grade=report_grade,
        ),
    }


def build_messenger_export_framework_manifest(
    *,
    artifact_type: str,
    service: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    row_citation = messenger_row_citation(
        artifact_type=artifact_type,
        service=service,
        source_tool=source_tool,
        source_format=source_format,
        source_index=source_index,
        source_hashes=source_hashes,
        source_path=source_path,
        details=details,
    )
    raw_table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    table_citations = [
        messenger_table_citation(
            service=service,
            source_path=source_path,
            source_hashes=source_hashes,
            row=table,
            source_index=index,
        )
        for index, table in enumerate(raw_table_summaries[:MAX_SQLITE_TABLES])
        if isinstance(table, Mapping)
    ]
    supported_services = [str(profile["service"]) for profile in CHAT_APP_PROFILES]
    legacy_gap_ids = chat_app_gap_ids(service)
    manifest: dict[str, object] = {
        "manifest_version": "messenger-export-framework-manifest-v1",
        "item_number": 50,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "gap_id": "#50",
        "commercial_gap_ids": ["#50", *legacy_gap_ids],
        "artifact_type": artifact_type,
        "service": service,
        "service_family": service_family(service),
        "known_service_profile": service in CHAT_APP_GAP_IDS,
        "supported_service_count": len(supported_services),
        "supported_services": supported_services,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "reaction_present": bool(optional_text(details.get("reaction"))),
        "mapped_legacy_gap_ids": legacy_gap_ids,
        "row_citation": row_citation,
        "table_citations": table_citations,
        "table_summary_count": len(raw_table_summaries),
        "table_citation_count": len(table_citations),
        "large_data_controls": {
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "max_chat_db_sample_rows": MAX_CHAT_DB_SAMPLE_ROWS,
            "table_inventory_capped": len(raw_table_summaries) >= MAX_SQLITE_TABLES,
            "text_values_hash_only_by_default": True,
            "raw_values_redacted_by_default": True,
        },
        "capability_statement": {
            "authorized_export_row_normalization": True,
            "service_specific_native_database_decode": False,
            "encrypted_store_decryption": False,
            "deleted_record_recovery": False,
            "attachment_binary_recovery": False,
            "known_answer_service_corpus": False,
        },
        "review_workflow": {
            "default_view": "chat-bubble-row-with-metadata-collapsed",
            "source_viewer": "authorized-export-row-or-sqlite-table-inventory",
            "metadata_collapsed_by_default": True,
            "recommended_grouping": ["service", "conversation_id", "sender", "timestamp"],
            "required_before_report": [
                "validate the service/app/schema version with known-answer data",
                "attach a trusted service export or native database diff for reportable rows",
                "verify encrypted-store authority and deleted/ephemeral semantics before content claims",
                "resolve media references against recovered attachment bytes before reporting media content",
            ],
        },
        "validation_status": "framework-implemented-validation-required",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def messenger_row_citation(
    *,
    artifact_type: str,
    service: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    payload = {
        "artifact_type": artifact_type,
        "service": service,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "timestamp": optional_text(details.get("timestamp")),
        "conversation_id": optional_text(details.get("conversation_id")),
        "conversation_title": optional_text(details.get("conversation_title")),
        "message_id": optional_text(details.get("message_id")),
        "message_text_sha256": optional_text(details.get("message_text_sha256")),
        "sender": optional_text(details.get("sender")),
        "recipient": optional_text(details.get("recipient")),
        "participant_count": messenger_participant_count(details),
        "media_reference_sha256": optional_text(details.get("media_reference_sha256")),
        "reaction": optional_text(details.get("reaction")),
        "schema_version": optional_text(details.get("schema_version")),
        "app_version": optional_text(details.get("app_version")),
    }
    return {
        **payload,
        "row_hash": stable_mobile_sha256(payload),
        "source_viewer_locator": {
            "viewer": "messenger-export-row",
            "source_path": str(source_path.resolve()),
            "source_index": source_index,
            "source_record_id": payload["source_record_id"],
            "service": service,
        },
        "validation_status": "messenger-export-row-citation",
    }


def messenger_table_citation(
    *,
    service: str,
    source_path: Path,
    source_hashes: Mapping[str, str],
    row: Mapping[str, object],
    source_index: int,
) -> dict[str, object]:
    table_name = optional_text(row.get("table") or row.get("table_name") or row.get("name"))
    payload = {
        "service": service,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_index": source_index,
        "table_name": table_name,
        "row_count": row.get("row_count"),
        "column_count": len(row.get("columns") or []) if isinstance(row.get("columns"), list) else 0,
        "columns_sample": [optional_text(column) for column in (row.get("columns") or [])[:20]]
        if isinstance(row.get("columns"), list)
        else [],
        "message_table_candidate": bool(row.get("message_table_candidate") or row.get("is_message_table")),
    }
    return {
        **payload,
        "row_hash": stable_mobile_sha256(payload),
        "source_viewer_locator": {
            "viewer": "sqlite-table-inventory",
            "source_path": str(source_path.resolve()),
            "table_name": payload["table_name"],
        },
        "validation_status": "messenger-database-table-citation",
    }


def messenger_participant_count(details: Mapping[str, object]) -> int:
    participant_count = details.get("participant_count")
    if isinstance(participant_count, int):
        return max(participant_count, 0)
    if isinstance(participant_count, str) and participant_count.strip().isdigit():
        return int(participant_count.strip())
    participants = details.get("participants")
    if isinstance(participants, Sequence) and not isinstance(participants, (str, bytes)):
        return len([item for item in participants if optional_text(item)])
    return len(
        {
            value
            for value in (optional_text(details.get("sender")), optional_text(details.get("recipient")))
            if value
        }
    )


def chat_app_commercial_uplift_evidence(
    *,
    artifact_type: str,
    service: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    gap_ids = chat_app_gap_ids(service)
    item_numbers = sorted(
        int(gap_id.lstrip("#"))
        for gap_id in gap_ids
        if gap_id.startswith("#") and gap_id.lstrip("#").isdigit()
    )
    qc_prep_item_numbers = chat_app_qc_prep_item_numbers(service)
    issue_matrix = [
        item for item in details.get("chat_app_issue_matrix") or [] if isinstance(item, Mapping)
    ]
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    objectives = {
        31: "Expose KakaoTalk export/database evidence, BigBang compatibility state, and schema/encryption/deleted-record blockers.",
        32: "Expose WhatsApp export/database evidence, msgstore/contact/media pivots, and crypt/deleted-row blockers.",
        33: "Expose Telegram export/database evidence, account/cache/media attribution, and encrypted local-store blockers.",
        34: "Expose Signal export/database evidence, thread/recipient inventory, and SQLCipher/key authority blockers.",
        35: "Expose extended messenger export evidence, service profile coverage, media/reaction pivots, and schema/ephemeral blockers.",
    }
    source_refs = [
        f"source_tool:{source_tool}",
        f"source_format:{source_format}",
        f"source_index:{source_index}",
        f"source_sha256:{source_hashes.get('sha256', '')}",
        f"artifact_type:{artifact_type}",
        f"service:{service or 'unknown'}",
    ]
    for key in ("conversation_id", "message_id", "database_name", "schema_version", "app_version"):
        value = optional_text(details.get(key))
        if value:
            source_refs.append(f"{key}:{value}")
    passed_issue_matrix_ids = [str(item.get("id")) for item in issue_matrix if item.get("passed")]
    failed_issue_matrix_ids = [str(item.get("id")) for item in issue_matrix if not item.get("passed")]
    trusted_diff = (
        details.get("chat_app_trusted_diff")
        if isinstance(details.get("chat_app_trusted_diff"), Mapping)
        else {"status": "not-attached", "commercial_grade_evidence": False}
    )
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    kakaotalk_manifest = (
        details.get("kakaotalk_parser_manifest")
        if isinstance(details.get("kakaotalk_parser_manifest"), Mapping)
        else {}
    )
    kakaotalk_validation_plan = (
        details.get("kakaotalk_report_grade_validation_plan")
        if isinstance(details.get("kakaotalk_report_grade_validation_plan"), Mapping)
        else {}
    )
    whatsapp_manifest = (
        details.get("whatsapp_parser_manifest")
        if isinstance(details.get("whatsapp_parser_manifest"), Mapping)
        else {}
    )
    whatsapp_validation_plan = (
        details.get("whatsapp_report_grade_validation_plan")
        if isinstance(details.get("whatsapp_report_grade_validation_plan"), Mapping)
        else {}
    )
    telegram_manifest = (
        details.get("telegram_parser_manifest")
        if isinstance(details.get("telegram_parser_manifest"), Mapping)
        else {}
    )
    telegram_validation_plan = (
        details.get("telegram_report_grade_validation_plan")
        if isinstance(details.get("telegram_report_grade_validation_plan"), Mapping)
        else {}
    )
    signal_manifest = (
        details.get("signal_parser_manifest")
        if isinstance(details.get("signal_parser_manifest"), Mapping)
        else {}
    )
    signal_validation_plan = (
        details.get("signal_report_grade_validation_plan")
        if isinstance(details.get("signal_report_grade_validation_plan"), Mapping)
        else {}
    )
    extended_messenger_manifest = (
        details.get("extended_messenger_parser_manifest")
        if isinstance(details.get("extended_messenger_parser_manifest"), Mapping)
        else {}
    )
    extended_messenger_validation_plan = (
        details.get("extended_messenger_report_grade_validation_plan")
        if isinstance(details.get("extended_messenger_report_grade_validation_plan"), Mapping)
        else {}
    )
    manifest_hash = optional_text(messenger_manifest.get("manifest_sha256"))
    kakaotalk_manifest_hash = optional_text(kakaotalk_manifest.get("manifest_sha256"))
    kakaotalk_validation_plan_hash = optional_text(kakaotalk_validation_plan.get("manifest_sha256"))
    whatsapp_manifest_hash = optional_text(whatsapp_manifest.get("manifest_sha256"))
    whatsapp_validation_plan_hash = optional_text(whatsapp_validation_plan.get("manifest_sha256"))
    telegram_manifest_hash = optional_text(telegram_manifest.get("manifest_sha256"))
    telegram_validation_plan_hash = optional_text(telegram_validation_plan.get("manifest_sha256"))
    signal_manifest_hash = optional_text(signal_manifest.get("manifest_sha256"))
    signal_validation_plan_hash = optional_text(signal_validation_plan.get("manifest_sha256"))
    extended_messenger_manifest_hash = optional_text(extended_messenger_manifest.get("manifest_sha256"))
    extended_messenger_validation_plan_hash = optional_text(extended_messenger_validation_plan.get("manifest_sha256"))
    if manifest_hash:
        source_refs.append(f"messenger_manifest_sha256:{manifest_hash}")
    if kakaotalk_manifest_hash:
        source_refs.append(f"kakaotalk_parser_manifest_sha256:{kakaotalk_manifest_hash}")
    if kakaotalk_validation_plan_hash:
        source_refs.append(f"kakaotalk_report_grade_validation_plan_sha256:{kakaotalk_validation_plan_hash}")
    if whatsapp_manifest_hash:
        source_refs.append(f"whatsapp_parser_manifest_sha256:{whatsapp_manifest_hash}")
    if whatsapp_validation_plan_hash:
        source_refs.append(f"whatsapp_report_grade_validation_plan_sha256:{whatsapp_validation_plan_hash}")
    if telegram_manifest_hash:
        source_refs.append(f"telegram_parser_manifest_sha256:{telegram_manifest_hash}")
    if telegram_validation_plan_hash:
        source_refs.append(f"telegram_report_grade_validation_plan_sha256:{telegram_validation_plan_hash}")
    if signal_manifest_hash:
        source_refs.append(f"signal_parser_manifest_sha256:{signal_manifest_hash}")
    if signal_validation_plan_hash:
        source_refs.append(f"signal_report_grade_validation_plan_sha256:{signal_validation_plan_hash}")
    if extended_messenger_manifest_hash:
        source_refs.append(f"extended_messenger_parser_manifest_sha256:{extended_messenger_manifest_hash}")
    if extended_messenger_validation_plan_hash:
        source_refs.append(
            f"extended_messenger_report_grade_validation_plan_sha256:{extended_messenger_validation_plan_hash}"
        )
    return {
        "batch_id": "commercial-uplift-031-035",
        "item_numbers": item_numbers,
        "qc_prep_item_numbers": qc_prep_item_numbers,
        "qc_prep_contracts": chat_app_qc_prep_contracts(service),
        "functional_priority_profile": messenger_export_functional_profile(
            artifact_type=artifact_type,
            service=service,
            source_tool=source_tool,
            source_format=source_format,
            source_hashes=source_hashes,
            details=details,
            item_numbers=item_numbers,
            failed_issue_matrix_ids=failed_issue_matrix_ids,
            trusted_diff=trusted_diff,
        ),
        "implementation_track": "messenger-service-parser-validation",
        "objective": " ".join(objectives[number] for number in item_numbers if number in objectives),
        "reportability_decision": chat_app_reportability_decision(
            service=service,
            item_numbers=item_numbers,
            source_tool=source_tool,
            artifact_type=artifact_type,
            failed_issue_matrix_ids=failed_issue_matrix_ids,
            report_grade=report_grade,
            details=details,
            trusted_diff=trusted_diff,
        ),
        "chat_app_trusted_diff": trusted_diff,
        "source_refs": source_refs,
        "passed_issue_matrix_ids": passed_issue_matrix_ids,
        "failed_issue_matrix_ids": failed_issue_matrix_ids,
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or chat_app_blockers(service)),
        "large_data_controls": {
            "max_sqlite_tables": MAX_SQLITE_TABLES,
            "max_chat_db_sample_rows": MAX_CHAT_DB_SAMPLE_ROWS,
            "table_summary_count": len(table_summaries),
            "messenger_export_framework_manifest_hash": manifest_hash,
            "messenger_row_citation_present": bool(
                isinstance(messenger_manifest.get("row_citation"), Mapping)
                and messenger_manifest.get("row_citation", {}).get("row_hash")
            ),
            "messenger_table_citation_count": int(messenger_manifest.get("table_citation_count") or 0),
            "kakaotalk_parser_manifest_hash": kakaotalk_manifest_hash,
            "kakaotalk_report_grade_validation_plan_hash": kakaotalk_validation_plan_hash,
            "kakaotalk_report_grade_validation_ready_slot_count": int(
                kakaotalk_validation_plan.get("ready_slot_count") or 0
            ),
            "kakaotalk_report_grade_validation_blocking_slot_count": int(
                kakaotalk_validation_plan.get("blocking_slot_count") or 0
            ),
            "kakaotalk_source_row_citation_present": bool(
                isinstance(kakaotalk_manifest.get("row_citation"), Mapping)
                and kakaotalk_manifest.get("row_citation", {}).get("row_hash")
            ),
            "kakaotalk_review_viewer_controls_present": bool(
                isinstance(kakaotalk_manifest.get("large_data_controls"), Mapping)
                and kakaotalk_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "whatsapp_parser_manifest_hash": whatsapp_manifest_hash,
            "whatsapp_report_grade_validation_plan_hash": whatsapp_validation_plan_hash,
            "whatsapp_report_grade_validation_ready_slot_count": int(
                whatsapp_validation_plan.get("ready_slot_count") or 0
            ),
            "whatsapp_report_grade_validation_blocking_slot_count": int(
                whatsapp_validation_plan.get("blocking_slot_count") or 0
            ),
            "whatsapp_source_row_citation_present": bool(
                isinstance(whatsapp_manifest.get("row_citation"), Mapping)
                and whatsapp_manifest.get("row_citation", {}).get("row_hash")
            ),
            "whatsapp_review_viewer_controls_present": bool(
                isinstance(whatsapp_manifest.get("large_data_controls"), Mapping)
                and whatsapp_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "telegram_parser_manifest_hash": telegram_manifest_hash,
            "telegram_report_grade_validation_plan_hash": telegram_validation_plan_hash,
            "telegram_report_grade_validation_ready_slot_count": int(
                telegram_validation_plan.get("ready_slot_count") or 0
            ),
            "telegram_report_grade_validation_blocking_slot_count": int(
                telegram_validation_plan.get("blocking_slot_count") or 0
            ),
            "telegram_source_row_citation_present": bool(
                isinstance(telegram_manifest.get("row_citation"), Mapping)
                and telegram_manifest.get("row_citation", {}).get("row_hash")
            ),
            "telegram_review_viewer_controls_present": bool(
                isinstance(telegram_manifest.get("large_data_controls"), Mapping)
                and telegram_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "signal_parser_manifest_hash": signal_manifest_hash,
            "signal_report_grade_validation_plan_hash": signal_validation_plan_hash,
            "signal_report_grade_validation_ready_slot_count": int(
                signal_validation_plan.get("ready_slot_count") or 0
            ),
            "signal_report_grade_validation_blocking_slot_count": int(
                signal_validation_plan.get("blocking_slot_count") or 0
            ),
            "signal_source_row_citation_present": bool(
                isinstance(signal_manifest.get("row_citation"), Mapping)
                and signal_manifest.get("row_citation", {}).get("row_hash")
            ),
            "signal_review_viewer_controls_present": bool(
                isinstance(signal_manifest.get("large_data_controls"), Mapping)
                and signal_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "extended_messenger_parser_manifest_hash": extended_messenger_manifest_hash,
            "extended_messenger_report_grade_validation_plan_hash": extended_messenger_validation_plan_hash,
            "extended_messenger_report_grade_validation_ready_slot_count": int(
                extended_messenger_validation_plan.get("ready_slot_count") or 0
            ),
            "extended_messenger_report_grade_validation_blocking_slot_count": int(
                extended_messenger_validation_plan.get("blocking_slot_count") or 0
            ),
            "extended_messenger_source_row_citation_present": bool(
                isinstance(extended_messenger_manifest.get("row_citation"), Mapping)
                and extended_messenger_manifest.get("row_citation", {}).get("row_hash")
            ),
            "extended_messenger_review_viewer_controls_present": bool(
                isinstance(extended_messenger_manifest.get("large_data_controls"), Mapping)
                and extended_messenger_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "known_service_profile": service in CHAT_APP_GAP_IDS,
            "kakaotalk_message_review_profile_present": bool(details.get("kakaotalk_message_review_profile")),
            "kakaotalk_database_review_profile_present": bool(details.get("kakaotalk_database_review_profile")),
            "whatsapp_message_review_profile_present": bool(details.get("whatsapp_message_review_profile")),
            "whatsapp_database_review_profile_present": bool(details.get("whatsapp_database_review_profile")),
            "telegram_message_review_profile_present": bool(details.get("telegram_message_review_profile")),
            "telegram_database_review_profile_present": bool(details.get("telegram_database_review_profile")),
            "signal_message_review_profile_present": bool(details.get("signal_message_review_profile")),
            "signal_database_review_profile_present": bool(details.get("signal_database_review_profile")),
            "extended_messenger_message_review_profile_present": bool(details.get("extended_messenger_message_review_profile")),
            "extended_messenger_database_review_profile_present": bool(details.get("extended_messenger_database_review_profile")),
            "service_specific_native_database_decode": False,
            "encrypted_store_decryption": False,
            "deleted_record_recovery": False,
            "known_answer_service_corpus_required": True,
        },
        "next_internal_step": "Add service/version-specific schema mappers, encrypted-store authority workflows, attachment recovery checks, and known-answer corpora for each messenger.",
        "external_evidence_required": True,
    }


def messenger_export_functional_profile(
    *,
    artifact_type: str,
    service: str,
    source_tool: str,
    source_format: str,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
    item_numbers: list[int],
    failed_issue_matrix_ids: list[str],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    table_summaries = details.get("table_summaries") if isinstance(details.get("table_summaries"), list) else []
    messenger_manifest = (
        details.get("messenger_export_framework_manifest")
        if isinstance(details.get("messenger_export_framework_manifest"), Mapping)
        else {}
    )
    kakaotalk_manifest = (
        details.get("kakaotalk_parser_manifest")
        if isinstance(details.get("kakaotalk_parser_manifest"), Mapping)
        else {}
    )
    kakaotalk_validation_plan = (
        details.get("kakaotalk_report_grade_validation_plan")
        if isinstance(details.get("kakaotalk_report_grade_validation_plan"), Mapping)
        else {}
    )
    whatsapp_manifest = (
        details.get("whatsapp_parser_manifest")
        if isinstance(details.get("whatsapp_parser_manifest"), Mapping)
        else {}
    )
    whatsapp_validation_plan = (
        details.get("whatsapp_report_grade_validation_plan")
        if isinstance(details.get("whatsapp_report_grade_validation_plan"), Mapping)
        else {}
    )
    telegram_manifest = (
        details.get("telegram_parser_manifest")
        if isinstance(details.get("telegram_parser_manifest"), Mapping)
        else {}
    )
    telegram_validation_plan = (
        details.get("telegram_report_grade_validation_plan")
        if isinstance(details.get("telegram_report_grade_validation_plan"), Mapping)
        else {}
    )
    signal_manifest = (
        details.get("signal_parser_manifest")
        if isinstance(details.get("signal_parser_manifest"), Mapping)
        else {}
    )
    signal_validation_plan = (
        details.get("signal_report_grade_validation_plan")
        if isinstance(details.get("signal_report_grade_validation_plan"), Mapping)
        else {}
    )
    extended_messenger_manifest = (
        details.get("extended_messenger_parser_manifest")
        if isinstance(details.get("extended_messenger_parser_manifest"), Mapping)
        else {}
    )
    extended_messenger_validation_plan = (
        details.get("extended_messenger_report_grade_validation_plan")
        if isinstance(details.get("extended_messenger_report_grade_validation_plan"), Mapping)
        else {}
    )
    failed_checks: list[str] = []
    if not service or service not in CHAT_APP_GAP_IDS:
        failed_checks.append("messenger-service-profile-not-known")
    if not source_hashes.get("sha256"):
        failed_checks.append("messenger-source-sha256-missing")
    if failed_issue_matrix_ids:
        failed_checks.extend(f"issue:{item}" for item in failed_issue_matrix_ids)
    if trusted_diff.get("status") != "pass":
        failed_checks.append("messenger-trusted-export-or-native-db-diff-required")
    if not messenger_manifest:
        failed_checks.append("messenger-export-framework-manifest-not-emitted")
    if "KakaoTalk" == service and not kakaotalk_manifest:
        failed_checks.append("kakaotalk-parser-manifest-not-emitted")
    if "KakaoTalk" == service and not kakaotalk_validation_plan:
        failed_checks.append("kakaotalk-report-grade-validation-plan-not-emitted")
    if service == "WhatsApp" and not whatsapp_manifest:
        failed_checks.append("whatsapp-parser-manifest-not-emitted")
    if service == "WhatsApp" and not whatsapp_validation_plan:
        failed_checks.append("whatsapp-report-grade-validation-plan-not-emitted")
    if service == "Telegram" and not telegram_manifest:
        failed_checks.append("telegram-parser-manifest-not-emitted")
    if service == "Telegram" and not telegram_validation_plan:
        failed_checks.append("telegram-report-grade-validation-plan-not-emitted")
    if service == "Signal" and not signal_manifest:
        failed_checks.append("signal-parser-manifest-not-emitted")
    if service == "Signal" and not signal_validation_plan:
        failed_checks.append("signal-report-grade-validation-plan-not-emitted")
    if chat_app_gap_ids(service) == ["#35"] and not extended_messenger_manifest:
        failed_checks.append("extended-messenger-parser-manifest-not-emitted")
    if chat_app_gap_ids(service) == ["#35"] and not extended_messenger_validation_plan:
        failed_checks.append("extended-messenger-report-grade-validation-plan-not-emitted")
    row_citation = messenger_manifest.get("row_citation") if isinstance(messenger_manifest, Mapping) else {}
    kakaotalk_row_citation = kakaotalk_manifest.get("row_citation") if isinstance(kakaotalk_manifest, Mapping) else {}
    whatsapp_row_citation = whatsapp_manifest.get("row_citation") if isinstance(whatsapp_manifest, Mapping) else {}
    telegram_row_citation = telegram_manifest.get("row_citation") if isinstance(telegram_manifest, Mapping) else {}
    signal_row_citation = signal_manifest.get("row_citation") if isinstance(signal_manifest, Mapping) else {}
    extended_messenger_row_citation = (
        extended_messenger_manifest.get("row_citation") if isinstance(extended_messenger_manifest, Mapping) else {}
    )
    if not isinstance(row_citation, Mapping) or not row_citation.get("row_hash"):
        failed_checks.append("messenger-source-row-citation-not-emitted")
    if service == "KakaoTalk" and (
        not isinstance(kakaotalk_row_citation, Mapping) or not kakaotalk_row_citation.get("row_hash")
    ):
        failed_checks.append("kakaotalk-source-row-citation-not-emitted")
    if service == "WhatsApp" and (
        not isinstance(whatsapp_row_citation, Mapping) or not whatsapp_row_citation.get("row_hash")
    ):
        failed_checks.append("whatsapp-source-row-citation-not-emitted")
    if service == "Telegram" and (
        not isinstance(telegram_row_citation, Mapping) or not telegram_row_citation.get("row_hash")
    ):
        failed_checks.append("telegram-source-row-citation-not-emitted")
    if service == "Signal" and (
        not isinstance(signal_row_citation, Mapping) or not signal_row_citation.get("row_hash")
    ):
        failed_checks.append("signal-source-row-citation-not-emitted")
    if chat_app_gap_ids(service) == ["#35"] and (
        not isinstance(extended_messenger_row_citation, Mapping) or not extended_messenger_row_citation.get("row_hash")
    ):
        failed_checks.append("extended-messenger-source-row-citation-not-emitted")
    supported_services = [str(profile["service"]) for profile in CHAT_APP_PROFILES]
    manifest_hash = optional_text(messenger_manifest.get("manifest_sha256"))
    kakaotalk_manifest_hash = optional_text(kakaotalk_manifest.get("manifest_sha256"))
    kakaotalk_validation_plan_hash = optional_text(kakaotalk_validation_plan.get("manifest_sha256"))
    whatsapp_manifest_hash = optional_text(whatsapp_manifest.get("manifest_sha256"))
    whatsapp_validation_plan_hash = optional_text(whatsapp_validation_plan.get("manifest_sha256"))
    telegram_manifest_hash = optional_text(telegram_manifest.get("manifest_sha256"))
    telegram_validation_plan_hash = optional_text(telegram_validation_plan.get("manifest_sha256"))
    signal_manifest_hash = optional_text(signal_manifest.get("manifest_sha256"))
    signal_validation_plan_hash = optional_text(signal_validation_plan.get("manifest_sha256"))
    extended_messenger_manifest_hash = optional_text(extended_messenger_manifest.get("manifest_sha256"))
    extended_messenger_validation_plan_hash = optional_text(extended_messenger_validation_plan.get("manifest_sha256"))
    table_citation_count = int(messenger_manifest.get("table_citation_count") or 0)
    passed_validation_check_ids = [
        "authorized-export-row-normalized",
        "messenger-service-profile-detected",
        "message-participant-media-reaction-fields-normalized",
        "chat-database-table-inventory-enabled",
        "secret-values-not-exposed-by-default",
    ]
    if messenger_manifest:
        passed_validation_check_ids.append("messenger-export-framework-manifest-emitted")
    if isinstance(row_citation, Mapping) and row_citation.get("source_viewer_locator"):
        passed_validation_check_ids.append("messenger-source-locator-emitted")
    if table_citation_count:
        passed_validation_check_ids.append("messenger-table-citation-inventory-emitted")
    if kakaotalk_manifest:
        passed_validation_check_ids.append("kakaotalk-parser-manifest-emitted")
    if kakaotalk_validation_plan:
        passed_validation_check_ids.append("kakaotalk-report-grade-validation-plan-emitted")
    if isinstance(kakaotalk_row_citation, Mapping) and kakaotalk_row_citation.get("source_viewer_locator"):
        passed_validation_check_ids.append("kakaotalk-source-locator-emitted")
    if whatsapp_manifest:
        passed_validation_check_ids.append("whatsapp-parser-manifest-emitted")
    if whatsapp_validation_plan:
        passed_validation_check_ids.append("whatsapp-report-grade-validation-plan-emitted")
    if isinstance(whatsapp_row_citation, Mapping) and whatsapp_row_citation.get("source_viewer_locator"):
        passed_validation_check_ids.append("whatsapp-source-locator-emitted")
    if telegram_manifest:
        passed_validation_check_ids.append("telegram-parser-manifest-emitted")
    if telegram_validation_plan:
        passed_validation_check_ids.append("telegram-report-grade-validation-plan-emitted")
    if isinstance(telegram_row_citation, Mapping) and telegram_row_citation.get("source_viewer_locator"):
        passed_validation_check_ids.append("telegram-source-locator-emitted")
    if signal_manifest:
        passed_validation_check_ids.append("signal-parser-manifest-emitted")
    if signal_validation_plan:
        passed_validation_check_ids.append("signal-report-grade-validation-plan-emitted")
    if isinstance(signal_row_citation, Mapping) and signal_row_citation.get("source_viewer_locator"):
        passed_validation_check_ids.append("signal-source-locator-emitted")
    if extended_messenger_manifest:
        passed_validation_check_ids.append("extended-messenger-parser-manifest-emitted")
    if extended_messenger_validation_plan:
        passed_validation_check_ids.append("extended-messenger-report-grade-validation-plan-emitted")
    if isinstance(extended_messenger_row_citation, Mapping) and extended_messenger_row_citation.get("source_viewer_locator"):
        passed_validation_check_ids.append("extended-messenger-source-locator-emitted")
    return {
        "item_number": 50,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "qc_prep_item_numbers": chat_app_qc_prep_item_numbers(service),
        "qc_prep_contracts": chat_app_qc_prep_contracts(service),
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "artifact_type": artifact_type,
            "service": service,
            "service_family": service_family(service),
            "source_tool": source_tool,
            "source_format": source_format,
            "source_sha256_present": bool(source_hashes.get("sha256")),
            "known_service_profile": service in CHAT_APP_GAP_IDS,
            "supported_service_count": len(supported_services),
            "supported_services": supported_services,
            "conversation_id_present": bool(optional_text(details.get("conversation_id"))),
            "message_id_present": bool(optional_text(details.get("message_id"))),
            "message_text_hash_present": bool(optional_text(details.get("message_text_sha256"))),
            "media_reference_hash_present": bool(optional_text(details.get("media_reference_sha256"))),
            "reaction_present": bool(optional_text(details.get("reaction"))),
            "table_summary_count": len(table_summaries),
            "messenger_export_framework_manifest_hash": manifest_hash,
            "messenger_row_citation_present": bool(isinstance(row_citation, Mapping) and row_citation.get("row_hash")),
            "messenger_table_citation_count": table_citation_count,
            "kakaotalk_parser_manifest_hash": kakaotalk_manifest_hash,
            "kakaotalk_report_grade_validation_plan_hash": kakaotalk_validation_plan_hash,
            "kakaotalk_row_citation_present": bool(
                isinstance(kakaotalk_row_citation, Mapping) and kakaotalk_row_citation.get("row_hash")
            ),
            "whatsapp_parser_manifest_hash": whatsapp_manifest_hash,
            "whatsapp_report_grade_validation_plan_hash": whatsapp_validation_plan_hash,
            "whatsapp_row_citation_present": bool(
                isinstance(whatsapp_row_citation, Mapping) and whatsapp_row_citation.get("row_hash")
            ),
            "telegram_parser_manifest_hash": telegram_manifest_hash,
            "telegram_report_grade_validation_plan_hash": telegram_validation_plan_hash,
            "telegram_row_citation_present": bool(
                isinstance(telegram_row_citation, Mapping) and telegram_row_citation.get("row_hash")
            ),
            "signal_parser_manifest_hash": signal_manifest_hash,
            "signal_report_grade_validation_plan_hash": signal_validation_plan_hash,
            "signal_row_citation_present": bool(
                isinstance(signal_row_citation, Mapping) and signal_row_citation.get("row_hash")
            ),
            "extended_messenger_parser_manifest_hash": extended_messenger_manifest_hash,
            "extended_messenger_report_grade_validation_plan_hash": extended_messenger_validation_plan_hash,
            "extended_messenger_row_citation_present": bool(
                isinstance(extended_messenger_row_citation, Mapping)
                and extended_messenger_row_citation.get("row_hash")
            ),
            "mapped_legacy_items": item_numbers,
            "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        },
        "passed_validation_check_ids": passed_validation_check_ids,
        "failed_validation_check_ids": sorted(set(failed_checks)),
        "reportability_decision": {
            "allowed_use": "messenger-authorized-export-or-database-triage-pivot",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Messenger content remains service/version/export scoped until schema, encryption, deleted-state, attachment, and trusted diff evidence are attached.",
        },
    }


def chat_app_reportability_decision(
    *,
    service: str,
    item_numbers: list[int],
    source_tool: str,
    artifact_type: str,
    failed_issue_matrix_ids: list[str],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers") or chat_app_blockers(service) if str(item)}
    blockers.update(f"issue:{item}" for item in failed_issue_matrix_ids)
    if service == "KakaoTalk":
        compatibility = details.get("kakaotalk_compatibility_assessment")
        if isinstance(compatibility, Mapping) and not compatibility.get("report_grade_ready"):
            blockers.update(str(item) for item in compatibility.get("blockers") or [] if str(item))
    if not trusted_diff or trusted_diff.get("status") != "pass":
        for number in item_numbers:
            trusted_check = CHAT_APP_TRUSTED_DIFF_CHECKS.get(number)
            if trusted_check:
                blockers.add(trusted_check[1])
    primary = item_numbers[0] if item_numbers else 35
    decisions = {
        31: ("do-not-report-kakaotalk-message-content-as-decrypted-complete", "kakaotalk-export-or-inventory-triage-pivot"),
        32: ("do-not-report-whatsapp-message-content-as-crypt-or-deleted-complete", "whatsapp-export-or-db-inventory-triage-pivot"),
        33: ("do-not-report-telegram-message-content-as-local-store-complete", "telegram-export-or-cache-triage-pivot"),
        34: ("do-not-report-signal-message-content-as-sqlcipher-complete", "signal-export-or-inventory-triage-pivot"),
        35: ("do-not-report-extended-messenger-content-as-service-complete", "extended-messenger-export-triage-pivot"),
    }
    decision, allowed_use = decisions.get(primary, ("do-not-report-messenger-content-as-commercial-grade", "messenger-triage-pivot"))
    return {
        "profile_version": "messenger-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}" for number in item_numbers],
        "qc_prep_item_numbers": chat_app_qc_prep_item_numbers(service),
        "qc_prep_contracts": chat_app_qc_prep_contracts(service),
        "decision": decision,
        "allowed_use": allowed_use,
        "service": service or "unknown",
        "source_tool": source_tool,
        "artifact_type": artifact_type,
        "blockers": sorted(blockers),
        "failed_issue_matrix_ids": list(failed_issue_matrix_ids),
        "message_text_hash_only_default": True,
        "encrypted_store_decryption_complete": False,
        "deleted_record_recovery_complete": False,
        "ready_for_court_report": False,
        "required_before_report": [
            "attach app/service version, account ownership, timezone, and original acquisition/export logs",
            "validate service-specific schema and deleted/ephemeral semantics against known-answer corpora",
            "document encrypted-store or key/authority workflow before relying on message content",
            "cross-check important rows against the original forensic tool or service export view",
        ],
    }


def chat_app_qc_prep_item_numbers(service: str) -> list[int]:
    item_number = QC_PREP_CHAT_APP_ITEMS.get(service)
    if item_number:
        return [item_number]
    return [41] if chat_app_gap_ids(service) == ["#35"] else []


def chat_app_qc_prep_contracts(service: str) -> list[dict[str, object]]:
    return [dict(QC_PREP_CHAT_APP_CONTRACTS[number]) for number in chat_app_qc_prep_item_numbers(service)]


def chat_app_native_capabilities(service: str) -> dict[str, object]:
    capabilities = dict(CHAT_APP_NATIVE_CAPABILITIES)
    capabilities["service"] = service or "unknown"
    capabilities["known_service_profile"] = service in CHAT_APP_GAP_IDS
    return capabilities


def chat_app_strategy_profile(service: str, *, artifact_type: str, details: Mapping[str, object]) -> dict[str, object]:
    profile = chat_app_profile(service)
    service_key = service_family(service)
    tracks = {
        "whatsapp": "whatsapp-export-msgstore-crypt-validation",
        "telegram": "telegram-export-cache-account-attribution",
        "signal": "signal-sqlcipher-authority-gated-inventory",
        "wechat": "extended-service-export-schema-validation",
        "line": "extended-service-export-schema-validation",
        "discord": "extended-service-export-schema-validation",
        "instagram": "extended-service-export-schema-validation",
        "facebook-messenger": "extended-service-export-schema-validation",
    }
    expected_pivots = {
        "whatsapp": ["msgstore.db", "wa.db", "Contact JID", "media path", "crypt backup key authority"],
        "telegram": ["tdata/export JSON", "account id", "dialog id", "cache/media path", "secret chat warning"],
        "signal": ["signal.db", "recipient/thread/message tables", "attachment pointers", "SQLCipher key authority"],
        "wechat": ["export chat rows", "media/reaction/read-state fields", "account attribution"],
        "line": ["export chat rows", "media/reaction/read-state fields", "account attribution"],
        "discord": ["package/export JSON", "channel/message/attachment ids", "edited/deleted visibility"],
        "instagram": ["package/export JSON", "thread/message/media ids", "ephemeral limitation"],
        "facebook-messenger": ["package/export JSON", "thread/message/media ids", "reaction/read-state fields"],
    }
    encrypted_services = {"Signal", "WhatsApp", "Telegram", "Session", "Wickr", "Threema", "Wire"}
    ephemeral_services = {"Signal", "Telegram", "WhatsApp", "Instagram", "Snapchat", "Session", "Wickr"}
    attachment_services = {
        "Signal",
        "Telegram",
        "WhatsApp",
        "Facebook Messenger",
        "Instagram",
        "Discord",
        "Slack",
        "Microsoft Teams",
    }
    blockers = [
        "known-answer-service-corpus-not-attached",
        "trusted-export-or-native-database-diff-required",
    ]
    if service in encrypted_services:
        blockers.append("encrypted-store-or-backup-key-authority-not-validated")
    if service in ephemeral_services:
        blockers.append("ephemeral-or-deleted-message-semantics-not-validated")
    if service in attachment_services:
        blockers.append("attachment-locality-and-hash-validation-required")
    return {
        "profile_version": "chat-app-strategy-v1",
        "service": service or "unknown",
        "artifact_type": artifact_type,
        "selected_track": tracks.get(service_key, "generic-authorized-export-schema-validation"),
        "known_profile": profile is not None,
        "mapped_gap_ids": chat_app_gap_ids(service),
        "expected_source_pivots": expected_pivots.get(service_key, ["authorized export row", "source hash", "app version"]),
        "message_content_reportable": False,
        "protected_store_strategy": (
            "authority-gated-key-or-export-validation-required"
            if service in encrypted_services
            else "authorized-export-and-schema-validation-required"
        ),
        "attachment_validation_required": service in attachment_services,
        "ephemeral_or_deleted_semantics_required": service in ephemeral_services,
        "app_version_present": bool(optional_text(details.get("app_version"))),
        "schema_version_present": bool(optional_text(details.get("schema_version"))),
        "conversation_id_present": bool(optional_text(details.get("conversation_id"))),
        "message_id_present": bool(optional_text(details.get("message_id"))),
        "table_inventory_present": bool(details.get("table_summaries")),
        "blockers": blockers,
        "required_before_report": [
            "capture app/service version, account ownership, timezone, and acquisition/export logs",
            "validate schema and deleted/ephemeral behavior against a known-answer corpus",
            "attach a trusted export/native database diff for important message rows",
            "verify attachment bytes or explicitly report attachment metadata-only status",
        ],
    }


def chat_app_scope_profile(service: str) -> dict[str, object]:
    profile = chat_app_profile(service)
    return {
        "service": service or "unknown",
        "known_profile": profile is not None,
        "alias_count": len(profile.get("aliases", ())) if profile else 0,
        "message_table_candidates": list(profile.get("message_tables", ())) if profile else [],
        "support_tier": "explicit-profile" if profile else "generic-mobile-message",
        "collection_mode": "authorized-export-or-inventory",
        "reporting_boundary": "review-candidate-only",
    }


def chat_app_issue_matrix(service: str, *, artifact_type: str, app_version: str = "") -> list[dict[str, object]]:
    encrypted = service in {"Signal", "WhatsApp", "Telegram", "Session", "Wickr", "Threema", "Wire"}
    ephemeral = service in {"Signal", "Telegram", "WhatsApp", "Instagram", "Snapchat", "Session", "Wickr"}
    attachment_sync = service in {"Signal", "Telegram", "WhatsApp", "Facebook Messenger", "Instagram", "Discord", "Slack", "Microsoft Teams"}
    issues = [
        {
            "id": "service-profile-known",
            "label": "Service has an explicit RapidTriage profile",
            "passed": service in CHAT_APP_GAP_IDS,
            "severity": "high",
        },
        {
            "id": "encrypted-store-authority",
            "label": "Encrypted store/keychain/backup-key workflow is validated when required",
            "passed": False,
            "severity": "critical" if encrypted else "high",
        },
        {
            "id": "ephemeral-message-warning",
            "label": "Disappearing/secret-chat/deleted-message limitations are surfaced",
            "passed": True,
            "severity": "critical" if ephemeral else "medium",
        },
        {
            "id": "attachment-locality",
            "label": "Attachment/media presence is verified, not just link or thumbnail metadata",
            "passed": False,
            "severity": "high" if attachment_sync else "medium",
        },
        {
            "id": "schema-version-known-answer",
            "label": "App version and schema are validated against known-answer data",
            "passed": False,
            "severity": "critical",
        },
        {
            "id": "database-row-decode",
            "label": "Native database rows are decoded rather than inventoried only",
            "passed": False,
            "severity": "critical",
        },
    ]
    if service == "KakaoTalk":
        compatibility = kakaotalk_compatibility_assessment(app_version)
        issues.append(
            {
                "id": "kakaotalk-post-2025-08-bigbang",
                "label": "KakaoTalk post-2025-08-13 / 25.7.2 encryption and deletion-behavior changes are handled",
                "passed": False,
                "severity": "critical",
                "status": compatibility["status"],
                "legacy_method_applicable": compatibility["legacy_method_applicable"],
            }
        )
    return issues


def kakaotalk_compatibility_payload(service: str, app_version: str) -> dict[str, object]:
    if service != "KakaoTalk":
        return {}
    return {"kakaotalk_compatibility_assessment": kakaotalk_compatibility_assessment(app_version)}


def kakaotalk_compatibility_assessment(app_version: str) -> dict[str, object]:
    status = "unknown-version-validation-required"
    if app_version and version_at_least(app_version, KAKAOTALK_BIGBANG_VERSION):
        status = "post-bigbang-legacy-method-not-applicable"
    elif app_version:
        status = "pre-bigbang-version-declared-still-validation-required"
    strategy_profile = {
        "profile_version": "kakaotalk-analysis-strategy-v1",
        "selected_track": (
            "post-bigbang-memory-key-store-and-export-validation"
            if status == "post-bigbang-legacy-method-not-applicable"
            else "legacy-deviceinfo-userdir-validation"
            if status == "pre-bigbang-version-declared-still-validation-required"
            else "version-first-triage"
        ),
        "legacy_edb_method_allowed_without_validation": False,
        "requires_app_version_capture": True,
        "requires_memory_or_key_store_correlation": status != "pre-bigbang-version-declared-still-validation-required",
        "requires_trusted_export_or_native_db_diff": True,
        "message_content_reportable": False,
    }
    return {
        "status": status,
        "app_version": app_version or "unknown",
        "strategy_profile": strategy_profile,
        "bigbang_release_date": KAKAOTALK_BIGBANG_RELEASE_DATE,
        "bigbang_minimum_version": KAKAOTALK_BIGBANG_VERSION,
        "bigbang_reference_build": KAKAOTALK_BIGBANG_RELEASE_BUILD,
        "legacy_method_applicable": False if status != "pre-bigbang-version-declared-still-validation-required" else "not-assumed",
        "report_grade_ready": False,
        "validation_required": True,
        "required_validation": [
            "Record KakaoTalk app version/build, OS version, acquisition type, and vendor parser version.",
            "Treat post-2025-08-13/25.7.2 KakaoTalk stores as incompatible with legacy decoding assumptions until independently validated.",
            "Use authorized export, original device acquisition metadata, and cross-tool/known-answer diff before reporting message content.",
        ],
        "blockers": [
            "KakaoTalk 25.7.2 release notes include enhanced encryption and deletion-behavior changes.",
            "RapidTriage does not decrypt KakaoTalk protected stores or recover post-patch deleted records.",
            "No post-BigBang KakaoTalk known-answer corpus is bundled.",
        ],
    }


def chat_app_profile(service: str) -> Mapping[str, object] | None:
    for profile in CHAT_APP_PROFILES:
        if str(profile["service"]).lower() == service.lower():
            return profile
    return None


def chat_app_report_grade_assessment(service: str) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": chat_app_gap_ids(service),
        "service": service or "unknown",
        "blockers": chat_app_blockers(service),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Verify service/app version, database schema version, timezone semantics, and account ownership.",
            "Validate message, deletion, attachment, and sync-state behavior against service-specific known-answer data.",
        ],
    }
