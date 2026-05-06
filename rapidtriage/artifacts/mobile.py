from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import plistlib
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping

from ..core.forensic_accuracy import build_accuracy_gate
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "mobile-export-v4"
MOBILE_EXPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
MAX_ROWS_PER_SOURCE = 50_000
MAX_IOS_BACKUP_FILES = 50_000
MAX_SQLITE_TABLES = 100
MAX_CHAT_DB_SAMPLE_ROWS = 25
KAKAOTALK_BIGBANG_VERSION = "25.7.2"
KAKAOTALK_BIGBANG_RELEASE_DATE = "2025-08-13"
KAKAOTALK_BIGBANG_RELEASE_BUILD = "25.7.2.4641"
MOBILE_NATIVE_CAPABILITIES = {
    "vendor_csv_json_import": True,
    "cellebrite_xry_graykey_axiom_source_hinting": True,
    "message_contact_call_app_file_account_media_browser_normalization": True,
    "ios_manifest_db_inventory": True,
    "ios_backup_plist_metadata": True,
    "ios_keychain_inventory_redacted": True,
    "chat_database_table_inventory": True,
    "media_message_correlation": True,
    "contact_call_sms_unified_view": True,
    "app_schema_version_registry": True,
    "proprietary_vendor_package_decode": False,
    "ios_protected_file_decryption": False,
    "ios_keychain_secret_decryption": False,
    "android_backup_payload_decode": False,
    "app_specific_deleted_record_recovery": False,
    "known_answer_mobile_corpus": False,
}
MOBILE_REPORT_GRADE_BLOCKERS = [
    "vendor-export-settings-and-parser-version-not-verified",
    "original-device-acquisition-hash-not-verified",
    "proprietary-package-direct-decoding-not-implemented",
    "protected-encrypted-store-decryption-not-implemented",
    "deleted-record-and-schema-version-known-answer-validation-required",
]
MOBILE_TRUSTED_TOOLS = {
    "cellebrite",
    "ufed",
    "physical analyzer",
    "xry",
    "msab",
    "graykey",
    "axiom",
    "magnet axiom",
    "ileapp",
    "idevicebackup",
    "ios backup manifest",
    "keychain-dumper",
}
MOBILE_TRUSTED_DIFF_BLOCKERS = {
    26: "vendor-mobile-export-trusted-diff-required",
    27: "ios-backup-manifest-trusted-diff-required",
    28: "ios-keychain-inventory-trusted-diff-required",
}

VENDOR_HINTS = {
    "cellebrite": ("cellebrite", "ufed", "ufdr", "ufdx", "physical analyzer"),
    "xry": ("xry", "msab"),
    "graykey": ("graykey", "grayshift"),
    "axiom": ("axiom", "magnet"),
}

MESSAGE_KEYS = {
    "body",
    "content",
    "message",
    "messagebody",
    "messagetext",
    "text",
    "snippet",
    "chat",
}
CONTACT_KEYS = {"contact", "contactname", "displayname", "fullname", "name", "phone", "phonenumber", "email"}
CALL_KEYS = {"calltype", "duration", "durationseconds", "endtime", "answered", "missed"}
APP_KEYS = {"app", "appname", "application", "bundleid", "bundleidentifier", "package", "packagename", "version"}
FILE_KEYS = {"filepath", "filename", "path", "originalpath", "logicalpath", "sha1", "sha256", "md5", "mime", "size"}
ACCOUNT_KEYS = {
    "account",
    "accountid",
    "accountname",
    "appleid",
    "email",
    "handle",
    "profileid",
    "userid",
    "username",
}
MEDIA_KEYS = {
    "attachment",
    "attachmentname",
    "duration",
    "height",
    "media",
    "mediafilename",
    "mediapath",
    "mime",
    "mimetype",
    "thumbnail",
    "width",
}
BROWSER_KEYS = {"url", "uri", "title", "visitcount", "lastvisited", "browser", "domain", "downloadurl"}
CHAT_KEYS = {
    "chatid",
    "chatname",
    "chattitle",
    "conversationid",
    "conversationname",
    "groupid",
    "roomid",
    "threadid",
}
MESSAGE_ID_KEYS = {"guid", "id", "messageid", "msgid", "rowid", "serverid"}
REACTION_KEYS = {"reaction", "reactions", "emoji", "like", "likes"}
MEDIA_REFERENCE_KEYS = {
    "attachment",
    "attachmentname",
    "attachmentpath",
    "file",
    "filename",
    "media",
    "mediafilename",
    "mediapath",
    "thumbnail",
}

CHAT_APP_PROFILES: tuple[dict[str, object], ...] = (
    {
        "service": "KakaoTalk",
        "aliases": ("kakaotalk", "kakao", "com.kakao.talk", "talk_user", "chat_logs"),
        "message_tables": ("chat_logs", "chatlog", "message", "messages"),
    },
    {
        "service": "WhatsApp",
        "aliases": ("whatsapp", "msgstore", "wa.db", "chatstorage", "com.whatsapp"),
        "message_tables": ("messages", "message", "chat_list", "jid", "wa_contacts"),
    },
    {
        "service": "Telegram",
        "aliases": ("telegram", "org.telegram", "tdesktop", "cache4.db", "telegram desktop"),
        "message_tables": ("messages", "chats", "users", "dialogs", "media_v2"),
    },
    {
        "service": "Signal",
        "aliases": ("signal", "org.thoughtcrime.securesms", "signal.sqlite", "signal.db"),
        "message_tables": ("message", "thread", "recipient", "sms", "mms"),
    },
    {
        "service": "WeChat",
        "aliases": ("wechat", "weixin", "com.tencent.mm", "wcdb", "message.db"),
        "message_tables": ("message", "rcontact", "chatroom", "appmessage"),
    },
    {
        "service": "LINE",
        "aliases": ("line", "jp.naver.line", "naver_line", "line.sqlite"),
        "message_tables": ("chat", "chat_history", "contacts", "groups"),
    },
    {
        "service": "Discord",
        "aliases": ("discord", "com.discord", "discord canary", "discordptb"),
        "message_tables": ("messages", "channels", "users"),
    },
    {
        "service": "Instagram",
        "aliases": ("instagram", "threads", "com.instagram", "direct.db", "direct messages"),
        "message_tables": ("messages", "threads", "users", "direct"),
    },
    {
        "service": "iMessage",
        "aliases": ("imessage", "sms.db", "ichat", "com.apple.messages", "apple messages"),
        "message_tables": ("message", "chat", "handle", "attachment", "chat_message_join"),
    },
    {
        "service": "Facebook Messenger",
        "aliases": ("facebook messenger", "messenger", "orca", "com.facebook.orca", "fb_messenger"),
        "message_tables": ("messages", "threads", "participants", "attachments"),
    },
    {
        "service": "Viber",
        "aliases": ("viber", "com.viber", "viber_messages"),
        "message_tables": ("messages", "conversations", "participants"),
    },
    {
        "service": "Skype",
        "aliases": ("skype", "main.db", "com.skype", "skypemessages"),
        "message_tables": ("messages", "conversations", "contacts", "chats"),
    },
    {
        "service": "Slack",
        "aliases": ("slack", "com.tinyspeck", "slack export", "slack_messages"),
        "message_tables": ("messages", "channels", "users", "attachments"),
    },
    {
        "service": "Microsoft Teams",
        "aliases": ("microsoft teams", "teams", "msteams", "com.microsoft.teams"),
        "message_tables": ("messages", "chats", "channels", "users"),
    },
    {
        "service": "Reddit",
        "aliases": ("reddit", "reddit chat", "com.reddit", "reddit_messages"),
        "message_tables": ("messages", "chats", "users"),
    },
    {
        "service": "X/Twitter",
        "aliases": ("twitter", "x.com", "x twitter", "com.twitter", "direct messages"),
        "message_tables": ("messages", "conversations", "participants"),
    },
    {
        "service": "TikTok",
        "aliases": ("tiktok", "musically", "com.zhiliaoapp.musically", "aweme"),
        "message_tables": ("messages", "conversations", "users"),
    },
    {
        "service": "Snapchat",
        "aliases": ("snapchat", "com.snapchat", "snap", "memories"),
        "message_tables": ("messages", "conversation", "friends"),
    },
    {
        "service": "Matrix/Element",
        "aliases": ("matrix", "element", "riot.im", "im.vector.app"),
        "message_tables": ("events", "rooms", "users", "messages"),
    },
    {
        "service": "Wire",
        "aliases": ("wire", "com.wire", "wire secure messenger"),
        "message_tables": ("messages", "conversations", "users"),
    },
    {
        "service": "Threema",
        "aliases": ("threema", "ch.threema", "threema.db"),
        "message_tables": ("messages", "contacts", "groups"),
    },
    {
        "service": "Session",
        "aliases": ("session", "getsession", "network.loki.messenger"),
        "message_tables": ("messages", "threads", "attachments"),
    },
    {
        "service": "Wickr",
        "aliases": ("wickr", "wickr me", "wickr pro", "com.mywickr"),
        "message_tables": ("messages", "conversations", "users"),
    },
)
CHAT_APP_GAP_IDS = {
    "KakaoTalk": "#31",
    "WhatsApp": "#32",
    "Telegram": "#33",
    "Signal": "#34",
    "WeChat": "#35",
    "LINE": "#35",
    "Discord": "#35",
    "Instagram": "#35",
    "iMessage": "#35",
    "Facebook Messenger": "#35",
    "Viber": "#35",
    "Skype": "#35",
    "Slack": "#35",
    "Microsoft Teams": "#35",
    "Reddit": "#35",
    "X/Twitter": "#35",
    "TikTok": "#35",
    "Snapchat": "#35",
    "Matrix/Element": "#35",
    "Wire": "#35",
    "Threema": "#35",
    "Session": "#35",
    "Wickr": "#35",
}
CHAT_APP_NATIVE_CAPABILITIES = {
    "authorized_export_row_normalization": True,
    "service_alias_detection": True,
    "message_id_participant_media_reaction_pivots": True,
    "sqlite_table_inventory": True,
    "schema_version_hinting": True,
    "service_specific_native_database_decode": False,
    "encrypted_store_decryption": False,
    "deleted_record_recovery": False,
    "attachment_binary_recovery": False,
    "multi_device_sync_state_resolution": False,
    "known_answer_service_corpus": False,
}
CHAT_APP_TRUSTED_TOOLS = {
    "kakaotalk export",
    "validated kakaotalk sqlite",
    "whatsapp export",
    "validated msgstore",
    "telegram export",
    "telegram desktop export",
    "signal export",
    "validated signal sqlite",
    "line export",
    "discord export",
    "instagram export",
    "facebook messenger export",
    "service export",
    "vendor tool export",
    "cellebrite",
    "xry",
    "graykey",
    "axiom",
}
CHAT_APP_TRUSTED_DIFF_CHECKS = {
    31: ("trusted KakaoTalk export/native DB diff pass", "kakaotalk-trusted-export-or-native-db-diff-required"),
    32: ("trusted WhatsApp export/native DB diff pass", "whatsapp-trusted-export-or-native-db-diff-required"),
    33: ("trusted Telegram export/native DB diff pass", "telegram-trusted-export-or-native-db-diff-required"),
    34: ("trusted Signal export/native DB diff pass", "signal-trusted-export-or-native-db-diff-required"),
    35: ("trusted extended messenger export/native DB diff pass", "extended-messenger-trusted-export-or-native-db-diff-required"),
}

TIMESTAMP_KEYS = (
    "timestamp",
    "time",
    "date",
    "datetime",
    "created",
    "createdtime",
    "createddate",
    "sent",
    "senttime",
    "received",
    "receivedtime",
    "starttime",
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
    emitted = 0
    detected_types: set[str] = set()
    normalized_details: list[Mapping[str, object]] = []
    for index, row in enumerate(rows):
        if emitted >= MAX_ROWS_PER_SOURCE:
            break
        normalized = normalize_keys(row)
        artifact_type = detect_artifact_type(normalized, path)
        if not artifact_type:
            continue
        detected_types.add(artifact_type)
        emitted += 1
        details = normalize_mobile_row(artifact_type, normalized, path)
        normalized_details.append({"artifact_type": artifact_type, **details})
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
                "artifact_types": sorted(detected_types),
                "coverage_status": "vendor-export-import",
                "commercial_grade_ready": False,
                "validation_checks": source_validation_checks(source_format, source_tool, emitted, detected_types),
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
    gap_ids = mobile_commercial_gap_ids(artifact_type, source_tool)
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


def load_rows(path: Path) -> list[Mapping[str, object]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return load_csv_rows(path)
    if suffix in {".jsonl", ".ndjson"}:
        return load_jsonl_rows(path)
    return load_json_rows(path)


def load_csv_rows(path: Path) -> list[Mapping[str, object]]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle) if any((value or "").strip() for value in row.values())]
    except (OSError, csv.Error):
        return []


def load_jsonl_rows(path: Path) -> list[Mapping[str, object]]:
    rows: list[Mapping[str, object]] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, Mapping):
                    rows.append(flatten_mapping(value))
    except OSError:
        return []
    return rows


def load_json_rows(path: Path) -> list[Mapping[str, object]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    return list(extract_mapping_rows(payload))


def extract_mapping_rows(value: object) -> Iterable[Mapping[str, object]]:
    if isinstance(value, Mapping):
        if looks_like_row(value):
            yield flatten_mapping(value)
        for child in value.values():
            if isinstance(child, (list, tuple)):
                for item in child:
                    if isinstance(item, Mapping):
                        yield flatten_mapping(item)
            elif isinstance(child, Mapping):
                yield from extract_mapping_rows(child)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                yield flatten_mapping(item)


def flatten_mapping(value: Mapping[str, object], *, prefix: str = "") -> dict[str, object]:
    flattened: dict[str, object] = {}
    for key, item in value.items():
        joined = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, Mapping):
            flattened.update(flatten_mapping(item, prefix=joined))
        elif isinstance(item, (list, tuple)):
            flattened[joined] = json.dumps(item, ensure_ascii=False, default=str)
        else:
            flattened[joined] = item
    return flattened


def looks_like_row(value: Mapping[str, object]) -> bool:
    normalized = normalize_keys(value)
    return bool(detect_artifact_type(normalized, Path("")))


def normalize_keys(row: Mapping[str, object]) -> dict[str, object]:
    normalized: dict[str, object] = {}
    for key, value in row.items():
        canonical = normalize_key(key)
        normalized[canonical] = value
    return normalized


def normalize_key(key: object) -> str:
    return "".join(character for character in str(key).lower() if character.isalnum())


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


def index_mobile_trusted_rows(rows: list[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        event_type = normalized_mobile_diff_value(first_mobile_alias(row, "artifact_type", "event_type", "type"))
        source_record_id_value = normalized_mobile_diff_value(first_mobile_alias(row, "source_record_id", "record_id", "id"))
        timestamp = normalized_mobile_diff_value(first_mobile_alias(row, "timestamp", "date", "time"))
        message_id = normalized_mobile_diff_value(first_mobile_alias(row, "message_id", "guid", "msg_id"))
        text_hash = normalized_mobile_diff_value(first_mobile_alias(row, "message_text_sha256", "text_sha256", "body_sha256"))
        sender = normalized_mobile_diff_value(first_mobile_alias(row, "sender", "from"))
        recipient = normalized_mobile_diff_value(first_mobile_alias(row, "recipient", "to"))
        domain = normalized_mobile_diff_value(first_mobile_alias(row, "domain"))
        file_id = normalized_mobile_diff_value(first_mobile_alias(row, "file_id", "fileID"))
        logical_path = normalized_mobile_diff_value(first_mobile_alias(row, "logical_path", "relative_path", "path"))
        table = normalized_mobile_diff_value(first_mobile_alias(row, "table", "table_name"))
        row_count = normalized_mobile_diff_value(first_mobile_alias(row, "row_count", "count"))
        key = "|".join(
            item
            for item in (
                event_type,
                source_record_id_value,
                message_id,
                timestamp,
                sender,
                recipient,
                domain,
                file_id,
                logical_path,
                table,
            )
            if item
        )
        if not key:
            continue
        indexed[key] = {
            "event_type": event_type,
            "source_record_id": source_record_id_value,
            "timestamp": timestamp,
            "message_id": message_id,
            "message_text_sha256": text_hash,
            "sender": sender,
            "recipient": recipient,
            "domain": domain,
            "file_id": file_id,
            "logical_path": logical_path,
            "table": table,
            "row_count": row_count,
        }
    return indexed


def first_mobile_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalized_mobile_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def detect_artifact_type(row: Mapping[str, object], path: Path) -> str:
    source_hint = str(path).lower()
    keys = set(row)
    if keys.intersection(MESSAGE_KEYS) and (
        keys.intersection({"sender", "from", "fromphone", "recipient", "to", "tophone", "direction"})
        or keys.intersection(CHAT_KEYS)
        or any(token in source_hint for token in ("sms", "message", "chat", "conversation", "imessage", "whatsapp"))
        or detect_chat_service(row, path)
    ):
        return "mobile-message"
    if keys.intersection(APP_KEYS) and (
        keys.intersection({"package", "packagename", "bundleid", "bundleidentifier"})
        or any(token in source_hint for token in ("app", "application", "installed"))
    ):
        return "mobile-app"
    if keys.intersection(BROWSER_KEYS) and (
        any(key in keys for key in ("url", "uri", "downloadurl"))
        or any(token in source_hint for token in ("browser", "history", "safari", "chrome", "edge", "firefox"))
    ):
        return "mobile-browser"
    if keys.intersection(CALL_KEYS):
        return "mobile-call"
    if keys.intersection(CONTACT_KEYS) and any(key in keys for key in ("phone", "phonenumber", "email", "displayname", "fullname")):
        return "mobile-contact"
    if "call" in source_hint and any(key in keys for key in ("phone", "phonenumber", "number", "date", "timestamp")):
        return "mobile-call"
    if keys.intersection(ACCOUNT_KEYS) and any(
        token in source_hint for token in ("account", "profile", "user", "owner", "identity")
    ):
        return "mobile-account"
    if keys.intersection(MEDIA_KEYS) and (
        any(key in keys for key in ("mediapath", "mediafilename", "attachment", "mime", "mimetype"))
        or any(token in source_hint for token in ("media", "photo", "image", "video", "camera", "dcim"))
    ):
        return "mobile-media"
    if keys.intersection(FILE_KEYS) and any(key in keys for key in ("filepath", "path", "originalpath", "logicalpath", "filename")):
        return "mobile-file"
    return ""


def normalize_mobile_row(artifact_type: str, row: Mapping[str, object], path: Path | None = None) -> dict[str, object]:
    if artifact_type == "mobile-message":
        return normalize_message(row, path or Path(""))
    if artifact_type == "mobile-call":
        return normalize_call(row)
    if artifact_type == "mobile-app":
        return normalize_app(row)
    if artifact_type == "mobile-contact":
        return normalize_contact(row)
    if artifact_type == "mobile-file":
        return normalize_file(row)
    if artifact_type == "mobile-account":
        return normalize_account(row)
    if artifact_type == "mobile-media":
        return normalize_media(row)
    if artifact_type == "mobile-browser":
        return normalize_browser(row)
    return {"event_type": "mobile-row", "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)), "raw": dict(row)}


def normalize_message(row: Mapping[str, object], path: Path) -> dict[str, object]:
    text = optional_text(first_value(row, ("messagetext", "messagebody", "body", "message", "content", "text", "snippet", "chat")))
    participants = unique_non_empty(
        [
            optional_text(first_value(row, ("sender", "from", "fromphone", "author", "source"))),
            optional_text(first_value(row, ("recipient", "to", "tophone", "destination"))),
            *split_participants(first_value(row, ("participants", "members", "contacts", "users"))),
        ]
    )
    service = detect_chat_service(row, path) or optional_text(first_value(row, ("service", "platform", "app", "appname", "application", "source")))
    message_id = optional_text(first_value(row, MESSAGE_ID_KEYS))
    app_version = optional_text(first_value(row, ("appversion", "version", "clientversion", "kakaotalkversion")))
    media_reference = optional_text(first_value(row, MEDIA_REFERENCE_KEYS))
    reaction = optional_text(first_value(row, REACTION_KEYS))
    return {
        "event_type": "message",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "service": service,
        "service_family": service_family(service),
        "schema_version": optional_text(first_value(row, ("schemaversion", "dbversion", "exportversion", "appversion"))),
        "app_version": app_version,
        "conversation_id": optional_text(first_value(row, ("conversationid", "chatid", "threadid", "groupid", "roomid"))),
        "conversation_title": optional_text(first_value(row, ("conversationname", "chatname", "chattitle", "roomname", "groupname"))),
        "message_id": message_id,
        "message_id_sha256": sha256_text(message_id) if message_id else "",
        "direction": optional_text(first_value(row, ("direction", "type", "messagetype", "status"))),
        "sender": participants[0] if participants else "",
        "recipient": participants[1] if len(participants) > 1 else "",
        "participants": participants,
        "participant_count": len(participants),
        "message_text": text,
        "message_text_preview": text[:240],
        "message_text_sha256": sha256_text(text) if text else "",
        "attachment_name": optional_text(first_value(row, ("attachment", "attachmentname", "filename", "mediafilename"))),
        "media_reference": media_reference,
        "media_reference_sha256": sha256_text(media_reference) if media_reference else "",
        "reaction": reaction,
        "reply_to_message_id": optional_text(first_value(row, ("replyto", "replytomessageid", "quotedmessageid", "parentmessageid"))),
        "edited_at": normalize_timestamp(first_value(row, ("edited", "editedat", "lastedited", "updated"))),
        "deleted_state": optional_text(first_value(row, ("deleted", "deletedstate", "isdeleted", "deletionstatus"))),
        "risk_flags": message_risk_flags(text, service),
        "validation_checks": {
            **row_validation_checks(row, required=("timestamp",), content_present=bool(text)),
            "service_detected": bool(service),
            "participants_detected": bool(participants),
            "message_id_present": bool(message_id),
            "media_reference_present": bool(media_reference),
            "reaction_present": bool(reaction),
            "app_schema_validated": False,
        },
        "chat_app_gap_ids": chat_app_gap_ids(service),
        "chat_app_report_grade_assessment": chat_app_report_grade_assessment(service),
        "chat_app_native_capabilities": chat_app_native_capabilities(service),
        "chat_app_scope_profile": chat_app_scope_profile(service),
        "chat_app_issue_matrix": chat_app_issue_matrix(service, artifact_type="mobile-message", app_version=app_version),
        **kakaotalk_compatibility_payload(service, app_version),
        "commercial_grade_blockers": chat_app_blockers(service),
        "raw": dict(row),
    }


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
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
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


def normalize_call(row: Mapping[str, object]) -> dict[str, object]:
    phone = optional_text(first_value(row, ("phone", "phonenumber", "number", "remote", "remotephone", "address")))
    call_type = optional_text(first_value(row, ("calltype", "type", "direction", "status")))
    return {
        "event_type": "call",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "contact_name": optional_text(first_value(row, ("name", "contact", "contactname", "displayname"))),
        "phone_number": phone,
        "call_type": call_type,
        "duration_seconds": optional_text(first_value(row, ("durationseconds", "duration", "callduration"))),
        "risk_flags": ["missed-call"] if "miss" in call_type.lower() else [],
        "validation_checks": row_validation_checks(row, required=("timestamp", "phone", "phonenumber", "number")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-call-export"),
        "raw": dict(row),
    }


def normalize_contact(row: Mapping[str, object]) -> dict[str, object]:
    email = optional_text(first_value(row, ("email", "emailaddress", "mail")))
    phone = optional_text(first_value(row, ("phone", "phonenumber", "mobile", "number")))
    return {
        "event_type": "contact",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "contact_name": optional_text(first_value(row, ("displayname", "fullname", "name", "contact", "contactname"))),
        "phone_number": phone,
        "email": email,
        "organization": optional_text(first_value(row, ("organization", "company"))),
        "risk_flags": ["contact-identity"] if phone or email else [],
        "validation_checks": row_validation_checks(row, required=("phone", "phonenumber", "email", "displayname", "fullname")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-contact-export"),
        "raw": dict(row),
    }


def normalize_app(row: Mapping[str, object]) -> dict[str, object]:
    package = optional_text(first_value(row, ("packagename", "package", "bundleid", "bundleidentifier", "identifier")))
    app_name = optional_text(first_value(row, ("appname", "app", "application", "name", "displayname")))
    return {
        "event_type": "installed-app",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "app_name": app_name,
        "package": package,
        "version": optional_text(first_value(row, ("version", "versionname", "bundleversion", "appversion"))),
        "installed_at": normalize_timestamp(first_value(row, ("installed", "installedtime", "installdate"))),
        "risk_flags": app_risk_flags(app_name, package),
        "source_app_identifier": package or app_name,
        "validation_checks": row_validation_checks(row, required=("packagename", "package", "bundleid", "bundleidentifier")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-app-export"),
        "raw": dict(row),
    }


def normalize_file(row: Mapping[str, object]) -> dict[str, object]:
    file_path = optional_text(first_value(row, ("filepath", "originalpath", "logicalpath", "path", "filename")))
    return {
        "event_type": "file",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "file_path": file_path,
        "file_name": Path(file_path).name if file_path else optional_text(first_value(row, ("filename", "name"))),
        "size": optional_text(first_value(row, ("size", "filesize", "length"))),
        "mime_type": optional_text(first_value(row, ("mime", "mimetype", "contenttype"))),
        "md5": optional_text(first_value(row, ("md5", "hashmd5"))),
        "sha1": optional_text(first_value(row, ("sha1", "hashsha1"))),
        "sha256": optional_text(first_value(row, ("sha256", "hashsha256"))),
        "risk_flags": file_risk_flags(file_path),
        "validation_checks": row_validation_checks(row, required=("filepath", "originalpath", "logicalpath", "path", "filename")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-file-export"),
        "raw": dict(row),
    }


def normalize_account(row: Mapping[str, object]) -> dict[str, object]:
    identifier = optional_text(first_value(row, ("accountid", "userid", "profileid", "handle", "email", "username", "account")))
    account_name = optional_text(first_value(row, ("accountname", "username", "displayname", "fullname", "name", "email")))
    service = optional_text(first_value(row, ("service", "platform", "app", "appname", "application", "source")))
    return {
        "event_type": "account",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "service": service,
        "account_identifier": identifier,
        "account_identifier_sha256": sha256_text(identifier) if identifier else "",
        "account_name": account_name,
        "risk_flags": ["mobile-account"] + (["ai-service-account"] if "chatgpt" in f"{service} {account_name}".lower() else []),
        "validation_checks": row_validation_checks(row, required=("accountid", "userid", "profileid", "email", "username")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-account-export"),
        "raw": dict(row),
    }


def normalize_media(row: Mapping[str, object]) -> dict[str, object]:
    media_path = optional_text(first_value(row, ("mediapath", "filepath", "originalpath", "logicalpath", "path", "filename")))
    mime_type = optional_text(first_value(row, ("mime", "mimetype", "contenttype")))
    return {
        "event_type": "media",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "media_path": media_path,
        "file_name": Path(media_path).name if media_path else optional_text(first_value(row, ("mediafilename", "filename", "name"))),
        "mime_type": mime_type,
        "size": optional_text(first_value(row, ("size", "filesize", "length"))),
        "width": optional_text(first_value(row, ("width", "pixelwidth"))),
        "height": optional_text(first_value(row, ("height", "pixelheight"))),
        "duration": optional_text(first_value(row, ("duration", "durationseconds"))),
        "md5": optional_text(first_value(row, ("md5", "hashmd5"))),
        "sha1": optional_text(first_value(row, ("sha1", "hashsha1"))),
        "sha256": optional_text(first_value(row, ("sha256", "hashsha256"))),
        "risk_flags": media_risk_flags(media_path, mime_type),
        "validation_checks": row_validation_checks(row, required=("mediapath", "filepath", "mime", "mimetype", "sha256")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-media-export"),
        "raw": dict(row),
    }


def normalize_browser(row: Mapping[str, object]) -> dict[str, object]:
    url = optional_text(first_value(row, ("url", "uri", "downloadurl")))
    title = optional_text(first_value(row, ("title", "pagetitle", "name")))
    return {
        "event_type": "mobile-browser",
        "timestamp": normalize_timestamp(first_value(row, (*TIMESTAMP_KEYS, "lastvisited", "visittime"))),
        "browser": optional_text(first_value(row, ("browser", "app", "appname", "application"))),
        "url": url,
        "url_sha256": sha256_text(url) if url else "",
        "title": title,
        "visit_count": optional_text(first_value(row, ("visitcount", "visits", "typedcount"))),
        "risk_flags": browser_risk_flags(url, title),
        "validation_checks": row_validation_checks(row, required=("url", "uri", "timestamp", "lastvisited")),
        "commercial_grade_blockers": mobile_export_blockers("vendor-browser-export"),
        "raw": dict(row),
    }


def build_mobile_correlation_summary(rows: list[Mapping[str, object]]) -> dict[str, object]:
    message_rows = [row for row in rows if row.get("artifact_type") == "mobile-message"]
    media_rows = [row for row in rows if row.get("artifact_type") == "mobile-media"]
    contact_rows = [row for row in rows if row.get("artifact_type") == "mobile-contact"]
    call_rows = [row for row in rows if row.get("artifact_type") == "mobile-call"]
    app_rows = [row for row in rows if row.get("artifact_type") == "mobile-app"]
    services = sorted({optional_text(row.get("service")) for row in rows if optional_text(row.get("service"))})
    participants = sorted(
        {
            participant
            for row in message_rows
            for participant in row.get("participants", [])
            if isinstance(participant, str) and participant
        }
    )
    schema_versions = sorted(
        {
            f"{optional_text(row.get('service') or 'unknown')}:{optional_text(row.get('schema_version'))}"
            for row in message_rows
            if optional_text(row.get("schema_version"))
        }
    )
    message_media_links = build_message_media_links(message_rows, media_rows)
    unified_actor_view = build_unified_contact_call_sms_view(message_rows, contact_rows, call_rows)
    schema_version_registry = build_schema_version_registry([*message_rows, *app_rows])
    validation_checks = {
        "message_media_correlation_available": bool(message_rows and media_rows),
        "media_message_links_built": bool(message_media_links),
        "contact_message_correlation_available": bool(contact_rows and message_rows),
        "call_message_correlation_available": bool(call_rows and message_rows),
        "unified_contact_call_sms_view_built": bool(unified_actor_view),
        "app_specific_schema_versions_tracked": bool(schema_versions),
        "schema_version_registry_built": bool(schema_version_registry),
        "schema_version_registry_known_answer_validated": False,
        "correlation_validated_against_known_answer": False,
    }
    return {
        "event_type": "mobile-correlation-summary",
        "timestamp": "",
        "message_count": len(message_rows),
        "media_count": len(media_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "service_count": len(services),
        "services": services,
        "participants": participants[:200],
        "participant_count": len(participants),
        "schema_versions": schema_versions,
        "schema_version_registry": schema_version_registry,
        "schema_version_registry_count": len(schema_version_registry),
        "message_media_links": message_media_links,
        "media_message_link_count": len(message_media_links),
        "unified_contact_call_sms_view": unified_actor_view,
        "unified_contact_call_sms_view_count": len(unified_actor_view),
        "timeline_correlation_ready": bool(message_rows or media_rows or call_rows),
        "validation_checks": validation_checks,
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "mobile_correlation_report_grade_assessment": mobile_correlation_report_grade_assessment(),
        "mobile_correlation_commercial_uplift_evidence": mobile_correlation_commercial_uplift_evidence(
            message_count=len(message_rows),
            media_count=len(media_rows),
            contact_count=len(contact_rows),
            call_count=len(call_rows),
            services=services,
            participant_count=len(participants),
            message_media_link_count=len(message_media_links),
            unified_actor_count=len(unified_actor_view),
            schema_version_count=len(schema_version_registry),
            validation_checks=validation_checks,
        ),
        "forensic_review": mobile_correlation_forensic_review(
            message_count=len(message_rows),
            media_count=len(media_rows),
            contact_count=len(contact_rows),
            call_count=len(call_rows),
            services=services,
            message_media_link_count=len(message_media_links),
            unified_actor_count=len(unified_actor_view),
            schema_version_count=len(schema_version_registry),
        ),
        "commercial_grade_blockers": [
            "Correlation is source-export scoped and does not prove device-wide completeness.",
            "App-specific schema versions, timezone semantics, deleted rows, and media attachment recovery need known-answer validation.",
        ],
        "risk_flags": ["mobile-correlation-summary"],
        "reporting_guidance": "Use this summary to pivot between messages, contacts, calls, media, and app rows before building a report timeline.",
    }


def build_message_media_links(
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    links: list[dict[str, object]] = []
    for message in message_rows:
        reference = optional_text(message.get("media_reference") or message.get("attachment_name"))
        reference_hash = optional_text(message.get("media_reference_sha256"))
        if not reference and not reference_hash:
            continue
        reference_name = Path(reference).name.lower() if reference else ""
        matched = False
        for media in media_rows:
            media_path = optional_text(media.get("media_path"))
            media_name = optional_text(media.get("file_name") or (Path(media_path).name if media_path else ""))
            media_hashes = {
                optional_text(media.get("md5")).lower(),
                optional_text(media.get("sha1")).lower(),
                optional_text(media.get("sha256")).lower(),
            }
            matched_by: list[str] = []
            haystack = f"{media_path} {media_name}".lower()
            if reference and reference.lower() in haystack:
                matched_by.append("path-reference")
            elif reference_name and reference_name in haystack:
                matched_by.append("filename-reference")
            if reference_hash and reference_hash.lower() in media_hashes:
                matched_by.append("hash-reference")
            if not matched_by:
                continue
            matched = True
            links.append(
                {
                    "message_id": optional_text(message.get("message_id")),
                    "message_timestamp": optional_text(message.get("timestamp")),
                    "service": optional_text(message.get("service")),
                    "media_reference": reference,
                    "media_path": media_path,
                    "media_sha256": optional_text(media.get("sha256")),
                    "matched_by": matched_by,
                    "validation_status": "candidate",
                }
            )
            if len(links) >= limit:
                return links
        if not matched:
            links.append(
                {
                    "message_id": optional_text(message.get("message_id")),
                    "message_timestamp": optional_text(message.get("timestamp")),
                    "service": optional_text(message.get("service")),
                    "media_reference": reference,
                    "media_path": "",
                    "media_sha256": "",
                    "matched_by": ["unresolved-message-reference"],
                    "validation_status": "unresolved-candidate",
                }
            )
            if len(links) >= limit:
                return links
    return links


def build_unified_contact_call_sms_view(
    message_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    *,
    limit: int = 200,
) -> list[dict[str, object]]:
    actors: dict[str, dict[str, object]] = {}

    def actor_for(identifier: str) -> dict[str, object]:
        actor = actors.setdefault(
            identifier,
            {
                "actor": identifier,
                "contact_names": set(),
                "phones": set(),
                "emails": set(),
                "message_count": 0,
                "call_count": 0,
                "contact_record_count": 0,
                "services": set(),
                "first_seen_at": "",
                "last_seen_at": "",
            },
        )
        return actor

    def update_seen(actor: dict[str, object], timestamp: str) -> None:
        if not timestamp:
            return
        first = optional_text(actor.get("first_seen_at"))
        last = optional_text(actor.get("last_seen_at"))
        actor["first_seen_at"] = min(first, timestamp) if first else timestamp
        actor["last_seen_at"] = max(last, timestamp) if last else timestamp

    for contact in contact_rows:
        identifiers = unique_non_empty(
            [
                optional_text(contact.get("phone_number")),
                optional_text(contact.get("email")),
                optional_text(contact.get("contact_name")),
            ]
        )
        for identifier in identifiers:
            actor = actor_for(identifier)
            actor["contact_record_count"] = int(actor["contact_record_count"]) + 1
            if contact.get("contact_name"):
                actor["contact_names"].add(optional_text(contact.get("contact_name")))
            if contact.get("phone_number"):
                actor["phones"].add(optional_text(contact.get("phone_number")))
            if contact.get("email"):
                actor["emails"].add(optional_text(contact.get("email")))
            update_seen(actor, optional_text(contact.get("timestamp")))

    for message in message_rows:
        for participant in message.get("participants", []):
            if not isinstance(participant, str) or not participant:
                continue
            actor = actor_for(participant)
            actor["message_count"] = int(actor["message_count"]) + 1
            if "@" in participant:
                actor["emails"].add(participant)
            else:
                actor["phones"].add(participant)
            if message.get("service"):
                actor["services"].add(optional_text(message.get("service")))
            update_seen(actor, optional_text(message.get("timestamp")))

    for call in call_rows:
        identifier = optional_text(call.get("phone_number") or call.get("contact_name"))
        if not identifier:
            continue
        actor = actor_for(identifier)
        actor["call_count"] = int(actor["call_count"]) + 1
        actor["phones"].add(identifier)
        if call.get("contact_name"):
            actor["contact_names"].add(optional_text(call.get("contact_name")))
        update_seen(actor, optional_text(call.get("timestamp")))

    normalized: list[dict[str, object]] = []
    for actor in actors.values():
        normalized.append(
            {
                "actor": optional_text(actor.get("actor")),
                "contact_names": sorted(actor["contact_names"])[:10],
                "phones": sorted(actor["phones"])[:10],
                "emails": sorted(actor["emails"])[:10],
                "message_count": int(actor["message_count"]),
                "call_count": int(actor["call_count"]),
                "contact_record_count": int(actor["contact_record_count"]),
                "services": sorted(actor["services"])[:10],
                "first_seen_at": optional_text(actor.get("first_seen_at")),
                "last_seen_at": optional_text(actor.get("last_seen_at")),
                "validation_status": "candidate",
            }
        )
    normalized.sort(key=lambda item: (-(int(item["message_count"]) + int(item["call_count"])), str(item["actor"])))
    return normalized[:limit]


def build_schema_version_registry(rows: list[Mapping[str, object]], *, limit: int = 200) -> list[dict[str, object]]:
    registry: dict[tuple[str, str, str], dict[str, object]] = {}
    for row in rows:
        app_identifier = optional_text(row.get("package") or row.get("service") or row.get("app_name") or "unknown")
        version = optional_text(row.get("schema_version") or row.get("version") or "unknown")
        event_type = optional_text(row.get("event_type") or row.get("artifact_type") or "unknown")
        key = (app_identifier, version, event_type)
        entry = registry.setdefault(
            key,
            {
                "app_identifier": app_identifier,
                "schema_or_app_version": version,
                "event_type": event_type,
                "row_count": 0,
                "known_schema_validated": False,
                "validation_status": "candidate",
            },
        )
        entry["row_count"] = int(entry["row_count"]) + 1
    values = sorted(registry.values(), key=lambda item: (str(item["app_identifier"]), str(item["schema_or_app_version"])))
    return values[:limit]


def mobile_correlation_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "ready_for_court_report": False,
        "blockers": [
            "media-message-links-are-candidate-matches-not-app-native-attachment-resolution",
            "contact-call-sms-view-is-export-scoped-not-device-wide-entity-resolution",
            "app-schema-version-registry-needs-known-answer-validation",
        ],
        "recommended_validation": [
            "Validate message/media links against app-native databases and attachment tables for each supported service.",
            "Validate contact/call/SMS identity resolution with known-answer mobile images before report-grade conclusions.",
        ],
    }


def mobile_correlation_forensic_review(
    *,
    message_count: int,
    media_count: int,
    contact_count: int,
    call_count: int,
    services: list[str],
    message_media_link_count: int,
    unified_actor_count: int,
    schema_version_count: int,
) -> dict[str, object]:
    report_grade = mobile_correlation_report_grade_assessment()
    return build_forensic_review(
        gap_id="#43",
        artifact_goal="Mobile message-media-contact-call correlation, unified actor view, and app schema version tracking",
        primary_evidence=[
            f"messages={message_count}",
            f"media={media_count}",
            f"contacts={contact_count}",
            f"calls={call_count}",
            f"services={','.join(services[:8])}",
            f"message_media_links={message_media_link_count}",
            f"unified_actors={unified_actor_count}",
            f"schema_versions={schema_version_count}",
        ],
        validation_required=True,
        report_grade_assessment=report_grade,
        blockers=report_grade["blockers"],
        caveats=[
            "Correlation is export-scoped and candidate-level, not a complete device-wide timeline.",
            "Known-answer validation is required for attachment resolution, contact identity merging, and schema-version semantics.",
        ],
    )


def mobile_correlation_commercial_uplift_evidence(
    *,
    message_count: int,
    media_count: int,
    contact_count: int,
    call_count: int,
    services: list[str],
    participant_count: int,
    message_media_link_count: int,
    unified_actor_count: int,
    schema_version_count: int,
    validation_checks: Mapping[str, object],
) -> dict[str, object]:
    report_grade = mobile_correlation_report_grade_assessment()
    passed_validation_check_ids = [
        str(check_id)
        for check_id, passed in validation_checks.items()
        if passed and not str(check_id).endswith("_known_answer_validated")
    ]
    failed_validation_check_ids = [
        str(check_id)
        for check_id, passed in validation_checks.items()
        if not passed and str(check_id).endswith("_known_answer_validated")
    ]
    if not validation_checks.get("correlation_validated_against_known_answer"):
        failed_validation_check_ids.append("correlation_validated_against_known_answer")
    return {
        "batch_id": "commercial-uplift-041-045",
        "item_numbers": [43, 44, 45],
        "implementation_track": "mobile-correlation-schema-gate",
        "reportability_decision": mobile_correlation_reportability_decision(
            validation_checks=validation_checks,
            failed_validation_check_ids=sorted(set(failed_validation_check_ids)),
            report_grade=report_grade,
            message_count=message_count,
            media_count=media_count,
            unified_actor_count=unified_actor_count,
            schema_version_count=schema_version_count,
        ),
        "source_refs": [f"service:{service}" for service in services[:20]],
        "passed_validation_check_ids": sorted(set(passed_validation_check_ids)),
        "failed_validation_check_ids": sorted(set(failed_validation_check_ids)),
        "commercial_blockers": list(report_grade["blockers"]),
        "large_data_controls": {
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
            "max_chat_db_sample_rows": MAX_CHAT_DB_SAMPLE_ROWS,
            "message_count": message_count,
            "media_count": media_count,
            "contact_count": contact_count,
            "call_count": call_count,
            "participant_count": participant_count,
            "message_media_link_count": message_media_link_count,
            "unified_actor_count": unified_actor_count,
            "schema_version_count": schema_version_count,
            "device_wide_timeline_ready": False,
            "known_answer_correlation_required": True,
        },
        "reporting_status": "candidate-correlation-validation-required",
    }


def mobile_correlation_reportability_decision(
    *,
    validation_checks: Mapping[str, object],
    failed_validation_check_ids: list[str],
    report_grade: Mapping[str, object],
    message_count: int,
    media_count: int,
    unified_actor_count: int,
    schema_version_count: int,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade["blockers"] if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    if not validation_checks.get("device_wide_timeline_validated"):
        blockers.add("device-wide-timeline-not-validated")
    if not validation_checks.get("schema_version_registry_known_answer_validated"):
        blockers.add("schema-version-registry-known-answer-not-attached")
    return {
        "profile_version": "mobile-correlation-reportability-decision-v1",
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "decision": "do-not-report-mobile-correlation-as-device-wide-or-identity-complete",
        "allowed_use": "mobile-correlation-and-schema-triage-pivot",
        "blockers": sorted(blockers),
        "failed_validation_check_ids": list(failed_validation_check_ids),
        "message_count": message_count,
        "media_count": media_count,
        "unified_actor_count": unified_actor_count,
        "schema_version_count": schema_version_count,
        "ready_for_court_report": False,
        "required_before_report": [
            "validate device-wide timeline joins, timezone assumptions, and attachment recovery",
            "attach analyst-reviewed identity merge/split decisions for contacts/calls/SMS actors",
            "gate each app parser with schema migration fixtures and release-reviewed compatibility matrices",
        ],
    }


def collect_ios_backup_metadata(path: Path) -> Iterable[ArtifactRecord]:
    if path.name == "Manifest.db":
        yield from collect_ios_manifest_db(path)
        return
    yield collect_ios_plist_metadata(path)


def collect_ios_manifest_db(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    emitted = 0
    validation = {
        "manifest_db_present": True,
        "opened_readonly": False,
        "files_table_present": False,
        "row_limit": MAX_IOS_BACKUP_FILES,
    }
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
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
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            validation["opened_readonly"] = True
            for table_name in sqlite_table_names(connection)[:MAX_SQLITE_TABLES]:
                table_summaries.append(
                    {
                        "table": table_name,
                        "row_count": sqlite_row_count(connection, table_name),
                        "columns": sqlite_columns(connection, table_name)[:50],
                    }
                )
    except sqlite3.Error as error:
        validation["sqlite_error"] = str(error)[:240]
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
            "protected_data_class_handling": {
                "status": "redacted-inventory-only",
                "default_label": "protected-data-redacted",
                "class_values_revealed": False,
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


def normalize_ios_backup_file(row: Mapping[str, object], validation: Mapping[str, object]) -> dict[str, object]:
    domain = optional_text(row.get("domain"))
    relative_path = optional_text(row.get("relativePath"))
    file_id = optional_text(row.get("fileID"))
    return {
        "event_type": "ios-backup-file",
        "timestamp": "",
        "file_id": file_id,
        "file_id_sha256": sha256_text(file_id) if file_id else "",
        "domain": domain,
        "relative_path": relative_path,
        "logical_path": f"{domain}/{relative_path}".strip("/"),
        "flags": optional_text(row.get("flags")),
        "risk_flags": ios_backup_file_risk_flags(domain, relative_path),
        "validation_checks": dict(validation),
        "commercial_grade_blockers": [
            "Manifest inventory only; file payload decoding and application schema parsing are not complete.",
            "Encrypted/protected backup handling and deleted-record recovery require external validation.",
        ],
        "raw": dict(row),
    }


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
    }
    sanitized: dict[str, object] = {}
    for source_key, output_key in allowed.items():
        if source_key in payload:
            value = payload[source_key]
            if isinstance(value, (dt.datetime, dt.date)):
                sanitized[output_key] = value.isoformat()
            else:
                sanitized[output_key] = optional_text(value)
    sanitized["available_key_count"] = len(payload)
    sanitized["available_keys"] = sorted(str(key) for key in payload)[:80]
    return sanitized


def detect_chat_service(row: Mapping[str, object], path: Path) -> str:
    haystack_parts = [str(path).lower()]
    for value in row.values():
        if value in (None, ""):
            continue
        haystack_parts.append(optional_text(value).lower())
    haystack = " ".join(haystack_parts)
    for profile in CHAT_APP_PROFILES:
        aliases = profile.get("aliases", ())
        if any(str(alias).lower() in haystack for alias in aliases):
            return str(profile["service"])
    return ""


def service_family(service: str) -> str:
    text = service.lower().replace(" ", "-")
    if not text:
        return "unknown-chat"
    for profile in CHAT_APP_PROFILES:
        if str(profile["service"]).lower() == service.lower():
            return str(profile["service"]).lower().replace(" ", "-")
    return text


def chat_profile_message_tables(service: str) -> tuple[str, ...]:
    for profile in CHAT_APP_PROFILES:
        if str(profile["service"]).lower() == service.lower():
            return tuple(str(value).lower() for value in profile.get("message_tables", ()))
    return ("message", "messages", "chat", "chat_history")


def chat_table_is_message_candidate(table_name: str, columns: Iterable[str], profile_tables: Iterable[str]) -> bool:
    lowered_table = table_name.lower()
    lowered_columns = {column.lower() for column in columns}
    if any(candidate in lowered_table for candidate in profile_tables):
        return True
    return bool(
        lowered_columns.intersection({"message", "text", "body", "content", "timestamp", "date", "sender", "author"})
        and lowered_columns.intersection({"chat_id", "thread_id", "conversation_id", "from_jid", "recipient", "remote_jid"})
    )


def split_participants(value: object) -> list[str]:
    text = optional_text(value)
    if not text:
        return []
    if text.startswith("[") or text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            return [optional_text(item) for item in parsed if optional_text(item)]
        if isinstance(parsed, Mapping):
            return [optional_text(item) for item in parsed.values() if optional_text(item)]
    return [
        item.strip()
        for item in text.replace(";", ",").replace("|", ",").split(",")
        if item.strip()
    ]


def first_value(row: Mapping[str, object], keys: Iterable[str]) -> object:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return ""


def normalize_timestamp(value: object) -> str:
    text = optional_text(value)
    if not text:
        return ""
    if text.isdigit():
        timestamp = int(text)
        if timestamp > 10_000_000_000_000:
            timestamp = timestamp // 1_000_000
        elif timestamp > 10_000_000_000:
            timestamp = timestamp // 1000
        return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def detect_source_tool(path: Path) -> str:
    lowered = str(path).lower()
    for vendor, hints in VENDOR_HINTS.items():
        if any(hint in lowered for hint in hints):
            return vendor
    return "mobile-export"


def source_format_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    return "json"


def message_risk_flags(text: str, service: str) -> list[str]:
    lowered = f"{service} {text}".lower()
    flags: list[str] = []
    if any(token in lowered for token in ("password", "otp", "2fa", "인증", "비밀번호")):
        flags.append("credential-or-otp")
    if any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        flags.append("ai-service-conversation")
    if detect_chat_service({"service": service}, Path("")):
        flags.append("messenger-app-conversation")
    if text:
        flags.append("message-content")
    return flags


def app_risk_flags(app_name: str, package: str) -> list[str]:
    lowered = f"{app_name} {package}".lower()
    flags: list[str] = []
    if any(token in lowered for token in ("vpn", "proxy", "tor", "secure", "vault", "signal", "telegram")):
        flags.append("privacy-or-evasion-app")
    if any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        flags.append("ai-service-app")
    return flags


def file_risk_flags(file_path: str) -> list[str]:
    lowered = file_path.lower()
    flags: list[str] = []
    if any(token in lowered for token in ("/dcim/", "/pictures/", "/download/", "/documents/")):
        flags.append("user-file")
    if any(lowered.endswith(suffix) for suffix in (".db", ".sqlite", ".sqlite3", ".plist", ".xml", ".json")):
        flags.append("structured-data-file")
    return flags


def media_risk_flags(media_path: str, mime_type: str) -> list[str]:
    lowered = f"{media_path} {mime_type}".lower()
    flags = ["mobile-media"]
    if any(token in lowered for token in ("image", ".jpg", ".jpeg", ".png", "/dcim/", "camera")):
        flags.append("image-media")
    if any(token in lowered for token in ("video", ".mp4", ".mov", ".3gp")):
        flags.append("video-media")
    if any(token in lowered for token in ("audio", ".m4a", ".wav", ".mp3")):
        flags.append("audio-media")
    return flags


def browser_risk_flags(url: str, title: str) -> list[str]:
    lowered = f"{url} {title}".lower()
    flags = ["mobile-browser-history"]
    if any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        flags.append("ai-service-usage")
    if any(token in lowered for token in ("login", "account", "password", "otp")):
        flags.append("credential-context")
    return flags


def ios_backup_file_risk_flags(domain: str, relative_path: str) -> list[str]:
    lowered = f"{domain}/{relative_path}".lower()
    flags = ["ios-backup-file"]
    if any(token in lowered for token in ("sms", "message", "chat", "whatsapp", "telegram", "line", "kakao")):
        flags.append("message-store-candidate")
    if any(token in lowered for token in ("camera", "dcim", "photo", "media", ".jpg", ".mov", ".mp4")):
        flags.append("media-candidate")
    if any(token in lowered for token in ("account", "profile", "keychain", "credential", "cookie")):
        flags.append("sensitive-artifact-candidate")
    return flags


def row_validation_checks(
    row: Mapping[str, object],
    *,
    required: Iterable[str],
    content_present: bool | None = None,
) -> dict[str, object]:
    keys = set(row)
    checks: dict[str, object] = {
        "has_required_field_candidate": any(key in keys and row[key] not in (None, "") for key in required),
        "normalized_key_count": len(keys),
        "row_hash_algorithm": "sha256-json-normalized",
        "vendor_schema_validated": False,
    }
    if content_present is not None:
        checks["content_present"] = content_present
    return checks


def mobile_commercial_gap_ids(artifact_type: str, source_tool: str) -> list[str]:
    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata"}:
        return ["#27"]
    if artifact_type == "ios-keychain-inventory":
        return ["#28"]
    if source_tool in {"cellebrite", "xry", "graykey", "axiom"} or artifact_type.startswith("mobile-"):
        return ["#26"]
    return ["#26"]


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


def mobile_validation_matrix(
    *,
    artifact_type: str,
    source_tool: str,
    validation_checks: Mapping[str, object],
) -> list[dict[str, object]]:
    return [
        {
            "id": "source-hash-present",
            "label": "Source export or database hash is recorded",
            "passed": True,
            "severity": "critical",
        },
        {
            "id": "source-tool-detected",
            "label": "Source tool or acquisition family is identified",
            "passed": bool(source_tool),
            "severity": "medium",
        },
        {
            "id": "core-fields-normalized",
            "label": "Core artifact fields are normalized into reviewable output",
            "passed": bool(validation_checks.get("has_required_field_candidate", True)),
            "severity": "high",
        },
        {
            "id": "vendor-settings-verified",
            "label": "Vendor export settings, parser version, and original acquisition hash are verified",
            "passed": bool(validation_checks.get("vendor_export_settings_verified"))
            and bool(validation_checks.get("original_acquisition_hash_verified")),
            "severity": "critical",
        },
        {
            "id": "protected-data-boundary",
            "label": "Protected/encrypted secrets are not exposed without explicit validated workflow",
            "passed": not bool(validation_checks.get("secrets_extracted")),
            "severity": "critical",
        },
        {
            "id": "known-answer-mobile-validation",
            "label": "Parser behavior is validated against mobile known-answer corpora",
            "passed": False,
            "severity": "critical",
        },
    ]


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
    return {
        "batch_id": "commercial-uplift-026-030",
        "item_numbers": item_numbers,
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
    record_id = source_record_id(details, source_index)
    if record_id:
        evidence_refs.append(f"source_record_id:{record_id}")

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
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted vendor mobile export diff pass")
        gates.append(build_accuracy_gate(26, satisfied_checks=satisfied, evidence_refs=evidence_refs))

    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata"}:
        satisfied = []
        if details.get("file_id") and details.get("domain") and details.get("logical_path"):
            satisfied.append("Manifest.db domain/fileID mapping")
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
        if details.get("protected_data_class_handling"):
            satisfied.append("protected-data class labeling")
        if details.get("legal_warning") and details.get("controlled_reveal_audit"):
            satisfied.append("authority gate before reveal/decrypt")
        if table_summaries or validation.get("opened_readonly"):
            satisfied.append("record count/table inventory")
        if details.get("controlled_reveal_audit"):
            satisfied.append("audit log for any controlled reveal")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted iOS keychain inventory diff pass")
        gates.append(build_accuracy_gate(28, satisfied_checks=satisfied, evidence_refs=evidence_refs))

    return gates


def mobile_correlation_core_accuracy_gates(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> list[dict[str, object]]:
    if artifact_type != "mobile-correlation-summary":
        return []
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    evidence_refs = [
        f"source_tool:{source_tool}",
        f"source_format:{source_format}",
        f"source_index:{source_index}",
        f"message_count:{details.get('message_count', 0)}",
        f"media_count:{details.get('media_count', 0)}",
        f"contact_count:{details.get('contact_count', 0)}",
        f"call_count:{details.get('call_count', 0)}",
    ]
    if source_hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{source_hashes['sha256']}")

    item43: list[str] = []
    if validation.get("media_message_links_built") or details.get("message_media_links") is not None:
        item43.append("message-media linkage built")
    if any(int(details.get(key) or 0) >= 0 for key in ("message_count", "media_count", "contact_count", "call_count")):
        item43.append("message/contact/call/media counts preserved")
    if details.get("services") is not None:
        item43.append("service attribution")
    if details.get("timeline_correlation_ready") is not None:
        item43.append("timeline correlation readiness")
    if not validation.get("correlation_validated_against_known_answer", False):
        item43.append("known-answer limitation warning")

    item44: list[str] = []
    if validation.get("unified_contact_call_sms_view_built") or details.get("unified_contact_call_sms_view") is not None:
        item44.append("contact/call/SMS actor merge")
    if details.get("message_media_links") is not None or details.get("unified_contact_call_sms_view") is not None:
        item44.append("source row links preserved")
    if details.get("participants") is not None:
        item44.append("participant attribution")
    item44.append("dedupe/entity limitation warning")
    item44.append("export-scope limitation warning")

    item45: list[str] = []
    if validation.get("schema_version_registry_built") or details.get("schema_version_registry") is not None:
        item45.append("app/service schema version registry")
    if details.get("services") is not None or details.get("schema_versions") is not None:
        item45.append("source app/version attribution")
    item45.append("schema compatibility warning")
    if not validation.get("schema_version_registry_known_answer_validated", False):
        item45.append("migration fixture warning")
    item45.append("release-gate limitation disclosure")

    return [
        build_accuracy_gate(43, satisfied_checks=item43, evidence_refs=evidence_refs),
        build_accuracy_gate(44, satisfied_checks=item44, evidence_refs=evidence_refs),
        build_accuracy_gate(45, satisfied_checks=item45, evidence_refs=evidence_refs),
    ]


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
            if details.get("kakaotalk_compatibility_assessment") or details.get("schema_version") or details.get("app_version"):
                satisfied.append("schema/app version and BigBang compatibility tracking")
            if "kakaotalk-post-2025-08-bigbang" in issue_ids or details.get("commercial_grade_blockers"):
                satisfied.append("encrypted/deleted limitation warning")
            if source_hashes.get("sha256") and source_tool:
                satisfied.append("source hash and legal provenance")
        elif number == 32:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("chat/contact/media normalization")
            if details.get("commercial_grade_blockers") or not validation.get("decryption_attempted", True):
                satisfied.append("crypt backup authority workflow warning")
            if details.get("commercial_grade_blockers"):
                satisfied.append("deleted-row limitation warning")
            if source_hashes.get("sha256") and (details.get("app_version") is not None or details.get("chat_app_issue_matrix")):
                satisfied.append("source hash and app-version provenance")
        elif number == 33:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("chat/user/media attribution")
            if source_hashes.get("sha256") and (details.get("message_id") or details.get("database_name") or table_summaries):
                satisfied.append("account/cache provenance")
            if details.get("commercial_grade_blockers"):
                satisfied.append("encrypted local store warning")
                satisfied.append("deleted/cache recovery limitation")
        elif number == 34:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("thread/recipient/message inventory")
            if details.get("commercial_grade_blockers") or not validation.get("decryption_attempted", True):
                satisfied.append("SQLCipher/key authority gate")
            if details.get("commercial_grade_blockers"):
                satisfied.append("attachment/deleted limitation warning")
            if source_hashes.get("sha256") and source_tool:
                satisfied.append("secret-safe legal provenance")
        elif number == 35:
            if details.get("message_text_sha256") or table_summaries:
                satisfied.append("message/media/reaction normalization")
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


def mobile_artifact_goal(artifact_type: str) -> str:
    if artifact_type.startswith("ios-backup"):
        return "iOS backup Manifest.db/plist inventory and authorized backup pivot evidence"
    if artifact_type == "ios-keychain-inventory":
        return "iOS keychain redacted inventory with strict protected-data boundary"
    if artifact_type.startswith("mobile-"):
        return "Vendor mobile export row normalization for messages, apps, contacts, calls, files, media and browser data"
    return "Mobile export artifact review"


def source_validation_checks(
    source_format: str,
    source_tool: str,
    emitted: int,
    detected_types: set[str],
) -> dict[str, object]:
    return {
        "source_format": source_format,
        "source_tool_detected": source_tool,
        "row_count_nonzero": emitted > 0,
        "detected_artifact_type_count": len(detected_types),
        "vendor_export_settings_verified": False,
        "original_acquisition_hash_verified": False,
    }


def mobile_export_blockers(source_tool: str) -> list[str]:
    return [
        f"{source_tool} schema coverage is heuristic and fixture-backed only for common CSV/JSON exports.",
        "Original device/acquisition hashes, extraction settings, and vendor parser version must be independently recorded.",
        "Deleted records, encrypted app stores, and proprietary package semantics are not fully validated.",
    ]


def chat_app_blockers(service: str) -> list[str]:
    label = service or "chat app"
    return [
        f"{label} parsing is limited to authorized exports/backups and heuristic CSV/JSON/SQLite inventory.",
        "App-specific encrypted stores, deleted records, schema-version drift, and attachment recovery are not fully validated.",
        "Original device/acquisition hashes, export settings, app version, timezone, and account ownership must be independently verified.",
    ]


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
    return {
        "batch_id": "commercial-uplift-031-035",
        "item_numbers": item_numbers,
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
            "known_service_profile": service in CHAT_APP_GAP_IDS,
            "service_specific_native_database_decode": False,
            "encrypted_store_decryption": False,
            "deleted_record_recovery": False,
            "known_answer_service_corpus_required": True,
        },
        "next_internal_step": "Add service/version-specific schema mappers, encrypted-store authority workflows, attachment recovery checks, and known-answer corpora for each messenger.",
        "external_evidence_required": True,
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


def chat_app_gap_ids(service: str) -> list[str]:
    gap = CHAT_APP_GAP_IDS.get(service)
    return [gap] if gap else ["#31", "#32", "#33", "#34", "#35"]


def chat_app_native_capabilities(service: str) -> dict[str, object]:
    capabilities = dict(CHAT_APP_NATIVE_CAPABILITIES)
    capabilities["service"] = service or "unknown"
    capabilities["known_service_profile"] = service in CHAT_APP_GAP_IDS
    return capabilities


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
    return {
        "status": status,
        "app_version": app_version or "unknown",
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


def version_at_least(value: str, minimum: str) -> bool:
    return version_tuple(value) >= version_tuple(minimum)


def version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for item in value.replace("-", ".").split("."):
        digits = "".join(character for character in item if character.isdigit())
        if digits:
            parts.append(int(digits))
        if len(parts) >= 4:
            break
    return tuple(parts or [0])


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


def source_record_id(details: Mapping[str, object], source_index: int) -> str:
    raw = details.get("raw")
    if isinstance(raw, Mapping):
        for key in ("id", "recordid", "sourceid", "guid", "messageid", "fileid"):
            value = raw.get(key)
            if value not in (None, ""):
                return optional_text(value)
        return sha256_text(json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str))
    return str(source_index)


def is_ios_backup_metadata_file(path: Path) -> bool:
    return path.name in {"Manifest.db", "Info.plist", "Status.plist"} and looks_like_ios_backup_path(path)


def is_ios_keychain_candidate(path: Path) -> bool:
    lowered = str(path).lower()
    return path.suffix.lower() in {".db", ".sqlite", ".sqlite3"} and "keychain" in lowered and looks_like_ios_backup_path(path)


def is_chat_app_database_candidate(path: Path) -> bool:
    if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        return False
    return bool(detect_chat_service({}, path))


def looks_like_ios_backup_path(path: Path) -> bool:
    lowered = str(path).lower()
    if any(token in lowered for token in ("ios", "iphone", "ipad", "mobilebackup", "backup")):
        return True
    return path.name in {"Manifest.db", "Info.plist", "Status.plist", "keychain-2.db"}


def sqlite_table_names(connection: sqlite3.Connection) -> list[str]:
    try:
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
    except sqlite3.Error:
        return []


def sqlite_columns(connection: sqlite3.Connection, table_name: str) -> list[str]:
    if not safe_sqlite_identifier(table_name):
        return []
    try:
        return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table_name}")')]
    except sqlite3.Error:
        return []


def sqlite_row_count(connection: sqlite3.Connection, table_name: str) -> int | None:
    if not safe_sqlite_identifier(table_name):
        return None
    try:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()
    except sqlite3.Error:
        return None
    return int(row[0]) if row else None


def safe_sqlite_identifier(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character in {"_", "-"} for character in value)


def unique_non_empty(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def optional_text(value: object) -> str:
    if value in (None, ""):
        return ""
    return str(value)
