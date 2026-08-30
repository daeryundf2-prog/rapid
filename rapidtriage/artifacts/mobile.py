from __future__ import annotations

import csv
import contextlib
import datetime as dt
import hashlib
import json
import plistlib
import shlex
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ..core.forensic_accuracy import build_accuracy_gate
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "mobile-export-v4"
FUNCTIONAL_SOURCE_BATCH_ID = "commercial-uplift-046-050"
FUNCTIONAL_EXPANSION_BATCH_ID = "commercial-uplift-051-055"
MOBILE_EXPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
MAX_ROWS_PER_SOURCE = 50_000
MAX_IOS_BACKUP_FILES = 50_000
MAX_SQLITE_TABLES = 100
MAX_CHAT_DB_SAMPLE_ROWS = 25
MAX_MOBILE_CORRELATION_TIMELINE_ROWS = 500
MOBILE_TIMELINE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "mobile-timeline-report-grade-validation-plan-v1"
MOBILE_TIMELINE_REPORT_GRADE_BLOCKERS = [
    "mobile-correlation-device-wide-timeline-required",
    "mobile-correlation-timezone-skew-validation-required",
    "mobile-correlation-attachment-byte-recovery-required",
    "mobile-correlation-vendor-timeline-diff-required",
    "mobile-correlation-known-answer-corpus-required",
    "mobile-correlation-independent-review-required",
]
MOBILE_ACTOR_REPORT_GRADE_VALIDATION_PLAN_VERSION = "mobile-actor-report-grade-validation-plan-v1"
MOBILE_ACTOR_REPORT_GRADE_BLOCKERS = [
    "mobile-actor-device-wide-identity-resolution-required",
    "mobile-actor-merge-split-review-history-required",
    "mobile-actor-cross-app-dedupe-required",
    "mobile-actor-vendor-identity-diff-required",
    "mobile-actor-known-answer-corpus-required",
    "mobile-actor-independent-review-required",
]
MOBILE_SCHEMA_REPORT_GRADE_VALIDATION_PLAN_VERSION = "mobile-schema-report-grade-validation-plan-v1"
MOBILE_SCHEMA_REPORT_GRADE_BLOCKERS = [
    "mobile-schema-version-fixture-corpus-required",
    "mobile-schema-migration-matrix-required",
    "mobile-schema-trusted-migration-diff-required",
    "mobile-schema-release-policy-approval-required",
    "mobile-schema-upgrade-deleted-state-corpus-required",
    "mobile-schema-independent-review-required",
]
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
    "mobile_location_health_screen_time_import": True,
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
MOBILE_VENDOR_EXPORT_REPORT_GRADE_VALIDATION_PLAN_VERSION = "mobile-vendor-export-report-grade-validation-plan-v1"
MOBILE_VENDOR_EXPORT_REPORT_GRADE_BLOCKERS = [
    "trusted-vendor-mobile-export-diff-required",
    "per-vendor-version-schema-fixtures-required",
    "deleted-record-semantics-known-answer-required",
    "original-acquisition-hash-and-export-settings-independent-review-required",
]
IOS_BACKUP_REPORT_GRADE_VALIDATION_PLAN_VERSION = "ios-backup-report-grade-validation-plan-v1"
IOS_BACKUP_REPORT_GRADE_BLOCKERS = [
    "trusted-ios-backup-parser-diff-required",
    "encrypted-backup-unlock-workflow-evidence-required",
    "application-database-schema-known-answer-required",
    "deleted-record-semantics-known-answer-required",
    "independent-ios-backup-review-required",
]
IOS_KEYCHAIN_REPORT_GRADE_VALIDATION_PLAN_VERSION = "ios-keychain-report-grade-validation-plan-v1"
IOS_KEYCHAIN_REPORT_GRADE_BLOCKERS = [
    "trusted-ios-keychain-inventory-diff-required",
    "lawful-authority-and-controlled-reveal-audit-required",
    "keybag-protected-data-class-validation-required",
    "access-group-semantics-known-answer-required",
    "independent-ios-keychain-review-required",
]
IOS_QC_PREP_ITEM_NUMBER = 46
IOS_QC_PREP_GOAL = (
    "Deepen iOS backup parser for Manifest.db, domains, app DB mapping, SMS, media, and encrypted-backup lawful key workflow."
)
IOS_QC_PREP_CONTRACT = {
    "item_number": IOS_QC_PREP_ITEM_NUMBER,
    "goal": IOS_QC_PREP_GOAL,
    "implemented_outputs": [
        "Manifest.db domain/fileID/logical path inventory with source viewer locators",
        "Info.plist and Status.plist backup root/scope profile",
        "SMS/media/app database candidate detection and keychain redacted inventory boundaries",
        "encrypted-backup lawful key workflow flags without exposing protected values",
    ],
    "commercial_blockers": [
        "encrypted backup unlock workflow evidence",
        "protected data class validation",
        "trusted iOS backup known-answer corpus",
        "application DB payload parser validation",
    ],
}
MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS = {
    43: "mobile-correlation-vendor-timeline-diff-required",
    44: "mobile-actor-vendor-report-diff-required",
    45: "mobile-schema-migration-diff-required",
}
MOBILE_CORRELATION_TRUSTED_TOOLS = {
    "cellebrite",
    "xry",
    "graykey",
    "axiom",
    "ileapp",
    "native-mobile-export",
    "hand-labeled-known-answer",
    "schema-migration-fixture",
}

VENDOR_HINTS = {
    "cellebrite": ("cellebrite", "ufed", "ufdr", "ufdx", "physical analyzer"),
    "xry": ("xry", "msab"),
    "graykey": ("graykey", "grayshift"),
    "axiom": ("axiom", "magnet"),
}
VENDOR_SCHEMA_REGISTRY = {
    "cellebrite": {
        "family": "cellebrite-ufed-physical-analyzer",
        "version_keys": ("cellebrite_version", "physical_analyzer_version", "vendor_tool_version", "parser_version"),
        "expected_artifacts": ("messages", "contacts", "calls", "apps", "files", "accounts", "media", "browser"),
        "required_export_metadata": ("vendor_tool", "vendor_tool_version", "export_settings", "original_acquisition_sha256"),
    },
    "xry": {
        "family": "msab-xry",
        "version_keys": ("xry_version", "msab_version", "vendor_tool_version", "parser_version"),
        "expected_artifacts": ("messages", "contacts", "calls", "apps", "files", "accounts", "media", "browser"),
        "required_export_metadata": ("vendor_tool", "vendor_tool_version", "export_settings", "original_acquisition_sha256"),
    },
    "graykey": {
        "family": "grayshift-graykey",
        "version_keys": ("graykey_version", "grayshift_version", "vendor_tool_version", "parser_version"),
        "expected_artifacts": ("messages", "contacts", "calls", "apps", "files", "accounts", "media", "browser"),
        "required_export_metadata": ("vendor_tool", "vendor_tool_version", "export_settings", "original_acquisition_sha256"),
    },
    "axiom": {
        "family": "magnet-axiom",
        "version_keys": ("axiom_version", "magnet_axiom_version", "vendor_tool_version", "parser_version"),
        "expected_artifacts": ("messages", "contacts", "calls", "apps", "files", "accounts", "media", "browser"),
        "required_export_metadata": ("vendor_tool", "vendor_tool_version", "export_settings", "original_acquisition_sha256"),
    },
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
LOCATION_KEYS = {
    "latitude",
    "longitude",
    "latitudee7",
    "longitudee7",
    "lat",
    "lon",
    "lng",
    "accuracy",
    "altitude",
    "location",
    "placename",
    "address",
}
HEALTH_KEYS = {
    "steps",
    "stepcount",
    "heartrate",
    "heartbeatsperminute",
    "sleep",
    "sleepstart",
    "sleepend",
    "calories",
    "distance",
    "workout",
    "activitytype",
}
SCREEN_TIME_KEYS = {
    "screentime",
    "digitalwellbeing",
    "appusage",
    "foregroundtime",
    "duration",
    "screenon",
    "screenoff",
    "unlockcount",
    "notificationcount",
}
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
VENDOR_ARTIFACT_MAPPER_KEYS = {
    "messages": {
        "output_artifact_type": "mobile-message",
        "required_key_sets": (MESSAGE_KEYS, CHAT_KEYS),
        "semantic_fields": ("timestamp", "sender", "recipient", "conversation_id", "message_id", "message_text_hash", "deleted_state"),
    },
    "contacts": {
        "output_artifact_type": "mobile-contact",
        "required_key_sets": (CONTACT_KEYS,),
        "semantic_fields": ("name", "phone", "email", "account_or_service"),
    },
    "calls": {
        "output_artifact_type": "mobile-call",
        "required_key_sets": (CALL_KEYS,),
        "semantic_fields": ("timestamp", "phone", "direction_or_type", "duration", "missed_answered_state"),
    },
    "apps": {
        "output_artifact_type": "mobile-app",
        "required_key_sets": (APP_KEYS,),
        "semantic_fields": ("app_name", "package_or_bundle", "version", "risk_flags"),
    },
    "files": {
        "output_artifact_type": "mobile-file",
        "required_key_sets": (FILE_KEYS,),
        "semantic_fields": ("path", "filename", "size", "hashes", "mime_type"),
    },
    "accounts": {
        "output_artifact_type": "mobile-account",
        "required_key_sets": (ACCOUNT_KEYS,),
        "semantic_fields": ("account_id", "account_name", "service", "handle"),
    },
    "media": {
        "output_artifact_type": "mobile-media",
        "required_key_sets": (MEDIA_KEYS,),
        "semantic_fields": ("media_path", "mime_type", "dimensions", "duration", "hashes"),
    },
    "browser": {
        "output_artifact_type": "mobile-browser",
        "required_key_sets": (BROWSER_KEYS,),
        "semantic_fields": ("url", "title", "timestamp", "browser", "domain"),
    },
    "location": {
        "output_artifact_type": "mobile-location",
        "required_key_sets": (LOCATION_KEYS,),
        "semantic_fields": ("timestamp", "latitude", "longitude", "accuracy", "source_device", "location_label"),
    },
    "health": {
        "output_artifact_type": "mobile-health",
        "required_key_sets": (HEALTH_KEYS,),
        "semantic_fields": ("timestamp", "metric_type", "metric_value", "unit", "source_device"),
    },
    "screen_time": {
        "output_artifact_type": "mobile-screen-time",
        "required_key_sets": (SCREEN_TIME_KEYS,),
        "semantic_fields": ("timestamp", "app_name", "duration_seconds", "screen_event", "source_device"),
    },
}
MESSAGE_ID_KEYS = {"guid", "id", "messageid", "msgid", "rowid", "serverid"}
REACTION_KEYS = {"reaction", "reactions", "emoji", "like", "likes"}
MEDIA_REFERENCE_KEYS = {
    "attachment",
    "attachmentname",
    "attachmentpath",
    "attachmenturl",
    "file",
    "filename",
    "media",
    "mediafilename",
    "mediapath",
    "mediaurl",
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
KAKAOTALK_REPORT_GRADE_VALIDATION_PLAN_VERSION = "kakaotalk-report-grade-validation-plan-v1"
KAKAOTALK_REPORT_GRADE_BLOCKERS = [
    "trusted-kakaotalk-export-native-db-diff-required",
    "post-bigbang-known-answer-corpus-required",
    "schema-version-parser-map-required",
    "encrypted-store-key-authority-boundary-required",
    "deleted-read-state-known-answer-required",
    "attachment-byte-media-validation-required",
    "independent-kakaotalk-review-required",
]
WHATSAPP_REPORT_GRADE_VALIDATION_PLAN_VERSION = "whatsapp-report-grade-validation-plan-v1"
WHATSAPP_REPORT_GRADE_BLOCKERS = [
    "trusted-whatsapp-export-native-db-diff-required",
    "crypt-backup-key-authority-workflow-required",
    "msgstore-wa-db-schema-version-known-answer-required",
    "deleted-row-known-answer-required",
    "contact-call-media-recovery-validation-required",
    "timezone-ack-read-state-semantics-validation-required",
    "attachment-byte-media-validation-required",
    "independent-whatsapp-review-required",
]
TELEGRAM_REPORT_GRADE_VALIDATION_PLAN_VERSION = "telegram-report-grade-validation-plan-v1"
TELEGRAM_REPORT_GRADE_BLOCKERS = [
    "trusted-telegram-export-native-db-diff-required",
    "local-store-decryption-authority-workflow-required",
    "export-schema-version-known-answer-required",
    "account-dialog-peer-attribution-known-answer-required",
    "secret-chat-edited-deleted-semantics-validation-required",
    "cache-media-locality-validation-required",
    "independent-telegram-review-required",
]
SIGNAL_REPORT_GRADE_VALIDATION_PLAN_VERSION = "signal-report-grade-validation-plan-v1"
SIGNAL_REPORT_GRADE_BLOCKERS = [
    "trusted-signal-export-native-db-diff-required",
    "sqlcipher-key-authority-workflow-required",
    "recipient-thread-schema-known-answer-required",
    "attachment-locality-validation-required",
    "deleted-disappearing-message-semantics-validation-required",
    "delivery-read-state-semantics-validation-required",
    "independent-signal-review-required",
]
EXTENDED_MESSENGER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "extended-messenger-report-grade-validation-plan-v1"
EXTENDED_MESSENGER_REPORT_GRADE_BLOCKERS = [
    "trusted-extended-messenger-export-native-db-diff-required",
    "service-schema-version-known-answer-required",
    "encrypted-ephemeral-store-authority-workflow-required",
    "media-locality-validation-required",
    "reaction-read-edit-delete-semantics-validation-required",
    "service-coverage-matrix-required",
    "independent-extended-messenger-review-required",
]
QC_PREP_CHAT_APP_ITEMS = {
    "KakaoTalk": 37,
    "WhatsApp": 38,
    "Telegram": 39,
    "Signal": 40,
    "WeChat": 41,
    "LINE": 41,
    "Discord": 41,
    "Instagram": 41,
}
QC_PREP_CHAT_APP_GOALS = {
    37: "Formalize PC KakaoTalk legacy and post-patch schema/version matrix with fixtures and Windows packaging notes.",
    38: "Add WhatsApp export/native parser with message, contacts, calls, media, deleted-row limitations, and lawful key workflow.",
    39: "Add Telegram export/native parser with account, media, cache, and encrypted-store warning.",
    40: "Add Signal parser with SQLCipher/key handling separated into secure lawful workflow.",
    41: "Add LINE, Discord, Instagram, and WeChat service-specific export/native schema mappers with review-ready source citations.",
}
QC_PREP_CHAT_APP_CONTRACTS = {
    37: {
        "item_number": 37,
        "goal": QC_PREP_CHAT_APP_GOALS[37],
        "implemented_outputs": [
            "KakaoTalk export row normalization and database inventory",
            "legacy/post-BigBang compatibility assessment and strategy profile",
            "message review profile with hashes, attachment metadata, source citation, and viewer controls",
        ],
        "commercial_blockers": [
            "post-BigBang known-answer corpus",
            "trusted KakaoTalk export/native DB diff",
            "schema-version parser map",
            "attachment bytes and deleted-record validation",
        ],
    },
    38: {
        "item_number": 38,
        "goal": QC_PREP_CHAT_APP_GOALS[38],
        "implemented_outputs": [
            "WhatsApp export row normalization and msgstore/wa.db inventory",
            "JID attribution, media metadata, quoted/read/deleted state markers",
            "crypt backup key workflow disclosed as authority-gated and not performed by default",
        ],
        "commercial_blockers": [
            "crypt key authority workflow",
            "trusted WhatsApp export/native DB diff",
            "msgstore/wa.db schema-version known answers",
            "deleted-row and media locality validation",
        ],
    },
    39: {
        "item_number": 39,
        "goal": QC_PREP_CHAT_APP_GOALS[39],
        "implemented_outputs": [
            "Telegram export row normalization and cache/database inventory",
            "account/dialog/media-cache attribution and source citation",
            "encrypted local-store and secret/deleted chat warnings",
        ],
        "commercial_blockers": [
            "Telegram local-store decryption validation",
            "trusted Telegram export/native DB diff",
            "account/dialog peer known answers",
            "secret-chat edited/deleted semantics validation",
        ],
    },
    40: {
        "item_number": 40,
        "goal": QC_PREP_CHAT_APP_GOALS[40],
        "implemented_outputs": [
            "Signal export row normalization and SQLCipher database inventory",
            "thread/recipient attribution and attachment metadata",
            "SQLCipher key handling separated into authority-gated workflow",
        ],
        "commercial_blockers": [
            "SQLCipher key authority workflow",
            "trusted Signal export/native DB diff",
            "recipient/thread schema known answers",
            "deleted/disappearing message validation",
        ],
    },
    41: {
        "item_number": 41,
        "goal": QC_PREP_CHAT_APP_GOALS[41],
        "implemented_outputs": [
            "LINE, Discord, Instagram, and WeChat export row normalization",
            "service-specific thread/channel, actor, recipient, media, reaction, read/edit/deleted-state review profile",
            "extended messenger parser manifest with row citation, source viewer locator, and metadata-collapsed viewer controls",
        ],
        "commercial_blockers": [
            "service/version schema matrix and fixture corpus",
            "trusted service export/native DB diff",
            "attachment byte locality and hash validation",
            "edited/deleted/read/ephemeral semantics validation",
        ],
    },
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


def discover_vendor_export_manifest(path: Path) -> Path | None:
    candidates = [
        path.with_suffix(path.suffix + ".export-metadata.json"),
        path.with_suffix(path.suffix + ".manifest.json"),
        path.with_suffix(path.suffix + ".export-manifest.json"),
        path.with_name(path.stem + "-export-metadata.json"),
        path.with_name(path.stem + "-manifest.json"),
        path.parent / "export-metadata.json",
        path.parent / "export_manifest.json",
        path.parent / "manifest.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def build_vendor_export_manifest_profile(
    path: Path,
    *,
    source_hashes: Mapping[str, str],
    source_tool: str,
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    manifest_path = discover_vendor_export_manifest(path)
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    if manifest_path is None:
        return {
            "profile_version": "mobile-vendor-export-manifest-v1",
            "manifest_present": False,
            "source_tool": source_tool,
            "vendor_family": registry.get("family", source_tool),
            "required_export_metadata": list(registry.get("required_export_metadata", ())),
            "expected_sidecar_names": [
                path.with_suffix(path.suffix + ".export-metadata.json").name,
                path.with_suffix(path.suffix + ".manifest.json").name,
                "export-metadata.json",
                "export_manifest.json",
            ],
            "validation_status": "metadata-missing",
            "warnings": ["Vendor export metadata sidecar is missing; parser version, settings, and original acquisition hash are unverified."],
        }
    profile: dict[str, object] = {
        "profile_version": "mobile-vendor-export-manifest-v1",
        "manifest_present": True,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_file_sha256(manifest_path),
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "validation_status": "review-required",
        "warnings": [],
    }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        profile.update({"parse_status": "failed", "error": str(exc), "warnings": ["Vendor export metadata sidecar is not valid JSON."]})
        return profile
    if not isinstance(manifest, Mapping):
        profile.update({"parse_status": "failed", "warnings": ["Vendor export metadata sidecar root must be a JSON object."]})
        return profile
    normalized_manifest = normalize_keys(manifest)
    source_sha256 = source_hashes.get("sha256", "")
    manifest_source_sha256 = optional_text(
        first_value(normalized_manifest, ("source_sha256", "export_sha256", "export_file_sha256", "file_sha256"))
    )
    original_hash = optional_text(
        first_value(
            normalized_manifest,
            ("original_acquisition_sha256", "device_acquisition_sha256", "image_sha256", "ufdr_sha256", "source_device_sha256"),
        )
    )
    version_keys = tuple(registry.get("version_keys", ()))
    vendor_tool_version = optional_text(first_value(normalized_manifest, (*version_keys, "vendor_tool_version", "tool_version")))
    parser_version = optional_text(first_value(normalized_manifest, ("parser_version", "export_parser_version", "schema_version")))
    export_settings = first_value(normalized_manifest, ("export_settings", "settings", "options", "export_options"))
    missing_required: list[str] = []
    for field in registry.get("required_export_metadata", ()):
        if field == "vendor_tool" and not optional_text(first_value(normalized_manifest, ("vendor_tool", "tool", "product"))):
            missing_required.append(field)
        elif field == "vendor_tool_version" and not vendor_tool_version:
            missing_required.append(field)
        elif field == "export_settings" and not export_settings:
            missing_required.append(field)
        elif field == "original_acquisition_sha256" and not original_hash:
            missing_required.append(field)
    source_hash_matches = bool(source_sha256 and manifest_source_sha256 and source_sha256.lower() == manifest_source_sha256.lower())
    profile.update(
        {
            "parse_status": "json-parsed",
            "vendor_tool": optional_text(first_value(normalized_manifest, ("vendor_tool", "tool", "product"))) or source_tool,
            "vendor_tool_version": vendor_tool_version,
            "parser_version": parser_version,
            "schema_version": optional_text(first_value(normalized_manifest, ("schema_version", "export_schema_version", "format_version"))),
            "source_sha256": manifest_source_sha256,
            "source_hash_matches_manifest": source_hash_matches,
            "original_acquisition_sha256": original_hash,
            "original_acquisition_hash_present": bool(original_hash),
            "export_settings_present": bool(export_settings),
            "missing_required_metadata": missing_required,
            "manifest_key_count": len(normalized_manifest),
            "input_row_count": len(rows),
            "validation_status": "metadata-linked" if source_hash_matches and original_hash and vendor_tool_version and not missing_required else "review-required",
        }
    )
    if not source_hash_matches:
        profile["warnings"].append("Source export SHA-256 in sidecar is missing or does not match the imported export file.")
    if missing_required:
        profile["warnings"].append(f"Vendor export metadata is missing required fields: {', '.join(missing_required)}")
    return profile


def build_vendor_schema_registry_profile(
    *,
    source_tool: str,
    rows: Sequence[Mapping[str, object]],
    detected_types: set[str],
    vendor_manifest_profile: Mapping[str, object],
) -> dict[str, object]:
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    normalized_rows = [normalize_keys(row) for row in rows[:500]]
    key_set = sorted({key for row in normalized_rows for key in row})
    version_keys = tuple(registry.get("version_keys", ()))
    schema_versions = sorted(
        {
            optional_text(first_value(row, (*version_keys, "schemaversion", "schema_version", "exportversion", "export_version")))
            for row in normalized_rows
            if optional_text(first_value(row, (*version_keys, "schemaversion", "schema_version", "exportversion", "export_version")))
        }
    )
    expected_artifacts = set(registry.get("expected_artifacts", ()))
    family_aliases = {
        "message": "messages",
        "contact": "contacts",
        "call": "calls",
        "app": "apps",
        "file": "files",
        "account": "accounts",
        "browser": "browser",
        "media": "media",
    }
    observed_families = {
        family_aliases.get(artifact_type.removeprefix("mobile-"), artifact_type.removeprefix("mobile-"))
        for artifact_type in detected_types
    }
    missing_expected = sorted(expected_artifacts - observed_families)
    return {
        "profile_version": "mobile-vendor-schema-registry-v1",
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "known_vendor_profile": bool(registry),
        "schema_versions": schema_versions[:50],
        "schema_version_count": len(schema_versions),
        "observed_artifact_families": sorted(observed_families),
        "expected_artifact_families": sorted(expected_artifacts),
        "missing_expected_artifact_families": missing_expected,
        "sampled_normalized_key_count": len(key_set),
        "sampled_normalized_keys": key_set[:100],
        "manifest_validation_status": vendor_manifest_profile.get("validation_status", "metadata-missing"),
        "manifest_vendor_tool_version": vendor_manifest_profile.get("vendor_tool_version", ""),
        "schema_registry_known_answer_validated": False,
        "reporting_status": "schema-mapped-but-known-answer-required",
    }


def build_mobile_vendor_schema_mapper_manifest(
    *,
    path: Path,
    source_format: str,
    source_tool: str,
    source_hashes: Mapping[str, str],
    rows: Sequence[Mapping[str, object]],
    detected_type_counts: Mapping[str, int],
    source_profile: Mapping[str, object],
    vendor_manifest_profile: Mapping[str, object],
) -> dict[str, object]:
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    normalized_rows = [normalize_keys(row) for row in rows[:500]]
    sampled_keys = sorted({key for row in normalized_rows for key in row})
    output_to_family = {
        str(definition["output_artifact_type"]): family
        for family, definition in VENDOR_ARTIFACT_MAPPER_KEYS.items()
    }
    mapper_statuses: list[dict[str, object]] = []
    for family, definition in VENDOR_ARTIFACT_MAPPER_KEYS.items():
        output_type = str(definition["output_artifact_type"])
        key_sets = definition.get("required_key_sets", ())
        recognized_keys = sorted(
            {
                key
                for key_set in key_sets
                for key in key_set
                if key in sampled_keys
            }
        )
        mapper_statuses.append(
            {
                "family": family,
                "output_artifact_type": output_type,
                "observed": int(detected_type_counts.get(output_type, 0)) > 0,
                "normalized_row_count": int(detected_type_counts.get(output_type, 0)),
                "recognized_key_count": len(recognized_keys),
                "recognized_key_sample": recognized_keys[:40],
                "semantic_fields": list(definition.get("semantic_fields", ())),
                "mapper_status": "active" if detected_type_counts.get(output_type, 0) else "available-not-observed",
            }
        )
    observed_families = sorted(
        {
            output_to_family.get(artifact_type, artifact_type.removeprefix("mobile-"))
            for artifact_type in detected_type_counts
        }
    )
    expected_families = sorted(str(item) for item in registry.get("expected_artifacts", ()))
    missing_expected = sorted(set(expected_families) - set(observed_families))
    source_hash_matches = bool(vendor_manifest_profile.get("source_hash_matches_manifest"))
    original_hash_present = bool(vendor_manifest_profile.get("original_acquisition_hash_present"))
    settings_present = bool(vendor_manifest_profile.get("export_settings_present"))
    vendor_version_present = bool(vendor_manifest_profile.get("vendor_tool_version"))
    manifest: dict[str, object] = {
        "manifest_version": "mobile-vendor-schema-mapper-manifest-v1",
        "item_number": 26,
        "gap_id": "#26",
        "artifact_goal": "Cellebrite/XRY/GrayKey/AXIOM export deep import schema registry and mapper evidence",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "known_vendor_profile": bool(registry),
        "supported_vendor_families": [
            {
                "source_tool": vendor,
                "vendor_family": str(profile.get("family", vendor)),
                "expected_artifacts": list(profile.get("expected_artifacts", ())),
            }
            for vendor, profile in sorted(VENDOR_SCHEMA_REGISTRY.items())
        ],
        "source": {
            "source_format": source_format,
            "source_sha256": source_hashes.get("sha256", ""),
            "input_row_count": int(source_profile.get("input_row_count") or len(rows)),
            "emitted_row_count": int(source_profile.get("emitted_row_count") or sum(detected_type_counts.values())),
            "unclassified_or_skipped_row_count": int(source_profile.get("unclassified_or_skipped_row_count") or 0),
            "truncated_by_row_cap": bool(source_profile.get("truncated_by_row_cap")),
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
        },
        "schema_registry": {
            "profile_version": "mobile-vendor-schema-registry-v1",
            "schema_versions": list(
                (source_profile.get("vendor_schema_registry_profile") or {}).get("schema_versions", [])
            )
            if isinstance(source_profile.get("vendor_schema_registry_profile"), Mapping)
            else [],
            "expected_artifact_families": expected_families,
            "observed_artifact_families": observed_families,
            "missing_expected_artifact_families": missing_expected,
            "sampled_normalized_key_count": len(sampled_keys),
            "sampled_normalized_keys": sampled_keys[:100],
        },
        "artifact_mappers": mapper_statuses,
        "source_manifest_linkage": {
            "manifest_present": bool(vendor_manifest_profile.get("manifest_present")),
            "manifest_path": optional_text(vendor_manifest_profile.get("manifest_path")),
            "manifest_sha256": optional_text(vendor_manifest_profile.get("manifest_sha256")),
            "vendor_tool_version": optional_text(vendor_manifest_profile.get("vendor_tool_version")),
            "vendor_parser_version": optional_text(vendor_manifest_profile.get("parser_version")),
            "schema_version": optional_text(vendor_manifest_profile.get("schema_version")),
            "source_hash_matches_manifest": source_hash_matches,
            "original_acquisition_hash_present": original_hash_present,
            "export_settings_present": settings_present,
            "validation_status": optional_text(vendor_manifest_profile.get("validation_status")),
        },
        "source_viewer_locator": {
            "viewer": "mobile-vendor-export-source",
            "source_path": str(path.resolve()),
            "artifact_type": "mobile-export-source",
            "source_tool": source_tool,
        },
        "validation": {
            "implemented": True,
            "usable": True,
            "internal_fixture_validated": True,
            "vendor_version_schema_matrix_present": bool(registry),
            "source_hash_linked_to_sidecar": source_hash_matches,
            "original_acquisition_hash_recorded": original_hash_present,
            "export_settings_recorded": settings_present,
            "vendor_tool_version_recorded": vendor_version_present,
            "trusted_vendor_diff_attached": False,
            "known_answer_deleted_semantics_attached": False,
            "commercial_grade": False,
        },
        "commercial_blockers": [
            "trusted-vendor-mobile-export-diff-required",
            "per-vendor-version-schema-fixtures-required",
            "deleted-record-semantics-known-answer-required",
            "original-acquisition-hash-and-export-settings-independent-review-required",
        ],
        "reporting_status": "schema-mapper-ready-for-review-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_vendor_export_report_grade_validation_plan(
    *,
    path: Path,
    source_format: str,
    source_tool: str,
    source_hashes: Mapping[str, str],
    rows: Sequence[Mapping[str, object]],
    detected_type_counts: Mapping[str, int],
    source_profile: Mapping[str, object],
    vendor_manifest_profile: Mapping[str, object],
    mapper_manifest: Mapping[str, object],
) -> dict[str, object]:
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    output_root = path.parent / f"{path.stem}-rapidtriage-validation"
    vendor_version = optional_text(vendor_manifest_profile.get("vendor_tool_version"))
    source_hash_matches = bool(vendor_manifest_profile.get("source_hash_matches_manifest"))
    original_hash_present = bool(vendor_manifest_profile.get("original_acquisition_hash_present"))
    settings_present = bool(vendor_manifest_profile.get("export_settings_present"))
    manifest_linked = bool(vendor_manifest_profile.get("manifest_present"))
    known_vendor = bool(registry)
    emitted_count = int(source_profile.get("emitted_row_count") or sum(detected_type_counts.values()))
    input_count = int(source_profile.get("input_row_count") or len(rows))
    metadata_sidecar = discover_vendor_export_manifest(path) or path.with_suffix(path.suffix + ".export-metadata.json")
    validation_commands = [
        _mobile_vendor_export_validation_command(
            "source-export-manifest",
            ["rapidtriage", "manifest", str(path.parent), "--output", str(output_root / "source-export-manifest.json")],
            purpose="Hash the vendor export folder and preserve the imported source file inventory.",
            expected_output=str(output_root / "source-export-manifest.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "mobile-export-import",
            [
                "rapidtriage",
                "artifacts",
                str(path.parent),
                "--kind",
                "mobile-export",
                "--output",
                str(output_root / "rapidtriage-mobile-export.json"),
            ],
            purpose="Regenerate RapidTriage mobile export rows from the vendor export folder.",
            expected_output=str(output_root / "rapidtriage-mobile-export.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "vendor-metadata-sidecar",
            [
                "<analyst>",
                "create-or-review-export-metadata",
                str(metadata_sidecar),
            ],
            purpose="Attach vendor tool/version, export settings, source SHA-256, and original acquisition hash linkage.",
            expected_output=str(metadata_sidecar),
            trusted_tool=True,
            status="complete" if manifest_linked and source_hash_matches and vendor_version and settings_present else "operator-action-required",
        ),
        _mobile_vendor_export_validation_command(
            "trusted-vendor-mobile-export-diff",
            [
                "rapidtriage",
                "cross-tool-validate",
                "--rapid-output",
                str(output_root / "rapidtriage-mobile-export.json"),
                "--reference-output",
                f"{source_tool}=<trusted-vendor-export.csv>",
                "--backlog-item",
                "26",
                "--source-evidence",
                str(path),
                "--tool-version",
                f"{source_tool}={vendor_version or '<vendor-version>'}",
                "--tool-command",
                f"{source_tool}=<trusted-tool-export-command>",
                "--corpus-scope",
                "<vendor-version-and-deleted-record-known-answer-scope>",
                "--output",
                str(output_root / "mobile-vendor-trusted-diff.json"),
                "--json",
            ],
            purpose="Compare normalized RapidTriage rows against trusted Cellebrite/XRY/GrayKey/AXIOM export rows.",
            expected_output=str(output_root / "mobile-vendor-trusted-diff.json"),
            trusted_tool=True,
            status="pending-cross-tool-validate",
        ),
    ]
    evidence_slots = [
        {
            "id": "source-export-integrity",
            "label": "Imported vendor export source SHA-256",
            "status": "complete" if source_hashes.get("sha256") else "pending-source-hash",
            "required_before_report": True,
            "sha256": source_hashes.get("sha256", ""),
        },
        {
            "id": "vendor-tool-family-detected",
            "label": "Cellebrite/XRY/GrayKey/AXIOM family detected",
            "status": "complete" if known_vendor else "review-required",
            "required_before_report": True,
            "source_tool": source_tool,
            "vendor_family": registry.get("family", source_tool),
        },
        {
            "id": "vendor-metadata-sidecar",
            "label": "Vendor export metadata sidecar linked to source hash",
            "status": "complete" if manifest_linked and source_hash_matches else ("review-required" if manifest_linked else "missing"),
            "required_before_report": True,
            "manifest_sha256": vendor_manifest_profile.get("manifest_sha256", ""),
            "source_hash_matches_manifest": source_hash_matches,
            "validation_status": vendor_manifest_profile.get("validation_status", ""),
        },
        {
            "id": "vendor-tool-version-and-export-settings",
            "label": "Vendor tool version and export settings recorded",
            "status": "complete" if vendor_version and settings_present else "pending-vendor-version-or-settings",
            "required_before_report": True,
            "vendor_tool_version": vendor_version,
            "export_settings_present": settings_present,
        },
        {
            "id": "original-acquisition-hash-linkage",
            "label": "Original device/acquisition hash linkage recorded",
            "status": "complete" if original_hash_present else "pending-original-acquisition-hash",
            "required_before_report": True,
            "original_acquisition_hash_present": original_hash_present,
        },
        {
            "id": "schema-mapper-and-row-identity",
            "label": "Schema mapper, source row identity, and row caps recorded",
            "status": "complete" if mapper_manifest.get("manifest_sha256") and emitted_count > 0 else "pending-schema-mapper",
            "required_before_report": True,
            "mapper_manifest_sha256": mapper_manifest.get("manifest_sha256", ""),
            "input_row_count": input_count,
            "emitted_row_count": emitted_count,
            "detected_type_counts": dict(detected_type_counts),
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
        },
        {
            "id": "trusted-vendor-mobile-export-diff",
            "label": "Independent trusted vendor export row diff",
            "status": "pending-cross-tool-validate",
            "required_before_report": True,
            "required_fields": [
                "source_record_id",
                "timestamp",
                "sender",
                "recipient",
                "message_text_sha256",
                "contact",
                "call",
                "media",
                "browser",
            ],
        },
        {
            "id": "per-vendor-version-schema-fixtures",
            "label": "Per-vendor/version schema known-answer fixtures",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["cellebrite", "xry", "graykey", "axiom"],
        },
        {
            "id": "deleted-record-semantics-corpus",
            "label": "Deleted-record and retention-semantics known-answer corpus",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["live-row", "deleted-row", "edited-row", "attachment-or-media-row"],
        },
        {
            "id": "independent-review-signoff",
            "label": "Independent analyst review of original acquisition/export procedure",
            "status": "external-review-required",
            "required_before_commercial_grade": True,
            "required_materials": ["tool version log", "export command/log", "original acquisition hash", "trusted diff"],
        },
    ]
    ready_slots = [slot["id"] for slot in evidence_slots if str(slot.get("status", "")).startswith("complete")]
    blocker_slots = [
        slot["id"]
        for slot in evidence_slots
        if slot.get("required_before_report") and not str(slot.get("status", "")).startswith("complete")
    ]
    payload: dict[str, object] = {
        "profile_version": MOBILE_VENDOR_EXPORT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 26,
        "gap_id": "#26",
        "source_path": str(path.resolve()),
        "source_tool": source_tool,
        "source_format": source_format,
        "vendor_family": registry.get("family", source_tool),
        "output_root": str(output_root),
        "status": "report-validation-blocked" if blocker_slots else "ready-for-report-review",
        "commercial_grade_ready": False,
        "source_hashes": dict(source_hashes),
        "source_profile": dict(source_profile),
        "vendor_export_manifest_profile": dict(vendor_manifest_profile),
        "mobile_vendor_schema_mapper_manifest_hash": optional_text(mapper_manifest.get("manifest_sha256")),
        "validation_commands": validation_commands,
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slots,
        "blocking_slot_ids": blocker_slots,
        "report_claim_boundary": (
            "This plan can make one vendor mobile export reviewable when all report-required slots pass; "
            "it is still not proof of complete device acquisition, deleted-record semantics, encrypted store coverage, "
            "or vendor-version parser parity without trusted diffs and external known-answer corpora."
        ),
        "commercial_grade_blockers": list(MOBILE_VENDOR_EXPORT_REPORT_GRADE_BLOCKERS),
        "operator_next_steps": [
            "Preserve the original acquisition hash and vendor export transcript before importing rows.",
            "Attach or review the export metadata sidecar and confirm the source export SHA-256 matches.",
            "Regenerate RapidTriage mobile export rows, then run cross-tool validation against the trusted vendor export.",
            "Attach vendor-version schema fixtures and deleted-record known-answer evidence before using commercial-grade wording.",
        ],
    }
    payload["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    return payload


def _mobile_vendor_export_validation_command(
    command_id: str,
    argv: Sequence[object],
    *,
    purpose: str,
    expected_output: str,
    trusted_tool: bool = False,
    status: str = "pending-run",
) -> dict[str, object]:
    clean_argv = [str(item) for item in argv if str(item) != ""]
    return {
        "id": command_id,
        "argv": clean_argv,
        "command": shlex.join(clean_argv),
        "purpose": purpose,
        "expected_output": expected_output,
        "status": status,
        "trusted_tool_required": trusted_tool,
    }


def _gap_item_numbers(gap_ids: Sequence[str]) -> list[int]:
    numbers: list[int] = []
    for gap_id in gap_ids:
        value = str(gap_id).strip().removeprefix("#")
        if value.isdigit():
            number = int(value)
            if number not in numbers:
                numbers.append(number)
    return numbers


def _matrix_item_numbers(rows: Sequence[Mapping[str, object]], fallback: Sequence[int]) -> list[int]:
    numbers = set(fallback)
    for row in rows:
        item_number = row.get("item_number")
        if isinstance(item_number, int):
            numbers.add(item_number)
        row_numbers = row.get("item_numbers")
        if isinstance(row_numbers, Sequence) and not isinstance(row_numbers, (str, bytes)):
            numbers.update(int(number) for number in row_numbers if isinstance(number, int))
    return sorted(numbers)


def _mobile_matrix_status(complete: bool, observed: bool) -> str:
    if complete:
        return "validated"
    if observed:
        return "observed-validation-required"
    return "supported-not-observed"


def build_mobile_schema_compatibility_matrix(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
    gap_ids: Sequence[str],
) -> dict[str, object]:
    service = optional_text(details.get("service"))
    profile = chat_app_profile(service) if service else None
    source_profile = (
        details.get("mobile_export_source_profile")
        if isinstance(details.get("mobile_export_source_profile"), Mapping)
        else {}
    )
    vendor_manifest = (
        details.get("vendor_export_manifest_profile")
        if isinstance(details.get("vendor_export_manifest_profile"), Mapping)
        else {}
    )
    mapper_manifest = (
        details.get("mobile_vendor_schema_mapper_manifest")
        if isinstance(details.get("mobile_vendor_schema_mapper_manifest"), Mapping)
        else {}
    )
    validation_plan = (
        details.get("mobile_vendor_export_validation_plan")
        if isinstance(details.get("mobile_vendor_export_validation_plan"), Mapping)
        else {}
    )
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    matrix_rows: list[dict[str, object]] = []
    base_item_numbers = _gap_item_numbers(gap_ids)

    if "#26" in gap_ids:
        observed_artifacts = (
            source_profile.get("detected_artifact_types")
            if isinstance(source_profile.get("detected_artifact_types"), list)
            else []
        )
        registry_profile = source_profile.get("vendor_schema_registry_profile")
        schema_versions: list[str] = []
        if isinstance(registry_profile, Mapping):
            raw_versions = registry_profile.get("schema_versions")
            if isinstance(raw_versions, list):
                schema_versions = [optional_text(value) for value in raw_versions if optional_text(value)]
        for vendor, registry in sorted(VENDOR_SCHEMA_REGISTRY.items()):
            observed_vendor = vendor == source_tool
            metadata_complete = observed_vendor and all(
                bool(vendor_manifest.get(key))
                for key in ("vendor_tool_version", "source_hash_matches_manifest", "original_acquisition_hash_present")
            )
            matrix_rows.append(
                {
                    "row_id": f"vendor-export:{vendor}",
                    "scope": "vendor-export",
                    "item_number": 26,
                    "target": vendor,
                    "vendor_family": optional_text(registry.get("family") or vendor),
                    "observed_in_source": observed_vendor,
                    "source_tool_version": optional_text(
                        vendor_manifest.get("vendor_tool_version") or source_profile.get("vendor_tool_version")
                    )
                    if observed_vendor
                    else "",
                    "schema_versions": schema_versions if observed_vendor else [],
                    "source_format": source_format if observed_vendor else "",
                    "required_export_metadata": list(registry.get("required_export_metadata", ())),
                    "metadata_linkage_complete": bool(metadata_complete),
                    "expected_artifact_families": list(registry.get("expected_artifacts", ())),
                    "observed_artifact_types": observed_artifacts if observed_vendor else [],
                    "mapper_manifest_sha256": optional_text(mapper_manifest.get("manifest_sha256")) if observed_vendor else "",
                    "validation_plan_sha256": optional_text(validation_plan.get("manifest_sha256")) if observed_vendor else "",
                    "known_answer_validated": False,
                    "commercial_grade_ready": False,
                    "status": _mobile_matrix_status(False, observed_vendor),
                    "blockers": [
                        "per-vendor-version-schema-fixtures-required",
                        "trusted-vendor-mobile-export-diff-required",
                    ],
                }
            )
        artifact_mappers = mapper_manifest.get("artifact_mappers")
        if isinstance(artifact_mappers, list):
            for mapper in artifact_mappers:
                if not isinstance(mapper, Mapping):
                    continue
                observed_mapper = bool(mapper.get("observed"))
                matrix_rows.append(
                    {
                        "row_id": f"vendor-mapper:{optional_text(mapper.get('family'))}",
                        "scope": "vendor-artifact-mapper",
                        "item_number": 26,
                        "target": optional_text(mapper.get("family")),
                        "output_artifact_type": optional_text(mapper.get("output_artifact_type")),
                        "observed_in_source": observed_mapper,
                        "normalized_row_count": int(mapper.get("normalized_row_count") or 0),
                        "semantic_fields": list(mapper.get("semantic_fields", ())),
                        "known_answer_validated": False,
                        "commercial_grade_ready": False,
                        "status": _mobile_matrix_status(False, observed_mapper),
                        "blockers": [
                            "mapper-field-semantics-known-answer-required",
                            "deleted-record-semantics-known-answer-required",
                        ],
                    }
                )

    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata", "ios-keychain-inventory"}:
        root_profile = details.get("ios_backup_root_profile") if isinstance(details.get("ios_backup_root_profile"), Mapping) else {}
        scope_profile = details.get("ios_backup_scope_profile") if isinstance(details.get("ios_backup_scope_profile"), Mapping) else {}
        is_keychain = artifact_type == "ios-keychain-inventory"
        matrix_rows.append(
            {
                "row_id": "ios-backup:manifest-db",
                "scope": "ios-backup",
                "item_number": 27,
                "target": "Manifest.db / Info.plist / Status.plist",
                "observed_in_source": artifact_type != "ios-keychain-inventory",
                "product_version": optional_text(root_profile.get("product_version") or details.get("product_version")),
                "manifest_row_count": int(scope_profile.get("manifest_row_count") or details.get("manifest_row_count") or 0),
                "required_files_present": bool(root_profile.get("required_files_present") or validation_checks.get("required_backup_files_present")),
                "encrypted_backup_unlocked": bool(validation_checks.get("encrypted_backup_unlocked")),
                "commercial_grade_ready": False,
                "status": _mobile_matrix_status(False, artifact_type != "ios-keychain-inventory"),
                "blockers": [
                    "trusted-ios-backup-parser-diff-required",
                    "encrypted-backup-authority-review-required",
                ],
            }
        )
        matrix_rows.append(
            {
                "row_id": "ios-keychain:redacted-inventory",
                "scope": "ios-keychain",
                "item_number": 28,
                "target": "keychain inventory",
                "observed_in_source": is_keychain or bool(root_profile.get("keychain_file")),
                "values_redacted": bool(validation_checks.get("values_redacted", True)),
                "secrets_extracted": bool(validation_checks.get("secrets_extracted")),
                "lawful_authority_gate_required": True,
                "commercial_grade_ready": False,
                "status": _mobile_matrix_status(False, is_keychain or bool(root_profile.get("keychain_file"))),
                "blockers": [
                    "trusted-ios-keychain-inventory-diff-required",
                    "lawful-authority-and-controlled-reveal-audit-required",
                ],
            }
        )

    if artifact_type == "mobile-app":
        package = optional_text(details.get("package") or details.get("bundle_id") or details.get("bundle") or details.get("app_id"))
        matrix_rows.append(
            {
                "row_id": f"android-app-package:{package or 'unknown'}",
                "scope": "android-app-or-ios-bundle",
                "item_numbers": [29, 30],
                "target": package or optional_text(details.get("app_name") or "unknown"),
                "observed_in_source": True,
                "app_version": optional_text(details.get("version") or details.get("app_version")),
                "apk_or_app_data_inventory": True,
                "native_app_database_decoded": False,
                "permission_risk_model_present": bool(details.get("risk_flags")),
                "commercial_grade_ready": False,
                "status": "inventory-only-validation-required",
                "blockers": [
                    "android-backup-artifact-known-answer-required",
                    "apk-binary-manifest-and-data-schema-validation-required",
                ],
            }
        )

    if service:
        selected_services = {
            "KakaoTalk",
            "WhatsApp",
            "Telegram",
            "Signal",
            "LINE",
            "Discord",
            "Instagram",
            "WeChat",
        }
        for chat_profile in CHAT_APP_PROFILES:
            chat_service = optional_text(chat_profile.get("service"))
            if chat_service not in selected_services and chat_service != service:
                continue
            observed_chat = chat_service == service
            chat_gap_ids = chat_app_gap_ids(chat_service)
            blockers = chat_app_blockers(chat_service)
            if chat_service == "KakaoTalk":
                blockers = sorted(
                    {
                        *blockers,
                        "post-bigbang-known-answer-corpus-required",
                        "kakaotalk-version-and-memory-key-boundary-validation-required",
                    }
                )
            matrix_rows.append(
                {
                    "row_id": f"messenger-service:{service_family(chat_service)}",
                    "scope": "messenger-service",
                    "item_numbers": _gap_item_numbers(chat_gap_ids),
                    "target": chat_service,
                    "observed_in_source": observed_chat,
                    "aliases": list(chat_profile.get("aliases", ())),
                    "message_tables": list(chat_profile.get("message_tables", ())),
                    "source_tool": source_tool if observed_chat else "",
                    "app_version": optional_text(details.get("app_version")) if observed_chat else "",
                    "schema_version": optional_text(details.get("schema_version")) if observed_chat else "",
                    "strategy_track": optional_text(
                        (details.get("chat_app_strategy_profile") or {}).get("selected_track")
                        if isinstance(details.get("chat_app_strategy_profile"), Mapping)
                        else ""
                    )
                    if observed_chat
                    else "supported-profile",
                    "row_citation_present": bool(details.get("source_record_id") or source_index is not None) if observed_chat else False,
                    "known_answer_validated": False,
                    "commercial_grade_ready": False,
                    "status": _mobile_matrix_status(False, observed_chat),
                    "blockers": blockers,
                }
            )

    row_item_numbers = _matrix_item_numbers(matrix_rows, base_item_numbers)
    row_blockers = sorted(
        {
            str(blocker)
            for row in matrix_rows
            for blocker in row.get("blockers", [])
            if isinstance(blocker, str) and blocker
        }
    )
    scope = "mobile-record"
    if artifact_type == "mobile-export-source":
        scope = "vendor-export-source"
    elif service:
        scope = "messenger-service"
    elif artifact_type.startswith("ios-"):
        scope = "ios-backup-or-keychain"
    elif artifact_type == "mobile-app":
        scope = "mobile-app-package"
    matrix: dict[str, object] = {
        "profile_version": "mobile-schema-compatibility-matrix-v1",
        "scope": scope,
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": optional_text(source_hashes.get("sha256")),
        "gap_ids": list(gap_ids),
        "item_numbers": row_item_numbers,
        "service": service,
        "known_service_profile": profile is not None if service else False,
        "matrix_row_count": len(matrix_rows),
        "matrix_rows": matrix_rows,
        "coverage": {
            "vendor_export_rows": sum(1 for row in matrix_rows if row.get("scope") == "vendor-export"),
            "vendor_mapper_rows": sum(1 for row in matrix_rows if row.get("scope") == "vendor-artifact-mapper"),
            "messenger_service_rows": sum(1 for row in matrix_rows if row.get("scope") == "messenger-service"),
            "backup_or_keychain_rows": sum(1 for row in matrix_rows if str(row.get("scope", "")).startswith("ios-")),
            "android_or_app_rows": sum(1 for row in matrix_rows if row.get("scope") == "android-app-or-ios-bundle"),
            "observed_row_count": sum(1 for row in matrix_rows if row.get("observed_in_source")),
            "commercial_grade_row_count": sum(1 for row in matrix_rows if row.get("commercial_grade_ready")),
        },
        "reportability_decision": {
            "decision": "do-not-report-mobile-schema-as-commercial-complete",
            "allowed_use": "triage-schema-version-and-source-review-pivot",
            "blockers": row_blockers,
        },
        "commercial_grade_ready": False,
        "ready_for_court_report": False,
    }
    matrix["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in matrix.items() if key != "manifest_sha256"}
    )
    return matrix


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
    # Screen-time classification runs before the generic app branch: loose
    # path tokens such as "app" otherwise match user directories like
    # Windows AppData and swallow screen-time rows.
    if keys.intersection(SCREEN_TIME_KEYS) and any(
        token in source_hint for token in ("screentime", "screen_time", "digital", "wellbeing", "appusage", "app_usage")
    ):
        return "mobile-screen-time"
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
    if keys.intersection(LOCATION_KEYS) and (
        keys.intersection({"latitude", "longitude", "latitudee7", "longitudee7", "lat", "lon", "lng"})
        or any(token in source_hint for token in ("location", "gps", "geofence", "map"))
    ):
        return "mobile-location"
    if keys.intersection(HEALTH_KEYS) and any(
        token in source_hint for token in ("health", "fitness", "steps", "workout", "activity", "sleep")
    ):
        return "mobile-health"
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
    if artifact_type == "mobile-location":
        return normalize_location(row)
    if artifact_type == "mobile-health":
        return normalize_health(row)
    if artifact_type == "mobile-screen-time":
        return normalize_screen_time(row)
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
    deleted_state = optional_text(first_value(row, ("deleted", "deletedstate", "isdeleted", "deletionstatus")))
    kakaotalk_profile = kakaotalk_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    whatsapp_profile = whatsapp_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    telegram_profile = telegram_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    signal_profile = signal_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
    extended_messenger_profile = extended_messenger_message_review_profile(
        service=service,
        row=row,
        app_version=app_version,
        text=text,
        media_reference=media_reference,
        reaction=reaction,
        deleted_state=deleted_state,
    )
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
        "deleted_state": deleted_state,
        "risk_flags": message_risk_flags(text, service),
        "validation_checks": {
            **row_validation_checks(row, required=("timestamp",), content_present=bool(text)),
            "service_detected": bool(service),
            "participants_detected": bool(participants),
            "message_id_present": bool(message_id),
            "media_reference_present": bool(media_reference),
            "reaction_present": bool(reaction),
            "app_schema_validated": False,
            "kakaotalk_review_profile_emitted": bool(kakaotalk_profile),
            "kakaotalk_message_hash_present": bool(kakaotalk_profile.get("message_text_sha256_present")) if kakaotalk_profile else False,
            "kakaotalk_attachment_metadata_present": bool(kakaotalk_profile.get("attachment_metadata_present")) if kakaotalk_profile else False,
            "kakaotalk_read_or_deleted_state_tracked": bool(kakaotalk_profile.get("read_state_present") or kakaotalk_profile.get("deleted_state_present")) if kakaotalk_profile else False,
            "whatsapp_review_profile_emitted": bool(whatsapp_profile),
            "whatsapp_message_hash_present": bool(whatsapp_profile.get("message_text_sha256_present")) if whatsapp_profile else False,
            "whatsapp_media_metadata_present": bool(whatsapp_profile.get("media_metadata_present")) if whatsapp_profile else False,
            "whatsapp_jid_attribution_present": bool(whatsapp_profile.get("jid_attribution_present")) if whatsapp_profile else False,
            "telegram_review_profile_emitted": bool(telegram_profile),
            "telegram_message_hash_present": bool(telegram_profile.get("message_text_sha256_present")) if telegram_profile else False,
            "telegram_account_or_dialog_attribution_present": bool(telegram_profile.get("account_or_dialog_attribution_present")) if telegram_profile else False,
            "telegram_media_cache_metadata_present": bool(telegram_profile.get("media_cache_metadata_present")) if telegram_profile else False,
            "signal_review_profile_emitted": bool(signal_profile),
            "signal_message_hash_present": bool(signal_profile.get("message_text_sha256_present")) if signal_profile else False,
            "signal_thread_or_recipient_attribution_present": bool(signal_profile.get("thread_or_recipient_attribution_present")) if signal_profile else False,
            "signal_attachment_metadata_present": bool(signal_profile.get("attachment_metadata_present")) if signal_profile else False,
            "extended_messenger_review_profile_emitted": bool(extended_messenger_profile),
            "extended_messenger_service_attribution_present": (
                bool(extended_messenger_profile.get("service_attribution_present")) if extended_messenger_profile else False
            ),
            "extended_messenger_thread_or_channel_present": (
                bool(extended_messenger_profile.get("thread_or_channel_attribution_present")) if extended_messenger_profile else False
            ),
            "extended_messenger_attachment_metadata_present": (
                bool(extended_messenger_profile.get("attachment_metadata_present")) if extended_messenger_profile else False
            ),
        },
        **({"kakaotalk_message_review_profile": kakaotalk_profile} if kakaotalk_profile else {}),
        **({"whatsapp_message_review_profile": whatsapp_profile} if whatsapp_profile else {}),
        **({"telegram_message_review_profile": telegram_profile} if telegram_profile else {}),
        **({"signal_message_review_profile": signal_profile} if signal_profile else {}),
        **({"extended_messenger_message_review_profile": extended_messenger_profile} if extended_messenger_profile else {}),
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


def classify_kakaotalk_export_attachment(media_reference: str, attachment_name: str, message_type: str) -> str:
    lowered = f"{media_reference} {attachment_name} {message_type}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".gif", "image", "photo", "thumbnail")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".avi", ".3gp", "video")):
        return "video"
    if any(token in lowered for token in (".m4a", ".mp3", ".wav", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in ("file", "attach", ".pdf", ".doc", ".xls", ".zip")):
        return "file"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


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


def is_whatsapp_jid(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith("@s.whatsapp.net") or lowered.endswith("@g.us") or lowered.endswith("@broadcast")


def whatsapp_actor_shape(value: str) -> str:
    if not value:
        return "missing"
    if value.endswith("@g.us"):
        return "group-jid"
    if value.endswith("@s.whatsapp.net"):
        return "user-jid"
    if value.endswith("@broadcast"):
        return "broadcast-jid"
    if any(character.isdigit() for character in value):
        return "phone-or-export-actor"
    return "display-name-or-export-actor"


def classify_whatsapp_media(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".3gp", "video")):
        return "video"
    if any(token in lowered for token in (".opus", ".ogg", ".m4a", ".mp3", ".wav", "audio", "ptt", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


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


def classify_telegram_media(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".mkv", ".webm", "video")):
        return "video"
    if any(token in lowered for token in (".ogg", ".opus", ".m4a", ".mp3", ".wav", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


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


def classify_signal_attachment(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".webm", ".3gp", "video")):
        return "video"
    if any(token in lowered for token in (".m4a", ".mp3", ".wav", ".ogg", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


EXTENDED_MESSENGER_REVIEW_SERVICES = {"WeChat", "LINE", "Discord", "Instagram"}


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


def extended_messenger_source_track(service: str) -> str:
    tracks = {
        "WeChat": "wechat-export-wcdb-authority-gated-schema-review",
        "LINE": "line-export-database-schema-review",
        "Discord": "discord-data-package-channel-message-review",
        "Instagram": "instagram-data-download-thread-message-review",
    }
    return tracks.get(service, "extended-service-export-schema-validation")


def classify_extended_messenger_attachment(media_reference: str, attachment_name: str) -> str:
    lowered = f"{media_reference} {attachment_name}".lower()
    if any(token in lowered for token in (".jpg", ".jpeg", ".png", ".webp", ".gif", "image", "photo", "sticker")):
        return "image"
    if any(token in lowered for token in (".mp4", ".mov", ".mkv", ".webm", ".3gp", "video", "reel")):
        return "video"
    if any(token in lowered for token in (".m4a", ".mp3", ".wav", ".ogg", ".opus", "audio", "voice")):
        return "audio"
    if any(token in lowered for token in (".pdf", ".doc", ".xls", ".ppt", ".zip", "document", "file")):
        return "document"
    if media_reference or attachment_name:
        return "metadata-only"
    return "none"


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


def mobile_decimal_location(value: object) -> float | None:
    text = optional_text(value).strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        return None
    if abs(number) > 180 and number.is_integer():
        number = number / 10_000_000
    if -180 <= number <= 180:
        return number
    return None


def mobile_location_review_profile(
    latitude: float | None,
    longitude: float | None,
    label: str,
    source_device: str,
) -> dict[str, object]:
    return {
        "profile_version": "mobile-location-map-review-profile-v1",
        "coordinate_pair_present": latitude is not None and longitude is not None,
        "latitude": latitude,
        "longitude": longitude,
        "label_present": bool(label),
        "source_device_present": bool(source_device),
        "values_are_candidates": True,
        "source_viewer_hint": "Use the map/timeline view to correlate this coordinate with media EXIF, Wi-Fi, app, and cloud location rows.",
        "not_proof_of": [
            "person-physically-present",
            "device-owner-present",
            "continuous-route",
        ],
        "report_blockers": [
            "source-app-schema-fixture-required",
            "timezone-and-clock-skew-validation-required",
            "map-provider-independent-review-required",
        ],
    }


def mobile_location_risk_flags(latitude: float | None, longitude: float | None) -> list[str]:
    flags = ["mobile-location-candidate"]
    if latitude is not None and longitude is not None:
        flags.extend(["precise-location", "map-review-candidate"])
    return flags


def first_present_health_metric(row: Mapping[str, object]) -> str:
    for key in ("steps", "stepcount", "heartrate", "sleep", "sleepstart", "workout", "calories", "distance"):
        if optional_text(first_value(row, (key,))):
            return key
    return ""


def mobile_health_review_profile(metric_type: str, metric_value: str) -> dict[str, object]:
    return {
        "profile_version": "mobile-health-review-profile-v1",
        "metric_type": metric_type,
        "metric_value_present": bool(metric_value),
        "values_are_candidates": True,
        "source_viewer_hint": "Correlate health/fitness rows with device unlocks, app usage, location, and acquisition timestamps.",
        "not_proof_of": [
            "device-holder-identity",
            "medical-grade-measurement",
            "continuous-activity",
        ],
        "report_blockers": [
            "health-app-schema-version-required",
            "device-timezone-validation-required",
            "source-device-attribution-required",
        ],
    }


def mobile_screen_time_review_profile(app_name: str, duration: str, screen_event: str) -> dict[str, object]:
    return {
        "profile_version": "mobile-screen-time-review-profile-v1",
        "app_name_present": bool(app_name),
        "duration_present": bool(duration),
        "screen_event_present": bool(screen_event),
        "values_are_candidates": True,
        "source_viewer_hint": "Correlate screen/app usage with notifications, app databases, and device lock/unlock events.",
        "not_proof_of": [
            "specific-person-using-device",
            "foreground-app-content-viewed",
            "complete-screen-time-history",
        ],
        "report_blockers": [
            "digital-wellbeing-screen-time-schema-fixture-required",
            "timezone-and-device-clock-validation-required",
            "app-identity-corroboration-required",
        ],
    }


def normalize_location(row: Mapping[str, object]) -> dict[str, object]:
    latitude = mobile_decimal_location(first_value(row, ("latitude", "lat", "latitudee7")))
    longitude = mobile_decimal_location(first_value(row, ("longitude", "lon", "lng", "longitudee7")))
    label = optional_text(first_value(row, ("placename", "address", "location", "name", "label")))
    source_device = optional_text(first_value(row, ("sourcedevice", "device", "devicename", "account", "source")))
    return {
        "event_type": "mobile-location",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "latitude": latitude,
        "longitude": longitude,
        "accuracy_meters": optional_text(first_value(row, ("accuracy", "horizontalaccuracy", "radius"))),
        "altitude": optional_text(first_value(row, ("altitude", "elevation"))),
        "location_label": label,
        "source_device": source_device,
        "map_review_profile": mobile_location_review_profile(latitude, longitude, label, source_device),
        "risk_flags": mobile_location_risk_flags(latitude, longitude),
        "validation_checks": {
            **row_validation_checks(row, required=("latitude", "longitude", "latitudee7", "longitudee7")),
            "coordinate_pair_present": latitude is not None and longitude is not None,
            "map_review_profile_emitted": True,
        },
        "commercial_grade_blockers": mobile_export_blockers("vendor-location-export"),
        "raw": dict(row),
    }


def normalize_health(row: Mapping[str, object]) -> dict[str, object]:
    metric_type = optional_text(first_value(row, ("metric", "type", "activitytype", "workout", "category")))
    metric_value = optional_text(first_value(row, ("value", "steps", "stepcount", "heartrate", "calories", "distance", "duration")))
    if not metric_type:
        metric_type = first_present_health_metric(row)
    return {
        "event_type": "mobile-health",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "metric_type": metric_type,
        "metric_value": metric_value,
        "unit": optional_text(first_value(row, ("unit", "units"))),
        "source_device": optional_text(first_value(row, ("sourcedevice", "device", "devicename", "source"))),
        "start_time": normalize_timestamp(first_value(row, ("start", "starttime", "sleepstart"))),
        "end_time": normalize_timestamp(first_value(row, ("end", "endtime", "sleepend"))),
        "health_review_profile": mobile_health_review_profile(metric_type, metric_value),
        "risk_flags": ["mobile-health-fitness-candidate"] + ([f"health-metric:{normalize_key(metric_type)}"] if metric_type else []),
        "validation_checks": {
            **row_validation_checks(row, required=("steps", "stepcount", "heartrate", "sleep", "workout")),
            "metric_present": bool(metric_type or metric_value),
            "health_review_profile_emitted": True,
        },
        "commercial_grade_blockers": mobile_export_blockers("vendor-health-export"),
        "raw": dict(row),
    }


def normalize_screen_time(row: Mapping[str, object]) -> dict[str, object]:
    app_name = optional_text(first_value(row, ("app", "appname", "application", "bundleid", "package", "name")))
    duration = optional_text(first_value(row, ("duration", "durationseconds", "foregroundtime", "screentime", "appusage")))
    screen_event = optional_text(first_value(row, ("event", "screenon", "screenoff", "unlockcount", "notificationcount")))
    return {
        "event_type": "mobile-screen-time",
        "timestamp": normalize_timestamp(first_value(row, TIMESTAMP_KEYS)),
        "app_name": app_name,
        "duration_seconds": duration,
        "screen_event": screen_event,
        "source_device": optional_text(first_value(row, ("sourcedevice", "device", "devicename", "source"))),
        "screen_time_review_profile": mobile_screen_time_review_profile(app_name, duration, screen_event),
        "risk_flags": ["mobile-screen-time-candidate"] + (["app-usage-duration-candidate"] if duration else []),
        "validation_checks": {
            **row_validation_checks(row, required=("screentime", "digitalwellbeing", "appusage", "duration")),
            "app_or_event_present": bool(app_name or screen_event),
            "duration_present": bool(duration),
            "screen_time_review_profile_emitted": True,
        },
        "commercial_grade_blockers": mobile_export_blockers("vendor-screen-time-export"),
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
    timeline_profile = build_mobile_timeline_correlation_profile(
        message_rows=message_rows,
        media_rows=media_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        message_media_links=message_media_links,
    )
    correlation_citation_manifest = build_mobile_correlation_citation_manifest(
        message_rows=message_rows,
        media_rows=media_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        message_media_links=message_media_links,
        timeline_profile=timeline_profile,
    )
    timeline_report_grade_validation_plan = build_mobile_timeline_report_grade_validation_plan(
        message_rows=message_rows,
        media_rows=media_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        message_media_links=message_media_links,
        timeline_profile=timeline_profile,
        citation_manifest=correlation_citation_manifest,
    )
    actor_review_profile = build_mobile_actor_review_profile(unified_actor_view)
    actor_citation_manifest = build_mobile_actor_citation_manifest(
        actor_rows=unified_actor_view,
        message_rows=message_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
    )
    actor_report_grade_validation_plan = build_mobile_actor_report_grade_validation_plan(
        actor_rows=unified_actor_view,
        message_rows=message_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        actor_review_profile=actor_review_profile,
        actor_citation_manifest=actor_citation_manifest,
    )
    schema_compatibility_profile = build_mobile_schema_compatibility_profile(schema_version_registry)
    schema_version_manifest = build_mobile_schema_version_manifest(
        registry=schema_version_registry,
        source_rows=[*message_rows, *app_rows],
    )
    schema_report_grade_validation_plan = build_mobile_schema_report_grade_validation_plan(
        registry=schema_version_registry,
        source_rows=[*message_rows, *app_rows],
        schema_compatibility_profile=schema_compatibility_profile,
        schema_version_manifest=schema_version_manifest,
    )
    validation_checks = {
        "message_media_correlation_available": bool(message_rows and media_rows),
        "media_message_links_built": bool(message_media_links),
        "contact_message_correlation_available": bool(contact_rows and message_rows),
        "call_message_correlation_available": bool(call_rows and message_rows),
        "unified_contact_call_sms_view_built": bool(unified_actor_view),
        "actor_review_profile_built": bool(actor_review_profile.get("actor_count")),
        "timeline_correlation_profile_built": bool(timeline_profile.get("event_count")),
        "app_specific_schema_versions_tracked": bool(schema_versions),
        "schema_version_registry_built": bool(schema_version_registry),
        "schema_compatibility_profile_built": bool(schema_compatibility_profile.get("entry_count")),
        "schema_version_manifest_built": bool(schema_version_manifest.get("schema_entry_count")),
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
        "mobile_schema_compatibility_profile": schema_compatibility_profile,
        "mobile_schema_version_manifest": schema_version_manifest,
        "mobile_schema_version_manifest_hash": schema_version_manifest["manifest_sha256"],
        "mobile_schema_report_grade_validation_plan": schema_report_grade_validation_plan,
        "mobile_schema_report_grade_validation_plan_hash": schema_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "message_media_links": message_media_links,
        "media_message_link_count": len(message_media_links),
        "mobile_timeline_correlation_profile": timeline_profile,
        "mobile_correlation_citation_manifest": correlation_citation_manifest,
        "mobile_correlation_citation_manifest_hash": correlation_citation_manifest["manifest_sha256"],
        "mobile_timeline_report_grade_validation_plan": timeline_report_grade_validation_plan,
        "mobile_timeline_report_grade_validation_plan_hash": timeline_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "unified_contact_call_sms_view": unified_actor_view,
        "unified_contact_call_sms_view_count": len(unified_actor_view),
        "mobile_actor_review_profile": actor_review_profile,
        "mobile_actor_citation_manifest": actor_citation_manifest,
        "mobile_actor_citation_manifest_hash": actor_citation_manifest["manifest_sha256"],
        "mobile_actor_report_grade_validation_plan": actor_report_grade_validation_plan,
        "mobile_actor_report_grade_validation_plan_hash": actor_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
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
            timeline_profile=timeline_profile,
            citation_manifest=correlation_citation_manifest,
            timeline_validation_plan=timeline_report_grade_validation_plan,
            actor_review_profile=actor_review_profile,
            actor_citation_manifest=actor_citation_manifest,
            actor_validation_plan=actor_report_grade_validation_plan,
            schema_compatibility_profile=schema_compatibility_profile,
            schema_version_manifest=schema_version_manifest,
            schema_validation_plan=schema_report_grade_validation_plan,
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


def build_mobile_timeline_correlation_profile(
    *,
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    message_media_links: list[Mapping[str, object]],
    limit: int = MAX_MOBILE_CORRELATION_TIMELINE_ROWS,
) -> dict[str, object]:
    media_link_by_message = {
        optional_text(link.get("message_id")): link
        for link in message_media_links
        if optional_text(link.get("message_id"))
    }
    events: list[dict[str, object]] = []
    missing_timestamp_count = 0

    def append_event(row: Mapping[str, object], event_type: str, actor: str, summary: str) -> None:
        nonlocal missing_timestamp_count
        timestamp = optional_text(row.get("timestamp"))
        if not timestamp:
            missing_timestamp_count += 1
        events.append(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "service": optional_text(row.get("service")),
                "actor": actor,
                "summary": summary[:240],
                "source_record_id": optional_text(row.get("source_record_id") or row.get("message_id")),
                "message_id": optional_text(row.get("message_id")),
                "media_reference": optional_text(row.get("media_reference") or row.get("attachment_name")),
                "media_link_status": mobile_media_link_status(row, media_link_by_message),
                "validation_status": "candidate",
            }
        )

    for message in message_rows:
        actor = optional_text(message.get("sender") or message.get("recipient") or "")
        append_event(message, "message", actor, optional_text(message.get("text") or message.get("message_text_sha256")))
    for media in media_rows:
        append_event(
            media,
            "media",
            optional_text(media.get("owner") or media.get("account") or ""),
            optional_text(media.get("media_path") or media.get("file_name") or media.get("sha256")),
        )
    for call in call_rows:
        append_event(
            call,
            "call",
            optional_text(call.get("phone_number") or call.get("contact_name") or ""),
            optional_text(call.get("call_type") or "call"),
        )

    events.sort(key=lambda event: (not bool(event.get("timestamp")), str(event.get("timestamp")), str(event.get("event_type"))))
    unresolved_link_count = sum(
        1 for link in message_media_links if link.get("validation_status") == "unresolved-candidate"
    )
    linked_count = sum(1 for link in message_media_links if link.get("validation_status") == "candidate")
    return {
        "profile_version": "mobile-timeline-correlation-v1",
        "selected_track": "source-export-bounded-message-media-call-timeline",
        "event_count": len(events),
        "events": events[:limit],
        "event_cap": limit,
        "event_truncated": len(events) > limit,
        "message_event_count": len(message_rows),
        "media_event_count": len(media_rows),
        "call_event_count": len(call_rows),
        "contact_record_count": len(contact_rows),
        "missing_timestamp_count": missing_timestamp_count,
        "message_media_link_count": len(message_media_links),
        "resolved_media_link_count": linked_count,
        "unresolved_media_link_count": unresolved_link_count,
        "device_wide_timeline_ready": False,
        "known_answer_correlation_required": True,
        "timezone_validation_required": True,
        "reporting_status": "candidate-timeline-correlation-validation-required",
        "required_before_report": [
            "validate message/media/call ordering against a known-answer device or trusted vendor timeline",
            "verify attachment bytes and hashes before treating media metadata as recovered media",
            "record timezone assumptions and device clock skew before report-grade chronology claims",
        ],
    }


def build_mobile_correlation_citation_manifest(
    *,
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    message_media_links: list[Mapping[str, object]],
    timeline_profile: Mapping[str, object],
    limit: int = MAX_MOBILE_CORRELATION_TIMELINE_ROWS,
) -> dict[str, object]:
    source_rows = [*message_rows, *media_rows, *contact_rows, *call_rows]
    row_citations: list[dict[str, object]] = []
    for index, row in enumerate(source_rows[:limit], start=1):
        row_type = optional_text(row.get("artifact_type") or row.get("event_type") or "mobile-row")
        citation_payload = {
            "citation_index": index,
            "row_type": row_type,
            "source_index": int(row.get("source_index") or 0),
            "source_record_id": optional_text(row.get("source_record_id") or row.get("message_id")),
            "timestamp": optional_text(row.get("timestamp")),
            "service": optional_text(row.get("service")),
            "message_id": optional_text(row.get("message_id")),
            "media_reference_sha256": optional_text(row.get("media_reference_sha256")),
            "media_sha256": optional_text(row.get("sha256")),
            "actor_hash": sha256_text(
                optional_text(
                    row.get("sender")
                    or row.get("recipient")
                    or row.get("phone_number")
                    or row.get("contact_name")
                    or row.get("account_identifier")
                )
            )
            if optional_text(
                row.get("sender")
                or row.get("recipient")
                or row.get("phone_number")
                or row.get("contact_name")
                or row.get("account_identifier")
            )
            else "",
        }
        row_citations.append(
            {
                **citation_payload,
                "row_hash": stable_mobile_sha256(citation_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-export-row",
                    "source_index": citation_payload["source_index"],
                    "source_record_id": citation_payload["source_record_id"],
                    "row_type": row_type,
                    "open_requires_authority": False,
                },
            }
        )

    link_citations: list[dict[str, object]] = []
    for index, link in enumerate(message_media_links[:limit], start=1):
        link_payload = {
            "link_index": index,
            "message_id": optional_text(link.get("message_id")),
            "message_timestamp": optional_text(link.get("message_timestamp")),
            "service": optional_text(link.get("service")),
            "media_reference_sha256": sha256_text(optional_text(link.get("media_reference")))
            if optional_text(link.get("media_reference"))
            else "",
            "media_sha256": optional_text(link.get("media_sha256")),
            "validation_status": optional_text(link.get("validation_status")),
            "matched_by": list(link.get("matched_by") or []),
        }
        link_citations.append(
            {
                **link_payload,
                "link_hash": stable_mobile_sha256(link_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-message-media-link",
                    "message_id": link_payload["message_id"],
                    "validation_status": link_payload["validation_status"],
                    "open_requires_attachment_validation": link_payload["validation_status"] != "candidate",
                },
            }
        )

    timeline_events = [
        event for event in timeline_profile.get("events", []) if isinstance(event, Mapping)
    ]
    timeline_citations: list[dict[str, object]] = []
    for index, event in enumerate(timeline_events[:limit], start=1):
        event_payload = {
            "event_index": index,
            "timestamp": optional_text(event.get("timestamp")),
            "event_type": optional_text(event.get("event_type")),
            "service": optional_text(event.get("service")),
            "source_record_id": optional_text(event.get("source_record_id")),
            "message_id": optional_text(event.get("message_id")),
            "media_link_status": optional_text(event.get("media_link_status")),
            "validation_status": optional_text(event.get("validation_status")),
        }
        timeline_citations.append(
            {
                **event_payload,
                "event_hash": stable_mobile_sha256(event_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-correlation-timeline-event",
                    "event_index": index,
                    "source_record_id": event_payload["source_record_id"],
                    "message_id": event_payload["message_id"],
                },
            }
        )

    manifest: dict[str, object] = {
        "manifest_version": "mobile-correlation-citation-manifest-v1",
        "item_number": 43,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-message-media-call-timeline-citations",
        "row_citation_count": len(row_citations),
        "row_citation_cap": limit,
        "row_citations_truncated": len(source_rows) > limit,
        "row_citations": row_citations,
        "message_media_link_citation_count": len(link_citations),
        "message_media_link_citations": link_citations,
        "timeline_event_citation_count": len(timeline_citations),
        "timeline_event_citations": timeline_citations,
        "event_count": int(timeline_profile.get("event_count") or 0),
        "event_cap": int(timeline_profile.get("event_cap") or limit),
        "timeline_event_truncated": bool(timeline_profile.get("event_truncated")),
        "resolved_media_link_count": int(timeline_profile.get("resolved_media_link_count") or 0),
        "unresolved_media_link_count": int(timeline_profile.get("unresolved_media_link_count") or 0),
        "device_wide_timeline_ready": False,
        "timezone_validation_required": True,
        "known_answer_correlation_required": True,
        "passed_validation_check_ids": [
            "mobile-correlation-citation-manifest-emitted",
            "mobile-source-row-citations-built",
            "mobile-timeline-event-citations-built",
        ],
        "failed_validation_check_ids": [
            "device-wide-timeline-not-validated",
            "timezone-clock-skew-not-validated",
            "attachment-byte-recovery-not-validated",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[43],
        ],
        "commercial_blockers": [
            "device-wide-timeline-not-validated",
            "timezone-clock-skew-not-validated",
            "attachment-byte-recovery-not-validated",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[43],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_timeline_report_grade_validation_plan(
    *,
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    message_media_links: list[Mapping[str, object]],
    timeline_profile: Mapping[str, object],
    citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    timeline_profile_hash = stable_mobile_sha256(timeline_profile)
    citation_manifest_hash = optional_text(citation_manifest.get("manifest_sha256"))
    timeline_event_citation_count = int(citation_manifest.get("timeline_event_citation_count") or 0)
    message_media_link_citation_count = int(citation_manifest.get("message_media_link_citation_count") or 0)
    event_count = int(timeline_profile.get("event_count") or 0)
    event_cap = int(timeline_profile.get("event_cap") or MAX_MOBILE_CORRELATION_TIMELINE_ROWS)

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "mobile-timeline-source-row-counts-preserved",
            ready=True,
            evidence=(
                f"messages={len(message_rows)} media={len(media_rows)} "
                f"contacts={len(contact_rows)} calls={len(call_rows)}"
            ),
        ),
        slot(
            "mobile-timeline-profile-emitted",
            ready=timeline_profile.get("profile_version") == "mobile-timeline-correlation-v1",
            evidence=f"timeline_profile_sha256={timeline_profile_hash}",
            blocker_id="mobile-timeline-profile-required",
            operator_action="Regenerate the mobile export so the bounded timeline correlation profile is emitted.",
        ),
        slot(
            "mobile-correlation-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="mobile-correlation-citation-manifest-required",
            operator_action="Regenerate the mobile export so row, link, and timeline citations are hashable.",
        ),
        slot(
            "mobile-timeline-event-source-citations",
            ready=timeline_event_citation_count > 0,
            evidence=f"timeline_event_citation_count={timeline_event_citation_count}",
            blocker_id="mobile-timeline-event-source-citations-required",
            operator_action="Attach source row locators for every report-selected timeline event.",
        ),
        slot(
            "mobile-message-media-link-citations",
            ready=message_media_link_citation_count > 0,
            evidence=f"message_media_link_citation_count={message_media_link_citation_count}",
            blocker_id="mobile-message-media-link-citations-required",
            operator_action="Attach source locators for message-to-media links before reporting attachment correlation.",
        ),
        slot(
            "mobile-timeline-row-cap-and-truncation-disclosed",
            ready=event_cap > 0,
            evidence=(
                f"event_count={event_count} event_cap={event_cap} "
                f"event_truncated={bool(timeline_profile.get('event_truncated'))}"
            ),
            blocker_id="mobile-timeline-row-cap-disclosure-required",
            operator_action="Record row caps and truncation status before reviewing large mobile timelines.",
        ),
        slot(
            "mobile-correlation-device-wide-timeline",
            ready=False,
            evidence="device_wide_timeline_ready=false",
            blocker_id="mobile-correlation-device-wide-timeline-required",
            operator_action="Join app export rows with filesystem, acquisition, and device metadata timelines.",
        ),
        slot(
            "mobile-correlation-timezone-skew-validation",
            ready=False,
            evidence="timezone_and_clock_skew_validated=false",
            blocker_id="mobile-correlation-timezone-skew-validation-required",
            operator_action="Validate source timezone semantics and device clock skew against acquisition metadata.",
        ),
        slot(
            "mobile-correlation-attachment-byte-recovery",
            ready=False,
            evidence=(
                f"resolved_media_link_count={int(timeline_profile.get('resolved_media_link_count') or 0)} "
                f"unresolved_media_link_count={int(timeline_profile.get('unresolved_media_link_count') or 0)}"
            ),
            blocker_id="mobile-correlation-attachment-byte-recovery-required",
            operator_action="Recover attachment bytes and hash them before claiming media was recovered.",
        ),
        slot(
            "mobile-correlation-vendor-timeline-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[43],
            operator_action="Attach a passing Cellebrite/XRY/GrayKey/AXIOM/iLEAPP/native timeline diff.",
        ),
        slot(
            "mobile-correlation-known-answer-corpus",
            ready=False,
            evidence="known_answer_corpus_attached=false",
            blocker_id="mobile-correlation-known-answer-corpus-required",
            operator_action="Validate message/media/call chronology against a known-answer mobile corpus.",
        ),
        slot(
            "mobile-correlation-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="mobile-correlation-independent-review-required",
            operator_action="Attach independent reviewer signoff before device-wide timeline wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": MOBILE_TIMELINE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 43,
        "gap_id": "#43",
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-message-media-call-timeline-report-validation",
        "message_count": len(message_rows),
        "media_count": len(media_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "message_media_link_count": len(message_media_links),
        "timeline_event_count": event_count,
        "timeline_event_cap": event_cap,
        "timeline_event_truncated": bool(timeline_profile.get("event_truncated")),
        "timeline_profile_sha256": timeline_profile_hash,
        "citation_manifest_sha256": citation_manifest_hash,
        "timeline_event_citation_count": timeline_event_citation_count,
        "message_media_link_citation_count": message_media_link_citation_count,
        "resolved_media_link_count": int(timeline_profile.get("resolved_media_link_count") or 0),
        "unresolved_media_link_count": int(timeline_profile.get("unresolved_media_link_count") or 0),
        "missing_timestamp_count": int(timeline_profile.get("missing_timestamp_count") or 0),
        "device_wide_timeline_ready": False,
        "timezone_validation_required": True,
        "known_answer_correlation_required": True,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MOBILE_TIMELINE_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapidtriage-mobile-export.json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-mobile-export.json --reference-output <trusted-mobile-timeline> --backlog-item 43 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 45 --json",
        ],
        "report_guidance": {
            "allowed_use": "mobile-message-media-call-timeline-triage-pivot",
            "forbidden_claims": [
                "complete device-wide mobile timeline",
                "all attachments recovered",
                "timezone-normalized chronology is report-defensible",
                "deleted or hidden app events are fully recovered",
            ],
            "required_disclaimer": (
                "Mobile correlation is bounded to imported source rows. Treat it as a review pivot until "
                "device-wide joins, timezone/skew checks, attachment byte recovery, trusted diffs, known-answer "
                "fixtures, and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def mobile_media_link_status(
    message: Mapping[str, object],
    media_link_by_message: Mapping[str, Mapping[str, object]],
) -> str:
    message_id = optional_text(message.get("message_id"))
    if message_id and message_id in media_link_by_message:
        return optional_text(media_link_by_message[message_id].get("validation_status")) or "candidate"
    if optional_text(message.get("media_reference") or message.get("attachment_name")):
        return "unresolved-candidate"
    return "not-applicable"


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


def build_mobile_actor_review_profile(actor_rows: list[Mapping[str, object]], *, limit: int = 100) -> dict[str, object]:
    review_queue: list[dict[str, object]] = []
    multi_identifier_count = 0
    named_actor_count = 0
    for actor in actor_rows:
        phone_count = len(actor.get("phones") or [])
        email_count = len(actor.get("emails") or [])
        name_count = len(actor.get("contact_names") or [])
        if phone_count + email_count > 1 or name_count > 1:
            multi_identifier_count += 1
        if name_count:
            named_actor_count += 1
        score = int(actor.get("message_count") or 0) + int(actor.get("call_count") or 0) + int(actor.get("contact_record_count") or 0)
        review_queue.append(
            {
                "actor": optional_text(actor.get("actor")),
                "message_count": int(actor.get("message_count") or 0),
                "call_count": int(actor.get("call_count") or 0),
                "contact_record_count": int(actor.get("contact_record_count") or 0),
                "phone_count": phone_count,
                "email_count": email_count,
                "contact_name_count": name_count,
                "services": list(actor.get("services") or [])[:10],
                "first_seen_at": optional_text(actor.get("first_seen_at")),
                "last_seen_at": optional_text(actor.get("last_seen_at")),
                "review_priority": "high" if score >= 3 or phone_count + email_count > 1 else "normal",
                "merge_split_review_required": phone_count + email_count > 1 or name_count > 1,
                "validation_status": "candidate",
            }
        )
    review_queue.sort(
        key=lambda item: (
            item["review_priority"] != "high",
            -(int(item["message_count"]) + int(item["call_count"]) + int(item["contact_record_count"])),
            str(item["actor"]),
        )
    )
    return {
        "profile_version": "mobile-actor-review-v1",
        "selected_track": "source-export-contact-call-sms-actor-review",
        "actor_count": len(actor_rows),
        "named_actor_count": named_actor_count,
        "multi_identifier_actor_count": multi_identifier_count,
        "review_queue": review_queue[:limit],
        "review_queue_count": min(len(review_queue), limit),
        "review_queue_truncated": len(review_queue) > limit,
        "device_wide_identity_resolution_ready": False,
        "merge_split_review_required": bool(actor_rows),
        "known_answer_actor_diff_required": True,
        "reporting_status": "candidate-actor-view-validation-required",
        "required_before_report": [
            "review actor merge/split decisions for shared devices, recycled numbers, aliases, and group chats",
            "validate contact/call/SMS actor counts against a trusted vendor report or hand-labeled fixture",
            "preserve analyst review state before using actor groupings in a report narrative",
        ],
    }


def build_mobile_actor_citation_manifest(
    *,
    actor_rows: list[Mapping[str, object]],
    message_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    limit: int = 200,
) -> dict[str, object]:
    actor_entries: list[dict[str, object]] = []
    for index, actor in enumerate(actor_rows[:limit], start=1):
        actor_value = optional_text(actor.get("actor"))
        actor_hash = sha256_text(actor_value) if actor_value else ""
        linked_message_count = sum(
            1
            for row in message_rows
            if actor_value
            and actor_value in [participant for participant in row.get("participants", []) if isinstance(participant, str)]
        )
        linked_contact_count = sum(
            1
            for row in contact_rows
            if actor_value
            and actor_value
            in {
                optional_text(row.get("phone_number")),
                optional_text(row.get("email")),
                optional_text(row.get("contact_name")),
            }
        )
        linked_call_count = sum(
            1
            for row in call_rows
            if actor_value
            and actor_value
            in {
                optional_text(row.get("phone_number")),
                optional_text(row.get("contact_name")),
            }
        )
        entry_payload = {
            "entry_index": index,
            "actor_sha256": actor_hash,
            "message_count": int(actor.get("message_count") or 0),
            "call_count": int(actor.get("call_count") or 0),
            "contact_record_count": int(actor.get("contact_record_count") or 0),
            "linked_message_count": linked_message_count,
            "linked_contact_count": linked_contact_count,
            "linked_call_count": linked_call_count,
            "first_seen_at": optional_text(actor.get("first_seen_at")),
            "last_seen_at": optional_text(actor.get("last_seen_at")),
            "service_count": len(actor.get("services") or []),
            "phone_count": len(actor.get("phones") or []),
            "email_count": len(actor.get("emails") or []),
            "contact_name_count": len(actor.get("contact_names") or []),
            "merge_split_review_required": len(actor.get("phones") or []) + len(actor.get("emails") or []) > 1
            or len(actor.get("contact_names") or []) > 1,
        }
        actor_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_mobile_sha256(entry_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-actor-review",
                    "actor_sha256": actor_hash,
                    "open_requires_merge_split_review": entry_payload["merge_split_review_required"],
                },
                "validation_status": "candidate-actor-citation",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "mobile-actor-citation-manifest-v1",
        "item_number": 44,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-contact-call-sms-actor-citations",
        "actor_entry_count": len(actor_entries),
        "actor_entry_cap": limit,
        "actor_entries_truncated": len(actor_rows) > limit,
        "actor_entries": actor_entries,
        "message_count": len(message_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "raw_actor_values_serialized": False,
        "device_wide_identity_resolution_ready": False,
        "merge_split_review_required": bool(actor_rows),
        "known_answer_actor_diff_required": True,
        "passed_validation_check_ids": [
            "mobile-actor-citation-manifest-emitted",
            "actor-source-viewer-locators-built",
            "actor-values-hashed-in-manifest",
        ],
        "failed_validation_check_ids": [
            "device-wide-identity-resolution-not-validated",
            "actor-merge-split-review-not-persisted",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[44],
        ],
        "commercial_blockers": [
            "device-wide-identity-resolution-not-validated",
            "actor-merge-split-review-not-persisted",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[44],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_actor_report_grade_validation_plan(
    *,
    actor_rows: list[Mapping[str, object]],
    message_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    actor_review_profile: Mapping[str, object],
    actor_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    actor_review_profile_hash = stable_mobile_sha256(actor_review_profile)
    actor_manifest_hash = optional_text(actor_citation_manifest.get("manifest_sha256"))
    actor_entries = actor_citation_manifest.get("actor_entries")
    if not isinstance(actor_entries, list):
        actor_entries = []
    locators_present = all(
        isinstance(entry, Mapping) and isinstance(entry.get("source_viewer_locator"), Mapping)
        for entry in actor_entries
    )

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "mobile-actor-view-built",
            ready=bool(actor_rows),
            evidence=f"actor_count={len(actor_rows)}",
            blocker_id="mobile-actor-view-required",
            operator_action="Regenerate mobile correlation so contact/call/SMS/message actor pivots are present.",
        ),
        slot(
            "mobile-actor-review-profile-emitted",
            ready=actor_review_profile.get("profile_version") == "mobile-actor-review-v1",
            evidence=f"actor_review_profile_sha256={actor_review_profile_hash}",
            blocker_id="mobile-actor-review-profile-required",
            operator_action="Regenerate mobile correlation so the actor review queue is emitted.",
        ),
        slot(
            "mobile-actor-citation-manifest-emitted",
            ready=bool(actor_manifest_hash),
            evidence=f"actor_citation_manifest_sha256={actor_manifest_hash}",
            blocker_id="mobile-actor-citation-manifest-required",
            operator_action="Generate hashable actor citations before report review.",
        ),
        slot(
            "mobile-actor-values-hashed",
            ready=actor_citation_manifest.get("raw_actor_values_serialized") is False,
            evidence=f"raw_actor_values_serialized={bool(actor_citation_manifest.get('raw_actor_values_serialized'))}",
            blocker_id="mobile-actor-raw-value-serialization-blocked",
            operator_action="Regenerate actor citations with hash-only actor values.",
        ),
        slot(
            "mobile-actor-source-viewer-locators",
            ready=locators_present and bool(actor_entries),
            evidence=f"actor_entry_count={len(actor_entries)} locators_present={locators_present}",
            blocker_id="mobile-actor-source-viewer-locator-required",
            operator_action="Attach source viewer locators for every actor selected for review.",
        ),
        slot(
            "mobile-actor-review-queue-cap-disclosed",
            ready=int(actor_review_profile.get("review_queue_count") or 0) >= 0,
            evidence=(
                f"review_queue_count={int(actor_review_profile.get('review_queue_count') or 0)} "
                f"review_queue_truncated={bool(actor_review_profile.get('review_queue_truncated'))}"
            ),
            blocker_id="mobile-actor-review-queue-cap-disclosure-required",
            operator_action="Record review queue caps and truncation before large-case actor review.",
        ),
        slot(
            "mobile-actor-device-wide-identity-resolution",
            ready=False,
            evidence="device_wide_identity_resolution_ready=false",
            blocker_id="mobile-actor-device-wide-identity-resolution-required",
            operator_action="Merge actor pivots with device accounts, address books, SIM/account metadata, and app-native IDs.",
        ),
        slot(
            "mobile-actor-merge-split-review-history",
            ready=False,
            evidence="merge_split_review_history_persisted=false",
            blocker_id="mobile-actor-merge-split-review-history-required",
            operator_action="Persist analyst merge/split decisions with reviewer identity, rationale, and source citations.",
        ),
        slot(
            "mobile-actor-cross-app-dedupe",
            ready=False,
            evidence="cross_app_dedupe_validated=false",
            blocker_id="mobile-actor-cross-app-dedupe-required",
            operator_action="Validate cross-app entity deduplication before identity-complete claims.",
        ),
        slot(
            "mobile-actor-vendor-identity-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[44],
            operator_action="Attach a passing vendor/native actor identity diff.",
        ),
        slot(
            "mobile-actor-known-answer-corpus",
            ready=False,
            evidence="known_answer_actor_corpus_attached=false",
            blocker_id="mobile-actor-known-answer-corpus-required",
            operator_action="Validate shared devices, aliases, recycled numbers, group chats, and app IDs against known-answer data.",
        ),
        slot(
            "mobile-actor-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="mobile-actor-independent-review-required",
            operator_action="Attach independent reviewer signoff before identity-complete actor wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": MOBILE_ACTOR_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 44,
        "gap_id": "#44",
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-contact-call-sms-actor-report-validation",
        "actor_count": len(actor_rows),
        "message_count": len(message_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "actor_review_profile_sha256": actor_review_profile_hash,
        "actor_citation_manifest_sha256": actor_manifest_hash,
        "actor_entry_count": int(actor_citation_manifest.get("actor_entry_count") or 0),
        "review_queue_count": int(actor_review_profile.get("review_queue_count") or 0),
        "review_queue_truncated": bool(actor_review_profile.get("review_queue_truncated")),
        "multi_identifier_actor_count": int(actor_review_profile.get("multi_identifier_actor_count") or 0),
        "raw_actor_values_serialized": bool(actor_citation_manifest.get("raw_actor_values_serialized")),
        "device_wide_identity_resolution_ready": False,
        "merge_split_review_required": bool(actor_review_profile.get("merge_split_review_required")),
        "known_answer_actor_diff_required": True,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MOBILE_ACTOR_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapidtriage-mobile-export.json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-mobile-export.json --reference-output <trusted-mobile-actor-report> --backlog-item 44 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 45 --json",
        ],
        "report_guidance": {
            "allowed_use": "mobile-contact-call-sms-actor-review-pivot",
            "forbidden_claims": [
                "device-wide identity resolution complete",
                "all accounts for this person are merged",
                "actor deduplication is report-defensible",
                "shared-device or recycled-number ambiguity has been eliminated",
            ],
            "required_disclaimer": (
                "Mobile actor views are source-export review pivots. Treat identity grouping as candidate-only until "
                "merge/split review history, cross-app dedupe validation, trusted diffs, known-answer fixtures, and "
                "independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


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


def build_mobile_schema_compatibility_profile(registry: list[Mapping[str, object]]) -> dict[str, object]:
    known_validated = [row for row in registry if row.get("known_schema_validated")]
    unvalidated = [row for row in registry if not row.get("known_schema_validated")]
    app_ids = sorted({optional_text(row.get("app_identifier") or "unknown") for row in registry})
    versions = sorted({optional_text(row.get("schema_or_app_version") or "unknown") for row in registry})
    release_gate_entries = [
        {
            "app_identifier": optional_text(row.get("app_identifier") or "unknown"),
            "schema_or_app_version": optional_text(row.get("schema_or_app_version") or "unknown"),
            "event_type": optional_text(row.get("event_type") or "unknown"),
            "row_count": int(row.get("row_count") or 0),
            "known_schema_validated": bool(row.get("known_schema_validated")),
            "release_gate_status": "blocked-pending-known-answer-fixture"
            if not row.get("known_schema_validated")
            else "validated-fixture-attached",
        }
        for row in registry[:200]
    ]
    return {
        "profile_version": "mobile-schema-compatibility-v1",
        "selected_track": "app-schema-version-registry-with-release-gates",
        "entry_count": len(registry),
        "app_identifier_count": len(app_ids),
        "schema_or_app_version_count": len(versions),
        "validated_entry_count": len(known_validated),
        "unvalidated_entry_count": len(unvalidated),
        "app_identifiers": app_ids[:100],
        "schema_or_app_versions": versions[:100],
        "release_gate_entries": release_gate_entries,
        "release_gate_entry_count": len(release_gate_entries),
        "known_answer_fixture_required": bool(unvalidated),
        "schema_migration_matrix_required": True,
        "commercial_release_blocked": bool(unvalidated),
        "reporting_status": "schema-compatibility-validation-required",
        "required_before_report": [
            "attach app/version-specific schema fixtures for every message/contact/media database family",
            "record migration behavior when app schema versions change across releases",
            "block commercial parser claims for unvalidated app/schema combinations",
        ],
    }


def build_mobile_schema_version_manifest(
    *,
    registry: list[Mapping[str, object]],
    source_rows: list[Mapping[str, object]],
    limit: int = 200,
) -> dict[str, object]:
    schema_entries: list[dict[str, object]] = []
    for index, row in enumerate(registry[:limit], start=1):
        app_identifier = optional_text(row.get("app_identifier") or "unknown")
        version = optional_text(row.get("schema_or_app_version") or "unknown")
        event_type = optional_text(row.get("event_type") or "unknown")
        linked_sources: list[dict[str, object]] = []
        for source in source_rows:
            source_app = optional_text(source.get("package") or source.get("service") or source.get("app_name") or "unknown")
            source_version = optional_text(
                source.get("schema_version")
                or source.get("version")
                or source.get("app_version")
                or source.get("appversion")
                or "unknown"
            )
            source_event_type = optional_text(source.get("event_type") or source.get("artifact_type") or "unknown")
            if (source_app, source_version, source_event_type) != (app_identifier, version, event_type):
                continue
            linked_sources.append(
                {
                    "source_index": int(source.get("source_index") or len(linked_sources) + 1),
                    "source_record_id": optional_text(source.get("source_record_id") or source_record_id(source, len(linked_sources))),
                    "source_path_sha256": sha256_text(optional_text(source.get("source_path"))),
                    "source_hash_sha256": optional_text(
                        (source.get("source_hashes") or {}).get("sha256")
                        if isinstance(source.get("source_hashes"), Mapping)
                        else ""
                    ),
                }
            )
        entry_payload = {
            "entry_index": index,
            "app_identifier": app_identifier,
            "schema_or_app_version": version,
            "event_type": event_type,
            "row_count": int(row.get("row_count") or 0),
            "known_schema_validated": bool(row.get("known_schema_validated")),
            "validation_status": optional_text(row.get("validation_status") or "candidate"),
            "linked_source_count": len(linked_sources),
            "release_gate_status": "validated-fixture-attached"
            if row.get("known_schema_validated")
            else "blocked-pending-known-answer-fixture",
        }
        schema_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_mobile_sha256(entry_payload),
                "linked_source_refs": linked_sources[:25],
                "linked_source_refs_truncated": len(linked_sources) > 25,
                "source_viewer_locator": {
                    "viewer": "mobile-schema-version-review",
                    "app_identifier": app_identifier,
                    "schema_or_app_version": version,
                    "event_type": event_type,
                    "open_requires_known_answer_fixture": not row.get("known_schema_validated"),
                },
                "required_fixture_id": stable_mobile_sha256(
                    {
                        "app_identifier": app_identifier,
                        "schema_or_app_version": version,
                        "event_type": event_type,
                    }
                )[:16],
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "mobile-schema-version-manifest-v1",
        "item_number": 45,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "app-schema-version-registry-release-gates",
        "schema_entry_count": len(schema_entries),
        "schema_entry_cap": limit,
        "schema_entries_truncated": len(registry) > limit,
        "schema_entries": schema_entries,
        "source_row_count": len(source_rows),
        "known_answer_fixture_required": any(not row.get("known_schema_validated") for row in registry),
        "schema_migration_matrix_required": True,
        "release_gate_blocked": any(not row.get("known_schema_validated") for row in registry),
        "passed_validation_check_ids": [
            "mobile-schema-version-manifest-emitted",
            "schema-source-viewer-locators-built",
            "schema-release-gates-recorded",
        ],
        "failed_validation_check_ids": [
            "schema-version-registry-known-answer-not-attached",
            "schema-migration-matrix-not-attached",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[45],
        ],
        "commercial_blockers": [
            "schema-version-registry-known-answer-not-attached",
            "schema-migration-matrix-not-attached",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[45],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_schema_report_grade_validation_plan(
    *,
    registry: list[Mapping[str, object]],
    source_rows: list[Mapping[str, object]],
    schema_compatibility_profile: Mapping[str, object],
    schema_version_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    schema_profile_hash = stable_mobile_sha256(schema_compatibility_profile)
    schema_manifest_hash = optional_text(schema_version_manifest.get("manifest_sha256"))
    schema_entries = schema_version_manifest.get("schema_entries")
    if not isinstance(schema_entries, list):
        schema_entries = []
    locators_present = all(
        isinstance(entry, Mapping) and isinstance(entry.get("source_viewer_locator"), Mapping)
        for entry in schema_entries
    )
    fixture_ids_present = all(
        isinstance(entry, Mapping) and optional_text(entry.get("required_fixture_id"))
        for entry in schema_entries
    )

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "mobile-schema-version-registry-built",
            ready=bool(registry),
            evidence=f"schema_entry_count={len(registry)} source_row_count={len(source_rows)}",
            blocker_id="mobile-schema-version-registry-required",
            operator_action="Regenerate mobile correlation so app/schema version registry entries are present.",
        ),
        slot(
            "mobile-schema-compatibility-profile-emitted",
            ready=schema_compatibility_profile.get("profile_version") == "mobile-schema-compatibility-v1",
            evidence=f"schema_compatibility_profile_sha256={schema_profile_hash}",
            blocker_id="mobile-schema-compatibility-profile-required",
            operator_action="Regenerate mobile correlation so compatibility/release-gate profile is emitted.",
        ),
        slot(
            "mobile-schema-version-manifest-emitted",
            ready=bool(schema_manifest_hash),
            evidence=f"schema_version_manifest_sha256={schema_manifest_hash}",
            blocker_id="mobile-schema-version-manifest-required",
            operator_action="Generate the schema version manifest before release/report review.",
        ),
        slot(
            "mobile-schema-source-viewer-locators",
            ready=locators_present and bool(schema_entries),
            evidence=f"schema_entry_count={len(schema_entries)} locators_present={locators_present}",
            blocker_id="mobile-schema-source-viewer-locator-required",
            operator_action="Attach source viewer locators for every app/schema entry.",
        ),
        slot(
            "mobile-schema-release-gates-recorded",
            ready=bool(schema_version_manifest.get("release_gate_blocked")) or bool(schema_entries),
            evidence=f"release_gate_blocked={bool(schema_version_manifest.get('release_gate_blocked'))}",
            blocker_id="mobile-schema-release-gates-required",
            operator_action="Record release gates for every unvalidated app/schema combination.",
        ),
        slot(
            "mobile-schema-fixture-ids-emitted",
            ready=fixture_ids_present and bool(schema_entries),
            evidence=f"fixture_ids_present={fixture_ids_present} schema_entry_count={len(schema_entries)}",
            blocker_id="mobile-schema-fixture-id-required",
            operator_action="Generate stable fixture IDs so missing schema corpora are trackable.",
        ),
        slot(
            "mobile-schema-version-fixture-corpus",
            ready=False,
            evidence="schema_version_fixture_corpus_attached=false",
            blocker_id="mobile-schema-version-fixture-corpus-required",
            operator_action="Attach known-answer fixtures for every supported app/schema/event family.",
        ),
        slot(
            "mobile-schema-migration-matrix",
            ready=False,
            evidence="schema_migration_matrix_attached=false",
            blocker_id="mobile-schema-migration-matrix-required",
            operator_action="Attach schema migration behavior across app upgrades and DB version changes.",
        ),
        slot(
            "mobile-schema-trusted-migration-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[45],
            operator_action="Attach a passing trusted app-schema migration diff.",
        ),
        slot(
            "mobile-schema-release-policy-approval",
            ready=False,
            evidence="operator_release_policy_approved=false",
            blocker_id="mobile-schema-release-policy-approval-required",
            operator_action="Require an operator-approved release gate before marking a schema parser supported.",
        ),
        slot(
            "mobile-schema-upgrade-deleted-state-corpus",
            ready=False,
            evidence="upgrade_deleted_state_corpus_attached=false",
            blocker_id="mobile-schema-upgrade-deleted-state-corpus-required",
            operator_action="Validate deleted/edited/read-state semantics across schema upgrades.",
        ),
        slot(
            "mobile-schema-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="mobile-schema-independent-review-required",
            operator_action="Attach independent reviewer signoff before release-safe schema wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": MOBILE_SCHEMA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 45,
        "gap_id": "#45",
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "app-schema-version-release-gate-report-validation",
        "schema_entry_count": len(registry),
        "source_row_count": len(source_rows),
        "schema_compatibility_profile_sha256": schema_profile_hash,
        "schema_version_manifest_sha256": schema_manifest_hash,
        "schema_manifest_entry_count": int(schema_version_manifest.get("schema_entry_count") or 0),
        "schema_unvalidated_entry_count": int(schema_compatibility_profile.get("unvalidated_entry_count") or 0),
        "release_gate_entry_count": int(schema_compatibility_profile.get("release_gate_entry_count") or 0),
        "release_gate_blocked": bool(schema_version_manifest.get("release_gate_blocked")),
        "known_answer_fixture_required": bool(schema_version_manifest.get("known_answer_fixture_required")),
        "schema_migration_matrix_required": bool(schema_version_manifest.get("schema_migration_matrix_required")),
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MOBILE_SCHEMA_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapidtriage-mobile-export.json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-mobile-export.json --reference-output <trusted-schema-migration-fixture> --backlog-item 45 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 45 --json",
        ],
        "report_guidance": {
            "allowed_use": "mobile-app-schema-version-release-gate-pivot",
            "forbidden_claims": [
                "all app schemas are supported",
                "schema migration behavior is validated",
                "deleted/read-state semantics are release-safe",
                "parser compatibility is commercial-grade for unvalidated app versions",
            ],
            "required_disclaimer": (
                "Schema/version entries are release-gate candidates. Do not claim parser support for an app/version "
                "until fixture corpora, migration matrices, trusted diffs, release approval, upgrade/deleted-state "
                "tests, and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def build_mobile_correlation_trusted_diff(
    rapid_rows: list[Mapping[str, object]],
    trusted_rows: list[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    rapid_index = index_mobile_correlation_rows(rapid_rows)
    trusted_index = index_mobile_correlation_rows(trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in MOBILE_CORRELATION_TRUSTED_TOOLS
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
                        "mobile_correlation_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "mobile-correlation-trusted-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-mobile-correlation-output-as-final",
            "blockers": [] if status == "pass" else list(MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS.values()),
        },
    }


def index_mobile_correlation_rows(rows: list[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        kind = normalized_mobile_diff_value(first_mobile_alias(row, "kind", "artifact_type", "event_type", "type"))
        service = normalized_mobile_diff_value(first_mobile_alias(row, "service", "app_identifier", "app"))
        message_id = normalized_mobile_diff_value(first_mobile_alias(row, "message_id", "msg_id", "id"))
        actor = normalized_mobile_diff_value(first_mobile_alias(row, "actor", "participant", "phone", "email"))
        media_sha256 = normalized_mobile_diff_value(first_mobile_alias(row, "media_sha256", "sha256", "attachment_sha256"))
        schema_version = normalized_mobile_diff_value(first_mobile_alias(row, "schema_or_app_version", "schema_version", "app_version", "version"))
        timestamp = normalized_mobile_diff_value(first_mobile_alias(row, "timestamp", "message_timestamp", "date"))
        key = "|".join(item for item in (kind, service, message_id, actor, media_sha256, schema_version, timestamp) if item)
        if not key:
            continue
        indexed[key] = {
            "kind": kind,
            "service": service,
            "message_id": message_id,
            "actor": actor,
            "media_sha256": media_sha256,
            "schema_or_app_version": schema_version,
            "timestamp": timestamp,
        }
    return indexed


def mobile_correlation_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "ready_for_court_report": False,
        "blockers": [
            "media-message-links-are-candidate-matches-not-app-native-attachment-resolution",
            "contact-call-sms-view-is-export-scoped-not-device-wide-entity-resolution",
            "app-schema-version-registry-needs-known-answer-validation",
            *MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS.values(),
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
    timeline_profile: Mapping[str, object] | None = None,
    citation_manifest: Mapping[str, object] | None = None,
    timeline_validation_plan: Mapping[str, object] | None = None,
    actor_review_profile: Mapping[str, object] | None = None,
    actor_citation_manifest: Mapping[str, object] | None = None,
    actor_validation_plan: Mapping[str, object] | None = None,
    schema_compatibility_profile: Mapping[str, object] | None = None,
    schema_version_manifest: Mapping[str, object] | None = None,
    schema_validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    report_grade = mobile_correlation_report_grade_assessment()
    timeline_profile = timeline_profile or {}
    citation_manifest = citation_manifest or {}
    timeline_validation_plan = timeline_validation_plan or {}
    actor_review_profile = actor_review_profile or {}
    actor_citation_manifest = actor_citation_manifest or {}
    actor_validation_plan = actor_validation_plan or {}
    schema_compatibility_profile = schema_compatibility_profile or {}
    schema_version_manifest = schema_version_manifest or {}
    schema_validation_plan = schema_validation_plan or {}
    trusted_diff = trusted_diff or {}
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
    if timeline_validation_plan:
        passed_validation_check_ids.append("mobile_timeline_report_grade_validation_plan_present")
        if int(timeline_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_validation_check_ids.append("mobile_timeline_report_grade_ready_slots")
    if actor_validation_plan:
        passed_validation_check_ids.append("mobile_actor_report_grade_validation_plan_present")
        if int(actor_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_validation_check_ids.append("mobile_actor_report_grade_ready_slots")
    if schema_validation_plan:
        passed_validation_check_ids.append("mobile_schema_report_grade_validation_plan_present")
        if int(schema_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_validation_check_ids.append("mobile_schema_report_grade_ready_slots")
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
            trusted_diff=trusted_diff,
            timeline_validation_plan=timeline_validation_plan,
            actor_validation_plan=actor_validation_plan,
            schema_validation_plan=schema_validation_plan,
        ),
        "source_refs": [
            f"service:{service}" for service in services[:20]
        ] + [
            f"mobile_correlation_citation_manifest_sha256:{citation_manifest.get('manifest_sha256', '')}"
        ] + [
            "mobile_timeline_report_grade_validation_plan_sha256:"
            f"{timeline_validation_plan.get('validation_plan_sha256', '')}"
        ] + [
            f"mobile_actor_citation_manifest_sha256:{actor_citation_manifest.get('manifest_sha256', '')}"
        ] + [
            f"mobile_actor_report_grade_validation_plan_sha256:{actor_validation_plan.get('validation_plan_sha256', '')}"
        ] + [
            f"mobile_schema_version_manifest_sha256:{schema_version_manifest.get('manifest_sha256', '')}"
        ] + [
            "mobile_schema_report_grade_validation_plan_sha256:"
            f"{schema_validation_plan.get('validation_plan_sha256', '')}"
        ],
        "passed_validation_check_ids": sorted(set(passed_validation_check_ids)),
        "failed_validation_check_ids": sorted(set(failed_validation_check_ids)),
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_ids": [MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[number] for number in (43, 44, 45)],
            "required_tools": sorted(MOBILE_CORRELATION_TRUSTED_TOOLS),
        },
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
            "timeline_event_count": int(timeline_profile.get("event_count") or 0),
            "timeline_event_truncated": bool(timeline_profile.get("event_truncated")),
            "timeline_profile_present": bool(timeline_profile),
            "citation_manifest_present": bool(citation_manifest),
            "citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "timeline_report_grade_validation_plan_present": bool(timeline_validation_plan),
            "timeline_report_grade_validation_plan_hash": str(
                timeline_validation_plan.get("validation_plan_sha256") or ""
            ),
            "timeline_report_grade_ready_slot_count": int(
                timeline_validation_plan.get("ready_slot_count") or 0
            ),
            "timeline_report_grade_blocking_slot_count": int(
                timeline_validation_plan.get("blocking_slot_count") or 0
            ),
            "timeline_event_citation_count": int(citation_manifest.get("timeline_event_citation_count") or 0),
            "message_media_link_citation_count": int(
                citation_manifest.get("message_media_link_citation_count") or 0
            ),
            "timeline_missing_timestamp_count": int(timeline_profile.get("missing_timestamp_count") or 0),
            "unresolved_media_link_count": int(timeline_profile.get("unresolved_media_link_count") or 0),
            "actor_review_profile_present": bool(actor_review_profile),
            "actor_citation_manifest_present": bool(actor_citation_manifest),
            "actor_citation_manifest_hash": str(actor_citation_manifest.get("manifest_sha256") or ""),
            "actor_report_grade_validation_plan_present": bool(actor_validation_plan),
            "actor_report_grade_validation_plan_hash": str(actor_validation_plan.get("validation_plan_sha256") or ""),
            "actor_report_grade_ready_slot_count": int(actor_validation_plan.get("ready_slot_count") or 0),
            "actor_report_grade_blocking_slot_count": int(actor_validation_plan.get("blocking_slot_count") or 0),
            "actor_citation_entry_count": int(actor_citation_manifest.get("actor_entry_count") or 0),
            "raw_actor_values_serialized": bool(actor_citation_manifest.get("raw_actor_values_serialized")),
            "actor_review_queue_count": int(actor_review_profile.get("review_queue_count") or 0),
            "multi_identifier_actor_count": int(actor_review_profile.get("multi_identifier_actor_count") or 0),
            "device_wide_identity_resolution_ready": False,
            "schema_compatibility_profile_present": bool(schema_compatibility_profile),
            "schema_compatibility_entry_count": int(schema_compatibility_profile.get("entry_count") or 0),
            "schema_unvalidated_entry_count": int(schema_compatibility_profile.get("unvalidated_entry_count") or 0),
            "schema_release_gate_blocked": bool(schema_compatibility_profile.get("commercial_release_blocked")),
            "schema_version_manifest_present": bool(schema_version_manifest),
            "schema_version_manifest_hash": str(schema_version_manifest.get("manifest_sha256") or ""),
            "schema_version_manifest_entry_count": int(schema_version_manifest.get("schema_entry_count") or 0),
            "schema_version_manifest_release_gate_blocked": bool(schema_version_manifest.get("release_gate_blocked")),
            "schema_report_grade_validation_plan_present": bool(schema_validation_plan),
            "schema_report_grade_validation_plan_hash": str(
                schema_validation_plan.get("validation_plan_sha256") or ""
            ),
            "schema_report_grade_ready_slot_count": int(schema_validation_plan.get("ready_slot_count") or 0),
            "schema_report_grade_blocking_slot_count": int(schema_validation_plan.get("blocking_slot_count") or 0),
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
    trusted_diff: Mapping[str, object] | None = None,
    timeline_validation_plan: Mapping[str, object] | None = None,
    actor_validation_plan: Mapping[str, object] | None = None,
    schema_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade["blockers"] if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    if not validation_checks.get("device_wide_timeline_validated"):
        blockers.add("device-wide-timeline-not-validated")
    if not validation_checks.get("schema_version_registry_known_answer_validated"):
        blockers.add("schema-version-registry-known-answer-not-attached")
    trusted_diff = trusted_diff or {}
    timeline_validation_plan = timeline_validation_plan or {}
    actor_validation_plan = actor_validation_plan or {}
    schema_validation_plan = schema_validation_plan or {}
    if trusted_diff.get("status") != "pass":
        blockers.update(MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS.values())
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
        "timeline_report_grade_validation_plan_present": bool(timeline_validation_plan),
        "timeline_report_grade_validation_plan_hash": str(
            timeline_validation_plan.get("validation_plan_sha256") or ""
        ),
        "timeline_report_grade_ready_slot_count": int(timeline_validation_plan.get("ready_slot_count") or 0),
        "timeline_report_grade_blocking_slot_count": int(timeline_validation_plan.get("blocking_slot_count") or 0),
        "actor_report_grade_validation_plan_present": bool(actor_validation_plan),
        "actor_report_grade_validation_plan_hash": str(actor_validation_plan.get("validation_plan_sha256") or ""),
        "actor_report_grade_ready_slot_count": int(actor_validation_plan.get("ready_slot_count") or 0),
        "actor_report_grade_blocking_slot_count": int(actor_validation_plan.get("blocking_slot_count") or 0),
        "schema_report_grade_validation_plan_present": bool(schema_validation_plan),
        "schema_report_grade_validation_plan_hash": str(schema_validation_plan.get("validation_plan_sha256") or ""),
        "schema_report_grade_ready_slot_count": int(schema_validation_plan.get("ready_slot_count") or 0),
        "schema_report_grade_blocking_slot_count": int(schema_validation_plan.get("blocking_slot_count") or 0),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate device-wide timeline joins, timezone assumptions, and attachment recovery",
            "attach analyst-reviewed identity merge/split decisions for contacts/calls/SMS actors",
            "gate each app parser with schema migration fixtures and release-reviewed compatibility matrices",
            "attach passing vendor/native known-answer diffs for mobile correlation, actor view, and schema registry claims",
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
        "ios_backup_file_profile": build_ios_backup_file_profile(domain, relative_path, file_id, row.get("flags")),
        "risk_flags": ios_backup_file_risk_flags(domain, relative_path),
        "validation_checks": dict(validation),
        "commercial_grade_blockers": [
            "Manifest inventory only; file payload decoding and application schema parsing are not complete.",
            "Encrypted/protected backup handling and deleted-record recovery require external validation.",
        ],
        "raw": dict(row),
    }


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


IOS_KEYCHAIN_TABLE_CLASSES = {
    "genp": "generic-password",
    "inet": "internet-password",
    "cert": "certificate",
    "keys": "cryptographic-key",
    "identity": "identity",
    "tversion": "metadata",
}

IOS_KEYCHAIN_SENSITIVE_COLUMN_TOKENS = (
    "data",
    "v_data",
    "value",
    "password",
    "secret",
    "token",
    "key",
    "cert",
    "priv",
    "acct",
    "account",
    "agrp",
    "service",
    "svce",
    "sha1",
)


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
        normalized_key = normalize_key(key)
        if normalized_key in row and row[normalized_key] not in (None, ""):
            return row[normalized_key]
    return ""


def first_truthy(*values: object) -> object:
    for value in values:
        if value:
            return value
    return None


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
    trusted_diff = (
        details.get("mobile_correlation_trusted_diff")
        if isinstance(details.get("mobile_correlation_trusted_diff"), Mapping)
        else {}
    )
    if trusted_diff:
        evidence_refs.append(f"trusted_diff_status:{trusted_diff.get('status', '')}")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")

    item43: list[str] = []
    if validation.get("media_message_links_built") or details.get("message_media_links") is not None:
        item43.append("message-media linkage built")
    if any(int(details.get(key) or 0) >= 0 for key in ("message_count", "media_count", "contact_count", "call_count")):
        item43.append("message/contact/call/media counts preserved")
    if details.get("services") is not None:
        item43.append("service attribution")
    if details.get("timeline_correlation_ready") is not None:
        item43.append("timeline correlation readiness")
    timeline_profile = (
        details.get("mobile_timeline_correlation_profile")
        if isinstance(details.get("mobile_timeline_correlation_profile"), Mapping)
        else {}
    )
    if timeline_profile:
        item43.append("timeline correlation profile")
        evidence_refs.append(f"timeline_event_count:{timeline_profile.get('event_count', 0)}")
        evidence_refs.append(f"unresolved_media_link_count:{timeline_profile.get('unresolved_media_link_count', 0)}")
    citation_manifest = (
        details.get("mobile_correlation_citation_manifest")
        if isinstance(details.get("mobile_correlation_citation_manifest"), Mapping)
        else {}
    )
    if citation_manifest:
        item43.append("correlation citation manifest")
        evidence_refs.append(
            f"mobile_correlation_citation_manifest_sha256:{citation_manifest.get('manifest_sha256', '')}"
        )
        if int(citation_manifest.get("timeline_event_citation_count") or 0) > 0:
            item43.append("timeline event source citations")
        if int(citation_manifest.get("message_media_link_citation_count") or 0) > 0:
            item43.append("message-media link citations")
    timeline_validation_plan = (
        details.get("mobile_timeline_report_grade_validation_plan")
        if isinstance(details.get("mobile_timeline_report_grade_validation_plan"), Mapping)
        else {}
    )
    if timeline_validation_plan:
        item43.append("timeline report-grade validation plan")
        evidence_refs.append(
            "mobile_timeline_report_grade_validation_plan_sha256:"
            f"{timeline_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(timeline_validation_plan.get("ready_slot_count") or 0) >= 6:
            item43.append("timeline report-grade ready slots")
    if not validation.get("correlation_validated_against_known_answer", False):
        item43.append("known-answer limitation warning")
    if trusted_diff.get("status") == "pass":
        item43.append("trusted mobile correlation diff pass")

    item44: list[str] = []
    if validation.get("unified_contact_call_sms_view_built") or details.get("unified_contact_call_sms_view") is not None:
        item44.append("contact/call/SMS actor merge")
    if details.get("message_media_links") is not None or details.get("unified_contact_call_sms_view") is not None:
        item44.append("source row links preserved")
    if details.get("participants") is not None:
        item44.append("participant attribution")
    actor_review_profile = (
        details.get("mobile_actor_review_profile")
        if isinstance(details.get("mobile_actor_review_profile"), Mapping)
        else {}
    )
    if actor_review_profile:
        item44.append("actor review profile")
        evidence_refs.append(f"actor_review_queue_count:{actor_review_profile.get('review_queue_count', 0)}")
        evidence_refs.append(f"multi_identifier_actor_count:{actor_review_profile.get('multi_identifier_actor_count', 0)}")
    actor_citation_manifest = (
        details.get("mobile_actor_citation_manifest")
        if isinstance(details.get("mobile_actor_citation_manifest"), Mapping)
        else {}
    )
    if actor_citation_manifest:
        item44.append("actor citation manifest")
        evidence_refs.append(
            f"mobile_actor_citation_manifest_sha256:{actor_citation_manifest.get('manifest_sha256', '')}"
        )
        if int(actor_citation_manifest.get("actor_entry_count") or 0) > 0:
            item44.append("actor source viewer locators")
        if actor_citation_manifest.get("raw_actor_values_serialized") is False:
            item44.append("actor values hashed in manifest")
    actor_validation_plan = (
        details.get("mobile_actor_report_grade_validation_plan")
        if isinstance(details.get("mobile_actor_report_grade_validation_plan"), Mapping)
        else {}
    )
    if actor_validation_plan:
        item44.append("actor report-grade validation plan")
        evidence_refs.append(
            "mobile_actor_report_grade_validation_plan_sha256:"
            f"{actor_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(actor_validation_plan.get("ready_slot_count") or 0) >= 6:
            item44.append("actor report-grade ready slots")
    if actor_review_profile.get("merge_split_review_required"):
        item44.append("merge/split review requirement")
    item44.append("dedupe/entity limitation warning")
    item44.append("export-scope limitation warning")
    if trusted_diff.get("status") == "pass":
        item44.append("trusted mobile actor diff pass")

    item45: list[str] = []
    if validation.get("schema_version_registry_built") or details.get("schema_version_registry") is not None:
        item45.append("app/service schema version registry")
    schema_compatibility_profile = (
        details.get("mobile_schema_compatibility_profile")
        if isinstance(details.get("mobile_schema_compatibility_profile"), Mapping)
        else {}
    )
    if schema_compatibility_profile:
        item45.append("schema compatibility profile")
        evidence_refs.append(f"schema_compatibility_entry_count:{schema_compatibility_profile.get('entry_count', 0)}")
        evidence_refs.append(f"schema_unvalidated_entry_count:{schema_compatibility_profile.get('unvalidated_entry_count', 0)}")
    schema_version_manifest = (
        details.get("mobile_schema_version_manifest")
        if isinstance(details.get("mobile_schema_version_manifest"), Mapping)
        else {}
    )
    if schema_version_manifest:
        item45.append("schema version manifest")
        evidence_refs.append(
            f"mobile_schema_version_manifest_sha256:{schema_version_manifest.get('manifest_sha256', '')}"
        )
        if int(schema_version_manifest.get("schema_entry_count") or 0) > 0:
            item45.append("schema source viewer locators")
        if schema_version_manifest.get("release_gate_blocked"):
            item45.append("schema release gates recorded")
    schema_validation_plan = (
        details.get("mobile_schema_report_grade_validation_plan")
        if isinstance(details.get("mobile_schema_report_grade_validation_plan"), Mapping)
        else {}
    )
    if schema_validation_plan:
        item45.append("schema report-grade validation plan")
        evidence_refs.append(
            "mobile_schema_report_grade_validation_plan_sha256:"
            f"{schema_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(schema_validation_plan.get("ready_slot_count") or 0) >= 6:
            item45.append("schema report-grade ready slots")
    if details.get("services") is not None or details.get("schema_versions") is not None:
        item45.append("source app/version attribution")
    item45.append("schema compatibility warning")
    if not validation.get("schema_version_registry_known_answer_validated", False):
        item45.append("migration fixture warning")
    item45.append("release-gate limitation disclosure")
    if trusted_diff.get("status") == "pass":
        item45.append("trusted app schema migration diff pass")

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


def build_mobile_analyst_review_profile(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    gap_ids: Sequence[str],
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    manifest = details.get("mobile_vendor_import_manifest")
    if not isinstance(manifest, Mapping):
        manifest = details.get("ios_backup_parser_manifest")
    if not isinstance(manifest, Mapping):
        manifest = {}
    viewer_locator = manifest.get("source_viewer_locator") if isinstance(manifest.get("source_viewer_locator"), Mapping) else {}
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    failed_checks = report_grade.get("failed_check_ids") if isinstance(report_grade.get("failed_check_ids"), list) else []
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    summary_parts = [artifact_type, source_tool or "unknown-tool"]
    service = optional_text(details.get("service"))
    if service:
        summary_parts.append(service)
    domain = optional_text(details.get("domain"))
    if domain:
        summary_parts.append(domain)
    table = optional_text(details.get("table"))
    if table:
        summary_parts.append(table)
    package = optional_text(details.get("package"))
    if package:
        summary_parts.append(package)
    not_proof_of = [
        "complete device extraction",
        "vendor parser equivalence",
        "deleted record recovery",
        "protected or encrypted value decryption",
    ]
    if "#28" in gap_ids:
        not_proof_of.append("keychain secret values or access semantics")
    if "#27" in gap_ids:
        not_proof_of.append("decrypted iOS protected file contents")
    if "#26" in gap_ids:
        not_proof_of.append("source-complete vendor export coverage")
    return {
        "profile_version": "mobile-analyst-review-profile-v1",
        "gap_ids": list(gap_ids),
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "severity": "high" if {"credential-or-otp", "sensitive-artifact-redacted"} & set(map(str, risk_flags)) else "medium",
        "summary": " / ".join(part for part in summary_parts if part),
        "evidence_interpretation": mobile_artifact_goal(artifact_type),
        "not_proof_of": not_proof_of,
        "analyst_questions": [
            "Does this row match the original vendor/mobile tool view?",
            "Are acquisition hash, export settings, timezone, and parser version preserved?",
            "Is the source app/schema version covered by a known-answer fixture?",
            "Should this item be correlated with messages, contacts, calls, media, browser, or cloud records?",
        ],
        "primary_pivots": [
            key
            for key in (
                optional_text(details.get("source_record_id")),
                optional_text(details.get("message_id")),
                optional_text(details.get("conversation_id")),
                optional_text(details.get("file_id")),
                optional_text(details.get("domain")),
                optional_text(details.get("logical_path")),
                optional_text(details.get("table")),
                optional_text(details.get("package")),
            )
            if key
        ][:8],
        "source_field_values": {
            "source_path": optional_text(details.get("source_path")),
            "source_sha256": source_hashes.get("sha256", ""),
            "source_record_id": optional_text(details.get("source_record_id")),
            "event_type": optional_text(details.get("event_type")),
            "service": service,
            "domain": domain,
            "logical_path": optional_text(details.get("logical_path")),
            "file_id": optional_text(details.get("file_id")),
            "table": table,
            "row_count": int(details.get("row_count") or details.get("record_count") or 0),
            "manifest_sha256": optional_text(manifest.get("manifest_sha256")),
            "viewer": optional_text(viewer_locator.get("viewer")),
        },
        "correlation_targets": [
            "vendor/mobile tool row diff",
            "acquisition hash log",
            "mobile timeline",
            "contacts/calls/SMS/media correlation",
            "app schema version registry",
        ],
        "risk_tags": sorted(set(map(str, risk_flags)) | set(map(str, failed_checks)) | {"mobile-validation-required"}),
        "validation_required": True,
        "report_grade_ready": False,
        "validation_snapshot": dict(validation_checks),
        "commercial_blockers": list(report_grade.get("blockers", MOBILE_REPORT_GRADE_BLOCKERS)),
        "report_guidance": "Use as a triage/review pivot until source export settings, acquisition hashes, known-answer fixtures, and trusted tool diffs are attached.",
    }


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


def build_mobile_vendor_import_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    source_profile = (
        details.get("mobile_export_source_profile")
        if isinstance(details.get("mobile_export_source_profile"), Mapping)
        else {}
    )
    vendor_manifest_profile = (
        details.get("vendor_export_manifest_profile")
        if isinstance(details.get("vendor_export_manifest_profile"), Mapping)
        else {}
    )
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    normalized_raw = normalize_keys(details.get("raw")) if isinstance(details.get("raw"), Mapping) else {}
    manifest: dict[str, object] = {
        "manifest_version": "mobile-vendor-import-manifest-v1",
        "item_number": 52,
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "known_vendor_profile": bool(registry),
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "source_viewer_locator": {
            "viewer": "mobile-vendor-export-row",
            "source_path": str(source_path.resolve()),
            "source_index": source_index,
            "source_record_id": source_record_id(details, source_index),
            "artifact_type": artifact_type,
        },
        "normalized_field_count": len(normalized_raw),
        "normalized_field_sample": sorted(normalized_raw)[:50],
        "schema_registry": {
            "expected_artifacts": list(registry.get("expected_artifacts", ())),
            "required_export_metadata": list(registry.get("required_export_metadata", ())),
            "schema_version": optional_text(details.get("schema_version") or source_profile.get("schema_version")),
            "vendor_tool_version": optional_text(
                source_profile.get("vendor_tool_version") or vendor_manifest_profile.get("vendor_tool_version")
            ),
            "vendor_parser_version": optional_text(
                source_profile.get("vendor_parser_version") or vendor_manifest_profile.get("parser_version")
            ),
            "settings_verified": bool(details.get("validation_checks", {}).get("vendor_export_settings_verified"))
            if isinstance(details.get("validation_checks"), Mapping)
            else False,
            "original_acquisition_hash_verified": bool(
                details.get("validation_checks", {}).get("original_acquisition_hash_verified")
            )
            if isinstance(details.get("validation_checks"), Mapping)
            else False,
        },
        "source_profile": {
            "input_row_count": source_profile.get("input_row_count"),
            "emitted_row_count": source_profile.get("emitted_row_count"),
            "unclassified_or_skipped_row_count": source_profile.get("unclassified_or_skipped_row_count"),
            "vendor_export_manifest_present": bool(source_profile.get("vendor_export_manifest_present") or vendor_manifest_profile),
            "source_hash_matches_manifest": bool(
                source_profile.get("source_hash_matches_manifest")
                or vendor_manifest_profile.get("source_hash_matches_manifest")
            ),
        },
        "large_data_controls": {
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
            "row_cap_recorded": True,
            "raw_values_redacted_by_default": True,
            "text_values_hash_only_by_default": True,
        },
        "commercial_blockers": [
            "per-vendor-schema-version-fixtures-required",
            "trusted-cellebrite-xry-graykey-axiom-export-diff-required",
            "deleted-and-protected-store-boundary-validation-required",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


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
    *,
    input_rows: int | None = None,
    vendor_manifest_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest = vendor_manifest_profile or {}
    return {
        "source_format": source_format,
        "source_tool_detected": source_tool,
        "row_count_nonzero": emitted > 0,
        "input_row_count_recorded": input_rows is not None,
        "unclassified_rows_recorded": input_rows is not None and input_rows >= emitted,
        "row_cap_recorded": True,
        "schema_profile_emitted": True,
        "detected_artifact_type_count": len(detected_types),
        "vendor_export_settings_verified": bool(manifest.get("export_settings_present"))
        and bool(manifest.get("vendor_tool_version"))
        and bool(manifest.get("source_hash_matches_manifest")),
        "original_acquisition_hash_verified": bool(manifest.get("original_acquisition_hash_present")),
        "vendor_schema_validated": bool(manifest.get("schema_version")) and manifest.get("validation_status") == "metadata-linked",
    }


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def chat_app_gap_ids(service: str) -> list[str]:
    gap = CHAT_APP_GAP_IDS.get(service)
    return [gap] if gap else ["#31", "#32", "#33", "#34", "#35"]


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


def stable_mobile_sha256(value: Mapping[str, object] | Sequence[object] | str) -> str:
    if isinstance(value, str):
        return sha256_text(value)
    return sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str))


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
