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


EXTENDED_MESSENGER_REVIEW_SERVICES = {"WeChat", "LINE", "Discord", "Instagram"}


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
