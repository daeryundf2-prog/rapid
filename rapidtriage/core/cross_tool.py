from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .docs import write_result
from .validation_qc_controls import build_validation_qc_contract


MAX_ROWS_PER_TOOL = 100_000
MAX_RECORD_FIELD_DIFF_ROWS = 5_000
MAX_REGISTRY_FIELD_DIFF_ROWS = 5_000
MAX_NTFS_FIELD_DIFF_ROWS = 5_000
MAX_ESE_FIELD_DIFF_ROWS = 5_000
MAX_USN_STATE_REPLAY_FIELD_DIFF_ROWS = 5_000
MAX_OS_ACCOUNT_FIELD_DIFF_ROWS = 5_000
MAX_EXECUTION_ARTIFACT_FIELD_DIFF_ROWS = 5_000
MAX_USER_ACTIVITY_FIELD_DIFF_ROWS = 5_000
MAX_SYSTEM_ARTIFACT_FIELD_DIFF_ROWS = 5_000
MAX_BROWSER_FIELD_DIFF_ROWS = 5_000
MAX_MOBILE_FIELD_DIFF_ROWS = 5_000
MAX_MESSAGING_FIELD_DIFF_ROWS = 5_000
MAX_FIELD_MISMATCH_SAMPLES = 50
FUNCTIONAL_VALIDATION_BATCH_ID = "commercial-uplift-036-040"
KEY_FIELDS = (
    "event_record_id",
    "EventRecordID",
    "record_id",
    "RecordNumber",
    "record_number",
    "event_id",
    "EventID",
    "provider_name",
    "Provider",
    "channel",
    "Channel",
    "key_path",
    "KeyPath",
    "registry_path",
    "RegistryPath",
    "value_name",
    "ValueName",
    "cell_offset",
    "CellOffset",
    "source_offset",
    "SourceOffset",
    "source_file",
    "SourceFile",
    "path",
    "Path",
    "source_path",
    "file_path",
    "file_name",
    "table_name",
    "row_id",
    "page_number",
    "TargetFilename",
    "FileName",
    "filename",
    "sha256",
    "SHA256",
    "hash",
    "source_record_id",
    "SourceRecordId",
    "message_id",
    "MessageId",
    "conversation_id",
    "ConversationId",
    "file_id",
    "FileId",
    "package_name",
    "PackageName",
    "apk_sha256",
    "ApkSHA256",
    "internet_message_id",
    "InternetMessageId",
    "cloud_record_id",
    "CloudRecordId",
    "provider_record_id",
    "ProviderRecordId",
    "api_request_id",
    "ApiRequestId",
)
EVTX_FIELD_ALIASES = {
    "event_record_id": ("event_record_id", "EventRecordID", "record_id", "RecordNumber", "record_number"),
    "event_id": ("event_id", "EventID"),
    "provider_name": ("provider_name", "Provider", "ProviderName"),
    "channel": ("channel", "Channel"),
    "computer": ("computer", "Computer"),
    "event_created_at": ("event_created_at", "TimeCreated", "timestamp", "Timestamp", "DateTime"),
    "event_message": ("event_message", "EventMessage", "RenderedMessage", "Message", "message"),
}
EVTX_EVENT_DATA_PREFIXES = (
    "event_data",
    "eventdata",
    "userdata",
    "user_data",
    "binxml_event_data_fields",
    "binxml_user_data_fields",
)
EVTX_EVENT_DATA_KEY_MARKERS = (
    ".event_data.",
    ".eventdata.",
    ".userdata.",
    ".user_data.",
    ".binxml_event_data_fields.",
    ".binxml_user_data_fields.",
)
REGISTRY_FIELD_ALIASES = {
    "key_path": ("key_path", "KeyPath", "RegistryPath", "registry_path", "Path", "path", "Key", "key"),
    "value_name": ("value_name", "ValueName", "name", "Name"),
    "value_type": ("value_type", "ValueType", "type", "Type"),
    "value_data": (
        "value_data",
        "ValueData",
        "Data",
        "data",
        "value",
        "Value",
        "decoded_data_preview",
        "data_preview",
    ),
    "last_written_at": ("last_written_at", "LastWriteTime", "last_write_time", "LastWrite", "timestamp"),
    "cell_offset": ("cell_offset", "CellOffset", "source_offset", "SourceOffset", "offset", "Offset"),
    "candidate_class": ("candidate_class", "CandidateClass", "candidate_kind", "cell_kind", "CellKind"),
    "allocation_status": ("allocation_status", "AllocationStatus", "allocated", "Allocated"),
    "parent_key_path": (
        "parent_key_path",
        "ParentKeyPath",
        "parent_key_path_candidate",
        "ParentPath",
        "parent_path",
    ),
    "transaction_replay_status": (
        "transaction_replay_status",
        "TransactionReplayStatus",
        "log_replay_status",
        "LogReplayStatus",
    ),
}
REGISTRY_PATH_PREFIX_ALIASES = {
    "hkey_current_user": "hkcu",
    "hkey_local_machine": "hklm",
    "hkey_classes_root": "hkcr",
    "hkey_users": "hku",
    "hkey_current_config": "hkcc",
}
OS_ACCOUNT_FIELD_ALIASES = {
    "account_name": ("account_name", "UserName", "Username", "Name", "name", "user_name"),
    "rid": ("rid", "RID", "RelativeId", "relative_id"),
    "sid": ("sid", "SID", "UserSid", "user_sid"),
    "account_type": ("account_type", "AccountType", "type", "Type"),
    "admin_status": ("admin_status", "IsAdmin", "is_admin", "admin", "Admin"),
    "created_at": ("created_at", "Created", "created", "CreatedOn", "creation_time"),
    "last_login_at": ("last_login_at", "LastLogin", "last_login", "LastLogon", "last_logon"),
    "deleted_at": ("deleted_at", "DeletedAt", "deleted_time", "DeletedTime"),
    "uac_flags": ("uac_flags", "UacFlags", "UserAccountControl", "uac", "UAC"),
    "group_name": ("group_name", "GroupName", "AliasName", "alias_name", "group", "Group"),
    "privilege_name": ("privilege_name", "Privilege", "privilege", "PrivilegeName", "RightName"),
    "control_set": ("control_set", "ControlSet", "CurrentControlSet", "controlset"),
    "lsa_secret_name": ("lsa_secret_name", "SecretName", "secret_name", "LSASecret", "lsa_secret"),
    "secret_redaction_status": (
        "secret_redaction_status",
        "SecretRedactionStatus",
        "redaction_status",
        "RedactionStatus",
    ),
}
EXECUTION_ARTIFACT_FIELD_ALIASES = {
    "artifact_family": ("artifact_family", "ArtifactFamily", "source_family", "SourceFamily"),
    "executable_path": (
        "executable_path",
        "ExecutablePath",
        "Path",
        "path",
        "FilePath",
        "file_path",
        "ProgramName",
        "program_name",
    ),
    "timestamp": (
        "timestamp",
        "Timestamp",
        "TimeStamp",
        "LastRun",
        "LastExecution",
        "last_execution_at",
        "LastModified",
    ),
    "user_sid": ("user_sid", "UserSid", "SID", "sid"),
    "sha1": ("sha1", "SHA1", "SourceFileSHA1", "source_file_sha1", "hash", "Hash"),
    "source_key": ("source_key", "SourceKey", "key_path", "KeyPath", "registry_path", "RegistryPath"),
    "source_value": ("source_value", "SourceValue", "ValueName", "value_name"),
    "semantics_warning": ("semantics_warning", "SemanticsWarning", "Warning", "warning"),
    "execution_evidence_status": (
        "execution_evidence_status",
        "ExecutionEvidenceStatus",
        "evidence_status",
        "EvidenceStatus",
    ),
}
USER_ACTIVITY_FIELD_ALIASES = {
    "artifact_family": ("artifact_family", "ArtifactFamily", "source_family", "SourceFamily"),
    "app_id": ("app_id", "AppId", "AppID", "ApplicationID", "application_id"),
    "entry_id": ("entry_id", "EntryId", "EntryID", "DestListEntryNumber", "destlist_entry_number", "EntryNumber", "MRU"),
    "target_path": (
        "target_path",
        "TargetPath",
        "TargetFilename",
        "target_filename",
        "Path",
        "path",
        "file_path",
        "FilePath",
        "LocalPath",
    ),
    "file_name": ("file_name", "FileName", "filename", "Name", "name"),
    "timestamp": (
        "timestamp",
        "Timestamp",
        "LastRun",
        "LastRunTime",
        "LastAccessTime",
        "LastModified",
        "Created",
        "Accessed",
    ),
    "source_path": ("source_path", "SourcePath", "source_file", "SourceFile"),
    "source_offset": ("source_offset", "SourceOffset", "Offset", "offset"),
    "mru_order": ("mru_order", "MRUOrder", "mru", "Slot", "slot"),
    "access_count": ("access_count", "AccessCount", "RunCount", "run_count", "OpenCount", "open_count"),
    "volume_name": ("volume_name", "VolumeName", "volume", "Volume"),
    "bag_path": ("bag_path", "BagPath", "bag_path", "shell_path", "ShellPath", "AbsolutePath"),
    "shell_item_type": ("shell_item_type", "ShellItemType", "ItemType", "item_type"),
    "tracker_guid": ("tracker_guid", "TrackerGuid", "DroidFileIdentifier", "MachineIdentifier"),
}
SYSTEM_ARTIFACT_FIELD_ALIASES = {
    "artifact_family": ("artifact_family", "ArtifactFamily", "Family", "family", "Type", "type"),
    "task_uri": ("task_uri", "TaskURI", "TaskUri", "TaskName", "task_name", "Path", "path"),
    "command": (
        "command",
        "Command",
        "ActionCommand",
        "Executable",
        "ImagePath",
        "ProcessCommandLine",
        "process_command_line",
    ),
    "principal": ("principal", "Principal", "UserId", "UserID", "User", "Account", "user"),
    "trigger": ("trigger", "Trigger", "TriggerType", "StartBoundary", "trigger_type"),
    "threat_name": ("threat_name", "ThreatName", "Threat", "Detection", "Signature", "Name"),
    "remediation": ("remediation", "Remediation", "RemediationAction", "Action", "Result"),
    "source_ip": ("source_ip", "SourceIP", "SourceAddress", "src_ip", "src"),
    "destination_ip": ("destination_ip", "DestinationIP", "DestinationAddress", "dst_ip", "dst"),
    "destination_port": ("destination_port", "DestinationPort", "DestPort", "dst_port", "port"),
    "protocol": ("protocol", "Protocol", "proto"),
    "application_name": ("application_name", "ApplicationName", "AppName", "FaultingApplication", "ProcessName"),
    "exception_code": ("exception_code", "ExceptionCode", "FaultCode", "ErrorCode"),
    "wmi_consumer": ("wmi_consumer", "ConsumerName", "Consumer", "EventConsumer", "Name"),
    "wmi_filter": ("wmi_filter", "FilterName", "Filter", "EventFilter", "Query"),
    "timestamp": ("timestamp", "Timestamp", "TimeCreated", "LastWriteTime", "Modified", "DateTime"),
    "source_path": ("source_path", "SourcePath", "SourceFile", "source_file", "FilePath", "Path"),
}
BROWSER_STORAGE_FIELD_ALIASES = {
    "browser": ("browser", "Browser"),
    "profile": ("profile", "Profile", "profile_name", "ProfileName"),
    "storage_type": ("storage_type", "Type", "type", "store_type", "StoreType"),
    "storage_name": ("storage_name", "Name", "name", "store_name", "StoreName", "path", "Path"),
    "relative_path": ("relative_path", "RelativePath", "source_path", "SourcePath", "path", "Path"),
    "artifact_hint": ("artifact_hint", "ArtifactHint", "hint", "Hint", "artifact", "Artifact"),
    "file_count": ("file_count", "FileCount", "files", "Files", "count", "Count"),
    "total_bytes": ("total_bytes", "TotalBytes", "bytes", "Bytes", "size", "Size"),
    "is_file": ("is_file", "IsFile", "file", "File"),
    "sensitive": ("sensitive", "Sensitive", "contains_secrets", "ContainsSecrets", "scope_sensitive"),
    "sample_hashes": ("sample_hashes", "SampleHashes", "sample_files", "SampleFiles", "hashes", "Hashes"),
    "inventory_truncated": ("inventory_truncated", "InventoryTruncated", "truncated", "Truncated"),
}
BROWSER_TIMELINE_FIELD_ALIASES = {
    "browser": ("browser", "Browser"),
    "profile": ("profile", "Profile", "profile_name", "ProfileName"),
    "timeline_type": ("timeline_type", "Type", "type", "row_type", "RowType"),
    "timestamp": ("timestamp", "Timestamp", "visit_time", "VisitTime", "start_time", "StartTime", "started_at"),
    "url": ("url", "URL", "source_url", "SourceURL", "target_url", "TargetURL"),
    "title": ("title", "Title", "page_title", "PageTitle"),
    "domain": ("domain", "Domain", "host", "Host", "hostname", "Hostname"),
    "transition": ("transition", "Transition", "transition_type", "TransitionType"),
    "visit_count": ("visit_count", "VisitCount", "visitcount"),
    "typed_count": ("typed_count", "TypedCount", "typedcount"),
    "target_path": ("target_path", "TargetPath", "download_path", "DownloadPath", "filename", "Filename"),
    "total_bytes": ("total_bytes", "TotalBytes", "bytes", "Bytes", "size", "Size"),
    "state": ("state", "State", "download_state", "DownloadState"),
    "ended_at": ("ended_at", "EndTime", "end_time", "completed_at", "CompletedAt"),
    "ai_service": ("ai_service", "AIService", "service", "Service"),
    "source_table": ("source_table", "SourceTable", "table", "Table"),
    "source_index": ("source_index", "SourceIndex", "row_index", "RowIndex", "index", "Index"),
}
AI_TRANSCRIPT_FIELD_ALIASES = {
    "ai_service": ("ai_service", "AIService", "service", "Service", "provider", "Provider"),
    "conversation_id": ("conversation_id", "ConversationId", "chat_id", "ChatId", "thread_id", "ThreadId"),
    "conversation_title": ("conversation_title", "ConversationTitle", "title", "Title", "chat_title", "ChatTitle"),
    "pair_id": ("pair_id", "PairId", "message_id", "MessageId", "id", "Id"),
    "question": ("question", "Question", "prompt", "Prompt", "user_text", "UserText", "user_message", "UserMessage"),
    "answer": (
        "answer",
        "Answer",
        "response",
        "Response",
        "assistant_text",
        "AssistantText",
        "assistant_message",
        "AssistantMessage",
    ),
    "timestamp": ("timestamp", "Timestamp", "created_at", "CreatedAt", "Created", "created", "message_time", "MessageTime"),
    "source_path": ("source_path", "SourcePath", "source", "Source", "export_path", "ExportPath"),
    "source_sha256s": ("source_sha256s", "SourceSha256s", "source_sha256", "SourceSha256", "source_hashes", "SourceHashes"),
    "question_source_path": ("question_source_path", "QuestionSourcePath", "prompt_source_path", "PromptSourcePath"),
    "answer_source_path": ("answer_source_path", "AnswerSourcePath", "response_source_path", "ResponseSourcePath"),
    "question_source_offset": ("question_source_offset", "QuestionSourceOffset", "prompt_offset", "PromptOffset"),
    "answer_source_offset": ("answer_source_offset", "AnswerSourceOffset", "response_offset", "ResponseOffset"),
    "storage_area": ("storage_area", "StorageArea", "source_storage_area", "SourceStorageArea"),
    "pairing_confidence": ("pairing_confidence", "PairingConfidence", "confidence_label", "ConfidenceLabel"),
    "confidence": ("confidence", "Confidence", "score", "Score"),
    "transcript_validation_status": (
        "transcript_validation_status",
        "TranscriptValidationStatus",
        "validation_status",
        "ValidationStatus",
    ),
    "completeness_score": (
        "completeness_score",
        "CompletenessScore",
        "transcript_completeness_score",
        "TranscriptCompletenessScore",
    ),
}
MOBILE_EXPORT_FIELD_ALIASES = {
    "artifact_family": ("artifact_family", "ArtifactFamily", "artifact_type", "ArtifactType", "type", "Type"),
    "source_tool": ("source_tool", "SourceTool", "tool", "Tool", "vendor_tool", "VendorTool"),
    "source_record_id": ("source_record_id", "SourceRecordId", "RecordId", "record_id", "id", "Id"),
    "service": ("service", "Service", "app", "App", "platform", "Platform"),
    "conversation_id": ("conversation_id", "ConversationId", "chat_id", "ChatId", "thread_id", "ThreadId"),
    "message_id": ("message_id", "MessageId", "msg_id", "MsgId", "id", "Id"),
    "timestamp": ("timestamp", "Timestamp", "datetime", "DateTime", "created_at", "CreatedAt", "sent_at", "SentAt"),
    "sender": ("sender", "Sender", "from", "From", "from_id", "FromId", "sender_id", "SenderId"),
    "recipient": ("recipient", "Recipient", "to", "To", "to_id", "ToId", "recipient_id", "RecipientId"),
    "message_text_hash": ("message_text_hash", "MessageTextHash", "text_hash", "TextHash", "body_hash", "BodyHash"),
    "message_text": ("message_text", "MessageText", "text", "Text", "body", "Body"),
    "media_hash": ("media_hash", "MediaHash", "attachment_hash", "AttachmentHash", "file_hash", "FileHash"),
    "media_path": ("media_path", "MediaPath", "attachment_path", "AttachmentPath", "file_path", "FilePath"),
    "contact_name": ("contact_name", "ContactName", "display_name", "DisplayName", "name", "Name"),
    "phone": ("phone", "Phone", "phone_number", "PhoneNumber", "number", "Number"),
    "email": ("email", "Email", "email_address", "EmailAddress"),
    "call_type": ("call_type", "CallType", "direction", "Direction"),
    "duration": ("duration", "Duration", "duration_seconds", "DurationSeconds"),
    "domain": ("domain", "Domain", "ios_domain", "IOSDomain"),
    "relative_path": ("relative_path", "RelativePath", "path", "Path", "logical_path", "LogicalPath"),
    "file_id": ("file_id", "FileId", "fileID", "ManifestFileId", "manifest_file_id", "backup_file_id"),
    "protection_class": ("protection_class", "ProtectionClass", "DataProtectionClass"),
    "redaction_status": ("redaction_status", "RedactionStatus", "secret_redaction_status", "SecretRedactionStatus"),
    "schema_version": ("schema_version", "SchemaVersion", "schema", "Schema"),
}
MOBILE_APP_FIELD_ALIASES = {
    "package_name": ("package_name", "PackageName", "bundle_id", "BundleId", "application_id", "ApplicationId"),
    "app_label": ("app_label", "AppLabel", "application_label", "ApplicationLabel", "name", "Name"),
    "version_name": ("version_name", "VersionName", "CFBundleShortVersionString", "version", "Version"),
    "version_code": ("version_code", "VersionCode", "build", "Build", "CFBundleVersion"),
    "permission": ("permission", "Permission", "permissions", "Permissions"),
    "dangerous_permission_count": (
        "dangerous_permission_count",
        "DangerousPermissionCount",
        "dangerous_permissions",
        "DangerousPermissions",
    ),
    "cert_sha256": ("cert_sha256", "CertSHA256", "certificate_sha256", "CertificateSHA256", "signer_sha256"),
    "apk_sha256": ("apk_sha256", "ApkSHA256", "file_sha256", "FileSHA256", "sha256", "SHA256"),
    "dex_count": ("dex_count", "DexCount", "dex_files", "DexFiles"),
    "native_library_count": ("native_library_count", "NativeLibraryCount", "so_count", "SoCount"),
    "app_data_path": ("app_data_path", "AppDataPath", "data_path", "DataPath", "path", "Path"),
    "database": ("database", "Database", "db_name", "DbName", "source_path", "SourcePath"),
    "table_name": ("table_name", "TableName", "table", "Table"),
    "indicator": ("indicator", "Indicator", "url", "URL", "ip", "IP", "domain", "Domain"),
    "risk_model": ("risk_model", "RiskModel", "risk", "Risk", "permission_risk_model"),
}
CHAT_APP_FIELD_ALIASES = {
    "service": ("service", "Service", "app", "App", "platform", "Platform"),
    "profile": ("profile", "Profile", "account", "Account", "account_id", "AccountId"),
    "conversation_id": ("conversation_id", "ConversationId", "chat_id", "ChatId", "thread_id", "ThreadId"),
    "conversation_title": ("conversation_title", "ConversationTitle", "chat_name", "ChatName", "thread_name", "ThreadName"),
    "message_id": ("message_id", "MessageId", "msg_id", "MsgId", "id", "Id"),
    "timestamp": ("timestamp", "Timestamp", "datetime", "DateTime", "created_at", "CreatedAt", "sent_at", "SentAt"),
    "sender": ("sender", "Sender", "from", "From", "from_id", "FromId", "author", "Author"),
    "recipient": ("recipient", "Recipient", "to", "To", "to_id", "ToId", "recipient_id", "RecipientId"),
    "message_text_hash": ("message_text_hash", "MessageTextHash", "text_hash", "TextHash", "body_hash", "BodyHash"),
    "message_text": ("message_text", "MessageText", "text", "Text", "body", "Body", "message", "Message"),
    "media_hash": ("media_hash", "MediaHash", "attachment_hash", "AttachmentHash", "file_hash", "FileHash"),
    "media_path": ("media_path", "MediaPath", "attachment_path", "AttachmentPath", "file_path", "FilePath"),
    "reaction_summary": ("reaction_summary", "ReactionSummary", "reactions", "Reactions"),
    "read_state": ("read_state", "ReadState", "read_status", "ReadStatus"),
    "deleted_state": ("deleted_state", "DeletedState", "deleted", "Deleted"),
    "schema_version": ("schema_version", "SchemaVersion", "schema", "Schema"),
    "source_record_id": ("source_record_id", "SourceRecordId", "RecordId", "record_id"),
}
CHAT_APP_SERVICES = {
    "discord",
    "facebook",
    "imessage",
    "instagram",
    "kakaotalk",
    "line",
    "matrix",
    "messenger",
    "session",
    "signal",
    "skype",
    "slack",
    "telegram",
    "threema",
    "viber",
    "wechat",
    "whatsapp",
    "wickr",
    "wire",
}
EMAIL_FIELD_ALIASES = {
    "message_id": ("message_id", "MessageId", "InternetMessageId", "internet_message_id", "Message-ID"),
    "subject": ("subject", "Subject"),
    "sent_at": ("sent_at", "SentAt", "Date", "date", "timestamp", "Timestamp"),
    "sender": ("sender", "Sender", "From", "from"),
    "recipient": ("recipient", "Recipient", "To", "to"),
    "cc": ("cc", "CC", "Cc"),
    "mailbox": ("mailbox", "Mailbox", "mailbox_name", "MailboxName"),
    "folder": ("folder", "Folder", "folder_path", "FolderPath"),
    "attachment_count": ("attachment_count", "AttachmentCount", "attachments", "Attachments"),
    "attachment_hash": ("attachment_hash", "AttachmentHash", "file_hash", "FileHash"),
    "body_hash": ("body_hash", "BodyHash", "message_text_hash", "MessageTextHash"),
    "source_path": ("source_path", "SourcePath", "SourceFile", "path", "Path"),
    "source_record_id": ("source_record_id", "SourceRecordId", "RecordId", "record_id"),
}
CLOUD_EXPORT_FIELD_ALIASES = {
    "provider": ("provider", "Provider", "cloud_family", "CloudFamily", "service", "Service"),
    "product": ("product", "Product", "workload", "Workload", "app", "App"),
    "record_id": ("record_id", "RecordId", "cloud_record_id", "CloudRecordId", "provider_record_id", "ProviderRecordId"),
    "item_id": ("item_id", "ItemId", "file_id", "FileId", "message_id", "MessageId", "event_id", "EventId"),
    "timestamp": ("timestamp", "Timestamp", "created_at", "CreatedAt", "event_time", "EventTime"),
    "actor": ("actor", "Actor", "user", "User", "sender", "Sender", "owner", "Owner"),
    "target": ("target", "Target", "recipient", "Recipient", "path", "Path", "name", "Name", "url", "URL"),
    "action": ("action", "Action", "operation", "Operation", "activity", "Activity"),
    "ip": ("ip", "IP", "client_ip", "ClientIP"),
    "hash": ("hash", "Hash", "sha256", "SHA256", "file_hash", "FileHash"),
    "size": ("size", "Size", "bytes", "Bytes"),
    "source_record_id": ("source_record_id", "SourceRecordId", "SourceRow", "source_row"),
}
CLOUD_API_FIELD_ALIASES = {
    "request_id": ("request_id", "RequestId", "api_request_id", "ApiRequestId"),
    "provider": ("provider", "Provider", "service", "Service"),
    "endpoint": ("endpoint", "Endpoint", "url", "URL", "request_url", "RequestUrl"),
    "method": ("method", "Method", "http_method", "HttpMethod"),
    "status_code": ("status_code", "StatusCode", "status", "Status"),
    "response_hash": ("response_hash", "ResponseHash", "body_hash", "BodyHash", "sha256", "SHA256"),
    "item_count": ("item_count", "ItemCount", "record_count", "RecordCount"),
    "page_token": ("page_token", "PageToken", "cursor", "Cursor", "next_cursor", "NextCursor"),
}
MFT_FIELD_ALIASES = {
    "record_number": ("record_number", "RecordNumber", "EntryNumber", "entry_number", "MFTEntryNumber"),
    "sequence_number": ("sequence_number", "SequenceNumber", "Sequence", "seq"),
    "parent_reference": (
        "parent_reference",
        "ParentReference",
        "ParentEntryNumber",
        "parent_entry_number",
        "ParentFRN",
        "parent_frn",
        "parent_file_reference",
    ),
    "file_path": ("file_path", "FullPath", "full_path", "Path", "path", "FileName", "filename"),
    "deleted": ("deleted_hint", "Deleted", "deleted", "IsDeleted", "is_deleted", "in_use", "InUse", "allocated"),
    "timestamp": (
        "timestamp",
        "Created0x10",
        "Created",
        "CreatedTimestamp",
        "SI Created",
        "FN Created",
        "modified_at",
    ),
    "attribute_types": ("attribute_types", "Attributes", "attributes", "AttributeTypes", "AttributeTypeNames"),
    "record_offset": ("record_offset", "Offset", "offset", "ByteOffset", "source_offset"),
    "resident_data_sha256": ("resident_data_sha256", "ResidentDataSHA256", "resident_sha256", "SHA256"),
    "runlist_decode_status": ("runlist_decode_status", "DataRunStatus", "RunlistStatus", "data_run_status"),
}
USN_FIELD_ALIASES = {
    "usn": ("usn", "USN", "Usn", "usn_number"),
    "file_reference_number": ("file_reference_number", "FRN", "frn", "FileReferenceNumber", "file_reference"),
    "parent_reference": (
        "parent_file_reference_number",
        "ParentFRN",
        "parent_frn",
        "ParentFileReferenceNumber",
        "parent_reference",
    ),
    "file_name": ("file_name", "FileName", "filename", "Name", "name", "Path", "path", "file_path"),
    "reason": ("reason", "Reason", "reason_flags", "ReasonFlags", "usn_reason"),
    "timestamp": ("timestamp", "Timestamp", "TimeStamp", "event_time", "TimeCreated"),
    "major_version": ("major_version", "MajorVersion", "Major", "major"),
    "source_info": ("source_info", "SourceInfo", "source_info_flags", "SourceInfoFlags"),
    "file_attributes": ("file_attribute_names", "FileAttributes", "file_attributes", "Attributes"),
    "record_cursor": ("record_cursor", "RecordOffset", "record_offset", "Offset", "offset", "ByteOffset"),
    "v4_extent_count": ("v4_extent_count", "ExtentCount", "extent_count", "ExtentCountV4"),
}
USN_STATE_REPLAY_FIELD_ALIASES = {
    "usn": ("usn", "USN", "Usn", "usn_number"),
    "file_reference_number": ("file_reference_number", "FRN", "frn", "FileReferenceNumber", "file_reference"),
    "record_cursor": ("record_cursor", "RecordCursor", "RecordOffset", "record_offset", "Offset", "offset", "ByteOffset"),
    "transition": ("transition", "Transition", "state_transition", "StateTransition"),
    "timestamp": ("timestamp", "Timestamp", "TimeStamp", "event_time", "TimeCreated"),
    "previous_path": ("previous_path", "PreviousPath", "old_path", "OldPath", "path_before", "PathBefore"),
    "new_path": ("new_path", "NewPath", "path_after", "PathAfter", "path_candidate", "PathCandidate"),
    "file_name": ("file_name", "FileName", "filename", "Name", "name"),
    "state_effect": ("state_effect", "StateEffect", "effect", "Effect"),
}
USN_STATE_REPLAY_TEMPLATE_COLUMNS = [
    "USN",
    "FRN",
    "RecordCursor",
    "Transition",
    "Timestamp",
    "PreviousPath",
    "NewPath",
    "FileName",
    "StateEffect",
    "ExpectedSource",
    "ReviewerNote",
]
USN_STATE_REPLAY_TEMPLATE_ROWS = [
    {
        "USN": "9001",
        "FRN": "41",
        "RecordCursor": "128",
        "Transition": "create",
        "Timestamp": "2026-01-02T03:04:00Z",
        "PreviousPath": "",
        "NewPath": r"C:\Users\alice\Desktop\case.txt",
        "FileName": "case.txt",
        "StateEffect": "set-current-path",
        "ExpectedSource": "known-answer-lab-note",
        "ReviewerNote": "Replace this example with a confirmed create transition from the validation corpus.",
    },
    {
        "USN": "9002",
        "FRN": "41",
        "RecordCursor": "208",
        "Transition": "rename-old-name",
        "Timestamp": "2026-01-02T03:04:05Z",
        "PreviousPath": r"C:\Users\alice\Desktop\case.txt",
        "NewPath": "",
        "FileName": "case.txt",
        "StateEffect": "record-previous-name",
        "ExpectedSource": "known-answer-lab-note",
        "ReviewerNote": "Pair with the following rename-new-name row by FRN/order.",
    },
    {
        "USN": "9003",
        "FRN": "41",
        "RecordCursor": "308",
        "Transition": "rename-new-name",
        "Timestamp": "2026-01-02T03:04:06Z",
        "PreviousPath": r"C:\Users\alice\Desktop\case.txt",
        "NewPath": r"C:\Users\alice\Desktop\renamed.txt",
        "FileName": "renamed.txt",
        "StateEffect": "replace-current-path",
        "ExpectedSource": "known-answer-lab-note",
        "ReviewerNote": "Confirm old/new path with the full FRN path cache or trusted replay export.",
    },
    {
        "USN": "9004",
        "FRN": "41",
        "RecordCursor": "408",
        "Transition": "delete",
        "Timestamp": "2026-01-02T03:05:00Z",
        "PreviousPath": r"C:\Users\alice\Desktop\renamed.txt",
        "NewPath": "",
        "FileName": "renamed.txt",
        "StateEffect": "remove-current-path",
        "ExpectedSource": "known-answer-lab-note",
        "ReviewerNote": "Confirm delete state using complete journal ordering, not a bounded preview alone.",
    },
]
ESE_FIELD_ALIASES = {
    "ese_family": ("ese_family", "ESEFamily", "source_family", "SourceFamily", "database_family"),
    "table_name": (
        "table_name",
        "TableName",
        "Table",
        "srum_table_family",
        "table_family",
        "SystemIndexTable",
    ),
    "row_id": ("row_id", "RowId", "RecordId", "Id", "WorkId", "DocumentId", "DocId"),
    "page_number": ("page_number", "PageNumber", "page", "Page", "source_page_number"),
    "source_offset": ("source_offset", "SourceOffset", "offset", "Offset", "page_offset", "PageOffset"),
    "item_path": (
        "item_path",
        "ItemPath",
        "ItemUrl",
        "System.ItemPathDisplay",
        "System.ItemUrl",
        "path",
        "Path",
        "url",
        "Url",
        "app_id",
        "AppId",
        "executable_path",
    ),
    "timestamp": ("timestamp", "Timestamp", "TimeStamp", "LastModified", "System.DateModified", "event_time"),
    "deleted_state": ("deleted_state", "Deleted", "IsDeleted", "is_deleted", "tombstone", "Tombstone"),
    "user_sid": ("user_sid", "UserSid", "SID", "Sid"),
    "bytes_sent": ("bytes_sent", "BytesSent", "bytes sent", "NetworkBytesSent"),
    "bytes_received": ("bytes_received", "BytesReceived", "bytes received", "NetworkBytesReceived"),
    "content_hash": ("content_hash", "ContentSHA256", "sha256", "SHA256", "hash"),
    "decode_status": ("decode_status", "DecodeStatus", "row_decode_status", "RowDecodeStatus"),
}


class CrossToolValidationError(ValueError):
    """Raised when cross-tool validation inputs are invalid."""


def build_usn_state_replay_known_answer_template(*, include_examples: bool = True) -> dict[str, object]:
    rows = [dict(row) for row in USN_STATE_REPLAY_TEMPLATE_ROWS] if include_examples else []
    core = {
        "profile_version": "usn-state-replay-known-answer-template-v1",
        "purpose": "known-answer CSV template for validating RapidTriage bounded USN state replay transitions",
        "trusted_tool_name": "known-answer-state-replay",
        "backlog_items": [13, 14],
        "csv_columns": list(USN_STATE_REPLAY_TEMPLATE_COLUMNS),
        "row_count": len(rows),
        "rows": rows,
        "cross_tool_command_template": (
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-filesystem.json "
            "--reference-output known-answer-state-replay=usn-state-replay-known-answer.csv "
            "--backlog-item 13 --min-overlap 1.0 --output usn-state-replay-cross-tool.json --json"
        ),
        "required_evidence": [
            "source evidence hash for the NTFS volume or image",
            "RapidTriage filesystem artifact output containing bounded_state_replay_preview.transitions",
            "known-answer replay CSV populated from an independent lab note or trusted replay export",
            "tool versions and command lines for all generated outputs",
            "independent reviewer signoff before report-grade use",
        ],
        "limitations": [
            "example rows are placeholders and must not be used as validation evidence",
            "state replay rows validate transition output only; full commercial-grade USN support still requires full FRN path cache, complete journal ordering, and large-journal pagination proof",
        ],
    }
    return {
        **core,
        "template_hash": hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def write_usn_state_replay_known_answer_template(
    output: Path,
    *,
    include_examples: bool = True,
) -> dict[str, object]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = build_usn_state_replay_known_answer_template(include_examples=include_examples)
    rows = payload.get("rows") if isinstance(payload.get("rows"), list) else []
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=USN_STATE_REPLAY_TEMPLATE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            if isinstance(row, Mapping):
                writer.writerow(row)
    manifest = output.with_suffix(output.suffix + ".manifest.json")
    manifest_payload = {
        **payload,
        "csv_path": str(output),
        "csv_sha256": file_sha256(output),
    }
    manifest.write_text(json.dumps(manifest_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        **manifest_payload,
        "manifest_path": str(manifest),
        "manifest_sha256": file_sha256(manifest),
    }


def build_cross_tool_validation_report(
    *,
    rapid_output: Path,
    reference_outputs: Mapping[str, Path],
    output: Path | None = None,
    min_overlap: float = 0.8,
    backlog_items: Iterable[int] | None = None,
    tool_versions: Mapping[str, str] | None = None,
    tool_commands: Mapping[str, str] | None = None,
    source_evidence: Iterable[Path] | None = None,
    independent_reports: Iterable[Path] | None = None,
    corpus_scope: str = "",
) -> dict[str, object]:
    if not reference_outputs:
        raise CrossToolValidationError("at least one --reference-output NAME=PATH is required")
    if not 0 <= min_overlap <= 1:
        raise CrossToolValidationError("--min-overlap must be between 0 and 1")

    rapid_dataset = load_tool_dataset("rapidtriage", rapid_output)
    reference_datasets = {
        name: load_tool_dataset(name, path)
        for name, path in sorted(reference_outputs.items())
    }
    comparisons = [
        compare_datasets(rapid_dataset, dataset, min_overlap=min_overlap)
        for dataset in reference_datasets.values()
    ]
    mapped_items = list(dict.fromkeys(int(item) for item in (backlog_items or [])))
    source_evidence_integrity = [file_integrity(path) for path in (source_evidence or [])]
    independent_review_integrity = [file_integrity(path) for path in (independent_reports or [])]
    tool_metadata = build_tool_metadata(
        rapid_dataset=rapid_dataset,
        reference_datasets=list(reference_datasets.values()),
        tool_versions=tool_versions or {},
        tool_commands=tool_commands or {},
    )
    status = "pass"
    if any(item["status"] == "failed" for item in comparisons):
        status = "failed"
    elif any(item["status"] == "warning" for item in comparisons):
        status = "warning"
    assessment = cross_tool_validation_assessment(
        status=status,
        comparisons=comparisons,
        backlog_items=mapped_items,
        output=output,
        min_overlap=min_overlap,
        source_evidence_integrity=source_evidence_integrity,
        independent_review_integrity=independent_review_integrity,
        corpus_scope=corpus_scope,
        tool_metadata=tool_metadata,
    )
    readiness_checks = assessment.get("commercial_grade_readiness_checks", {})
    validation_qc_contract = build_validation_qc_contract(
        comparisons=comparisons,
        status=status,
        backlog_items=mapped_items,
        output_written=output is not None,
        source_evidence_count=len(source_evidence_integrity),
        independent_review_count=len(independent_review_integrity),
        commercial_grade_blockers=assessment.get("commercial_grade_blockers", []),
        tool_versions_attached=bool(
            readiness_checks.get("external_tool_versions_attached")
            if isinstance(readiness_checks, Mapping)
            else False
        ),
        tool_commands_attached=bool(
            readiness_checks.get("external_tool_commands_attached")
            if isinstance(readiness_checks, Mapping)
            else False
        ),
        corpus_scope_attached=bool(
            readiness_checks.get("corpus_scope_attached")
            if isinstance(readiness_checks, Mapping)
            else False
        ),
    )
    payload = {
        "command": "cross-tool-validate",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "status": status,
        "min_overlap": min_overlap,
        "rapid_output": rapid_dataset,
        "reference_outputs": list(reference_datasets.values()),
        "backlog_items": mapped_items,
        "source_evidence_integrity": source_evidence_integrity,
        "independent_review_integrity": independent_review_integrity,
        "corpus_scope": corpus_scope.strip(),
        "tool_metadata": tool_metadata,
        "comparisons": comparisons,
        "cross_tool_validation_assessment": assessment,
        "validation_qc_contract": validation_qc_contract,
        "validation_qc_contract_hash": validation_qc_contract["contract_hash"],
        "operator_guidance": build_operator_guidance(comparisons),
    }
    if mapped_items:
        payload["datasets"] = build_validation_datasets(
            status=status,
            backlog_items=mapped_items,
            comparisons=comparisons,
            output=output,
            rapid_output=rapid_output,
            reference_outputs=reference_outputs,
            source_evidence=source_evidence or [],
            independent_reports=independent_reports or [],
            corpus_scope=corpus_scope,
        )
    if output is not None:
        write_result(payload, output.expanduser().resolve())
        payload["output"] = str(output.expanduser().resolve())
    return payload


def load_tool_dataset(name: str, path: Path) -> dict[str, object]:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise CrossToolValidationError(f"{name} output not found: {path}")
    sampled_rows = list(iter_rows(path, max_rows=MAX_ROWS_PER_TOOL + 1))
    truncated = len(sampled_rows) > MAX_ROWS_PER_TOOL
    rows = sampled_rows[:MAX_ROWS_PER_TOOL]
    keys = sorted({key for row in rows for key in candidate_keys(row)})
    key_quality = key_quality_profile(rows)
    return {
        "name": name,
        "path": str(path),
        "format": infer_format(path),
        "file_integrity": file_integrity(path),
        "row_count": len(rows),
        "truncated": truncated,
        "row_cap": MAX_ROWS_PER_TOOL,
        "key_count": len(keys),
        "keys": keys[:5000],
        "key_quality": key_quality,
        "sample_rows": rows[:5],
        "record_field_index": record_field_index(rows),
        "registry_field_index": registry_field_index(rows),
        "mft_field_index": mft_field_index(rows),
        "usn_field_index": usn_field_index(rows),
        "usn_state_replay_field_index": usn_state_replay_field_index(rows),
        "ese_field_index": ese_field_index(rows),
        "os_account_field_index": os_account_field_index(rows),
        "execution_artifact_field_index": execution_artifact_field_index(rows),
        "user_activity_field_index": user_activity_field_index(rows),
        "system_artifact_field_index": system_artifact_field_index(rows),
        "browser_storage_field_index": browser_storage_field_index(rows),
        "browser_timeline_field_index": browser_timeline_field_index(rows),
        "ai_transcript_field_index": ai_transcript_field_index(rows),
        "mobile_export_field_index": mobile_export_field_index(rows),
        "mobile_app_field_index": mobile_app_field_index(rows),
        "chat_app_field_index": chat_app_field_index(rows),
        "email_field_index": email_field_index(rows),
        "cloud_export_field_index": cloud_export_field_index(rows),
        "cloud_api_field_index": cloud_api_field_index(rows),
    }


def key_quality_profile(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    key_counts: dict[str, int] = {}
    keyed_row_count = 0
    for row in rows:
        identity_key = primary_identity_key(row)
        if identity_key:
            keyed_row_count += 1
            key_counts[identity_key] = key_counts.get(identity_key, 0) + 1
    duplicate_items = sorted(
        (
            {"key": key, "row_count": count}
            for key, count in key_counts.items()
            if count > 1
        ),
        key=lambda item: (-int(item["row_count"]), str(item["key"])),
    )
    return {
        "profile_version": "cross-tool-key-quality-v1",
        "row_count": len(rows),
        "keyed_row_count": keyed_row_count,
        "unkeyed_row_count": max(len(rows) - keyed_row_count, 0),
        "unique_key_count": len(key_counts),
        "duplicate_key_count": len(duplicate_items),
        "duplicate_key_samples": duplicate_items[:50],
    }


def primary_identity_key(row: Mapping[str, object]) -> str:
    keys = candidate_keys(row)
    return keys[0] if keys else ""


def iter_rows(path: Path, *, max_rows: int) -> Iterable[dict[str, object]]:
    file_format = infer_format(path)
    if file_format == "json":
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        yield from rows_from_json(raw, max_rows=max_rows)
        return
    if file_format == "jsonl":
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                if index >= max_rows:
                    break
                line = line.strip()
                if not line:
                    continue
                item = json.loads(line)
                if isinstance(item, Mapping):
                    yield flatten_mapping(item)
        return
    if file_format == "csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if index >= max_rows:
                    break
                yield {str(key): value for key, value in row.items() if key is not None}
        return
    raise CrossToolValidationError(f"unsupported output format for {path}: use JSON, JSONL, or CSV")


def rows_from_json(raw: object, *, max_rows: int) -> Iterable[dict[str, object]]:
    candidates: list[object] = []
    if isinstance(raw, list):
        candidates = raw
    elif isinstance(raw, Mapping):
        for key in ("artifacts", "events", "results", "records", "rows", "indicators", "candidates"):
            value = raw.get(key)
            if isinstance(value, list):
                candidates = value
                break
        if not candidates:
            candidates = [raw]
    emitted = 0
    for item in candidates:
        if isinstance(item, Mapping):
            for row in rows_from_mapping(item):
                if emitted >= max_rows:
                    return
                yield row
                emitted += 1


def rows_from_mapping(item: Mapping[str, object]) -> Iterable[dict[str, object]]:
    flattened = flatten_mapping(item)
    yield flattened
    yield from nested_usn_state_replay_rows(item, flattened)
    yield from nested_browser_rows(item, flattened)
    yield from nested_ai_transcript_rows(item, flattened)
    yield from nested_mobile_export_rows(item, flattened)
    yield from nested_mobile_app_rows(item, flattened)
    yield from nested_chat_app_rows(item, flattened)
    yield from nested_email_rows(item, flattened)
    yield from nested_cloud_export_rows(item, flattened)
    yield from nested_cloud_api_rows(item, flattened)


def nested_browser_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    browser = first_value(flattened_parent, ("browser", "details.browser", "Browser")) or ""
    profile = first_value(flattened_parent, ("profile", "details.profile", "Profile")) or ""
    for storage_row in first_nested_list(item, (("details", "storage_inventory"), ("storage_inventory",))):
        if not isinstance(storage_row, Mapping):
            continue
        row = flatten_mapping(storage_row)
        row.setdefault("artifact_type", "browser-storage-inventory")
        row.setdefault("browser", browser)
        row.setdefault("profile", profile)
        yield row
    for timeline_row in first_nested_list(item, (("details", "unified_timeline"), ("unified_timeline",))):
        if not isinstance(timeline_row, Mapping):
            continue
        row = flatten_mapping(timeline_row)
        row.setdefault("artifact_type", "browser-unified-timeline")
        row.setdefault("browser", browser)
        row.setdefault("profile", profile)
        yield row


def nested_ai_transcript_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    parent_values = {
        "ai_service": first_value(flattened_parent, ("ai_service", "details.ai_service", "service", "details.service")),
        "conversation_id": first_value(
            flattened_parent,
            ("conversation_id", "details.conversation_id", "id", "details.id", "chat_id", "details.chat_id"),
        ),
        "conversation_title": first_value(
            flattened_parent,
            ("conversation_title", "details.conversation_title", "title", "details.title"),
        ),
        "timestamp": first_value(flattened_parent, ("timestamp", "details.timestamp", "created_at", "details.created_at")),
        "source_path": first_value(flattened_parent, ("source_path", "details.source_path", "path", "details.path")),
    }
    pair_paths = (
        ("details", "transcript_pairs"),
        ("transcript_pairs",),
        ("details", "transcript", "pairs"),
        ("transcript", "pairs"),
    )
    for pair in first_nested_list(item, pair_paths):
        if not isinstance(pair, Mapping):
            continue
        row = flatten_mapping(pair)
        row.setdefault("artifact_type", "ai-transcript-pair")
        for key, value in parent_values.items():
            if value not in (None, ""):
                row.setdefault(key, value)
        yield row

    conversation_paths = (
        ("details", "conversation_rows"),
        ("conversation_rows",),
        ("details", "conversation_candidates"),
        ("conversation_candidates",),
    )
    rows = [row for row in first_nested_list(item, conversation_paths) if isinstance(row, Mapping)]
    for pair in pair_ai_conversation_rows(rows):
        row = flatten_mapping(pair)
        row.setdefault("artifact_type", "ai-transcript-pair")
        for key, value in parent_values.items():
            if value not in (None, ""):
                row.setdefault(key, value)
        yield row


def pair_ai_conversation_rows(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    pairs: list[dict[str, object]] = []
    pending_question: Mapping[str, object] | None = None
    for row in rows:
        direction = normalize_field_value(
            first_value(row, ("direction", "Direction", "role", "Role", "author_role", "AuthorRole")) or ""
        )
        text = first_value(row, ("text", "Text", "message_text", "MessageText", "content", "Content"))
        if direction in {"question", "prompt", "user"}:
            pending_question = row
            continue
        if direction not in {"answer", "response", "assistant"} or pending_question is None:
            continue
        pair_id = first_value(row, ("pair_id", "PairId", "message_id", "MessageId", "id", "Id"))
        question_id = first_value(pending_question, ("message_id", "MessageId", "id", "Id"))
        pairs.append(
            {
                "ai_service": first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["ai_service"])
                or first_value(pending_question, AI_TRANSCRIPT_FIELD_ALIASES["ai_service"]),
                "pair_id": pair_id or question_id,
                "question": first_value(pending_question, ("question", "Question", "prompt", "Prompt")) or first_value(
                    pending_question, ("text", "Text", "message_text", "MessageText", "content", "Content")
                ),
                "answer": first_value(row, ("answer", "Answer", "response", "Response")) or text,
                "timestamp": first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["timestamp"])
                or first_value(pending_question, AI_TRANSCRIPT_FIELD_ALIASES["timestamp"]),
                "source_path": first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["source_path"])
                or first_value(pending_question, AI_TRANSCRIPT_FIELD_ALIASES["source_path"]),
                "source_sha256s": [
                    value
                    for value in (
                        first_value(pending_question, AI_TRANSCRIPT_FIELD_ALIASES["source_sha256s"]),
                        first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["source_sha256s"]),
                    )
                    if value
                ],
                "question_source_path": first_value(pending_question, AI_TRANSCRIPT_FIELD_ALIASES["source_path"]),
                "answer_source_path": first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["source_path"]),
                "question_source_offset": first_value(
                    pending_question,
                    ("source_offset", "SourceOffset", "question_source_offset", "QuestionSourceOffset"),
                ),
                "answer_source_offset": first_value(
                    row,
                    ("source_offset", "SourceOffset", "answer_source_offset", "AnswerSourceOffset"),
                ),
                "storage_area": first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["storage_area"])
                or first_value(pending_question, AI_TRANSCRIPT_FIELD_ALIASES["storage_area"]),
            }
        )
        pending_question = None
    return pairs


def nested_mobile_export_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    artifact_hint = row_family_hint(flattened_parent)
    source_tool = first_value(
        flattened_parent,
        ("source_tool", "details.source_tool", "vendor_tool", "details.vendor_tool", "tool", "details.tool"),
    )
    mobile_source = normalize_mobile_identifier(source_tool)
    if not re.search(
        r"\b(mobile|cellebrite|xry|graykey|axiom|ufed|ios|android|phone|backup)\b",
        artifact_hint,
    ) and mobile_source not in {"cellebrite", "xry", "graykey", "axiom", "ufed", "magnet-axiom", "rapidtriage"}:
        return
    parent_values = {
        "source_tool": source_tool,
        "service": first_value(
            flattened_parent,
            ("service", "details.service", "app", "details.app", "platform", "details.platform"),
        ),
        "conversation_id": first_value(
            flattened_parent,
            ("conversation_id", "details.conversation_id", "chat_id", "details.chat_id", "thread_id", "details.thread_id"),
        ),
        "source_path": first_value(flattened_parent, ("source_path", "details.source_path", "path", "details.path")),
    }
    nested_groups: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
        (
            "mobile-export-message",
            (
                ("details", "messages"),
                ("messages",),
                ("details", "message_rows"),
                ("message_rows",),
                ("details", "mobile_messages"),
                ("mobile_messages",),
            ),
        ),
        (
            "mobile-export-contact",
            (
                ("details", "contacts"),
                ("contacts",),
                ("details", "contact_rows"),
                ("contact_rows",),
            ),
        ),
        (
            "mobile-export-call",
            (
                ("details", "calls"),
                ("calls",),
                ("details", "call_logs"),
                ("call_logs",),
            ),
        ),
        (
            "mobile-export-media",
            (
                ("details", "media"),
                ("media",),
                ("details", "attachments"),
                ("attachments",),
            ),
        ),
        (
            "ios-backup-file",
            (
                ("details", "ios_backup_files"),
                ("ios_backup_files",),
                ("details", "manifest_files"),
                ("manifest_files",),
            ),
        ),
        (
            "ios-keychain-inventory",
            (
                ("details", "keychain_rows"),
                ("keychain_rows",),
                ("details", "keychain_inventory"),
                ("keychain_inventory",),
            ),
        ),
    )
    for artifact_type, paths in nested_groups:
        for nested in first_nested_list(item, paths):
            if not isinstance(nested, Mapping):
                continue
            row = flatten_mapping(nested)
            row.setdefault("artifact_type", artifact_type)
            for key, value in parent_values.items():
                if value not in (None, ""):
                    row.setdefault(key, value)
            yield row


def nested_mobile_app_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    parent_values = {
        "package_name": first_value(
            flattened_parent,
            ("package_name", "details.package_name", "bundle_id", "details.bundle_id", "application_id", "details.application_id"),
        ),
        "app_label": first_value(flattened_parent, ("app_label", "details.app_label", "name", "details.name")),
        "version_name": first_value(
            flattened_parent,
            ("version_name", "details.version_name", "version", "details.version"),
        ),
        "version_code": first_value(
            flattened_parent,
            ("version_code", "details.version_code", "build", "details.build"),
        ),
        "apk_sha256": first_value(flattened_parent, ("apk_sha256", "details.apk_sha256", "sha256", "details.sha256")),
        "cert_sha256": first_value(
            flattened_parent,
            ("cert_sha256", "details.cert_sha256", "certificate_sha256", "details.certificate_sha256"),
        ),
    }
    nested_groups: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = (
        (
            "mobile-app",
            (
                ("details", "apps"),
                ("apps",),
                ("details", "app_rows"),
                ("app_rows",),
                ("details", "android_apps"),
                ("android_apps",),
            ),
        ),
        (
            "android-app-data",
            (
                ("details", "app_data_rows"),
                ("app_data_rows",),
                ("details", "databases"),
                ("databases",),
                ("details", "tables"),
                ("tables",),
            ),
        ),
    )
    for artifact_type, paths in nested_groups:
        for nested in first_nested_list(item, paths):
            if not isinstance(nested, Mapping):
                continue
            row = flatten_mapping(nested)
            row.setdefault("artifact_type", artifact_type)
            for key, value in parent_values.items():
                if value not in (None, ""):
                    row.setdefault(key, value)
            yield row


def nested_chat_app_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    artifact_hint = row_family_hint(flattened_parent)
    service = normalize_mobile_identifier(
        first_value(flattened_parent, ("service", "details.service", "app", "details.app", "platform", "details.platform"))
    )
    if re.search(r"\b(mobile-export|mobile-vendor|ios-backup|android-backup|vendor-export)\b", artifact_hint):
        return
    if not re.search(
        r"\b(kakaotalk|whatsapp|telegram|signal|wechat|line|discord|instagram|facebook|messenger|chat|slack|matrix|viber|skype)\b",
        artifact_hint,
    ) and service not in CHAT_APP_SERVICES:
        return
    parent_values = {
        "service": first_value(
            flattened_parent,
            ("service", "details.service", "app", "details.app", "platform", "details.platform"),
        ),
        "profile": first_value(flattened_parent, ("profile", "details.profile", "account", "details.account")),
        "conversation_id": first_value(
            flattened_parent,
            ("conversation_id", "details.conversation_id", "chat_id", "details.chat_id", "thread_id", "details.thread_id"),
        ),
        "conversation_title": first_value(
            flattened_parent,
            ("conversation_title", "details.conversation_title", "chat_name", "details.chat_name"),
        ),
    }
    for nested in first_nested_list(
        item,
        (
            ("details", "messages"),
            ("messages",),
            ("details", "message_rows"),
            ("message_rows",),
            ("details", "chat_messages"),
            ("chat_messages",),
        ),
    ):
        if not isinstance(nested, Mapping):
            continue
        row = flatten_mapping(nested)
        row.setdefault("artifact_type", "chat-message")
        for key, value in parent_values.items():
            if value not in (None, ""):
                row.setdefault(key, value)
        yield row


def nested_email_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    artifact_hint = row_family_hint(flattened_parent)
    has_mailbox_context = bool(
        first_value(flattened_parent, ("mailbox", "details.mailbox", "mailbox_name", "details.mailbox_name"))
        or first_value(flattened_parent, ("folder", "details.folder", "folder_path", "details.folder_path"))
    )
    if not re.search(r"\b(email|mail|mbox|eml|emlx|pst|ost|msg|gmail)\b", artifact_hint) and not has_mailbox_context:
        return
    parent_values = {
        "mailbox": first_value(flattened_parent, ("mailbox", "details.mailbox", "mailbox_name", "details.mailbox_name")),
        "folder": first_value(flattened_parent, ("folder", "details.folder", "folder_path", "details.folder_path")),
        "source_path": first_value(flattened_parent, ("source_path", "details.source_path", "path", "details.path")),
    }
    for nested in first_nested_list(
        item,
        (
            ("details", "messages"),
            ("messages",),
            ("details", "email_messages"),
            ("email_messages",),
            ("details", "mailbox_messages"),
            ("mailbox_messages",),
            ("details", "exported_messages"),
            ("exported_messages",),
        ),
    ):
        if not isinstance(nested, Mapping):
            continue
        row = flatten_mapping(nested)
        row.setdefault("artifact_type", "email-message")
        for key, value in parent_values.items():
            if value not in (None, ""):
                row.setdefault(key, value)
        yield row


def nested_cloud_export_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    artifact_hint = row_family_hint(flattened_parent)
    provider = first_value(
        flattened_parent,
        ("provider", "details.provider", "cloud_family", "details.cloud_family", "service", "details.service"),
    )
    product = first_value(
        flattened_parent,
        ("product", "details.product", "workload", "details.workload", "app", "details.app"),
    )
    if not re.search(
        r"\b(cloud|takeout|icloud|m365|onedrive|teams|sharepoint|purview|drive|google)\b",
        artifact_hint,
    ) and not (provider and product):
        return
    parent_values = {
        "provider": provider,
        "product": product,
    }
    for nested in first_nested_list(
        item,
        (
            ("details", "rows"),
            ("rows",),
            ("details", "files"),
            ("files",),
            ("details", "items"),
            ("items",),
            ("details", "events"),
            ("events",),
            ("details", "messages"),
            ("messages",),
            ("details", "audit_rows"),
            ("audit_rows",),
        ),
    ):
        if not isinstance(nested, Mapping):
            continue
        row = flatten_mapping(nested)
        row.setdefault("artifact_type", "cloud-export-row")
        for key, value in parent_values.items():
            if value not in (None, ""):
                row.setdefault(key, value)
        yield row


def nested_cloud_api_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    artifact_hint = row_family_hint(flattened_parent)
    endpoint = first_value(flattened_parent, ("endpoint", "details.endpoint", "url", "details.url"))
    provider = first_value(flattened_parent, ("provider", "details.provider", "service", "details.service"))
    if not re.search(r"\b(cloud-api|api-response|oauth|graph-api|provider-api|api|collection)\b", artifact_hint) and not (
        endpoint and provider
    ):
        return
    parent_values = {
        "provider": provider,
        "endpoint": endpoint,
        "method": first_value(flattened_parent, ("method", "details.method", "http_method", "details.http_method")),
    }
    for nested in first_nested_list(
        item,
        (
            ("details", "responses"),
            ("responses",),
            ("details", "pages"),
            ("pages",),
            ("details", "requests"),
            ("requests",),
            ("details", "api_rows"),
            ("api_rows",),
        ),
    ):
        if not isinstance(nested, Mapping):
            continue
        row = flatten_mapping(nested)
        row.setdefault("artifact_type", "cloud-api-response")
        for key, value in parent_values.items():
            if value not in (None, ""):
                row.setdefault(key, value)
        yield row


def nested_usn_state_replay_rows(
    item: Mapping[str, object],
    flattened_parent: Mapping[str, object],
) -> Iterable[dict[str, object]]:
    transitions = first_nested_list(
        item,
        (
            ("details", "usn_replay_inventory_profile", "bounded_state_replay_preview", "transitions"),
            ("usn_replay_inventory_profile", "bounded_state_replay_preview", "transitions"),
            ("bounded_state_replay_preview", "transitions"),
        ),
    )
    for transition in transitions:
        if not isinstance(transition, Mapping):
            continue
        row = flatten_mapping(transition)
        row.setdefault("artifact_type", "usn-state-replay-transition")
        for parent_key in ("source_path", "source_sha256", "parser", "artifact_type"):
            if parent_key in flattened_parent and parent_key not in row:
                row[f"parent_{parent_key}"] = flattened_parent[parent_key]
        yield row


def first_nested_list(
    item: Mapping[str, object],
    paths: Sequence[Sequence[str]],
) -> list[object]:
    for path in paths:
        value: object = item
        for part in path:
            if not isinstance(value, Mapping):
                value = None
                break
            value = value.get(part)
        if isinstance(value, list):
            return value
    return []


def flatten_mapping(value: Mapping[str, object], *, prefix: str = "") -> dict[str, object]:
    row: dict[str, object] = {}
    for key, item in value.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, Mapping):
            row.update(flatten_mapping(item, prefix=full_key))
        elif isinstance(item, (list, tuple, set)) and all(
            isinstance(part, (str, int, float, bool)) or part is None
            for part in item
        ):
            row[full_key] = list(item)
        elif isinstance(item, (str, int, float, bool)) or item is None:
            row[full_key] = item
    return row


def candidate_keys(row: Mapping[str, object]) -> list[str]:
    keys: list[str] = []
    keys.extend(composite_candidate_keys(row))
    for field in KEY_FIELDS:
        value = value_for_key(row, field)
        if value is not None and str(value).strip():
            if field.lower() in {"message_id", "messageid", "internetmessageid", "message-id"}:
                keys.append(normalize_key(normalize_email_message_id(value)))
            else:
                keys.append(normalize_key(value))
    if not keys:
        joined = "|".join(f"{key}={row[key]}" for key in sorted(row)[:8])
        if joined:
            keys.append(normalize_key(joined))
    return keys


def composite_candidate_keys(row: Mapping[str, object]) -> list[str]:
    composites: list[str] = []
    event_record_id = first_value(row, ("event_record_id", "EventRecordID", "record_id", "RecordNumber", "record_number"))
    event_id = first_value(row, ("event_id", "EventID"))
    provider = first_value(row, ("provider_name", "Provider"))
    channel = first_value(row, ("channel", "Channel"))
    if event_record_id is not None:
        composites.append(normalize_key(f"evtx-record:{event_record_id}"))
    if event_record_id is not None and channel is not None:
        composites.append(normalize_key(f"evtx-record:{channel}:{event_record_id}"))
    if event_id is not None and provider is not None:
        composites.append(normalize_key(f"evtx-event:{provider}:{event_id}"))

    key_path = registry_path_value(row, ("key_path", "KeyPath", "registry_path", "RegistryPath", "path", "Path"))
    value_name = first_value(row, ("value_name", "ValueName"))
    cell_offset = first_value(row, ("cell_offset", "CellOffset", "source_offset", "SourceOffset"))
    if key_path:
        composites.append(normalize_key(f"registry-key:{key_path}"))
    if key_path and value_name is not None:
        composites.append(normalize_key(f"registry-value:{key_path}:{value_name}"))
    if cell_offset is not None:
        composites.append(normalize_key(f"registry-cell:{normalize_registry_numeric_string(str(cell_offset))}"))
    composites.extend(os_account_key_variants(row))
    composites.extend(execution_artifact_key_variants(row))
    composites.extend(user_activity_key_variants(row))
    composites.extend(system_artifact_key_variants(row))
    composites.extend(browser_storage_key_variants(row))
    composites.extend(browser_timeline_key_variants(row))
    if has_ai_transcript_signal(row):
        composites.extend(ai_transcript_key_variants(row))
    if has_mobile_export_signal(row):
        composites.extend(mobile_export_key_variants(row))
    if has_mobile_app_signal(row):
        composites.extend(mobile_app_key_variants(row))
    if has_chat_app_signal(row):
        composites.extend(chat_app_key_variants(row))
    if has_email_signal(row):
        composites.extend(email_key_variants(row))
    if has_cloud_export_signal(row):
        composites.extend(cloud_export_key_variants(row))
    if has_cloud_api_signal(row):
        composites.extend(cloud_api_key_variants(row))

    mft_record_number = ntfs_int_value(row, MFT_FIELD_ALIASES["record_number"])
    mft_path = ntfs_path_value(row, MFT_FIELD_ALIASES["file_path"])
    mft_offset = ntfs_int_value(row, MFT_FIELD_ALIASES["record_offset"])
    if mft_record_number and mft_path:
        composites.append(normalize_key(f"mft-record:{mft_record_number}:{mft_path}"))
    if mft_record_number:
        composites.append(normalize_key(f"mft-record:{mft_record_number}"))
    if mft_offset:
        composites.append(normalize_key(f"mft-offset:{mft_offset}"))

    usn = ntfs_int_value(row, USN_FIELD_ALIASES["usn"])
    frn = ntfs_int_value(row, USN_FIELD_ALIASES["file_reference_number"])
    file_name = normalize_ntfs_file_name(first_value(row, USN_FIELD_ALIASES["file_name"]))
    cursor = ntfs_int_value(row, USN_FIELD_ALIASES["record_cursor"])
    if usn and frn and file_name:
        composites.append(normalize_key(f"usn-record:{usn}:{frn}:{file_name}"))
    if usn and frn:
        composites.append(normalize_key(f"usn-record:{usn}:{frn}"))
    if usn:
        composites.append(normalize_key(f"usn-record:{usn}"))
    if cursor and frn:
        composites.append(normalize_key(f"usn-cursor:{cursor}:{frn}"))
    composites.extend(usn_state_replay_key_variants(row))
    composites.extend(ese_key_variants(row))
    return composites


def first_value(row: Mapping[str, object], fields: Iterable[str]) -> object | None:
    for field in fields:
        value = value_for_key(row, field)
        if value is not None and str(value).strip():
            return value
    return None


def row_family_hint(row: Mapping[str, object]) -> str:
    return normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )


def compare_datasets(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
    *,
    min_overlap: float,
) -> dict[str, object]:
    rapid_keys = set(str(item) for item in rapid_dataset.get("keys", []) if str(item))
    reference_keys = set(str(item) for item in reference_dataset.get("keys", []) if str(item))
    overlap = sorted(rapid_keys & reference_keys)
    missing_in_rapid = sorted(reference_keys - rapid_keys)
    only_in_rapid = sorted(rapid_keys - reference_keys)
    denominator = max(len(reference_keys), 1)
    overlap_ratio = round(len(overlap) / denominator, 4)
    row_count_delta = int(rapid_dataset.get("row_count", 0)) - int(reference_dataset.get("row_count", 0))
    rapid_quality = rapid_dataset.get("key_quality") if isinstance(rapid_dataset.get("key_quality"), Mapping) else {}
    reference_quality = reference_dataset.get("key_quality") if isinstance(reference_dataset.get("key_quality"), Mapping) else {}
    input_quality_blockers = input_quality_blockers_for_comparison(
        rapid_dataset=rapid_dataset,
        reference_dataset=reference_dataset,
        rapid_quality=rapid_quality,
        reference_quality=reference_quality,
    )
    status = "pass"
    if reference_keys and overlap_ratio < min_overlap:
        status = "failed"
    elif abs(row_count_delta) > max(int(reference_dataset.get("row_count", 0)) * 0.25, 10):
        status = "warning"
    field_comparison = compare_record_fields(rapid_dataset, reference_dataset)
    registry_field_comparison = compare_registry_fields(rapid_dataset, reference_dataset)
    mft_field_comparison = compare_mft_fields(rapid_dataset, reference_dataset)
    usn_field_comparison = compare_usn_fields(rapid_dataset, reference_dataset)
    usn_state_replay_field_comparison = compare_usn_state_replay_fields(rapid_dataset, reference_dataset)
    ese_field_comparison = compare_ese_fields(rapid_dataset, reference_dataset)
    os_account_field_comparison = compare_os_account_fields(rapid_dataset, reference_dataset)
    execution_artifact_field_comparison = compare_execution_artifact_fields(rapid_dataset, reference_dataset)
    user_activity_field_comparison = compare_user_activity_fields(rapid_dataset, reference_dataset)
    system_artifact_field_comparison = compare_system_artifact_fields(rapid_dataset, reference_dataset)
    browser_storage_field_comparison = compare_browser_storage_fields(rapid_dataset, reference_dataset)
    browser_timeline_field_comparison = compare_browser_timeline_fields(rapid_dataset, reference_dataset)
    ai_transcript_field_comparison = compare_ai_transcript_fields(rapid_dataset, reference_dataset)
    mobile_export_field_comparison = compare_mobile_export_fields(rapid_dataset, reference_dataset)
    mobile_app_field_comparison = compare_mobile_app_fields(rapid_dataset, reference_dataset)
    chat_app_field_comparison = compare_chat_app_fields(rapid_dataset, reference_dataset)
    email_field_comparison = compare_email_fields(rapid_dataset, reference_dataset)
    cloud_export_field_comparison = compare_cloud_export_fields(rapid_dataset, reference_dataset)
    cloud_api_field_comparison = compare_cloud_api_fields(rapid_dataset, reference_dataset)
    if field_comparison["mismatch_count"] or field_comparison["missing_common_field_count"]:
        status = "failed"
    if registry_field_comparison["mismatch_count"]:
        status = "failed"
    if mft_field_comparison["mismatch_count"]:
        status = "failed"
    if usn_field_comparison["mismatch_count"]:
        status = "failed"
    if usn_state_replay_field_comparison["mismatch_count"]:
        status = "failed"
    if ese_field_comparison["mismatch_count"]:
        status = "failed"
    if os_account_field_comparison["mismatch_count"]:
        status = "failed"
    if execution_artifact_field_comparison["mismatch_count"]:
        status = "failed"
    if user_activity_field_comparison["mismatch_count"]:
        status = "failed"
    if system_artifact_field_comparison["mismatch_count"]:
        status = "failed"
    if browser_storage_field_comparison["mismatch_count"]:
        status = "failed"
    if browser_timeline_field_comparison["mismatch_count"]:
        status = "failed"
    if (
        ai_transcript_field_comparison["mismatch_count"]
        or ai_transcript_field_comparison["missing_common_field_count"]
    ):
        status = "failed"
    if (
        mobile_export_field_comparison["mismatch_count"]
        or mobile_export_field_comparison["missing_common_field_count"]
    ):
        status = "failed"
    if mobile_app_field_comparison["mismatch_count"] or mobile_app_field_comparison["missing_common_field_count"]:
        status = "failed"
    if chat_app_field_comparison["mismatch_count"] or chat_app_field_comparison["missing_common_field_count"]:
        status = "failed"
    if email_field_comparison["mismatch_count"] or email_field_comparison["missing_common_field_count"]:
        status = "failed"
    if cloud_export_field_comparison["mismatch_count"] or cloud_export_field_comparison["missing_common_field_count"]:
        status = "failed"
    if cloud_api_field_comparison["mismatch_count"] or cloud_api_field_comparison["missing_common_field_count"]:
        status = "failed"
    if input_quality_blockers:
        status = "failed"
    return {
        "reference_name": reference_dataset.get("name", ""),
        "status": status,
        "rapid_row_count": rapid_dataset.get("row_count", 0),
        "reference_row_count": reference_dataset.get("row_count", 0),
        "row_count_delta": row_count_delta,
        "rapid_key_count": len(rapid_keys),
        "reference_key_count": len(reference_keys),
        "overlap_count": len(overlap),
        "overlap_ratio": overlap_ratio,
        "missing_in_rapid_sample": missing_in_rapid[:50],
        "only_in_rapid_sample": only_in_rapid[:50],
        "input_quality": {
            "rapid_truncated": bool(rapid_dataset.get("truncated")),
            "reference_truncated": bool(reference_dataset.get("truncated")),
            "rapid_row_cap": int(rapid_dataset.get("row_cap") or MAX_ROWS_PER_TOOL),
            "reference_row_cap": int(reference_dataset.get("row_cap") or MAX_ROWS_PER_TOOL),
            "rapid_duplicate_key_count": int(rapid_quality.get("duplicate_key_count") or 0),
            "reference_duplicate_key_count": int(reference_quality.get("duplicate_key_count") or 0),
            "rapid_unkeyed_row_count": int(rapid_quality.get("unkeyed_row_count") or 0),
            "reference_unkeyed_row_count": int(reference_quality.get("unkeyed_row_count") or 0),
            "rapid_duplicate_key_samples": rapid_quality.get("duplicate_key_samples", [])[:10]
            if isinstance(rapid_quality.get("duplicate_key_samples"), list)
            else [],
            "reference_duplicate_key_samples": reference_quality.get("duplicate_key_samples", [])[:10]
            if isinstance(reference_quality.get("duplicate_key_samples"), list)
            else [],
            "blockers": input_quality_blockers,
        },
        "record_field_comparison": field_comparison,
        "registry_field_comparison": registry_field_comparison,
        "mft_field_comparison": mft_field_comparison,
        "usn_field_comparison": usn_field_comparison,
        "usn_state_replay_field_comparison": usn_state_replay_field_comparison,
        "ese_field_comparison": ese_field_comparison,
        "os_account_field_comparison": os_account_field_comparison,
        "execution_artifact_field_comparison": execution_artifact_field_comparison,
        "user_activity_field_comparison": user_activity_field_comparison,
        "system_artifact_field_comparison": system_artifact_field_comparison,
        "browser_storage_field_comparison": browser_storage_field_comparison,
        "browser_timeline_field_comparison": browser_timeline_field_comparison,
        "ai_transcript_field_comparison": ai_transcript_field_comparison,
        "mobile_export_field_comparison": mobile_export_field_comparison,
        "mobile_app_field_comparison": mobile_app_field_comparison,
        "chat_app_field_comparison": chat_app_field_comparison,
        "email_field_comparison": email_field_comparison,
        "cloud_export_field_comparison": cloud_export_field_comparison,
        "cloud_api_field_comparison": cloud_api_field_comparison,
        "release_gate": "review-required" if status != "pass" else "comparison-passed",
    }


def input_quality_blockers_for_comparison(
    *,
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
    rapid_quality: Mapping[str, object],
    reference_quality: Mapping[str, object],
) -> list[str]:
    blockers: list[str] = []
    if bool(rapid_dataset.get("truncated")):
        blockers.append("rapid-output-row-cap-truncated")
    if bool(reference_dataset.get("truncated")):
        blockers.append("reference-output-row-cap-truncated")
    if int(rapid_quality.get("duplicate_key_count") or 0) > 0:
        blockers.append("rapid-output-duplicate-record-keys")
    if int(reference_quality.get("duplicate_key_count") or 0) > 0:
        blockers.append("reference-output-duplicate-record-keys")
    if int(rapid_quality.get("unkeyed_row_count") or 0) > 0:
        blockers.append("rapid-output-unkeyed-rows")
    if int(reference_quality.get("unkeyed_row_count") or 0) > 0:
        blockers.append("reference-output-unkeyed-rows")
    return blockers


def record_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_RECORD_FIELD_DIFF_ROWS]:
        record_keys = evtx_record_key_variants(row)
        if not record_keys:
            continue
        fields: dict[str, str] = {}
        for canonical, aliases in EVTX_FIELD_ALIASES.items():
            value = first_value(row, aliases)
            if value is not None and str(value).strip():
                fields[canonical] = normalize_field_value(value)
        fields.update(evtx_event_data_fields(row))
        if fields:
            for key in record_keys:
                index.setdefault(key, fields)
    return index


def evtx_record_key_variants(row: Mapping[str, object]) -> list[str]:
    record_id = first_value(row, EVTX_FIELD_ALIASES["event_record_id"])
    if record_id is None:
        return []
    channel = first_value(row, EVTX_FIELD_ALIASES["channel"])
    keys = [normalize_key(f"evtx-record:{record_id}")]
    if channel is not None and str(channel).strip():
        keys.insert(0, normalize_key(f"evtx-record:{channel}:{record_id}"))
    return list(dict.fromkeys(keys))


def evtx_event_data_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in row.items():
        if value is None or isinstance(value, (dict, list, tuple, set)):
            continue
        field_name = evtx_event_data_field_name(str(key))
        if not field_name:
            continue
        normalized_name = normalize_key(field_name).replace(" ", "_")
        if not normalized_name:
            continue
        fields[f"event_data:{normalized_name}"] = normalize_field_value(value)
    return fields


def evtx_event_data_field_name(key: str) -> str:
    key_lower = key.lower()
    parts = key.split(".")
    for index, part in enumerate(parts[:-1]):
        if part.lower() in EVTX_EVENT_DATA_PREFIXES:
            return parts[index + 1]
    for marker in EVTX_EVENT_DATA_KEY_MARKERS:
        position = key_lower.find(marker)
        if position >= 0:
            return key[position + len(marker):].split(".", 1)[0]
    return ""


def compare_record_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    rapid_index = rapid_dataset.get("record_field_index") if isinstance(rapid_dataset.get("record_field_index"), Mapping) else {}
    reference_index = (
        reference_dataset.get("record_field_index")
        if isinstance(reference_dataset.get("record_field_index"), Mapping)
        else {}
    )
    common_key_variants = sorted(set(rapid_index) & set(reference_index))
    common_keys: list[str] = []
    seen_record_ids: set[str] = set()
    for key in common_key_variants:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        record_id = str(rapid_fields.get("event_record_id") or reference_fields.get("event_record_id") or key)
        if record_id in seen_record_ids:
            continue
        seen_record_ids.add(record_id)
        common_keys.append(key)
    compared_field_count = 0
    mismatch_count = 0
    missing_common_field_count = 0
    mismatch_samples: list[dict[str, object]] = []
    for key in common_keys[:MAX_RECORD_FIELD_DIFF_ROWS]:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        field_names = sorted(set(rapid_fields) | set(reference_fields))
        for field_name in field_names:
            rapid_value = str(rapid_fields.get(field_name) or "")
            reference_value = str(reference_fields.get(field_name) or "")
            if not rapid_value or not reference_value:
                missing_common_field_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            "record_key": key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "missing-field",
                        }
                    )
                continue
            compared_field_count += 1
            if rapid_value != reference_value:
                mismatch_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            "record_key": key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "mismatch",
                        }
                    )
    match_count = max(compared_field_count - mismatch_count, 0)
    field_match_ratio = round(match_count / compared_field_count, 4) if compared_field_count else 0.0
    return {
        "mode": "evtx-record-field-diff",
        "rapid_indexed_record_count": len(rapid_index),
        "reference_indexed_record_count": len(reference_index),
        "common_record_count": len(common_keys),
        "common_record_key_variant_count": len(common_key_variants),
        "compared_field_count": compared_field_count,
        "field_match_count": match_count,
        "mismatch_count": mismatch_count,
        "missing_common_field_count": missing_common_field_count,
        "field_match_ratio": field_match_ratio,
        "compared_canonical_fields": sorted(
            {
                field
                for key in common_keys[:MAX_RECORD_FIELD_DIFF_ROWS]
                for row in (rapid_index.get(key), reference_index.get(key))
                if isinstance(row, Mapping)
                for field in row
            }
        )[:500],
        "mismatch_samples": mismatch_samples,
        "truncated": len(common_keys) > MAX_RECORD_FIELD_DIFF_ROWS,
    }


def registry_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_REGISTRY_FIELD_DIFF_ROWS]:
        registry_keys = registry_key_variants(row)
        if not registry_keys:
            continue
        fields = registry_normalized_fields(row)
        if fields:
            for key in registry_keys:
                index.setdefault(key, fields)
    return index


def registry_key_variants(row: Mapping[str, object]) -> list[str]:
    key_path = registry_path_value(row, REGISTRY_FIELD_ALIASES["key_path"])
    value_name = first_value(row, REGISTRY_FIELD_ALIASES["value_name"])
    cell_offset = first_value(row, REGISTRY_FIELD_ALIASES["cell_offset"])
    parent_path = registry_path_value(row, REGISTRY_FIELD_ALIASES["parent_key_path"])
    keys: list[str] = []
    if key_path:
        keys.append(normalize_key(f"registry-key:{key_path}"))
        if value_name is not None and str(value_name).strip():
            keys.insert(0, normalize_key(f"registry-value:{key_path}:{value_name}"))
    if cell_offset is not None and str(cell_offset).strip():
        normalized_offset = normalize_registry_numeric_string(str(cell_offset))
        keys.insert(0, normalize_key(f"registry-cell:{normalized_offset}"))
        if parent_path and value_name is not None and str(value_name).strip():
            keys.append(normalize_key(f"registry-value:{parent_path}:{value_name}"))
    return list(dict.fromkeys(keys))


def registry_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in REGISTRY_FIELD_ALIASES.items():
        if canonical in {"key_path", "parent_key_path"}:
            value = registry_path_value(row, aliases)
        elif canonical == "cell_offset":
            raw = first_value(row, aliases)
            value = normalize_registry_numeric_string(str(raw)) if raw is not None else ""
        elif canonical == "value_data":
            raw = first_value(row, aliases)
            value = registry_value_data_digest(raw) if raw is not None and str(raw).strip() else ""
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def registry_path_value(row: Mapping[str, object], aliases: Iterable[str]) -> str:
    raw = first_value(row, aliases)
    if raw is None:
        return ""
    return normalize_registry_path(str(raw))


def normalize_registry_path(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    if not text:
        return ""
    lowered = re.sub(r"/+", "/", text.lower())
    if "/" not in lowered and "\\" not in str(value):
        return ""
    parts = [part for part in lowered.split("/") if part]
    if not parts:
        return ""
    root = REGISTRY_PATH_PREFIX_ALIASES.get(parts[0], parts[0])
    if root not in {"hkcu", "hklm", "hkcr", "hku", "hkcc"}:
        if not parts[0].startswith("hkey_"):
            return ""
    return "/".join([root, *parts[1:]])


def normalize_registry_numeric_string(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return text.lower()


def registry_value_data_digest(value: object) -> str:
    return hashlib.sha256(normalize_field_value(value).encode("utf-8", errors="replace")).hexdigest()


def compare_registry_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    rapid_index = rapid_dataset.get("registry_field_index") if isinstance(rapid_dataset.get("registry_field_index"), Mapping) else {}
    reference_index = (
        reference_dataset.get("registry_field_index")
        if isinstance(reference_dataset.get("registry_field_index"), Mapping)
        else {}
    )
    common_key_variants = sorted(set(rapid_index) & set(reference_index))
    common_keys: list[str] = []
    seen_identity: set[str] = set()
    for key in common_key_variants:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        identity = str(
            rapid_fields.get("cell_offset")
            or reference_fields.get("cell_offset")
            or rapid_fields.get("key_path")
            or reference_fields.get("key_path")
            or key
        )
        if identity in seen_identity:
            continue
        seen_identity.add(identity)
        common_keys.append(key)

    compared_field_count = 0
    mismatch_count = 0
    missing_common_field_count = 0
    mismatch_samples: list[dict[str, object]] = []
    for key in common_keys[:MAX_REGISTRY_FIELD_DIFF_ROWS]:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        field_names = sorted(set(rapid_fields) | set(reference_fields))
        for field_name in field_names:
            rapid_value = str(rapid_fields.get(field_name) or "")
            reference_value = str(reference_fields.get(field_name) or "")
            if not rapid_value or not reference_value:
                missing_common_field_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            "registry_key": key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "missing-field",
                        }
                    )
                continue
            compared_field_count += 1
            if rapid_value != reference_value:
                mismatch_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            "registry_key": key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "mismatch",
                        }
                    )
    match_count = max(compared_field_count - mismatch_count, 0)
    field_match_ratio = round(match_count / compared_field_count, 4) if compared_field_count else 0.0
    compared_fields = sorted(
        {
            field
            for key in common_keys[:MAX_REGISTRY_FIELD_DIFF_ROWS]
            for row in (rapid_index.get(key), reference_index.get(key))
            if isinstance(row, Mapping)
            for field in row
        }
    )[:500]
    return {
        "mode": "registry-key-value-deleted-cell-field-diff",
        "rapid_indexed_registry_count": len(rapid_index),
        "reference_indexed_registry_count": len(reference_index),
        "common_registry_count": len(common_keys),
        "common_registry_key_variant_count": len(common_key_variants),
        "compared_field_count": compared_field_count,
        "field_match_count": match_count,
        "mismatch_count": mismatch_count,
        "missing_common_field_count": missing_common_field_count,
        "field_match_ratio": field_match_ratio,
        "compared_canonical_fields": compared_fields,
        "mismatch_samples": mismatch_samples,
        "truncated": len(common_keys) > MAX_REGISTRY_FIELD_DIFF_ROWS,
    }


def os_account_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_OS_ACCOUNT_FIELD_DIFF_ROWS]:
        keys = os_account_key_variants(row)
        if not keys:
            continue
        fields = os_account_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def os_account_key_variants(row: Mapping[str, object]) -> list[str]:
    sid = normalize_sid(first_value(row, OS_ACCOUNT_FIELD_ALIASES["sid"]))
    rid = ntfs_int_value(row, OS_ACCOUNT_FIELD_ALIASES["rid"])
    account_name = normalize_windows_identity(first_value(row, OS_ACCOUNT_FIELD_ALIASES["account_name"]))
    group_name = normalize_windows_identity(first_value(row, OS_ACCOUNT_FIELD_ALIASES["group_name"]))
    privilege_name = normalize_windows_identity(first_value(row, OS_ACCOUNT_FIELD_ALIASES["privilege_name"]))
    secret_name = normalize_windows_identity(first_value(row, OS_ACCOUNT_FIELD_ALIASES["lsa_secret_name"]))
    keys: list[str] = []
    if sid:
        keys.append(normalize_key(f"os-account-sid:{sid}"))
    if rid:
        keys.append(normalize_key(f"os-account-rid:{rid}"))
        if account_name:
            keys.append(normalize_key(f"os-account-rid-name:{rid}:{account_name}"))
    if account_name:
        keys.append(normalize_key(f"os-account-name:{account_name}"))
    if sid and group_name:
        keys.append(normalize_key(f"os-account-group:{sid}:{group_name}"))
    if account_name and group_name:
        keys.append(normalize_key(f"os-account-group:{account_name}:{group_name}"))
    if sid and privilege_name:
        keys.append(normalize_key(f"os-account-privilege:{sid}:{privilege_name}"))
    if account_name and privilege_name:
        keys.append(normalize_key(f"os-account-privilege:{account_name}:{privilege_name}"))
    if secret_name:
        keys.append(normalize_key(f"os-account-secret:{secret_name}"))
    return list(dict.fromkeys(keys))


def os_account_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in OS_ACCOUNT_FIELD_ALIASES.items():
        if canonical == "sid":
            value = normalize_sid(first_value(row, aliases))
        elif canonical == "rid":
            value = ntfs_int_value(row, aliases)
        elif canonical in {"account_name", "group_name", "privilege_name", "lsa_secret_name"}:
            value = normalize_windows_identity(first_value(row, aliases))
        elif canonical == "admin_status":
            value = normalize_boolish(first_value(row, aliases))
        elif canonical == "uac_flags":
            value = normalize_ntfs_list(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def execution_artifact_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_EXECUTION_ARTIFACT_FIELD_DIFF_ROWS]:
        keys = execution_artifact_key_variants(row)
        if not keys:
            continue
        fields = execution_artifact_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def execution_artifact_key_variants(row: Mapping[str, object]) -> list[str]:
    family = infer_execution_artifact_family(row)
    executable_path = ntfs_path_value(row, EXECUTION_ARTIFACT_FIELD_ALIASES["executable_path"])
    user_sid = normalize_sid(first_value(row, EXECUTION_ARTIFACT_FIELD_ALIASES["user_sid"]))
    sha1 = normalize_hash_value(first_value(row, EXECUTION_ARTIFACT_FIELD_ALIASES["sha1"]))
    source_key = registry_path_value(row, EXECUTION_ARTIFACT_FIELD_ALIASES["source_key"])
    source_value = normalize_windows_identity(first_value(row, EXECUTION_ARTIFACT_FIELD_ALIASES["source_value"]))
    if not family:
        return []
    keys: list[str] = []
    if executable_path:
        keys.append(normalize_key(f"execution:{family}:path:{executable_path}"))
    if user_sid and executable_path:
        keys.append(normalize_key(f"execution:{family}:sid-path:{user_sid}:{executable_path}"))
    if sha1:
        keys.append(normalize_key(f"execution:{family}:sha1:{sha1}"))
    if source_key and source_value:
        keys.append(normalize_key(f"execution:{family}:source:{source_key}:{source_value}"))
    elif source_key:
        keys.append(normalize_key(f"execution:{family}:source:{source_key}"))
    return list(dict.fromkeys(keys))


def execution_artifact_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    family = infer_execution_artifact_family(row)
    if not family:
        return {}
    fields: dict[str, str] = {"artifact_family": family}
    for canonical, aliases in EXECUTION_ARTIFACT_FIELD_ALIASES.items():
        if canonical == "artifact_family":
            value = family
        elif canonical == "executable_path":
            value = ntfs_path_value(row, aliases)
        elif canonical == "user_sid":
            value = normalize_sid(first_value(row, aliases))
        elif canonical == "sha1":
            value = normalize_hash_value(first_value(row, aliases))
        elif canonical == "source_key":
            value = registry_path_value(row, aliases)
        elif canonical == "source_value":
            value = normalize_windows_identity(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def infer_execution_artifact_family(row: Mapping[str, object]) -> str:
    explicit = first_value(row, EXECUTION_ARTIFACT_FIELD_ALIASES["artifact_family"])
    explicit_text = normalize_field_value(explicit) if explicit is not None else ""
    haystack = " ".join(
        str(value)
        for key, value in row.items()
        if key.lower().endswith(("artifact_type", "parser", "source_path", "path", "source_key", "key_path"))
    ).lower()
    combined = f"{explicit_text} {haystack}"
    if "amcache" in combined:
        return "amcache"
    if "shimcache" in combined or "appcompatcache" in combined or "appcompat" in combined:
        return "shimcache"
    if "bam" in combined:
        return "bam"
    if "dam" in combined:
        return "dam"
    return ""


def compare_os_account_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="os_account_field_index",
        mode="os-account-sam-security-system-field-diff",
        key_name="os_account_key",
        row_limit=MAX_OS_ACCOUNT_FIELD_DIFF_ROWS,
    )


def compare_execution_artifact_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="execution_artifact_field_index",
        mode="execution-artifact-amcache-shimcache-bam-dam-field-diff",
        key_name="execution_artifact_key",
        row_limit=MAX_EXECUTION_ARTIFACT_FIELD_DIFF_ROWS,
    )


def user_activity_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_USER_ACTIVITY_FIELD_DIFF_ROWS]:
        keys = user_activity_key_variants(row)
        if not keys:
            continue
        fields = user_activity_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def user_activity_key_variants(row: Mapping[str, object]) -> list[str]:
    family = infer_user_activity_family(row)
    if not family:
        return []
    app_id = normalize_windows_identity(first_value(row, USER_ACTIVITY_FIELD_ALIASES["app_id"]))
    entry_id = ntfs_int_value(row, USER_ACTIVITY_FIELD_ALIASES["entry_id"])
    target_path = ntfs_path_value(row, USER_ACTIVITY_FIELD_ALIASES["target_path"])
    file_name = normalize_ntfs_file_name(first_value(row, USER_ACTIVITY_FIELD_ALIASES["file_name"]))
    source_path = ntfs_path_value(row, USER_ACTIVITY_FIELD_ALIASES["source_path"])
    source_offset = ntfs_int_value(row, USER_ACTIVITY_FIELD_ALIASES["source_offset"])
    bag_path = ntfs_path_value(row, USER_ACTIVITY_FIELD_ALIASES["bag_path"])
    mru_order = ntfs_int_value(row, USER_ACTIVITY_FIELD_ALIASES["mru_order"])
    tracker_guid = normalize_guidish(first_value(row, USER_ACTIVITY_FIELD_ALIASES["tracker_guid"]))
    keys: list[str] = []
    if app_id and entry_id:
        keys.append(normalize_key(f"user-activity:{family}:app-entry:{app_id}:{entry_id}"))
    if app_id and target_path:
        keys.append(normalize_key(f"user-activity:{family}:app-target:{app_id}:{target_path}"))
    if target_path:
        keys.append(normalize_key(f"user-activity:{family}:target:{target_path}"))
    if file_name and source_path:
        keys.append(normalize_key(f"user-activity:{family}:file-source:{file_name}:{source_path}"))
    if source_path and source_offset:
        keys.append(normalize_key(f"user-activity:{family}:source-offset:{source_path}:{source_offset}"))
    if bag_path and mru_order:
        keys.append(normalize_key(f"user-activity:{family}:bag-mru:{bag_path}:{mru_order}"))
    if bag_path:
        keys.append(normalize_key(f"user-activity:{family}:bag:{bag_path}"))
    if tracker_guid:
        keys.append(normalize_key(f"user-activity:{family}:tracker:{tracker_guid}"))
    return list(dict.fromkeys(keys))


def user_activity_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    family = infer_user_activity_family(row)
    if not family:
        return {}
    fields: dict[str, str] = {"artifact_family": family}
    for canonical, aliases in USER_ACTIVITY_FIELD_ALIASES.items():
        if canonical == "artifact_family":
            value = family
        elif canonical in {"entry_id", "source_offset", "mru_order", "access_count"}:
            value = ntfs_int_value(row, aliases)
        elif canonical in {"target_path", "source_path", "bag_path"}:
            value = ntfs_path_value(row, aliases)
        elif canonical == "file_name":
            value = normalize_ntfs_file_name(first_value(row, aliases))
        elif canonical == "tracker_guid":
            value = normalize_guidish(first_value(row, aliases))
        elif canonical in {"app_id", "volume_name", "shell_item_type"}:
            value = normalize_windows_identity(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def infer_user_activity_family(row: Mapping[str, object]) -> str:
    explicit = first_value(row, USER_ACTIVITY_FIELD_ALIASES["artifact_family"])
    explicit_text = normalize_field_value(explicit) if explicit is not None else ""
    haystack = " ".join(
        str(value)
        for key, value in row.items()
        if key.lower().endswith(("artifact_type", "parser", "source_path", "path", "source_file", "sourcefile", "kind"))
    ).lower()
    combined = f"{explicit_text} {haystack}"
    if "jumplist" in combined or "jump list" in combined or "destlist" in combined or "jlecmd" in combined or "automaticdestinations" in combined or "customdestinations" in combined:
        return "jumplist"
    if "shellbag" in combined or "bagmru" in combined or "sbecmd" in combined:
        return "shellbags"
    if "prefetch" in combined or "pecmd" in combined:
        return "prefetch"
    if "lnk" in combined or "shelllink" in combined:
        return "lnk"
    return ""


def compare_user_activity_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="user_activity_field_index",
        mode="user-activity-jumplist-shellbags-prefetch-lnk-field-diff",
        key_name="user_activity_key",
        row_limit=MAX_USER_ACTIVITY_FIELD_DIFF_ROWS,
    )


def system_artifact_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_SYSTEM_ARTIFACT_FIELD_DIFF_ROWS]:
        keys = system_artifact_key_variants(row)
        if not keys:
            continue
        fields = system_artifact_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def system_artifact_key_variants(row: Mapping[str, object]) -> list[str]:
    family = infer_system_artifact_family(row)
    if not family:
        return []
    task_uri = ntfs_path_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["task_uri"])
    command = ntfs_path_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["command"])
    principal = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["principal"]))
    threat_name = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["threat_name"]))
    source_ip = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["source_ip"]))
    destination_ip = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["destination_ip"]))
    destination_port = ntfs_int_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["destination_port"])
    protocol = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["protocol"]))
    application_name = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["application_name"]))
    exception_code = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["exception_code"]))
    wmi_consumer = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["wmi_consumer"]))
    wmi_filter = normalize_windows_identity(first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["wmi_filter"]))
    source_path = ntfs_path_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["source_path"])
    keys: list[str] = []
    if family == "task":
        if task_uri:
            keys.append(normalize_key(f"system:{family}:task:{task_uri}"))
        if task_uri and command:
            keys.append(normalize_key(f"system:{family}:task-command:{task_uri}:{command}"))
        if command and principal:
            keys.append(normalize_key(f"system:{family}:principal-command:{principal}:{command}"))
    elif family == "defender":
        if threat_name:
            keys.append(normalize_key(f"system:{family}:threat:{threat_name}"))
        if threat_name and source_path:
            keys.append(normalize_key(f"system:{family}:threat-source:{threat_name}:{source_path}"))
    elif family == "firewall":
        if destination_ip and destination_port:
            keys.append(normalize_key(f"system:{family}:dst:{destination_ip}:{destination_port}:{protocol}"))
        if source_ip and destination_ip and destination_port:
            keys.append(normalize_key(f"system:{family}:tuple:{source_ip}:{destination_ip}:{destination_port}:{protocol}"))
    elif family == "wer":
        if application_name and exception_code:
            keys.append(normalize_key(f"system:{family}:app-exception:{application_name}:{exception_code}"))
        if application_name:
            keys.append(normalize_key(f"system:{family}:app:{application_name}"))
    elif family == "wmi":
        if wmi_consumer:
            keys.append(normalize_key(f"system:{family}:consumer:{wmi_consumer}"))
        if wmi_filter:
            keys.append(normalize_key(f"system:{family}:filter:{wmi_filter}"))
        if command:
            keys.append(normalize_key(f"system:{family}:command:{command}"))
    if source_path:
        keys.append(normalize_key(f"system:{family}:source:{source_path}"))
    return list(dict.fromkeys(keys))


def system_artifact_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    family = infer_system_artifact_family(row)
    if not family:
        return {}
    fields: dict[str, str] = {"artifact_family": family}
    for canonical, aliases in SYSTEM_ARTIFACT_FIELD_ALIASES.items():
        if canonical == "artifact_family":
            value = family
        elif canonical in {"task_uri", "command", "source_path"}:
            value = ntfs_path_value(row, aliases)
        elif canonical == "destination_port":
            value = ntfs_int_value(row, aliases)
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def infer_system_artifact_family(row: Mapping[str, object]) -> str:
    explicit = first_value(row, SYSTEM_ARTIFACT_FIELD_ALIASES["artifact_family"])
    explicit_text = normalize_field_value(explicit) if explicit is not None else ""
    haystack = " ".join(
        str(value)
        for key, value in row.items()
        if key.lower().endswith(("artifact_type", "parser", "source_path", "path", "source_file", "kind"))
    ).lower()
    combined = f"{explicit_text} {haystack}"
    if "task" in combined or "scheduled" in combined:
        return "task"
    if "defender" in combined or "microsoft-windows-windows defender" in combined or "mplog" in combined:
        return "defender"
    if "firewall" in combined or "pfirewall" in combined:
        return "firewall"
    if "wer" in combined or "windows error reporting" in combined:
        return "wer"
    if "wmi" in combined or "objects.data" in combined:
        return "wmi"
    return ""


def compare_system_artifact_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="system_artifact_field_index",
        mode="system-artifact-task-defender-firewall-wer-wmi-field-diff",
        key_name="system_artifact_key",
        row_limit=MAX_SYSTEM_ARTIFACT_FIELD_DIFF_ROWS,
    )


def browser_storage_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_BROWSER_FIELD_DIFF_ROWS]:
        keys = browser_storage_key_variants(row)
        if not keys:
            continue
        fields = browser_storage_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def browser_storage_key_variants(row: Mapping[str, object]) -> list[str]:
    storage_type = normalize_windows_identity(first_value(row, BROWSER_STORAGE_FIELD_ALIASES["storage_type"]))
    browser = normalize_windows_identity(first_value(row, BROWSER_STORAGE_FIELD_ALIASES["browser"]))
    profile = normalize_windows_identity(first_value(row, BROWSER_STORAGE_FIELD_ALIASES["profile"]))
    storage_name = normalize_windows_identity(first_value(row, BROWSER_STORAGE_FIELD_ALIASES["storage_name"]))
    relative_path = ntfs_path_value(row, BROWSER_STORAGE_FIELD_ALIASES["relative_path"])
    keys: list[str] = []
    if storage_type and browser and profile and storage_name:
        keys.append(normalize_key(f"browser-storage:{browser}:{profile}:{storage_type}:{storage_name}"))
    if storage_type and browser and profile and relative_path:
        keys.append(normalize_key(f"browser-storage:{browser}:{profile}:{storage_type}:{relative_path}"))
    if storage_type and relative_path:
        keys.append(normalize_key(f"browser-storage:{storage_type}:path:{relative_path}"))
    return list(dict.fromkeys(keys))


def browser_storage_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    if not browser_storage_key_variants(row):
        return {}
    fields: dict[str, str] = {}
    for canonical, aliases in BROWSER_STORAGE_FIELD_ALIASES.items():
        if canonical in {"relative_path", "storage_name"}:
            value = ntfs_path_value(row, aliases)
        elif canonical in {"file_count", "total_bytes"}:
            value = ntfs_int_value(row, aliases)
        elif canonical in {"is_file", "sensitive", "inventory_truncated"}:
            value = normalize_boolish(first_value(row, aliases))
        elif canonical == "sample_hashes":
            value = normalize_ntfs_list(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def browser_timeline_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_BROWSER_FIELD_DIFF_ROWS]:
        keys = browser_timeline_key_variants(row)
        if not keys:
            continue
        fields = browser_timeline_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def browser_timeline_key_variants(row: Mapping[str, object]) -> list[str]:
    browser = normalize_windows_identity(first_value(row, BROWSER_TIMELINE_FIELD_ALIASES["browser"]))
    profile = normalize_windows_identity(first_value(row, BROWSER_TIMELINE_FIELD_ALIASES["profile"]))
    timeline_type = normalize_windows_identity(first_value(row, BROWSER_TIMELINE_FIELD_ALIASES["timeline_type"]))
    timestamp = normalize_field_value(first_value(row, BROWSER_TIMELINE_FIELD_ALIASES["timestamp"]) or "")
    url = normalize_field_value(first_value(row, BROWSER_TIMELINE_FIELD_ALIASES["url"]) or "")
    target_path = ntfs_path_value(row, BROWSER_TIMELINE_FIELD_ALIASES["target_path"])
    source_index = ntfs_int_value(row, BROWSER_TIMELINE_FIELD_ALIASES["source_index"])
    keys: list[str] = []
    if browser and profile and timeline_type and timestamp and url:
        keys.append(normalize_key(f"browser-timeline:{browser}:{profile}:{timeline_type}:{timestamp}:{url}"))
    if timeline_type and timestamp and url:
        keys.append(normalize_key(f"browser-timeline:{timeline_type}:{timestamp}:{url}"))
    if timeline_type and timestamp and target_path:
        keys.append(normalize_key(f"browser-timeline:{timeline_type}:{timestamp}:{target_path}"))
    if browser and profile and timeline_type and source_index:
        keys.append(normalize_key(f"browser-timeline:{browser}:{profile}:{timeline_type}:row:{source_index}"))
    return list(dict.fromkeys(keys))


def browser_timeline_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    if not browser_timeline_key_variants(row):
        return {}
    fields: dict[str, str] = {}
    for canonical, aliases in BROWSER_TIMELINE_FIELD_ALIASES.items():
        if canonical == "target_path":
            value = ntfs_path_value(row, aliases)
        elif canonical in {"visit_count", "typed_count", "total_bytes", "state", "source_index"}:
            value = ntfs_int_value(row, aliases)
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def compare_browser_storage_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="browser_storage_field_index",
        mode="browser-cache-session-extension-sync-storage-field-diff",
        key_name="browser_storage_key",
        row_limit=MAX_BROWSER_FIELD_DIFF_ROWS,
    )


def compare_browser_timeline_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="browser_timeline_field_index",
        mode="browser-unified-timeline-field-diff",
        key_name="browser_timeline_key",
        row_limit=MAX_BROWSER_FIELD_DIFF_ROWS,
    )


def mobile_export_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_MOBILE_FIELD_DIFF_ROWS]:
        if not has_mobile_export_signal(row):
            continue
        keys = mobile_export_key_variants(row)
        if not keys:
            continue
        fields = mobile_export_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def mobile_app_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_MOBILE_FIELD_DIFF_ROWS]:
        if not has_mobile_app_signal(row):
            continue
        keys = mobile_app_key_variants(row)
        if not keys:
            continue
        fields = mobile_app_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def has_mobile_export_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(mobile|ios|android|sms|mms|call|contact|message|chat|whatsapp|telegram|signal|kakao|line|wechat)\b", artifact_hint):
        return True
    signal_fields = (
        "conversation_id",
        "message_id",
        "sender",
        "recipient",
        "message_text_hash",
        "message_text",
        "media_hash",
        "phone",
        "email",
        "call_type",
        "duration",
        "file_id",
        "protection_class",
        "redaction_status",
    )
    return any(first_value(row, MOBILE_EXPORT_FIELD_ALIASES[field]) for field in signal_fields)


def has_mobile_app_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(apk|android-app|mobile-app|app-data|ios-app|bundle)\b", artifact_hint):
        return True
    signal_fields = (
        "package_name",
        "permission",
        "dangerous_permission_count",
        "cert_sha256",
        "apk_sha256",
        "dex_count",
        "native_library_count",
        "risk_model",
    )
    return any(first_value(row, MOBILE_APP_FIELD_ALIASES[field]) for field in signal_fields)


def mobile_export_key_variants(row: Mapping[str, object]) -> list[str]:
    source_record_id = normalize_mobile_identifier(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["source_record_id"]))
    service = normalize_mobile_identifier(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["service"]))
    conversation_id = normalize_mobile_identifier(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["conversation_id"]))
    message_id = normalize_mobile_identifier(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["message_id"]))
    timestamp = normalize_field_value(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["timestamp"]) or "")
    sender = normalize_mobile_actor(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["sender"]))
    text_hash = normalize_hash_value(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["message_text_hash"]))
    phone = normalize_mobile_phone(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["phone"]))
    email = normalize_mobile_identifier(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["email"]))
    file_id = normalize_mobile_identifier(first_value(row, MOBILE_EXPORT_FIELD_ALIASES["file_id"]))
    relative_path = ntfs_path_value(row, MOBILE_EXPORT_FIELD_ALIASES["relative_path"])
    keys: list[str] = []
    if source_record_id:
        keys.append(normalize_key(f"mobile-source:{source_record_id}"))
    if service and conversation_id and message_id:
        keys.append(normalize_key(f"mobile-message:{service}:{conversation_id}:{message_id}"))
    if service and message_id:
        keys.append(normalize_key(f"mobile-message:{service}:{message_id}"))
    if conversation_id and timestamp and (sender or text_hash):
        keys.append(normalize_key(f"mobile-message-context:{conversation_id}:{timestamp}:{sender}:{text_hash}"))
    if phone:
        keys.append(normalize_key(f"mobile-phone:{phone}"))
    if email:
        keys.append(normalize_key(f"mobile-email:{email}"))
    if file_id:
        keys.append(normalize_key(f"mobile-file-id:{file_id}"))
    if relative_path:
        keys.append(normalize_key(f"mobile-path:{relative_path}"))
    return list(dict.fromkeys(keys))


def mobile_app_key_variants(row: Mapping[str, object]) -> list[str]:
    package_name = normalize_mobile_identifier(first_value(row, MOBILE_APP_FIELD_ALIASES["package_name"]))
    apk_sha256 = normalize_hash_value(first_value(row, MOBILE_APP_FIELD_ALIASES["apk_sha256"]))
    cert_sha256 = normalize_hash_value(first_value(row, MOBILE_APP_FIELD_ALIASES["cert_sha256"]))
    app_data_path = ntfs_path_value(row, MOBILE_APP_FIELD_ALIASES["app_data_path"])
    database = ntfs_path_value(row, MOBILE_APP_FIELD_ALIASES["database"])
    table_name = normalize_mobile_identifier(first_value(row, MOBILE_APP_FIELD_ALIASES["table_name"]))
    keys: list[str] = []
    if database and table_name:
        return [normalize_key(f"mobile-app-db:{database}:{table_name}")]
    if app_data_path:
        return [normalize_key(f"mobile-app-data:{app_data_path}")]
    if package_name:
        keys.append(normalize_key(f"mobile-app:{package_name}"))
    if apk_sha256:
        keys.append(normalize_key(f"mobile-apk:{apk_sha256}"))
    if cert_sha256 and package_name:
        keys.append(normalize_key(f"mobile-app-cert:{package_name}:{cert_sha256}"))
    return list(dict.fromkeys(keys))


def mobile_export_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in MOBILE_EXPORT_FIELD_ALIASES.items():
        if canonical in {"artifact_family", "source_tool"}:
            continue
        if canonical in {"service", "conversation_id", "message_id", "file_id"}:
            value = normalize_mobile_identifier(first_value(row, aliases))
        elif canonical in {"sender", "recipient"}:
            value = normalize_mobile_actor(first_value(row, aliases))
        elif canonical == "phone":
            value = normalize_mobile_phone(first_value(row, aliases))
        elif canonical == "email":
            value = normalize_mobile_identifier(first_value(row, aliases))
        elif canonical in {"message_text_hash", "media_hash"}:
            value = normalize_hash_value(first_value(row, aliases))
        elif canonical in {"media_path", "relative_path"}:
            value = ntfs_path_value(row, aliases)
        elif canonical == "duration":
            value = ntfs_int_value(row, aliases)
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def mobile_app_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in MOBILE_APP_FIELD_ALIASES.items():
        if canonical in {"package_name", "version_name", "app_label", "table_name", "risk_model"}:
            value = normalize_mobile_identifier(first_value(row, aliases))
        elif canonical in {"version_code", "dangerous_permission_count", "dex_count", "native_library_count"}:
            value = ntfs_int_value(row, aliases)
        elif canonical in {"cert_sha256", "apk_sha256"}:
            value = normalize_hash_value(first_value(row, aliases))
        elif canonical in {"app_data_path", "database"}:
            value = ntfs_path_value(row, aliases)
        elif canonical == "permission":
            value = normalize_ntfs_list(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def compare_mobile_export_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="mobile_export_field_index",
        mode="mobile-vendor-ios-android-export-field-diff",
        key_name="mobile_export_key",
        row_limit=MAX_MOBILE_FIELD_DIFF_ROWS,
    )


def compare_mobile_app_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="mobile_app_field_index",
        mode="mobile-apk-app-data-field-diff",
        key_name="mobile_app_key",
        row_limit=MAX_MOBILE_FIELD_DIFF_ROWS,
    )


def chat_app_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    return messaging_field_index(
        rows,
        signal=has_chat_app_signal,
        key_builder=chat_app_key_variants,
        field_builder=chat_app_normalized_fields,
    )


def email_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    return messaging_field_index(
        rows,
        signal=has_email_signal,
        key_builder=email_key_variants,
        field_builder=email_normalized_fields,
    )


def cloud_export_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    return messaging_field_index(
        rows,
        signal=has_cloud_export_signal,
        key_builder=cloud_export_key_variants,
        field_builder=cloud_export_normalized_fields,
    )


def cloud_api_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    return messaging_field_index(
        rows,
        signal=has_cloud_api_signal,
        key_builder=cloud_api_key_variants,
        field_builder=cloud_api_normalized_fields,
    )


def ai_transcript_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    return messaging_field_index(
        rows,
        signal=has_ai_transcript_signal,
        key_builder=ai_transcript_key_variants,
        field_builder=ai_transcript_normalized_fields,
    )


def messaging_field_index(
    rows: Sequence[Mapping[str, object]],
    *,
    signal,
    key_builder,
    field_builder,
) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_MESSAGING_FIELD_DIFF_ROWS]:
        if not signal(row):
            continue
        keys = key_builder(row)
        if not keys:
            continue
        fields = field_builder(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def has_chat_app_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(kakaotalk|whatsapp|telegram|signal|wechat|line|discord|instagram|facebook|messenger|chat)\b", artifact_hint):
        return True
    service = normalize_mobile_identifier(first_value(row, CHAT_APP_FIELD_ALIASES["service"]))
    conversation_id = first_value(row, CHAT_APP_FIELD_ALIASES["conversation_id"])
    message_id = first_value(row, CHAT_APP_FIELD_ALIASES["message_id"])
    return bool(service and (conversation_id or message_id))


def has_email_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(email|mail|mbox|eml|emlx|pst|ost|msg)\b", artifact_hint):
        return True
    email_specific_message_id = first_value(row, ("InternetMessageId", "internet_message_id", "Message-ID", "message-id"))
    subject = first_value(row, EMAIL_FIELD_ALIASES["subject"])
    folder = first_value(row, EMAIL_FIELD_ALIASES["folder"])
    mailbox = first_value(row, EMAIL_FIELD_ALIASES["mailbox"])
    sender = first_value(row, EMAIL_FIELD_ALIASES["sender"])
    return bool(sender and (email_specific_message_id or subject or folder or mailbox))


def has_cloud_export_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(cloud|takeout|icloud|m365|onedrive|teams|sharepoint|purview|gmail|drive)\b", artifact_hint):
        return True
    provider = first_value(row, CLOUD_EXPORT_FIELD_ALIASES["provider"])
    product = first_value(row, CLOUD_EXPORT_FIELD_ALIASES["product"])
    return bool(
        provider
        and product
        and (
            first_value(row, CLOUD_EXPORT_FIELD_ALIASES["record_id"])
            or first_value(row, CLOUD_EXPORT_FIELD_ALIASES["item_id"])
        )
    )


def has_cloud_api_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(cloud-api|api-response|oauth|graph-api|provider-api)\b", artifact_hint):
        return True
    request_id = first_value(row, CLOUD_API_FIELD_ALIASES["request_id"])
    endpoint = first_value(row, CLOUD_API_FIELD_ALIASES["endpoint"])
    response_hash = first_value(row, CLOUD_API_FIELD_ALIASES["response_hash"])
    return bool(request_id or (endpoint and response_hash))


def has_ai_transcript_signal(row: Mapping[str, object]) -> bool:
    artifact_hint = normalize_mobile_identifier(
        first_value(row, ("artifact_type", "ArtifactType", "artifact_family", "ArtifactFamily", "source_type", "SourceType"))
    )
    if re.search(r"\b(ai-service|ai-transcript|ai-conversation|chatgpt|claude|gemini|perplexity|copilot)\b", artifact_hint):
        return True
    service = normalize_mobile_identifier(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["ai_service"]))
    question = first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["question"])
    answer = first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["answer"])
    pair_id = first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["pair_id"])
    known_ai_services = {"chatgpt", "openai", "claude", "anthropic", "gemini", "bard", "perplexity", "copilot"}
    return bool(service in known_ai_services and (pair_id or (question and answer)))


def chat_app_key_variants(row: Mapping[str, object]) -> list[str]:
    service = normalize_mobile_identifier(first_value(row, CHAT_APP_FIELD_ALIASES["service"]))
    conversation_id = normalize_mobile_identifier(first_value(row, CHAT_APP_FIELD_ALIASES["conversation_id"]))
    message_id = normalize_mobile_identifier(first_value(row, CHAT_APP_FIELD_ALIASES["message_id"]))
    timestamp = normalize_field_value(first_value(row, CHAT_APP_FIELD_ALIASES["timestamp"]) or "")
    sender = normalize_mobile_actor(first_value(row, CHAT_APP_FIELD_ALIASES["sender"]))
    text_hash = normalize_hash_value(first_value(row, CHAT_APP_FIELD_ALIASES["message_text_hash"]))
    source_record_id = normalize_mobile_identifier(first_value(row, CHAT_APP_FIELD_ALIASES["source_record_id"]))
    keys: list[str] = []
    if source_record_id:
        keys.append(normalize_key(f"chat-source:{source_record_id}"))
    if service and conversation_id and message_id:
        keys.append(normalize_key(f"chat-message:{service}:{conversation_id}:{message_id}"))
    if service and message_id:
        keys.append(normalize_key(f"chat-message:{service}:{message_id}"))
    if conversation_id and timestamp and (sender or text_hash):
        keys.append(normalize_key(f"chat-context:{conversation_id}:{timestamp}:{sender}:{text_hash}"))
    return list(dict.fromkeys(keys))


def email_key_variants(row: Mapping[str, object]) -> list[str]:
    message_id = normalize_email_message_id(first_value(row, EMAIL_FIELD_ALIASES["message_id"]))
    subject = normalize_mobile_identifier(first_value(row, EMAIL_FIELD_ALIASES["subject"]))
    sender = normalize_mobile_actor(first_value(row, EMAIL_FIELD_ALIASES["sender"]))
    sent_at = normalize_field_value(first_value(row, EMAIL_FIELD_ALIASES["sent_at"]) or "")
    source_record_id = normalize_mobile_identifier(first_value(row, EMAIL_FIELD_ALIASES["source_record_id"]))
    keys: list[str] = []
    if source_record_id:
        keys.append(normalize_key(f"email-source:{source_record_id}"))
    if message_id:
        keys.append(normalize_key(f"email-message:{message_id}"))
    if sender and sent_at and subject:
        keys.append(normalize_key(f"email-context:{sender}:{sent_at}:{subject}"))
    return list(dict.fromkeys(keys))


def cloud_export_key_variants(row: Mapping[str, object]) -> list[str]:
    provider = normalize_mobile_identifier(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["provider"]))
    product = normalize_mobile_identifier(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["product"]))
    record_id = normalize_mobile_identifier(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["record_id"]))
    item_id = normalize_mobile_identifier(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["item_id"]))
    timestamp = normalize_field_value(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["timestamp"]) or "")
    actor = normalize_mobile_actor(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["actor"]))
    action = normalize_mobile_identifier(first_value(row, CLOUD_EXPORT_FIELD_ALIASES["action"]))
    keys: list[str] = []
    if provider and product and record_id:
        keys.append(normalize_key(f"cloud-record:{provider}:{product}:{record_id}"))
    if provider and product and item_id:
        keys.append(normalize_key(f"cloud-item:{provider}:{product}:{item_id}"))
    if provider and timestamp and actor and action:
        keys.append(normalize_key(f"cloud-context:{provider}:{timestamp}:{actor}:{action}"))
    return list(dict.fromkeys(keys))


def cloud_api_key_variants(row: Mapping[str, object]) -> list[str]:
    request_id = normalize_mobile_identifier(first_value(row, CLOUD_API_FIELD_ALIASES["request_id"]))
    provider = normalize_mobile_identifier(first_value(row, CLOUD_API_FIELD_ALIASES["provider"]))
    endpoint = normalize_field_value(first_value(row, CLOUD_API_FIELD_ALIASES["endpoint"]) or "")
    response_hash = normalize_hash_value(first_value(row, CLOUD_API_FIELD_ALIASES["response_hash"]))
    keys: list[str] = []
    if request_id:
        keys.append(normalize_key(f"cloud-api-request:{request_id}"))
    if provider and endpoint and response_hash:
        keys.append(normalize_key(f"cloud-api-response:{provider}:{endpoint}:{response_hash}"))
    return list(dict.fromkeys(keys))


def ai_transcript_key_variants(row: Mapping[str, object]) -> list[str]:
    service = normalize_mobile_identifier(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["ai_service"]))
    conversation_id = normalize_mobile_identifier(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["conversation_id"]))
    pair_id = normalize_mobile_identifier(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["pair_id"]))
    timestamp = normalize_field_value(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["timestamp"]) or "")
    question = normalize_field_value(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["question"]) or "")
    answer = normalize_field_value(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["answer"]) or "")
    source_hashes = normalize_ntfs_list(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["source_sha256s"]))
    keys: list[str] = []
    if service and conversation_id and pair_id:
        keys.append(normalize_key(f"ai-transcript-pair:{service}:{conversation_id}:{pair_id}"))
    if service and pair_id:
        keys.append(normalize_key(f"ai-transcript-pair:{service}:{pair_id}"))
    if service and timestamp and question and answer:
        keys.append(normalize_key(f"ai-transcript-text:{service}:{timestamp}:{question[:160]}:{answer[:160]}"))
    if service and source_hashes and question and answer:
        keys.append(normalize_key(f"ai-transcript-source:{service}:{source_hashes}:{question[:160]}:{answer[:160]}"))
    return list(dict.fromkeys(keys))


def chat_app_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    return normalized_fields_by_alias(
        row,
        CHAT_APP_FIELD_ALIASES,
        actor_fields={"sender", "recipient"},
        hash_fields={"message_text_hash", "media_hash"},
        path_fields={"media_path"},
    )


def email_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    return normalized_fields_by_alias(
        row,
        EMAIL_FIELD_ALIASES,
        actor_fields={"sender", "recipient", "cc"},
        hash_fields={"attachment_hash", "body_hash"},
        path_fields={"source_path"},
        int_fields={"attachment_count"},
        email_message_id_fields={"message_id"},
    )


def cloud_export_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    return normalized_fields_by_alias(
        row,
        CLOUD_EXPORT_FIELD_ALIASES,
        actor_fields={"actor", "target"},
        hash_fields={"hash"},
        int_fields={"size"},
    )


def cloud_api_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    return normalized_fields_by_alias(
        row,
        CLOUD_API_FIELD_ALIASES,
        hash_fields={"response_hash"},
        int_fields={"status_code", "item_count"},
    )


def ai_transcript_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields = normalized_fields_by_alias(
        row,
        AI_TRANSCRIPT_FIELD_ALIASES,
        path_fields={"source_path", "question_source_path", "answer_source_path"},
        int_fields={"question_source_offset", "answer_source_offset"},
    )
    source_hashes = normalize_ntfs_list(first_value(row, AI_TRANSCRIPT_FIELD_ALIASES["source_sha256s"]))
    if source_hashes:
        fields["source_sha256s"] = source_hashes
    return fields


def normalized_fields_by_alias(
    row: Mapping[str, object],
    aliases_by_field: Mapping[str, Sequence[str]],
    *,
    actor_fields: set[str] | None = None,
    hash_fields: set[str] | None = None,
    path_fields: set[str] | None = None,
    int_fields: set[str] | None = None,
    email_message_id_fields: set[str] | None = None,
) -> dict[str, str]:
    actor_fields = actor_fields or set()
    hash_fields = hash_fields or set()
    path_fields = path_fields or set()
    int_fields = int_fields or set()
    email_message_id_fields = email_message_id_fields or set()
    fields: dict[str, str] = {}
    for canonical, aliases in aliases_by_field.items():
        if canonical in actor_fields:
            value = normalize_mobile_actor(first_value(row, aliases))
        elif canonical in hash_fields:
            value = normalize_hash_value(first_value(row, aliases))
        elif canonical in path_fields:
            value = ntfs_path_value(row, aliases)
        elif canonical in int_fields:
            value = ntfs_int_value(row, aliases)
        elif canonical in email_message_id_fields:
            value = normalize_email_message_id(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def compare_chat_app_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="chat_app_field_index",
        mode="messenger-chat-app-field-diff",
        key_name="chat_app_key",
        row_limit=MAX_MESSAGING_FIELD_DIFF_ROWS,
    )


def compare_email_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="email_field_index",
        mode="email-mailbox-field-diff",
        key_name="email_key",
        row_limit=MAX_MESSAGING_FIELD_DIFF_ROWS,
    )


def compare_cloud_export_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="cloud_export_field_index",
        mode="cloud-provider-export-field-diff",
        key_name="cloud_export_key",
        row_limit=MAX_MESSAGING_FIELD_DIFF_ROWS,
    )


def compare_cloud_api_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="cloud_api_field_index",
        mode="cloud-api-response-field-diff",
        key_name="cloud_api_key",
        row_limit=MAX_MESSAGING_FIELD_DIFF_ROWS,
    )


def compare_ai_transcript_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="ai_transcript_field_index",
        mode="ai-service-transcript-qa-field-diff",
        key_name="ai_transcript_key",
        row_limit=MAX_MESSAGING_FIELD_DIFF_ROWS,
    )


def normalize_mobile_identifier(value: object) -> str:
    if value is None:
        return ""
    text = normalize_field_value(value)
    return re.sub(r"\s+", " ", text).strip()


def normalize_mobile_phone(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.startswith("+"):
        return "+" + re.sub(r"\D+", "", text[1:])
    return re.sub(r"\D+", "", text)


def normalize_mobile_actor(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    digits = re.sub(r"\D+", "", text)
    if text.startswith("+") or len(digits) >= 7:
        return normalize_mobile_phone(text)
    return normalize_mobile_identifier(text)


def normalize_email_message_id(value: object) -> str:
    return normalize_mobile_identifier(value).strip("<>")


def normalize_sid(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    return re.sub(r"[^a-z0-9-]+", "", text.lower())


def normalize_windows_identity(value: object) -> str:
    if value is None:
        return ""
    text = normalize_field_value(value)
    return re.sub(r"\s+", " ", text).strip()


def normalize_guidish(value: object) -> str:
    if value is None:
        return ""
    text = normalize_field_value(value)
    return re.sub(r"[^a-f0-9-]+", "", text)


def normalize_boolish(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalize_field_value(value)
    if text in {"1", "true", "yes", "y", "admin", "administrator", "enabled"}:
        return "true"
    if text in {"0", "false", "no", "n", "standard", "disabled"}:
        return "false"
    return text


def mft_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_NTFS_FIELD_DIFF_ROWS]:
        keys = mft_key_variants(row)
        if not keys:
            continue
        fields = mft_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def usn_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_NTFS_FIELD_DIFF_ROWS]:
        keys = usn_key_variants(row)
        if not keys:
            continue
        fields = usn_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def usn_state_replay_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_USN_STATE_REPLAY_FIELD_DIFF_ROWS]:
        keys = usn_state_replay_key_variants(row)
        if not keys:
            continue
        fields = usn_state_replay_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def mft_key_variants(row: Mapping[str, object]) -> list[str]:
    record_number = ntfs_int_value(row, MFT_FIELD_ALIASES["record_number"])
    file_path = ntfs_path_value(row, MFT_FIELD_ALIASES["file_path"])
    record_offset = ntfs_int_value(row, MFT_FIELD_ALIASES["record_offset"])
    if not record_number and not record_offset:
        return []
    keys: list[str] = []
    if record_number and file_path:
        keys.append(normalize_key(f"mft-record:{record_number}:{file_path}"))
    if record_number:
        keys.append(normalize_key(f"mft-record:{record_number}"))
    if record_offset:
        keys.append(normalize_key(f"mft-offset:{record_offset}"))
    return list(dict.fromkeys(keys))


def usn_key_variants(row: Mapping[str, object]) -> list[str]:
    usn = ntfs_int_value(row, USN_FIELD_ALIASES["usn"])
    frn = ntfs_int_value(row, USN_FIELD_ALIASES["file_reference_number"])
    file_name = normalize_ntfs_file_name(first_value(row, USN_FIELD_ALIASES["file_name"]))
    record_cursor = ntfs_int_value(row, USN_FIELD_ALIASES["record_cursor"])
    if not usn and not record_cursor:
        return []
    keys: list[str] = []
    if usn and frn and file_name:
        keys.append(normalize_key(f"usn-record:{usn}:{frn}:{file_name}"))
    if usn and frn:
        keys.append(normalize_key(f"usn-record:{usn}:{frn}"))
    if usn:
        keys.append(normalize_key(f"usn-record:{usn}"))
    if record_cursor and frn:
        keys.append(normalize_key(f"usn-cursor:{record_cursor}:{frn}"))
    return list(dict.fromkeys(keys))


def usn_state_replay_key_variants(row: Mapping[str, object]) -> list[str]:
    transition = normalize_field_value(first_value(row, USN_STATE_REPLAY_FIELD_ALIASES["transition"]) or "")
    usn = ntfs_int_value(row, USN_STATE_REPLAY_FIELD_ALIASES["usn"])
    frn = ntfs_int_value(row, USN_STATE_REPLAY_FIELD_ALIASES["file_reference_number"])
    record_cursor = ntfs_int_value(row, USN_STATE_REPLAY_FIELD_ALIASES["record_cursor"])
    if not transition or (not usn and not record_cursor):
        return []
    keys: list[str] = []
    if usn and frn:
        keys.append(normalize_key(f"usn-state:{usn}:{frn}"))
    if record_cursor and frn:
        keys.append(normalize_key(f"usn-state-cursor:{record_cursor}:{frn}"))
    if usn:
        keys.append(normalize_key(f"usn-state:{usn}"))
    if record_cursor:
        keys.append(normalize_key(f"usn-state-cursor:{record_cursor}"))
    return list(dict.fromkeys(keys))


def mft_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in MFT_FIELD_ALIASES.items():
        if canonical in {"record_number", "sequence_number", "parent_reference", "record_offset"}:
            value = ntfs_int_value(row, aliases)
        elif canonical == "file_path":
            value = ntfs_path_value(row, aliases)
        elif canonical == "deleted":
            value = normalize_ntfs_deleted(first_value(row, aliases))
        elif canonical == "attribute_types":
            value = normalize_ntfs_list(first_value(row, aliases))
        elif canonical == "resident_data_sha256":
            value = normalize_hash_value(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def usn_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in USN_FIELD_ALIASES.items():
        if canonical in {"usn", "file_reference_number", "parent_reference", "major_version", "record_cursor", "v4_extent_count"}:
            value = ntfs_int_value(row, aliases)
        elif canonical == "file_name":
            value = normalize_ntfs_file_name(first_value(row, aliases))
        elif canonical in {"reason", "source_info", "file_attributes"}:
            value = normalize_ntfs_list(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def usn_state_replay_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for canonical, aliases in USN_STATE_REPLAY_FIELD_ALIASES.items():
        if canonical in {"usn", "file_reference_number", "record_cursor"}:
            value = ntfs_int_value(row, aliases)
        elif canonical in {"previous_path", "new_path"}:
            value = ntfs_path_value(row, aliases)
        elif canonical == "file_name":
            value = normalize_ntfs_file_name(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def ese_field_index(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for row in rows[:MAX_ESE_FIELD_DIFF_ROWS]:
        keys = ese_key_variants(row)
        if not keys:
            continue
        fields = ese_normalized_fields(row)
        if fields:
            for key in keys:
                index.setdefault(key, fields)
    return index


def ese_key_variants(row: Mapping[str, object]) -> list[str]:
    family = infer_ese_family(row)
    if not family:
        return []
    table_name = normalize_ese_identifier(first_value(row, ESE_FIELD_ALIASES["table_name"]))
    row_id = ntfs_int_value(row, ESE_FIELD_ALIASES["row_id"])
    page_number = ntfs_int_value(row, ESE_FIELD_ALIASES["page_number"])
    source_offset = ntfs_int_value(row, ESE_FIELD_ALIASES["source_offset"])
    item_path = normalize_ntfs_path(str(first_value(row, ESE_FIELD_ALIASES["item_path"]) or ""))
    keys: list[str] = []
    if table_name and row_id:
        keys.append(normalize_key(f"ese-row:{family}:{table_name}:{row_id}"))
    if table_name and item_path:
        keys.append(normalize_key(f"ese-item:{family}:{table_name}:{item_path}"))
    if page_number and source_offset:
        keys.append(normalize_key(f"ese-page:{family}:{page_number}:{source_offset}"))
    if page_number and item_path:
        keys.append(normalize_key(f"ese-page-item:{family}:{page_number}:{item_path}"))
    return list(dict.fromkeys(keys))


def ese_normalized_fields(row: Mapping[str, object]) -> dict[str, str]:
    family = infer_ese_family(row)
    if not family:
        return {}
    fields: dict[str, str] = {"ese_family": family}
    for canonical, aliases in ESE_FIELD_ALIASES.items():
        if canonical == "ese_family":
            value = family
        elif canonical in {"row_id", "page_number", "source_offset", "bytes_sent", "bytes_received"}:
            value = ntfs_int_value(row, aliases)
        elif canonical == "table_name":
            value = normalize_ese_identifier(first_value(row, aliases))
        elif canonical == "item_path":
            value = normalize_ntfs_path(str(first_value(row, aliases) or ""))
        elif canonical == "deleted_state":
            value = normalize_ntfs_deleted(first_value(row, aliases))
        elif canonical == "content_hash":
            value = normalize_hash_value(first_value(row, aliases))
        else:
            raw = first_value(row, aliases)
            value = normalize_field_value(raw) if raw is not None and str(raw).strip() else ""
        if value:
            fields[canonical] = value
    return fields


def infer_ese_family(row: Mapping[str, object]) -> str:
    explicit = first_value(row, ESE_FIELD_ALIASES["ese_family"])
    explicit_text = normalize_field_value(explicit) if explicit is not None else ""
    haystack = " ".join(
        str(value)
        for key, value in row.items()
        if key.lower().endswith(
            (
                "artifact_type",
                "parser",
                "source_path",
                "path",
                "source_format",
                "table_name",
                "tablename",
            )
        )
    ).lower()
    combined = f"{explicit_text} {haystack}"
    if any(marker in combined for marker in ("srum", "srudb", "sru/")):
        return "srum"
    if any(marker in combined for marker in ("windows.edb", "windows-search", "windows search", "systemindex")):
        return "windows-edb"
    if explicit_text in {"srum", "windows-edb", "windows-search"}:
        return "windows-edb" if explicit_text == "windows-search" else explicit_text
    return ""


def normalize_ese_identifier(value: object) -> str:
    if value is None:
        return ""
    text = normalize_field_value(value)
    return re.sub(r"[^a-z0-9_.:-]+", "-", text).strip("-")


def ntfs_int_value(row: Mapping[str, object], aliases: Iterable[str]) -> str:
    raw = first_value(row, aliases)
    if raw is None:
        return ""
    return normalize_registry_numeric_string(str(raw))


def ntfs_path_value(row: Mapping[str, object], aliases: Iterable[str]) -> str:
    raw = first_value(row, aliases)
    if raw is None:
        return ""
    return normalize_ntfs_path(str(raw))


def normalize_ntfs_path(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    text = re.sub(r"/+", "/", text).rstrip("/")
    return text.lower()


def normalize_ntfs_file_name(value: object) -> str:
    if value is None:
        return ""
    text = normalize_ntfs_path(str(value))
    if "/" in text:
        return text.rsplit("/", 1)[-1]
    return text


def normalize_ntfs_deleted(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalize_field_value(value)
    if text in {"1", "true", "yes", "y", "deleted"}:
        return "true"
    if text in {"0", "false", "no", "n", "active", "allocated", "inuse", "in use"}:
        return "false"
    return text


def normalize_ntfs_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalize_field_value(part) for part in parts if part}))


def normalize_hash_value(value: object) -> str:
    if value in (None, ""):
        return ""
    return str(value).strip().lower()


def compare_mft_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="mft_field_index",
        mode="mft-record-field-diff",
        key_name="mft_key",
        row_limit=MAX_NTFS_FIELD_DIFF_ROWS,
    )


def compare_usn_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="usn_field_index",
        mode="usn-journal-field-diff",
        key_name="usn_key",
        row_limit=MAX_NTFS_FIELD_DIFF_ROWS,
    )


def compare_usn_state_replay_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="usn_state_replay_field_index",
        mode="usn-state-replay-field-diff",
        key_name="usn_state_replay_key",
        row_limit=MAX_USN_STATE_REPLAY_FIELD_DIFF_ROWS,
    )


def compare_ese_fields(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
) -> dict[str, object]:
    return compare_ntfs_field_indexes(
        rapid_dataset,
        reference_dataset,
        index_key="ese_field_index",
        mode="ese-srum-windows-edb-field-diff",
        key_name="ese_key",
        row_limit=MAX_ESE_FIELD_DIFF_ROWS,
    )


def compare_ntfs_field_indexes(
    rapid_dataset: Mapping[str, object],
    reference_dataset: Mapping[str, object],
    *,
    index_key: str,
    mode: str,
    key_name: str,
    row_limit: int,
) -> dict[str, object]:
    rapid_index = rapid_dataset.get(index_key) if isinstance(rapid_dataset.get(index_key), Mapping) else {}
    reference_index = reference_dataset.get(index_key) if isinstance(reference_dataset.get(index_key), Mapping) else {}
    common_key_variants = sorted(set(rapid_index) & set(reference_index))
    common_keys: list[str] = []
    seen_identity: set[str] = set()
    for key in common_key_variants:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        identity = str(
            rapid_fields.get("record_number")
            or reference_fields.get("record_number")
            or rapid_fields.get("usn")
            or reference_fields.get("usn")
            or rapid_fields.get("record_cursor")
            or reference_fields.get("record_cursor")
            or rapid_fields.get("row_id")
            or reference_fields.get("row_id")
            or rapid_fields.get("source_offset")
            or reference_fields.get("source_offset")
            or key
        )
        if identity in seen_identity:
            continue
        seen_identity.add(identity)
        common_keys.append(key)
    compared_field_count = 0
    mismatch_count = 0
    missing_common_field_count = 0
    mismatch_samples: list[dict[str, object]] = []
    for key in common_keys[:row_limit]:
        rapid_fields = rapid_index.get(key) if isinstance(rapid_index.get(key), Mapping) else {}
        reference_fields = reference_index.get(key) if isinstance(reference_index.get(key), Mapping) else {}
        field_names = sorted(set(rapid_fields) | set(reference_fields))
        for field_name in field_names:
            rapid_value = str(rapid_fields.get(field_name) or "")
            reference_value = str(reference_fields.get(field_name) or "")
            if not rapid_value or not reference_value:
                missing_common_field_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            key_name: key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "missing-field",
                        }
                    )
                continue
            compared_field_count += 1
            if rapid_value != reference_value:
                mismatch_count += 1
                if len(mismatch_samples) < MAX_FIELD_MISMATCH_SAMPLES:
                    mismatch_samples.append(
                        {
                            key_name: key,
                            "field": field_name,
                            "rapid_value": rapid_value,
                            "reference_value": reference_value,
                            "status": "mismatch",
                        }
                    )
    match_count = max(compared_field_count - mismatch_count, 0)
    field_match_ratio = round(match_count / compared_field_count, 4) if compared_field_count else 0.0
    compared_fields = sorted(
        {
            field
            for key in common_keys[:row_limit]
            for row in (rapid_index.get(key), reference_index.get(key))
            if isinstance(row, Mapping)
            for field in row
        }
    )[:500]
    return {
        "mode": mode,
        "rapid_indexed_count": len(rapid_index),
        "reference_indexed_count": len(reference_index),
        "common_record_count": len(common_keys),
        "common_key_variant_count": len(common_key_variants),
        "compared_field_count": compared_field_count,
        "field_match_count": match_count,
        "mismatch_count": mismatch_count,
        "missing_common_field_count": missing_common_field_count,
        "field_match_ratio": field_match_ratio,
        "compared_canonical_fields": compared_fields,
        "mismatch_samples": mismatch_samples,
        "truncated": len(common_keys) > row_limit,
    }


def build_operator_guidance(comparisons: list[Mapping[str, object]]) -> list[str]:
    if any(comparison_has_input_quality_blockers(item) for item in comparisons):
        return [
            "Fix cross-tool input quality before trusting this validation: duplicate keys or row-cap truncation can hide parser loss.",
            "Re-export the affected RapidTriage/reference rows with stable unique identifiers and split files or raise the validation cap for large corpora.",
            "Do not use a comparison with input-quality blockers for report-grade or commercial-grade claims.",
        ]
    if all(item.get("status") == "pass" for item in comparisons):
        return ["Cross-tool row/key overlap met the configured threshold."]
    return [
        "Review missing_in_rapid samples before treating parser output as report-grade.",
        "Low overlap can indicate parser loss, schema mismatch, wrong evidence root, or incompatible external-tool export settings.",
        "Attach this report with parser version, external tool version, and source evidence hash when validating high-value artifacts.",
    ]


def comparison_has_input_quality_blockers(comparison: Mapping[str, object]) -> bool:
    input_quality = comparison.get("input_quality") if isinstance(comparison.get("input_quality"), Mapping) else {}
    blockers = input_quality.get("blockers")
    return isinstance(blockers, list) and bool(blockers)


def build_validation_datasets(
    *,
    status: str,
    backlog_items: list[int],
    comparisons: list[Mapping[str, object]],
    output: Path | None,
    rapid_output: Path,
    reference_outputs: Mapping[str, Path],
    source_evidence: Iterable[Path],
    independent_reports: Iterable[Path],
    corpus_scope: str,
) -> list[dict[str, object]]:
    evidence_paths = [str(output.expanduser().resolve())] if output is not None else [
        str(rapid_output.expanduser().resolve()),
        *[str(path.expanduser().resolve()) for path in reference_outputs.values()],
        *[str(path.expanduser().resolve()) for path in source_evidence],
        *[str(path.expanduser().resolve()) for path in independent_reports],
    ]
    reference_names = [str(item.get("reference_name") or "") for item in comparisons]
    return [
        {
            "id": f"cross-tool-items-{'-'.join(str(item) for item in backlog_items)}",
            "name": "Cross-tool validation for RapidTriage core forensic parser claims",
            "source": ", ".join(name for name in reference_names if name),
            "corpus_family": "core-forensics-cross-tool",
            "status": "pass" if status == "pass" else "fail",
            "backlog_items": backlog_items,
            "evidence_paths": evidence_paths,
            "evidence_paths_present": True,
            "expected": {
                "backlog_items": backlog_items,
                "required_assertions": [
                    "RapidTriage output and trusted reference output share record/cell keys above the configured overlap threshold.",
                    "Missing reference keys are bounded in missing_in_rapid_sample for reviewer triage.",
                    "Reference tool names, row counts, key counts, and overlap ratio are preserved.",
                    "Cross-tool report preserves source/reference output hashes plus operator-provided tool version/command metadata when supplied.",
                    "Independent review report hash and corpus scope are preserved when supplied.",
                ],
                "reference_tools": reference_names,
                "corpus_scope": corpus_scope.strip(),
                "minimum_overlap": min(
                    [float(item.get("overlap_ratio") or 0.0) for item in comparisons] or [0.0]
                ),
            },
            "notes": "Cross-tool validation evidence. Passing overlap can satisfy the validated gate, but commercial-grade still requires corpus scope review and independent sign-off.",
        }
    ]


def cross_tool_validation_assessment(
    *,
    status: str,
    comparisons: list[Mapping[str, object]],
    backlog_items: list[int],
    output: Path | None,
    min_overlap: float,
    source_evidence_integrity: list[dict[str, object]],
    independent_review_integrity: list[dict[str, object]],
    corpus_scope: str,
    tool_metadata: Mapping[str, object],
) -> dict[str, object]:
    tool_rows = tool_metadata.get("tools") if isinstance(tool_metadata.get("tools"), list) else []
    external_tool_rows = [
        item for item in tool_rows
        if isinstance(item, Mapping) and item.get("name") and item.get("name") != "rapidtriage"
    ]
    tools_with_version = sum(1 for item in external_tool_rows if item.get("version"))
    tools_with_command = sum(1 for item in external_tool_rows if item.get("command"))
    source_hashes_attached = bool(source_evidence_integrity)
    independent_review_attached = bool(independent_review_integrity)
    corpus_scope_attached = bool(corpus_scope.strip())
    versions_attached = bool(external_tool_rows) and tools_with_version == len(external_tool_rows)
    commands_attached = bool(external_tool_rows) and tools_with_command == len(external_tool_rows)
    blockers: list[str] = []
    if not source_hashes_attached or not corpus_scope_attached:
        blockers.append("corpus-scope-and-source-hash-review-required")
    if not versions_attached or not commands_attached:
        blockers.append("external-tool-version-and-command-capture-required")
    if not independent_review_attached:
        blockers.append("independent-reviewer-signoff-required")
    if status != "pass":
        blockers.append("trusted-tool-diff-pass-required")
    if any(comparison_has_input_quality_blockers(item) for item in comparisons):
        blockers.append("trusted-tool-input-quality-clean-required")
    ready_for_commercial_grade = (
        bool(backlog_items)
        and status == "pass"
        and output is not None
        and source_hashes_attached
        and corpus_scope_attached
        and versions_attached
        and commands_attached
        and independent_review_attached
    )
    manifest = build_trusted_tool_diff_manifest(
        status=status,
        comparisons=comparisons,
        backlog_items=backlog_items,
        output=output,
        min_overlap=min_overlap,
        source_evidence_integrity=source_evidence_integrity,
        independent_review_integrity=independent_review_integrity,
        corpus_scope=corpus_scope,
        tool_metadata=tool_metadata,
        ready_for_commercial_grade=ready_for_commercial_grade,
        blockers=blockers,
    )
    return {
        "status": status,
        "backlog_items": backlog_items,
        "comparison_count": len(comparisons),
        "output": str(output.expanduser().resolve()) if output is not None else "",
        "ready_for_validated_gate": bool(backlog_items) and status == "pass" and output is not None,
        "ready_for_commercial_grade": ready_for_commercial_grade,
        "source_evidence_count": len(source_evidence_integrity),
        "independent_review_count": len(independent_review_integrity),
        "tools_with_version_count": tools_with_version,
        "tools_with_command_count": tools_with_command,
        "commercial_grade_readiness_checks": {
            "source_evidence_hashes_attached": source_hashes_attached,
            "corpus_scope_attached": corpus_scope_attached,
            "external_tool_versions_attached": versions_attached,
            "external_tool_commands_attached": commands_attached,
            "independent_reviewer_signoff_attached": independent_review_attached,
        },
        "functional_priority_profile": trusted_tool_diff_functional_profile(
            status=status,
            comparisons=comparisons,
            backlog_items=backlog_items,
            manifest=manifest,
            source_evidence_count=len(source_evidence_integrity),
            independent_review_count=len(independent_review_integrity),
            versions_attached=versions_attached,
            commands_attached=commands_attached,
            corpus_scope_attached=corpus_scope_attached,
            output_attached=output is not None,
        ),
        "trusted_tool_diff_manifest": manifest,
        "trusted_tool_diff_manifest_hash": manifest["manifest_hash"],
        "commercial_grade_blockers": blockers,
    }


def build_trusted_tool_diff_manifest(
    *,
    status: str,
    comparisons: list[Mapping[str, object]],
    backlog_items: list[int],
    output: Path | None,
    min_overlap: float,
    source_evidence_integrity: list[dict[str, object]],
    independent_review_integrity: list[dict[str, object]],
    corpus_scope: str,
    tool_metadata: Mapping[str, object],
    ready_for_commercial_grade: bool,
    blockers: list[str],
) -> dict[str, object]:
    tool_rows = tool_metadata.get("tools") if isinstance(tool_metadata.get("tools"), list) else []
    external_tool_rows = [
        item for item in tool_rows
        if isinstance(item, Mapping) and item.get("name") and item.get("name") != "rapidtriage"
    ]
    comparison_summaries: list[dict[str, object]] = []
    for comparison in comparisons:
        field_blocks = {}
        for field_name in (
            "record_field_comparison",
            "registry_field_comparison",
            "mft_field_comparison",
            "usn_field_comparison",
            "usn_state_replay_field_comparison",
            "ese_field_comparison",
            "os_account_field_comparison",
            "execution_artifact_field_comparison",
            "user_activity_field_comparison",
            "system_artifact_field_comparison",
            "browser_storage_field_comparison",
            "browser_timeline_field_comparison",
            "ai_transcript_field_comparison",
            "mobile_export_field_comparison",
            "mobile_app_field_comparison",
            "chat_app_field_comparison",
            "email_field_comparison",
            "cloud_export_field_comparison",
            "cloud_api_field_comparison",
        ):
            field_comparison = comparison.get(field_name)
            if not isinstance(field_comparison, Mapping):
                continue
            field_blocks[field_name] = {
                "mode": str(field_comparison.get("mode") or ""),
                "mismatch_count": int(field_comparison.get("mismatch_count") or 0),
                "missing_common_field_count": int(field_comparison.get("missing_common_field_count") or 0),
                "field_match_ratio": float(field_comparison.get("field_match_ratio") or 0.0),
                "truncated": bool(field_comparison.get("truncated")),
            }
        comparison_summaries.append(
            {
                "reference_name": str(comparison.get("reference_name") or ""),
                "status": str(comparison.get("status") or ""),
                "rapid_row_count": int(comparison.get("rapid_row_count") or 0),
                "reference_row_count": int(comparison.get("reference_row_count") or 0),
                "overlap_ratio": float(comparison.get("overlap_ratio") or 0.0),
                "overlap_count": int(comparison.get("overlap_count") or 0),
                "input_quality": comparison.get("input_quality") if isinstance(comparison.get("input_quality"), Mapping) else {},
                "field_diffs": field_blocks,
            }
        )
    manifest_core: dict[str, object] = {
        "profile_version": "trusted-tool-diff-manifest-v1",
        "item_number": 37,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "gap_id": "#37",
        "commercial_gap_ids": ["#81", "#84", "#85", "#95"],
        "status": status,
        "mapped_backlog_items": backlog_items,
        "comparison_count": len(comparisons),
        "configured_min_overlap": float(min_overlap),
        "minimum_observed_overlap": min(
            [float(item.get("overlap_ratio") or 0.0) for item in comparisons] or [0.0]
        ),
        "comparison_summaries": comparison_summaries,
        "output_written": output is not None,
        "output_path": str(output.expanduser().resolve()) if output is not None else "",
        "tool_output_hash_count": sum(
            1 for item in tool_rows
            if isinstance(item, Mapping) and str(item.get("output_sha256") or "")
        ),
        "external_reference_count": len(external_tool_rows),
        "external_reference_hash_count": sum(
            1 for item in external_tool_rows
            if isinstance(item, Mapping) and str(item.get("output_sha256") or "")
        ),
        "source_evidence_hash_count": len(source_evidence_integrity),
        "independent_review_hash_count": len(independent_review_integrity),
        "external_tool_versions_attached": bool(external_tool_rows)
        and all(bool(item.get("version")) for item in external_tool_rows if isinstance(item, Mapping)),
        "external_tool_commands_attached": bool(external_tool_rows)
        and all(bool(item.get("command")) for item in external_tool_rows if isinstance(item, Mapping)),
        "corpus_scope_attached": bool(corpus_scope.strip()),
        "corpus_scope_hash": hashlib.sha256(corpus_scope.strip().encode("utf-8", errors="replace")).hexdigest()
        if corpus_scope.strip()
        else "",
        "ready_for_commercial_grade": ready_for_commercial_grade,
        "commercial_grade_blockers": list(blockers),
        "required_external_evidence": [
            "trusted parser/export output for every parser family claimed report-grade",
            "source evidence hashes for each compared artifact family",
            "external tool version and command transcript",
            "independent reviewer signoff hash",
        ],
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def trusted_tool_diff_functional_profile(
    *,
    status: str,
    comparisons: list[Mapping[str, object]],
    backlog_items: list[int],
    manifest: Mapping[str, object],
    source_evidence_count: int,
    independent_review_count: int,
    versions_attached: bool,
    commands_attached: bool,
    corpus_scope_attached: bool,
    output_attached: bool,
) -> dict[str, object]:
    failed_checks: list[str] = []
    if not backlog_items:
        failed_checks.append("no-backlog-items-mapped")
    if status != "pass":
        failed_checks.append("trusted-tool-diff-not-passing")
    if not output_attached:
        failed_checks.append("trusted-tool-diff-output-not-written")
    if source_evidence_count == 0:
        failed_checks.append("source-evidence-hash-not-attached")
    if not corpus_scope_attached:
        failed_checks.append("corpus-scope-not-attached")
    if not versions_attached:
        failed_checks.append("external-tool-version-not-attached")
    if not commands_attached:
        failed_checks.append("external-tool-command-not-attached")
    if independent_review_count == 0:
        failed_checks.append("independent-review-not-attached")
    if any(comparison_has_input_quality_blockers(item) for item in comparisons):
        failed_checks.append("trusted-tool-input-quality-clean-required")
    overlap_ratios = [float(item.get("overlap_ratio") or 0.0) for item in comparisons]
    return {
        "item_number": 37,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "comparison_count": len(comparisons),
            "mapped_backlog_items": backlog_items,
            "minimum_overlap_ratio": min(overlap_ratios) if overlap_ratios else 0.0,
            "trusted_tool_diff_manifest_hash": str(manifest.get("manifest_hash") or ""),
            "trusted_tool_diff_manifest_profile": str(manifest.get("profile_version") or ""),
            "source_evidence_count": source_evidence_count,
            "independent_review_count": independent_review_count,
            "external_tool_versions_attached": versions_attached,
            "external_tool_commands_attached": commands_attached,
            "corpus_scope_attached": corpus_scope_attached,
            "output_written": output_attached,
        },
        "passed_validation_check_ids": [
            "rapid-output-hash-captured",
            "reference-output-hash-captured",
            "record-key-overlap-computed",
            "record-field-diff-computed-when-schema-supported",
            "evtx-record-id-and-channel-key-variants-supported",
            "evtx-rendered-message-field-diff-supported",
            "evtx-event-data-field-diff-supported",
            "registry-key-value-field-diff-supported",
            "registry-deleted-cell-offset-field-diff-supported",
            "registry-transaction-replay-status-diff-supported",
            "os-account-sam-security-system-field-diff-supported",
            "execution-artifact-amcache-shimcache-bam-dam-field-diff-supported",
            "user-activity-jumplist-shellbags-prefetch-lnk-field-diff-supported",
            "mft-record-field-diff-supported",
            "mft-parent-path-attribute-diff-supported",
            "usn-frn-reason-timestamp-field-diff-supported",
            "usn-state-replay-transition-field-diff-supported",
            "ese-srum-row-field-diff-supported",
            "ese-windows-edb-row-field-diff-supported",
            "ese-page-offset-deleted-state-diff-supported",
            "trusted-tool-input-quality-gate-supported",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "trusted-tool-parser-diff-evidence",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Cross-tool agreement is validation evidence, not proof of exhaustive parser correctness.",
        },
    }


def build_tool_metadata(
    *,
    rapid_dataset: Mapping[str, object],
    reference_datasets: list[Mapping[str, object]],
    tool_versions: Mapping[str, str],
    tool_commands: Mapping[str, str],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for dataset in [rapid_dataset, *reference_datasets]:
        name = str(dataset.get("name") or "")
        rows.append(
            {
                "name": name,
                "output_path": str(dataset.get("path") or ""),
                "output_sha256": (
                    dataset.get("file_integrity", {}).get("sha256")
                    if isinstance(dataset.get("file_integrity"), Mapping)
                    else ""
                ),
                "version": str(tool_versions.get(name) or ""),
                "command": str(tool_commands.get(name) or ""),
                "version_required_for_commercial_grade": name != "rapidtriage" and not tool_versions.get(name),
                "command_required_for_commercial_grade": name != "rapidtriage" and not tool_commands.get(name),
            }
        )
    return {
        "tools": rows,
        "version_count": sum(1 for item in rows if item.get("version")),
        "command_count": sum(1 for item in rows if item.get("command")),
        "commercial_grade_note": "Capture external tool version and command lines before relying on cross-tool output as commercial-grade evidence.",
    }


def file_integrity(path: Path) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    if resolved.is_dir():
        # Directory sources (e.g. staged evidence trees) get a deterministic
        # digest over their sorted file entries instead of failing to open.
        hasher = hashlib.sha256()
        size = 0
        for entry in sorted(resolved.rglob("*")):
            if not entry.is_file():
                continue
            entry_hash = hashlib.sha256(entry.read_bytes()).hexdigest()
            hasher.update(f"{entry.relative_to(resolved).as_posix()}|{entry.stat().st_size}|{entry_hash}\n".encode("utf-8"))
            size += entry.stat().st_size
        return {
            "path": str(resolved),
            "type": "directory",
            "size_bytes": size,
            "sha256": hasher.hexdigest(),
            "mtime_epoch": resolved.stat().st_mtime,
        }
    stat = resolved.stat()
    hasher = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return {
        "path": str(resolved),
        "size_bytes": stat.st_size,
        "sha256": hasher.hexdigest(),
        "mtime_epoch": stat.st_mtime,
    }


def file_sha256(path: Path) -> str:
    return str(file_integrity(path)["sha256"])


def infer_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    return ""


def value_for_key(row: Mapping[str, object], wanted: str) -> object | None:
    wanted_lower = wanted.lower()
    for key, value in row.items():
        if key.lower() == wanted_lower or key.lower().endswith(f".{wanted_lower}"):
            return value
    return None


def normalize_key(value: object) -> str:
    return str(value).strip().replace("\\", "/").lower()


def normalize_field_value(value: object) -> str:
    text = str(value).strip()
    if text.endswith(".0") and text[:-2].isdigit():
        text = text[:-2]
    return text.replace("\\", "/").lower()
