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
    "entry_id": ("entry_id", "EntryId", "EntryID", "DestListEntryNumber", "destlist_entry_number", "MRU"),
    "target_path": (
        "target_path",
        "TargetPath",
        "TargetFilename",
        "target_filename",
        "Path",
        "path",
        "file_path",
        "FilePath",
    ),
    "file_name": ("file_name", "FileName", "filename", "Name", "name"),
    "timestamp": ("timestamp", "Timestamp", "LastAccessTime", "LastModified", "Created", "Accessed"),
    "source_path": ("source_path", "SourcePath", "source_file", "SourceFile"),
    "source_offset": ("source_offset", "SourceOffset", "Offset", "offset"),
    "mru_order": ("mru_order", "MRUOrder", "mru", "Slot", "slot"),
    "access_count": ("access_count", "AccessCount", "access_count", "OpenCount", "open_count"),
    "volume_name": ("volume_name", "VolumeName", "volume", "Volume"),
    "bag_path": ("bag_path", "BagPath", "bag_path", "shell_path", "ShellPath", "AbsolutePath"),
    "shell_item_type": ("shell_item_type", "ShellItemType", "ItemType", "item_type"),
    "tracker_guid": ("tracker_guid", "TrackerGuid", "DroidFileIdentifier", "MachineIdentifier"),
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
        if key.lower().endswith(("artifact_type", "parser", "source_path", "path", "source_file", "kind"))
    ).lower()
    combined = f"{explicit_text} {haystack}"
    if "jumplist" in combined or "jump list" in combined or "destlist" in combined or "jlecmd" in combined:
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
