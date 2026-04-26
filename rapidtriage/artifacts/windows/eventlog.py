from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord

EVENT_LOG_ROOT = ("Windows", "System32", "winevt", "Logs")
PARSER_VERSION = "eventlog-normalized-v3"
BUILTIN_RULEPACK_VERSION = "eventlog-builtin-rules-v1"
EVENT_EXPORT_SUFFIXES = {".xml", ".json", ".jsonl", ".ndjson", ".csv"}
EVENT_EXPORT_HINTS = ("event", "evtx", "hayabusa", "chainsaw", "winevt", "winlog")
EVTX_FILE_SIGNATURE = b"ElfFile\x00"
EVTX_RECORD_MAGIC = b"**\x00\x00"
EVTX_RECORD_HEADER_SIZE = 24
MAX_NATIVE_EVTX_RECORDS = 10_000
MAX_NATIVE_EVTX_RECORD_SIZE = 16 * 1024 * 1024
MAX_NATIVE_EVTX_STRINGS = 200

EVENT_ID_CATEGORIES = {
    "4624": ("logon-success", "Authentication success"),
    "4625": ("logon-failure", "Authentication failure"),
    "4634": ("logoff", "Account logoff"),
    "4648": ("explicit-credential-logon", "Explicit credential logon"),
    "4672": ("privileged-logon", "Special privileges assigned to new logon"),
    "4688": ("process-created", "Process creation"),
    "4697": ("service-installed", "Service installed"),
    "4698": ("scheduled-task-created", "Scheduled task created"),
    "4702": ("scheduled-task-updated", "Scheduled task updated"),
    "4720": ("user-created", "User account created"),
    "4722": ("user-enabled", "User account enabled"),
    "4724": ("password-reset", "Password reset attempted"),
    "4728": ("group-member-added", "Member added to global group"),
    "4732": ("local-group-member-added", "Member added to local group"),
    "4738": ("user-changed", "User account changed"),
    "4740": ("account-locked", "User account locked"),
    "4768": ("kerberos-tgt-request", "Kerberos TGT request"),
    "4769": ("kerberos-service-ticket", "Kerberos service ticket request"),
    "4771": ("kerberos-preauth-failure", "Kerberos pre-authentication failed"),
    "4776": ("credential-validation", "Credential validation"),
    "1102": ("audit-log-cleared", "Audit log cleared"),
    "104": ("system-log-cleared", "Event log cleared"),
    "7045": ("service-installed", "Service installed"),
    "4103": ("powershell-module", "PowerShell module logging"),
    "4104": ("powershell-script-block", "PowerShell script block"),
    "1": ("sysmon-process-created", "Sysmon process creation"),
    "3": ("sysmon-network-connection", "Sysmon network connection"),
    "7": ("sysmon-image-loaded", "Sysmon image loaded"),
    "11": ("sysmon-file-created", "Sysmon file created"),
    "13": ("sysmon-registry-value-set", "Sysmon registry value set"),
    "22": ("sysmon-dns-query", "Sysmon DNS query"),
}

HIGH_RISK_EVENT_IDS = {"1102", "104", "4672", "4697", "4698", "4720", "4728", "4732", "7045", "4104"}
SUSPICIOUS_TERMS = (
    "powershell -enc",
    "frombase64string",
    "invoke-expression",
    "iex ",
    "rundll32",
    "regsvr32",
    "wmic",
    "bitsadmin",
    "certutil",
    "mimikatz",
    "procdump",
    "vssadmin delete shadows",
    "wevtutil cl",
)

BUILTIN_EVENT_RULES = (
    {
        "id": "RT-EVTX-LOG-CLEARED",
        "title": "Windows event log was cleared",
        "level": "high",
        "event_ids": {"1102", "104"},
        "categories": {"audit-log-cleared", "system-log-cleared"},
        "mitre_tags": ["attack.defense-evasion", "attack.t1070.001"],
        "risk_flags": ["log-clear"],
        "description": "Security or system event logs were cleared; validate operator activity and nearby process/account events.",
    },
    {
        "id": "RT-EVTX-PS-ENCODED",
        "title": "Suspicious encoded PowerShell activity",
        "level": "high",
        "event_ids": {"4103", "4104", "4688", "1"},
        "categories": {"powershell-module", "powershell-script-block", "process-created", "sysmon-process-created"},
        "terms": {"powershell -enc", "encodedcommand", "frombase64string", "invoke-expression", "iex "},
        "mitre_tags": ["attack.execution", "attack.t1059.001"],
        "risk_flags": ["powershell-encoded-command"],
        "description": "PowerShell script block, module, or process creation text contains encoded or dynamic execution indicators.",
    },
    {
        "id": "RT-EVTX-RDP-LOGON",
        "title": "Remote interactive logon",
        "level": "medium",
        "event_ids": {"4624"},
        "categories": {"logon-success"},
        "logon_types": {"10"},
        "mitre_tags": ["attack.lateral-movement", "attack.t1021.001"],
        "risk_flags": ["rdp-logon"],
        "description": "Successful logon with LogonType 10, commonly associated with RDP remote interactive sessions.",
    },
    {
        "id": "RT-EVTX-FAILED-LOGON",
        "title": "Failed account logon",
        "level": "low",
        "event_ids": {"4625"},
        "categories": {"logon-failure"},
        "mitre_tags": ["attack.credential-access", "attack.t1110"],
        "risk_flags": ["failed-logon"],
        "description": "Failed logon activity detected; correlate repeated failures by account, host, and source IP.",
    },
    {
        "id": "RT-EVTX-PRIVILEGED-LOGON",
        "title": "Privileged logon rights assigned",
        "level": "medium",
        "event_ids": {"4672"},
        "categories": {"privileged-logon"},
        "mitre_tags": ["attack.privilege-escalation"],
        "risk_flags": ["privileged-logon"],
        "description": "Special privileges were assigned to a new logon; review account legitimacy and adjacent logon events.",
    },
    {
        "id": "RT-EVTX-SERVICE-INSTALLED",
        "title": "Service installation event",
        "level": "medium",
        "event_ids": {"4697", "7045"},
        "categories": {"service-installed"},
        "mitre_tags": ["attack.persistence", "attack.privilege-escalation", "attack.t1543.003"],
        "risk_flags": ["service-install"],
        "description": "A service was installed; inspect service name, binary path, signer, and parent activity.",
    },
    {
        "id": "RT-EVTX-SCHEDULED-TASK",
        "title": "Scheduled task created or updated",
        "level": "medium",
        "event_ids": {"4698", "4702"},
        "categories": {"scheduled-task-created", "scheduled-task-updated"},
        "mitre_tags": ["attack.persistence", "attack.t1053.005"],
        "risk_flags": ["scheduled-task-change"],
        "description": "A scheduled task was created or updated; verify command path, author, trigger, and timestamp.",
    },
    {
        "id": "RT-EVTX-ACCOUNT-CREATED",
        "title": "Windows account created",
        "level": "medium",
        "event_ids": {"4720"},
        "categories": {"user-created"},
        "mitre_tags": ["attack.persistence", "attack.t1136.001"],
        "risk_flags": ["account-created"],
        "description": "A local or domain account was created; confirm expected administration or onboarding activity.",
    },
    {
        "id": "RT-EVTX-GROUP-MEMBER-ADDED",
        "title": "Security group membership changed",
        "level": "medium",
        "event_ids": {"4728", "4732"},
        "categories": {"group-member-added", "local-group-member-added"},
        "mitre_tags": ["attack.persistence", "attack.privilege-escalation", "attack.t1098"],
        "risk_flags": ["group-member-added"],
        "description": "A member was added to a security group; inspect target group, subject account, and business justification.",
    },
    {
        "id": "RT-EVTX-SYSMON-NETWORK",
        "title": "Sysmon network connection event",
        "level": "info",
        "event_ids": {"3"},
        "categories": {"sysmon-network-connection"},
        "mitre_tags": ["attack.command-and-control"],
        "risk_flags": ["sysmon-network"],
        "description": "Sysmon network connection observed; use as a pivot for process, DNS, and destination review.",
    },
)

RULE_LEVEL_SCORES = {"info": 15, "low": 25, "medium": 45, "high": 70, "critical": 90}


class WindowsEventLogProvider:
    name = "windows-eventlog"
    collector_kind = "eventlog"
    description = "Windows Event Log EVTX inventory and XML/JSON/JSONL/CSV event imports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        seen: set[Path] = set()
        for path in candidate_eventlog_paths(root):
            resolved = path.resolve()
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            suffix = path.suffix.lower()
            if suffix == ".xml":
                records.extend(collect_xml_events(path))
            elif suffix in {".json", ".jsonl", ".ndjson"}:
                records.extend(collect_json_like_events(path))
            elif suffix == ".csv":
                records.extend(collect_csv_events(path))
            elif suffix == ".evtx":
                native_records = list(collect_native_evtx_events(path))
                records.extend(native_records)
                records.append(build_eventlog_file_record(path, native_record_count=len(native_records)))
        records.extend(build_builtin_detection_records(records))
        yield from records
        summary = build_eventlog_summary(root, records)
        if summary is not None:
            yield summary


def candidate_eventlog_paths(root: Path) -> Iterable[Path]:
    logs_root = root.joinpath(*EVENT_LOG_ROOT)
    if logs_root.is_dir():
        yield from sorted(
            (path for path in logs_root.rglob("*") if path.is_file() and path.suffix.lower() in EVENT_EXPORT_SUFFIXES | {".evtx"}),
            key=lambda item: str(item).lower(),
        )

    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in EVENT_EXPORT_SUFFIXES | {".evtx"}:
            continue
        lowered = str(path.relative_to(root)).lower()
        if any(hint in lowered for hint in EVENT_EXPORT_HINTS):
            yield path


def collect_xml_events(path: Path) -> Iterable[ArtifactRecord]:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return
    root = tree.getroot()
    events = [root] if strip_namespace(root.tag) == "Event" else root.findall(".//{*}Event")
    source_hashes = file_hashes(path)
    for index, event in enumerate(events):
        system = child_by_name(event, "System")
        event_data = child_by_name(event, "EventData")
        user_data = child_by_name(event, "UserData")
        data = event_data_values(event_data)
        if user_data is not None:
            data.update(prefixed_xml_values(user_data, "UserData"))
        details = normalize_event_details(
            parser="windows-eventlog-xml",
            source_format="xml",
            source_path=path,
            source_index=index,
            source_hashes=source_hashes,
            provider_name=attr_from_child(system, "Provider", "Name"),
            event_id=text_from_child(system, "EventID"),
            record_id=text_from_child(system, "EventRecordID"),
            channel=text_from_child(system, "Channel"),
            level=text_from_child(system, "Level"),
            computer=text_from_child(system, "Computer"),
            event_created_at=attr_from_child(system, "TimeCreated", "SystemTime"),
            data=data,
            raw_preview=ET.tostring(event, encoding="unicode")[:2000],
            user_sid=attr_from_child(system, "Security", "UserID"),
            process_id=attr_from_child(system, "Execution", "ProcessID"),
            thread_id=attr_from_child(system, "Execution", "ThreadID"),
            task=text_from_child(system, "Task"),
            opcode=text_from_child(system, "Opcode"),
            keywords=text_from_child(system, "Keywords"),
        )
        yield event_record(path, "eventlog-event", details)


def collect_json_like_events(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = file_hashes(path)
    for index, row in enumerate(iter_json_rows(path)):
        details = details_from_mapping(
            row,
            parser=guess_parser_name(row, path),
            source_format=path.suffix.lower().lstrip("."),
            source_path=path,
            source_index=index,
            source_hashes=source_hashes,
        )
        artifact_type = "eventlog-detection" if is_detection_row(details) else "eventlog-event"
        yield event_record(path, artifact_type, details)


def collect_csv_events(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = file_hashes(path)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                details = details_from_mapping(
                    row,
                    parser=guess_parser_name(row, path),
                    source_format="csv",
                    source_path=path,
                    source_index=index,
                    source_hashes=source_hashes,
                )
                artifact_type = "eventlog-detection" if is_detection_row(details) else "eventlog-event"
                yield event_record(path, artifact_type, details)
    except (OSError, UnicodeError, csv.Error):
        return


def collect_native_evtx_events(path: Path) -> Iterable[ArtifactRecord]:
    try:
        blob = path.read_bytes()
    except OSError:
        return
    if not blob.startswith(EVTX_FILE_SIGNATURE):
        return

    source_hashes = file_hashes(path)
    for source_index, (offset, record_blob) in enumerate(iter_evtx_record_blobs(blob)):
        record_id = read_u64(record_blob, 8)
        timestamp = filetime_to_iso(read_u64(record_blob, 16))
        payload = record_blob[EVTX_RECORD_HEADER_SIZE:]
        extracted_strings = extract_utf16le_strings(payload)
        raw_preview = " ".join(extracted_strings)[:2000]
        data = {
            "evtx_parse_status": "native-binary-partial",
            "evtx_record_offset": offset,
            "evtx_record_size": len(record_blob),
            "extracted_strings": extracted_strings[:MAX_NATIVE_EVTX_STRINGS],
            "extracted_string_count": len(extracted_strings),
        }
        provider_name = first_matching_string(extracted_strings, "Microsoft-Windows-")
        channel = first_matching_string(extracted_strings, "/Operational", "Security", "System", "Application")
        computer = first_matching_string(extracted_strings, "WIN-", ".local")
        details = normalize_event_details(
            parser="windows-eventlog-evtx-native",
            source_format="evtx",
            source_path=path,
            source_index=source_index,
            source_hashes=source_hashes,
            provider_name=provider_name,
            event_id="",
            record_id=str(record_id or ""),
            channel=channel,
            level="",
            computer=computer,
            event_created_at=timestamp,
            data=data,
            raw_preview=raw_preview,
            command_line=raw_preview,
        )
        details.update(data)
        yield event_record(path, "eventlog-event", details)


def iter_evtx_record_blobs(blob: bytes) -> Iterable[tuple[int, bytes]]:
    offset = 0
    emitted = 0
    while emitted < MAX_NATIVE_EVTX_RECORDS:
        offset = blob.find(EVTX_RECORD_MAGIC, offset)
        if offset < 0:
            return
        size = read_u32(blob, offset + 4)
        if size < EVTX_RECORD_HEADER_SIZE or size > MAX_NATIVE_EVTX_RECORD_SIZE or offset + size > len(blob):
            offset += len(EVTX_RECORD_MAGIC)
            continue
        yield offset, blob[offset : offset + size]
        emitted += 1
        offset += size


def iter_json_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, Mapping):
                yield row
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, Mapping):
        rows = payload.get("events") or payload.get("Events") or payload.get("records") or payload.get("Rows") or [payload]
    else:
        rows = []
    for row in rows:
        if isinstance(row, Mapping):
            yield row


def details_from_mapping(
    row: Mapping[str, object],
    *,
    parser: str,
    source_format: str,
    source_path: Path,
    source_index: int,
    source_hashes: Mapping[str, str],
) -> dict[str, object]:
    lowered = {normalize_key(key): value for key, value in row.items()}
    event_id = first_value(lowered, "eventid", "event_id", "id", "eid")
    details = normalize_event_details(
        parser=parser,
        source_format=source_format,
        source_path=source_path,
        source_index=source_index,
        source_hashes=source_hashes,
        provider_name=str(first_value(lowered, "provider", "providername", "provider_name", "source") or ""),
        event_id=str(event_id or ""),
        record_id=str(first_value(lowered, "recordid", "record_id", "eventrecordid") or ""),
        channel=str(first_value(lowered, "channel", "logname", "evtxchannel") or ""),
        level=str(first_value(lowered, "level", "severity") or ""),
        computer=str(first_value(lowered, "computer", "computername", "hostname") or ""),
        event_created_at=str(first_value(lowered, "timestamp", "timecreated", "eventcreatedat", "datetime", "date") or ""),
        data=dict(row),
        raw_preview=json.dumps(row, ensure_ascii=False, sort_keys=True)[:2000],
        user_sid=str(first_value(lowered, "usersid", "user_sid", "subjectusersid", "targetusersid") or ""),
        user_name=str(first_value(lowered, "user", "username", "user_name", "subjectusername", "targetusername") or ""),
        process_id=str(first_value(lowered, "processid", "process_id") or ""),
        process_name=str(first_value(lowered, "processname", "process_name", "image") or ""),
        command_line=str(first_value(lowered, "commandline", "command_line", "processcommandline") or ""),
        task=str(first_value(lowered, "task", "taskcategory") or ""),
        opcode=str(first_value(lowered, "opcode") or ""),
        keywords=str(first_value(lowered, "keywords") or ""),
        rule_title=str(first_value(lowered, "ruletitle", "rule_title", "title", "detections", "detection") or ""),
        rule_id=str(first_value(lowered, "ruleid", "rule_id", "sigmaid", "sigma_id") or ""),
        rule_level=str(first_value(lowered, "rulelevel", "rule_level", "level", "severity", "criticality") or ""),
        mitre_tags=split_tags(first_value(lowered, "mitretags", "mitre_tags", "mitre", "tags")),
    )
    return details


def normalize_event_details(
    *,
    parser: str,
    source_format: str,
    source_path: Path,
    source_index: int,
    source_hashes: Mapping[str, str],
    provider_name: str,
    event_id: str,
    record_id: str,
    channel: str,
    level: str,
    computer: str,
    event_created_at: str,
    data: Mapping[str, object],
    raw_preview: str,
    user_sid: str = "",
    user_name: str = "",
    process_id: str = "",
    thread_id: str = "",
    process_name: str = "",
    command_line: str = "",
    task: str = "",
    opcode: str = "",
    keywords: str = "",
    rule_title: str = "",
    rule_id: str = "",
    rule_level: str = "",
    mitre_tags: list[str] | None = None,
) -> dict[str, object]:
    normalized_event_id = normalize_event_id(event_id)
    target_user_name = first_data_text(data, "TargetUserName", "TargetUser", "AccountName")
    subject_user_name = first_data_text(data, "SubjectUserName", "SubjectUser")
    target_domain_name = first_data_text(data, "TargetDomainName", "AccountDomain")
    logon_type = first_data_text(data, "LogonType")
    source_ip = first_data_text(data, "IpAddress", "SourceAddress", "SourceIp", "SourceNetworkAddress")
    source_port = first_data_text(data, "IpPort", "SourcePort")
    service_name = first_data_text(data, "ServiceName")
    new_process_name = first_data_text(data, "NewProcessName", "ProcessName", "Image")
    parent_process_name = first_data_text(data, "ParentProcessName", "CreatorProcessName")
    script_block_text = first_data_text(data, "ScriptBlockText")
    if not user_sid:
        user_sid = first_data_text(data, "TargetUserSid", "SubjectUserSid", "UserSid")
    if not user_name:
        user_name = target_user_name or subject_user_name
    if not process_name:
        process_name = new_process_name
    if not command_line:
        command_line = first_data_text(data, "CommandLine", "ProcessCommandLine") or script_block_text
    category, description = EVENT_ID_CATEGORIES.get(normalized_event_id, ("event", "Windows event log record"))
    detected_terms = suspicious_terms(data, command_line)
    risk_flags = []
    if normalized_event_id in HIGH_RISK_EVENT_IDS:
        risk_flags.append(f"high-value-event-id:{normalized_event_id}")
    if detected_terms:
        risk_flags.extend(f"suspicious-term:{term}" for term in detected_terms)
    if rule_title or rule_id:
        risk_flags.append("detection-rule-hit")
    is_native_evtx = parser == "windows-eventlog-evtx-native"
    reportability = "triage" if is_native_evtx else ("reportable" if source_format != "evtx" else "inventory-only")
    normalized_timestamp = normalize_timestamp(event_created_at)
    return {
        "parser": parser,
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-binary-partial" if is_native_evtx else ("detected-by-rule" if rule_title or rule_id else "mapped"),
        "reportability": reportability,
        "source_path": str(source_path.resolve()),
        "source_format": source_format,
        "source_index": source_index,
        "source_hashes": dict(source_hashes),
        "provider_name": provider_name,
        "event_id": normalized_event_id,
        "event_category": category,
        "event_description": description,
        "record_id": str(record_id or ""),
        "channel": channel,
        "level": level,
        "computer": computer,
        "user_sid": user_sid,
        "user_name": user_name,
        "subject_user_name": subject_user_name,
        "target_user_name": target_user_name,
        "target_domain_name": target_domain_name,
        "logon_type": logon_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "service_name": service_name,
        "process_id": process_id,
        "thread_id": thread_id,
        "process_name": process_name,
        "new_process_name": new_process_name,
        "parent_process_name": parent_process_name,
        "command_line": command_line,
        "script_block_text": script_block_text,
        "task": task,
        "opcode": opcode,
        "keywords": keywords,
        "event_created_at": normalized_timestamp,
        "timestamp": normalized_timestamp,
        "rule": {
            "title": rule_title,
            "id": rule_id,
            "level": rule_level,
            "mitre_tags": mitre_tags or [],
        },
        "risk_flags": risk_flags,
        "risk_score": event_risk_score(normalized_event_id, detected_terms, bool(rule_title or rule_id)),
        "data": dict(data),
        "raw_preview": raw_preview,
    }


def build_eventlog_file_record(path: Path, *, native_record_count: int = 0) -> ArtifactRecord:
    stat_result = path.stat()
    return ArtifactRecord(
        provider=WindowsEventLogProvider.name,
        artifact_type="eventlog-file",
        path=str(path.resolve()),
        supported=False,
        details={
            "parser": "windows-eventlog-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "detected",
            "reportability": "inventory-only",
            "source_path": str(path.resolve()),
            "source_format": "evtx",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "native_record_count": native_record_count,
            "native_parse_status": "partial-record-scan" if native_record_count else "no-records-emitted",
            "recommended_parsers": ["EvtxECmd", "Hayabusa", "Chainsaw", "Velociraptor Windows.EventLogs.Evtx"],
            "note": "Binary EVTX detected. RapidTriage emits partial native record rows when record headers and UTF-16 strings are recoverable; import EvtxECmd/Hayabusa/Chainsaw/Velociraptor JSONL/CSV/XML output for full BinXML field mapping.",
        },
    )


def build_builtin_detection_records(records: Sequence[ArtifactRecord]) -> list[ArtifactRecord]:
    detections: list[ArtifactRecord] = []
    for record in records:
        if record.artifact_type != "eventlog-event" or not isinstance(record.details, Mapping):
            continue
        for rule in BUILTIN_EVENT_RULES:
            if builtin_rule_matches(rule, record.details):
                detections.append(build_builtin_detection_record(record, rule))
    return detections


def builtin_rule_matches(rule: Mapping[str, object], details: Mapping[str, object]) -> bool:
    event_id = str(details.get("event_id") or "")
    category = str(details.get("event_category") or "")
    event_ids = {str(item) for item in rule.get("event_ids", set())}
    categories = {str(item) for item in rule.get("categories", set())}
    if event_ids and event_id not in event_ids:
        return False
    if categories and category not in categories:
        return False

    logon_types = {str(item) for item in rule.get("logon_types", set())}
    if logon_types and str(details.get("logon_type") or "") not in logon_types:
        return False

    terms = {str(item).lower() for item in rule.get("terms", set())}
    if terms:
        haystack = " ".join(
            str(details.get(key) or "")
            for key in ("command_line", "script_block_text", "process_name", "new_process_name", "raw_preview")
        ).lower()
        haystack = f"{haystack} {json.dumps(details.get('data') or {}, ensure_ascii=False, sort_keys=True).lower()}"
        if not any(term in haystack for term in terms):
            return False

    return True


def build_builtin_detection_record(source_record: ArtifactRecord, rule: Mapping[str, object]) -> ArtifactRecord:
    details = source_record.details
    rule_level = str(rule.get("level") or "")
    rule_flags = [str(item) for item in rule.get("risk_flags", []) if str(item)]
    risk_flags = sorted(set(list(details.get("risk_flags") or []) + [f"builtin-rule:{rule.get('id')}", *rule_flags]))
    risk_score = max(int(details.get("risk_score") or 0), RULE_LEVEL_SCORES.get(rule_level.lower(), 40))
    detection_details = {
        "parser": "windows-eventlog-builtin-rulepack",
        "parser_version": PARSER_VERSION,
        "rulepack_version": BUILTIN_RULEPACK_VERSION,
        "coverage_status": "detected-by-rule",
        "reportability": "triage",
        "source_path": details.get("source_path") or source_record.path,
        "source_format": details.get("source_format") or "",
        "source_index": details.get("source_index"),
        "source_hashes": dict(details.get("source_hashes") or {}),
        "provider_name": details.get("provider_name") or "",
        "event_id": details.get("event_id") or "",
        "event_category": details.get("event_category") or "",
        "event_description": details.get("event_description") or "",
        "record_id": details.get("record_id") or "",
        "channel": details.get("channel") or "",
        "level": details.get("level") or "",
        "computer": details.get("computer") or "",
        "user_sid": details.get("user_sid") or "",
        "user_name": details.get("user_name") or "",
        "subject_user_name": details.get("subject_user_name") or "",
        "target_user_name": details.get("target_user_name") or "",
        "target_domain_name": details.get("target_domain_name") or "",
        "logon_type": details.get("logon_type") or "",
        "source_ip": details.get("source_ip") or "",
        "source_port": details.get("source_port") or "",
        "service_name": details.get("service_name") or "",
        "process_id": details.get("process_id") or "",
        "thread_id": details.get("thread_id") or "",
        "process_name": details.get("process_name") or "",
        "new_process_name": details.get("new_process_name") or "",
        "parent_process_name": details.get("parent_process_name") or "",
        "command_line": details.get("command_line") or "",
        "script_block_text": details.get("script_block_text") or "",
        "event_created_at": details.get("event_created_at") or "",
        "timestamp": details.get("timestamp") or "",
        "rule": {
            "title": rule.get("title") or "",
            "id": rule.get("id") or "",
            "level": rule_level,
            "mitre_tags": list(rule.get("mitre_tags") or []),
            "description": rule.get("description") or "",
            "source": "rapidtriage-builtin",
        },
        "risk_flags": risk_flags,
        "risk_score": min(100, risk_score),
        "matched_event": {
            "artifact_type": source_record.artifact_type,
            "path": source_record.path,
            "source_index": details.get("source_index"),
            "record_id": details.get("record_id") or "",
        },
    }
    return event_record(Path(source_record.path), "eventlog-detection", detection_details)


def build_eventlog_summary(root: Path, records: Sequence[ArtifactRecord]) -> ArtifactRecord | None:
    event_rows = [
        record
        for record in records
        if record.artifact_type == "eventlog-event" and isinstance(record.details, Mapping)
    ]
    detection_rows = [
        record
        for record in records
        if record.artifact_type == "eventlog-detection" and isinstance(record.details, Mapping)
    ]
    parsed_rows = [
        record
        for record in records
        if record.artifact_type in {"eventlog-event", "eventlog-detection"} and isinstance(record.details, Mapping)
    ]
    inventory_rows = [record for record in records if record.artifact_type == "eventlog-file"]
    if not parsed_rows and not inventory_rows:
        return None

    event_id_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    channel_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    source_ip_counts: Counter[str] = Counter()
    process_counts: Counter[str] = Counter()
    source_paths: set[str] = set()
    timestamps: list[str] = []
    high_risk_events: list[dict[str, object]] = []
    record_ids_by_channel: dict[str, list[int]] = defaultdict(list)
    detection_rule_counts: Counter[str] = Counter()

    for record in event_rows:
        details = record.details
        event_id = str(details.get("event_id") or "")
        category = str(details.get("event_category") or "")
        channel = str(details.get("channel") or "unknown")
        user_name = str(details.get("user_name") or details.get("target_user_name") or details.get("subject_user_name") or "")
        source_ip = str(details.get("source_ip") or "")
        process_name = str(details.get("process_name") or details.get("new_process_name") or "")
        source_path = str(details.get("source_path") or record.path)
        timestamp = str(details.get("timestamp") or details.get("event_created_at") or "")
        record_id = int_text(details.get("record_id"))

        increment_counter(event_id_counts, event_id)
        increment_counter(category_counts, category)
        increment_counter(channel_counts, channel)
        increment_counter(user_counts, user_name)
        increment_counter(source_ip_counts, source_ip)
        increment_counter(process_counts, process_name)
        source_paths.add(source_path)
        if timestamp:
            timestamps.append(timestamp)
        if record_id is not None:
            record_ids_by_channel[channel].append(record_id)
        if int(details.get("risk_score") or 0) >= 40 or details.get("risk_flags"):
            high_risk_events.append(
                {
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "event_category": category,
                    "channel": channel,
                    "user_name": user_name,
                    "source_ip": source_ip,
                    "process_name": process_name,
                    "risk_score": details.get("risk_score", 0),
                    "risk_flags": list(details.get("risk_flags") or []),
                    "rule": details.get("rule", {}),
                    "source_path": source_path,
                }
            )

    for record in detection_rows:
        details = record.details
        channel = str(details.get("channel") or "unknown")
        source_path = str(details.get("source_path") or record.path)
        timestamp = str(details.get("timestamp") or details.get("event_created_at") or "")
        record_id = int_text(details.get("record_id"))
        rule = details.get("rule") if isinstance(details.get("rule"), Mapping) else {}
        rule_id = str(rule.get("id") or rule.get("title") or "")
        increment_counter(detection_rule_counts, rule_id)
        source_paths.add(source_path)
        if timestamp:
            timestamps.append(timestamp)
        if record_id is not None:
            record_ids_by_channel[channel].append(record_id)
        if int(details.get("risk_score") or 0) >= 40 or details.get("risk_flags"):
            high_risk_events.append(
                {
                    "timestamp": timestamp,
                    "event_id": str(details.get("event_id") or ""),
                    "event_category": str(details.get("event_category") or ""),
                    "channel": channel,
                    "user_name": str(details.get("user_name") or details.get("target_user_name") or details.get("subject_user_name") or ""),
                    "source_ip": str(details.get("source_ip") or ""),
                    "process_name": str(details.get("process_name") or details.get("new_process_name") or ""),
                    "risk_score": details.get("risk_score", 0),
                    "risk_flags": list(details.get("risk_flags") or []),
                    "rule": rule,
                    "source_path": source_path,
                }
            )

    timestamps.sort()
    details = {
        "parser": "windows-eventlog-summary",
        "parser_version": PARSER_VERSION,
        "coverage_status": "summarized",
        "reportability": "triage",
        "source_path": str(root.resolve()),
        "source_format": "summary",
        "event_count": len(event_rows),
        "detection_count": len(detection_rows),
        "parsed_row_count": len(parsed_rows),
        "inventory_count": len(inventory_rows),
        "source_files": sorted(source_paths),
        "detection_rule_counts": counter_items(detection_rule_counts),
        "event_id_counts": counter_items(event_id_counts),
        "event_category_counts": counter_items(category_counts),
        "channel_counts": counter_items(channel_counts),
        "user_counts": counter_items(user_counts),
        "source_ip_counts": counter_items(source_ip_counts),
        "process_counts": counter_items(process_counts),
        "first_event_at": timestamps[0] if timestamps else "",
        "last_event_at": timestamps[-1] if timestamps else "",
        "high_risk_events": sorted(high_risk_events, key=lambda item: int(item.get("risk_score") or 0), reverse=True)[:50],
        "record_sequence_gaps": record_sequence_gaps(record_ids_by_channel),
        "summary_notes": [
            "Review record_sequence_gaps as triage hints only; filtered exports may naturally contain non-contiguous EventRecordID values.",
            "Binary EVTX rows include partial native record scans when recoverable; use external parser exports for complete BinXML field fidelity.",
        ],
    }
    return ArtifactRecord(
        provider=WindowsEventLogProvider.name,
        artifact_type="eventlog-summary",
        path=str(root.resolve()),
        supported=True,
        details=details,
    )


def event_record(path: Path, artifact_type: str, details: Mapping[str, object]) -> ArtifactRecord:
    return ArtifactRecord(
        provider=WindowsEventLogProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details=dict(details),
    )


def is_detection_row(details: Mapping[str, object]) -> bool:
    rule = details.get("rule")
    return isinstance(rule, Mapping) and bool(rule.get("title") or rule.get("id"))


def guess_parser_name(row: Mapping[str, object], path: Path) -> str:
    keys = {normalize_key(key) for key in row}
    lowered_path = str(path).lower()
    if "hayabusa" in lowered_path or {"ruletitle", "rulelevel"} & keys:
        return "windows-eventlog-hayabusa-import"
    if "chainsaw" in lowered_path or {"sigmaid", "detections"} & keys:
        return "windows-eventlog-chainsaw-import"
    if "evtxecmd" in lowered_path or {"eventrecordid", "mapdescription"} & keys:
        return "windows-eventlog-evtxecmd-import"
    if "velociraptor" in lowered_path:
        return "windows-eventlog-velociraptor-import"
    return "windows-eventlog-export-import"


def normalize_event_id(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.search(r"\d+", text)
    return match.group(0) if match else text


def normalize_timestamp(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = re.match(r"^(?P<head>.+?\.)(?P<fraction>\d{7,})(?P<tail>Z|[+-]\d\d:?\d\d)?$", text)
    if match:
        text = f"{match.group('head')}{match.group('fraction')[:6]}{match.group('tail') or ''}"
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    return text


def filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        moment = base + dt.timedelta(microseconds=value // 10)
    except (OverflowError, TypeError, ValueError):
        return ""
    return moment.isoformat()


def read_u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little", signed=False)


def read_u64(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 8], "little", signed=False)


def extract_utf16le_strings(blob: bytes, *, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    start: int | None = None
    cursor = 0
    while cursor + 1 < len(blob):
        code_unit = blob[cursor : cursor + 2]
        value = int.from_bytes(code_unit, "little", signed=False)
        printable = value in (9, 10, 13) or 32 <= value <= 0xD7FF or 0xE000 <= value <= 0xFFFD
        if printable and value != 0:
            if start is None:
                start = cursor
        else:
            if start is not None:
                text = decode_utf16le_string(blob[start:cursor])
                if len(text) >= min_chars:
                    strings.append(text)
                    if len(strings) >= MAX_NATIVE_EVTX_STRINGS:
                        return strings
                start = None
        cursor += 2
    if start is not None:
        text = decode_utf16le_string(blob[start:cursor])
        if len(text) >= min_chars:
            strings.append(text)
    return strings


def decode_utf16le_string(blob: bytes) -> str:
    try:
        return blob.decode("utf-16le", errors="ignore").strip("\x00\r\n\t ")
    except UnicodeError:
        return ""


def first_matching_string(values: Sequence[str], *needles: str) -> str:
    lowered_needles = [needle.lower() for needle in needles if needle]
    for value in values:
        lowered = value.lower()
        if any(needle in lowered for needle in lowered_needles):
            return value
    return ""


def normalize_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def first_value(row: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = row.get(normalize_key(key))
        if value not in (None, ""):
            return value
    return ""


def first_data_text(row: Mapping[str, object], *keys: str) -> str:
    lowered = {normalize_key(key): value for key, value in row.items()}
    value = first_value(lowered, *keys)
    return str(value or "")


def split_tags(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    text = str(value or "")
    return [item.strip() for item in re.split(r"[,;| ]+", text) if item.strip()]


def suspicious_terms(data: Mapping[str, object], command_line: str = "") -> list[str]:
    haystack = f"{command_line}\n{json.dumps(data, ensure_ascii=False, sort_keys=True)}".lower()
    return [term for term in SUSPICIOUS_TERMS if term in haystack]


def event_risk_score(event_id: str, terms: list[str], has_rule: bool) -> int:
    score = 0
    if event_id in HIGH_RISK_EVENT_IDS:
        score += 40
    if terms:
        score += min(40, len(terms) * 15)
    if has_rule:
        score += 40
    return min(100, score)


def increment_counter(counter: Counter[str], value: str) -> None:
    if value:
        counter[value] += 1


def counter_items(counter: Counter[str], limit: int = 25) -> list[dict[str, object]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def int_text(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def record_sequence_gaps(record_ids_by_channel: Mapping[str, Sequence[int]], limit: int = 50) -> list[dict[str, object]]:
    gaps: list[dict[str, object]] = []
    for channel, record_ids in sorted(record_ids_by_channel.items()):
        unique_ids = sorted(set(record_ids))
        for previous, current in zip(unique_ids, unique_ids[1:]):
            if current - previous <= 1:
                continue
            gaps.append(
                {
                    "channel": channel,
                    "after_record_id": previous,
                    "before_record_id": current,
                    "missing_count": current - previous - 1,
                }
            )
            if len(gaps) >= limit:
                return gaps
    return gaps


def strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child_by_name(node: ET.Element | None, name: str) -> ET.Element | None:
    if node is None:
        return None
    for child in list(node):
        if strip_namespace(child.tag) == name:
            return child
    return None


def text_from_child(node: ET.Element | None, name: str) -> str:
    child = child_by_name(node, name)
    return (child.text or "").strip() if child is not None else ""


def attr_from_child(node: ET.Element | None, name: str, attribute: str) -> str:
    child = child_by_name(node, name)
    return str(child.attrib.get(attribute, "")) if child is not None else ""


def event_data_values(node: ET.Element | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if node is None:
        return values
    for index, child in enumerate(list(node)):
        if strip_namespace(child.tag) != "Data":
            continue
        key = str(child.attrib.get("Name") or f"Data{index}")
        values[key] = (child.text or "").strip()
    return values


def prefixed_xml_values(node: ET.Element, prefix: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for index, child in enumerate(node.iter()):
        if child is node:
            continue
        text = (child.text or "").strip()
        if not text:
            continue
        key = f"{prefix}.{strip_namespace(child.tag)}.{index}"
        values[key] = text
    return values


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
