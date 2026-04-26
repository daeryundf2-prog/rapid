from __future__ import annotations

import csv
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Mapping

from ...core.models import ArtifactRecord

EVENT_LOG_ROOT = ("Windows", "System32", "winevt", "Logs")
PARSER_VERSION = "eventlog-normalized-v2"
EVENT_EXPORT_SUFFIXES = {".xml", ".json", ".jsonl", ".ndjson", ".csv"}
EVENT_EXPORT_HINTS = ("event", "evtx", "hayabusa", "chainsaw", "winevt", "winlog")

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


class WindowsEventLogProvider:
    name = "windows-eventlog"
    collector_kind = "eventlog"
    description = "Windows Event Log EVTX inventory and XML/JSON/JSONL/CSV event imports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        seen: set[Path] = set()
        for path in candidate_eventlog_paths(root):
            resolved = path.resolve()
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            suffix = path.suffix.lower()
            if suffix == ".xml":
                yield from collect_xml_events(path)
            elif suffix in {".json", ".jsonl", ".ndjson"}:
                yield from collect_json_like_events(path)
            elif suffix == ".csv":
                yield from collect_csv_events(path)
            elif suffix == ".evtx":
                yield build_eventlog_file_record(path)


def candidate_eventlog_paths(root: Path) -> Iterable[Path]:
    logs_root = root.joinpath(*EVENT_LOG_ROOT)
    if logs_root.is_dir():
        yield from sorted(
            (path for path in logs_root.rglob("*") if path.is_file() and path.suffix.lower() in EVENT_EXPORT_SUFFIXES | {".evtx"}),
            key=lambda item: str(item).lower(),
        )

    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in EVENT_EXPORT_SUFFIXES:
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
    reportability = "reportable" if source_format != "evtx" else "inventory-only"
    normalized_timestamp = normalize_timestamp(event_created_at)
    return {
        "parser": parser,
        "parser_version": PARSER_VERSION,
        "coverage_status": "detected-by-rule" if rule_title or rule_id else "mapped",
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


def build_eventlog_file_record(path: Path) -> ArtifactRecord:
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
            "recommended_parsers": ["EvtxECmd", "Hayabusa", "Chainsaw", "Velociraptor Windows.EventLogs.Evtx"],
            "note": "Binary EVTX detected. Native EVTX decoding is not enabled in this build; import EvtxECmd/Hayabusa/Chainsaw/Velociraptor JSONL/CSV/XML output for parsed rows.",
        },
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
