from __future__ import annotations

import datetime as dt
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from ...core.audit import compute_sha256
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review, isoformat_from_timestamp

PARSER_VERSION = "windows-system-v6"
TASKS_ROOT = ("Windows", "System32", "Tasks")
TASK_SUSPICIOUS_TERMS = (
    "powershell",
    "pwsh",
    "-enc",
    "-encodedcommand",
    "executionpolicy bypass",
    "hidden",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "curl",
    "http://",
    "https://",
)
TASK_USER_WRITABLE_PATH_TERMS = (
    "\\users\\",
    "\\appdata\\",
    "\\programdata\\",
    "\\temp\\",
    "%appdata%",
    "%localappdata%",
    "%temp%",
    "%tmp%",
)
TASK_LOLBINS = {
    "bitsadmin.exe",
    "certutil.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "schtasks.exe",
    "wscript.exe",
}
DEFENDER_SUPPORT_ROOT = ("ProgramData", "Microsoft", "Windows Defender", "Support")
WMI_REPOSITORY_ROOT = ("Windows", "System32", "wbem", "Repository")
WMI_REPOSITORY_NAMES = {"OBJECTS.DATA", "INDEX.BTR", "MAPPING.VER"}
WMI_REPOSITORY_SUFFIXES = {".MAP", ".BTR", ".DATA"}
WMI_SCAN_LIMIT = 8 * 1024 * 1024
WMI_PERSISTENCE_TERMS = (
    "__eventfilter",
    "commandlineeventconsumer",
    "activescripteventconsumer",
    "__filtertoconsumerbinding",
    "powershell",
    "wmic",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
)
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\|\\device\\)[^\x00\r\n\t\"'<>|]{4,260}")
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")
FIREWALL_LOG_PATHS = (
    ("Windows", "System32", "LogFiles", "Firewall", "pfirewall.log"),
    ("Windows", "System32", "LogFiles", "Firewall", "pfirewall.log.old"),
)
WER_ROOTS = (
    ("ProgramData", "Microsoft", "Windows", "WER"),
    ("Users",),
)
WER_REPORT_GRADE_BLOCKERS = [
    "wer-dump-file-correlation-not-implemented",
    "wer-reportqueue-state-validation-not-implemented",
    "wer-cab-metadata-validation-not-implemented",
]
SYSTEM_NATIVE_CAPABILITIES = {
    "task_xml_normalization": True,
    "task_action_trigger_principal_pivots": True,
    "defender_mplog_triage": True,
    "firewall_w3c_log_parsing": True,
    "wer_key_value_normalization": True,
    "wmi_repository_string_pivots": True,
    "taskcache_registry_correlation": False,
    "task_security_descriptor_validation": False,
    "defender_event_mpcmdrun_correlation": False,
    "firewall_rule_store_correlation": False,
    "wer_dump_cab_reportqueue_correlation": False,
    "native_wmi_repository_decode": False,
}
SYSTEM_REPORT_GRADE_BLOCKERS = [
    "task-cache-registry-correlation-not-implemented",
    "task-security-descriptor-validation-not-implemented",
    "task-history-event-correlation-not-implemented",
    "defender-event-and-mpcmdrun-correlation-not-implemented",
    "firewall-rule-store-correlation-not-implemented",
    "wer-dump-cab-reportqueue-correlation-not-implemented",
    "native-wmi-repository-decoding-not-implemented",
    "known-answer-system-artifact-corpus-required",
]
ZONE_IDENTIFIER_PATTERN = re.compile(r"(?i)(?P<target>.+)(?::Zone\.Identifier|\.Zone\.Identifier)$")


class WindowsSystemArtifactsProvider:
    collector_kind = "windows-system"
    name = "windows-system-artifacts"
    description = "Windows Task Scheduler, Defender, Firewall, WER, and Zone.Identifier artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_task_scheduler(root)
        yield from collect_defender_support(root)
        yield from collect_firewall_logs(root)
        yield from collect_wer_reports(root)
        yield from collect_wmi_repository(root)
        yield from collect_zone_identifier_ads(root)


def collect_task_scheduler(root: Path) -> Iterable[ArtifactRecord]:
    tasks_root = root.joinpath(*TASKS_ROOT)
    if not tasks_root.is_dir():
        return
    for path in sorted((item for item in tasks_root.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
        try:
            xml_root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue
        stat_result = path.stat()
        command = first_text(xml_root, "Command")
        arguments = first_text(xml_root, "Arguments")
        working_directory = first_text(xml_root, "WorkingDirectory")
        uri = first_text(xml_root, "URI") or "\\" + str(path.relative_to(tasks_root)).replace("/", "\\")
        triggers = [local_name(child.tag) for child in find_children(xml_root, "Triggers")]
        trigger_details = task_trigger_details(xml_root)
        action_details = task_action_details(xml_root)
        principal_details = task_principal_details(xml_root)
        risk_flags = task_scheduler_risk_flags(command, arguments, working_directory, uri)
        validation_checks = task_scheduler_validation_checks(
            command=command,
            arguments=arguments,
            working_directory=working_directory,
            uri=uri,
            risk_flags=risk_flags,
            trigger_details=trigger_details,
            action_details=action_details,
            principal_details=principal_details,
        )
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="task-scheduler-task",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "task-xml"),
                "task_uri": uri,
                "command": command,
                "arguments": arguments,
                "working_directory": working_directory,
                "action_preview": " ".join(item for item in (command, arguments) if item).strip(),
                "command_line": " ".join(item for item in (command, arguments) if item).strip(),
                "executable_name": windows_executable_name(command),
                "normalized_action": normalized_task_action(command, arguments, working_directory),
                "actions": action_details,
                "action_count": len(action_details),
                "author": first_text(xml_root, "Author"),
                "user_id": first_text(xml_root, "UserId"),
                "run_level": first_text(xml_root, "RunLevel"),
                "logon_type": first_text(xml_root, "LogonType"),
                "principals": principal_details,
                "principal_count": len(principal_details),
                "hidden": parse_bool_text(first_text(xml_root, "Hidden")),
                "trigger_types": triggers,
                "trigger_details": trigger_details,
                "trigger_count": len(trigger_details),
                "start_boundaries": all_text(xml_root, "StartBoundary"),
                "coverage_status": "task-xml-normalized",
                "evidence_strength": "persistence-configuration",
                "reportability": "triage",
                "parser_confidence": "high" if command and uri else "medium",
                "validation_required": True,
                "validation_checks": validation_checks,
                "core_accuracy_gates": system_core_accuracy_gates(
                    "task-scheduler",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "validation_checks": validation_checks,
                        "risk_flags": risk_flags,
                        "actions": action_details,
                        "trigger_details": trigger_details,
                        "normalized_action": normalized_task_action(command, arguments, working_directory),
                    },
                ),
                "system_validation_matrix": system_validation_matrix("task-scheduler", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("task-scheduler", validation_checks),
                "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
                "forensic_review": system_forensic_review(
                    "task-scheduler",
                    [
                        f"task_uri={uri}",
                        f"command={command}",
                        f"trigger_count={len(trigger_details)}",
                        f"principal_count={len(principal_details)}",
                    ],
                    validation_checks,
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "task-cache-registry-correlation-not-implemented",
                    "task-security-descriptor-validation-not-implemented",
                    "task-history-event-correlation-not-implemented",
                ],
                "validation_guidance": (
                    "Task XML is normalized for triage. Correlate with TaskCache registry keys, task security descriptors, "
                    "and task operational events before report-grade conclusions about creation, tampering, or execution."
                ),
                "risk_flags": risk_flags,
                "risk_score": min(100, len(risk_flags) * 12),
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "task_file_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": preview_text(path),
            },
        )


def collect_defender_support(root: Path) -> Iterable[ArtifactRecord]:
    support_root = root.joinpath(*DEFENDER_SUPPORT_ROOT)
    if not support_root.is_dir():
        return
    for path in sorted(support_root.glob("MPLog*.log"), key=lambda item: item.name.lower()):
        if not path.is_file():
            continue
        lines = read_lines(path, limit=400)
        interesting = [
            line
            for line in lines
            if any(token in line.lower() for token in ("threat", "malware", "quarantine", "exclusion", "remediation"))
        ][:25]
        stat_result = path.stat()
        validation_checks = {
            "log_readable": True,
            "interesting_entries_present": bool(interesting),
            "threat_or_quarantine_terms_present": any(
                any(token in line.lower() for token in ("threat", "malware", "quarantine"))
                for line in interesting
            ),
            "defender_eventlog_correlated": False,
            "mpcmdrun_history_correlated": False,
            "signature_version_validated": False,
        }
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="defender-support-log",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "text-log"),
                "entry_count": len(lines),
                "interesting_entry_count": len(interesting),
                "interesting_entries": interesting,
                "coverage_status": "defender-mplog-triage",
                "reportability": "triage",
                "parser_confidence": "medium",
                "validation_required": True,
                "validation_checks": validation_checks,
                "core_accuracy_gates": system_core_accuracy_gates(
                    "defender",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "validation_checks": validation_checks,
                        "interesting_entries": interesting,
                    },
                ),
                "system_validation_matrix": system_validation_matrix("defender", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("defender", validation_checks),
                "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
                "forensic_review": system_forensic_review(
                    "defender",
                    [f"entry_count={len(lines)}", f"interesting_entry_count={len(interesting)}"],
                    validation_checks,
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": SYSTEM_REPORT_GRADE_BLOCKERS,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "defender_support_log_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": "\n".join(lines[:5]),
            },
        )


def collect_firewall_logs(root: Path) -> Iterable[ArtifactRecord]:
    for parts in FIREWALL_LOG_PATHS:
        path = root.joinpath(*parts)
        if not path.is_file():
            continue
        rows = parse_firewall_log(path)
        stat_result = path.stat()
        validation_checks = {
            "w3c_fields_present": bool(rows),
            "blocked_entries_present": any(row.get("action", "").upper() == "DROP" for row in rows),
            "allowed_entries_present": any(row.get("action", "").upper() == "ALLOW" for row in rows),
            "firewall_rule_store_correlated": False,
            "firewall_policy_export_validated": False,
        }
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="firewall-log",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "w3c-log"),
                "entry_count": len(rows),
                "blocked_count": sum(1 for row in rows if row.get("action", "").upper() == "DROP"),
                "sample_entries": rows[:20],
                "coverage_status": "firewall-w3c-log-normalized",
                "reportability": "triage",
                "parser_confidence": "medium" if rows else "low",
                "validation_required": True,
                "validation_checks": validation_checks,
                "core_accuracy_gates": system_core_accuracy_gates(
                    "firewall",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": {"sha256": compute_sha256(path)},
                        "validation_checks": validation_checks,
                        "sample_entries": rows[:20],
                    },
                ),
                "system_validation_matrix": system_validation_matrix("firewall", validation_checks),
                "system_report_grade_assessment": system_report_grade_assessment("firewall", validation_checks),
                "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
                "forensic_review": system_forensic_review(
                    "firewall",
                    [
                        f"entry_count={len(rows)}",
                        f"blocked_count={sum(1 for row in rows if row.get('action', '').upper() == 'DROP')}",
                    ],
                    validation_checks,
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": SYSTEM_REPORT_GRADE_BLOCKERS,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "firewall_log_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": preview_text(path),
            },
        )


def collect_wer_reports(root: Path) -> Iterable[ArtifactRecord]:
    candidates: list[Path] = []
    programdata = root.joinpath(*WER_ROOTS[0])
    if programdata.is_dir():
        candidates.extend(path for path in programdata.rglob("Report.wer") if path.is_file())
    users = root / "Users"
    if users.is_dir():
        candidates.extend(path for path in users.rglob("Report.wer") if path.is_file() and "WER" in str(path))
    for path in sorted(set(candidates), key=lambda item: str(item).lower()):
        fields = parse_key_value_file(path)
        stat_result = path.stat()
        normalized = normalized_wer_report(path, fields)
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="wer-report",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "wer"),
                "event_type": fields.get("EventType", ""),
                "application": fields.get("AppName", fields.get("FriendlyEventName", "")),
                "module": fields.get("FaultModuleName", ""),
                "bucket": fields.get("Bucket", fields.get("Response.BucketId", "")),
                **normalized,
                "fields": fields,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "source_hashes": {"sha256": compute_sha256(path)},
                "raw_preview": preview_text(path),
            },
        )


def collect_wmi_repository(root: Path) -> Iterable[ArtifactRecord]:
    repository = root.joinpath(*WMI_REPOSITORY_ROOT)
    if not repository.is_dir():
        return
    for path in sorted((item for item in repository.rglob("*") if item.is_file()), key=lambda item: str(item).lower()):
        if path.name.upper() not in WMI_REPOSITORY_NAMES and path.suffix.upper() not in WMI_REPOSITORY_SUFFIXES:
            continue
        stat_result = path.stat()
        pivots = wmi_repository_pivots(path)
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="wmi-repository-file",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "wmi-repository"),
                "entry_name": path.name,
                "relative_repository_path": str(path.relative_to(repository)),
                "size": stat_result.st_size,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                "timestamp_source": "wmi_repository_modified_at",
                "source_hashes": {"sha256": compute_sha256(path)},
                **pivots,
                "note": "WMI repository file inventoried with bounded string pivots for persistence review; validate findings with a dedicated WMI repository parser.",
            },
        )


def collect_zone_identifier_ads(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*Zone.Identifier"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        match = ZONE_IDENTIFIER_PATTERN.match(path.name)
        target_name = match.group("target") if match else path.name
        fields = parse_key_value_file(path)
        stat_result = path.stat()
        yield ArtifactRecord(
            provider=WindowsSystemArtifactsProvider.name,
            artifact_type="zone-identifier",
            path=str(path.resolve()),
            supported=True,
            details={
                **source_details(path, "ini-ads-export"),
                "target_name": target_name,
                "zone_id": fields.get("ZoneId", ""),
                "referrer_url": fields.get("ReferrerUrl", ""),
                "host_url": fields.get("HostUrl", ""),
                "fields": fields,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                "raw_preview": preview_text(path),
            },
        )


def source_details(path: Path, source_format: str) -> dict[str, object]:
    return {
        "parser": "windows-system-artifacts",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_size": path.stat().st_size,
    }


def first_text(root: ET.Element, target_name: str) -> str:
    for element in root.iter():
        if local_name(element.tag) == target_name and element.text:
            return element.text.strip()
    return ""


def all_text(root: ET.Element, target_name: str) -> list[str]:
    values: list[str] = []
    for element in root.iter():
        if local_name(element.tag) == target_name and element.text:
            values.append(element.text.strip())
    return values


def find_children(root: ET.Element, target_name: str) -> list[ET.Element]:
    for element in root.iter():
        if local_name(element.tag) == target_name:
            return list(element)
    return []


def first_element(root: ET.Element, target_name: str) -> ET.Element | None:
    for element in root.iter():
        if local_name(element.tag) == target_name:
            return element
    return None


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def parse_bool_text(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def task_scheduler_risk_flags(command: str, arguments: str, working_directory: str, uri: str) -> list[str]:
    haystack = " ".join((command, arguments, working_directory, uri)).lower()
    flags: list[str] = []
    for term in TASK_SUSPICIOUS_TERMS:
        if term in haystack:
            flags.append(f"task-string:{term.strip('-').replace('://', '')}")
    normalized_command = command.strip().lower().replace("/", "\\").rsplit("\\", 1)[-1]
    if normalized_command in TASK_LOLBINS:
        flags.append(f"task-lolbin:{normalized_command}")
    if any(term in haystack for term in TASK_USER_WRITABLE_PATH_TERMS):
        flags.append("task-user-writable-path")
    if uri.lower().startswith(r"\microsoft\windows") and "task-user-writable-path" in flags:
        flags.append("task-microsoft-path-user-payload")
    return unique_preserve_order(flags)


def task_action_details(root: ET.Element) -> list[dict[str, object]]:
    actions_element = first_element(root, "Actions")
    if actions_element is None:
        return []
    context = actions_element.attrib.get("Context", "")
    actions: list[dict[str, object]] = []
    for action in list(actions_element):
        action_type = local_name(action.tag)
        command = first_text(action, "Command")
        arguments = first_text(action, "Arguments")
        working_directory = first_text(action, "WorkingDirectory")
        actions.append(
            {
                "action_type": action_type,
                "context": context,
                "command": command,
                "arguments": arguments,
                "working_directory": working_directory,
                "command_line": " ".join(item for item in (command, arguments) if item).strip(),
                "executable_name": windows_executable_name(command),
                "path_category": windows_path_category(command, " ".join((arguments, working_directory))),
            }
        )
    return actions


def task_trigger_details(root: ET.Element) -> list[dict[str, object]]:
    triggers_element = first_element(root, "Triggers")
    if triggers_element is None:
        return []
    details: list[dict[str, object]] = []
    for trigger in list(triggers_element):
        details.append(
            {
                "trigger_type": local_name(trigger.tag),
                "enabled": parse_bool_text(first_text(trigger, "Enabled")),
                "start_boundary": first_text(trigger, "StartBoundary"),
                "end_boundary": first_text(trigger, "EndBoundary"),
                "subscription": first_text(trigger, "Subscription"),
                "delay": first_text(trigger, "Delay"),
            }
        )
    return details


def task_principal_details(root: ET.Element) -> list[dict[str, str]]:
    principals_element = first_element(root, "Principals")
    if principals_element is None:
        return []
    principals: list[dict[str, str]] = []
    for principal in list(principals_element):
        principals.append(
            {
                "id": principal.attrib.get("id", ""),
                "user_id": first_text(principal, "UserId"),
                "group_id": first_text(principal, "GroupId"),
                "run_level": first_text(principal, "RunLevel"),
                "logon_type": first_text(principal, "LogonType"),
            }
        )
    return principals


def normalized_task_action(command: str, arguments: str, working_directory: str) -> dict[str, str]:
    return {
        "command": command,
        "arguments": arguments,
        "working_directory": working_directory,
        "command_line": " ".join(item for item in (command, arguments) if item).strip(),
        "executable_name": windows_executable_name(command),
        "path_category": windows_path_category(command, " ".join((arguments, working_directory))),
    }


def task_scheduler_validation_checks(
    *,
    command: str,
    arguments: str,
    working_directory: str,
    uri: str,
    risk_flags: list[str],
    trigger_details: list[dict[str, object]],
    action_details: list[dict[str, object]],
    principal_details: list[dict[str, str]],
) -> dict[str, object]:
    haystack = " ".join((command, arguments, working_directory)).lower()
    return {
        "xml_parsed": True,
        "has_task_uri": bool(uri),
        "has_exec_action": any(action.get("action_type") == "Exec" for action in action_details),
        "has_command": bool(command),
        "has_arguments": bool(arguments),
        "has_trigger": bool(trigger_details),
        "has_principal": bool(principal_details),
        "microsoft_namespace": uri.lower().startswith(r"\microsoft\windows"),
        "command_uses_lolbin": any(flag.startswith("task-lolbin:") for flag in risk_flags),
        "references_user_writable_path": any(term in haystack for term in TASK_USER_WRITABLE_PATH_TERMS),
        "taskcache_registry_validated": False,
        "security_descriptor_validated": False,
        "task_history_events_correlated": False,
    }


def system_validation_matrix(artifact_family: str, checks: dict[str, object]) -> list[dict[str, object]]:
    base = [
        {
            "id": f"{artifact_family}-source-parsed",
            "label": "Source artifact parsed into normalized triage fields",
            "passed": True,
            "severity": "medium",
        },
    ]
    if artifact_family == "task-scheduler":
        base.extend(
            [
                {
                    "id": "task-exec-action",
                    "label": "Task XML has an executable action and command pivot",
                    "passed": bool(checks.get("has_exec_action") and checks.get("has_command")),
                    "severity": "high",
                },
                {
                    "id": "task-report-grade-correlation",
                    "label": "TaskCache registry, security descriptor, and TaskScheduler event history correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "defender":
        base.extend(
            [
                {
                    "id": "defender-interesting-entries",
                    "label": "Defender support log contains triage-worthy threat/quarantine/exclusion lines",
                    "passed": bool(checks.get("interesting_entries_present")),
                    "severity": "medium",
                },
                {
                    "id": "defender-report-grade-correlation",
                    "label": "Defender EVTX, MpCmdRun, quarantine metadata, and signature versions correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "firewall":
        base.extend(
            [
                {
                    "id": "firewall-w3c-rows",
                    "label": "Firewall W3C rows parsed",
                    "passed": bool(checks.get("w3c_fields_present")),
                    "severity": "medium",
                },
                {
                    "id": "firewall-report-grade-correlation",
                    "label": "Firewall policy/rule store and event-log context correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "wer":
        base.extend(
            [
                {
                    "id": "wer-core-fields",
                    "label": "WER report has application, exception, identifier, and event-time pivots",
                    "passed": bool(
                        checks.get("has_application")
                        and checks.get("has_exception_code")
                        and checks.get("has_report_identifier")
                    ),
                    "severity": "high",
                },
                {
                    "id": "wer-report-grade-correlation",
                    "label": "Dump files, CAB metadata, queue/archive state, and event logs correlated",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    elif artifact_family == "wmi":
        base.extend(
            [
                {
                    "id": "wmi-persistence-pivots",
                    "label": "WMI repository string pivots include persistence terms or path/URL pivots",
                    "passed": bool(
                        checks.get("persistence_terms_present") or checks.get("path_or_url_pivots_present")
                    ),
                    "severity": "high",
                },
                {
                    "id": "wmi-native-report-grade",
                    "label": "Native WMI repository namespaces/classes/consumer-filter bindings decoded",
                    "passed": False,
                    "severity": "critical",
                },
            ]
        )
    return base


def system_report_grade_assessment(artifact_family: str, checks: dict[str, object]) -> dict[str, object]:
    matrix = system_validation_matrix(artifact_family, checks)
    failed = [item for item in matrix if not item["passed"]]
    family_blockers = {
        "task-scheduler": [
            "task-cache-registry-correlation-not-implemented",
            "task-security-descriptor-validation-not-implemented",
            "task-history-event-correlation-not-implemented",
        ],
        "defender": ["defender-event-and-mpcmdrun-correlation-not-implemented"],
        "firewall": ["firewall-rule-store-correlation-not-implemented"],
        "wer": list(WER_REPORT_GRADE_BLOCKERS),
        "wmi": ["native-wmi-repository-decoding-not-implemented"],
    }
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#18"],
        "artifact_family": artifact_family,
        "failed_check_ids": [str(item["id"]) for item in failed],
        "blockers": family_blockers.get(artifact_family, SYSTEM_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Correlate this artifact family with EVTX, registry hives, filesystem timeline, and known-answer fixtures.",
            "Do not present this row as standalone report-grade attribution until failed critical checks are resolved.",
        ],
    }


def system_core_accuracy_gates(artifact_family: str, details: dict[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), dict) else {}
    evidence_refs = [f"source_path:{details.get('source_path', '')}", f"family:{artifact_family}"]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if details.get("risk_flags") or checks.get("interesting_entries_present") or checks.get("blocked_entries_present") or checks.get("persistence_terms_present"):
        satisfied.append("event semantics and risk rules")
    if artifact_family == "task-scheduler" and checks.get("taskcache_registry_validated"):
        satisfied.append("Task XML/TaskCache correlation")
    if artifact_family in {"defender", "firewall"} and (details.get("interesting_entries") or details.get("sample_entries")):
        satisfied.append("Defender/Firewall field normalization")
    if artifact_family == "wer" and checks.get("dump_file_correlated") and checks.get("cab_metadata_validated"):
        satisfied.append("WER dump/cab linkage")
    if artifact_family == "wmi" and checks.get("consumer_filter_binding_reconstructed"):
        satisfied.append("WMI consumer/filter binding validation")
    return [build_accuracy_gate(18, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def system_forensic_review(
    artifact_family: str,
    primary_evidence: list[str],
    validation_checks: dict[str, object],
) -> dict[str, object]:
    return build_forensic_review(
        gap_id="#18",
        artifact_goal=f"Windows {artifact_family} artifact semantics, risk rules, and correlation evidence",
        primary_evidence=primary_evidence,
        validation_required=True,
        report_grade_assessment=system_report_grade_assessment(artifact_family, validation_checks),
        blockers=SYSTEM_REPORT_GRADE_BLOCKERS,
        caveats=[
            "This row is triage-grade until correlated with EVTX, registry, filesystem timeline, and known-answer fixtures.",
            "Report conclusions should cite the source hash and unresolved critical validation checks.",
        ],
    )


def windows_executable_name(command: str) -> str:
    cleaned = command.strip().strip('"').strip("'")
    if not cleaned:
        return ""
    return cleaned.replace("/", "\\").rsplit("\\", 1)[-1]


def windows_path_category(command: str, working_directory: str = "") -> str:
    haystack = " ".join((command, working_directory)).lower().replace("/", "\\")
    if any(term in haystack for term in TASK_USER_WRITABLE_PATH_TERMS):
        return "user-writable"
    if "\\windows\\system32\\" in haystack or haystack.startswith(r"c:\windows\system32\\"):
        return "windows-system32"
    if "\\" not in command and "/" not in command:
        return "path-search"
    return "other"


def normalized_wer_report(path: Path, fields: dict[str, str]) -> dict[str, object]:
    app_name = first_field(fields, "AppName", "ApplicationName", "Sig[0].Value", "FriendlyEventName")
    module_name = first_field(fields, "FaultModuleName", "FaultingModule", "Sig[3].Value")
    exception_code = first_field(fields, "ExceptionCode", "Exception Code", "Sig[6].Value")
    event_time_raw = first_field(fields, "EventTime", "ReportTime")
    event_time = wer_time_to_iso(event_time_raw)
    report_id = first_field(fields, "ReportIdentifier", "ReportId", "CabId") or path.parent.name
    bucket = first_field(fields, "Bucket", "Response.BucketId", "BucketId")
    validation_checks = {
        "has_event_type": bool(first_field(fields, "EventType")),
        "has_application": bool(app_name),
        "has_fault_module": bool(module_name),
        "has_exception_code": bool(exception_code),
        "has_bucket": bool(bucket),
        "has_report_identifier": bool(report_id),
        "has_event_time": bool(event_time),
        "dump_file_correlated": False,
        "cab_metadata_validated": False,
        "reportqueue_state_validated": False,
    }
    return {
        "coverage_status": "wer-key-value-normalized",
        "reportability": "triage",
        "evidence_strength": "application-fault-report",
        "parser_confidence": "high" if app_name and first_field(fields, "EventType") else "medium",
        "report_id": report_id,
        "report_store": wer_report_store(path),
        "application_name": app_name,
        "application_path": first_field(fields, "ApplicationPath", "AppPath", "TargetAppId"),
        "fault_module_name": module_name,
        "fault_module_path": first_field(fields, "FaultModulePath", "ModulePath"),
        "exception_code": exception_code,
        "event_time": event_time,
        "timestamp": event_time or "",
        "timestamp_source": "wer_event_time" if event_time else "missing_wer_event_time",
        "bucket_id": bucket,
        "cab_id": first_field(fields, "CabId"),
        "problem_signature": wer_problem_signature(fields),
        "validation_required": True,
        "validation_checks": validation_checks,
        "core_accuracy_gates": system_core_accuracy_gates(
            "wer",
            {
                "source_path": str(path.resolve()),
                "source_hashes": {"sha256": compute_sha256(path)},
                "validation_checks": validation_checks,
                "report_id": report_id,
                "problem_signature": wer_problem_signature(fields),
            },
        ),
        "system_validation_matrix": system_validation_matrix("wer", validation_checks),
        "system_report_grade_assessment": system_report_grade_assessment("wer", validation_checks),
        "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
        "forensic_review": system_forensic_review(
            "wer",
            [
                f"application={app_name}",
                f"fault_module={module_name}",
                f"exception_code={exception_code}",
                f"report_id={report_id}",
            ],
            validation_checks,
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": WER_REPORT_GRADE_BLOCKERS,
        "validation_guidance": (
            "Report.wer key/value fields are normalized for triage. Correlate dumps, ReportQueue/ReportArchive state, "
            "cab metadata, and application/event-log timelines before report-grade crash attribution."
        ),
    }


def first_field(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(name, "")
        if value:
            return value
    return ""


def wer_problem_signature(fields: dict[str, str]) -> list[dict[str, str]]:
    signatures: list[dict[str, str]] = []
    for index in range(10):
        name = fields.get(f"Sig[{index}].Name", "")
        value = fields.get(f"Sig[{index}].Value", "")
        if name or value:
            signatures.append({"name": name, "value": value})
    return signatures


def wer_report_store(path: Path) -> str:
    lowered = [part.lower() for part in path.parts]
    for store in ("reportarchive", "reportqueue", "reporttemp"):
        if store in lowered:
            return store
    if "users" in lowered:
        return "user-wer"
    return "unknown"


def wer_time_to_iso(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        return ""
    if cleaned.isdigit():
        try:
            number = int(cleaned)
        except ValueError:
            return ""
        if number > 10_000_000_000:
            try:
                base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
                return (base + dt.timedelta(microseconds=number // 10)).isoformat()
            except (OverflowError, ValueError):
                return ""
        return isoformat_from_timestamp(number) or ""
    try:
        parsed = dt.datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat()


def unique_preserve_order(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def read_lines(path: Path, *, limit: int) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()[:limit]


def preview_text(path: Path, *, limit: int = 600) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def parse_firewall_log(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    fields: list[str] = []
    for line in read_lines(path, limit=500):
        if line.startswith("#Fields:"):
            fields = line.removeprefix("#Fields:").strip().split()
            continue
        if not line or line.startswith("#") or not fields:
            continue
        values = line.split()
        rows.append(dict(zip(fields, values)))
    return rows


def parse_key_value_file(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in read_lines(path, limit=300):
        stripped = line.strip()
        if not stripped or stripped.startswith("[") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


def wmi_repository_pivots(path: Path) -> dict[str, object]:
    blob = read_prefix(path, WMI_SCAN_LIMIT)
    strings = unique_strings([*extract_ascii_strings(blob), *extract_utf16_strings(blob)])
    interesting = [
        value
        for value in strings
        if any(term in value.lower() for term in WMI_PERSISTENCE_TERMS)
    ][:50]
    path_candidates = regex_candidates(strings, WINDOWS_PATH_RE)[:50]
    url_candidates = regex_candidates(strings, URL_RE)[:50]
    risk_flags = [f"wmi-string:{term}" for term in WMI_PERSISTENCE_TERMS if any(term in value.lower() for value in strings)]
    validation_checks = {
        "repository_file_readable": bool(blob),
        "bounded_strings_extracted": bool(strings),
        "persistence_terms_present": bool(interesting),
        "path_or_url_pivots_present": bool(path_candidates or url_candidates),
        "native_wmi_repository_decoded": False,
        "consumer_filter_binding_reconstructed": False,
    }
    return {
        "coverage_status": "bounded-string-pivot",
        "scan_bytes": len(blob),
        "extracted_string_count": len(strings),
        "interesting_strings": interesting,
        "path_candidates": path_candidates,
        "url_candidates": url_candidates,
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 15),
        "reportability": "triage",
        "parser_confidence": "medium" if interesting else "low",
        "validation_required": True,
        "validation_checks": validation_checks,
        "core_accuracy_gates": system_core_accuracy_gates(
            "wmi",
            {
                "source_path": str(path.resolve()),
                "source_hashes": {"sha256": compute_sha256(path)},
                "validation_checks": validation_checks,
                "interesting_strings": interesting,
                "path_candidates": path_candidates,
                "url_candidates": url_candidates,
            },
        ),
        "system_validation_matrix": system_validation_matrix("wmi", validation_checks),
        "system_report_grade_assessment": system_report_grade_assessment("wmi", validation_checks),
        "system_native_capabilities": dict(SYSTEM_NATIVE_CAPABILITIES),
        "forensic_review": system_forensic_review(
            "wmi",
            [
                f"interesting_strings={len(interesting)}",
                f"path_candidates={len(path_candidates)}",
                f"url_candidates={len(url_candidates)}",
            ],
            validation_checks,
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": SYSTEM_REPORT_GRADE_BLOCKERS,
        "recommended_parsers": ["PyWMIPersistenceFinder", "python-cim", "Velociraptor WMI artifacts"],
    }


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def extract_ascii_strings(blob: bytes, *, min_chars: int = 5) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_chars:
            strings.append(current.decode("ascii", errors="ignore"))
        current.clear()
    if len(current) >= min_chars:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def extract_utf16_strings(blob: bytes, *, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    for start in (0, 1):
        current = bytearray()
        for index in range(start, len(blob) - 1, 2):
            value = int.from_bytes(blob[index : index + 2], "little", signed=False)
            if 32 <= value <= 126:
                current.extend(blob[index : index + 2])
                continue
            if len(current) >= min_chars * 2:
                strings.append(current.decode("utf-16le", errors="ignore").strip())
            current.clear()
        if len(current) >= min_chars * 2:
            strings.append(current.decode("utf-16le", errors="ignore").strip())
    return strings


def unique_strings(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = " ".join(value.split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
        if len(unique) >= 500:
            break
    return unique


def regex_candidates(strings: list[str], pattern: re.Pattern[str]) -> list[str]:
    candidates: list[str] = []
    for value in strings:
        for match in pattern.finditer(value):
            candidate = match.group(0).rstrip(".,);]")
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates
