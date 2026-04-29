from __future__ import annotations

import csv
import datetime as dt
import hashlib
import html
import json
import re
import struct
import xml.etree.ElementTree as ET
import zlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Mapping, NamedTuple, Sequence

from ...core.models import ArtifactRecord

EVENT_LOG_ROOT = ("Windows", "System32", "winevt", "Logs")
PARSER_VERSION = "eventlog-normalized-v14"
BUILTIN_RULEPACK_VERSION = "eventlog-builtin-rules-v1"
EVENT_EXPORT_SUFFIXES = {".xml", ".json", ".jsonl", ".ndjson", ".csv"}
EVENT_EXPORT_HINTS = ("event", "evtx", "hayabusa", "chainsaw", "winevt", "winlog")
EVTX_FILE_SIGNATURE = b"ElfFile\x00"
EVTX_CHUNK_SIGNATURE = b"ElfChnk\x00"
EVTX_FILE_HEADER_SIZE = 4096
EVTX_CHUNK_SIZE = 65536
EVTX_CHUNK_HEADER_SIZE = 512
EVTX_RECORD_MAGIC = b"**\x00\x00"
EVTX_RECORD_HEADER_SIZE = 24
MAX_NATIVE_EVTX_RECORDS = 10_000
MAX_NATIVE_EVTX_CHUNKS = 4096
MAX_NATIVE_EVTX_RECORD_SIZE = 16 * 1024 * 1024
MAX_NATIVE_EVTX_STRINGS = 200
MAX_NATIVE_EVTX_BINXML_TOKENS = 500
NATIVE_EVTX_PARSE_SCOPE = "record-header-binxml-template-scalar-recovery-triage"
NATIVE_EVTX_BINXML_STATUS = "not-decoded"
NATIVE_EVTX_REPORT_GRADE_BLOCKERS = [
    "provider-message-resource-rendering-not-implemented",
    "full-binxml-object-model-not-implemented",
    "broad-deleted-corrupt-record-corpus-validation-required",
    "chunk-crc-algorithm-variant-validation-required",
]
NATIVE_EVTX_CAPABILITIES = {
    "record_header": True,
    "file_header": True,
    "chunk_header": True,
    "chunk_boundary_context": True,
    "record_size_trailer_validation": True,
    "deleted_slack_candidate_labeling": True,
    "binxml_fragment_token_scan": True,
    "template_instance_header": True,
    "template_substitution_values": True,
    "provider_resource_message_rendering": False,
    "full_binxml_dom": False,
    "report_grade_deleted_record_validation": False,
    "validated_value_types": [
        "StringType",
        "AnsiStringType",
        "Int8Type",
        "UInt8Type",
        "Int16Type",
        "UInt16Type",
        "Int32Type",
        "UInt32Type",
        "Int64Type",
        "UInt64Type",
        "Real32Type",
        "Real64Type",
        "BoolType",
        "BinaryType",
        "GuidType",
        "FileTimeType",
        "SysTimeType",
        "SidType",
        "HexInt32Type",
        "HexInt64Type",
    ],
}

EVENT_ID_CATEGORIES = {
    "4624": ("logon-success", "Authentication success"),
    "4625": ("logon-failure", "Authentication failure"),
    "4634": ("logoff", "Account logoff"),
    "4647": ("user-initiated-logoff", "User initiated logoff"),
    "4648": ("explicit-credential-logon", "Explicit credential logon"),
    "4616": ("system-time-changed", "System time changed"),
    "4672": ("privileged-logon", "Special privileges assigned to new logon"),
    "4688": ("process-created", "Process creation"),
    "4697": ("service-installed", "Service installed"),
    "4698": ("scheduled-task-created", "Scheduled task created"),
    "4699": ("scheduled-task-deleted", "Scheduled task deleted"),
    "4700": ("scheduled-task-enabled", "Scheduled task enabled"),
    "4701": ("scheduled-task-disabled", "Scheduled task disabled"),
    "4702": ("scheduled-task-updated", "Scheduled task updated"),
    "4719": ("audit-policy-changed", "System audit policy changed"),
    "4720": ("user-created", "User account created"),
    "4722": ("user-enabled", "User account enabled"),
    "4724": ("password-reset", "Password reset attempted"),
    "4725": ("user-disabled", "User account disabled"),
    "4726": ("user-deleted", "User account deleted"),
    "4728": ("group-member-added", "Member added to global group"),
    "4732": ("local-group-member-added", "Member added to local group"),
    "4738": ("user-changed", "User account changed"),
    "4739": ("domain-policy-changed", "Domain policy changed"),
    "4740": ("account-locked", "User account locked"),
    "4741": ("computer-created", "Computer account created"),
    "4756": ("universal-group-member-added", "Member added to universal group"),
    "4768": ("kerberos-tgt-request", "Kerberos TGT request"),
    "4769": ("kerberos-service-ticket", "Kerberos service ticket request"),
    "4771": ("kerberos-preauth-failure", "Kerberos pre-authentication failed"),
    "4776": ("credential-validation", "Credential validation"),
    "4778": ("rdp-session-reconnected", "Remote session reconnected"),
    "4779": ("rdp-session-disconnected", "Remote session disconnected"),
    "4800": ("workstation-locked", "Workstation locked"),
    "4801": ("workstation-unlocked", "Workstation unlocked"),
    "5140": ("network-share-accessed", "Network share object accessed"),
    "5145": ("network-share-detailed-access", "Detailed file share access checked"),
    "5156": ("firewall-connection-allowed", "Windows Filtering Platform permitted connection"),
    "5158": ("firewall-bind-allowed", "Windows Filtering Platform permitted bind"),
    "6416": ("external-device-recognized", "External device recognized"),
    "1102": ("audit-log-cleared", "Audit log cleared"),
    "104": ("system-log-cleared", "Event log cleared"),
    "106": ("scheduled-task-registered", "Task Scheduler task registered"),
    "140": ("scheduled-task-updated", "Task Scheduler task updated"),
    "141": ("scheduled-task-deleted", "Task Scheduler task deleted"),
    "200": ("scheduled-task-started", "Task Scheduler action started"),
    "201": ("scheduled-task-completed", "Task Scheduler action completed"),
    "1149": ("rdp-authentication-succeeded", "Terminal Services user authentication succeeded"),
    "21": ("rdp-session-logon", "Terminal Services session logon"),
    "24": ("rdp-session-disconnected", "Terminal Services session disconnected"),
    "25": ("rdp-session-reconnected", "Terminal Services session reconnected"),
    "1116": ("defender-malware-detected", "Microsoft Defender malware detected"),
    "1117": ("defender-remediation-action", "Microsoft Defender remediation action"),
    "5007": ("defender-config-changed", "Microsoft Defender configuration changed"),
    "2004": ("firewall-rule-added", "Windows Firewall rule added"),
    "2005": ("firewall-rule-modified", "Windows Firewall rule modified"),
    "2006": ("firewall-rule-deleted", "Windows Firewall rule deleted"),
    "5857": ("wmi-activity", "WMI provider started"),
    "5858": ("wmi-activity-error", "WMI activity error"),
    "5861": ("wmi-permanent-event", "WMI permanent event consumer activity"),
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

HIGH_RISK_EVENT_IDS = {
    "1102",
    "104",
    "4672",
    "4697",
    "4698",
    "4719",
    "4720",
    "4724",
    "4726",
    "4728",
    "4732",
    "4756",
    "7045",
    "4104",
    "1116",
    "5007",
    "5861",
}
EVENT_FAMILY_BY_CATEGORY = {
    "logon-success": "authentication",
    "logon-failure": "authentication",
    "logoff": "authentication",
    "user-initiated-logoff": "authentication",
    "explicit-credential-logon": "authentication",
    "privileged-logon": "authentication",
    "rdp-authentication-succeeded": "remote-access",
    "rdp-session-logon": "remote-access",
    "rdp-session-reconnected": "remote-access",
    "rdp-session-disconnected": "remote-access",
    "process-created": "execution",
    "powershell-module": "execution",
    "powershell-script-block": "execution",
    "sysmon-process-created": "execution",
    "service-installed": "persistence",
    "scheduled-task-created": "persistence",
    "scheduled-task-updated": "persistence",
    "scheduled-task-deleted": "persistence",
    "scheduled-task-registered": "persistence",
    "scheduled-task-started": "execution",
    "scheduled-task-completed": "execution",
    "audit-log-cleared": "defense-evasion",
    "system-log-cleared": "defense-evasion",
    "audit-policy-changed": "defense-evasion",
    "defender-config-changed": "defense-evasion",
    "user-created": "account-management",
    "user-enabled": "account-management",
    "user-disabled": "account-management",
    "user-deleted": "account-management",
    "password-reset": "account-management",
    "group-member-added": "account-management",
    "local-group-member-added": "account-management",
    "universal-group-member-added": "account-management",
    "computer-created": "account-management",
    "kerberos-preauth-failure": "authentication",
    "credential-validation": "authentication",
    "sysmon-network-connection": "network",
    "sysmon-dns-query": "network",
    "firewall-connection-allowed": "network",
    "firewall-bind-allowed": "network",
    "firewall-rule-added": "network",
    "firewall-rule-modified": "network",
    "firewall-rule-deleted": "network",
    "network-share-accessed": "file-share",
    "network-share-detailed-access": "file-share",
    "external-device-recognized": "device",
    "defender-malware-detected": "malware",
    "defender-remediation-action": "malware",
    "wmi-activity": "wmi",
    "wmi-activity-error": "wmi",
    "wmi-permanent-event": "persistence",
    "sysmon-registry-value-set": "registry",
    "sysmon-image-loaded": "execution",
}
CHANNEL_FAMILY_HINTS = (
    ("powershell", "powershell"),
    ("sysmon", "sysmon"),
    ("terminalservices", "remote-access"),
    ("remoteconnectionmanager", "remote-access"),
    ("localsessionmanager", "remote-access"),
    ("taskscheduler", "persistence"),
    ("defender", "defender"),
    ("firewall", "firewall"),
    ("wmi-activity", "wmi"),
    ("security", "security"),
    ("system", "system"),
    ("application", "application"),
)
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
    {
        "id": "RT-EVTX-EXPLICIT-CREDS",
        "title": "Explicit credential logon",
        "level": "medium",
        "event_ids": {"4648"},
        "categories": {"explicit-credential-logon"},
        "mitre_tags": ["attack.credential-access", "attack.lateral-movement"],
        "risk_flags": ["explicit-credentials"],
        "description": "A process used explicit credentials; review target server, account, and nearby process activity.",
    },
    {
        "id": "RT-EVTX-SUSPICIOUS-PROCESS",
        "title": "Suspicious process creation command",
        "level": "high",
        "event_ids": {"4688", "1"},
        "categories": {"process-created", "sysmon-process-created"},
        "terms": {"rundll32", "regsvr32", "wmic", "bitsadmin", "certutil", "procdump"},
        "mitre_tags": ["attack.execution", "attack.defense-evasion"],
        "risk_flags": ["suspicious-process-command"],
        "description": "Process creation text includes common living-off-the-land or credential-access tooling.",
    },
    {
        "id": "RT-EVTX-ACCOUNT-DELETED",
        "title": "Windows account deleted",
        "level": "medium",
        "event_ids": {"4726"},
        "categories": {"user-deleted"},
        "mitre_tags": ["attack.impact"],
        "risk_flags": ["account-deleted"],
        "description": "A user account was deleted; validate expected administration and adjacent logon activity.",
    },
    {
        "id": "RT-EVTX-ACCOUNT-DISABLED",
        "title": "Windows account disabled",
        "level": "low",
        "event_ids": {"4725"},
        "categories": {"user-disabled"},
        "mitre_tags": ["attack.impact"],
        "risk_flags": ["account-disabled"],
        "description": "A user account was disabled; useful for account lifecycle reconstruction.",
    },
    {
        "id": "RT-EVTX-PASSWORD-RESET",
        "title": "Password reset attempted",
        "level": "medium",
        "event_ids": {"4724"},
        "categories": {"password-reset"},
        "mitre_tags": ["attack.persistence", "attack.credential-access"],
        "risk_flags": ["password-reset"],
        "description": "A password reset was attempted; inspect subject account and target account.",
    },
    {
        "id": "RT-EVTX-ACCOUNT-LOCKED",
        "title": "Account lockout",
        "level": "low",
        "event_ids": {"4740"},
        "categories": {"account-locked"},
        "mitre_tags": ["attack.credential-access", "attack.t1110"],
        "risk_flags": ["account-lockout"],
        "description": "An account lockout occurred; correlate with failed logons by source host/account.",
    },
    {
        "id": "RT-EVTX-KERBEROS-PREAUTH-FAIL",
        "title": "Kerberos pre-authentication failure",
        "level": "low",
        "event_ids": {"4771"},
        "categories": {"kerberos-preauth-failure"},
        "mitre_tags": ["attack.credential-access", "attack.t1110"],
        "risk_flags": ["kerberos-preauth-failure"],
        "description": "Kerberos pre-authentication failed; correlate repeated failures by client and account.",
    },
    {
        "id": "RT-EVTX-SYSTEM-TIME-CHANGED",
        "title": "System time changed",
        "level": "medium",
        "event_ids": {"4616"},
        "categories": {"system-time-changed"},
        "mitre_tags": ["attack.defense-evasion"],
        "risk_flags": ["system-time-change"],
        "description": "System time changed; validate expected time synchronization versus timestomping or log confusion.",
    },
    {
        "id": "RT-EVTX-AUDIT-POLICY-CHANGED",
        "title": "Audit policy changed",
        "level": "high",
        "event_ids": {"4719"},
        "categories": {"audit-policy-changed"},
        "mitre_tags": ["attack.defense-evasion"],
        "risk_flags": ["audit-policy-change"],
        "description": "Audit policy changed; review whether logging was weakened or redirected.",
    },
    {
        "id": "RT-EVTX-RDP-SESSION",
        "title": "Terminal Services RDP session activity",
        "level": "medium",
        "event_ids": {"1149", "21", "22", "24", "25", "4778", "4779"},
        "categories": {
            "rdp-authentication-succeeded",
            "rdp-session-logon",
            "rdp-session-reconnected",
            "rdp-session-disconnected",
        },
        "mitre_tags": ["attack.lateral-movement", "attack.t1021.001"],
        "risk_flags": ["rdp-session-activity"],
        "description": "RDP session activity was observed; pivot by user, host, and source address.",
    },
    {
        "id": "RT-EVTX-WMI-ACTIVITY",
        "title": "WMI activity of interest",
        "level": "medium",
        "event_ids": {"5857", "5858", "5861"},
        "categories": {"wmi-activity", "wmi-activity-error", "wmi-permanent-event"},
        "mitre_tags": ["attack.execution", "attack.persistence", "attack.t1047"],
        "risk_flags": ["wmi-activity"],
        "description": "WMI provider or permanent consumer activity observed; inspect query/consumer details.",
    },
    {
        "id": "RT-EVTX-DEFENDER-DETECTION",
        "title": "Microsoft Defender malware detection",
        "level": "high",
        "event_ids": {"1116", "1117"},
        "categories": {"defender-malware-detected", "defender-remediation-action"},
        "mitre_tags": ["attack.execution"],
        "risk_flags": ["defender-detection"],
        "description": "Defender reported malware detection/remediation; preserve threat name, path, and action.",
    },
    {
        "id": "RT-EVTX-DEFENDER-CONFIG",
        "title": "Microsoft Defender configuration changed",
        "level": "medium",
        "event_ids": {"5007"},
        "categories": {"defender-config-changed"},
        "mitre_tags": ["attack.defense-evasion"],
        "risk_flags": ["defender-config-change"],
        "description": "Defender configuration changed; inspect exclusions, disabled features, and responsible process/user.",
    },
    {
        "id": "RT-EVTX-FIREWALL-RULE-CHANGE",
        "title": "Windows Firewall rule changed",
        "level": "medium",
        "event_ids": {"2004", "2005", "2006"},
        "categories": {"firewall-rule-added", "firewall-rule-modified", "firewall-rule-deleted"},
        "mitre_tags": ["attack.defense-evasion", "attack.command-and-control"],
        "risk_flags": ["firewall-rule-change"],
        "description": "A firewall rule was added, modified, or deleted; inspect application, direction, and port.",
    },
    {
        "id": "RT-EVTX-USB-DEVICE",
        "title": "External device recognized",
        "level": "info",
        "event_ids": {"6416"},
        "categories": {"external-device-recognized"},
        "mitre_tags": ["attack.exfiltration"],
        "risk_flags": ["external-device"],
        "description": "An external device was recognized; correlate with USB registry and file access artifacts.",
    },
    {
        "id": "RT-EVTX-SHARE-ACCESS",
        "title": "Network share access",
        "level": "info",
        "event_ids": {"5140", "5145"},
        "categories": {"network-share-accessed", "network-share-detailed-access"},
        "mitre_tags": ["attack.collection", "attack.lateral-movement"],
        "risk_flags": ["network-share-access"],
        "description": "Network share access was observed; pivot by share, relative path, user, and source address.",
    },
    {
        "id": "RT-EVTX-SYSMON-DNS",
        "title": "Sysmon DNS query",
        "level": "info",
        "event_ids": {"22"},
        "categories": {"sysmon-dns-query"},
        "mitre_tags": ["attack.command-and-control"],
        "risk_flags": ["sysmon-dns"],
        "description": "Sysmon DNS query observed; correlate query name with process and network connections.",
    },
    {
        "id": "RT-EVTX-SYSMON-REGISTRY",
        "title": "Sysmon registry value set",
        "level": "medium",
        "event_ids": {"13"},
        "categories": {"sysmon-registry-value-set"},
        "mitre_tags": ["attack.persistence", "attack.defense-evasion"],
        "risk_flags": ["sysmon-registry"],
        "description": "Sysmon registry value set event observed; inspect target object and process.",
    },
    {
        "id": "RT-EVTX-SYSMON-IMAGELOAD",
        "title": "Sysmon image load",
        "level": "info",
        "event_ids": {"7"},
        "categories": {"sysmon-image-loaded"},
        "terms": {"\\temp\\", "appdata", "rundll32", "regsvr32"},
        "mitre_tags": ["attack.defense-evasion"],
        "risk_flags": ["sysmon-image-load-interest"],
        "description": "Sysmon image load contains location/process hints that may deserve review.",
    },
    {
        "id": "RT-EVTX-VSC-DELETION",
        "title": "Volume shadow copy deletion command",
        "level": "critical",
        "event_ids": {"4103", "4104", "4688", "1"},
        "categories": {"powershell-module", "powershell-script-block", "process-created", "sysmon-process-created"},
        "terms": {"vssadmin delete shadows"},
        "mitre_tags": ["attack.impact", "attack.t1490"],
        "risk_flags": ["vsc-deletion-command"],
        "description": "Command text indicates volume shadow copy deletion; correlate with VSC deltas and ransomware indicators.",
    },
)

RULE_LEVEL_SCORES = {"info": 15, "low": 25, "medium": 45, "high": 70, "critical": 90}

EVENT_MESSAGE_TEMPLATES = {
    "4624": "An account successfully logged on. User={TargetUserName|SubjectUserName}; logon_type={LogonType}; source={IpAddress|SourceAddress|SourceIp|SourceNetworkAddress}.",
    "4625": "An account failed to log on. User={TargetUserName|SubjectUserName}; status={Status|SubStatus|ErrorCode}; source={IpAddress|SourceAddress|SourceIp|SourceNetworkAddress}.",
    "4648": "A logon used explicit credentials. Account={SubjectUserName|TargetUserName}; target={TargetServerName|TargetInfo}; process={ProcessName}.",
    "4688": "A process was created. Process={NewProcessName|ProcessName|Image}; command={CommandLine|ProcessCommandLine}; parent={ParentProcessName|CreatorProcessName}.",
    "4697": "A service was installed. Service={ServiceName}; image={ServiceFileName|ImagePath}.",
    "4698": "A scheduled task was created. Task={TaskName}; content={TaskContent|CommandLine}.",
    "4720": "A user account was created. User={TargetUserName|AccountName}; actor={SubjectUserName}.",
    "4726": "A user account was deleted. User={TargetUserName|AccountName}; actor={SubjectUserName}.",
    "4732": "A member was added to a local group. Member={MemberName|TargetUserName}; group={TargetUserName|GroupName}; actor={SubjectUserName}.",
    "4738": "A user account was changed. User={TargetUserName|AccountName}; actor={SubjectUserName}.",
    "4103": "PowerShell module logging recorded command activity. Command={CommandLine|Payload|ScriptBlockText}.",
    "4104": "PowerShell script block was recorded. Script={ScriptBlockText|CommandLine|Payload}.",
    "7045": "A service was installed. Service={ServiceName}; image={ServiceFileName|ImagePath}; account={AccountName|User}.",
    "1149": "An RDP authentication succeeded. User={User|TargetUserName}; source={SourceNetworkAddress|IpAddress|SourceIp}.",
    "1102": "The Security audit log was cleared. Subject={SubjectUserName|User}.",
    "104": "An event log was cleared. Channel={Channel}; user={SubjectUserName|User}.",
}

PROVIDER_EVENT_MESSAGE_TEMPLATES = {
    "sysmon": {
        "1": "Sysmon process creation. Image={Image|ProcessName}; command={CommandLine}; parent={ParentImage|ParentProcessName}.",
        "3": "Sysmon network connection. Image={Image|ProcessName}; destination={DestinationIp|DestinationHostname}:{DestinationPort}.",
        "7": "Sysmon image loaded. Image={Image|ProcessName}; loaded={ImageLoaded}.",
        "11": "Sysmon file created. Image={Image|ProcessName}; target={TargetFilename|FileName}.",
        "13": "Sysmon registry value set. Image={Image|ProcessName}; target={TargetObject|ObjectName}.",
        "22": "Sysmon DNS query. Image={Image|ProcessName}; query={QueryName|Query}.",
    },
    "defender": {
        "1116": "Microsoft Defender detected malware. Threat={ThreatName}; path={Path|FileName}; action={ActionName}.",
        "5007": "Microsoft Defender configuration changed. Setting={NewValue|OldValue|SettingName}; actor={User|SubjectUserName}.",
    },
    "wmi": {
        "5857": "WMI provider activity was recorded. Provider={ProviderName}; operation={Operation|Query}.",
        "5861": "WMI permanent event consumer activity was recorded. Consumer={Consumer|ConsumerName}; command={CommandLine|ExecutablePath}.",
    },
    "firewall": {
        "2004": "Windows Firewall rule was added. Rule={RuleName|Name}; application={ApplicationPath|AppPath}; action={Action}.",
        "2005": "Windows Firewall rule was modified. Rule={RuleName|Name}; application={ApplicationPath|AppPath}; action={Action}.",
        "2006": "Windows Firewall rule was deleted. Rule={RuleName|Name}; application={ApplicationPath|AppPath}; action={Action}.",
    },
}


class NativeEvtxRecordCandidate(NamedTuple):
    offset: int
    declared_size: int
    record_blob: bytes
    parseable: bool
    reason: str
    available_size: int


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
                native_event_count = sum(1 for record in native_records if record.artifact_type == "eventlog-event")
                native_candidate_count = sum(1 for record in native_records if record.artifact_type == "eventlog-record-candidate")
                records.append(
                    build_eventlog_file_record(
                        path,
                        native_record_count=native_event_count,
                        native_record_candidate_count=native_candidate_count,
                    )
                )
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
        rendering = child_by_name(event, "RenderingInfo")
        data = event_data_values(event_data)
        if user_data is not None:
            data.update(prefixed_xml_values(user_data, "UserData"))
        rendered_message = text_from_child(rendering, "Message")
        if rendered_message:
            data.setdefault("Message", rendered_message)
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
    for chunk_index, chunk in enumerate(iter_native_evtx_chunks(blob)):
        yield native_evtx_chunk_record(path, chunk_index, source_hashes, blob, chunk)

    previous_record_id: int | None = None
    for source_index, candidate in enumerate(iter_evtx_record_candidates(blob)):
        if not candidate.parseable:
            yield native_evtx_record_candidate_record(path, source_index, source_hashes, blob, candidate)
            continue
        offset = candidate.offset
        record_blob = candidate.record_blob
        record_id = read_u64(record_blob, 8)
        timestamp = filetime_to_iso(read_u64(record_blob, 16))
        payload = record_blob[EVTX_RECORD_HEADER_SIZE:]
        binxml = parse_native_evtx_binxml(payload)
        binxml_promoted = native_evtx_promoted_fields(binxml)
        extracted_strings = extract_utf16le_strings(payload)
        binxml_strings = [str(item.get("text") or "") for item in binxml.get("value_fields", []) if item.get("text")]
        searchable_strings = unique_texts([*binxml_strings, *extracted_strings])
        native_indicators = merge_native_evtx_promoted_fields(
            native_evtx_indicators(searchable_strings, path),
            binxml_promoted,
        )
        integrity = native_evtx_record_integrity(record_blob, offset)
        chunk_context = native_evtx_chunk_context(blob, offset, len(record_blob))
        binxml_status = str(binxml.get("status") or NATIVE_EVTX_BINXML_STATUS)
        recovery_context = native_evtx_recovery_context(candidate, integrity, chunk_context, binxml_status)
        sequence = native_evtx_sequence(record_id, previous_record_id)
        previous_record_id = record_id or previous_record_id
        parameter_candidates = native_evtx_parameter_candidates(native_indicators, binxml)
        raw_preview = str(binxml.get("rendered_preview") or "") or native_evtx_message_preview(native_indicators, searchable_strings)
        field_fidelity = native_evtx_field_fidelity(binxml_status)
        validation_required = native_evtx_validation_required(binxml_status, recovery_context)
        validation_reasons = native_evtx_validation_reasons(binxml_status, recovery_context)
        data = {
            "evtx_parse_status": "native-binary-partial",
            "evtx_native_parse_scope": NATIVE_EVTX_PARSE_SCOPE,
            "evtx_binxml_status": binxml_status,
            "evtx_field_fidelity": field_fidelity,
            "evtx_validation_required": validation_required,
            "evtx_validation_reasons": validation_reasons,
            "evtx_validation_guidance": (
                "Use an EVTX-capable parser export such as EvtxECmd, Hayabusa, Chainsaw, or "
                "Velociraptor when report-grade Event/System/EventData field fidelity is required."
            ),
            "evtx_validation_checks": native_evtx_validation_checks(
                integrity,
                chunk_context,
                recovery_context,
                binxml,
            ),
            "evtx_validation_matrix": native_evtx_validation_matrix(
                integrity,
                chunk_context,
                recovery_context,
                binxml,
            ),
            "evtx_binxml": binxml,
            "binxml_system_fields": dict(binxml_promoted.get("system_fields") or {}),
            "binxml_event_data_fields": dict(binxml_promoted.get("event_data_fields") or {}),
            "binxml_user_data_fields": dict(binxml_promoted.get("user_data_fields") or {}),
            "evtx_file_header": native_evtx_file_header(blob),
            "evtx_chunk_context": chunk_context,
            "evtx_record_offset": offset,
            "evtx_record_size": len(record_blob),
            "evtx_record_sha256": hashlib.sha256(record_blob).hexdigest(),
            "evtx_record_integrity": integrity,
            "evtx_recovery_context": recovery_context,
            "evtx_recovery_status": recovery_context["status"],
            "evtx_allocation_status": recovery_context["allocation_status"],
            "evtx_native_capabilities": NATIVE_EVTX_CAPABILITIES,
            "evtx_record_sequence": sequence,
            "validation_required": validation_required,
            "caution_labels": recovery_context["caution_labels"] if validation_required else [],
            "extracted_strings": searchable_strings[:MAX_NATIVE_EVTX_STRINGS],
            "extracted_string_count": len(searchable_strings),
            "native_indicators": native_indicators,
            "ProviderName": native_indicators.get("provider_name", ""),
            "Channel": native_indicators.get("channel", ""),
            "Computer": native_indicators.get("computer", ""),
            "CommandLine": native_indicators.get("command_line", ""),
            "SourceIp": native_indicators.get("source_ip", ""),
            "TargetUserName": native_indicators.get("user_name", ""),
            "parameter_candidates": parameter_candidates,
            "native_message_preview": raw_preview,
        }
        data.update(dict(binxml_promoted.get("flat_fields") or {}))
        system_fields = binxml_promoted.get("system_fields") if isinstance(binxml_promoted.get("system_fields"), Mapping) else {}
        provider_name = str(native_indicators.get("provider_name") or "")
        channel = str(native_indicators.get("channel") or "")
        computer = str(native_indicators.get("computer") or "")
        event_created_at = str(system_fields.get("TimeCreated") or timestamp)
        details = normalize_event_details(
            parser="windows-eventlog-evtx-native",
            source_format="evtx",
            source_path=path,
            source_index=source_index,
            source_hashes=source_hashes,
            provider_name=provider_name,
            event_id=str(system_fields.get("EventID") or ""),
            record_id=str(system_fields.get("EventRecordID") or record_id or ""),
            channel=channel,
            level=str(system_fields.get("Level") or ""),
            computer=computer,
            event_created_at=event_created_at,
            data=data,
            raw_preview=raw_preview,
            user_sid=str(system_fields.get("UserID") or ""),
            user_name=str(native_indicators.get("user_name") or ""),
            process_id=str(system_fields.get("ProcessID") or ""),
            thread_id=str(system_fields.get("ThreadID") or ""),
            process_name=str(native_indicators.get("process_name") or ""),
            command_line=str(native_indicators.get("command_line") or raw_preview),
        )
        details.update(data)
        details["parser_confidence"] = native_evtx_confidence(details)
        details["evtx_report_grade_assessment"] = native_evtx_report_grade_assessment(details)
        details["commercial_grade_ready"] = details["evtx_report_grade_assessment"]["report_grade_ready"]
        details["commercial_grade_blockers"] = list(details["evtx_report_grade_assessment"]["blockers"])
        yield event_record(path, "eventlog-event", details)


def iter_evtx_record_blobs(blob: bytes) -> Iterable[tuple[int, bytes]]:
    for candidate in iter_evtx_record_candidates(blob):
        if candidate.parseable:
            yield candidate.offset, candidate.record_blob


def iter_native_evtx_chunks(blob: bytes) -> Iterable[dict[str, object]]:
    if not blob.startswith(EVTX_FILE_SIGNATURE):
        return
    declared_chunks = read_u16(blob, 42)
    offset = EVTX_FILE_HEADER_SIZE
    emitted = 0
    while offset + len(EVTX_CHUNK_SIGNATURE) <= len(blob) and emitted < MAX_NATIVE_EVTX_CHUNKS:
        chunk_blob = blob[offset : min(len(blob), offset + EVTX_CHUNK_SIZE)]
        if not chunk_blob.startswith(EVTX_CHUNK_SIGNATURE):
            next_signature = blob.find(EVTX_CHUNK_SIGNATURE, offset + 1)
            if next_signature < 0:
                return
            offset = next_signature
            continue
        yield {
            "chunk_offset": offset,
            "chunk_blob": chunk_blob,
            "declared_chunk_count": declared_chunks,
            "chunk_index": emitted,
        }
        emitted += 1
        offset += EVTX_CHUNK_SIZE


def iter_evtx_record_candidates(blob: bytes) -> Iterable[NativeEvtxRecordCandidate]:
    offset = 0
    emitted = 0
    while emitted < MAX_NATIVE_EVTX_RECORDS:
        offset = blob.find(EVTX_RECORD_MAGIC, offset)
        if offset < 0:
            return
        declared_size = read_u32(blob, offset + 4)
        available_size = len(blob) - offset
        if declared_size < EVTX_RECORD_HEADER_SIZE:
            record_blob = blob[offset : min(len(blob), offset + max(available_size, EVTX_RECORD_HEADER_SIZE))]
            yield NativeEvtxRecordCandidate(
                offset, declared_size, record_blob[:4096], False, "declared-size-too-small", available_size
            )
            emitted += 1
            offset += len(EVTX_RECORD_MAGIC)
            continue
        if declared_size > MAX_NATIVE_EVTX_RECORD_SIZE:
            record_blob = blob[offset : min(len(blob), offset + 4096)]
            yield NativeEvtxRecordCandidate(
                offset, declared_size, record_blob, False, "declared-size-too-large", available_size
            )
            emitted += 1
            offset += len(EVTX_RECORD_MAGIC)
            continue
        if offset + declared_size > len(blob):
            record_blob = blob[offset : min(len(blob), offset + min(declared_size, 4096))]
            yield NativeEvtxRecordCandidate(
                offset, declared_size, record_blob, False, "record-extends-past-eof", available_size
            )
            emitted += 1
            offset += len(EVTX_RECORD_MAGIC)
            continue
        yield NativeEvtxRecordCandidate(
            offset, declared_size, blob[offset : offset + declared_size], True, "record-size-plausible", available_size
        )
        emitted += 1
        offset += declared_size


def native_evtx_record_integrity(record_blob: bytes, offset: int) -> dict[str, object]:
    declared_size = read_u32(record_blob, 4)
    trailing_size = read_u32(record_blob, len(record_blob) - 4) if len(record_blob) >= EVTX_RECORD_HEADER_SIZE + 4 else 0
    trailing_size_present = trailing_size == declared_size
    return {
        "magic_valid": record_blob.startswith(EVTX_RECORD_MAGIC),
        "declared_size": declared_size,
        "actual_size": len(record_blob),
        "declared_size_valid": declared_size == len(record_blob),
        "trailing_size": trailing_size,
        "trailing_size_valid": trailing_size_present,
        "offset": offset,
        "alignment": offset % 8,
    }


def native_evtx_candidate_integrity(candidate: NativeEvtxRecordCandidate) -> dict[str, object]:
    trailing_size = (
        read_u32(candidate.record_blob, len(candidate.record_blob) - 4)
        if len(candidate.record_blob) >= EVTX_RECORD_HEADER_SIZE + 4
        else 0
    )
    return {
        "magic_valid": candidate.record_blob.startswith(EVTX_RECORD_MAGIC),
        "declared_size": candidate.declared_size,
        "actual_size": len(candidate.record_blob),
        "available_size": candidate.available_size,
        "declared_size_valid": candidate.parseable and candidate.declared_size == len(candidate.record_blob),
        "trailing_size": trailing_size,
        "trailing_size_valid": candidate.parseable and trailing_size == candidate.declared_size,
        "offset": candidate.offset,
        "alignment": candidate.offset % 8,
        "candidate_reason": candidate.reason,
    }


def native_evtx_recovery_context(
    candidate: NativeEvtxRecordCandidate,
    integrity: Mapping[str, object],
    chunk_context: Mapping[str, object],
    binxml_status: str,
) -> dict[str, object]:
    allocation_status = native_evtx_allocation_status(chunk_context)
    caution_labels: list[str] = []
    if allocation_status in {"slack-or-deleted-candidate", "after-last-record-candidate"}:
        caution_labels.append("slack-or-deleted-record-candidate")
    if not integrity.get("trailing_size_valid"):
        caution_labels.append("trailing-size-mismatch")
    if candidate.reason != "record-size-plausible":
        caution_labels.append(candidate.reason)
    if binxml_status == NATIVE_EVTX_BINXML_STATUS:
        caution_labels.append("binxml-not-decoded")

    if not candidate.parseable:
        status = "corrupt-record-candidate"
    elif allocation_status in {"slack-or-deleted-candidate", "after-last-record-candidate"}:
        status = "slack-or-deleted-record-candidate"
    elif not integrity.get("trailing_size_valid"):
        status = "corrupt-record-candidate"
    else:
        status = "recoverable-record"

    validation_required = status != "recoverable-record" or binxml_status == NATIVE_EVTX_BINXML_STATUS
    if validation_required:
        caution_labels.append("do-not-report-without-validation")
    return {
        "status": status,
        "allocation_status": allocation_status,
        "candidate_reason": candidate.reason,
        "confidence": native_evtx_recovery_confidence(status, integrity, chunk_context, binxml_status),
        "validation_required": validation_required,
        "caution_labels": sorted(set(caution_labels)),
    }


def native_evtx_allocation_status(chunk_context: Mapping[str, object]) -> str:
    if not chunk_context.get("chunk_signature_valid"):
        return "unknown-no-valid-chunk-header"
    boundary_status = str(chunk_context.get("chunk_boundary_status") or "")
    if boundary_status in {"record-outside-chunk-bounds", "record-crosses-free-space-boundary"}:
        return boundary_status
    relative_offset = int(chunk_context.get("record_relative_offset") or 0)
    free_space_offset = int(chunk_context.get("free_space_offset") or 0)
    last_record_offset = int(chunk_context.get("last_record_offset") or 0)
    if free_space_offset and relative_offset >= free_space_offset:
        return "slack-or-deleted-candidate"
    if last_record_offset and relative_offset > last_record_offset:
        return "after-last-record-candidate"
    return "allocated-or-live-record"


def native_evtx_recovery_confidence(
    status: str,
    integrity: Mapping[str, object],
    chunk_context: Mapping[str, object],
    binxml_status: str,
) -> float:
    score = 0.35 if status == "corrupt-record-candidate" else 0.55
    if integrity.get("magic_valid"):
        score += 0.05
    if integrity.get("declared_size_valid"):
        score += 0.1
    if integrity.get("trailing_size_valid"):
        score += 0.1
    if chunk_context.get("chunk_signature_valid"):
        score += 0.05
    if binxml_status in {"basic-rendered", "template-substituted-partial"}:
        score += 0.1
    elif binxml_status == "partial-tokenized":
        score += 0.05
    return min(0.9, round(score, 2))


def native_evtx_validation_required(binxml_status: str, recovery_context: Mapping[str, object]) -> bool:
    return bool(recovery_context.get("validation_required")) or binxml_status not in {
        "basic-rendered",
        "template-substituted-partial",
    }


def native_evtx_validation_reasons(binxml_status: str, recovery_context: Mapping[str, object]) -> list[str]:
    reasons = [
        str(item)
        for item in recovery_context.get("caution_labels", [])
        if str(item)
    ] if isinstance(recovery_context.get("caution_labels"), list) else []
    if binxml_status not in {"basic-rendered", "template-substituted-partial"}:
        reasons.append(f"binxml-status:{binxml_status or 'unknown'}")
    return sorted(set(reasons))


def native_evtx_validation_checks(
    integrity: Mapping[str, object],
    chunk_context: Mapping[str, object],
    recovery_context: Mapping[str, object],
    binxml: Mapping[str, object],
) -> dict[str, object]:
    decoded_types = Counter(
        str(item.get("value_type") or "unknown")
        for item in binxml.get("value_fields", [])
        if isinstance(item, Mapping) and item.get("value_type")
    ) if isinstance(binxml.get("value_fields"), list) else Counter()
    checks = {
        "record_magic_valid": bool(integrity.get("magic_valid")),
        "declared_size_valid": bool(integrity.get("declared_size_valid")),
        "trailing_size_valid": bool(integrity.get("trailing_size_valid")),
        "chunk_header_present": bool(chunk_context.get("chunk_signature_valid")),
        "chunk_allocation_status": recovery_context.get("allocation_status", ""),
        "recovery_status": recovery_context.get("status", ""),
        "binxml_status": binxml.get("status", NATIVE_EVTX_BINXML_STATUS),
        "decoded_value_type_counts": counter_items(decoded_types),
        "template_value_count": int(binxml.get("template_value_count") or 0),
        "template_ids": list(binxml.get("template_ids") or []) if isinstance(binxml.get("template_ids"), list) else [],
    }
    checks["passes_basic_record_integrity"] = (
        checks["record_magic_valid"]
        and checks["declared_size_valid"]
        and checks["trailing_size_valid"]
    )
    checks["requires_second_parser"] = bool(recovery_context.get("validation_required")) or checks["binxml_status"] == NATIVE_EVTX_BINXML_STATUS
    return checks


def native_evtx_validation_matrix(
    integrity: Mapping[str, object],
    chunk_context: Mapping[str, object],
    recovery_context: Mapping[str, object],
    binxml: Mapping[str, object],
) -> list[dict[str, object]]:
    binxml_status = str(binxml.get("status") or NATIVE_EVTX_BINXML_STATUS) if isinstance(binxml, Mapping) else NATIVE_EVTX_BINXML_STATUS
    return [
        {
            "id": "record-magic",
            "label": "EVTX record magic",
            "passed": bool(integrity.get("magic_valid")),
            "severity": "critical",
            "detail": "Record starts with the EVTX record marker.",
        },
        {
            "id": "declared-size",
            "label": "Declared record size",
            "passed": bool(integrity.get("declared_size_valid")),
            "severity": "critical",
            "detail": f"declared={integrity.get('declared_size', 0)} observed={integrity.get('actual_size', 0)}",
        },
        {
            "id": "trailing-size",
            "label": "Trailing record size",
            "passed": bool(integrity.get("trailing_size_valid")),
            "severity": "high",
            "detail": f"trailing={integrity.get('trailing_size', 0)}",
        },
        {
            "id": "chunk-context",
            "label": "Chunk boundary context",
            "passed": bool(chunk_context.get("chunk_signature_valid")),
            "severity": "medium",
            "detail": str(chunk_context.get("chunk_boundary_status") or chunk_context.get("chunk_validation_status") or ""),
        },
        {
            "id": "allocation-region",
            "label": "Allocated/slack region",
            "passed": str(recovery_context.get("allocation_status") or "") == "allocated-or-live-record",
            "severity": "high",
            "detail": str(recovery_context.get("allocation_status") or ""),
        },
        {
            "id": "binxml-field-decode",
            "label": "BinXML field decode",
            "passed": binxml_status in {"basic-rendered", "template-substituted-partial"},
            "severity": "high",
            "detail": binxml_status,
        },
        {
            "id": "deleted-corrupt-caution",
            "label": "Deleted/corrupt caution",
            "passed": str(recovery_context.get("status") or "") == "recoverable-record",
            "severity": "critical",
            "detail": str(recovery_context.get("status") or ""),
        },
    ]


def native_evtx_report_grade_assessment(details: Mapping[str, object]) -> dict[str, object]:
    blockers: list[str] = []
    checks = details.get("evtx_validation_checks") if isinstance(details.get("evtx_validation_checks"), Mapping) else {}
    message = details.get("message_rendering") if isinstance(details.get("message_rendering"), Mapping) else {}
    recovery = details.get("evtx_recovery_context") if isinstance(details.get("evtx_recovery_context"), Mapping) else {}
    chunk = details.get("evtx_chunk_context") if isinstance(details.get("evtx_chunk_context"), Mapping) else {}
    binxml_status = str(details.get("evtx_binxml_status") or checks.get("binxml_status") or "")

    if not checks.get("passes_basic_record_integrity"):
        blockers.append("record-integrity-not-proven")
    if binxml_status not in {"basic-rendered", "template-substituted-partial"}:
        blockers.append("full-binxml-field-decoding-required")
    if not chunk.get("chunk_signature_valid"):
        blockers.append("chunk-boundary-not-validated")
    if recovery.get("status") != "recoverable-record":
        blockers.append("deleted-or-corrupt-record-independent-validation-required")
    if message and message.get("provider_resource_required") and not (
        isinstance(message.get("provenance"), Mapping)
        and message["provenance"].get("provider_message_resource_resolved")
    ):
        blockers.append("provider-message-resource-rendering-required")
    if details.get("validation_required"):
        blockers.append("native-record-validation-required")

    blockers.extend(NATIVE_EVTX_REPORT_GRADE_BLOCKERS)
    blockers = sorted(set(blockers))
    report_grade_ready = not blockers
    if report_grade_ready:
        status = "report-grade-ready"
    elif checks.get("passes_basic_record_integrity") and binxml_status in {"basic-rendered", "template-substituted-partial"}:
        status = "triage-validated-report-grade-blocked"
    else:
        status = "validation-required"

    return {
        "report_grade_ready": report_grade_ready,
        "status": status,
        "blockers": blockers,
        "validated_strengths": [
            item["id"]
            for item in details.get("evtx_validation_matrix", [])
            if isinstance(item, Mapping) and item.get("passed")
        ],
        "commercial_gap_ids": ["#1", "#2", "#3"],
        "next_validation_step": (
            "Compare this row against an external EVTX parser export and provider message resource rendering before "
            "using native EVTX rows as report-grade testimony."
        ),
    }


def native_evtx_record_candidate_record(
    path: Path,
    source_index: int,
    source_hashes: Mapping[str, str],
    blob: bytes,
    candidate: NativeEvtxRecordCandidate,
) -> ArtifactRecord:
    record_id = read_u64(candidate.record_blob, 8) if len(candidate.record_blob) >= 16 else 0
    timestamp = filetime_to_iso(read_u64(candidate.record_blob, 16)) if len(candidate.record_blob) >= 24 else ""
    strings = extract_utf16le_strings(candidate.record_blob)
    indicators = native_evtx_indicators(strings, path)
    integrity = native_evtx_candidate_integrity(candidate)
    chunk_context = native_evtx_chunk_context(blob, candidate.offset, len(candidate.record_blob))
    recovery_context = native_evtx_recovery_context(candidate, integrity, chunk_context, NATIVE_EVTX_BINXML_STATUS)
    validation_checks = native_evtx_validation_checks(integrity, chunk_context, recovery_context, {})
    details = {
        "parser": "windows-eventlog-evtx-native-candidate",
        "parser_version": PARSER_VERSION,
        "coverage_status": "corrupt-or-deleted-candidate",
        "reportability": "triage",
        "evidence_strength": "evtx-record-candidate",
        "source_path": str(path.resolve()),
        "source_format": "evtx",
        "source_index": source_index,
        "source_hashes": dict(source_hashes),
        "record_id": str(record_id or ""),
        "timestamp": timestamp,
        "evtx_record_offset": candidate.offset,
        "evtx_declared_size": candidate.declared_size,
        "evtx_available_size": candidate.available_size,
        "evtx_record_sha256": hashlib.sha256(candidate.record_blob).hexdigest(),
        "evtx_record_integrity": integrity,
        "evtx_chunk_context": chunk_context,
        "evtx_recovery_context": recovery_context,
        "evtx_recovery_status": recovery_context["status"],
        "evtx_allocation_status": recovery_context["allocation_status"],
        "evtx_validation_checks": validation_checks,
        "evtx_validation_matrix": native_evtx_validation_matrix(integrity, chunk_context, recovery_context, {}),
        "evtx_native_capabilities": NATIVE_EVTX_CAPABILITIES,
        "parser_confidence": recovery_context["confidence"],
        "validation_required": True,
        "caution_labels": recovery_context["caution_labels"],
        "extracted_strings": strings[:MAX_NATIVE_EVTX_STRINGS],
        "extracted_string_count": len(strings),
        "native_indicators": indicators,
        "triage_recommendation": (
            "Treat this as a recovery candidate only. Validate with a second EVTX parser and adjacent chunk/file "
            "context before relying on it in a report."
        ),
    }
    details["evtx_report_grade_assessment"] = native_evtx_report_grade_assessment(details)
    details["commercial_grade_ready"] = False
    details["commercial_grade_blockers"] = list(details["evtx_report_grade_assessment"]["blockers"])
    return event_record(path, "eventlog-record-candidate", details)


def native_evtx_chunk_record(
    path: Path,
    source_index: int,
    source_hashes: Mapping[str, str],
    blob: bytes,
    chunk: Mapping[str, object],
) -> ArtifactRecord:
    chunk_offset = int(chunk.get("chunk_offset") or 0)
    chunk_blob = chunk.get("chunk_blob") if isinstance(chunk.get("chunk_blob"), bytes) else b""
    header = native_evtx_chunk_header(chunk_blob, chunk_offset)
    integrity = native_evtx_chunk_integrity(chunk_blob, header)
    details = {
        "parser": "windows-eventlog-evtx-native-chunk",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-evtx-chunk-structure",
        "reportability": "triage",
        "evidence_strength": "evtx-chunk-header",
        "source_path": str(path.resolve()),
        "source_format": "evtx",
        "source_index": source_index,
        "source_hashes": dict(source_hashes),
        "evtx_file_header": native_evtx_file_header(blob),
        "evtx_chunk_header": header,
        "evtx_chunk_integrity": integrity,
        "chunk_offset": chunk_offset,
        "chunk_size_observed": len(chunk_blob),
        "declared_chunk_count": chunk.get("declared_chunk_count", 0),
        "chunk_index": chunk.get("chunk_index", source_index),
        "parser_confidence": 0.78 if integrity.get("signature_valid") else 0.25,
        "validation_required": not integrity.get("structure_plausible", False),
        "validation_guidance": "Chunk rows validate EVTX chunk structure and slack bounds; use a second EVTX parser for report-grade message rendering.",
        "risk_flags": native_evtx_chunk_risk_flags(integrity),
        "risk_score": 35 if not integrity.get("structure_plausible", False) else 0,
        "raw_preview": f"chunk@0x{chunk_offset:x} records={header.get('first_event_record_identifier')}-{header.get('last_event_record_identifier')}",
    }
    return event_record(path, "eventlog-chunk", details)


def native_evtx_file_header(blob: bytes) -> dict[str, object]:
    header_size = read_u32(blob, 32) or (EVTX_FILE_HEADER_SIZE if len(blob) >= EVTX_FILE_HEADER_SIZE else len(blob))
    checksum = read_u32(blob, 124)
    return {
        "signature_valid": blob.startswith(EVTX_FILE_SIGNATURE),
        "header_size": header_size,
        "file_size": len(blob),
        "oldest_chunk_number": read_u64(blob, 8),
        "current_chunk_number": read_u64(blob, 16),
        "next_record_identifier": read_u64(blob, 24),
        "minor_version": read_u16(blob, 36),
        "major_version": read_u16(blob, 38),
        "header_block_size": read_u16(blob, 40),
        "chunk_count": read_u16(blob, 42),
        "header_flags": read_u32(blob, 120),
        "header_checksum": checksum,
        "header_checksum_present": checksum != 0,
        "validation_status": "signature-only" if checksum == 0 else "checksum-present-unverified",
    }


def native_evtx_chunk_header(chunk_blob: bytes, chunk_offset: int) -> dict[str, object]:
    signature_valid = chunk_blob.startswith(EVTX_CHUNK_SIGNATURE)
    header_size = read_u32(chunk_blob, 40) if signature_valid else 0
    last_record_offset = read_u32(chunk_blob, 44) if signature_valid else 0
    free_space_offset = read_u32(chunk_blob, 48) if signature_valid else 0
    legacy_free_space_offset = read_u32(chunk_blob, 44) if signature_valid else 0
    if not free_space_offset and legacy_free_space_offset >= EVTX_CHUNK_HEADER_SIZE:
        free_space_offset = legacy_free_space_offset
    return {
        "signature_valid": signature_valid,
        "chunk_offset": chunk_offset,
        "first_event_record_number": read_u64(chunk_blob, 8) if signature_valid else 0,
        "last_event_record_number": read_u64(chunk_blob, 16) if signature_valid else 0,
        "first_event_record_identifier": read_u64(chunk_blob, 24) if signature_valid else 0,
        "last_event_record_identifier": read_u64(chunk_blob, 32) if signature_valid else 0,
        "header_size": header_size,
        "last_record_offset": last_record_offset,
        "free_space_offset": free_space_offset,
        "events_checksum": read_u32(chunk_blob, 52) if signature_valid else 0,
        "header_checksum": read_u32(chunk_blob, 124) if signature_valid else 0,
        "flags": read_u32(chunk_blob, 120) if signature_valid else 0,
        "computed_header_crc32": evtx_crc32(chunk_blob[:120]) if len(chunk_blob) >= 120 else 0,
        "computed_records_crc32": evtx_crc32(chunk_blob[EVTX_CHUNK_HEADER_SIZE:free_space_offset])
        if free_space_offset > EVTX_CHUNK_HEADER_SIZE and free_space_offset <= len(chunk_blob)
        else 0,
    }


def native_evtx_chunk_integrity(chunk_blob: bytes, header: Mapping[str, object]) -> dict[str, object]:
    signature_valid = bool(header.get("signature_valid"))
    header_size = int(header.get("header_size") or 0)
    last_record_offset = int(header.get("last_record_offset") or 0)
    free_space_offset = int(header.get("free_space_offset") or 0)
    first_record_id = int(header.get("first_event_record_identifier") or 0)
    last_record_id = int(header.get("last_event_record_identifier") or 0)
    header_size_plausible = header_size in {0, EVTX_CHUNK_HEADER_SIZE}
    offsets_plausible = (
        free_space_offset == 0
        or EVTX_CHUNK_HEADER_SIZE <= free_space_offset <= len(chunk_blob) <= EVTX_CHUNK_SIZE
    )
    last_record_plausible = last_record_offset == 0 or EVTX_CHUNK_HEADER_SIZE <= last_record_offset <= max(free_space_offset, len(chunk_blob))
    record_range_plausible = not first_record_id or not last_record_id or first_record_id <= last_record_id
    expected_header_checksum = int(header.get("header_checksum") or 0)
    expected_events_checksum = int(header.get("events_checksum") or 0)
    computed_header = int(header.get("computed_header_crc32") or 0)
    computed_events = int(header.get("computed_records_crc32") or 0)
    return {
        "signature_valid": signature_valid,
        "header_size_plausible": header_size_plausible,
        "offsets_plausible": offsets_plausible,
        "last_record_offset_plausible": last_record_plausible,
        "record_identifier_range_plausible": record_range_plausible,
        "header_checksum_present": expected_header_checksum != 0,
        "events_checksum_present": expected_events_checksum != 0,
        "header_checksum_match": expected_header_checksum != 0 and expected_header_checksum == computed_header,
        "events_checksum_match": expected_events_checksum != 0 and expected_events_checksum == computed_events,
        "structure_plausible": signature_valid and header_size_plausible and offsets_plausible and last_record_plausible and record_range_plausible,
        "checksum_status": "matched" if (expected_header_checksum and expected_header_checksum == computed_header) else ("present-unmatched-or-algorithm-variant" if expected_header_checksum else "not-present"),
    }


def native_evtx_chunk_risk_flags(integrity: Mapping[str, object]) -> list[str]:
    flags: list[str] = []
    if not integrity.get("signature_valid"):
        flags.append("evtx-chunk-signature-invalid")
    if not integrity.get("offsets_plausible"):
        flags.append("evtx-chunk-offsets-invalid")
    if not integrity.get("record_identifier_range_plausible"):
        flags.append("evtx-chunk-record-range-invalid")
    if integrity.get("header_checksum_present") and not integrity.get("header_checksum_match"):
        flags.append("evtx-chunk-checksum-unmatched")
    return flags


def evtx_crc32(value: bytes) -> int:
    return zlib.crc32(value) & 0xFFFFFFFF


def native_evtx_chunk_context(blob: bytes, record_offset: int, record_size: int = 0) -> dict[str, object]:
    if record_offset < EVTX_FILE_HEADER_SIZE:
        chunk_offset = 0
    else:
        chunk_offset = EVTX_FILE_HEADER_SIZE + ((record_offset - EVTX_FILE_HEADER_SIZE) // EVTX_CHUNK_SIZE) * EVTX_CHUNK_SIZE
    signature = blob[chunk_offset : chunk_offset + len(EVTX_CHUNK_SIGNATURE)]
    signature_valid = signature == EVTX_CHUNK_SIGNATURE
    header = native_evtx_chunk_header(blob[chunk_offset : min(len(blob), chunk_offset + EVTX_CHUNK_SIZE)], chunk_offset)
    relative_offset = record_offset - chunk_offset
    relative_end_offset = relative_offset + max(record_size, 0)
    free_space_offset = int(header.get("free_space_offset") or 0)
    last_record_offset = int(header.get("last_record_offset") or 0)
    record_within_chunk = 0 <= relative_offset < EVTX_CHUNK_SIZE and relative_end_offset <= EVTX_CHUNK_SIZE
    record_after_free_space = bool(signature_valid and free_space_offset and relative_offset >= free_space_offset)
    record_crosses_free_space = bool(
        signature_valid
        and free_space_offset
        and relative_offset < free_space_offset < relative_end_offset
    )
    record_after_last_record = bool(signature_valid and last_record_offset and relative_offset > last_record_offset)
    if not signature_valid:
        boundary_status = "no-valid-chunk-header"
    elif not record_within_chunk:
        boundary_status = "record-outside-chunk-bounds"
    elif record_after_free_space or record_after_last_record:
        boundary_status = "slack-or-deleted-region"
    elif record_crosses_free_space:
        boundary_status = "record-crosses-free-space-boundary"
    else:
        boundary_status = "allocated-record-region"
    return {
        "chunk_offset": chunk_offset,
        "chunk_signature_valid": signature_valid,
        "chunk_validation_status": "header-present" if signature_valid else "missing-or-not-a-chunk-header",
        "record_relative_offset": relative_offset,
        "record_relative_end_offset": relative_end_offset,
        "record_size": record_size,
        "record_within_chunk_bounds": record_within_chunk,
        "record_after_free_space": record_after_free_space,
        "record_crosses_free_space": record_crosses_free_space,
        "record_after_last_record": record_after_last_record,
        "chunk_boundary_status": boundary_status,
        "first_event_record_number": header.get("first_event_record_number", 0),
        "last_event_record_number": header.get("last_event_record_number", 0),
        "first_event_record_identifier": header.get("first_event_record_identifier", 0),
        "last_event_record_identifier": header.get("last_event_record_identifier", 0),
        "header_size": header.get("header_size", 0),
        "last_record_offset": header.get("last_record_offset", 0),
        "free_space_offset": header.get("free_space_offset", 0),
        "events_checksum": header.get("events_checksum", 0),
        "header_checksum": header.get("header_checksum", 0),
        "computed_header_crc32": header.get("computed_header_crc32", 0),
        "computed_records_crc32": header.get("computed_records_crc32", 0),
    }


def native_evtx_sequence(record_id: int, previous_record_id: int | None) -> dict[str, object]:
    if not record_id:
        status = "missing-record-id"
    elif previous_record_id is None:
        status = "first-record"
    elif record_id == previous_record_id + 1:
        status = "contiguous"
    elif record_id > previous_record_id + 1:
        status = "gap"
    elif record_id <= previous_record_id:
        status = "non-monotonic"
    else:
        status = "unknown"
    return {
        "status": status,
        "previous_record_id": previous_record_id or "",
        "gap": record_id - previous_record_id - 1 if previous_record_id is not None and record_id > previous_record_id + 1 else 0,
    }


def native_evtx_indicators(strings: Sequence[str], path: Path) -> dict[str, object]:
    provider = first_matching_string(strings, "Microsoft-Windows-")
    channel = first_native_channel(strings) or channel_hint_from_path(path)
    command = first_command_string(strings)
    process_path = first_process_path(strings)
    ip_addresses = sorted(set(iter_ip_addresses(strings)))
    users = sorted(set(iter_user_candidates(strings)))
    urls = sorted(set(iter_url_candidates(strings)))
    paths = sorted(set(iter_path_candidates(strings)))
    return {
        "provider_name": provider,
        "channel": channel,
        "channel_hint_source": "record-string" if first_native_channel(strings) else "filename",
        "computer": first_matching_string(strings, "WIN-", ".local"),
        "command_line": command,
        "process_name": process_path,
        "source_ip": ip_addresses[0] if ip_addresses else "",
        "ip_addresses": ip_addresses[:20],
        "user_name": users[0] if users else "",
        "user_candidates": users[:20],
        "url_candidates": urls[:20],
        "path_candidates": paths[:20],
        "string_count": len(strings),
    }


def native_evtx_parameter_candidates(
    indicators: Mapping[str, object],
    binxml: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    fields = (
        ("ProviderName", indicators.get("provider_name")),
        ("Channel", indicators.get("channel")),
        ("Computer", indicators.get("computer")),
        ("CommandLine", indicators.get("command_line")),
        ("ProcessName", indicators.get("process_name")),
        ("SourceIp", indicators.get("source_ip")),
        ("TargetUserName", indicators.get("user_name")),
    )
    candidates = [
        {"name": name, "value": str(value), "confidence": "string-pivot"}
        for name, value in fields
        if value
    ]
    binxml_fields = binxml.get("value_fields", []) if isinstance(binxml, Mapping) else []
    if isinstance(binxml_fields, list):
        for item in binxml_fields:
            if not isinstance(item, Mapping):
                continue
            text = str(item.get("text") or "").strip()
            if not text:
                continue
            name = str(item.get("element_path") or item.get("element") or "BinXmlValue")
            candidates.append({"name": name, "value": text, "confidence": "binxml-value-text"})
    for value in indicators.get("url_candidates", []) if isinstance(indicators.get("url_candidates"), list) else []:
        candidates.append({"name": "Url", "value": str(value), "confidence": "string-pivot"})
    for value in indicators.get("path_candidates", []) if isinstance(indicators.get("path_candidates"), list) else []:
        candidates.append({"name": "Path", "value": str(value), "confidence": "string-pivot"})
    return candidates[:50]


def native_evtx_field_fidelity(binxml_status: str) -> str:
    if binxml_status == "template-substituted-partial":
        return "partial-binxml-template-substitution"
    if binxml_status != NATIVE_EVTX_BINXML_STATUS:
        return "partial-binxml-token-scan"
    return "partial-string-pivot"


def native_evtx_promoted_fields(binxml: Mapping[str, object]) -> dict[str, object]:
    value_fields = binxml.get("value_fields", []) if isinstance(binxml, Mapping) else []
    system_fields: dict[str, str] = {}
    event_data_fields: dict[str, str] = {}
    user_data_fields: dict[str, str] = {}
    flat_fields: dict[str, str] = {}
    pending_event_data_name = ""
    event_data_index = 0

    if not isinstance(value_fields, list):
        value_fields = []

    for item in value_fields:
        if not isinstance(item, Mapping):
            continue
        path = str(item.get("element_path") or "").strip()
        text = str(item.get("text") or "").strip()
        if not path or not text:
            continue

        if path.startswith("Event/System/"):
            key = native_evtx_system_field_name(path.removeprefix("Event/System/"))
            if key:
                system_fields.setdefault(key, text)
            continue

        if path == "Event/EventData/Data/@Name":
            pending_event_data_name = text
            continue

        if path == "Event/EventData/Data":
            key = pending_event_data_name or f"Data{event_data_index}"
            event_data_index += 1
            pending_event_data_name = ""
            event_data_fields.setdefault(key, text)
            continue

        if path.startswith("Event/EventData/"):
            key = native_evtx_leaf_field_name(path.removeprefix("Event/EventData/"))
            if key:
                event_data_fields.setdefault(key, text)
            continue

        if path.startswith("Event/UserData/"):
            key = native_evtx_leaf_field_name(path.removeprefix("Event/UserData/"))
            if key:
                user_data_fields.setdefault(f"UserData.{key}", text)

    for key, value in system_fields.items():
        flat_fields.setdefault(key, value)
    for key, value in event_data_fields.items():
        flat_fields.setdefault(key, value)
    for key, value in user_data_fields.items():
        flat_fields.setdefault(key, value)

    return {
        "system_fields": system_fields,
        "event_data_fields": event_data_fields,
        "user_data_fields": user_data_fields,
        "flat_fields": flat_fields,
    }


def native_evtx_system_field_name(path_suffix: str) -> str:
    normalized = path_suffix.strip("/")
    if not normalized or normalized.startswith("@"):
        return ""
    aliases = {
        "ProviderName": "ProviderName",
        "Provider/Name": "ProviderName",
        "Provider/@Name": "ProviderName",
        "EventID": "EventID",
        "EventID/Qualifiers": "EventIDQualifiers",
        "EventID/@Qualifiers": "EventIDQualifiers",
        "Version": "Version",
        "Level": "Level",
        "Task": "Task",
        "Opcode": "Opcode",
        "Keywords": "Keywords",
        "TimeCreated/SystemTime": "TimeCreated",
        "TimeCreated/@SystemTime": "TimeCreated",
        "EventRecordID": "EventRecordID",
        "Correlation/ActivityID": "CorrelationActivityID",
        "Correlation/@ActivityID": "CorrelationActivityID",
        "Correlation/RelatedActivityID": "CorrelationRelatedActivityID",
        "Correlation/@RelatedActivityID": "CorrelationRelatedActivityID",
        "Execution/ProcessID": "ProcessID",
        "Execution/@ProcessID": "ProcessID",
        "Execution/ThreadID": "ThreadID",
        "Execution/@ThreadID": "ThreadID",
        "Channel": "Channel",
        "Computer": "Computer",
        "Security/UserID": "UserID",
        "Security/@UserID": "UserID",
    }
    return aliases.get(normalized, normalized.split("/")[-1])


def native_evtx_leaf_field_name(path_suffix: str) -> str:
    normalized = path_suffix.strip("/")
    if not normalized or normalized.endswith("/@Name") or "/@" in normalized:
        return ""
    return normalized.rsplit("/", 1)[-1]


def merge_native_evtx_promoted_fields(
    indicators: Mapping[str, object],
    promoted: Mapping[str, object],
) -> dict[str, object]:
    output = dict(indicators)
    system = promoted.get("system_fields") if isinstance(promoted, Mapping) else {}
    event_data = promoted.get("event_data_fields") if isinstance(promoted, Mapping) else {}
    if not isinstance(system, Mapping):
        system = {}
    if not isinstance(event_data, Mapping):
        event_data = {}

    native_evtx_prefer(output, "provider_name", system.get("ProviderName"))
    native_evtx_prefer(output, "channel", system.get("Channel"))
    native_evtx_prefer(output, "computer", system.get("Computer"))
    native_evtx_prefer(output, "command_line", first_promoted_value(event_data, "CommandLine", "ProcessCommandLine", "ScriptBlockText"))
    native_evtx_prefer(output, "process_name", first_promoted_value(event_data, "NewProcessName", "ProcessName", "Image"))
    native_evtx_prefer(output, "source_ip", first_promoted_value(event_data, "IpAddress", "SourceAddress", "SourceIp", "SourceNetworkAddress"))
    native_evtx_prefer(output, "user_name", first_promoted_value(event_data, "TargetUserName", "SubjectUserName", "User", "AccountName"))
    output["promoted_system_field_count"] = len(system)
    output["promoted_event_data_field_count"] = len(event_data)
    return output


def first_promoted_value(fields: Mapping[str, object], *keys: str) -> str:
    for key in keys:
        value = str(fields.get(key) or "").strip()
        if value:
            return value
    return ""


def native_evtx_prefer(target: dict[str, object], key: str, value: object) -> None:
    text = str(value or "").strip()
    if text:
        target[key] = text


def parse_native_evtx_binxml(payload: bytes) -> dict[str, object]:
    if len(payload) < 4 or payload[0] != 0x0F:
        return {"status": NATIVE_EVTX_BINXML_STATUS, "reason": "missing-fragment-header"}

    offset = 0
    stack: list[dict[str, object]] = []
    elements: list[dict[str, object]] = []
    value_fields: list[dict[str, object]] = []
    template_values: list[dict[str, object]] = []
    template_ids: list[str] = []
    tokens: Counter[str] = Counter()
    rendered: list[str] = []
    version: dict[str, object] = {}
    warnings: list[str] = []

    while offset < len(payload) and sum(tokens.values()) < MAX_NATIVE_EVTX_BINXML_TOKENS:
        token = payload[offset]
        token_kind = token & 0xBF
        more = bool(token & 0x40)
        tokens[binxml_token_name(token)] += 1

        if token == 0x00:
            offset += 1
            break
        if token_kind == 0x0F:
            if offset + 4 > len(payload):
                warnings.append("truncated-fragment-header")
                break
            version = {
                "major_version": payload[offset + 1],
                "minor_version": payload[offset + 2],
                "flags": payload[offset + 3],
            }
            offset += 4
            continue
        if token_kind == 0x01:
            next_offset = offset + 1
            dependency_id = read_u16(payload, next_offset)
            byte_length = read_u32(payload, next_offset + 2)
            name, after_name = read_binxml_name(payload, next_offset + 6)
            if not name:
                warnings.append(f"truncated-start-element:{offset}")
                break
            path = "/".join([str(item.get("name") or "") for item in stack] + [name])
            stack.append({"name": name, "path": path, "open": False})
            elements.append(
                {
                    "name": name,
                    "path": path,
                    "offset": offset,
                    "dependency_id": dependency_id,
                    "byte_length": byte_length,
                    "has_attribute_list": more,
                }
            )
            rendered.append(f"<{name}")
            offset = after_name
            continue
        if token_kind == 0x06:
            name, after_name = read_binxml_name(payload, offset + 1)
            if not name:
                warnings.append(f"truncated-attribute:{offset}")
                break
            text, after_value, value_type = read_inline_binxml_value_text(payload, after_name)
            current_path = str(stack[-1].get("path") or "") if stack else ""
            value_fields.append(
                {
                    "element": str(stack[-1].get("name") or "") if stack else "",
                    "element_path": f"{current_path}/@{name}" if current_path else f"@{name}",
                    "attribute": name,
                    "text": text,
                    "value_type": value_type,
                    "offset": offset,
                    "confidence": "binxml-attribute",
                    "more": more,
                }
            )
            rendered.append(f' {name}="{html.escape(text)}"')
            offset = after_value
            continue
        if token_kind == 0x02:
            if stack:
                stack[-1]["open"] = True
            rendered.append(">")
            offset += 1
            continue
        if token_kind == 0x03:
            rendered.append("/>")
            if stack:
                stack.pop()
            offset += 1
            continue
        if token_kind == 0x04:
            name = str(stack.pop().get("name") or "") if stack else ""
            rendered.append(f"</{name}>")
            offset += 1
            continue
        if token_kind == 0x05:
            text, after_value, value_type = read_inline_binxml_value_text(payload, offset)
            current = stack[-1] if stack else {}
            current_path = str(current.get("path") or "")
            value_fields.append(
                {
                    "element": str(current.get("name") or ""),
                    "element_path": current_path,
                    "text": text,
                    "value_type": value_type,
                    "offset": offset,
                    "confidence": "binxml-value-text",
                    "more": more,
                }
            )
            rendered.append(html.escape(text))
            offset = after_value
            continue
        if token_kind == 0x0C:
            template = parse_binxml_template_instance(payload, offset)
            template_id = str(template.get("template_id") or "")
            if template_id:
                template_ids.append(template_id)
            elements.extend(item for item in template.get("elements", []) if isinstance(item, Mapping))
            value_fields.extend(item for item in template.get("value_fields", []) if isinstance(item, Mapping))
            template_values.extend(item for item in template.get("template_values", []) if isinstance(item, Mapping))
            rendered.append(str(template.get("rendered_preview") or ""))
            warnings.extend(str(item) for item in template.get("warnings", []) if str(item))
            template_counts = template.get("token_counts", [])
            if isinstance(template_counts, list):
                for item in template_counts:
                    if isinstance(item, Mapping):
                        tokens[str(item.get("value") or "unknown")] += int(item.get("count") or 0)
            offset = int(template.get("next_offset") or offset + 1)
            continue

        warnings.append(f"unsupported-token:0x{token:02x}@{offset}")
        offset += 1

    has_template_substitution = any(
        isinstance(item, Mapping) and item.get("confidence") == "binxml-template-substitution"
        for item in value_fields
    )
    status = "template-substituted-partial" if has_template_substitution else (
        "basic-rendered" if elements or value_fields else NATIVE_EVTX_BINXML_STATUS
    )
    if warnings and not has_template_substitution:
        status = "partial-tokenized" if elements or value_fields else NATIVE_EVTX_BINXML_STATUS
    return {
        "status": status,
        "version": version,
        "token_counts": counter_items(tokens),
        "elements": elements[:100],
        "value_fields": value_fields[:100],
        "template_values": template_values[:100],
        "template_ids": sorted(set(template_ids)),
        "template_value_count": len(template_values),
        "rendered_preview": "".join(rendered)[:4000],
        "token_count": sum(tokens.values()),
        "warnings": warnings[:25],
    }


def parse_binxml_template_instance(blob: bytes, offset: int) -> dict[str, object]:
    warnings: list[str] = []
    cursor = offset + 1
    if cursor >= len(blob) or blob[cursor] != 0xB0:
        return {
            "status": "template-header-invalid",
            "offset": offset,
            "next_offset": offset + 1,
            "warnings": [f"template-marker-missing:{offset}"],
            "elements": [],
            "value_fields": [],
            "rendered_preview": "",
            "token_counts": [],
        }
    if cursor + 21 > len(blob):
        return {
            "status": "template-header-truncated",
            "offset": offset,
            "next_offset": len(blob),
            "warnings": [f"template-header-truncated:{offset}"],
            "elements": [],
            "value_fields": [],
            "rendered_preview": "",
            "token_counts": [],
        }

    template_id = format_guid_le(blob[cursor + 1 : cursor + 17])
    template_length = read_u32(blob, cursor + 17)
    body_start = cursor + 21
    body_end = min(len(blob), body_start + template_length)
    if body_end <= body_start:
        warnings.append("template-definition-empty")
    if body_start + template_length > len(blob):
        warnings.append("template-definition-truncated")

    values, values_next_offset, value_warnings = read_binxml_template_values(blob, body_end)
    warnings.extend(value_warnings)
    fragment = parse_binxml_fragment_tokens(blob[body_start:body_end], substitutions=values)
    warnings.extend(str(item) for item in fragment.get("warnings", []) if str(item))
    value_fields = [
        {
            "element": "TemplateInstance",
            "element_path": "TemplateInstance",
            "text": template_id,
            "value_type": "TemplateInstance",
            "offset": offset,
            "confidence": "binxml-template-header",
            "template_marker": "0xb0",
            "template_id": template_id,
            "template_definition_length": template_length,
        }
    ]
    value_fields.extend(values)
    value_fields.extend(item for item in fragment.get("value_fields", []) if isinstance(item, Mapping))
    return {
        "status": "template-substituted-partial" if values else "template-tokenized",
        "offset": offset,
        "next_offset": values_next_offset,
        "template_id": template_id,
        "template_definition_length": template_length,
        "template_value_count": len(values),
        "template_values": values[:100],
        "elements": list(fragment.get("elements", []))[:100],
        "value_fields": value_fields[:150],
        "rendered_preview": str(fragment.get("rendered_preview") or "")[:4000],
        "token_counts": list(fragment.get("token_counts", [])),
        "warnings": warnings[:25],
    }


def parse_binxml_fragment_tokens(
    payload: bytes,
    *,
    substitutions: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    offset = 0
    stack: list[dict[str, object]] = []
    elements: list[dict[str, object]] = []
    value_fields: list[dict[str, object]] = []
    tokens: Counter[str] = Counter()
    rendered: list[str] = []
    version: dict[str, object] = {}
    warnings: list[str] = []
    substitution_values = list(substitutions or [])

    while offset < len(payload) and sum(tokens.values()) < MAX_NATIVE_EVTX_BINXML_TOKENS:
        token = payload[offset]
        token_kind = token & 0xBF
        more = bool(token & 0x40)
        tokens[binxml_token_name(token)] += 1
        if token == 0x00:
            offset += 1
            break
        if token_kind == 0x0F:
            if offset + 4 > len(payload):
                warnings.append("truncated-fragment-header")
                break
            version = {
                "major_version": payload[offset + 1],
                "minor_version": payload[offset + 2],
                "flags": payload[offset + 3],
            }
            offset += 4
            continue
        if token_kind == 0x01:
            next_offset = offset + 1
            dependency_id = read_u16(payload, next_offset)
            byte_length = read_u32(payload, next_offset + 2)
            name, after_name = read_binxml_name(payload, next_offset + 6)
            if not name:
                warnings.append(f"truncated-start-element:{offset}")
                break
            path = "/".join([str(item.get("name") or "") for item in stack] + [name])
            stack.append({"name": name, "path": path, "open": False})
            elements.append(
                {
                    "name": name,
                    "path": path,
                    "offset": offset,
                    "dependency_id": dependency_id,
                    "byte_length": byte_length,
                    "has_attribute_list": more,
                }
            )
            rendered.append(f"<{name}")
            offset = after_name
            continue
        if token_kind == 0x06:
            name, after_name = read_binxml_name(payload, offset + 1)
            if not name:
                warnings.append(f"truncated-attribute:{offset}")
                break
            text, after_value, value_type = read_inline_binxml_value_text(payload, after_name)
            current_path = str(stack[-1].get("path") or "") if stack else ""
            value_fields.append(
                {
                    "element": str(stack[-1].get("name") or "") if stack else "",
                    "element_path": f"{current_path}/@{name}" if current_path else f"@{name}",
                    "attribute": name,
                    "text": text,
                    "value_type": value_type,
                    "offset": offset,
                    "confidence": "binxml-attribute",
                    "more": more,
                }
            )
            rendered.append(f' {name}="{html.escape(text)}"')
            offset = after_value
            continue
        if token_kind == 0x02:
            if stack:
                stack[-1]["open"] = True
            rendered.append(">")
            offset += 1
            continue
        if token_kind == 0x03:
            rendered.append("/>")
            if stack:
                stack.pop()
            offset += 1
            continue
        if token_kind == 0x04:
            name = str(stack.pop().get("name") or "") if stack else ""
            rendered.append(f"</{name}>")
            offset += 1
            continue
        if token_kind == 0x05:
            text, after_value, value_type = read_inline_binxml_value_text(payload, offset)
            current = stack[-1] if stack else {}
            current_path = str(current.get("path") or "")
            value_fields.append(
                {
                    "element": str(current.get("name") or ""),
                    "element_path": current_path,
                    "text": text,
                    "value_type": value_type,
                    "offset": offset,
                    "confidence": "binxml-value-text",
                    "more": more,
                }
            )
            rendered.append(html.escape(text))
            offset = after_value
            continue
        if token_kind in {0x0D, 0x0E}:
            if offset + 4 > len(payload):
                warnings.append(f"truncated-substitution:{offset}")
                break
            substitution_id = read_u16(payload, offset + 1)
            expected_type = payload[offset + 3]
            current = stack[-1] if stack else {}
            current_path = str(current.get("path") or "")
            value = substitution_values[substitution_id] if substitution_id < len(substitution_values) else {}
            text = str(value.get("text") or "") if isinstance(value, Mapping) else ""
            value_type = str(value.get("value_type") or binxml_value_type_name(expected_type)) if isinstance(value, Mapping) else binxml_value_type_name(expected_type)
            optional = token_kind == 0x0E
            if not text and optional:
                offset += 4
                continue
            value_fields.append(
                {
                    "element": str(current.get("name") or ""),
                    "element_path": current_path,
                    "text": text,
                    "value_type": value_type,
                    "offset": offset,
                    "confidence": "binxml-template-substitution",
                    "substitution_id": substitution_id,
                    "expected_value_type": binxml_value_type_name(expected_type),
                    "optional": optional,
                }
            )
            rendered.append(html.escape(text))
            offset += 4
            continue
        warnings.append(f"unsupported-template-token:0x{token:02x}@{offset}")
        offset += 1

    status = "basic-rendered" if elements or value_fields else NATIVE_EVTX_BINXML_STATUS
    if warnings:
        status = "partial-tokenized" if elements or value_fields else NATIVE_EVTX_BINXML_STATUS
    return {
        "status": status,
        "version": version,
        "token_counts": counter_items(tokens),
        "elements": elements,
        "value_fields": value_fields,
        "rendered_preview": "".join(rendered)[:4000],
        "token_count": sum(tokens.values()),
        "warnings": warnings[:25],
    }


def read_binxml_name(blob: bytes, offset: int) -> tuple[str, int]:
    if offset + 4 > len(blob):
        return "", offset
    char_count = read_u16(blob, offset + 2)
    start = offset + 4
    end = start + char_count * 2
    terminator_end = end + 2
    if terminator_end > len(blob):
        return "", offset
    name = decode_utf16le_string(blob[start:end])
    return name, terminator_end


def read_inline_binxml_value_text(blob: bytes, offset: int) -> tuple[str, int, str]:
    if offset + 2 > len(blob):
        return "", offset + 1, "truncated"
    token = blob[offset]
    token_kind = token & 0xBF
    if token_kind != 0x05:
        return "", offset, "missing-value-text-token"
    value_type = blob[offset + 1]
    value_type_name = binxml_value_type_name(value_type)

    if value_type == 0x00:
        return "", offset + 2, value_type_name
    if value_type == 0x01:
        if offset + 4 > len(blob):
            return "", len(blob), "truncated-string"
        char_count = read_u16(blob, offset + 2)
        start = offset + 4
        end = start + char_count * 2
        if end > len(blob):
            return "", len(blob), "truncated-string"
        text = decode_utf16le_string(blob[start:end])
        return text, end, value_type_name
    if value_type == 0x02:
        if offset + 4 > len(blob):
            return "", len(blob), "truncated-ansi-string"
        byte_count = read_u16(blob, offset + 2)
        start = offset + 4
        end = start + byte_count
        if end > len(blob):
            return "", len(blob), "truncated-ansi-string"
        text, _ = decode_binxml_template_value(blob[start:end], value_type)
        return text, end, value_type_name
    if value_type == 0x0E:
        if offset + 4 > len(blob):
            return "", len(blob), "truncated-binary"
        byte_count = read_u16(blob, offset + 2)
        start = offset + 4
        end = start + byte_count
        if end > len(blob):
            return "", len(blob), "truncated-binary"
        text, _ = decode_binxml_template_value(blob[start:end], value_type)
        return text, end, value_type_name
    if value_type == 0x13:
        start = offset + 2
        if start + 8 > len(blob):
            return "", len(blob), "truncated-sid"
        sub_authority_count = blob[start + 1]
        byte_count = 8 + sub_authority_count * 4
        end = start + byte_count
        if end > len(blob):
            return "", len(blob), "truncated-sid"
        text, _ = decode_binxml_template_value(blob[start:end], value_type)
        return text, end, value_type_name

    fixed_lengths = {
        0x03: 1,
        0x04: 1,
        0x05: 2,
        0x06: 2,
        0x07: 4,
        0x08: 4,
        0x09: 8,
        0x0A: 8,
        0x0B: 4,
        0x0C: 8,
        0x0D: 4,
        0x0F: 16,
        0x11: 8,
        0x12: 16,
        0x14: 4,
        0x15: 8,
    }
    byte_count = fixed_lengths.get(value_type)
    if byte_count is None:
        return "", offset + 2, f"unsupported-type-0x{value_type:02x}"
    start = offset + 2
    end = start + byte_count
    if end > len(blob):
        return "", len(blob), f"truncated-{value_type_name.lower()}"
    text, _ = decode_binxml_template_value(blob[start:end], value_type)
    return text, end, value_type_name


def read_binxml_template_values(blob: bytes, offset: int) -> tuple[list[dict[str, object]], int, list[str]]:
    warnings: list[str] = []
    values: list[dict[str, object]] = []
    if offset + 4 > len(blob):
        return values, offset, ["template-instance-data-missing"]
    value_count = read_u32(blob, offset)
    if value_count > 1024:
        return values, offset + 4, [f"template-value-count-too-large:{value_count}"]
    spec_offset = offset + 4
    value_offset = spec_offset + value_count * 4
    if value_offset > len(blob):
        return values, len(blob), ["template-value-spec-truncated"]

    specs: list[dict[str, int]] = []
    for index in range(value_count):
        entry_offset = spec_offset + index * 4
        length = read_u16(blob, entry_offset)
        value_type = blob[entry_offset + 2]
        reserved = blob[entry_offset + 3]
        if reserved != 0:
            warnings.append(f"template-value-spec-reserved-nonzero:{index}")
        specs.append({"length": length, "value_type": value_type})

    cursor = value_offset
    for index, spec in enumerate(specs):
        length = spec["length"]
        value_type = spec["value_type"]
        value_blob = blob[cursor : cursor + length]
        if cursor + length > len(blob):
            warnings.append(f"template-value-truncated:{index}")
            value_blob = blob[cursor:]
            cursor = len(blob)
        else:
            cursor += length
        text, normalized_value = decode_binxml_template_value(value_blob, value_type)
        values.append(
            {
                "element": "TemplateValue",
                "element_path": f"TemplateInstance/Value[{index}]",
                "text": text,
                "value": normalized_value,
                "value_type": binxml_value_type_name(value_type),
                "value_type_id": value_type,
                "value_length": length,
                "offset": cursor - len(value_blob),
                "confidence": "binxml-template-value",
                "substitution_id": index,
            }
        )
    return values, cursor, warnings


def decode_binxml_template_value(value_blob: bytes, value_type: int) -> tuple[str, object]:
    if value_type == 0x00:
        return "", None
    if value_type == 0x01:
        text = decode_utf16le_string(value_blob).rstrip("\x00")
        return text, text
    if value_type == 0x02:
        text = value_blob.rstrip(b"\x00").decode("latin-1", errors="replace")
        return text, text
    if value_type in {0x03, 0x04} and len(value_blob) >= 1:
        signed = value_type == 0x03
        value = int.from_bytes(value_blob[:1], "little", signed=signed)
        return str(value), value
    if value_type in {0x05, 0x06} and len(value_blob) >= 2:
        signed = value_type == 0x05
        value = int.from_bytes(value_blob[:2], "little", signed=signed)
        return str(value), value
    if value_type in {0x07, 0x08, 0x14} and len(value_blob) >= 4:
        signed = value_type == 0x07
        value = int.from_bytes(value_blob[:4], "little", signed=signed)
        text = f"0x{value:08x}" if value_type == 0x14 else str(value)
        return text, value
    if value_type in {0x09, 0x0A, 0x15} and len(value_blob) >= 8:
        signed = value_type == 0x09
        value = int.from_bytes(value_blob[:8], "little", signed=signed)
        text = f"0x{value:016x}" if value_type == 0x15 else str(value)
        return text, value
    if value_type == 0x0D and value_blob:
        value = value_blob[0] != 0
        return str(value).lower(), value
    if value_type == 0x0B and len(value_blob) >= 4:
        value = struct.unpack("<f", value_blob[:4])[0]
        return f"{value:.6g}", value
    if value_type == 0x0C and len(value_blob) >= 8:
        value = struct.unpack("<d", value_blob[:8])[0]
        return f"{value:.12g}", value
    if value_type == 0x0F and len(value_blob) >= 16:
        text = format_guid_le(value_blob[:16])
        return text, text
    if value_type == 0x11 and len(value_blob) >= 8:
        text = filetime_to_iso(int.from_bytes(value_blob[:8], "little", signed=False))
        return text, text
    if value_type == 0x12 and len(value_blob) >= 16:
        text = systime_to_iso(value_blob[:16])
        return text, text
    if value_type == 0x13:
        text = sid_to_string(value_blob)
        return text, text
    if value_type == 0x0E:
        text = value_blob.hex()
        return text, text
    text = value_blob.hex()
    return text, text


def binxml_value_type_name(value_type: int) -> str:
    names = {
        0x00: "NullType",
        0x01: "StringType",
        0x02: "AnsiStringType",
        0x03: "Int8Type",
        0x04: "UInt8Type",
        0x05: "Int16Type",
        0x06: "UInt16Type",
        0x07: "Int32Type",
        0x08: "UInt32Type",
        0x09: "Int64Type",
        0x0A: "UInt64Type",
        0x0B: "Real32Type",
        0x0C: "Real64Type",
        0x0D: "BoolType",
        0x0E: "BinaryType",
        0x0F: "GuidType",
        0x11: "FileTimeType",
        0x12: "SysTimeType",
        0x13: "SidType",
        0x14: "HexInt32Type",
        0x15: "HexInt64Type",
        0x21: "BinXmlType",
    }
    return names.get(value_type, f"UnknownType0x{value_type:02x}")


def format_guid_le(value: bytes) -> str:
    if len(value) < 16:
        return value.hex()
    return (
        f"{int.from_bytes(value[0:4], 'little'):08x}-"
        f"{int.from_bytes(value[4:6], 'little'):04x}-"
        f"{int.from_bytes(value[6:8], 'little'):04x}-"
        f"{value[8:10].hex()}-{value[10:16].hex()}"
    )


def sid_to_string(value: bytes) -> str:
    if len(value) < 8:
        return value.hex()
    revision = value[0]
    sub_authority_count = value[1]
    expected_length = 8 + sub_authority_count * 4
    if len(value) < expected_length:
        return value.hex()
    authority = int.from_bytes(value[2:8], "big", signed=False)
    sub_authorities = [
        str(int.from_bytes(value[8 + index * 4 : 12 + index * 4], "little", signed=False))
        for index in range(sub_authority_count)
    ]
    return "-".join([f"S-{revision}", str(authority), *sub_authorities])


def systime_to_iso(value: bytes) -> str:
    if len(value) < 16:
        return ""
    year = int.from_bytes(value[0:2], "little")
    month = int.from_bytes(value[2:4], "little")
    day = int.from_bytes(value[6:8], "little")
    hour = int.from_bytes(value[8:10], "little")
    minute = int.from_bytes(value[10:12], "little")
    second = int.from_bytes(value[12:14], "little")
    millisecond = int.from_bytes(value[14:16], "little")
    try:
        return dt.datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            millisecond * 1000,
            tzinfo=dt.timezone.utc,
        ).isoformat()
    except ValueError:
        return ""


def binxml_token_name(token: int) -> str:
    names = {
        0x00: "EOFToken",
        0x01: "OpenStartElementToken",
        0x41: "OpenStartElementTokenMore",
        0x02: "CloseStartElementToken",
        0x03: "CloseEmptyElementToken",
        0x04: "EndElementToken",
        0x05: "ValueTextToken",
        0x45: "ValueTextTokenMore",
        0x06: "AttributeToken",
        0x46: "AttributeTokenMore",
        0x0C: "TemplateInstanceToken",
        0x0D: "NormalSubstitutionToken",
        0x0E: "OptionalSubstitutionToken",
        0x0F: "FragmentHeaderToken",
    }
    return names.get(token, f"UnknownToken0x{token:02x}")


def native_evtx_message_preview(indicators: Mapping[str, object], strings: Sequence[str]) -> str:
    parts: list[str] = []
    labels = (
        ("provider", indicators.get("provider_name")),
        ("channel", indicators.get("channel")),
        ("computer", indicators.get("computer")),
        ("command", indicators.get("command_line")),
        ("process", indicators.get("process_name")),
        ("source_ip", indicators.get("source_ip")),
        ("user", indicators.get("user_name")),
    )
    for label, value in labels:
        text = str(value or "").strip()
        if text:
            parts.append(f"{label}={text}")
    seen = {part.split("=", 1)[-1] for part in parts}
    for value in strings:
        text = str(value or "").strip()
        if text and text not in seen:
            parts.append(text)
            seen.add(text)
        if len(parts) >= 20:
            break
    return " | ".join(parts)[:2000]


def first_native_channel(strings: Sequence[str]) -> str:
    for value in strings:
        lowered = value.lower()
        if "/operational" in lowered or "/admin" in lowered or "/debug" in lowered:
            return value
    for value in strings:
        if value in {"Security", "System", "Application", "Setup"}:
            return value
    return ""


def channel_hint_from_path(path: Path) -> str:
    stem = path.stem
    if not stem:
        return ""
    return stem.replace("%4", "/")


def first_command_string(strings: Sequence[str]) -> str:
    command_patterns = (
        r"\bpowershell(?:\.exe)?\s+",
        r"\bpwsh(?:\.exe)?\s+",
        r"\bcmd\.exe\s+",
        r"\bwscript(?:\.exe)?\s+",
        r"\bcscript(?:\.exe)?\s+",
        r"\brundll32(?:\.exe)?\s+",
        r"\bregsvr32(?:\.exe)?\s+",
        r"\bmshta(?:\.exe)?\s+",
        r"\bwevtutil(?:\.exe)?\s+",
        r"\bvssadmin(?:\.exe)?\s+",
        r"\bwmic(?:\.exe)?\s+",
    )
    for value in strings:
        lowered = value.lower()
        if any(re.search(pattern, lowered) for pattern in command_patterns):
            return value
    return ""


def first_process_path(strings: Sequence[str]) -> str:
    for value in strings:
        lowered = value.lower()
        if lowered.endswith(".exe") or "\\system32\\" in lowered or "\\syswow64\\" in lowered:
            return value
    return ""


def iter_ip_addresses(strings: Sequence[str]) -> Iterable[str]:
    for value in strings:
        for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
            parts = [int(part) for part in match.split(".") if part.isdigit()]
            if len(parts) == 4 and all(0 <= part <= 255 for part in parts):
                yield match


def iter_user_candidates(strings: Sequence[str]) -> Iterable[str]:
    for value in strings:
        if re.fullmatch(r"[A-Za-z0-9._$-]{3,64}", value) and not value.lower().endswith((".exe", ".dll")):
            if not value.lower().startswith(("microsoft-", "windows", "system32")):
                yield value
        domain_user = re.search(r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9._$-]{2,64}\b", value)
        if domain_user:
            yield domain_user.group(0)


def iter_url_candidates(strings: Sequence[str]) -> Iterable[str]:
    for value in strings:
        for match in re.findall(r"https?://[^\s\"'<>]+", value):
            yield match.rstrip(".,;)")


def iter_path_candidates(strings: Sequence[str]) -> Iterable[str]:
    for value in strings:
        if re.search(r"[A-Za-z]:\\", value) or value.startswith("\\\\"):
            yield value


def native_evtx_confidence(details: Mapping[str, object]) -> float:
    score = 0.55
    if details.get("record_id"):
        score += 0.05
    if details.get("timestamp"):
        score += 0.05
    if details.get("provider_name"):
        score += 0.05
    if details.get("channel"):
        score += 0.05
    integrity = details.get("evtx_record_integrity") if isinstance(details.get("evtx_record_integrity"), Mapping) else {}
    if integrity.get("declared_size_valid"):
        score += 0.05
    if integrity.get("trailing_size_valid"):
        score += 0.05
    if details.get("command_line") or details.get("source_ip") or details.get("user_name"):
        score += 0.05
    if details.get("evtx_binxml_status") in {"basic-rendered", "partial-tokenized"}:
        score += 0.05
    recovery = details.get("evtx_recovery_context") if isinstance(details.get("evtx_recovery_context"), Mapping) else {}
    if recovery.get("status") in {"slack-or-deleted-record-candidate", "corrupt-record-candidate"}:
        score = min(score, float(recovery.get("confidence") or 0.6))
    return min(0.82, round(score, 2))


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


def render_event_message(
    *,
    provider_name: str,
    event_id: str,
    category: str,
    data: Mapping[str, object],
    raw_preview: str,
    is_native_evtx: bool,
) -> dict[str, object]:
    external_message = first_data_text(data, "RenderedMessage", "Message", "MapDescription", "EventMessage")
    template_ids = native_evtx_template_ids(data)
    if external_message:
        message_source = "imported-export-field"
        return {
            "status": "external-message",
            "message": external_message[:4000],
            "message_source": message_source,
            "rendering_confidence": 0.98,
            "provider_resource_required": False,
            "provider_name": provider_name,
            "event_id": event_id,
            "event_category": category,
            "template_ids": template_ids,
            "validation_required": False,
            "rendering_limitations": [],
            "warnings": [],
            "provenance": event_message_provenance(
                data=data,
                is_native_evtx=is_native_evtx,
                message_source=message_source,
                renderer="external-export-field",
                validation_required=False,
            ),
        }

    template = event_message_template(provider_name, event_id)
    if template:
        message, missing_fields = render_message_template(template, data)
        message_source = "rapidtriage-builtin-event-template"
        return {
            "status": "rendered-builtin-template",
            "message": message[:4000],
            "message_source": message_source,
            "rendering_confidence": 0.72 if is_native_evtx else 0.84,
            "provider_resource_required": is_native_evtx,
            "provider_name": provider_name,
            "event_id": event_id,
            "event_category": category,
            "template_ids": template_ids,
            "missing_fields": missing_fields,
            "validation_required": is_native_evtx,
            "rendering_limitations": ["provider-resource-not-used"] if is_native_evtx else [],
            "warnings": ["validate-against-provider-message-resource"] if is_native_evtx else [],
            "provenance": event_message_provenance(
                data=data,
                is_native_evtx=is_native_evtx,
                message_source=message_source,
                renderer="rapidtriage-builtin-template",
                validation_required=is_native_evtx,
            ),
        }

    preview = str(data.get("native_message_preview") or raw_preview or "")
    warnings = ["provider-message-resource-not-resolved"] if is_native_evtx else []
    if template_ids and is_native_evtx:
        warnings.append("native-template-id-preserved")
    message_source = "binxml-rendered-preview" if preview else "unavailable"
    return {
        "status": "unresolved-provider-template" if is_native_evtx else "no-template-available",
        "message": preview[:4000],
        "message_source": message_source,
        "rendering_confidence": 0.42 if is_native_evtx and preview else 0.2,
        "provider_resource_required": is_native_evtx,
        "provider_name": provider_name,
        "event_id": event_id,
        "event_category": category,
        "template_ids": template_ids,
        "validation_required": is_native_evtx,
        "rendering_limitations": ["provider-message-resource-not-resolved"] if is_native_evtx else [],
        "warnings": warnings,
        "provenance": event_message_provenance(
            data=data,
            is_native_evtx=is_native_evtx,
            message_source=message_source,
            renderer="native-binxml-preview" if is_native_evtx and preview else "unresolved",
            validation_required=is_native_evtx,
        ),
    }


def event_message_provenance(
    *,
    data: Mapping[str, object],
    is_native_evtx: bool,
    message_source: str,
    renderer: str,
    validation_required: bool,
) -> dict[str, object]:
    provenance: dict[str, object] = {
        "message_source": message_source,
        "renderer": renderer,
        "provider_message_resource_resolved": False,
        "validation_required": validation_required,
    }
    if not is_native_evtx:
        provenance["provider_message_resource_resolved"] = message_source == "imported-export-field"
        return provenance

    binxml = data.get("evtx_binxml") if isinstance(data.get("evtx_binxml"), Mapping) else {}
    provenance.update(
        {
            "native_binxml_status": str(data.get("evtx_binxml_status") or ""),
            "native_field_fidelity": str(data.get("evtx_field_fidelity") or ""),
            "native_recovery_status": str(data.get("evtx_recovery_status") or ""),
            "native_allocation_status": str(data.get("evtx_allocation_status") or ""),
            "template_ids": native_evtx_template_ids(data),
            "template_value_count": int(binxml.get("template_value_count") or 0) if isinstance(binxml, Mapping) else 0,
        }
    )
    return provenance


def render_message_template(template: str, data: Mapping[str, object]) -> tuple[str, list[str]]:
    missing_fields: list[str] = []

    def replace(match: re.Match[str]) -> str:
        expression = match.group(1)
        keys = [key.strip() for key in expression.split("|") if key.strip()]
        value = first_data_text(data, *keys)
        if value:
            return value
        missing_fields.append(expression)
        return ""

    rendered = re.sub(r"\{([^{}]+)\}", replace, template)
    return re.sub(r"\s+", " ", rendered).strip(), missing_fields


def event_message_template(provider_name: str, event_id: str) -> str:
    provider_key = provider_name.lower()
    for marker, templates in PROVIDER_EVENT_MESSAGE_TEMPLATES.items():
        if marker in provider_key and event_id in templates:
            return templates[event_id]
    return EVENT_MESSAGE_TEMPLATES.get(event_id, "")


def native_evtx_template_ids(data: Mapping[str, object]) -> list[str]:
    binxml = data.get("evtx_binxml") if isinstance(data, Mapping) else {}
    if not isinstance(binxml, Mapping):
        return []
    candidates: list[str] = []
    if isinstance(binxml.get("template_ids"), list):
        candidates.extend(str(item) for item in binxml.get("template_ids", []) if str(item))
    template_id = str(binxml.get("template_id") or "")
    if template_id:
        candidates.append(template_id)
    for item in binxml.get("value_fields", []) if isinstance(binxml.get("value_fields"), list) else []:
        if isinstance(item, Mapping) and item.get("template_id"):
            candidates.append(str(item.get("template_id")))
    return sorted(set(candidates))


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
    service_file_name = first_data_text(data, "ServiceFileName", "ImagePath")
    new_process_name = first_data_text(data, "NewProcessName", "ProcessName", "Image")
    parent_process_name = first_data_text(data, "ParentProcessName", "CreatorProcessName")
    parent_command_line = first_data_text(data, "ParentCommandLine", "ParentProcessCommandLine")
    script_block_text = first_data_text(data, "ScriptBlockText")
    destination_ip = first_data_text(data, "DestinationIp", "DestAddress", "DestinationAddress")
    destination_hostname = first_data_text(data, "DestinationHostname", "DestinationHostName", "DestHost")
    destination_port = first_data_text(data, "DestinationPort", "DestPort")
    query_name = first_data_text(data, "QueryName", "Query", "DnsQuery")
    target_object = first_data_text(data, "TargetObject", "ObjectName", "ObjectValueName")
    image_loaded = first_data_text(data, "ImageLoaded", "LoadedImage")
    task_name = first_data_text(data, "TaskName", "TaskContent")
    workstation_name = first_data_text(data, "WorkstationName", "Workstation")
    logon_process_name = first_data_text(data, "LogonProcessName")
    authentication_package_name = first_data_text(data, "AuthenticationPackageName")
    status_code = first_data_text(data, "Status", "SubStatus", "ErrorCode")
    failure_reason = first_data_text(data, "FailureReason")
    share_name = first_data_text(data, "ShareName")
    relative_target_name = first_data_text(data, "RelativeTargetName", "FileName")
    if not user_sid:
        user_sid = first_data_text(data, "TargetUserSid", "SubjectUserSid", "UserSid")
    if not user_name:
        user_name = target_user_name or subject_user_name
    if not process_name:
        process_name = new_process_name
    if not command_line:
        command_line = first_data_text(data, "CommandLine", "ProcessCommandLine") or script_block_text
    category, description = event_category_for(normalized_event_id, channel)
    channel_family_value = channel_family(channel)
    event_family = inferred_event_family(category, channel_family_value)
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
    parser_confidence = parser_confidence_score(parser, source_format)
    normalized_timestamp = normalize_timestamp(event_created_at)
    message_rendering = render_event_message(
        provider_name=provider_name,
        event_id=normalized_event_id,
        category=category,
        data=data,
        raw_preview=raw_preview,
        is_native_evtx=is_native_evtx,
    )
    return {
        "parser": parser,
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-binary-partial" if is_native_evtx else ("detected-by-rule" if rule_title or rule_id else "mapped"),
        "reportability": reportability,
        "parser_confidence": parser_confidence,
        "evidence_strength": "partial-event-record" if is_native_evtx else "event-log-record",
        "source_path": str(source_path.resolve()),
        "source_format": source_format,
        "source_index": source_index,
        "source_hashes": dict(source_hashes),
        "provider_name": provider_name,
        "event_id": normalized_event_id,
        "event_category": category,
        "event_family": event_family,
        "event_tags": event_tags(normalized_event_id, category, event_family, channel_family_value, detected_terms),
        "event_description": description,
        "event_message": message_rendering.get("message") or "",
        "message_rendering": message_rendering,
        "record_id": str(record_id or ""),
        "channel": channel,
        "channel_family": channel_family_value,
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
        "destination_ip": destination_ip,
        "destination_hostname": destination_hostname,
        "destination_port": destination_port,
        "service_name": service_name,
        "service_file_name": service_file_name,
        "process_id": process_id,
        "thread_id": thread_id,
        "process_name": process_name,
        "new_process_name": new_process_name,
        "parent_process_name": parent_process_name,
        "parent_command_line": parent_command_line,
        "command_line": command_line,
        "script_block_text": script_block_text,
        "query_name": query_name,
        "target_object": target_object,
        "image_loaded": image_loaded,
        "task_name": task_name,
        "workstation_name": workstation_name,
        "logon_process_name": logon_process_name,
        "authentication_package_name": authentication_package_name,
        "status_code": status_code,
        "failure_reason": failure_reason,
        "share_name": share_name,
        "relative_target_name": relative_target_name,
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
        "triage_recommendation": triage_recommendation(category, detected_terms),
        "data": dict(data),
        "raw_preview": raw_preview,
    }


def build_eventlog_file_record(
    path: Path,
    *,
    native_record_count: int = 0,
    native_record_candidate_count: int = 0,
) -> ArtifactRecord:
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
            "channel_hint": channel_hint_from_path(path),
            "native_record_count": native_record_count,
            "native_record_candidate_count": native_record_candidate_count,
            "native_parse_status": (
                "partial-record-scan"
                if native_record_count
                else ("candidate-record-scan" if native_record_candidate_count else "no-records-emitted")
            ),
            "native_parser_scope": NATIVE_EVTX_PARSE_SCOPE,
            "native_binxml_status": NATIVE_EVTX_BINXML_STATUS,
            "native_capabilities": NATIVE_EVTX_CAPABILITIES,
            "native_report_grade_blockers": NATIVE_EVTX_REPORT_GRADE_BLOCKERS,
            "native_validation_required": True,
            "recommended_parsers": ["EvtxECmd", "Hayabusa", "Chainsaw", "Velociraptor Windows.EventLogs.Evtx"],
            "note": "Binary EVTX detected. RapidTriage emits partial native record rows when record headers and BinXML fields are recoverable; import EvtxECmd/Hayabusa/Chainsaw/Velociraptor JSONL/CSV/XML output for report-grade provider message rendering.",
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
        "event_family": details.get("event_family") or "",
        "event_tags": list(details.get("event_tags") or []),
        "event_description": details.get("event_description") or "",
        "record_id": details.get("record_id") or "",
        "channel": details.get("channel") or "",
        "channel_family": details.get("channel_family") or "",
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
        "destination_ip": details.get("destination_ip") or "",
        "destination_hostname": details.get("destination_hostname") or "",
        "destination_port": details.get("destination_port") or "",
        "service_name": details.get("service_name") or "",
        "service_file_name": details.get("service_file_name") or "",
        "process_id": details.get("process_id") or "",
        "thread_id": details.get("thread_id") or "",
        "process_name": details.get("process_name") or "",
        "new_process_name": details.get("new_process_name") or "",
        "parent_process_name": details.get("parent_process_name") or "",
        "parent_command_line": details.get("parent_command_line") or "",
        "command_line": details.get("command_line") or "",
        "script_block_text": details.get("script_block_text") or "",
        "query_name": details.get("query_name") or "",
        "target_object": details.get("target_object") or "",
        "image_loaded": details.get("image_loaded") or "",
        "task_name": details.get("task_name") or "",
        "workstation_name": details.get("workstation_name") or "",
        "logon_process_name": details.get("logon_process_name") or "",
        "authentication_package_name": details.get("authentication_package_name") or "",
        "status_code": details.get("status_code") or "",
        "failure_reason": details.get("failure_reason") or "",
        "share_name": details.get("share_name") or "",
        "relative_target_name": details.get("relative_target_name") or "",
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
        "matched_fields": rule_matched_fields(rule, details),
        "false_positive_note": rule.get("false_positive_note") or "Validate expected administration, source host, account owner, and nearby activity before reporting.",
        "triage_recommendation": rule.get("triage_recommendation") or details.get("triage_recommendation") or "",
        "matched_event": {
            "artifact_type": source_record.artifact_type,
            "path": source_record.path,
            "source_index": details.get("source_index"),
            "record_id": details.get("record_id") or "",
            "source_hashes": dict(details.get("source_hashes") or {}),
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
        if record.artifact_type in {"eventlog-event", "eventlog-detection", "eventlog-record-candidate"}
        and isinstance(record.details, Mapping)
    ]
    inventory_rows = [record for record in records if record.artifact_type == "eventlog-file"]
    chunk_rows = [
        record
        for record in records
        if record.artifact_type == "eventlog-chunk" and isinstance(record.details, Mapping)
    ]
    candidate_rows = [
        record
        for record in records
        if record.artifact_type == "eventlog-record-candidate" and isinstance(record.details, Mapping)
    ]
    if not parsed_rows and not inventory_rows:
        return None

    event_id_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    channel_counts: Counter[str] = Counter()
    channel_family_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    source_ip_counts: Counter[str] = Counter()
    process_counts: Counter[str] = Counter()
    parser_status_counts: Counter[str] = Counter()
    reportability_counts: Counter[str] = Counter()
    risk_term_counts: Counter[str] = Counter()
    native_integrity_counts: Counter[str] = Counter()
    native_sequence_counts: Counter[str] = Counter()
    native_channel_hint_counts: Counter[str] = Counter()
    native_binxml_status_counts: Counter[str] = Counter()
    native_recovery_status_counts: Counter[str] = Counter()
    native_allocation_status_counts: Counter[str] = Counter()
    native_boundary_status_counts: Counter[str] = Counter()
    native_report_grade_status_counts: Counter[str] = Counter()
    native_chunk_integrity_counts: Counter[str] = Counter()
    source_paths: set[str] = set()
    timestamps: list[str] = []
    high_risk_events: list[dict[str, object]] = []
    record_ids_by_channel: dict[str, list[int]] = defaultdict(list)
    detection_rule_counts: Counter[str] = Counter()
    detection_level_counts: Counter[str] = Counter()

    for record in event_rows:
        details = record.details
        event_id = str(details.get("event_id") or "")
        category = str(details.get("event_category") or "")
        family = str(details.get("event_family") or "")
        channel = str(details.get("channel") or "unknown")
        channel_family_value = str(details.get("channel_family") or "unknown")
        user_name = str(details.get("user_name") or details.get("target_user_name") or details.get("subject_user_name") or "")
        source_ip = str(details.get("source_ip") or "")
        process_name = str(details.get("process_name") or details.get("new_process_name") or "")
        source_path = str(details.get("source_path") or record.path)
        timestamp = str(details.get("timestamp") or details.get("event_created_at") or "")
        record_id = int_text(details.get("record_id"))

        increment_counter(event_id_counts, event_id)
        increment_counter(category_counts, category)
        increment_counter(family_counts, family)
        increment_counter(channel_counts, channel)
        increment_counter(channel_family_counts, channel_family_value)
        increment_counter(user_counts, user_name)
        increment_counter(source_ip_counts, source_ip)
        increment_counter(process_counts, process_name)
        increment_counter(parser_status_counts, str(details.get("coverage_status") or ""))
        increment_counter(reportability_counts, str(details.get("reportability") or ""))
        if details.get("parser") == "windows-eventlog-evtx-native":
            integrity = details.get("evtx_record_integrity") if isinstance(details.get("evtx_record_integrity"), Mapping) else {}
            sequence = details.get("evtx_record_sequence") if isinstance(details.get("evtx_record_sequence"), Mapping) else {}
            native_indicators = details.get("native_indicators") if isinstance(details.get("native_indicators"), Mapping) else {}
            increment_counter(
                native_integrity_counts,
                "trailing-size-valid" if integrity.get("trailing_size_valid") else "trailing-size-unverified",
            )
            increment_counter(native_sequence_counts, str(sequence.get("status") or "unknown"))
            increment_counter(native_channel_hint_counts, str(native_indicators.get("channel_hint_source") or "unknown"))
            increment_counter(native_binxml_status_counts, str(details.get("evtx_binxml_status") or "unknown"))
            increment_counter(native_recovery_status_counts, str(details.get("evtx_recovery_status") or "unknown"))
            increment_counter(native_allocation_status_counts, str(details.get("evtx_allocation_status") or "unknown"))
            chunk_context = details.get("evtx_chunk_context") if isinstance(details.get("evtx_chunk_context"), Mapping) else {}
            report_grade = (
                details.get("evtx_report_grade_assessment")
                if isinstance(details.get("evtx_report_grade_assessment"), Mapping)
                else {}
            )
            increment_counter(native_boundary_status_counts, str(chunk_context.get("chunk_boundary_status") or "unknown"))
            increment_counter(native_report_grade_status_counts, str(report_grade.get("status") or "unknown"))
        for flag in details.get("risk_flags") or []:
            text = str(flag)
            if text.startswith("suspicious-term:"):
                increment_counter(risk_term_counts, text.removeprefix("suspicious-term:"))
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
        rule_level = str(rule.get("level") or "")
        increment_counter(detection_rule_counts, rule_id)
        increment_counter(detection_level_counts, rule_level)
        increment_counter(parser_status_counts, str(details.get("coverage_status") or ""))
        increment_counter(reportability_counts, str(details.get("reportability") or ""))
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

    for record in candidate_rows:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        timestamp = str(details.get("timestamp") or "")
        source_paths.add(source_path)
        if timestamp:
            timestamps.append(timestamp)
        increment_counter(parser_status_counts, str(details.get("coverage_status") or ""))
        increment_counter(reportability_counts, str(details.get("reportability") or ""))
        increment_counter(native_recovery_status_counts, str(details.get("evtx_recovery_status") or "unknown"))
        increment_counter(native_allocation_status_counts, str(details.get("evtx_allocation_status") or "unknown"))
        chunk_context = details.get("evtx_chunk_context") if isinstance(details.get("evtx_chunk_context"), Mapping) else {}
        report_grade = (
            details.get("evtx_report_grade_assessment")
            if isinstance(details.get("evtx_report_grade_assessment"), Mapping)
            else {}
        )
        increment_counter(native_boundary_status_counts, str(chunk_context.get("chunk_boundary_status") or "unknown"))
        increment_counter(native_report_grade_status_counts, str(report_grade.get("status") or "unknown"))

    for record in chunk_rows:
        details = record.details
        source_paths.add(str(details.get("source_path") or record.path))
        integrity = details.get("evtx_chunk_integrity") if isinstance(details.get("evtx_chunk_integrity"), Mapping) else {}
        increment_counter(
            native_chunk_integrity_counts,
            "structure-plausible" if integrity.get("structure_plausible") else "structure-warning",
        )
        increment_counter(
            native_chunk_integrity_counts,
            str(integrity.get("checksum_status") or "checksum-unknown"),
        )
        increment_counter(parser_status_counts, str(details.get("coverage_status") or ""))
        increment_counter(reportability_counts, str(details.get("reportability") or ""))

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
        "native_chunk_count": len(chunk_rows),
        "record_candidate_count": len(candidate_rows),
        "source_files": sorted(source_paths),
        "detection_rule_counts": counter_items(detection_rule_counts),
        "event_id_counts": counter_items(event_id_counts),
        "event_category_counts": counter_items(category_counts),
        "event_family_counts": counter_items(family_counts),
        "channel_counts": counter_items(channel_counts),
        "channel_family_counts": counter_items(channel_family_counts),
        "user_counts": counter_items(user_counts),
        "source_ip_counts": counter_items(source_ip_counts),
        "process_counts": counter_items(process_counts),
        "parser_status_counts": counter_items(parser_status_counts),
        "reportability_counts": counter_items(reportability_counts),
        "risk_term_counts": counter_items(risk_term_counts),
        "native_integrity_counts": counter_items(native_integrity_counts),
        "native_sequence_counts": counter_items(native_sequence_counts),
        "native_channel_hint_counts": counter_items(native_channel_hint_counts),
        "native_binxml_status_counts": counter_items(native_binxml_status_counts),
        "native_recovery_status_counts": counter_items(native_recovery_status_counts),
        "native_allocation_status_counts": counter_items(native_allocation_status_counts),
        "native_boundary_status_counts": counter_items(native_boundary_status_counts),
        "native_report_grade_status_counts": counter_items(native_report_grade_status_counts),
        "native_chunk_integrity_counts": counter_items(native_chunk_integrity_counts),
        "native_capabilities": NATIVE_EVTX_CAPABILITIES,
        "native_report_grade_blockers": NATIVE_EVTX_REPORT_GRADE_BLOCKERS,
        "detection_level_counts": counter_items(detection_level_counts),
        "first_event_at": timestamps[0] if timestamps else "",
        "last_event_at": timestamps[-1] if timestamps else "",
        "high_risk_events": sorted(high_risk_events, key=lambda item: int(item.get("risk_score") or 0), reverse=True)[:50],
        "record_sequence_gaps": record_sequence_gaps(record_ids_by_channel),
        "summary_notes": [
            "Review record_sequence_gaps as triage hints only; filtered exports may naturally contain non-contiguous EventRecordID values.",
            "Binary EVTX rows include partial native record scans when recoverable; native_binxml_status_counts shows whether BinXML field decoding is complete.",
            "eventlog-record-candidate rows and evtx_recovery_context mark slack/deleted/corrupt candidates that require independent validation.",
            "eventlog-chunk rows expose native chunk bounds and checksum observations so recovery candidates can be reviewed against chunk slack/structure.",
            "Use message_rendering.validation_required and external parser exports to separate built-in fallback messages from report-grade provider resource rendering.",
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


def read_u16(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 2], "little", signed=False)


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


def unique_texts(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


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


def event_category_for(event_id: str, channel: str) -> tuple[str, str]:
    if event_id == "22" and "terminalservices" in normalize_key(channel):
        return "rdp-session-logon", "Terminal Services session logon"
    return EVENT_ID_CATEGORIES.get(event_id, ("event", "Windows event log record"))


def event_family_for(category: str) -> str:
    return EVENT_FAMILY_BY_CATEGORY.get(category, category.split("-", 1)[0] if category else "event")


def inferred_event_family(category: str, channel_family_value: str) -> str:
    family = event_family_for(category)
    if family != "event":
        return family
    if channel_family_value in {"powershell", "sysmon"}:
        return "execution"
    if channel_family_value in {"remote-access", "wmi", "defender", "firewall"}:
        return channel_family_value
    return family


def channel_family(channel: str) -> str:
    normalized = normalize_key(channel)
    for needle, family in CHANNEL_FAMILY_HINTS:
        if needle.replace("-", "") in normalized:
            return family
    return "unknown" if not channel else "other"


def event_tags(event_id: str, category: str, family: str, channel_family_value: str, terms: Sequence[str]) -> list[str]:
    tags = [f"family:{family}", f"category:{category}"] if category else [f"family:{family}"]
    if event_id:
        tags.append(f"event-id:{event_id}")
    if channel_family_value and channel_family_value != "unknown":
        tags.append(f"channel:{channel_family_value}")
    tags.extend(f"term:{term}" for term in terms)
    return sorted(set(tags))


def parser_confidence_score(parser: str, source_format: str) -> float:
    if parser == "windows-eventlog-evtx-native":
        return 0.62
    if parser == "windows-eventlog-xml":
        return 0.9
    if "evtxecmd" in parser:
        return 0.9
    if "hayabusa" in parser or "chainsaw" in parser:
        return 0.85
    if source_format in {"json", "jsonl", "ndjson", "csv"}:
        return 0.78
    return 0.7


def triage_recommendation(category: str, terms: Sequence[str]) -> str:
    family = event_family_for(category)
    if terms:
        return "Review command text, parent/child process context, account, host, and adjacent timeline events."
    if family == "authentication":
        return "Pivot by account, source IP/host, logon type, and nearby failures/successes."
    if family in {"persistence", "wmi"}:
        return "Review created service/task/WMI object, command path, author, and surrounding execution artifacts."
    if family == "remote-access":
        return "Correlate session event with logon records, source address, user, and remote-access artifacts."
    if family in {"defense-evasion", "malware"}:
        return "Prioritize for analyst review and correlate with process, Defender, VSC, and file-system evidence."
    return "Use as a timeline/search pivot and validate source hash, parser, and surrounding events before reporting."


def rule_matched_fields(rule: Mapping[str, object], details: Mapping[str, object]) -> list[str]:
    fields: list[str] = []
    if rule.get("event_ids"):
        fields.append("event_id")
    if rule.get("categories"):
        fields.append("event_category")
    if rule.get("logon_types"):
        fields.append("logon_type")
    terms = {str(item).lower() for item in rule.get("terms", set())}
    if terms:
        for field in ("command_line", "script_block_text", "process_name", "new_process_name", "raw_preview", "data"):
            value = details.get(field)
            text = json.dumps(value, ensure_ascii=False, sort_keys=True).lower() if isinstance(value, Mapping) else str(value or "").lower()
            if any(term in text for term in terms):
                fields.append(field)
    return sorted(set(fields))


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
