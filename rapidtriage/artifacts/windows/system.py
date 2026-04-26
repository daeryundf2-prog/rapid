from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from ...core.audit import compute_sha256
from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp

PARSER_VERSION = "windows-system-v3"
TASKS_ROOT = ("Windows", "System32", "Tasks")
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
        uri = first_text(xml_root, "URI") or "\\" + str(path.relative_to(tasks_root)).replace("/", "\\")
        triggers = [local_name(child.tag) for child in find_children(xml_root, "Triggers")]
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
                "author": first_text(xml_root, "Author"),
                "user_id": first_text(xml_root, "UserId"),
                "trigger_types": triggers,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
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
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
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
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
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
                "fields": fields,
                "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
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


def find_children(root: ET.Element, target_name: str) -> list[ET.Element]:
    for element in root.iter():
        if local_name(element.tag) == target_name:
            return list(element)
    return []


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


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
    return {
        "coverage_status": "bounded-string-pivot",
        "scan_bytes": len(blob),
        "extracted_string_count": len(strings),
        "interesting_strings": interesting,
        "path_candidates": path_candidates,
        "url_candidates": url_candidates,
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 15),
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
