from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Mapping

from ...core.models import ArtifactRecord

EVENT_LOG_ROOT = ("Windows", "System32", "winevt", "Logs")
PARSER_VERSION = "eventlog-export-v1"


class WindowsEventLogProvider:
    name = "windows-eventlog"
    description = "Windows Event Log XML/JSON export artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        logs_root = root.joinpath(*EVENT_LOG_ROOT)
        if not logs_root.is_dir():
            return
        for path in sorted(logs_root.iterdir(), key=lambda item: item.name.lower()):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix == ".xml":
                yield from collect_xml_events(path)
            elif suffix == ".json":
                yield from collect_json_events(path)
            elif suffix == ".evtx":
                yield build_eventlog_file_record(path)


def collect_xml_events(path: Path) -> Iterable[ArtifactRecord]:
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return
    root = tree.getroot()
    events = [root] if strip_namespace(root.tag) == "Event" else root.findall(".//{*}Event")
    for index, event in enumerate(events):
        system = child_by_name(event, "System")
        event_data = child_by_name(event, "EventData")
        details = {
            "parser": "windows-eventlog-xml",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_format": "xml",
            "source_index": index,
            "provider_name": attr_from_child(system, "Provider", "Name"),
            "event_id": text_from_child(system, "EventID"),
            "record_id": text_from_child(system, "EventRecordID"),
            "channel": text_from_child(system, "Channel"),
            "level": text_from_child(system, "Level"),
            "computer": text_from_child(system, "Computer"),
            "event_created_at": attr_from_child(system, "TimeCreated", "SystemTime"),
            "data": event_data_values(event_data),
            "raw_preview": ET.tostring(event, encoding="unicode")[:1000],
        }
        yield ArtifactRecord(
            provider=WindowsEventLogProvider.name,
            artifact_type="eventlog-event",
            path=str(path.resolve()),
            supported=True,
            details=details,
        )


def collect_json_events(path: Path) -> Iterable[ArtifactRecord]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return
    rows = payload if isinstance(payload, list) else payload.get("events", []) if isinstance(payload, Mapping) else []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        details = {
            "parser": "windows-eventlog-json",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_format": "json",
            "source_index": index,
            "provider_name": row.get("provider") or row.get("provider_name") or "",
            "event_id": str(row.get("event_id") or row.get("id") or ""),
            "record_id": str(row.get("record_id") or ""),
            "channel": str(row.get("channel") or ""),
            "level": str(row.get("level") or ""),
            "computer": str(row.get("computer") or ""),
            "event_created_at": str(row.get("timestamp") or row.get("event_created_at") or ""),
            "data": dict(row),
            "raw_preview": json.dumps(row, ensure_ascii=False, sort_keys=True)[:1000],
        }
        yield ArtifactRecord(
            provider=WindowsEventLogProvider.name,
            artifact_type="eventlog-event",
            path=str(path.resolve()),
            supported=True,
            details=details,
        )


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
            "source_path": str(path.resolve()),
            "source_format": "evtx",
            "size": stat_result.st_size,
            "note": "Binary EVTX detected. Export to XML/JSON for parsed event rows in this build.",
        },
    )


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
