from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord

PARSER_VERSION = "reg-export-v2"
REGISTRY_EXPORT_PATTERN = re.compile(r"^\[(?P<key>.+)]$")
REGISTRY_VALUE_PATTERN = re.compile(r'^(?P<name>@|"[^"]+")=(?P<value>.*)$')
PERSISTENCE_TERMS = ("run\\", "\\runonce", "\\policies\\explorer\\run", "\\services\\")
SUSPICIOUS_VALUE_TERMS = (
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
    "bitsadmin",
    "appdata",
    "temp\\",
)


class WindowsRegistryProvider:
    name = "windows-registry"
    description = "Windows Registry .reg export artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        for path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            records.extend(collect_reg_export(path))
        yield from records
        summary = build_registry_summary(root, records)
        if summary is not None:
            yield summary


def collect_reg_export(path: Path) -> Iterable[ArtifactRecord]:
    try:
        lines = path.read_text(encoding="utf-16").splitlines()
    except UnicodeError:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return
    except OSError:
        return

    current_key = ""
    values: dict[str, str] = {}
    source_hashes = file_hashes(path)
    for line in [*lines, ""]:
        stripped = line.strip()
        key_match = REGISTRY_EXPORT_PATTERN.match(stripped)
        if key_match:
            if current_key:
                yield build_registry_record(path, current_key, values, source_hashes)
            current_key = key_match.group("key")
            values = {}
            continue
        value_match = REGISTRY_VALUE_PATTERN.match(stripped)
        if current_key and value_match:
            raw_name = value_match.group("name")
            name = "(default)" if raw_name == "@" else raw_name.strip('"')
            values[name] = value_match.group("value")
    if current_key:
        yield build_registry_record(path, current_key, values, source_hashes)


def build_registry_record(
    path: Path,
    key: str,
    values: dict[str, str],
    source_hashes: Mapping[str, str] | None = None,
) -> ArtifactRecord:
    lowered_key = key.lower()
    artifact_type = "registry-key"
    if "usb" in lowered_key or "usbstor" in lowered_key:
        artifact_type = "registry-usb"
    if "run\\" in lowered_key or lowered_key.endswith("\\run"):
        artifact_type = "registry-run-key"
    persistence_values = registry_persistence_values(values) if artifact_type == "registry-run-key" else []
    usb_device = registry_usb_device(key, values) if artifact_type == "registry-usb" else {}
    risk_flags = registry_risk_flags(key, values)
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "windows-registry-reg-export",
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "source_hashes": dict(source_hashes or file_hashes(path)),
            "key": key,
            "hive_hint": key.split("\\", 1)[0],
            "value_count": len(values),
            "value_names": sorted(values),
            "values": dict(sorted(values.items())),
            "persistence_values": persistence_values,
            "usb_device": usb_device,
            "risk_flags": risk_flags,
            "risk_score": min(100, len(risk_flags) * 20 + (30 if persistence_values else 0)),
            "raw_preview": f"[{key}]",
        },
    )


def build_registry_summary(root: Path, records: Sequence[ArtifactRecord]) -> ArtifactRecord | None:
    if not records:
        return None
    hive_counts: Counter[str] = Counter()
    artifact_type_counts: Counter[str] = Counter()
    source_paths: set[str] = set()
    persistence_entries: list[dict[str, object]] = []
    usb_devices: list[dict[str, object]] = []
    suspicious_entries: list[dict[str, object]] = []

    for record in records:
        details = record.details
        hive = str(details.get("hive_hint") or "")
        artifact_type_counts[record.artifact_type] += 1
        if hive:
            hive_counts[hive] += 1
        source_paths.add(str(details.get("source_path") or record.path))
        for item in details.get("persistence_values") or []:
            if isinstance(item, Mapping):
                persistence_entries.append({"key": details.get("key", ""), **dict(item)})
        usb_device = details.get("usb_device")
        if isinstance(usb_device, Mapping) and usb_device:
            usb_devices.append({"key": details.get("key", ""), **dict(usb_device)})
        if details.get("risk_flags"):
            suspicious_entries.append(
                {
                    "key": details.get("key", ""),
                    "artifact_type": record.artifact_type,
                    "risk_flags": list(details.get("risk_flags") or []),
                    "risk_score": details.get("risk_score", 0),
                    "source_path": details.get("source_path", record.path),
                }
            )

    details = {
        "parser": "windows-registry-summary",
        "parser_version": PARSER_VERSION,
        "coverage_status": "summarized",
        "reportability": "triage",
        "source_path": str(root.resolve()),
        "source_format": "summary",
        "key_count": len(records),
        "source_files": sorted(source_paths),
        "artifact_type_counts": counter_items(artifact_type_counts),
        "hive_counts": counter_items(hive_counts),
        "persistence_entries": persistence_entries[:100],
        "usb_devices": usb_devices[:100],
        "suspicious_entries": sorted(
            suspicious_entries,
            key=lambda item: int(item.get("risk_score") or 0),
            reverse=True,
        )[:100],
        "summary_notes": [
            "Registry rows are based on .reg exports; deleted-key recovery requires a hive-aware parser.",
            "Run-key command hints are triage pivots, not proof that a program executed.",
        ],
    }
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-summary",
        path=str(root.resolve()),
        supported=True,
        details=details,
    )


def registry_persistence_values(values: Mapping[str, str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for name, raw_value in sorted(values.items()):
        command = clean_reg_value(raw_value)
        entries.append(
            {
                "value_name": name,
                "command": command,
                "executable_hint": executable_hint(command),
                "risk_flags": suspicious_value_flags(command),
            }
        )
    return entries


def registry_usb_device(key: str, values: Mapping[str, str]) -> dict[str, object]:
    parts = [part for part in key.split("\\") if part]
    try:
        usbstor_index = next(index for index, part in enumerate(parts) if part.upper() == "USBSTOR")
    except StopIteration:
        usbstor_index = -1
    device_class = parts[usbstor_index + 1] if usbstor_index >= 0 and len(parts) > usbstor_index + 1 else ""
    serial = parts[usbstor_index + 2] if usbstor_index >= 0 and len(parts) > usbstor_index + 2 else ""
    return {
        "device_class": device_class,
        "serial_hint": serial,
        "friendly_name": clean_reg_value(values.get("FriendlyName", "")),
        "parent_id_prefix": clean_reg_value(values.get("ParentIdPrefix", "")),
    }


def registry_risk_flags(key: str, values: Mapping[str, str]) -> list[str]:
    flags: list[str] = []
    lowered_key = key.lower()
    if any(term in lowered_key for term in PERSISTENCE_TERMS) or lowered_key.endswith("\\run"):
        flags.append("persistence-key")
    for term in suspicious_value_flags(" ".join(values.values())):
        flags.append(term)
    return sorted(set(flags))


def suspicious_value_flags(value: str) -> list[str]:
    lowered = value.lower()
    return [f"suspicious-value:{term}" for term in SUSPICIOUS_VALUE_TERMS if term in lowered]


def clean_reg_value(value: object) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def executable_hint(command: str) -> str:
    match = re.search(r"(?i)([a-z]:\\\\[^\"']+?\.exe|[\w.-]+\.exe)", command)
    return match.group(1) if match else ""


def counter_items(counter: Counter[str], limit: int = 25) -> list[dict[str, object]]:
    return [{"value": value, "count": count} for value, count in counter.most_common(limit)]


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
