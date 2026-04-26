from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord

PARSER_VERSION = "registry-normalized-v3"
REGISTRY_EXPORT_PATTERN = re.compile(r"^\[(?P<key>.+)]$")
REGISTRY_VALUE_PATTERN = re.compile(r'^(?P<name>@|"[^"]+")=(?P<value>.*)$')
REGISTRY_HIVE_SIGNATURE = b"regf"
REGISTRY_HIVE_NAMES = {"NTUSER.DAT", "USRCLASS.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"}
MAX_HIVE_STRING_SCAN_BYTES = 8 * 1024 * 1024
MAX_HIVE_STRINGS = 250
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
HIVE_PIVOT_TERMS = SUSPICIOUS_VALUE_TERMS + (
    "runonce",
    "currentversion\\run",
    "usbstor",
    "terminal server client",
    "typedurls",
    "userassist",
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
        for path in candidate_registry_hive_paths(root):
            records.extend(collect_registry_hive(path))
        yield from records
        summary = build_registry_summary(root, records)
        if summary is not None:
            yield summary


def candidate_registry_hive_paths(root: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        name = path.name.upper()
        if name not in REGISTRY_HIVE_NAMES:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield path


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


def collect_registry_hive(path: Path) -> Iterable[ArtifactRecord]:
    try:
        stat_result = path.stat()
        with path.open("rb") as handle:
            header = handle.read(4096)
            handle.seek(0)
            scan_blob = handle.read(min(stat_result.st_size, MAX_HIVE_STRING_SCAN_BYTES))
    except OSError:
        return

    source_hashes = file_hashes(path)
    metadata = parse_registry_hive_header(header)
    yield build_registry_hive_record(path, stat_result.st_size, metadata, source_hashes)

    strings = extract_utf16le_strings(scan_blob)
    if strings:
        yield build_registry_hive_strings_record(path, strings, metadata, source_hashes)


def parse_registry_hive_header(header: bytes) -> dict[str, object]:
    valid = header.startswith(REGISTRY_HIVE_SIGNATURE)
    sequence_primary = read_u32(header, 4)
    sequence_secondary = read_u32(header, 8)
    timestamp = filetime_to_iso(read_u64(header, 12))
    major = read_u32(header, 20)
    minor = read_u32(header, 24)
    hive_type = read_u32(header, 28)
    format_version = read_u32(header, 32)
    root_cell_offset = read_u32(header, 36)
    hbin_data_size = read_u32(header, 40)
    clustering_factor = read_u32(header, 44)
    embedded_name = decode_utf16le_string(header[48:112])
    checksum = read_u32(header, 508)
    return {
        "regf_valid": valid,
        "sequence_primary": sequence_primary,
        "sequence_secondary": sequence_secondary,
        "dirty": bool(sequence_primary and sequence_secondary and sequence_primary != sequence_secondary),
        "last_written_at": timestamp,
        "major_version": major,
        "minor_version": minor,
        "hive_type": hive_type,
        "format_version": format_version,
        "root_cell_offset": root_cell_offset,
        "hbin_data_size": hbin_data_size,
        "clustering_factor": clustering_factor,
        "embedded_name": embedded_name,
        "base_block_checksum": checksum,
    }


def build_registry_hive_record(
    path: Path,
    size: int,
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    regf_valid = bool(metadata.get("regf_valid"))
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-hive",
        path=str(path.resolve()),
        supported=regf_valid,
        details={
            "parser": "windows-registry-hive-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-hive-inventory" if regf_valid else "invalid-or-unsupported-hive",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "registry-hive",
            "source_hashes": dict(source_hashes),
            "size": size,
            "hive_name": path.name,
            "hive_hint": hive_hint_from_path(path),
            "hive_path_hint": registry_hive_path_hint(path),
            "parser_confidence": 0.72 if regf_valid else 0.2,
            "evidence_strength": "registry-hive-header" if regf_valid else "registry-hive-candidate",
            "recommended_parsers": ["RECmd", "Registry Explorer", "RegRipper", "Eric Zimmerman's Registry tools"],
            "native_header": dict(metadata),
            "risk_flags": ["dirty-hive-sequence"] if metadata.get("dirty") else [],
            "risk_score": 30 if metadata.get("dirty") else 0,
            "raw_preview": f"{path.name} regf={regf_valid}",
        },
    )


def build_registry_hive_strings_record(
    path: Path,
    strings: Sequence[str],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    suspicious = suspicious_hive_strings(strings)
    path_candidates = registry_path_candidates(strings)
    url_candidates = registry_url_candidates(strings)
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-hive-strings",
        path=str(path.resolve()),
        supported=bool(metadata.get("regf_valid")),
        details={
            "parser": "windows-registry-hive-string-scan",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-hive-string-scan",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "registry-hive",
            "source_hashes": dict(source_hashes),
            "hive_name": path.name,
            "hive_hint": hive_hint_from_path(path),
            "parser_confidence": 0.45,
            "evidence_strength": "registry-hive-string-candidate",
            "scan_limit_bytes": MAX_HIVE_STRING_SCAN_BYTES,
            "extracted_string_count": len(strings),
            "extracted_strings": list(strings[:MAX_HIVE_STRINGS]),
            "suspicious_strings": suspicious[:100],
            "path_candidates": path_candidates[:100],
            "url_candidates": url_candidates[:50],
            "risk_flags": sorted({flag for item in suspicious for flag in item.get("risk_flags", [])}),
            "risk_score": min(100, len(suspicious) * 10),
            "raw_preview": " ".join(strings[:20])[:2000],
        },
    )


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
    source_format_counts: Counter[str] = Counter()
    source_paths: set[str] = set()
    persistence_entries: list[dict[str, object]] = []
    usb_devices: list[dict[str, object]] = []
    suspicious_entries: list[dict[str, object]] = []
    hive_files: list[dict[str, object]] = []
    hive_string_hits: list[dict[str, object]] = []

    for record in records:
        details = record.details
        hive = str(details.get("hive_hint") or "")
        artifact_type_counts[record.artifact_type] += 1
        source_format_counts[str(details.get("source_format") or "unknown")] += 1
        if hive:
            hive_counts[hive] += 1
        source_paths.add(str(details.get("source_path") or record.path))
        if record.artifact_type == "registry-hive":
            native_header = details.get("native_header") if isinstance(details.get("native_header"), Mapping) else {}
            hive_files.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "hive_name": details.get("hive_name", ""),
                    "hive_hint": hive,
                    "size": details.get("size", 0),
                    "regf_valid": native_header.get("regf_valid", False),
                    "dirty": native_header.get("dirty", False),
                    "last_written_at": native_header.get("last_written_at", ""),
                    "sha256": (details.get("source_hashes") or {}).get("sha256", "")
                    if isinstance(details.get("source_hashes"), Mapping)
                    else "",
                }
            )
        if record.artifact_type == "registry-hive-strings":
            for item in details.get("suspicious_strings") or []:
                if isinstance(item, Mapping):
                    hive_string_hits.append({"source_path": details.get("source_path", record.path), **dict(item)})
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
        "record_count": len(records),
        "key_count": sum(1 for record in records if record.artifact_type in {"registry-key", "registry-run-key", "registry-usb"}),
        "hive_file_count": sum(1 for record in records if record.artifact_type == "registry-hive"),
        "hive_string_row_count": sum(1 for record in records if record.artifact_type == "registry-hive-strings"),
        "source_files": sorted(source_paths),
        "artifact_type_counts": counter_items(artifact_type_counts),
        "source_format_counts": counter_items(source_format_counts),
        "hive_counts": counter_items(hive_counts),
        "hive_files": hive_files[:100],
        "hive_string_hits": sorted(hive_string_hits, key=lambda item: len(item.get("risk_flags", [])), reverse=True)[:100],
        "persistence_entries": persistence_entries[:100],
        "usb_devices": usb_devices[:100],
        "suspicious_entries": sorted(
            suspicious_entries,
            key=lambda item: int(item.get("risk_score") or 0),
            reverse=True,
        )[:100],
        "summary_notes": [
            "Registry hive rows use native regf header and bounded string scanning; full cell traversal and deleted-key recovery require a dedicated hive parser.",
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


def hive_hint_from_path(path: Path) -> str:
    name = path.name.upper()
    if name in {"NTUSER.DAT", "USRCLASS.DAT"}:
        return "HKEY_CURRENT_USER"
    if name in {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"}:
        return f"HKEY_LOCAL_MACHINE\\{name}"
    return name


def registry_hive_path_hint(path: Path) -> str:
    parts = [part.lower() for part in path.parts]
    if "system32" in parts and "config" in parts:
        return "system-config"
    if path.name.upper() in {"NTUSER.DAT", "USRCLASS.DAT"}:
        return "user-profile"
    return "registry-hive-candidate"


def suspicious_hive_strings(strings: Sequence[str]) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for index, value in enumerate(strings):
        flags = suspicious_value_flags(value)
        lowered = value.lower()
        flags.extend(f"hive-pivot:{term}" for term in HIVE_PIVOT_TERMS if term in lowered and f"suspicious-value:{term}" not in flags)
        if flags:
            hits.append({"index": index, "value": value, "risk_flags": sorted(set(flags))})
    return hits


def registry_path_candidates(strings: Sequence[str]) -> list[str]:
    candidates = []
    for value in strings:
        if re.search(r"(?i)[a-z]:\\", value) or value.startswith("\\\\"):
            candidates.append(value)
    return sorted(set(candidates))


def registry_url_candidates(strings: Sequence[str]) -> list[str]:
    candidates = []
    for value in strings:
        candidates.extend(match.rstrip(".,;)") for match in re.findall(r"https?://[^\s\"'<>]+", value))
    return sorted(set(candidates))


def extract_utf16le_strings(blob: bytes, *, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    start: int | None = None
    cursor = 0
    while cursor + 1 < len(blob):
        value = int.from_bytes(blob[cursor : cursor + 2], "little", signed=False)
        printable = value in (9, 10, 13) or 32 <= value <= 0xD7FF or 0xE000 <= value <= 0xFFFD
        if printable and value != 0:
            if start is None:
                start = cursor
        else:
            if start is not None:
                text = decode_utf16le_string(blob[start:cursor])
                if len(text) >= min_chars:
                    strings.append(text)
                    if len(strings) >= MAX_HIVE_STRINGS:
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
