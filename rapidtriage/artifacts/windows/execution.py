from __future__ import annotations

import codecs
import csv
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from ...core.models import ArtifactRecord
from .common import iter_windows_user_homes
from .os_account import decode_reg_export

PARSER_VERSION = "windows-execution-v2"
REGISTRY_EXPORT_EXT = ".reg"
SRUM_IMPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
POWERSHELL_HISTORY = ("AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")

EXECUTION_KEYWORDS = {
    "amcache": ("Amcache", "InventoryApplicationFile", "InventoryApplication", "Root\\File"),
    "shimcache": ("AppCompatCache", "AppCompatFlags\\Compatibility Assistant\\Store"),
    "userassist": ("UserAssist",),
    "bam": ("Services\\bam\\State\\UserSettings", "Services\\dam\\State\\UserSettings"),
}
SUSPICIOUS_COMMAND_TERMS = (
    "powershell -enc",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "rundll32",
    "regsvr32",
    "wmic",
    "certutil",
    "bitsadmin",
    "schtasks",
    "vssadmin delete shadows",
)


class WindowsExecutionProvider:
    name = "windows-execution"
    collector_kind = "windows-execution"
    description = "Windows execution artifacts from registry exports and PowerShell history"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records = [
            *collect_execution_reg_exports(root),
            *collect_powershell_history(root),
            *collect_srum_imports(root),
        ]
        yield from records
        summary = build_execution_summary(root, records)
        if summary is not None:
            yield summary


def collect_execution_reg_exports(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob(f"*{REGISTRY_EXPORT_EXT}"), key=lambda item: str(item).lower()):
        try:
            text = decode_reg_export(path.read_bytes())
        except OSError:
            continue
        if not any(token.lower() in text.lower() for tokens in EXECUTION_KEYWORDS.values() for token in tokens):
            continue
        yield from parse_execution_reg_export(path, text)


def parse_execution_reg_export(path: Path, text: str) -> Iterable[ArtifactRecord]:
    current_key = ""
    values: dict[str, str] = {}
    for line in [*text.splitlines(), ""]:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if current_key:
                record = build_execution_registry_record(path, current_key, values)
                if record is not None:
                    yield record
            current_key = stripped.strip("[]")
            values = {}
            continue
        name, value = parse_reg_value(stripped)
        if current_key and name:
            values[name] = value
    if current_key:
        record = build_execution_registry_record(path, current_key, values)
        if record is not None:
            yield record


def build_execution_registry_record(path: Path, key: str, values: Mapping[str, str]) -> ArtifactRecord | None:
    lowered_key = key.lower()
    artifact_type = ""
    parser = "windows-execution-reg-export"
    evidence_strength = "execution-indicator"
    decoded_values = {decode_userassist_name(name) if "userassist" in lowered_key else name: value for name, value in values.items()}

    if any(token.lower() in lowered_key for token in EXECUTION_KEYWORDS["amcache"]):
        artifact_type = "amcache-entry"
        evidence_strength = "program-presence-or-execution"
    elif any(token.lower() in lowered_key for token in EXECUTION_KEYWORDS["shimcache"]):
        artifact_type = "shimcache-entry"
        evidence_strength = "program-presence-not-proof-of-execution"
    elif "userassist" in lowered_key:
        artifact_type = "userassist-entry"
        evidence_strength = "user-execution-indicator"
    elif any(token.lower() in lowered_key for token in EXECUTION_KEYWORDS["bam"]):
        artifact_type = "bam-entry"
        evidence_strength = "execution-indicator"
    else:
        return None

    executable_path = extract_executable_path(key, decoded_values)
    timestamp = extract_timestamp(decoded_values)
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": parser,
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "source_hashes": file_hashes(path),
            "key": key,
            "hive_hint": key.split("\\", 1)[0],
            "executable_path": executable_path,
            "timestamp": timestamp,
            "evidence_strength": evidence_strength,
            "values": dict(sorted(decoded_values.items())),
            "raw_preview": f"[{key}]",
        },
    )


def collect_powershell_history(root: Path) -> Iterable[ArtifactRecord]:
    for user_root in iter_windows_user_homes(root):
        path = user_root.joinpath(*POWERSHELL_HISTORY)
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        modified_at = path_modified_at(path)
        for index, command in enumerate(lines):
            command = command.strip()
            if not command:
                continue
            risk_flags = [f"suspicious-command:{term}" for term in SUSPICIOUS_COMMAND_TERMS if term in command.lower()]
            yield ArtifactRecord(
                provider=WindowsExecutionProvider.name,
                artifact_type="powershell-history-command",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-powershell-history",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "text",
                    "source_hashes": file_hashes(path),
                    "source_index": index,
                    "user": user_root.name,
                    "command_line": command,
                    "timestamp": modified_at,
                    "timestamp_source": "history_file_modified_at",
                    "risk_flags": risk_flags,
                    "risk_score": min(100, len(risk_flags) * 25),
                },
            )


def collect_srum_imports(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in SRUM_IMPORT_SUFFIXES:
            continue
        if "srum" not in str(path).lower() and "srudb" not in str(path).lower():
            continue
        rows = iter_csv_rows(path) if path.suffix.lower() == ".csv" else iter_json_rows(path)
        for index, row in enumerate(rows):
            if isinstance(row, Mapping):
                yield build_srum_record(path, row, index)


def build_srum_record(path: Path, row: Mapping[str, object], index: int) -> ArtifactRecord:
    lowered = {normalize_key(key): value for key, value in row.items()}
    app_id = str(first_value(lowered, "app", "appid", "application", "applicationname", "executable", "executablepath") or "")
    user = str(first_value(lowered, "user", "username", "useraccount", "sid") or "")
    timestamp = str(first_value(lowered, "timestamp", "eventtime", "starttime", "endtime", "time") or "").replace("Z", "+00:00")
    bytes_sent = number_value(first_value(lowered, "bytessent", "sendbytes", "sentbytes", "networkbytessent"))
    bytes_received = number_value(first_value(lowered, "bytesreceived", "receivebytes", "receivedbytes", "networkbytesreceived"))
    cpu_time = number_value(first_value(lowered, "cputime", "cpu", "cpucycletime"))
    energy = number_value(first_value(lowered, "energy", "energyusage", "energyusagemwh"))
    artifact_type = "srum-network-usage" if bytes_sent or bytes_received else "srum-app-resource-usage"
    risk_flags = [f"suspicious-app:{term}" for term in SUSPICIOUS_COMMAND_TERMS if term.split()[0] in app_id.lower()]
    details = {
        "parser": "windows-srum-import",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": path.suffix.lower().lstrip("."),
        "source_hashes": file_hashes(path),
        "source_index": index,
        "app_id": app_id,
        "executable_path": app_id if looks_like_executable_path(app_id) else "",
        "user": user,
        "timestamp": timestamp,
        "timestamp_source": "srum_import_timestamp",
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "cpu_time": cpu_time,
        "energy_usage": energy,
        "evidence_strength": "application-resource-usage-indicator",
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 20),
        "raw": dict(row),
        "raw_preview": json.dumps(row, ensure_ascii=False, sort_keys=True)[:2000],
    }
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def build_execution_summary(root: Path, records: Iterable[ArtifactRecord]) -> ArtifactRecord | None:
    groups: dict[str, dict[str, object]] = {}
    for record in records:
        details = record.details
        key = execution_group_key(record.artifact_type, details)
        if not key:
            continue
        group = groups.setdefault(
            key,
            {
                "executable_key": key,
                "display_name": display_name_for_execution_key(key),
                "signal_count": 0,
                "signal_types": set(),
                "evidence_strengths": set(),
                "users": set(),
                "timestamps": set(),
                "risk_flags": set(),
                "source_paths": set(),
                "command_line_samples": [],
            },
        )
        group["signal_count"] = int(group["signal_count"]) + 1
        cast_set(group["signal_types"]).add(record.artifact_type)
        if details.get("evidence_strength"):
            cast_set(group["evidence_strengths"]).add(str(details["evidence_strength"]))
        if details.get("user"):
            cast_set(group["users"]).add(str(details["user"]))
        if details.get("timestamp"):
            cast_set(group["timestamps"]).add(str(details["timestamp"]))
        if details.get("source_path"):
            cast_set(group["source_paths"]).add(str(details["source_path"]))
        for flag in details.get("risk_flags", []):
            cast_set(group["risk_flags"]).add(str(flag))
        command_line = str(details.get("command_line") or "")
        samples = group["command_line_samples"]
        if command_line and isinstance(samples, list) and command_line not in samples and len(samples) < 3:
            samples.append(command_line)
    if not groups:
        return None

    normalized_groups = [normalize_execution_group(group) for group in groups.values()]
    normalized_groups.sort(key=lambda item: (-int(item["signal_count"]), str(item["display_name"]).lower()))
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type="windows-execution-summary",
        path=str(root.resolve()),
        supported=True,
        details={
            "parser": "windows-execution-summary",
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(root.resolve()),
            "group_count": len(normalized_groups),
            "groups": normalized_groups,
            "reporting_note": "Summary groups execution-related signals; review each source artifact before concluding proof of execution.",
        },
    )


def execution_group_key(artifact_type: str, details: Mapping[str, object]) -> str:
    executable_path = str(details.get("executable_path") or "").strip()
    if executable_path:
        return normalize_execution_path(executable_path)
    command_line = str(details.get("command_line") or "").strip()
    if command_line:
        return normalize_command_execution_key(command_line)
    key = str(details.get("key") or "").strip()
    if key:
        return normalize_execution_path(key.rsplit("\\", 1)[-1])
    return artifact_type


def normalize_command_execution_key(command_line: str) -> str:
    lowered = command_line.lower()
    if "powershell" in lowered:
        return "powershell.exe"
    match = re.search(r"([a-z0-9_ .:\\/-]+\.(?:exe|dll|ps1|bat|cmd|scr))", command_line, flags=re.IGNORECASE)
    if match:
        return normalize_execution_path(match.group(1).strip())
    return command_line.split(maxsplit=1)[0].lower()


def normalize_execution_path(value: str) -> str:
    cleaned = value.strip().strip('"').replace("/", "\\")
    display_name = display_name_for_execution_key(cleaned)
    return (display_name or cleaned).lower()


def display_name_for_execution_key(value: str) -> str:
    tail = value.replace("/", "\\").rsplit("\\", 1)[-1]
    return tail or value


def cast_set(value: object) -> set[str]:
    if isinstance(value, set):
        return value
    return set()


def normalize_execution_group(group: Mapping[str, object]) -> dict[str, object]:
    return {
        "executable_key": group["executable_key"],
        "display_name": group["display_name"],
        "signal_count": group["signal_count"],
        "signal_types": sorted(cast_set(group["signal_types"])),
        "evidence_strengths": sorted(cast_set(group["evidence_strengths"])),
        "users": sorted(cast_set(group["users"])),
        "timestamps": sorted(cast_set(group["timestamps"])),
        "risk_flags": sorted(cast_set(group["risk_flags"])),
        "source_paths": sorted(cast_set(group["source_paths"])),
        "command_line_samples": list(group.get("command_line_samples", [])),
    }


def iter_csv_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            yield from csv.DictReader(handle)
    except (OSError, UnicodeError, csv.Error):
        return


def iter_json_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
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
    rows = payload if isinstance(payload, list) else payload.get("rows", []) if isinstance(payload, Mapping) else []
    for row in rows:
        if isinstance(row, Mapping):
            yield row


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def first_value(row: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = row.get(normalize_key(key))
        if value not in (None, ""):
            return value
    return ""


def number_value(value: object) -> int | float | str:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        number = float(text)
    except ValueError:
        return text
    return int(number) if number.is_integer() else number


def parse_reg_value(line: str) -> tuple[str, str]:
    if "=" not in line:
        return "", ""
    raw_name, raw_value = line.split("=", 1)
    name = raw_name.strip().strip('"')
    value = raw_value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    return name, value


def decode_userassist_name(value: str) -> str:
    try:
        return codecs.decode(value, "rot_13")
    except Exception:
        return value


def extract_executable_path(key: str, values: Mapping[str, str]) -> str:
    for name, value in values.items():
        lowered = name.lower()
        if lowered in {"path", "fullpath", "filename", "programid", "name"} and value:
            return value
        if looks_like_executable_path(name):
            return name
        if looks_like_executable_path(value):
            return value
    tail = key.rsplit("\\", 1)[-1]
    return tail if looks_like_executable_path(tail) else ""


def looks_like_executable_path(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in (".exe", ".dll", ".ps1", ".bat", ".cmd", ".scr"))


def extract_timestamp(values: Mapping[str, str]) -> str:
    for name, value in values.items():
        if "time" not in name.lower() and "last" not in name.lower():
            continue
        parsed = parse_timestamp_value(value)
        if parsed:
            return parsed
    return ""


def parse_timestamp_value(value: str) -> str:
    text = value.strip().strip('"')
    if re.match(r"^\d{4}-\d\d-\d\d[T ]", text):
        return text.replace("Z", "+00:00")
    if text.lower().startswith("hex(b):"):
        raw = parse_hex_bytes(text[7:])
        if len(raw) >= 8:
            filetime = int.from_bytes(raw[:8], "little", signed=False)
            return filetime_to_iso(filetime)
    return ""


def parse_hex_bytes(value: str) -> bytes:
    items = []
    for item in value.replace("\\", "").replace("\n", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            items.append(int(item, 16))
        except ValueError:
            return b""
    return bytes(items)


def filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        return (base + dt.timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, ValueError):
        return ""


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}


def path_modified_at(path: Path) -> str:
    try:
        modified = path.stat().st_mtime
    except OSError:
        return ""
    return dt.datetime.fromtimestamp(modified, tz=dt.timezone.utc).isoformat()
