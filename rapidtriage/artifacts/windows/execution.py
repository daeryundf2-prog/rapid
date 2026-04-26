from __future__ import annotations

import codecs
import datetime as dt
import hashlib
import re
from pathlib import Path
from typing import Iterable, Mapping

from ...core.models import ArtifactRecord
from .common import iter_windows_user_homes
from .os_account import decode_reg_export

PARSER_VERSION = "windows-execution-v1"
REGISTRY_EXPORT_EXT = ".reg"
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
        yield from collect_execution_reg_exports(root)
        yield from collect_powershell_history(root)


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
