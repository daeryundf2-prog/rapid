from __future__ import annotations

import json
import ipaddress
from pathlib import Path
from typing import Iterable, Mapping

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "memory-volatility-v1"
MEMORY_OUTPUT_SUFFIXES = {".json", ".jsonl", ".ndjson"}
PLUGIN_HINTS = (
    "pslist",
    "pstree",
    "psscan",
    "cmdline",
    "netscan",
    "malfind",
    "dlllist",
    "handles",
)
SUSPICIOUS_PROCESS_NAMES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
}
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128")
)


class MemoryVolatilityProvider:
    collector_kind = "memory-volatility"
    name = "memory-volatility-artifacts"
    description = "Volatility/Volatility3 JSON or JSONL output normalization for process, network, and injected-code triage"
    target_platform = "memory"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file() or path.suffix.lower() not in MEMORY_OUTPUT_SUFFIXES:
                continue
            plugin = infer_plugin(path)
            if not plugin:
                continue
            yield from collect_volatility_output(path, plugin=plugin)


def collect_volatility_output(path: Path, *, plugin: str) -> Iterable[ArtifactRecord]:
    rows = load_rows(path)
    if not rows:
        return
    file_hashes = compute_hashes(path)
    for index, row in enumerate(rows):
        normalized = normalize_row(row, plugin=plugin)
        yield ArtifactRecord(
            provider=MemoryVolatilityProvider.name,
            artifact_type=artifact_type_for_plugin(plugin),
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "memory-volatility",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_format": path.suffix.lower().lstrip("."),
                "source_plugin": plugin,
                "source_index": index,
                "source_hashes": file_hashes,
                **normalized,
                "raw": dict(row),
            },
        )


def infer_plugin(path: Path) -> str:
    lowered = path.name.lower()
    for hint in PLUGIN_HINTS:
        if hint in lowered:
            return hint
    return ""


def load_rows(path: Path) -> list[Mapping[str, object]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        rows = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, Mapping):
                rows.append(value)
        return rows
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        for key in ("rows", "data", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
    return []


def artifact_type_for_plugin(plugin: str) -> str:
    if plugin in {"pslist", "pstree", "psscan"}:
        return "memory-process"
    if plugin == "cmdline":
        return "memory-cmdline"
    if plugin == "netscan":
        return "memory-network"
    if plugin == "malfind":
        return "memory-malfind"
    return "memory-artifact"


def normalize_row(row: Mapping[str, object], *, plugin: str) -> dict[str, object]:
    process_name = first_text(row, "ImageFileName", "Image", "Process", "Name", "process_name")
    pid = first_text(row, "PID", "Pid", "ProcessId", "process_id")
    ppid = first_text(row, "PPID", "Ppid", "ParentProcessId", "parent_pid")
    command_line = first_text(row, "CommandLine", "Cmd", "Args", "command_line")
    local_address = first_text(row, "LocalAddr", "LocalAddress", "Local", "local_address")
    foreign_address = first_text(row, "ForeignAddr", "ForeignAddress", "Remote", "remote_address")
    state = first_text(row, "State", "Proto", "Protocol", "state")
    offset = first_text(row, "Offset", "Offset(V)", "offset")
    flags = build_risk_flags(
        plugin=plugin,
        process_name=process_name,
        command_line=command_line,
        foreign_address=foreign_address,
        row=row,
    )
    return {
        "process_name": process_name,
        "pid": pid,
        "ppid": ppid,
        "command_line": command_line,
        "local_address": local_address,
        "foreign_address": foreign_address,
        "state": state,
        "offset": offset,
        "risk_flags": flags,
        "risk_score": score_risk(flags),
    }


def first_text(row: Mapping[str, object], *keys: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def build_risk_flags(
    *,
    plugin: str,
    process_name: str,
    command_line: str,
    foreign_address: str,
    row: Mapping[str, object],
) -> list[str]:
    flags: list[str] = []
    lowered_process = process_name.lower()
    lowered_command = command_line.lower()
    if lowered_process in SUSPICIOUS_PROCESS_NAMES:
        flags.append("suspicious-process-name")
    if any(token in lowered_command for token in ("-enc", "downloadstring", "frombase64string", "bypass")):
        flags.append("suspicious-command-line")
    if plugin == "malfind":
        flags.append("malfind-row")
    if plugin == "netscan" and foreign_address and not is_local_address(foreign_address):
        flags.append("external-network-connection")
    protection = first_text(row, "Protection", "Protect", "protection").lower()
    if "execute" in protection and "write" in protection:
        flags.append("writable-executable-memory")
    return flags


def is_local_address(value: str) -> bool:
    host = value.split(":", 1)[0].strip("[]")
    if host in {"localhost", "*"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_unspecified or any(address in network for network in LOCAL_NETWORKS)


def score_risk(flags: list[str]) -> int:
    weights = {
        "malfind-row": 35,
        "writable-executable-memory": 25,
        "suspicious-command-line": 25,
        "external-network-connection": 15,
        "suspicious-process-name": 10,
    }
    return min(sum(weights.get(flag, 5) for flag in flags), 100)
