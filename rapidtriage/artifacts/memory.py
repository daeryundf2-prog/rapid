from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, unquote_plus, urlparse

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "memory-volatility-v3"
MEMORY_OUTPUT_SUFFIXES = {".json", ".jsonl", ".ndjson"}
MEMORY_DUMP_SUFFIXES = {".dmp", ".hpak", ".mem", ".raw", ".vmem", ".vmsn", ".vmss"}
MEMORY_DUMP_GENERIC_SUFFIXES = {".bin"}
MEMORY_DUMP_NAME_HINTS = ("memory", "memdump", "ram", "ramdump", "dump")
DISK_MEMORY_FILE_NAMES = {"hiberfil.sys", "pagefile.sys", "swapfile.sys"}
CRASH_DUMP_FILE_NAMES = {"memory.dmp"}
MEMORY_DUMP_SCAN_LIMIT = 256 * 1024 * 1024
MEMORY_DUMP_HASH_DEFER_BYTES = 512 * 1024 * 1024
MEMORY_DUMP_RANGE_COUNT = 4
MEMORY_DUMP_CHUNK_SIZE = 1024 * 1024
MEMORY_DUMP_OVERLAP = 512
MEMORY_DUMP_PIVOT_LIMIT = 80
MEMORY_DUMP_PROCESS_CANDIDATE_LIMIT = 40
MEMORY_URL_CONTEXT_CHARS = 180
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
MEMORY_SUSPICIOUS_TERMS = (
    "mimikatz",
    "sekurlsa",
    "lsass.exe",
    "procdump",
    "nanodump",
    "rundll32.exe",
    "powershell.exe",
    "cmd.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin",
    "vssadmin delete shadows",
    "bcdedit /set",
)
PRIVATE_BROWSING_TERMS = (
    "incognito",
    "inprivate",
    "private browsing",
    "off the record",
    "guest profile",
)
AI_SERVICE_DOMAINS = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "claude.ai": "Claude",
    "gemini.google.com": "Gemini",
    "bard.google.com": "Gemini",
    "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Microsoft Copilot",
    "poe.com": "Poe",
}
SEARCH_QUERY_PARAM_NAMES = {"q", "query", "search", "search_query", "text", "prompt", "p"}
SEARCH_ENGINE_DOMAINS = (
    "google.",
    "bing.com",
    "duckduckgo.com",
    "naver.com",
    "daum.net",
    "yahoo.com",
    "baidu.com",
)
BITLOCKER_RECOVERY_KEY_RE = re.compile(rb"\b(?:\d{6}-){7}\d{6}\b")
BITLOCKER_RECOVERY_KEY_TEXT_RE = re.compile(r"\b(?:\d{6}-){7}\d{6}\b")
URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,240}")
URL_TEXT_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,240}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IP_TEXT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROCESS_NAME_TEXT_RE = re.compile(r"\b[A-Za-z0-9_.-]{1,64}\.exe\b", re.IGNORECASE)
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128")
)


class MemoryVolatilityProvider:
    collector_kind = "memory-volatility"
    name = "memory-volatility-artifacts"
    description = "Volatility/Volatility3 output normalization plus bounded direct memory dump indicator scanning"
    target_platform = "memory"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in MEMORY_OUTPUT_SUFFIXES:
                plugin = infer_plugin(path)
                if plugin:
                    yield from collect_volatility_output(path, plugin=plugin)
                continue
            if is_memory_dump_candidate(path):
                yield collect_memory_dump_indicators(path)


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


def collect_memory_dump_indicators(path: Path) -> ArtifactRecord:
    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0
    source_hashes = safe_memory_source_hashes(path, file_size=file_size)
    scan_ranges = build_scan_ranges(file_size)
    pivots = scan_memory_dump(path, scan_ranges)
    memory_file_kind = classify_memory_file(path)
    web_recovery_profile = build_memory_web_recovery_profile(pivots, memory_file_kind=memory_file_kind)
    flags = build_memory_dump_flags(pivots=pivots, file_size=file_size, scan_ranges=scan_ranges)
    return ArtifactRecord(
        provider=MemoryVolatilityProvider.name,
        artifact_type=memory_artifact_type(memory_file_kind),
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "memory-dump-bounded-scan",
            "parser_version": PARSER_VERSION,
            "coverage_status": "bounded-direct-memory-scan",
            "memory_file_kind": memory_file_kind,
            "source_path": str(path.resolve()),
            "source_format": path.suffix.lower().lstrip("."),
            "source_size": file_size,
            "source_hashes": source_hashes,
            "scan_limit_bytes": MEMORY_DUMP_SCAN_LIMIT,
            "scan_ranges": [{"start": start, "end": end} for start, end in scan_ranges],
            "scan_truncated": scanned_bytes(scan_ranges) < file_size,
            "indicator_pivots": pivots,
            "web_recovery_profile": web_recovery_profile,
            "risk_flags": flags,
            "risk_score": score_memory_dump_risk(flags, pivots),
            "triage_recommendation": memory_dump_recommendation(flags),
        },
    )


def is_memory_dump_candidate(path: Path) -> bool:
    if path.name.lower() in DISK_MEMORY_FILE_NAMES or path.name.lower() in CRASH_DUMP_FILE_NAMES:
        return True
    suffix = path.suffix.lower()
    if suffix in MEMORY_DUMP_SUFFIXES:
        return True
    if suffix not in MEMORY_DUMP_GENERIC_SUFFIXES:
        return False
    lowered_name = path.name.lower()
    return any(hint in lowered_name for hint in MEMORY_DUMP_NAME_HINTS)


def classify_memory_file(path: Path) -> str:
    lowered_name = path.name.lower()
    if lowered_name in DISK_MEMORY_FILE_NAMES:
        if lowered_name.startswith("hiberfil"):
            return "hibernation-file"
        if lowered_name.startswith("pagefile"):
            return "pagefile"
        return "swapfile"
    if lowered_name in CRASH_DUMP_FILE_NAMES or path.suffix.lower() == ".dmp":
        return "crash-dump"
    return "memory-dump"


def memory_artifact_type(memory_file_kind: str) -> str:
    if memory_file_kind in {"hibernation-file", "pagefile", "swapfile"}:
        return "disk-memory-file-indicators"
    if memory_file_kind == "crash-dump":
        return "crash-dump-indicators"
    return "memory-dump-indicators"


def safe_memory_source_hashes(path: Path, *, file_size: int) -> dict[str, str]:
    if 0 <= file_size <= MEMORY_DUMP_HASH_DEFER_BYTES:
        try:
            return compute_hashes(path)
        except OSError:
            pass
    return {
        "md5": "",
        "sha1": "",
        "sha256": "",
        "hash_status": "deferred-large-memory-file" if file_size > MEMORY_DUMP_HASH_DEFER_BYTES else "unavailable",
        "path_sha256": compute_text_sha256(str(path.resolve())),
    }


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
        "process_key": process_key(pid=pid, process_name=process_name),
        "parent_process_key": process_key(pid=ppid, process_name="") if ppid else "",
        "command_line": command_line,
        "command_line_indicators": command_line_indicators(command_line),
        "local_address": local_address,
        "foreign_address": foreign_address,
        "state": state,
        "offset": offset,
        "reconstruction_status": "volatility-row-normalized",
        "validation_status": "external-parser-row",
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


def process_key(*, pid: str, process_name: str) -> str:
    if not pid and not process_name:
        return ""
    return f"{pid}:{process_name.lower()}".strip(":")


def command_line_indicators(command_line: str) -> list[str]:
    lowered = command_line.lower()
    indicators: list[str] = []
    indicator_terms = {
        "encoded-command": ("-enc", "-encodedcommand", "frombase64string"),
        "policy-bypass": ("bypass", "executionpolicy"),
        "download": ("downloadstring", "invoke-webrequest", "curl ", "wget "),
        "credential-access": ("mimikatz", "sekurlsa", "lsass", "procdump", "nanodump"),
        "shadow-copy-tamper": ("vssadmin delete shadows", "wmic shadowcopy delete"),
        "persistence": ("schtasks", "runonce", "startup"),
    }
    for name, terms in indicator_terms.items():
        if any(term in lowered for term in terms):
            indicators.append(name)
    return indicators


def build_scan_ranges(file_size: int) -> list[tuple[int, int]]:
    if file_size <= 0:
        return []
    if file_size <= MEMORY_DUMP_SCAN_LIMIT:
        return [(0, file_size)]
    window_size = max(MEMORY_DUMP_CHUNK_SIZE, MEMORY_DUMP_SCAN_LIMIT // MEMORY_DUMP_RANGE_COUNT)
    anchors = (
        0,
        max(0, file_size // 3 - window_size // 2),
        max(0, (file_size * 2) // 3 - window_size // 2),
        max(0, file_size - window_size),
    )
    ranges: list[tuple[int, int]] = []
    for start in anchors:
        end = min(file_size, start + window_size)
        if not ranges or start > ranges[-1][1]:
            ranges.append((start, end))
            continue
        previous_start, previous_end = ranges[-1]
        ranges[-1] = (previous_start, max(previous_end, end))
    return ranges


def scanned_bytes(scan_ranges: list[tuple[int, int]]) -> int:
    return sum(max(0, end - start) for start, end in scan_ranges)


def scan_memory_dump(path: Path, scan_ranges: list[tuple[int, int]]) -> list[dict[str, object]]:
    pivots: list[dict[str, object]] = []
    seen: set[tuple[str, str, int]] = set()
    try:
        with path.open("rb") as handle:
            for start, end in scan_ranges:
                handle.seek(start)
                remaining = end - start
                previous_tail = b""
                current_offset = start
                while remaining > 0 and len(pivots) < MEMORY_DUMP_PIVOT_LIMIT:
                    chunk = handle.read(min(MEMORY_DUMP_CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    data = previous_tail + chunk
                    data_offset = current_offset - len(previous_tail)
                    collect_memory_pivots(data, data_offset, pivots, seen)
                    collect_memory_process_candidates(data, data_offset, pivots, seen)
                    previous_tail = data[-MEMORY_DUMP_OVERLAP:]
                    current_offset += len(chunk)
                    remaining -= len(chunk)
    except OSError:
        return pivots
    return pivots


def collect_memory_process_candidates(
    data: bytes,
    data_offset: int,
    pivots: list[dict[str, object]],
    seen: set[tuple[str, str, int]],
) -> None:
    text = data.decode("latin-1", errors="ignore")
    emitted = 0
    for match in PROCESS_NAME_TEXT_RE.finditer(text):
        if emitted >= MEMORY_DUMP_PROCESS_CANDIDATE_LIMIT or len(pivots) >= MEMORY_DUMP_PIVOT_LIMIT:
            return
        process_name = match.group(0)
        start = max(0, match.start() - 96)
        end = min(len(text), match.end() + 220)
        context = printable_preview(text[start:end])
        indicators = command_line_indicators(context)
        if process_name.lower() not in SUSPICIOUS_PROCESS_NAMES and not indicators:
            continue
        add_memory_pivot(
            pivots,
            seen,
            pivot_type="process-candidate",
            value=json.dumps(
                {
                    "process_name": process_name,
                    "command_line_preview": context,
                    "command_line_indicators": indicators,
                    "reconstruction_status": "bounded-string-context",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            offset=data_offset + match.start(),
            evidence_strength="triage",
            sensitive=False,
        )
        emitted += 1
    collect_utf16_process_candidates(data, data_offset, pivots, seen)


def collect_utf16_process_candidates(
    data: bytes,
    data_offset: int,
    pivots: list[dict[str, object]],
    seen: set[tuple[str, str, int]],
) -> None:
    text = data.decode("utf-16le", errors="ignore")
    emitted = 0
    for match in PROCESS_NAME_TEXT_RE.finditer(text):
        if emitted >= MEMORY_DUMP_PROCESS_CANDIDATE_LIMIT or len(pivots) >= MEMORY_DUMP_PIVOT_LIMIT:
            return
        process_name = match.group(0)
        start = max(0, match.start() - 96)
        end = min(len(text), match.end() + 220)
        context = printable_preview(text[start:end])
        indicators = command_line_indicators(context)
        if process_name.lower() not in SUSPICIOUS_PROCESS_NAMES and not indicators:
            continue
        add_memory_pivot(
            pivots,
            seen,
            pivot_type="process-candidate",
            value=json.dumps(
                {
                    "process_name": process_name,
                    "command_line_preview": context,
                    "command_line_indicators": indicators,
                    "reconstruction_status": "bounded-utf16-string-context",
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            offset=data_offset + (match.start() * 2),
            evidence_strength="triage",
            sensitive=False,
        )
        emitted += 1


def collect_memory_pivots(
    data: bytes,
    data_offset: int,
    pivots: list[dict[str, object]],
    seen: set[tuple[str, str, int]],
) -> None:
    for match in BITLOCKER_RECOVERY_KEY_RE.finditer(data):
        value = match.group(0).decode("ascii", errors="ignore")
        add_memory_pivot(
            pivots,
            seen,
            pivot_type="bitlocker-recovery-key",
            value=value,
            offset=data_offset + match.start(),
            evidence_strength="strong",
            sensitive=True,
        )
    lowered = data.lower()
    for term in MEMORY_SUSPICIOUS_TERMS:
        encoded = term.encode("utf-8").lower()
        index = lowered.find(encoded)
        if index >= 0:
            add_memory_pivot(
                pivots,
                seen,
                pivot_type="suspicious-string",
                value=term,
                offset=data_offset + index,
                evidence_strength="triage",
                sensitive=False,
            )
    for match in URL_RE.finditer(data):
        value = trim_indicator(match.group(0)).decode("latin-1", errors="ignore")
        context = byte_context_preview(data, match.start(), match.end())
        add_memory_pivot(
            pivots,
            seen,
            pivot_type="url",
            value=value,
            offset=data_offset + match.start(),
            evidence_strength="triage",
            sensitive=False,
            context_preview=context,
            classification=classify_memory_url(value, context),
        )
    for match in IP_RE.finditer(data):
        value = match.group(0).decode("ascii", errors="ignore")
        if valid_ipv4(value):
            add_memory_pivot(
                pivots,
                seen,
                pivot_type="ip",
                value=value,
                offset=data_offset + match.start(),
                evidence_strength="triage",
                sensitive=False,
            )
    collect_utf16_memory_pivots(data, data_offset, pivots, seen)


def collect_utf16_memory_pivots(
    data: bytes,
    data_offset: int,
    pivots: list[dict[str, object]],
    seen: set[tuple[str, str, int]],
) -> None:
    text = data.decode("utf-16le", errors="ignore")
    lowered = text.lower()
    for match in BITLOCKER_RECOVERY_KEY_TEXT_RE.finditer(text):
        add_memory_pivot(
            pivots,
            seen,
            pivot_type="bitlocker-recovery-key",
            value=match.group(0),
            offset=data_offset + (match.start() * 2),
            evidence_strength="strong",
            sensitive=True,
        )
    for term in MEMORY_SUSPICIOUS_TERMS:
        index = lowered.find(term.lower())
        if index >= 0:
            add_memory_pivot(
                pivots,
                seen,
                pivot_type="suspicious-string",
                value=term,
                offset=data_offset + (index * 2),
                evidence_strength="triage",
                sensitive=False,
            )
    for match in URL_TEXT_RE.finditer(text):
        context = text_context_preview(text, match.start(), match.end())
        add_memory_pivot(
            pivots,
            seen,
            pivot_type="url",
            value=match.group(0).rstrip(".,);]"),
            offset=data_offset + (match.start() * 2),
            evidence_strength="triage",
            sensitive=False,
            context_preview=context,
            classification=classify_memory_url(match.group(0).rstrip(".,);]"), context),
        )
    for match in IP_TEXT_RE.finditer(text):
        value = match.group(0)
        if valid_ipv4(value):
            add_memory_pivot(
                pivots,
                seen,
                pivot_type="ip",
                value=value,
                offset=data_offset + (match.start() * 2),
                evidence_strength="triage",
                sensitive=False,
            )


def add_memory_pivot(
    pivots: list[dict[str, object]],
    seen: set[tuple[str, str, int]],
    *,
    pivot_type: str,
    value: str,
    offset: int,
    evidence_strength: str,
    sensitive: bool,
    context_preview: str = "",
    classification: Mapping[str, object] | None = None,
) -> None:
    if len(pivots) >= MEMORY_DUMP_PIVOT_LIMIT:
        return
    normalized_value = value.strip("\x00\r\n\t ")
    if not normalized_value:
        return
    key = (pivot_type, normalized_value.lower(), offset)
    if key in seen:
        return
    seen.add(key)
    pivot: dict[str, object] = {
        "type": pivot_type,
        "offset": offset,
        "evidence_strength": evidence_strength,
    }
    if pivot_type == "bitlocker-recovery-key":
        validation = validate_bitlocker_recovery_key(normalized_value)
        pivot["validation"] = validation
        if validation["status"] != "valid":
            pivot["evidence_strength"] = "candidate"
    if sensitive:
        pivot["value_redacted"] = redact_secret(normalized_value)
        pivot["value_sha256"] = compute_text_sha256(normalized_value)
    else:
        pivot["value"] = decode_process_candidate_value(pivot_type, normalized_value)
    if context_preview:
        pivot["context_preview"] = context_preview
    if classification:
        pivot["classification"] = dict(classification)
    pivots.append(pivot)


def validate_bitlocker_recovery_key(value: str) -> dict[str, object]:
    groups = value.split("-")
    group_rows = []
    valid = len(groups) == 8
    for index, group in enumerate(groups, start=1):
        group_valid = bool(re.fullmatch(r"\d{6}", group))
        number = int(group) if group_valid else -1
        in_range = 0 <= number <= 720885
        divisible_by_11 = group_valid and number % 11 == 0
        row = {
            "index": index,
            "group_sha256": compute_text_sha256(group) if group_valid else "",
            "format_valid": group_valid,
            "in_range": in_range,
            "divisible_by_11": divisible_by_11,
            "status": "valid" if group_valid and in_range and divisible_by_11 else "invalid",
        }
        group_rows.append(row)
        if row["status"] != "valid":
            valid = False
    return {
        "status": "valid" if valid else "invalid",
        "format": "8x6-digit-groups",
        "valid_group_count": len([row for row in group_rows if row["status"] == "valid"]),
        "group_count": len(groups),
        "checks": group_rows,
        "rule": "Each 6-digit BitLocker recovery-password group must be in 000000-720885 and divisible by 11.",
    }


def decode_process_candidate_value(pivot_type: str, value: str) -> object:
    if pivot_type != "process-candidate":
        return value
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {"process_name": "", "command_line_preview": value}
    return decoded if isinstance(decoded, Mapping) else value


def printable_preview(value: str) -> str:
    cleaned = "".join(character if character.isprintable() else " " for character in value)
    redacted = BITLOCKER_RECOVERY_KEY_TEXT_RE.sub(lambda match: redact_secret(match.group(0)), cleaned)
    return " ".join(redacted.split())[:320]


def trim_indicator(value: bytes) -> bytes:
    for separator in (b"\x00", b'"', b"'", b"<", b">", b" "):
        if separator in value:
            value = value.split(separator, 1)[0]
    return value.rstrip(b".,);]")


def redact_secret(value: str) -> str:
    if len(value) <= 13:
        return "***"
    return f"{value[:6]}-***-{value[-6:]}"


def compute_text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4


def byte_context_preview(data: bytes, start: int, end: int) -> str:
    context_start = max(0, start - MEMORY_URL_CONTEXT_CHARS)
    context_end = min(len(data), end + MEMORY_URL_CONTEXT_CHARS)
    return printable_preview(data[context_start:context_end].decode("latin-1", errors="ignore"))


def text_context_preview(text: str, start: int, end: int) -> str:
    context_start = max(0, start - MEMORY_URL_CONTEXT_CHARS)
    context_end = min(len(text), end + MEMORY_URL_CONTEXT_CHARS)
    return printable_preview(text[context_start:context_end])


def classify_memory_url(url: str, context_preview: str = "") -> dict[str, object]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    context_lower = context_preview.lower()
    categories = ["web-url"]
    service = ""
    service_family = ""
    for domain, label in AI_SERVICE_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            service = label
            service_family = "ai-service"
            categories.append("ai-service")
            break
    if not service and not host and any(token in context_lower for token in ("chatgpt", "claude", "gemini", "perplexity", "copilot")):
        service_family = "ai-service-context"
        categories.append("ai-service-context")
    if any(term in context_lower for term in PRIVATE_BROWSING_TERMS):
        categories.append("private-browsing-context")
    if any(token in host for token in SEARCH_ENGINE_DOMAINS):
        categories.append("search-engine")
    query_terms = extract_url_query_terms(parsed.query)
    if query_terms:
        categories.append("search-query")
    categories = sorted(set(categories))
    confidence = 0.48
    if "private-browsing-context" in categories:
        confidence += 0.22
    if "ai-service" in categories or "search-query" in categories:
        confidence += 0.16
    if "search-engine" in categories:
        confidence += 0.08
    return {
        "profile_version": "memory-url-classification-v1",
        "host": host,
        "scheme": parsed.scheme,
        "service": service,
        "service_family": service_family,
        "categories": categories,
        "query_terms": query_terms,
        "confidence": min(round(confidence, 2), 0.94),
        "reportability": "triage",
        "validation_guidance": "Memory/pagefile URL candidates can be stale or fragmented. Correlate with browser history, WebCacheV01, DNS, process context, and acquisition time before reporting.",
    }


def extract_url_query_terms(query: str) -> list[dict[str, str]]:
    terms: list[dict[str, str]] = []
    for key, value in parse_qsl(query, keep_blank_values=False):
        normalized_key = key.lower()
        if normalized_key not in SEARCH_QUERY_PARAM_NAMES:
            continue
        decoded = unquote_plus(value).strip()
        if not decoded:
            continue
        terms.append(
            {
                "parameter": normalized_key,
                "value_preview": decoded[:160],
                "value_sha256": compute_text_sha256(decoded),
            }
        )
        if len(terms) >= 5:
            break
    return terms


def build_memory_web_recovery_profile(pivots: Sequence[Mapping[str, object]], *, memory_file_kind: str) -> dict[str, object]:
    url_pivots = [pivot for pivot in pivots if pivot.get("type") == "url"]
    classified = [pivot.get("classification") for pivot in url_pivots if isinstance(pivot.get("classification"), Mapping)]
    category_counts: dict[str, int] = {}
    query_terms: list[dict[str, str]] = []
    ai_services: set[str] = set()
    private_count = 0
    for classification in classified:
        categories = [str(category) for category in classification.get("categories", [])]
        for category in categories:
            category_counts[category] = category_counts.get(category, 0) + 1
        if "private-browsing-context" in categories:
            private_count += 1
        service = str(classification.get("service") or "")
        if service:
            ai_services.add(service)
        for term in classification.get("query_terms", []):
            if isinstance(term, Mapping):
                query_terms.append(
                    {
                        "parameter": str(term.get("parameter") or ""),
                        "value_preview": str(term.get("value_preview") or ""),
                        "value_sha256": str(term.get("value_sha256") or ""),
                    }
                )
    return {
        "profile_version": "memory-web-recovery-profile-v1",
        "memory_file_kind": memory_file_kind,
        "url_candidate_count": len(url_pivots),
        "private_browsing_candidate_count": private_count,
        "ai_service_candidate_count": category_counts.get("ai-service", 0),
        "search_query_candidate_count": category_counts.get("search-query", 0),
        "category_counts": [{"category": key, "count": value} for key, value in sorted(category_counts.items())],
        "ai_services": sorted(ai_services),
        "query_term_samples": query_terms[:10],
        "coverage_status": "url-classification-present" if url_pivots else "no-url-candidates",
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "browser-history-webcache-dns-correlation-required",
            "fragmented-memory-url-false-positive-corpus-required",
        ],
        "validation_guidance": "Use this profile as a triage lead for private browsing, AI service, and search query residues. It is not proof of user navigation without corroborating browser/process/network evidence.",
    }


def build_memory_dump_flags(
    *,
    pivots: list[dict[str, object]],
    file_size: int,
    scan_ranges: list[tuple[int, int]],
) -> list[str]:
    pivot_types = {str(pivot.get("type", "")) for pivot in pivots}
    url_categories = {
        str(category)
        for pivot in pivots
        if pivot.get("type") == "url" and isinstance(pivot.get("classification"), Mapping)
        for category in pivot["classification"].get("categories", [])
    }
    flags: list[str] = []
    if "bitlocker-recovery-key" in pivot_types:
        if any(
            isinstance(pivot.get("validation"), Mapping) and pivot["validation"].get("status") == "valid"
            for pivot in pivots
            if pivot.get("type") == "bitlocker-recovery-key"
        ):
            flags.append("bitlocker-recovery-key-validated")
        else:
            flags.append("bitlocker-recovery-key-candidate")
    if "process-candidate" in pivot_types:
        flags.append("process-string-candidate")
    if "suspicious-string" in pivot_types:
        flags.append("suspicious-memory-string")
    if "url" in pivot_types or "ip" in pivot_types:
        flags.append("network-indicator")
    if "private-browsing-context" in url_categories:
        flags.append("private-browsing-url-candidate")
    if "ai-service" in url_categories:
        flags.append("ai-service-url-candidate")
    if "search-query" in url_categories:
        flags.append("search-query-url-candidate")
    if scanned_bytes(scan_ranges) < file_size:
        flags.append("bounded-scan-truncated")
    return flags


def score_memory_dump_risk(flags: list[str], pivots: list[dict[str, object]]) -> int:
    weights = {
        "bitlocker-recovery-key-validated": 55,
        "bitlocker-recovery-key-candidate": 45,
        "process-string-candidate": 15,
        "suspicious-memory-string": 20,
        "network-indicator": 15,
        "private-browsing-url-candidate": 18,
        "ai-service-url-candidate": 16,
        "search-query-url-candidate": 12,
        "bounded-scan-truncated": 0,
    }
    return min(sum(weights.get(flag, 5) for flag in flags) + min(20, len(pivots)), 100)


def memory_dump_recommendation(flags: list[str]) -> str:
    if "bitlocker-recovery-key-validated" in flags:
        return "Preserve the memory dump, handle the validated redacted BitLocker recovery-key candidate as sensitive evidence, and correlate with disk encryption state."
    if "bitlocker-recovery-key-candidate" in flags:
        return "Preserve the memory dump, validate the redacted BitLocker recovery-key candidate in a controlled evidence workflow, and correlate with disk encryption state."
    if "process-string-candidate" in flags:
        return "Review direct process string candidates alongside Volatility process, command-line, network, and malfind output before reporting."
    if "private-browsing-url-candidate" in flags or "ai-service-url-candidate" in flags or "search-query-url-candidate" in flags:
        return "Review memory/pagefile URL classifications as browser/AI/search residues, then correlate with browser history, WebCacheV01, DNS, and process context before reporting."
    if "suspicious-memory-string" in flags or "network-indicator" in flags:
        return "Review memory string pivots with Volatility process/network output before reporting."
    return "No high-value bounded memory indicators were found; run Volatility/Volatility3 for full process, handle, network, and malfind analysis."
