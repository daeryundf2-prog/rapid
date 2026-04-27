from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Iterable

from ...core.audit import compute_sha256
from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp

PREFETCH_ROOT = ("Windows", "Prefetch")
PARSER_VERSION = "prefetch-inventory-v5"
PREFETCH_RUN_COUNT_OFFSETS = {
    17: 0x90,
    23: 0x98,
    26: 0xD0,
    30: 0xD0,
    31: 0xD0,
}
PREFETCH_LAST_RUN_TIME_OFFSETS = {
    17: 0x78,
    23: 0x80,
    26: 0x80,
    30: 0x80,
    31: 0x80,
}


class WindowsPrefetchProvider:
    name = "windows-prefetch"
    collector_kind = "windows-prefetch"
    description = "Windows Prefetch execution artifact inventory"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        prefetch_root = root.joinpath(*PREFETCH_ROOT)
        if not prefetch_root.is_dir():
            return
        for path in sorted(prefetch_root.glob("*.pf"), key=lambda item: item.name.lower()):
            if not path.is_file():
                continue
            stat_result = path.stat()
            header = prefetch_header_hints(path)
            filename_executable_hint = executable_hint(path.name)
            header_executable_name = str(header.get("header_executable_name") or "")
            source_hashes = {"sha256": compute_sha256(path)}
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="prefetch-file",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-prefetch-inventory",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "detected",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "pf",
                    "source_hashes": source_hashes,
                    "executable_hint": header_executable_name or filename_executable_hint,
                    "executable_hint_source": "prefetch_header" if header_executable_name else "filename",
                    "filename_executable_hint": filename_executable_hint,
                    **header,
                    "prefetch_hash": prefetch_hash_hint(path.name),
                    "entry_name": path.name,
                    "size": stat_result.st_size,
                    "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp_source": "prefetch_file_modified_at",
                    "evidence_strength": "execution-indicator",
                    "note": "Prefetch triage parser uses best-effort common-version offsets; validate critical findings with a dedicated parser such as PECmd.",
                },
            )
            for index, referenced_path in enumerate(header.get("referenced_paths") or []):
                yield build_prefetch_reference_record(path, str(referenced_path), index, header, source_hashes)


def executable_hint(name: str) -> str:
    stem = Path(name).stem
    if "-" not in stem:
        return stem
    return stem.rsplit("-", 1)[0]


def prefetch_hash_hint(name: str) -> str:
    stem = Path(name).stem
    if "-" not in stem:
        return ""
    return stem.rsplit("-", 1)[1]


def prefetch_header_hints(path: Path) -> dict[str, object]:
    try:
        blob = path.read_bytes()
    except OSError:
        return {"binary_format_detected": False}
    header = blob[:4096]
    is_scca = len(header) >= 8 and header[4:8] == b"SCCA"
    prefetch_version = int.from_bytes(header[:4], "little") if is_scca else 0
    hints: dict[str, object] = {
        "binary_format_detected": is_scca,
        "prefetch_parse_status": "parsed-common-header" if prefetch_version in PREFETCH_RUN_COUNT_OFFSETS else "inventory-only",
        "prefetch_version": prefetch_version,
        "header_executable_name": "",
        "run_count": 0,
        "last_run_at": "",
        "last_run_times": [],
        "referenced_paths": [],
        "referenced_path_count": 0,
    }
    if not is_scca:
        return hints
    run_count_offset = PREFETCH_RUN_COUNT_OFFSETS.get(prefetch_version)
    last_run_offset = PREFETCH_LAST_RUN_TIME_OFFSETS.get(prefetch_version)
    if run_count_offset is not None:
        hints["run_count"] = read_u32(blob, run_count_offset)
    if last_run_offset is not None:
        run_times = prefetch_run_times(blob, last_run_offset)
        hints["last_run_times"] = run_times
        hints["last_run_at"] = run_times[0] if run_times else ""
    strings = extract_utf16le_strings(blob[: min(len(blob), 1024 * 1024)])
    executable_names = [item for item in strings if ".exe" in item.lower()]
    if executable_names:
        hints["header_executable_name"] = executable_names[0]
    referenced_paths = referenced_prefetch_paths(strings)
    hints["referenced_paths"] = referenced_paths[:200]
    hints["referenced_path_count"] = len(referenced_paths)
    return hints


def build_prefetch_reference_record(
    path: Path,
    referenced_path: str,
    index: int,
    header: dict[str, object],
    source_hashes: dict[str, str],
) -> ArtifactRecord:
    executable_name = str(header.get("header_executable_name") or executable_hint(path.name))
    return ArtifactRecord(
        provider=WindowsPrefetchProvider.name,
        artifact_type="prefetch-reference",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "windows-prefetch-reference",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-reference-string",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "pf",
            "source_hashes": dict(source_hashes),
            "source_index": index,
            "prefetch_entry_name": path.name,
            "executable_hint": executable_name,
            "prefetch_hash": prefetch_hash_hint(path.name),
            "referenced_path": referenced_path,
            "referenced_file_name": PureWindowsPath(referenced_path).name,
            "referenced_extension": PureWindowsPath(referenced_path).suffix.lower(),
            "run_count": header.get("run_count", 0),
            "last_run_at": header.get("last_run_at", ""),
            "timestamp": header.get("last_run_at", ""),
            "timestamp_source": "prefetch_last_run_at",
            "evidence_strength": "prefetch-file-reference",
            "validation_required": True,
            "validation_guidance": "Prefetch reference rows are recovered from bounded native strings; validate complete file metrics and volumes with PECmd before final testimony.",
            "raw_preview": referenced_path,
        },
    )


def prefetch_run_times(blob: bytes, offset: int) -> list[str]:
    values = []
    for index in range(8):
        timestamp = windows_filetime_to_iso(read_u64(blob, offset + (index * 8)))
        if timestamp:
            values.append(timestamp)
    return values


def referenced_prefetch_paths(strings: list[str]) -> list[str]:
    paths = []
    for item in strings:
        text = item.strip()
        lowered = text.lower()
        if "\\" not in text:
            continue
        if lowered.endswith(".exe") and ":" not in text and not text.startswith("\\"):
            continue
        paths.append(text)
    return sorted(dict.fromkeys(paths))


def extract_utf16le_strings(blob: bytes, *, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for offset in range(0, len(blob) - 1, 2):
        pair = blob[offset : offset + 2]
        value = int.from_bytes(pair, "little")
        if 32 <= value <= 126:
            current.extend(pair)
            continue
        if len(current) >= min_chars * 2:
            strings.append(current.decode("utf-16le", errors="ignore").strip("\x00"))
        current = bytearray()
    if len(current) >= min_chars * 2:
        strings.append(current.decode("utf-16le", errors="ignore").strip("\x00"))
    return [item for item in strings if item]


def windows_filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        seconds = (value - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def read_u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little")


def read_u64(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 8], "little")
