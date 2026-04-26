from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ...core.audit import compute_sha256
from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp

PREFETCH_ROOT = ("Windows", "Prefetch")
PARSER_VERSION = "prefetch-inventory-v3"


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
                    "source_hashes": {"sha256": compute_sha256(path)},
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
                    "note": "Prefetch triage inventory; header hints are parsed when SCCA is detected, while full run-count parsing remains a dedicated parser task.",
                },
            )


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
        header = path.read_bytes()[:4096]
    except OSError:
        return {"binary_format_detected": False}
    is_scca = len(header) >= 8 and header[4:8] == b"SCCA"
    hints: dict[str, object] = {
        "binary_format_detected": is_scca,
        "prefetch_version": int.from_bytes(header[:4], "little") if is_scca else 0,
        "header_executable_name": "",
    }
    if not is_scca:
        return hints
    strings = extract_utf16le_strings(header)
    executable_names = [item for item in strings if ".exe" in item.lower()]
    if executable_names:
        hints["header_executable_name"] = executable_names[0]
    return hints


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
