from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord

PARSER_VERSION = "registry-normalized-v8"
REGISTRY_EXPORT_PATTERN = re.compile(r"^\[(?P<key>.+)]$")
REGISTRY_VALUE_PATTERN = re.compile(r'^(?P<name>@|"[^"]+")=(?P<value>.*)$')
REGISTRY_HIVE_SIGNATURE = b"regf"
REGISTRY_HBIN_SIGNATURE = b"hbin"
REGISTRY_HIVE_NAMES = {"NTUSER.DAT", "USRCLASS.DAT", "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "COMPONENTS"}
MAX_HIVE_STRING_SCAN_BYTES = 8 * 1024 * 1024
MAX_HIVE_STRINGS = 250
MAX_HIVE_CELL_SCAN_BYTES = 16 * 1024 * 1024
MAX_HIVE_CELL_RECORDS = 500
MAX_HIVE_CELL_SIZE = 1024 * 1024
HIVE_BIN_BASE_OFFSET = 4096
HIVE_BIN_HEADER_SIZE = 32
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
USER_HIVE_NAMES = {"NTUSER.DAT", "USRCLASS.DAT"}
USER_ACTIVITY_KEY_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("userassist", "execution", "UserAssist execution/activity"),
    ("typedurls", "browser-typed-url", "Typed browser URL"),
    ("typedpaths", "typed-path", "Typed Explorer path"),
    ("recentdocs", "recent-document", "RecentDocs MRU"),
    ("\\currentversion\\run", "persistence", "CurrentVersion Run persistence"),
    ("\\currentversion\\runonce", "persistence", "CurrentVersion RunOnce persistence"),
    ("\\policies\\explorer\\run", "persistence", "Explorer policy Run persistence"),
    ("\\explorer\\comdlg32\\opensavepidlmru", "file-dialog-mru", "OpenSavePidlMRU file dialog history"),
    ("\\explorer\\comdlg32\\lastvisitedpidlmru", "file-dialog-mru", "LastVisitedPidlMRU file dialog history"),
    ("\\explorer\\runmru", "run-dialog-mru", "Run dialog MRU"),
    ("\\explorer\\recentdocs", "recent-document", "Explorer RecentDocs"),
    ("\\shell\\bagmru", "shellbag", "ShellBags BagMRU"),
    ("\\shell\\bags", "shellbag", "ShellBags Bags"),
    ("mountpoints2", "mounted-device", "MountPoints2 device history"),
    ("\\network\\", "network-share", "Mapped network share"),
)
ROT13_TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
REGISTRY_NATIVE_CAPABILITIES = {
    "regf_header": True,
    "hbin_cell_walk": True,
    "nk_key_cell_decode": True,
    "vk_value_cell_decode": True,
    "parent_chain_path_reconstruction": True,
    "subkey_list_linking": True,
    "value_list_linking": True,
    "deleted_free_cell_candidate_labeling": True,
    "inline_value_preview": True,
    "transaction_log_replay": False,
    "security_descriptor_decode": False,
    "full_binary_value_decode": False,
    "deleted_cell_report_grade_validation": False,
}
REGISTRY_REPORT_GRADE_BLOCKERS = [
    "transaction-log-replay-not-implemented",
    "full-binary-value-decoding-not-implemented",
    "deleted-cell-known-answer-corpus-validation-required",
    "registry-security-descriptor-decoding-not-implemented",
]


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
                activity = build_registry_user_activity_from_reg(path, current_key, values, source_hashes)
                if activity is not None:
                    yield activity
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
        activity = build_registry_user_activity_from_reg(path, current_key, values, source_hashes)
        if activity is not None:
            yield activity


def collect_registry_hive(path: Path) -> Iterable[ArtifactRecord]:
    try:
        stat_result = path.stat()
        with path.open("rb") as handle:
            header = handle.read(4096)
            handle.seek(0)
            scan_blob = handle.read(min(stat_result.st_size, max(MAX_HIVE_STRING_SCAN_BYTES, MAX_HIVE_CELL_SCAN_BYTES)))
    except OSError:
        return

    source_hashes = file_hashes(path)
    metadata = parse_registry_hive_header(header)
    yield build_registry_hive_record(path, stat_result.st_size, metadata, source_hashes)

    strings = extract_utf16le_strings(scan_blob)
    if strings:
        yield build_registry_hive_strings_record(path, strings, metadata, source_hashes)
        yield from build_registry_user_activity_from_hive_strings(path, strings, metadata, source_hashes)
    cell_candidates = iter_registry_cell_candidates(scan_blob)
    for candidate in cell_candidates:
        yield build_registry_hive_cell_record(path, candidate, metadata, source_hashes)
        if candidate.get("allocation_status") == "free-or-deleted-candidate":
            yield build_registry_deleted_cell_record(path, candidate, metadata, source_hashes)
    yield from build_registry_key_tree_records(path, scan_blob, cell_candidates, metadata, source_hashes)
    yield from build_registry_key_recovery_records(path, cell_candidates, metadata, source_hashes)
    yield from build_registry_value_recovery_records(path, scan_blob, cell_candidates, metadata, source_hashes)


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


def build_registry_hive_cell_record(
    path: Path,
    candidate: Mapping[str, object],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    name = str(candidate.get("name") or "")
    risk_flags = registry_cell_risk_flags(candidate)
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-hive-cell",
        path=str(path.resolve()),
        supported=bool(metadata.get("regf_valid")),
        details={
            "parser": "windows-registry-hive-cell-scan",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-hive-cell-scan",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "registry-hive",
            "source_hashes": dict(source_hashes),
            "hive_name": path.name,
            "hive_hint": hive_hint_from_path(path),
            "parser_confidence": 0.58 if metadata.get("regf_valid") else 0.25,
            "evidence_strength": "registry-hive-cell-candidate",
            "scan_limit_bytes": MAX_HIVE_CELL_SCAN_BYTES,
            "cell_index": candidate.get("cell_index", 0),
            "cell_kind": candidate.get("cell_kind", ""),
            "cell_signature": candidate.get("cell_signature", ""),
            "cell_offset": candidate.get("cell_offset", 0),
            "cell_relative_offset": candidate.get("cell_relative_offset", 0),
            "cell_scan_method": candidate.get("cell_scan_method", ""),
            "hbin_offset": candidate.get("hbin_offset", 0),
            "cell_size": candidate.get("cell_size", 0),
            "allocation_status": candidate.get("allocation_status", ""),
            "flags": candidate.get("flags", 0),
            "name": name,
            "name_encoding": candidate.get("name_encoding", ""),
            "last_written_at": candidate.get("last_written_at", ""),
            "parent_cell_offset": candidate.get("parent_cell_offset", 0),
            "subkey_count": candidate.get("subkey_count", 0),
            "stable_subkey_list_offset": candidate.get("stable_subkey_list_offset", 0),
            "volatile_subkey_list_offset": candidate.get("volatile_subkey_list_offset", 0),
            "value_count": candidate.get("value_count", 0),
            "value_list_offset": candidate.get("value_list_offset", 0),
            "value_type": candidate.get("value_type", ""),
            "value_data_size": candidate.get("value_data_size", 0),
            "value_data_offset": candidate.get("value_data_offset", 0),
            "value_data_inline": candidate.get("value_data_inline", False),
            "risk_flags": risk_flags,
            "risk_score": min(100, len(risk_flags) * 20 + (20 if candidate.get("allocation_status") == "free-or-deleted-candidate" else 0)),
            "raw_preview": f"{candidate.get('cell_kind', 'cell')} {name}".strip(),
        },
    )


def build_registry_deleted_cell_record(
    path: Path,
    candidate: Mapping[str, object],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    name = str(candidate.get("name") or "")
    risk_flags = registry_cell_risk_flags(candidate)
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-deleted-cell-candidate",
        path=str(path.resolve()),
        supported=bool(metadata.get("regf_valid")),
        details={
            "parser": "windows-registry-hive-deleted-cell-recovery",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-deleted-cell-candidate",
            "reportability": "review",
            "source_path": str(path.resolve()),
            "source_format": "registry-hive",
            "source_hashes": dict(source_hashes),
            "hive_name": path.name,
            "hive_hint": hive_hint_from_path(path),
            "parser_confidence": 0.5 if metadata.get("regf_valid") else 0.2,
            "evidence_strength": "registry-deleted-cell-candidate",
            "validation_required": True,
            "validation_guidance": "Positive-size hive cells can represent free space that still contains old nk/vk structures; validate with a dedicated registry parser before final testimony.",
            "cell_kind": candidate.get("cell_kind", ""),
            "cell_signature": candidate.get("cell_signature", ""),
            "cell_offset": candidate.get("cell_offset", 0),
            "cell_relative_offset": candidate.get("cell_relative_offset", 0),
            "cell_scan_method": candidate.get("cell_scan_method", ""),
            "hbin_offset": candidate.get("hbin_offset", 0),
            "cell_size": candidate.get("cell_size", 0),
            "allocation_status": candidate.get("allocation_status", ""),
            "name": name,
            "name_encoding": candidate.get("name_encoding", ""),
            "last_written_at": candidate.get("last_written_at", ""),
            "parent_cell_offset": candidate.get("parent_cell_offset", 0),
            "subkey_count": candidate.get("subkey_count", 0),
            "value_count": candidate.get("value_count", 0),
            "value_list_offset": candidate.get("value_list_offset", 0),
            "value_type": candidate.get("value_type", ""),
            "value_data_size": candidate.get("value_data_size", 0),
            "value_data_offset": candidate.get("value_data_offset", 0),
            "value_data_inline": candidate.get("value_data_inline", False),
            "risk_flags": risk_flags,
            "risk_score": min(100, 40 + len(risk_flags) * 20),
            "raw_preview": f"deleted/free {candidate.get('cell_kind', 'cell')} {name}".strip(),
        },
    )


def build_registry_key_tree_records(
    path: Path,
    blob: bytes,
    candidates: Sequence[Mapping[str, object]],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    key_nodes = [candidate for candidate in candidates if candidate.get("cell_kind") == "key-node"]
    if not key_nodes:
        return
    key_by_offset = {int(candidate.get("cell_offset") or 0): candidate for candidate in key_nodes}
    value_by_offset = {
        int(candidate.get("cell_offset") or 0): candidate
        for candidate in candidates
        if candidate.get("cell_kind") == "value"
    }
    for index, key_node in enumerate(key_nodes):
        value_offsets = registry_value_offsets_for_key(blob, key_node)
        value_cells = [value_by_offset[offset] for offset in value_offsets if offset in value_by_offset]
        missing_value_offsets = [offset for offset in value_offsets if offset not in value_by_offset]
        subkey_offsets = registry_subkey_offsets_for_key(blob, key_node)
        subkey_names = [
            str(key_by_offset[offset].get("name") or "")
            for offset in subkey_offsets
            if offset in key_by_offset and key_by_offset[offset].get("name")
        ]
        missing_subkey_offsets = [offset for offset in subkey_offsets if offset not in key_by_offset]
        key_path, path_confidence = registry_key_path_for_node(key_node, key_by_offset)
        allocation_status = str(key_node.get("allocation_status") or "")
        validation_flags = registry_key_tree_validation_flags(
            key_node,
            path_confidence,
            missing_subkey_offsets,
            missing_value_offsets,
        )
        validation_required = bool(validation_flags)
        risk_flags = registry_cell_risk_flags(key_node)
        validation_matrix = registry_key_tree_validation_matrix(
            key_node,
            path_confidence,
            missing_subkey_offsets,
            missing_value_offsets,
            bool(metadata.get("regf_valid")),
        )
        report_grade_assessment = registry_report_grade_assessment(
            validation_matrix,
            validation_required=validation_required,
            recovery_candidate=False,
            extra_blockers=["native-key-tree-broad-corpus-validation-required"],
            gap_ids=["#4"],
        )
        yield ArtifactRecord(
            provider=WindowsRegistryProvider.name,
            artifact_type="registry-key-tree-node",
            path=str(path.resolve()),
            supported=bool(metadata.get("regf_valid")),
            details={
                "parser": "windows-registry-hive-key-tree",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-hive-key-tree-partial",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "registry-hive",
                "source_hashes": dict(source_hashes),
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "parser_confidence": registry_key_tree_confidence(key_node, path_confidence, bool(metadata.get("regf_valid"))),
                "evidence_strength": "registry-hive-key-tree-node",
                "tree_node_index": index,
                "key_path": f"{hive_hint_from_path(path)}\\{key_path}" if key_path else hive_hint_from_path(path),
                "key_path_confidence": path_confidence,
                "name": key_node.get("name", ""),
                "name_encoding": key_node.get("name_encoding", ""),
                "cell_offset": key_node.get("cell_offset", 0),
                "cell_relative_offset": key_node.get("cell_relative_offset", 0),
                "cell_scan_method": key_node.get("cell_scan_method", ""),
                "hbin_offset": key_node.get("hbin_offset", 0),
                "cell_size": key_node.get("cell_size", 0),
                "allocation_status": allocation_status,
                "parent_cell_offset": key_node.get("parent_cell_offset", 0),
                "subkey_count": key_node.get("subkey_count", 0),
                "stable_subkey_list_offset": key_node.get("stable_subkey_list_offset", 0),
                "volatile_subkey_list_offset": key_node.get("volatile_subkey_list_offset", 0),
                "subkey_cell_offsets": subkey_offsets,
                "subkey_names": sorted(subkey_names),
                "linked_subkey_count": len(subkey_names),
                "missing_subkey_cell_offsets": missing_subkey_offsets,
                "value_count": key_node.get("value_count", 0),
                "value_list_offset": key_node.get("value_list_offset", 0),
                "value_names": sorted(str(value.get("name") or "") for value in value_cells if value.get("name")),
                "value_cell_offsets": value_offsets,
                "linked_value_count": len(value_cells),
                "missing_value_cell_offsets": missing_value_offsets,
                "last_written_at": key_node.get("last_written_at", ""),
                "validation_required": validation_required,
                "validation_flags": validation_flags,
                "registry_validation_matrix": validation_matrix,
                "registry_report_grade_assessment": report_grade_assessment,
                "registry_native_capabilities": REGISTRY_NATIVE_CAPABILITIES,
                "commercial_grade_ready": report_grade_assessment["report_grade_ready"],
                "commercial_grade_blockers": report_grade_assessment["blockers"],
                "validation_guidance": "Native key-tree reconstruction walks hbin cells and nk parent/subkey/value-list metadata where recoverable; validate important paths with a second registry parser and hive transaction-log context.",
                "risk_flags": risk_flags,
                "risk_score": min(100, 20 + len(risk_flags) * 20),
                "raw_preview": f"{hive_hint_from_path(path)}\\{key_path}" if key_path else str(key_node.get("name") or ""),
            },
        )


def build_registry_key_recovery_records(
    path: Path,
    candidates: Sequence[Mapping[str, object]],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    key_by_offset = {
        int(candidate.get("cell_offset") or 0): candidate
        for candidate in candidates
        if candidate.get("cell_kind") == "key-node"
    }
    for candidate in candidates:
        if candidate.get("cell_kind") != "key-node" or candidate.get("allocation_status") != "free-or-deleted-candidate":
            continue
        key_path, path_confidence = registry_key_path_for_node(candidate, key_by_offset)
        risk_flags = registry_cell_risk_flags(candidate)
        validation_matrix = registry_key_tree_validation_matrix(
            candidate,
            path_confidence,
            [],
            [],
            bool(metadata.get("regf_valid")),
        )
        report_grade_assessment = registry_report_grade_assessment(
            validation_matrix,
            validation_required=True,
            recovery_candidate=True,
            extra_blockers=["deleted-key-parent-chain-independent-validation-required"],
            gap_ids=["#5"],
        )
        yield ArtifactRecord(
            provider=WindowsRegistryProvider.name,
            artifact_type="registry-key-recovery-candidate",
            path=str(path.resolve()),
            supported=bool(metadata.get("regf_valid")),
            details={
                "parser": "windows-registry-hive-key-recovery",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-deleted-key-candidate",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "registry-hive",
                "source_hashes": dict(source_hashes),
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "parser_confidence": registry_key_tree_confidence(candidate, path_confidence, bool(metadata.get("regf_valid"))),
                "evidence_strength": "registry-deleted-key-candidate",
                "validation_required": True,
                "registry_validation_matrix": validation_matrix,
                "registry_report_grade_assessment": report_grade_assessment,
                "registry_native_capabilities": REGISTRY_NATIVE_CAPABILITIES,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade_assessment["blockers"],
                "validation_guidance": "Recovered free nk cells can be stale or partially overwritten; validate with hive allocator state, transaction logs, and a second parser before testimony.",
                "candidate_kind": "deleted-or-free-key-cell",
                "key_path_candidate": f"{hive_hint_from_path(path)}\\{key_path}" if key_path else hive_hint_from_path(path),
                "key_path_confidence": path_confidence,
                "name": candidate.get("name", ""),
                "last_written_at": candidate.get("last_written_at", ""),
                "parent_cell_offset": candidate.get("parent_cell_offset", 0),
                "subkey_count": candidate.get("subkey_count", 0),
                "value_count": candidate.get("value_count", 0),
                "cell_offset": candidate.get("cell_offset", 0),
                "cell_relative_offset": candidate.get("cell_relative_offset", 0),
                "cell_scan_method": candidate.get("cell_scan_method", ""),
                "hbin_offset": candidate.get("hbin_offset", 0),
                "cell_size": candidate.get("cell_size", 0),
                "allocation_status": candidate.get("allocation_status", ""),
                "caution_labels": ["deleted-or-free-cell-candidate", "do-not-report-without-validation"],
                "risk_flags": risk_flags,
                "risk_score": min(100, 45 + len(risk_flags) * 20),
                "raw_preview": f"deleted/free key {candidate.get('name', '')}".strip(),
            },
        )


def build_registry_value_recovery_records(
    path: Path,
    blob: bytes,
    candidates: Sequence[Mapping[str, object]],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    key_by_offset = {
        int(candidate.get("cell_offset") or 0): candidate
        for candidate in candidates
        if candidate.get("cell_kind") == "key-node"
    }
    value_parent_by_offset = registry_value_parent_map(blob, key_by_offset)
    for candidate in candidates:
        if candidate.get("cell_kind") != "value" or candidate.get("allocation_status") != "free-or-deleted-candidate":
            continue
        parent = value_parent_by_offset.get(int(candidate.get("cell_offset") or 0))
        parent_confidence = "key-value-list" if parent is not None else "unknown"
        if parent is None:
            parent = nearest_preceding_key(candidate, key_by_offset)
            parent_confidence = "nearest-preceding-key" if parent is not None else "unknown"
        parent_path = ""
        if parent is not None:
            parent_key_path, _ = registry_key_path_for_node(parent, key_by_offset)
            parent_path = f"{hive_hint_from_path(path)}\\{parent_key_path}" if parent_key_path else hive_hint_from_path(path)
        decoded_data = registry_value_data_preview(blob, candidate)
        validation_matrix = registry_value_recovery_validation_matrix(
            candidate,
            parent_confidence,
            bool(parent_path),
            bool(decoded_data),
            bool(metadata.get("regf_valid")),
        )
        report_grade_assessment = registry_report_grade_assessment(
            validation_matrix,
            validation_required=True,
            recovery_candidate=True,
            extra_blockers=["deleted-value-parent-data-independent-validation-required"],
            gap_ids=["#5"],
        )
        yield ArtifactRecord(
            provider=WindowsRegistryProvider.name,
            artifact_type="registry-value-recovery-candidate",
            path=str(path.resolve()),
            supported=bool(metadata.get("regf_valid")),
            details={
                "parser": "windows-registry-hive-value-recovery",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-deleted-value-candidate",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "registry-hive",
                "source_hashes": dict(source_hashes),
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "parser_confidence": 0.54 if metadata.get("regf_valid") else 0.22,
                "evidence_strength": "registry-deleted-value-candidate",
                "validation_required": True,
                "registry_validation_matrix": validation_matrix,
                "registry_report_grade_assessment": report_grade_assessment,
                "registry_native_capabilities": REGISTRY_NATIVE_CAPABILITIES,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade_assessment["blockers"],
                "validation_guidance": "Recovered free vk cells may be stale, partially overwritten, or unrelated to the nearest key; validate with a second parser and surrounding hive context.",
                "candidate_kind": "deleted-or-free-value-cell",
                "name": candidate.get("name", ""),
                "value_type": candidate.get("value_type", ""),
                "value_data_size": candidate.get("value_data_size", 0),
                "value_data_offset": candidate.get("value_data_offset", 0),
                "value_data_inline": candidate.get("value_data_inline", False),
                "decoded_data_preview": decoded_data,
                "parent_key_path_candidate": parent_path,
                "parent_key_confidence": parent_confidence,
                "parent_key_cell_offset": parent.get("cell_offset", 0) if parent is not None else 0,
                "cell_offset": candidate.get("cell_offset", 0),
                "cell_relative_offset": candidate.get("cell_relative_offset", 0),
                "cell_scan_method": candidate.get("cell_scan_method", ""),
                "hbin_offset": candidate.get("hbin_offset", 0),
                "cell_size": candidate.get("cell_size", 0),
                "allocation_status": candidate.get("allocation_status", ""),
                "caution_labels": ["deleted-or-free-cell-candidate", "do-not-report-without-validation"],
                "risk_flags": registry_cell_risk_flags(candidate),
                "risk_score": min(100, 45 + len(registry_cell_risk_flags(candidate)) * 20),
                "raw_preview": f"deleted/free value {candidate.get('name', '')}".strip(),
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


def build_registry_user_activity_from_reg(
    path: Path,
    key: str,
    values: Mapping[str, str],
    source_hashes: Mapping[str, str],
) -> ArtifactRecord | None:
    classification = classify_user_activity_key(key)
    if classification is None:
        return None
    decoded_values = decode_user_activity_values(key, values)
    risk_flags = user_activity_risk_flags(classification["category"], key, decoded_values)
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-user-activity",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "windows-registry-user-hive-activity",
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped-reg-export",
            "reportability": "review",
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "source_hashes": dict(source_hashes),
            "hive_hint": key.split("\\", 1)[0],
            "user_hive_scope": "exported-user-hive" if key.upper().startswith("HKEY_CURRENT_USER") else "registry-export",
            "user_activity_category": classification["category"],
            "activity_label": classification["label"],
            "key": key,
            "value_count": len(values),
            "value_names": sorted(values),
            "decoded_values": decoded_values,
            "parser_confidence": 0.86,
            "evidence_strength": "registry-export-key",
            "risk_flags": risk_flags,
            "risk_score": min(100, 20 + len(risk_flags) * 20),
            "validation_required": False,
            "validation_guidance": "Registry export keys preserve explicit paths and values, but report-grade user activity should still be cross-checked against source hive hashes and collection context.",
            "raw_preview": f"[{key}]",
        },
    )


def build_registry_user_activity_from_hive_strings(
    path: Path,
    strings: Sequence[str],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    if path.name.upper() not in USER_HIVE_NAMES:
        return
    emitted: set[tuple[str, str]] = set()
    for index, value in enumerate(strings):
        classification = classify_user_activity_key(value)
        if classification is None:
            continue
        key = (classification["category"], value)
        if key in emitted:
            continue
        emitted.add(key)
        risk_flags = user_activity_risk_flags(classification["category"], value, {})
        yield ArtifactRecord(
            provider=WindowsRegistryProvider.name,
            artifact_type="registry-user-activity",
            path=str(path.resolve()),
            supported=bool(metadata.get("regf_valid")),
            details={
                "parser": "windows-registry-user-hive-activity",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-hive-string-pivot",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_format": "registry-hive",
                "source_hashes": dict(source_hashes),
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "user_hive_scope": "ntuser" if path.name.upper() == "NTUSER.DAT" else "usrclass",
                "user_activity_category": classification["category"],
                "activity_label": classification["label"],
                "string_index": index,
                "string_value": value,
                "parser_confidence": 0.52 if metadata.get("regf_valid") else 0.25,
                "evidence_strength": "registry-hive-string-candidate",
                "risk_flags": risk_flags,
                "risk_score": min(100, 10 + len(risk_flags) * 20),
                "validation_required": True,
                "validation_guidance": "Native NTUSER/UsrClass string pivots identify likely user-activity keys only; validate with a full registry hive parser before final testimony.",
                "raw_preview": value[:1000],
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
    hive_cell_hits: list[dict[str, object]] = []
    key_tree_nodes: list[dict[str, object]] = []
    deleted_cell_candidates: list[dict[str, object]] = []
    key_recovery_candidates: list[dict[str, object]] = []
    value_recovery_candidates: list[dict[str, object]] = []
    user_activity_entries: list[dict[str, object]] = []
    native_report_grade_status_counts: Counter[str] = Counter()

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
        if record.artifact_type == "registry-hive-cell":
            cell_hit = {
                "source_path": details.get("source_path", record.path),
                "hive_hint": details.get("hive_hint", ""),
                "cell_kind": details.get("cell_kind", ""),
                "cell_offset": details.get("cell_offset", 0),
                "allocation_status": details.get("allocation_status", ""),
                "name": details.get("name", ""),
                "last_written_at": details.get("last_written_at", ""),
                "risk_flags": list(details.get("risk_flags") or []),
                "risk_score": details.get("risk_score", 0),
            }
            if cell_hit["name"] or cell_hit["risk_flags"] or cell_hit["allocation_status"] == "free-or-deleted-candidate":
                hive_cell_hits.append(cell_hit)
        if record.artifact_type == "registry-deleted-cell-candidate":
            deleted_cell_candidates.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "hive_hint": details.get("hive_hint", ""),
                    "cell_kind": details.get("cell_kind", ""),
                    "cell_offset": details.get("cell_offset", 0),
                    "name": details.get("name", ""),
                    "last_written_at": details.get("last_written_at", ""),
                    "value_type": details.get("value_type", ""),
                    "risk_flags": list(details.get("risk_flags") or []),
                    "risk_score": details.get("risk_score", 0),
                    "validation_required": details.get("validation_required", True),
                }
            )
        if record.artifact_type == "registry-key-tree-node":
            report_grade = (
                details.get("registry_report_grade_assessment")
                if isinstance(details.get("registry_report_grade_assessment"), Mapping)
                else {}
            )
            if report_grade:
                native_report_grade_status_counts[str(report_grade.get("status") or "unknown")] += 1
            key_tree_nodes.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "hive_hint": details.get("hive_hint", ""),
                    "key_path": details.get("key_path", ""),
                    "key_path_confidence": details.get("key_path_confidence", ""),
                    "cell_offset": details.get("cell_offset", 0),
                    "parent_cell_offset": details.get("parent_cell_offset", 0),
                    "allocation_status": details.get("allocation_status", ""),
                    "value_names": list(details.get("value_names") or []),
                    "linked_subkey_count": details.get("linked_subkey_count", 0),
                    "linked_value_count": details.get("linked_value_count", 0),
                    "last_written_at": details.get("last_written_at", ""),
                    "validation_required": details.get("validation_required", False),
                    "validation_flags": list(details.get("validation_flags") or []),
                    "report_grade_status": report_grade.get("status", ""),
                }
            )
        if record.artifact_type == "registry-key-recovery-candidate":
            report_grade = (
                details.get("registry_report_grade_assessment")
                if isinstance(details.get("registry_report_grade_assessment"), Mapping)
                else {}
            )
            if report_grade:
                native_report_grade_status_counts[str(report_grade.get("status") or "unknown")] += 1
            key_recovery_candidates.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "hive_hint": details.get("hive_hint", ""),
                    "key_path_candidate": details.get("key_path_candidate", ""),
                    "key_path_confidence": details.get("key_path_confidence", ""),
                    "name": details.get("name", ""),
                    "last_written_at": details.get("last_written_at", ""),
                    "cell_offset": details.get("cell_offset", 0),
                    "risk_flags": list(details.get("risk_flags") or []),
                    "validation_required": details.get("validation_required", True),
                    "report_grade_status": report_grade.get("status", ""),
                }
            )
        if record.artifact_type == "registry-value-recovery-candidate":
            report_grade = (
                details.get("registry_report_grade_assessment")
                if isinstance(details.get("registry_report_grade_assessment"), Mapping)
                else {}
            )
            if report_grade:
                native_report_grade_status_counts[str(report_grade.get("status") or "unknown")] += 1
            value_recovery_candidates.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "hive_hint": details.get("hive_hint", ""),
                    "parent_key_path_candidate": details.get("parent_key_path_candidate", ""),
                    "parent_key_confidence": details.get("parent_key_confidence", ""),
                    "name": details.get("name", ""),
                    "value_type": details.get("value_type", ""),
                    "decoded_data_preview": details.get("decoded_data_preview", ""),
                    "cell_offset": details.get("cell_offset", 0),
                    "risk_flags": list(details.get("risk_flags") or []),
                    "validation_required": details.get("validation_required", True),
                    "report_grade_status": report_grade.get("status", ""),
                }
            )
        if record.artifact_type == "registry-user-activity":
            user_activity_entries.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "source_format": details.get("source_format", ""),
                    "coverage_status": details.get("coverage_status", ""),
                    "hive_hint": details.get("hive_hint", ""),
                    "user_hive_scope": details.get("user_hive_scope", ""),
                    "user_activity_category": details.get("user_activity_category", ""),
                    "activity_label": details.get("activity_label", ""),
                    "key": details.get("key", details.get("string_value", "")),
                    "value_names": list(details.get("value_names") or []),
                    "risk_flags": list(details.get("risk_flags") or []),
                    "validation_required": details.get("validation_required", False),
                }
            )
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
        "hive_cell_row_count": sum(1 for record in records if record.artifact_type == "registry-hive-cell"),
        "key_tree_node_count": sum(1 for record in records if record.artifact_type == "registry-key-tree-node"),
        "deleted_cell_candidate_count": sum(1 for record in records if record.artifact_type == "registry-deleted-cell-candidate"),
        "key_recovery_candidate_count": sum(1 for record in records if record.artifact_type == "registry-key-recovery-candidate"),
        "value_recovery_candidate_count": sum(1 for record in records if record.artifact_type == "registry-value-recovery-candidate"),
        "user_activity_count": sum(1 for record in records if record.artifact_type == "registry-user-activity"),
        "source_files": sorted(source_paths),
        "artifact_type_counts": counter_items(artifact_type_counts),
        "source_format_counts": counter_items(source_format_counts),
        "hive_counts": counter_items(hive_counts),
        "native_capabilities": REGISTRY_NATIVE_CAPABILITIES,
        "native_report_grade_status_counts": counter_items(native_report_grade_status_counts),
        "native_report_grade_blockers": REGISTRY_REPORT_GRADE_BLOCKERS,
        "hive_files": hive_files[:100],
        "hive_string_hits": sorted(hive_string_hits, key=lambda item: len(item.get("risk_flags", [])), reverse=True)[:100],
        "hive_cell_hits": sorted(
            hive_cell_hits,
            key=lambda item: int(item.get("risk_score") or 0),
            reverse=True,
        )[:100],
        "key_tree_nodes": sorted(
            key_tree_nodes,
            key=lambda item: (str(item.get("hive_hint") or ""), str(item.get("key_path") or "")),
        )[:100],
        "deleted_cell_candidates": sorted(
            deleted_cell_candidates,
            key=lambda item: int(item.get("risk_score") or 0),
            reverse=True,
        )[:100],
        "key_recovery_candidates": sorted(
            key_recovery_candidates,
            key=lambda item: str(item.get("key_path_candidate") or ""),
        )[:100],
        "value_recovery_candidates": sorted(
            value_recovery_candidates,
            key=lambda item: str(item.get("parent_key_path_candidate") or ""),
        )[:100],
        "user_activity_entries": sorted(
            user_activity_entries,
            key=lambda item: (str(item.get("user_activity_category") or ""), str(item.get("key") or "")),
        )[:100],
        "persistence_entries": persistence_entries[:100],
        "usb_devices": usb_devices[:100],
        "suspicious_entries": sorted(
            suspicious_entries,
            key=lambda item: int(item.get("risk_score") or 0),
            reverse=True,
        )[:100],
        "summary_notes": [
            "Registry hive rows use native regf header parsing, bounded string scanning, hbin-aware nk/vk cell walking when possible, best-effort key-tree rows, and separate deleted/free key/value recovery candidate rows; report-grade deleted-value testimony still requires validation with a dedicated hive parser.",
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


def classify_user_activity_key(value: str) -> dict[str, str] | None:
    lowered = value.lower()
    normalized = lowered.replace("/", "\\")
    for pattern, category, label in USER_ACTIVITY_KEY_PATTERNS:
        if pattern in normalized:
            return {"category": category, "label": label, "matched_pattern": pattern}
    return None


def decode_user_activity_values(key: str, values: Mapping[str, str]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    lowered_key = key.lower()
    for name, raw_value in sorted(values.items()):
        cleaned = clean_reg_value(raw_value)
        item: dict[str, object] = {"raw": cleaned}
        if "userassist" in lowered_key:
            item["decoded_name"] = decode_rot13_registry_value_name(name)
            item["note"] = "UserAssist value names are ROT13 encoded; binary counters require a dedicated parser for run counts and timestamps."
        elif "typedurls" in lowered_key or "typedpaths" in lowered_key:
            item["typed_value"] = cleaned
        elif "runmru" in lowered_key:
            item["command"] = cleaned
        elif "run" in lowered_key:
            item["command"] = cleaned
            item["executable_hint"] = executable_hint(cleaned)
        else:
            item["value"] = cleaned
        decoded[name] = item
    return decoded


def decode_rot13_registry_value_name(value: str) -> str:
    return value.translate(ROT13_TRANS)


def user_activity_risk_flags(category: object, key: str, decoded_values: Mapping[str, object]) -> list[str]:
    flags = [f"user-activity:{category}"] if category else []
    lowered = " ".join([key, " ".join(str(value) for value in decoded_values.values())]).lower()
    if category == "persistence":
        flags.append("user-hive-persistence")
    if category in {"browser-typed-url", "typed-path", "recent-document", "file-dialog-mru", "run-dialog-mru"}:
        flags.append("user-interaction-history")
    if category == "shellbag":
        flags.append("folder-view-history")
    if category == "mounted-device":
        flags.append("mounted-device-history")
    flags.extend(suspicious_value_flags(lowered))
    return sorted(set(flags))


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


def iter_registry_cell_candidates(blob: bytes) -> list[dict[str, object]]:
    scan_blob = blob[:MAX_HIVE_CELL_SCAN_BYTES]
    candidates: list[dict[str, object]] = []
    seen_offsets: set[int] = set()
    for hbin in iter_registry_hbin_descriptors(scan_blob):
        hbin_offset = int(hbin.get("hbin_offset") or 0)
        hbin_size = int(hbin.get("hbin_size") or 0)
        cursor = hbin_offset + HIVE_BIN_HEADER_SIZE
        hbin_end = min(len(scan_blob), hbin_offset + hbin_size)
        while cursor + 8 <= hbin_end and len(candidates) < MAX_HIVE_CELL_RECORDS:
            cell_size_raw = read_i32(scan_blob, cursor)
            cell_size = abs(cell_size_raw)
            if cell_size < 8 or cell_size > MAX_HIVE_CELL_SIZE:
                break
            cell_end = cursor + cell_size
            if cell_end > hbin_end:
                break
            signature = scan_blob[cursor + 4 : cursor + 6]
            candidate = parse_registry_cell_candidate(
                scan_blob,
                cursor,
                cursor + 4,
                cell_size,
                cell_size_raw,
                signature,
                scan_method="hbin-walk",
                hbin_offset=hbin_offset,
            )
            if candidate is not None:
                seen_offsets.add(cursor)
                candidate["cell_index"] = len(candidates)
                candidates.append(candidate)
            cursor += align_registry_cell_size(cell_size)

    for signature in (b"nk", b"vk"):
        cursor = 0
        while len(candidates) < MAX_HIVE_CELL_RECORDS:
            signature_offset = scan_blob.find(signature, cursor)
            if signature_offset < 0:
                break
            cursor = signature_offset + 1
            cell_offset = signature_offset - 4
            if cell_offset < 0 or cell_offset in seen_offsets:
                continue
            cell_size_raw = read_i32(scan_blob, cell_offset)
            cell_size = abs(cell_size_raw)
            if cell_size < 8 or cell_size > MAX_HIVE_CELL_SIZE:
                continue
            if cell_offset + cell_size > len(scan_blob):
                continue
            candidate = parse_registry_cell_candidate(
                scan_blob,
                cell_offset,
                signature_offset,
                cell_size,
                cell_size_raw,
                signature,
                scan_method="signature-scan",
                hbin_offset=registry_hbin_offset_for_cell(cell_offset),
            )
            if candidate is None:
                continue
            seen_offsets.add(cell_offset)
            candidate["cell_index"] = len(candidates)
            candidates.append(candidate)
    return sorted(candidates, key=lambda item: int(item.get("cell_offset") or 0))


def iter_registry_hbin_descriptors(blob: bytes) -> list[dict[str, object]]:
    descriptors: list[dict[str, object]] = []
    offset = HIVE_BIN_BASE_OFFSET
    while offset + HIVE_BIN_HEADER_SIZE <= len(blob):
        if blob[offset : offset + 4] != REGISTRY_HBIN_SIGNATURE:
            offset += 4096
            continue
        hbin_relative_offset = read_u32(blob, offset + 4)
        hbin_size = read_u32(blob, offset + 8)
        if hbin_size < HIVE_BIN_HEADER_SIZE or hbin_size % 4096 != 0:
            offset += 4096
            continue
        descriptors.append(
            {
                "hbin_offset": offset,
                "hbin_relative_offset": hbin_relative_offset,
                "hbin_size": hbin_size,
                "hbin_end_offset": min(len(blob), offset + hbin_size),
            }
        )
        offset += hbin_size
    return descriptors


def parse_registry_cell_candidate(
    blob: bytes,
    cell_offset: int,
    signature_offset: int,
    cell_size: int,
    cell_size_raw: int,
    signature: bytes,
    *,
    scan_method: str,
    hbin_offset: int,
) -> dict[str, object] | None:
    if signature == b"nk":
        candidate = parse_registry_nk_cell(blob, cell_offset, signature_offset, cell_size, cell_size_raw)
    elif signature == b"vk":
        candidate = parse_registry_vk_cell(blob, cell_offset, signature_offset, cell_size, cell_size_raw)
    else:
        return None
    if candidate is None:
        return None
    candidate["cell_scan_method"] = scan_method
    candidate["hbin_offset"] = hbin_offset
    candidate["cell_relative_offset"] = registry_file_to_relative_offset(cell_offset)
    return candidate


def align_registry_cell_size(cell_size: int) -> int:
    return cell_size + ((8 - (cell_size % 8)) % 8)


def parse_registry_nk_cell(
    blob: bytes,
    cell_offset: int,
    signature_offset: int,
    cell_size: int,
    cell_size_raw: int,
) -> dict[str, object] | None:
    flags = read_u16(blob, signature_offset + 2)
    last_written_at = filetime_to_iso(read_u64(blob, signature_offset + 4))
    parent_cell_relative_offset = read_u32(blob, signature_offset + 0x10)
    stable_subkey_count = read_u32(blob, signature_offset + 0x14)
    volatile_subkey_count = read_u32(blob, signature_offset + 0x18)
    stable_subkey_list_offset = read_u32(blob, signature_offset + 0x1C)
    volatile_subkey_list_offset = read_u32(blob, signature_offset + 0x20)
    value_count = read_u32(blob, signature_offset + 0x24)
    value_list_offset = read_u32(blob, signature_offset + 0x28)
    name_length = read_u16(blob, signature_offset + 0x48)
    name_start = signature_offset + 0x4C
    name_end = min(name_start + name_length, cell_offset + cell_size)
    name, encoding = decode_registry_cell_name(blob[name_start:name_end], compressed=True)
    if not is_plausible_registry_cell_name(name) and not last_written_at:
        return None
    return {
        "cell_kind": "key-node",
        "cell_signature": "nk",
        "cell_offset": cell_offset,
        "cell_size": cell_size,
        "allocation_status": registry_cell_allocation_status(cell_size_raw),
        "flags": flags,
        "name": name,
        "name_encoding": encoding,
        "last_written_at": last_written_at,
        "parent_cell_offset": registry_relative_to_file_offset(parent_cell_relative_offset),
        "parent_cell_relative_offset": parent_cell_relative_offset,
        "subkey_count": stable_subkey_count + volatile_subkey_count,
        "stable_subkey_count": stable_subkey_count,
        "volatile_subkey_count": volatile_subkey_count,
        "stable_subkey_list_offset": registry_relative_to_file_offset(stable_subkey_list_offset),
        "volatile_subkey_list_offset": registry_relative_to_file_offset(volatile_subkey_list_offset),
        "value_count": value_count,
        "value_list_offset": registry_relative_to_file_offset(value_list_offset),
        "value_list_relative_offset": value_list_offset,
    }


def parse_registry_vk_cell(
    blob: bytes,
    cell_offset: int,
    signature_offset: int,
    cell_size: int,
    cell_size_raw: int,
) -> dict[str, object] | None:
    name_length = read_u16(blob, signature_offset + 2)
    data_size = read_u32(blob, signature_offset + 4)
    data_offset = read_u32(blob, signature_offset + 8)
    value_type = read_u32(blob, signature_offset + 12)
    flags = read_u16(blob, signature_offset + 16)
    name_start = signature_offset + 20
    name_end = min(name_start + name_length, cell_offset + cell_size)
    name, encoding = decode_registry_cell_name(blob[name_start:name_end], compressed=bool(flags & 0x0001))
    if not is_plausible_registry_cell_name(name):
        return None
    value_data_inline = bool(data_size & 0x80000000)
    return {
        "cell_kind": "value",
        "cell_signature": "vk",
        "cell_offset": cell_offset,
        "cell_size": cell_size,
        "allocation_status": registry_cell_allocation_status(cell_size_raw),
        "flags": flags,
        "name": name,
        "name_encoding": encoding,
        "value_type": registry_value_type_name(value_type),
        "value_data_size": data_size & 0x7FFFFFFF,
        "value_data_offset": registry_relative_to_file_offset(data_offset) if not value_data_inline else data_offset,
        "value_data_relative_offset": data_offset,
        "value_data_inline": value_data_inline,
        "value_data_raw_size": data_size,
    }


def registry_relative_to_file_offset(relative_offset: int) -> int:
    if relative_offset in {0, 0xFFFFFFFF}:
        return 0
    return HIVE_BIN_BASE_OFFSET + relative_offset


def registry_file_to_relative_offset(file_offset: int) -> int:
    return file_offset - HIVE_BIN_BASE_OFFSET if file_offset >= HIVE_BIN_BASE_OFFSET else 0


def registry_hbin_offset_for_cell(cell_offset: int) -> int:
    if cell_offset < HIVE_BIN_BASE_OFFSET:
        return 0
    return HIVE_BIN_BASE_OFFSET + ((cell_offset - HIVE_BIN_BASE_OFFSET) // 4096) * 4096


def registry_subkey_offsets_for_key(blob: bytes, key_node: Mapping[str, object]) -> list[int]:
    offsets: list[int] = []
    for list_offset in (
        int(key_node.get("stable_subkey_list_offset") or 0),
        int(key_node.get("volatile_subkey_list_offset") or 0),
    ):
        offsets.extend(registry_subkey_offsets_from_list(blob, list_offset, depth=0))
    return sorted(set(offsets))


def registry_subkey_offsets_from_list(blob: bytes, list_offset: int, *, depth: int) -> list[int]:
    if list_offset <= 0 or list_offset + 8 > len(blob) or depth > 4:
        return []
    cell_size = abs(read_i32(blob, list_offset))
    if cell_size < 8 or list_offset + cell_size > len(blob):
        return []
    signature = blob[list_offset + 4 : list_offset + 6]
    count = read_u16(blob, list_offset + 6)
    if count > 8192:
        return []
    offsets: list[int] = []
    if signature in {b"lf", b"lh"}:
        cursor = list_offset + 8
        for _ in range(count):
            if cursor + 8 > list_offset + cell_size:
                break
            child = registry_relative_to_file_offset(read_u32(blob, cursor))
            if child:
                offsets.append(child)
            cursor += 8
    elif signature == b"li":
        cursor = list_offset + 8
        for _ in range(count):
            if cursor + 4 > list_offset + cell_size:
                break
            child = registry_relative_to_file_offset(read_u32(blob, cursor))
            if child:
                offsets.append(child)
            cursor += 4
    elif signature == b"ri":
        cursor = list_offset + 8
        for _ in range(count):
            if cursor + 4 > list_offset + cell_size:
                break
            nested = registry_relative_to_file_offset(read_u32(blob, cursor))
            offsets.extend(registry_subkey_offsets_from_list(blob, nested, depth=depth + 1))
            cursor += 4
    return offsets


def registry_value_offsets_for_key(blob: bytes, key_node: Mapping[str, object]) -> list[int]:
    value_count = int(key_node.get("value_count") or 0)
    value_list_offset = int(key_node.get("value_list_offset") or 0)
    if value_count <= 0 or value_count > 4096 or value_list_offset <= 0:
        return []
    end = value_list_offset + value_count * 4
    if end > len(blob):
        return []
    offsets: list[int] = []
    for index in range(value_count):
        relative = read_u32(blob, value_list_offset + index * 4)
        file_offset = registry_relative_to_file_offset(relative)
        if file_offset:
            offsets.append(file_offset)
    return offsets


def registry_value_parent_map(
    blob: bytes,
    key_by_offset: Mapping[int, Mapping[str, object]],
) -> dict[int, Mapping[str, object]]:
    value_parent_by_offset: dict[int, Mapping[str, object]] = {}
    for key_node in key_by_offset.values():
        for value_offset in registry_value_offsets_for_key(blob, key_node):
            value_parent_by_offset.setdefault(value_offset, key_node)
    return value_parent_by_offset


def registry_key_path_for_node(
    key_node: Mapping[str, object],
    key_by_offset: Mapping[int, Mapping[str, object]],
) -> tuple[str, str]:
    names = [str(key_node.get("name") or "")]
    current = key_node
    seen = {int(key_node.get("cell_offset") or 0)}
    confidence = "orphan-name"
    for _ in range(32):
        parent_offset = int(current.get("parent_cell_offset") or 0)
        if not parent_offset or parent_offset in seen or parent_offset not in key_by_offset:
            break
        parent = key_by_offset[parent_offset]
        parent_name = str(parent.get("name") or "")
        if parent_name:
            names.append(parent_name)
        seen.add(parent_offset)
        current = parent
        confidence = "parent-chain"
    names = [name for name in reversed(names) if name]
    return "\\".join(names), confidence


def nearest_preceding_key(
    value_cell: Mapping[str, object],
    key_by_offset: Mapping[int, Mapping[str, object]],
) -> Mapping[str, object] | None:
    value_offset = int(value_cell.get("cell_offset") or 0)
    preceding = [offset for offset in key_by_offset if offset < value_offset]
    if not preceding:
        return None
    nearest_offset = max(preceding)
    if value_offset - nearest_offset > 1024 * 1024:
        return None
    return key_by_offset[nearest_offset]


def registry_key_tree_validation_flags(
    key_node: Mapping[str, object],
    path_confidence: str,
    missing_subkey_offsets: Sequence[int],
    missing_value_offsets: Sequence[int],
) -> list[str]:
    flags: list[str] = []
    if key_node.get("allocation_status") != "allocated":
        flags.append("deleted-or-free-key-cell")
    if path_confidence != "parent-chain":
        flags.append(f"path-confidence:{path_confidence}")
    if missing_subkey_offsets:
        flags.append("subkey-list-has-unresolved-cells")
    if missing_value_offsets:
        flags.append("value-list-has-unresolved-cells")
    return flags


def registry_key_tree_validation_matrix(
    key_node: Mapping[str, object],
    path_confidence: str,
    missing_subkey_offsets: Sequence[int],
    missing_value_offsets: Sequence[int],
    hive_valid: bool,
) -> list[dict[str, object]]:
    return [
        {
            "id": "regf-header",
            "label": "Registry hive header",
            "passed": hive_valid,
            "severity": "critical",
            "detail": "Hive begins with a valid regf header.",
        },
        {
            "id": "allocated-key-cell",
            "label": "Allocated key cell",
            "passed": key_node.get("allocation_status") == "allocated",
            "severity": "high",
            "detail": str(key_node.get("allocation_status") or ""),
        },
        {
            "id": "parent-chain",
            "label": "Parent-chain path reconstruction",
            "passed": path_confidence == "parent-chain",
            "severity": "high",
            "detail": path_confidence,
        },
        {
            "id": "subkey-list-resolution",
            "label": "Subkey list resolution",
            "passed": not missing_subkey_offsets,
            "severity": "medium",
            "detail": f"missing={len(missing_subkey_offsets)}",
        },
        {
            "id": "value-list-resolution",
            "label": "Value list resolution",
            "passed": not missing_value_offsets,
            "severity": "medium",
            "detail": f"missing={len(missing_value_offsets)}",
        },
        {
            "id": "last-write-timestamp",
            "label": "Last-write timestamp",
            "passed": bool(key_node.get("last_written_at")),
            "severity": "medium",
            "detail": str(key_node.get("last_written_at") or ""),
        },
    ]


def registry_value_recovery_validation_matrix(
    value_cell: Mapping[str, object],
    parent_confidence: str,
    has_parent_path: bool,
    has_decoded_preview: bool,
    hive_valid: bool,
) -> list[dict[str, object]]:
    return [
        {
            "id": "regf-header",
            "label": "Registry hive header",
            "passed": hive_valid,
            "severity": "critical",
            "detail": "Hive begins with a valid regf header.",
        },
        {
            "id": "deleted-value-cell",
            "label": "Deleted/free value cell",
            "passed": value_cell.get("allocation_status") == "free-or-deleted-candidate",
            "severity": "critical",
            "detail": str(value_cell.get("allocation_status") or ""),
        },
        {
            "id": "parent-key-link",
            "label": "Parent key link",
            "passed": has_parent_path and parent_confidence == "key-value-list",
            "severity": "high",
            "detail": parent_confidence,
        },
        {
            "id": "value-type-present",
            "label": "Value type present",
            "passed": str(value_cell.get("value_type") or "") != "",
            "severity": "medium",
            "detail": str(value_cell.get("value_type") or ""),
        },
        {
            "id": "data-preview",
            "label": "Data preview",
            "passed": has_decoded_preview,
            "severity": "medium",
            "detail": "inline-or-bounded-data" if has_decoded_preview else "not-decoded",
        },
    ]


def registry_report_grade_assessment(
    validation_matrix: Sequence[Mapping[str, object]],
    *,
    validation_required: bool,
    recovery_candidate: bool,
    extra_blockers: Sequence[str],
    gap_ids: Sequence[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if isinstance(item, Mapping) and not item.get("passed")]
    blockers = list(REGISTRY_REPORT_GRADE_BLOCKERS)
    blockers.extend(f"validation-check-failed:{item}" for item in failed)
    blockers.extend(str(item) for item in extra_blockers if str(item))
    if validation_required:
        blockers.append("registry-native-validation-required")
    if recovery_candidate:
        blockers.append("deleted-or-free-cell-independent-validation-required")
    blockers = sorted(set(blockers))
    if not failed and not recovery_candidate:
        status = "triage-validated-report-grade-blocked"
    elif recovery_candidate:
        status = "recovery-candidate-validation-required"
    else:
        status = "validation-required"
    return {
        "report_grade_ready": False,
        "status": status,
        "blockers": blockers,
        "validated_strengths": [
            str(item.get("id"))
            for item in validation_matrix
            if isinstance(item, Mapping) and item.get("passed")
        ],
        "commercial_gap_ids": list(gap_ids),
        "next_validation_step": (
            "Validate important registry key/value testimony with transaction logs, hive allocator context, "
            "and a second parser before treating native rows as report-grade evidence."
        ),
    }


def registry_key_tree_confidence(key_node: Mapping[str, object], path_confidence: str, hive_valid: bool) -> float:
    score = 0.42 if hive_valid else 0.2
    if key_node.get("allocation_status") == "allocated":
        score += 0.12
    if key_node.get("last_written_at"):
        score += 0.08
    if path_confidence == "parent-chain":
        score += 0.18
    if key_node.get("value_count"):
        score += 0.05
    return min(0.82, round(score, 2))


def registry_value_data_preview(blob: bytes, value_cell: Mapping[str, object]) -> str:
    value_size = int(value_cell.get("value_data_size") or 0)
    if value_size <= 0 or value_size > 4096:
        return ""
    if value_cell.get("value_data_inline"):
        raw = int(value_cell.get("value_data_relative_offset") or 0).to_bytes(4, "little")[:value_size]
    else:
        data_offset = int(value_cell.get("value_data_offset") or 0)
        if data_offset <= 0 or data_offset + value_size > len(blob):
            return ""
        raw = blob[data_offset : data_offset + value_size]
    value_type = str(value_cell.get("value_type") or "")
    if value_type in {"REG_SZ", "REG_EXPAND_SZ"}:
        return decode_utf16le_string(raw) or raw.decode("latin-1", errors="replace").rstrip("\x00")
    if value_type == "REG_DWORD" and len(raw) >= 4:
        return str(int.from_bytes(raw[:4], "little", signed=False))
    if value_type == "REG_QWORD" and len(raw) >= 8:
        return str(int.from_bytes(raw[:8], "little", signed=False))
    return raw[:64].hex()


def decode_registry_cell_name(raw_name: bytes, *, compressed: bool) -> tuple[str, str]:
    if not raw_name:
        return "", ""
    if compressed:
        return raw_name.decode("latin-1", errors="ignore").strip("\x00\r\n\t "), "latin-1"
    decoded = decode_utf16le_string(raw_name)
    if decoded:
        return decoded, "utf-16le"
    return raw_name.decode("latin-1", errors="ignore").strip("\x00\r\n\t "), "latin-1-fallback"


def is_plausible_registry_cell_name(name: str) -> bool:
    if not name or len(name) > 260:
        return False
    return bool(re.search(r"[A-Za-z0-9_.$%{}() -]", name)) and not any(ord(char) < 32 for char in name)


def registry_cell_allocation_status(cell_size_raw: int) -> str:
    return "allocated" if cell_size_raw < 0 else "free-or-deleted-candidate"


def registry_value_type_name(value_type: int) -> str:
    value_types = {
        0: "REG_NONE",
        1: "REG_SZ",
        2: "REG_EXPAND_SZ",
        3: "REG_BINARY",
        4: "REG_DWORD",
        5: "REG_DWORD_BIG_ENDIAN",
        6: "REG_LINK",
        7: "REG_MULTI_SZ",
        8: "REG_RESOURCE_LIST",
        9: "REG_FULL_RESOURCE_DESCRIPTOR",
        10: "REG_RESOURCE_REQUIREMENTS_LIST",
        11: "REG_QWORD",
    }
    return value_types.get(value_type, f"REG_TYPE_{value_type}")


def registry_cell_risk_flags(candidate: Mapping[str, object]) -> list[str]:
    flags: list[str] = []
    name = str(candidate.get("name") or "")
    lowered = name.lower()
    if candidate.get("allocation_status") == "free-or-deleted-candidate":
        flags.append("deleted-or-free-cell-candidate")
    if candidate.get("cell_kind") == "key-node" and any(term.strip("\\") in lowered for term in PERSISTENCE_TERMS):
        flags.append("persistence-key-cell-candidate")
    flags.extend(suspicious_value_flags(name))
    return sorted(set(flags))


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
    seen: set[str] = set()
    for alignment in (0, 1):
        start: int | None = None
        cursor = alignment
        while cursor + 1 < len(blob):
            value = int.from_bytes(blob[cursor : cursor + 2], "little", signed=False)
            printable = value in (9, 10, 13) or 32 <= value <= 0xD7FF or 0xE000 <= value <= 0xFFFD
            if printable and value != 0:
                if start is None:
                    start = cursor
            else:
                if start is not None:
                    text = decode_utf16le_string(blob[start:cursor])
                    if len(text) >= min_chars and text not in seen:
                        strings.append(text)
                        seen.add(text)
                        if len(strings) >= MAX_HIVE_STRINGS:
                            return strings
                    start = None
            cursor += 2
        if start is not None:
            text = decode_utf16le_string(blob[start:cursor])
            if len(text) >= min_chars and text not in seen:
                strings.append(text)
                seen.add(text)
                if len(strings) >= MAX_HIVE_STRINGS:
                    return strings
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


def read_i32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little", signed=True)


def read_u16(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 2], "little", signed=False)


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
