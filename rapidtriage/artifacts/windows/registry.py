from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from ...core.recovery import build_recovery_record
from .._walk import iter_evidence_paths
from .registry_depth import (
    DepthStats,
    export_depth_records,
    hive_depth_records,
    read_export_lines,
)

PARSER_VERSION = "registry-native-walk-v14"
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
    ("\\shell\\muicache", "muicache", "MUICache application display cache"),
    ("clipboard", "clipboard-history", "Clipboard history/settings"),
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
    "full_native_tree_walk": True,
    "big_data_value_decode": True,
    "key_comp_name_flag_decode": True,
    "semantic_system_ntuser_software_plugins": True,
    "transaction_log_newer_sequence_disclosure": True,
    "transaction_log_replay": False,
    "security_descriptor_decode": False,
    "full_binary_value_decode": False,
    "deleted_cell_report_grade_validation": False,
}
REGISTRY_REPORT_GRADE_BLOCKERS = [
    "registry-key-tree-cross-tool-diff-required",
    "transaction-log-replay-not-implemented",
    "full-binary-value-decoding-not-implemented",
    "registry-deleted-cell-cross-tool-diff-required",
    "deleted-cell-known-answer-corpus-validation-required",
    "registry-security-descriptor-decoding-not-implemented",
]
REGISTRY_TRUSTED_TOOL_HINTS = ("regipper", "regripper", "registryexplorer", "pythonregistry", "recmd", "regexport")
REGISTRY_ANALYST_REVIEW_CATALOG = {
    "persistence": {
        "severity": "high",
        "summary": "Registry persistence location; inspect command path, user scope, file creation, signer, and execution artifacts.",
        "primary_pivots": ["key_path", "value_names", "decoded_values", "raw_preview"],
        "correlation_targets": ["mft-usn", "prefetch", "amcache", "bam-dam", "srum", "eventlog-process", "defender"],
        "analyst_questions": [
            "Does the value launch an executable or script from user-writable paths?",
            "Can file creation, execution, or download artifacts corroborate it?",
            "Is the key from HKCU, HKLM, policy, service, or a recovered/deleted cell?",
        ],
        "risk_tags": ["persistence", "execution-review"],
    },
    "execution": {
        "severity": "medium",
        "summary": "User activity/execution registry artifact; decode payloads and correlate with execution timeline.",
        "primary_pivots": ["key_path", "decoded_values", "normalized_activity_rows", "raw_preview"],
        "correlation_targets": ["prefetch", "amcache", "bam-dam", "srum", "mft-usn", "eventlog-process"],
        "analyst_questions": [
            "Which executable or command is represented by the decoded value?",
            "Does the timestamp/path align with other execution artifacts?",
            "Is this from an exported key or only a native string pivot?",
        ],
        "risk_tags": ["user-activity", "execution"],
    },
    "recent-document": {
        "severity": "info",
        "summary": "Recent document/MRU artifact; use as a user activity pivot, not standalone file access proof.",
        "primary_pivots": ["decoded_values", "normalized_activity_rows", "key_path", "raw_preview"],
        "correlation_targets": ["mft-usn", "lnk", "jumplist", "shellbags", "office-recent", "search-index"],
        "analyst_questions": [
            "What document name/path is represented after binary payload decoding?",
            "Does filesystem, LNK, JumpList, or application recent-file evidence corroborate access?",
            "Is MRU order preserved and source hive/user attribution clear?",
        ],
        "risk_tags": ["user-activity", "recent-file"],
    },
    "file-dialog-mru": {
        "severity": "info",
        "summary": "File dialog MRU artifact; useful for user-selected file/folder pivots.",
        "primary_pivots": ["decoded_values", "normalized_activity_rows", "key_path"],
        "correlation_targets": ["mft-usn", "shellbags", "jumplist", "lnk", "application-logs"],
        "analyst_questions": [
            "Which filename, extension, or folder was selected in the dialog?",
            "Can the target be found in filesystem or application artifacts?",
            "Does MRU order align with the case timeline?",
        ],
        "risk_tags": ["user-activity", "file-dialog"],
    },
    "muicache": {
        "severity": "info",
        "summary": "MUICache application display cache; useful as a weak application presence/user activity pivot.",
        "primary_pivots": ["decoded_values", "normalized_activity_rows", "key_path"],
        "correlation_targets": ["prefetch", "amcache", "shimcache", "bam-dam", "mft-usn", "lnk"],
        "analyst_questions": [
            "Which executable path or app display name is represented?",
            "Can Prefetch, Amcache, ShimCache, BAM/DAM, or filesystem evidence corroborate execution?",
            "Is this only a display cache entry without run-count or timestamp semantics?",
        ],
        "risk_tags": ["user-activity", "application-presence"],
    },
    "clipboard-history": {
        "severity": "medium",
        "summary": "Clipboard-related registry artifact; may contain sensitive copied text or Cloud Clipboard settings.",
        "primary_pivots": ["decoded_values", "normalized_activity_rows", "key_path"],
        "correlation_targets": ["cloudstore", "timeline", "recent-documents", "browser", "mft-usn"],
        "analyst_questions": [
            "Does the value represent clipboard content, sync settings, or only feature state?",
            "Is sensitive content minimized and authority documented before report inclusion?",
            "Can application, document, or browser evidence explain the copied value?",
        ],
        "risk_tags": ["user-activity", "sensitive-content-review"],
    },
    "browser-typed-url": {
        "severity": "info",
        "summary": "Typed URL registry artifact; correlate with browser history, cache, and downloads.",
        "primary_pivots": ["decoded_values", "normalized_activity_rows", "key_path"],
        "correlation_targets": ["browser-history", "browser-cache", "downloads", "zone-identifier", "dns"],
        "analyst_questions": [
            "Which URL was typed and under which user hive?",
            "Does browser history/cache/download evidence corroborate the visit?",
            "Are there related credentials, cloud, or AI-service artifacts?",
        ],
        "risk_tags": ["web-activity"],
    },
    "typed-path": {
        "severity": "info",
        "summary": "Typed Explorer path; correlate with ShellBags, LNK, JumpList, and filesystem timeline.",
        "primary_pivots": ["decoded_values", "normalized_activity_rows", "key_path"],
        "correlation_targets": ["shellbags", "lnk", "jumplist", "mft-usn", "network-share"],
        "analyst_questions": [
            "What path was typed or visited?",
            "Does it represent local, removable, or network storage?",
            "Do ShellBags or filesystem timestamps corroborate browsing?",
        ],
        "risk_tags": ["user-activity", "path-navigation"],
    },
    "mounted-device": {
        "severity": "medium",
        "summary": "Mounted device/USB registry artifact; correlate device identity with setupapi, MFT, and user activity.",
        "primary_pivots": ["key_path", "decoded_values", "raw_preview"],
        "correlation_targets": ["setupapi", "usbstor", "mountpoints2", "mft-usn", "lnk", "shellbags"],
        "analyst_questions": [
            "What serial/vendor/product or mount point is represented?",
            "Which user hive recorded the mount point?",
            "Can file access or transfer be correlated around mount time?",
        ],
        "risk_tags": ["device", "removable-media"],
    },
    "network-share": {
        "severity": "medium",
        "summary": "Mapped network share/user network artifact; correlate with logon, share access, and file activity.",
        "primary_pivots": ["decoded_values", "key_path", "raw_preview"],
        "correlation_targets": ["eventlog-share-access", "rdp-logons", "mft-usn", "lnk", "shellbags"],
        "analyst_questions": [
            "Which remote path or drive letter is represented?",
            "Which account/user hive owns the mapping?",
            "Do share access events or file artifacts corroborate use?",
        ],
        "risk_tags": ["network-share", "user-activity"],
    },
    "shellbag": {
        "severity": "info",
        "summary": "ShellBag registry location; decode shell items and correlate folder browsing with filesystem evidence.",
        "primary_pivots": ["key_path", "decoded_values", "raw_preview"],
        "correlation_targets": ["shellbags-native", "mft-usn", "lnk", "jumplist", "removable-media"],
        "analyst_questions": [
            "Which folder path is represented after shell item decoding?",
            "Does UsrClass/NTUSER transaction-log context change the interpretation?",
            "Can filesystem or shortcut artifacts corroborate folder access?",
        ],
        "risk_tags": ["user-activity", "folder-browsing"],
    },
    "deleted-cell": {
        "severity": "high",
        "summary": "Deleted/free registry cell candidate; useful as a lead only until allocator and trusted-parser validation pass.",
        "primary_pivots": ["cell_offset", "name", "key_path_candidate", "parent_key_path_candidate", "decoded_data_preview"],
        "correlation_targets": ["registry-explorer-diff", "recmd-diff", "transaction-logs", "mft-usn", "eventlog"],
        "analyst_questions": [
            "Is the positive-size cell truly free/deleted in allocator context?",
            "Can a second parser confirm the same offset/name/data?",
            "Do transaction logs or neighboring cells change the interpretation?",
        ],
        "risk_tags": ["recovery-candidate", "validation-required"],
    },
    "key-tree": {
        "severity": "medium",
        "summary": "Native registry key-tree row; review parent chain, root reachability, value-list links, and transaction logs.",
        "primary_pivots": ["key_path", "value_names", "subkey_names", "cell_offset", "last_written_at"],
        "correlation_targets": ["registry-explorer-diff", "recmd-diff", "transaction-logs", "eventlog", "mft-usn"],
        "analyst_questions": [
            "Is the parent chain root-reachable and free of cycles?",
            "Are subkey and value list offsets resolved without gaps?",
            "Are LOG1/LOG2 transaction files present and replayed or disclosed?",
        ],
        "risk_tags": ["registry-structure", "validation-required"],
    },
}


class WindowsRegistryProvider:
    collector_kind = "windows-registry"
    name = "windows-registry"
    description = "Windows Registry hives (native full walk) and .reg exports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        summary_records: list[ArtifactRecord] = []
        key_tree_counts: Counter[str] = Counter()
        for path in sorted(iter_evidence_paths(root, "*.reg"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            source_hashes: Mapping[str, str] | None = None
            for record in collect_reg_export(path):
                source_hashes = source_hashes or record.details.get("source_hashes")  # type: ignore[assignment]
                summary_records.append(record)
                yield record
            for record in export_depth_records(path, source_hashes or file_hashes(path)):
                summary_records.append(record)
                yield record
        context = RegistryCollectionContext(root)
        for path in candidate_native_registry_hive_paths(root):
            for record in collect_registry_hive(path, context=context):
                if record.artifact_type == "registry-key-tree-node":
                    key_tree_counts[str(record.details.get("hive_mount") or record.path)] += 1
                else:
                    summary_records.append(record)
                yield record
        summary = build_registry_summary(root, summary_records, key_tree_counts=key_tree_counts)
        if summary is not None:
            yield summary


def candidate_registry_hive_paths(root: Path, *, names: set[str] | None = None) -> Iterable[Path]:
    wanted = names if names is not None else REGISTRY_NATIVE_HIVE_NAMES
    seen: set[Path] = set()
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        name = path.name.upper()
        if name not in wanted:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield path


def collect_reg_export(path: Path) -> Iterable[ArtifactRecord]:
    # Same decoding as the depth rows: UTF-16 only with a BOM or the UTF-16 NUL pattern, then
    # UTF-8, then CP949 (an even-length ANSI export is no longer misread as UTF-16).
    lines = read_export_lines(path)
    if not lines:
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


def collect_registry_hive(
    path: Path,
    *,
    context: RegistryCollectionContext | None = None,
    include_key_tree: bool = True,
) -> Iterable[ArtifactRecord]:
    """Full native walk of one hive: key tree rows, typed plugin rows, free-cell candidates, inventory."""
    try:
        stat_result = path.stat()
    except OSError:
        return
    source_hashes = file_hashes(path)
    hive = NativeRegistryHive.open(path)
    if hive is None:
        try:
            with path.open("rb") as handle:
                header = handle.read(4096)
        except OSError:
            return
        metadata = parse_registry_hive_header(header)
        metadata["transaction_log_evidence"] = registry_transaction_log_evidence(path, hive_metadata=metadata)
        yield build_registry_hive_record(path, stat_result.st_size, metadata, source_hashes)
        return
    try:
        metadata: dict[str, object] = dict(hive.header)
        transaction_log_evidence = registry_transaction_log_evidence(path, hive_metadata=metadata)
        replay_validation_profile = registry_transaction_replay_validation_profile(metadata, transaction_log_evidence)
        transaction_log_evidence["replay_validation_profile"] = replay_validation_profile
        transaction_log_evidence["replay_validation_profile_hash"] = stable_registry_json_sha256(replay_validation_profile)
        metadata["transaction_log_evidence"] = transaction_log_evidence
        disclosure = registry_transaction_disclosure(transaction_log_evidence)
        mount = registry_hive_mount(path, hive, context)
        row_context = NativeHiveRowContext(path, hive, mount, source_hashes, disclosure)
        key_count = 0
        value_count = 0
        if include_key_tree:
            for components, key in hive.iter_keys():
                values = hive.values(key)
                key_count += 1
                value_count += len(values)
                yield build_native_key_tree_record(
                    row_context,
                    components,
                    key,
                    [str(value.name) or "(default)" for value in values],
                )
        walk_errors = dict(hive.errors)
        semantic_counts: Counter[str] = Counter()
        for record in registry_native_semantic_records(row_context):
            semantic_counts[record.artifact_type] += 1
            yield record
        depth_stats = DepthStats()
        for record in hive_depth_records(row_context, depth_stats):
            semantic_counts[record.artifact_type] += 1
            yield record
        scan_end = min(stat_result.st_size, MAX_HIVE_STRING_SCAN_BYTES)
        strings = extract_utf16le_strings(bytes(hive._data[:scan_end]))
        if strings:
            strings_record = build_registry_hive_strings_record(path, strings, metadata, source_hashes)
            strings_record.details["scan_truncated"] = stat_result.st_size > MAX_HIVE_STRING_SCAN_BYTES
            strings_record.details["string_limit_reached"] = len(strings) >= MAX_HIVE_STRINGS
            strings_record.details["string_limit"] = MAX_HIVE_STRINGS
            strings_record.details["cap_disclosure"] = (
                f"문자열 스캔은 앞 {MAX_HIVE_STRING_SCAN_BYTES // (1024 * 1024)}MB·최대 {MAX_HIVE_STRINGS}개로 제한된 "
                "보조 피벗입니다(키/값 해석은 전체 트리 순회 결과를 사용)."
            )
            strings_record.details["evidence_strength"] = "string-candidate-not-evidence"
            yield strings_record
        free_candidates, allocator_stats = iter_registry_free_cell_candidates(hive)
        recovery_candidates = [*free_candidates, *native_parent_key_candidates(hive, free_candidates)]
        for candidate in free_candidates:
            yield build_registry_deleted_cell_record(path, candidate, metadata, source_hashes)
        yield from build_registry_key_recovery_records(
            path, recovery_candidates, metadata, source_hashes, mount=row_context.mount
        )
        yield from build_registry_value_recovery_records(
            path, hive._data, recovery_candidates, metadata, source_hashes, mount=row_context.mount
        )
        metadata["native_walk"] = {
            "reader": "native-regf-tree-walk",
            "key_count": key_count if include_key_tree else None,
            "value_count": value_count if include_key_tree else None,
            "walk_errors": walk_errors,
            "post_walk_lookup_errors": {
                key: count - walk_errors.get(key, 0) for key, count in hive.errors.items() if count - walk_errors.get(key, 0)
            },
            "allocator_stats": allocator_stats,
            "allocated_unreachable_nk_count": max(0, int(allocator_stats.get("allocated_nk", 0)) - key_count)
            if include_key_tree
            else None,
            "free_cell_candidate_count": len(free_candidates),
            "semantic_row_counts": dict(sorted(semantic_counts.items())),
            "registry_depth": depth_stats.summary(),
            "read_cap_bytes": None,
            "cell_cap": None,
        }
        record = build_registry_hive_record(path, stat_result.st_size, metadata, source_hashes)
        record.details.update(
            {
                "coverage_status": "native-hive-full-walk",
                "parser_confidence": 0.9,
                "hive_mount": row_context.mount,
                "user_sid": row_context.user_sid,
                "user_sid_source": mount.get("user_sid_source", ""),
                "root_key_name": mount.get("root_key_name", ""),
                "key_count": key_count,
                "value_count": value_count,
                "native_walk": metadata["native_walk"],
                "transaction_log_disclosure": disclosure["message_ko"],
                "transaction_log_disclosure_status": disclosure["status"],
            }
        )
        record.details["native_header"] = {
            key: value for key, value in metadata.items() if key not in {"native_walk"}
        }
        yield record
    finally:
        hive.close()


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
            "registry_transaction_log_evidence": dict(metadata.get("transaction_log_evidence") or {}),
            "registry_transaction_replay_profile": registry_transaction_replay_profile(
                metadata.get("transaction_log_evidence") if isinstance(metadata.get("transaction_log_evidence"), Mapping) else {},
                dirty=bool(metadata.get("dirty")),
            ),
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


def build_registry_deleted_cell_record(
    path: Path,
    candidate: Mapping[str, object],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    name = str(candidate.get("name") or "")
    risk_flags = registry_cell_risk_flags(candidate)
    recovery_evidence = registry_recovery_evidence(candidate, "deleted-or-free-cell")
    recovery_identity_profile = registry_recovery_identity_profile(candidate, recovery_evidence)
    recovery_profile = registry_recovery_validation_profile(
        candidate,
        recovery_evidence,
        "deleted-or-free-cell",
        validation_checks=[],
        recovery_identity_profile=recovery_identity_profile,
    )
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
            "source_viewer_locator": registry_record_source_viewer_locator(
                source_path=str(path.resolve()),
                source_hashes=source_hashes,
                hive_name=path.name,
                hive_hint=hive_hint_from_path(path),
                key_path="",
                value_name=name if candidate.get("cell_kind") == "value" else "",
                cell_offset=candidate.get("cell_offset", 0),
                cell_relative_offset=candidate.get("cell_relative_offset", 0),
                hbin_offset=candidate.get("hbin_offset", 0),
                allocation_status=candidate.get("allocation_status", ""),
                transaction_log_evidence=metadata.get("transaction_log_evidence")
                if isinstance(metadata.get("transaction_log_evidence"), Mapping)
                else {},
                deleted_or_recovered=True,
            ),
            "hive_name": path.name,
            "hive_hint": hive_hint_from_path(path),
            "parser_confidence": 0.5 if metadata.get("regf_valid") else 0.2,
            "evidence_strength": "registry-deleted-cell-candidate",
            "registry_recovery_evidence": recovery_evidence,
            "registry_recovery_validation_profile": recovery_profile,
            "registry_recovery_identity_profile": recovery_identity_profile,
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


def registry_record_source_viewer_locator(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    hive_name: str,
    hive_hint: str,
    key_path: str,
    value_name: str = "",
    cell_offset: object = 0,
    cell_relative_offset: object = 0,
    hbin_offset: object = 0,
    allocation_status: object = "",
    transaction_log_evidence: Mapping[str, object] | None = None,
    deleted_or_recovered: bool = False,
) -> dict[str, object]:
    transaction_profile = registry_transaction_replay_profile(transaction_log_evidence or {})
    cell_offset_int = int(cell_offset or 0)
    validation_warnings = [
        "validate registry locator with RECmd/Registry Explorer diff before report use",
        "LOG1/LOG2 transaction replay status must be reviewed before final interpretation",
    ]
    if deleted_or_recovered or str(allocation_status) == "free-or-deleted-candidate":
        validation_warnings.append("deleted/free cell candidates require allocator and known-answer validation")
    return {
        "profile_version": "registry-record-source-viewer-locator-v1",
        "qc_prep_item": 8,
        "viewer": "registry-record",
        "source_path": source_path,
        "source_sha256": str(source_hashes.get("sha256") or ""),
        "hive_name": hive_name,
        "hive_hint": hive_hint,
        "key_path": key_path,
        "value_name": value_name,
        "cell_offset": cell_offset_int,
        "cell_offset_hex": f"0x{cell_offset_int:x}" if cell_offset_int else "",
        "cell_relative_offset": int(cell_relative_offset or 0),
        "hbin_offset": int(hbin_offset or 0),
        "allocation_status": str(allocation_status or ""),
        "deleted_or_recovered_candidate": deleted_or_recovered or str(allocation_status) == "free-or-deleted-candidate",
        "source_hash_available": bool(source_hashes.get("sha256")),
        "transaction_replay_status": transaction_profile.get("transaction_log_status", "not-present"),
        "transaction_replay_applied": bool(transaction_profile.get("transaction_log_replay_applied")),
        "validation_warning": " | ".join(validation_warnings),
        "required_before_report": [
            "open registry source viewer",
            "confirm hive/key/value/cell offset",
            "verify hive source hash",
            "review transaction replay status",
            "attach trusted registry-parser diff for report-grade claims",
        ],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "registry-key-tree-cross-tool-diff-required",
            "transaction-log-replay-or-second-parser-diff-required",
            "registry-deleted-cell-cross-tool-diff-required",
        ],
    }


def build_registry_key_recovery_records(
    path: Path,
    candidates: Sequence[Mapping[str, object]],
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
    *,
    mount: str | None = None,
) -> Iterable[ArtifactRecord]:
    path_prefix = mount or hive_hint_from_path(path)
    transaction_log_evidence = (
        metadata.get("transaction_log_evidence")
        if isinstance(metadata.get("transaction_log_evidence"), Mapping)
        else {}
    )
    key_by_offset = {
        int(candidate.get("cell_offset") or 0): candidate
        for candidate in candidates
        if candidate.get("cell_kind") == "key-node"
    }
    for candidate in candidates:
        if candidate.get("cell_kind") != "key-node" or candidate.get("allocation_status") != "free-or-deleted-candidate":
            continue
        key_path, path_confidence = registry_key_path_for_node(candidate, key_by_offset)
        recovered_key_path = f"{path_prefix}\\{key_path}" if key_path else path_prefix
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
        recovery_evidence = registry_recovery_evidence(
            candidate,
            "deleted-or-free-key-cell",
            path_confidence=path_confidence,
            recovered_path=recovered_key_path,
            allocator_neighbor_context=registry_allocator_neighbor_context(candidate, candidates),
        )
        recovery_identity_profile = registry_recovery_identity_profile(
            candidate,
            recovery_evidence,
            recovered_path=recovered_key_path,
        )
        recovery_profile = registry_recovery_validation_profile(
            candidate,
            recovery_evidence,
            "deleted-or-free-key-cell",
            validation_checks=validation_matrix,
            transaction_log_evidence=transaction_log_evidence,
            recovery_identity_profile=recovery_identity_profile,
        )
        report_citation_manifest = registry_report_citation_manifest(
            artifact_type="registry-key-recovery-candidate",
            source_path=str(path.resolve()),
            source_hashes=dict(source_hashes),
            row_identity={
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "key_path_candidate": f"{path_prefix}\\{key_path}" if key_path else path_prefix,
                "name": candidate.get("name", ""),
                "cell_offset": candidate.get("cell_offset", 0),
                "cell_relative_offset": candidate.get("cell_relative_offset", 0),
                "hbin_offset": candidate.get("hbin_offset", 0),
                "allocation_status": candidate.get("allocation_status", ""),
                "candidate_kind": "deleted-or-free-key-cell",
                "cell_signature": candidate.get("cell_signature", ""),
                "cell_size": candidate.get("cell_size", 0),
                "last_written_at": candidate.get("last_written_at", ""),
                "parent_cell_offset": candidate.get("parent_cell_offset", 0),
                "recovery_identity_hash": recovery_identity_profile["identity_hash"],
                "allocator_context_hash": recovery_identity_profile["allocator_context_hash"],
                "allocator_neighbor_context_hash": recovery_identity_profile["allocator_neighbor_context_hash"],
            },
            validation_matrix=validation_matrix,
            report_grade_assessment=report_grade_assessment,
            transaction_log_evidence=transaction_log_evidence,
            recovery_profile=recovery_profile,
            citation_scope="deleted-key-recovery",
        )
        core_accuracy_gates = registry_core_accuracy_gates(
            gap_ids=["#5"],
            validation_matrix=validation_matrix,
            details={
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "cell_offset": candidate.get("cell_offset", 0),
                "allocation_status": candidate.get("allocation_status", ""),
                "positive_size_free_cell": recovery_evidence.get("positive_size_free_cell", False),
                "allocator_context": recovery_evidence.get("allocator_context", {}),
                "transaction_log_evidence": transaction_log_evidence,
                "recovery_evidence": recovery_evidence,
                "recovery_profile": recovery_profile,
                "recovery_identity_profile": recovery_identity_profile,
                "allocator_neighbor_context": recovery_evidence.get("allocator_neighbor_context", {}),
            },
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
                "source_viewer_locator": registry_record_source_viewer_locator(
                    source_path=str(path.resolve()),
                    source_hashes=source_hashes,
                    hive_name=path.name,
                    hive_hint=hive_hint_from_path(path),
                    key_path=recovered_key_path,
                    cell_offset=candidate.get("cell_offset", 0),
                    cell_relative_offset=candidate.get("cell_relative_offset", 0),
                    hbin_offset=candidate.get("hbin_offset", 0),
                    allocation_status=candidate.get("allocation_status", ""),
                    transaction_log_evidence=transaction_log_evidence,
                    deleted_or_recovered=True,
                ),
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "parser_confidence": registry_key_tree_confidence(candidate, path_confidence, bool(metadata.get("regf_valid"))),
                "evidence_strength": "registry-deleted-key-candidate",
                "registry_recovery_evidence": recovery_evidence,
                "registry_recovery_validation_profile": recovery_profile,
                "registry_recovery_identity_profile": recovery_identity_profile,
                "registry_recovery_reportability_decision": recovery_profile["reportability_decision"],
                "registry_transaction_log_evidence": dict(transaction_log_evidence),
                "registry_transaction_replay_profile": registry_transaction_replay_profile(
                    transaction_log_evidence,
                    dirty=bool(metadata.get("dirty")),
                ),
                "validation_required": True,
                "registry_validation_matrix": validation_matrix,
                "registry_report_grade_assessment": report_grade_assessment,
                "registry_report_citation_manifest": report_citation_manifest,
                "registry_report_citation_manifest_hash": report_citation_manifest["manifest_sha256"],
                "registry_native_depth_readiness_profile": registry_native_depth_readiness_profile(
                    family="deleted-cell",
                    artifact_scope="key-recovery-candidate",
                    details={
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "hive_name": path.name,
                        "hive_hint": hive_hint_from_path(path),
                        "cell_offset": candidate.get("cell_offset", 0),
                        "key_path_candidate": f"{path_prefix}\\{key_path}" if key_path else path_prefix,
                        "name": candidate.get("name", ""),
                        "allocation_status": candidate.get("allocation_status", ""),
                        "candidate_kind": "deleted-or-free-key-cell",
                        "registry_recovery_evidence": recovery_evidence,
                        "registry_recovery_validation_profile": recovery_profile,
                        "registry_validation_matrix": validation_matrix,
                        "registry_report_grade_assessment": report_grade_assessment,
                        "registry_transaction_log_evidence": dict(transaction_log_evidence),
                    },
                ),
                "registry_analyst_review_profile": registry_analyst_review_profile(
                    artifact_type="registry-key-recovery-candidate",
                    category="deleted-cell",
                    source_format="registry-hive",
                    hive_name=path.name,
                    hive_hint=hive_hint_from_path(path),
                    key_path=recovered_key_path,
                    name=str(candidate.get("name") or ""),
                    risk_flags=risk_flags,
                    validation_required=True,
                    transaction_log_evidence=transaction_log_evidence,
                    report_grade_assessment=report_grade_assessment,
                    recovery_profile=recovery_profile,
                    source_values={
                        "key_path_candidate": recovered_key_path,
                        "cell_offset": candidate.get("cell_offset", 0),
                    },
                ),
                "core_accuracy_gates": core_accuracy_gates,
                "commercial_uplift_evidence": registry_commercial_uplift_evidence(
                    gap_ids=["#5"],
                    details={
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "cell_offset": candidate.get("cell_offset", 0),
                        "registry_validation_matrix": validation_matrix,
                        "registry_report_grade_assessment": report_grade_assessment,
                        "recovery_profile": recovery_profile,
                        "recovery_identity_profile": recovery_identity_profile,
                        "transaction_log_evidence": transaction_log_evidence,
                    },
                ),
                "registry_native_capabilities": REGISTRY_NATIVE_CAPABILITIES,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade_assessment["blockers"],
                "validation_guidance": "Recovered free nk cells can be stale or partially overwritten; validate with hive allocator state, transaction logs, and a second parser before testimony.",
                "candidate_kind": "deleted-or-free-key-cell",
                "key_path_candidate": f"{path_prefix}\\{key_path}" if key_path else path_prefix,
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
    *,
    mount: str | None = None,
) -> Iterable[ArtifactRecord]:
    path_prefix = mount or hive_hint_from_path(path)
    transaction_log_evidence = (
        metadata.get("transaction_log_evidence")
        if isinstance(metadata.get("transaction_log_evidence"), Mapping)
        else {}
    )
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
            parent_path = f"{path_prefix}\\{parent_key_path}" if parent_key_path else path_prefix
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
        recovery_evidence = registry_recovery_evidence(
            candidate,
            "deleted-or-free-value-cell",
            parent_confidence=parent_confidence,
            parent_path=parent_path,
            decoded_data_present=bool(decoded_data),
            allocator_neighbor_context=registry_allocator_neighbor_context(candidate, candidates),
        )
        recovery_identity_profile = registry_recovery_identity_profile(
            candidate,
            recovery_evidence,
            parent_path=parent_path,
            parent_confidence=parent_confidence,
            decoded_data_preview=decoded_data,
        )
        recovery_profile = registry_recovery_validation_profile(
            candidate,
            recovery_evidence,
            "deleted-or-free-value-cell",
            validation_checks=validation_matrix,
            transaction_log_evidence=transaction_log_evidence,
            recovery_identity_profile=recovery_identity_profile,
        )
        report_citation_manifest = registry_report_citation_manifest(
            artifact_type="registry-value-recovery-candidate",
            source_path=str(path.resolve()),
            source_hashes=dict(source_hashes),
            row_identity={
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "name": candidate.get("name", ""),
                "value_type": candidate.get("value_type", ""),
                "value_data_size": candidate.get("value_data_size", 0),
                "value_data_offset": candidate.get("value_data_offset", 0),
                "value_data_inline": candidate.get("value_data_inline", False),
                "decoded_data_preview_sha256": sha256_text(decoded_data),
                "parent_key_path_candidate": parent_path,
                "parent_key_confidence": parent_confidence,
                "parent_key_cell_offset": parent.get("cell_offset", 0) if parent is not None else 0,
                "cell_offset": candidate.get("cell_offset", 0),
                "cell_relative_offset": candidate.get("cell_relative_offset", 0),
                "hbin_offset": candidate.get("hbin_offset", 0),
                "allocation_status": candidate.get("allocation_status", ""),
                "candidate_kind": "deleted-or-free-value-cell",
                "cell_signature": candidate.get("cell_signature", ""),
                "cell_size": candidate.get("cell_size", 0),
                "recovery_identity_hash": recovery_identity_profile["identity_hash"],
                "allocator_context_hash": recovery_identity_profile["allocator_context_hash"],
                "allocator_neighbor_context_hash": recovery_identity_profile["allocator_neighbor_context_hash"],
            },
            validation_matrix=validation_matrix,
            report_grade_assessment=report_grade_assessment,
            transaction_log_evidence=transaction_log_evidence,
            recovery_profile=recovery_profile,
            citation_scope="deleted-value-recovery",
        )
        core_accuracy_gates = registry_core_accuracy_gates(
            gap_ids=["#5"],
            validation_matrix=validation_matrix,
            details={
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "cell_offset": candidate.get("cell_offset", 0),
                "allocation_status": candidate.get("allocation_status", ""),
                "positive_size_free_cell": recovery_evidence.get("positive_size_free_cell", False),
                "parent_key_confidence": parent_confidence,
                "decoded_data_preview": decoded_data,
                "allocator_context": recovery_evidence.get("allocator_context", {}),
                "transaction_log_evidence": transaction_log_evidence,
                "recovery_evidence": recovery_evidence,
                "recovery_profile": recovery_profile,
                "recovery_identity_profile": recovery_identity_profile,
                "allocator_neighbor_context": recovery_evidence.get("allocator_neighbor_context", {}),
            },
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
                "source_viewer_locator": registry_record_source_viewer_locator(
                    source_path=str(path.resolve()),
                    source_hashes=source_hashes,
                    hive_name=path.name,
                    hive_hint=hive_hint_from_path(path),
                    key_path=parent_path,
                    value_name=str(candidate.get("name") or ""),
                    cell_offset=candidate.get("cell_offset", 0),
                    cell_relative_offset=candidate.get("cell_relative_offset", 0),
                    hbin_offset=candidate.get("hbin_offset", 0),
                    allocation_status=candidate.get("allocation_status", ""),
                    transaction_log_evidence=transaction_log_evidence,
                    deleted_or_recovered=True,
                ),
                "hive_name": path.name,
                "hive_hint": hive_hint_from_path(path),
                "parser_confidence": 0.54 if metadata.get("regf_valid") else 0.22,
                "evidence_strength": "registry-deleted-value-candidate",
                "registry_recovery_evidence": recovery_evidence,
                "registry_recovery_validation_profile": recovery_profile,
                "registry_recovery_identity_profile": recovery_identity_profile,
                "registry_recovery_reportability_decision": recovery_profile["reportability_decision"],
                "registry_transaction_log_evidence": dict(transaction_log_evidence),
                "registry_transaction_replay_profile": registry_transaction_replay_profile(
                    transaction_log_evidence,
                    dirty=bool(metadata.get("dirty")),
                ),
                "validation_required": True,
                "registry_validation_matrix": validation_matrix,
                "registry_report_grade_assessment": report_grade_assessment,
                "registry_report_citation_manifest": report_citation_manifest,
                "registry_report_citation_manifest_hash": report_citation_manifest["manifest_sha256"],
                "registry_native_depth_readiness_profile": registry_native_depth_readiness_profile(
                    family="deleted-cell",
                    artifact_scope="value-recovery-candidate",
                    details={
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "hive_name": path.name,
                        "hive_hint": hive_hint_from_path(path),
                        "cell_offset": candidate.get("cell_offset", 0),
                        "name": candidate.get("name", ""),
                        "allocation_status": candidate.get("allocation_status", ""),
                        "candidate_kind": "deleted-or-free-value-cell",
                        "parent_key_path_candidate": parent_path,
                        "decoded_data_preview": decoded_data,
                        "registry_recovery_evidence": recovery_evidence,
                        "registry_recovery_validation_profile": recovery_profile,
                        "registry_validation_matrix": validation_matrix,
                        "registry_report_grade_assessment": report_grade_assessment,
                        "registry_transaction_log_evidence": dict(transaction_log_evidence),
                    },
                ),
                "registry_analyst_review_profile": registry_analyst_review_profile(
                    artifact_type="registry-value-recovery-candidate",
                    category="deleted-cell",
                    source_format="registry-hive",
                    hive_name=path.name,
                    hive_hint=hive_hint_from_path(path),
                    key_path=parent_path,
                    name=str(candidate.get("name") or ""),
                    risk_flags=registry_cell_risk_flags(candidate),
                    validation_required=True,
                    transaction_log_evidence=transaction_log_evidence,
                    report_grade_assessment=report_grade_assessment,
                    recovery_profile=recovery_profile,
                    source_values={
                        "parent_key_path_candidate": parent_path,
                        "decoded_data_preview": decoded_data,
                        "cell_offset": candidate.get("cell_offset", 0),
                    },
                ),
                "core_accuracy_gates": core_accuracy_gates,
                "commercial_uplift_evidence": registry_commercial_uplift_evidence(
                    gap_ids=["#5"],
                    details={
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "cell_offset": candidate.get("cell_offset", 0),
                        "registry_validation_matrix": validation_matrix,
                        "registry_report_grade_assessment": report_grade_assessment,
                        "recovery_profile": recovery_profile,
                        "recovery_identity_profile": recovery_identity_profile,
                        "transaction_log_evidence": transaction_log_evidence,
                    },
                ),
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


def registry_recovery_evidence(
    candidate: Mapping[str, object],
    candidate_kind: str,
    *,
    path_confidence: str = "",
    recovered_path: str = "",
    parent_confidence: str = "",
    parent_path: str = "",
    decoded_data_present: bool = False,
    allocator_neighbor_context: Mapping[str, object] | None = None,
) -> dict[str, object]:
    allocation_status = str(candidate.get("allocation_status") or "")
    cell_size = int(candidate.get("cell_size") or 0)
    evidence_reasons: list[str] = []
    if allocation_status == "free-or-deleted-candidate":
        evidence_reasons.append("allocator:positive-size-free-cell")
    if str(candidate.get("cell_signature") or "") in {"nk", "vk"}:
        evidence_reasons.append(f"signature:{candidate.get('cell_signature')}")
    if recovered_path:
        evidence_reasons.append(f"path:{path_confidence or 'unknown'}")
    if parent_path:
        evidence_reasons.append(f"parent:{parent_confidence or 'unknown'}")
    if decoded_data_present:
        evidence_reasons.append("value-data:preview-decoded")
    allocator_context = {
        "profile_version": "registry-free-cell-allocator-context-v1",
        "allocation_status": allocation_status,
        "positive_size_free_cell": allocation_status == "free-or-deleted-candidate" and cell_size > 0,
        "cell_size": cell_size,
        "hbin_offset": int(candidate.get("hbin_offset") or 0),
        "cell_relative_offset": int(candidate.get("cell_relative_offset") or 0),
        "validation_status": (
            "free-cell-candidate-validation-required"
            if allocation_status == "free-or-deleted-candidate" and cell_size > 0
            else "allocator-state-not-confirmed"
        ),
        "reporting_constraint": (
            "A positive registry cell size marks an unallocated/free cell candidate, not a proven deletion. "
            "Use only with surrounding hbin context and independent offset validation."
        ),
    }
    neighbor_context = dict(allocator_neighbor_context or {})
    if neighbor_context:
        evidence_reasons.append("allocator:neighbor-context-recorded")
    allocator_context_hash = stable_registry_json_sha256(allocator_context)
    allocator_neighbor_context_hash = (
        stable_registry_json_sha256(neighbor_context) if neighbor_context else ""
    )
    return {
        "candidate_kind": candidate_kind,
        "recovery": build_recovery_record(
            candidate_kind,
            subtype=candidate_kind,
            confidence=path_confidence or "low",
            validation_status=(
                "partial"
                if allocation_status == "free-or-deleted-candidate" and cell_size > 0
                else "unverified"
            ),
            deletion_state="registry-free-cell-candidate",
            source_offset=candidate.get("cell_offset"),
            limitation=(
                "A positive-size free cell is an unallocated-cell candidate, "
                "not a proven deletion; requires surrounding hbin context and "
                "independent offset validation."
            ),
        ),
        "cell_kind": str(candidate.get("cell_kind") or ""),
        "cell_signature": str(candidate.get("cell_signature") or ""),
        "cell_offset": int(candidate.get("cell_offset") or 0),
        "cell_relative_offset": int(candidate.get("cell_relative_offset") or 0),
        "hbin_offset": int(candidate.get("hbin_offset") or 0),
        "cell_size": cell_size,
        "allocation_status": allocation_status,
        "positive_size_free_cell": allocation_status == "free-or-deleted-candidate" and cell_size > 0,
        "path_confidence": path_confidence,
        "recovered_path": recovered_path,
        "parent_confidence": parent_confidence,
        "parent_path": parent_path,
        "decoded_data_present": decoded_data_present,
        "allocator_context": allocator_context,
        "allocator_context_hash": allocator_context_hash,
        "allocator_neighbor_context": neighbor_context,
        "allocator_neighbor_context_hash": allocator_neighbor_context_hash,
        "validation_required": True,
        "evidence_reasons": sorted(set(evidence_reasons)),
    }


def registry_recovery_identity_profile(
    candidate: Mapping[str, object],
    recovery_evidence: Mapping[str, object],
    *,
    recovered_path: str = "",
    parent_path: str = "",
    parent_confidence: str = "",
    decoded_data_preview: str = "",
) -> dict[str, object]:
    cell_kind = str(candidate.get("cell_kind") or "")
    candidate_class = (
        "deleted-key-cell"
        if cell_kind == "key-node"
        else "deleted-value-cell"
        if cell_kind == "value"
        else "deleted-generic-cell"
    )
    identity = {
        "cell_offset": int(candidate.get("cell_offset") or 0),
        "cell_relative_offset": int(candidate.get("cell_relative_offset") or 0),
        "hbin_offset": int(candidate.get("hbin_offset") or 0),
        "cell_size": int(candidate.get("cell_size") or 0),
        "cell_kind": cell_kind,
        "cell_signature": str(candidate.get("cell_signature") or ""),
        "allocation_status": str(candidate.get("allocation_status") or ""),
        "candidate_class": candidate_class,
        "candidate_kind": str(recovery_evidence.get("candidate_kind") or ""),
        "name": str(candidate.get("name") or ""),
        "name_sha256": sha256_text(str(candidate.get("name") or "")) if candidate.get("name") else "",
        "value_type": str(candidate.get("value_type") or ""),
        "value_data_size": int(candidate.get("value_data_size") or 0),
        "value_data_offset": int(candidate.get("value_data_offset") or 0),
        "decoded_data_preview_sha256": sha256_text(decoded_data_preview) if decoded_data_preview else "",
        "key_path_candidate": recovered_path,
        "parent_key_path_candidate": parent_path,
        "parent_key_confidence": parent_confidence,
        "allocator_context_hash": str(recovery_evidence.get("allocator_context_hash") or ""),
        "allocator_neighbor_context_hash": str(recovery_evidence.get("allocator_neighbor_context_hash") or ""),
    }
    return {
        "profile_version": "registry-recovery-identity-profile-v1",
        "identity": identity,
        "identity_hash": stable_registry_json_sha256(identity),
        "allocator_context_hash": identity["allocator_context_hash"],
        "allocator_neighbor_context_hash": identity["allocator_neighbor_context_hash"],
        "commercial_diff_required_fields": [
            "cell_offset",
            "candidate_class",
            "cell_signature",
            "cell_size",
            "hbin_offset",
            "allocation_status",
            "name",
        ],
        "reporting_constraint": (
            "Treat this hash as a stable recovery-candidate identity only; it proves row consistency, "
            "not deletion truth, until an oracle/second-parser diff and transaction context are attached."
        ),
    }


def registry_allocator_neighbor_context(
    candidate: Mapping[str, object],
    candidates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    candidate_offset = int(candidate.get("cell_offset") or 0)
    ordered = sorted(
        (item for item in candidates if int(item.get("cell_offset") or 0) > 0),
        key=lambda item: int(item.get("cell_offset") or 0),
    )
    index = next(
        (idx for idx, item in enumerate(ordered) if int(item.get("cell_offset") or 0) == candidate_offset),
        -1,
    )
    previous_cell = ordered[index - 1] if index > 0 else None
    next_cell = ordered[index + 1] if index >= 0 and index + 1 < len(ordered) else None
    current_end = candidate_offset + int(candidate.get("cell_size") or 0)
    next_offset = int(next_cell.get("cell_offset") or 0) if next_cell is not None else 0
    gap_to_next = next_offset - current_end if next_offset else 0
    previous_offset = int(previous_cell.get("cell_offset") or 0) if previous_cell is not None else 0
    return {
        "profile_version": "registry-allocator-neighbor-context-v1",
        "candidate_cell_offset": candidate_offset,
        "candidate_hbin_offset": int(candidate.get("hbin_offset") or 0),
        "ordered_cell_index": index,
        "previous_cell": registry_neighbor_cell_summary(previous_cell),
        "next_cell": registry_neighbor_cell_summary(next_cell),
        "same_hbin_previous": bool(
            previous_cell is not None
            and int(previous_cell.get("hbin_offset") or 0) == int(candidate.get("hbin_offset") or 0)
        ),
        "same_hbin_next": bool(
            next_cell is not None
            and int(next_cell.get("hbin_offset") or 0) == int(candidate.get("hbin_offset") or 0)
        ),
        "gap_to_next_cell": gap_to_next,
        "previous_gap_to_candidate": candidate_offset
        - (previous_offset + int(previous_cell.get("cell_size") or 0))
        if previous_cell is not None
        else 0,
        "context_quality": "bounded-neighbor-cells-recorded" if previous_cell or next_cell else "no-neighbor-cells-in-scan-window",
        "validation_guidance": (
            "Use neighbor context to detect overwritten/slack false positives; it is not sufficient alone "
            "to prove deletion without known-answer or second-parser offset validation."
        ),
    }


def registry_neighbor_cell_summary(cell: Mapping[str, object] | None) -> dict[str, object]:
    if cell is None:
        return {}
    return {
        "cell_offset": int(cell.get("cell_offset") or 0),
        "cell_relative_offset": int(cell.get("cell_relative_offset") or 0),
        "hbin_offset": int(cell.get("hbin_offset") or 0),
        "cell_size": int(cell.get("cell_size") or 0),
        "cell_kind": str(cell.get("cell_kind") or ""),
        "cell_signature": str(cell.get("cell_signature") or ""),
        "allocation_status": str(cell.get("allocation_status") or ""),
        "name_sha256": sha256_text(str(cell.get("name") or "")) if cell.get("name") else "",
    }


def registry_recovery_validation_profile(
    candidate: Mapping[str, object],
    recovery_evidence: Mapping[str, object],
    candidate_kind: str,
    *,
    validation_checks: Sequence[Mapping[str, object]],
    transaction_log_evidence: Mapping[str, object] | None = None,
    recovery_identity_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    cell_kind = str(candidate.get("cell_kind") or "")
    signature = str(candidate.get("cell_signature") or "")
    failed_checks = [
        str(item.get("id"))
        for item in validation_checks
        if isinstance(item, Mapping) and not item.get("passed")
    ]
    required_checks = [
        "hive-allocator-positive-size-confirmation",
        "second-registry-parser-offset-confirmation",
        "transaction-log-replay-or-explicit-absence",
        "known-answer-deleted-cell-fixture-match",
    ]
    if cell_kind == "key-node":
        candidate_class = "deleted-key-cell"
        required_checks.extend(
            [
                "parent-chain-and-root-reachability-review",
                "last-write-timestamp-plausibility-review",
            ]
        )
    elif cell_kind == "value":
        candidate_class = "deleted-value-cell"
        required_checks.extend(
            [
                "parent-key-link-confirmation",
                "value-data-allocation-and-type-review",
            ]
        )
    else:
        candidate_class = "deleted-generic-cell"
        required_checks.append("manual-cell-structure-review")
    reportability_decision = registry_recovery_reportability_decision(
        candidate_kind,
        recovery_evidence,
        transaction_log_evidence or {},
        failed_validation_checks=failed_checks,
        required_independent_checks=required_checks,
    )
    return {
        "profile_version": "registry-deleted-cell-validation-v1",
        "candidate_class": candidate_class,
        "candidate_kind": candidate_kind,
        "cell_kind": cell_kind,
        "cell_signature": signature,
        "cell_offset": int(candidate.get("cell_offset") or 0),
        "cell_relative_offset": int(candidate.get("cell_relative_offset") or 0),
        "allocation_status": str(candidate.get("allocation_status") or ""),
        "positive_size_free_cell": bool(recovery_evidence.get("positive_size_free_cell")),
        "signature_confirmed": signature in {"nk", "vk"},
        "path_confidence": str(recovery_evidence.get("path_confidence") or ""),
        "parent_confidence": str(recovery_evidence.get("parent_confidence") or ""),
        "decoded_data_present": bool(recovery_evidence.get("decoded_data_present")),
        "allocator_neighbor_context_present": bool(recovery_evidence.get("allocator_neighbor_context")),
        "allocator_neighbor_context": dict(recovery_evidence.get("allocator_neighbor_context") or {})
        if isinstance(recovery_evidence.get("allocator_neighbor_context"), Mapping)
        else {},
        "allocator_context_hash": str(recovery_evidence.get("allocator_context_hash") or ""),
        "allocator_neighbor_context_hash": str(recovery_evidence.get("allocator_neighbor_context_hash") or ""),
        "recovery_identity_profile": dict(recovery_identity_profile or {}),
        "recovery_identity_hash": str((recovery_identity_profile or {}).get("identity_hash") or ""),
        "failed_validation_checks": failed_checks,
        "independent_validation_status": "required",
        "false_positive_controls": [
            "positive-size-free-cell-confirmation",
            "cell-signature-confirmation",
            "allocator-context-review",
            "allocator-neighbor-context-review",
            "parent-or-path-link-review",
            "second-parser-offset-diff",
            "known-answer-deleted-cell-corpus",
        ],
        "false_positive_risk": "high" if failed_checks else "medium-validation-required",
        "analyst_wording": (
            "Report as a deleted/free registry cell candidate only; do not state that the key/value was deleted "
            "until independent offset, allocator, transaction-log, and corpus validation pass."
        ),
        "reportable_without_secondary_validation": False,
        "reportability_decision": reportability_decision,
        "required_independent_checks": sorted(set(required_checks)),
        "known_answer_corpus_requirement": (
            "Validate deleted/free registry nk/vk candidates against allocated, deleted, overwritten, "
            "and false-positive hive fixtures before using them as standalone testimony."
        ),
    }


def registry_recovery_reportability_decision(
    candidate_kind: str,
    recovery_evidence: Mapping[str, object],
    transaction_log_evidence: Mapping[str, object],
    *,
    failed_validation_checks: Sequence[str],
    required_independent_checks: Sequence[str],
) -> dict[str, object]:
    transaction_status = str(transaction_log_evidence.get("status") or "unknown")
    blockers = [
        "deleted-or-free-cell-independent-validation-required",
        "second-parser-cell-offset-confirmation-required",
        "hive-allocator-state-validation-required",
        "known-answer-deleted-cell-fixture-required",
    ]
    if transaction_status == "present-not-replayed":
        blockers.append("transaction-log-present-not-replayed")
    elif transaction_status == "absent":
        blockers.append("transaction-log-absent-or-not-supplied")
    else:
        blockers.append("transaction-log-context-unknown")
    blockers.extend(f"validation-check-failed:{check}" for check in failed_validation_checks)
    return {
        "profile_version": "registry-recovery-reportability-decision-v1",
        "candidate_kind": candidate_kind,
        "decision": "do-not-report-as-fact",
        "allowed_use": "triage-pivot-only",
        "blockers": sorted(set(blockers)),
        "transaction_log_status": transaction_status,
        "allocator_status": str(recovery_evidence.get("allocation_status") or ""),
        "positive_size_free_cell": bool(recovery_evidence.get("positive_size_free_cell")),
        "required_before_report": sorted(set(str(check) for check in required_independent_checks)),
        "analyst_wording": (
            "Describe this row as a deleted/free registry cell candidate until offset, allocator state, "
            "transaction context, and second-parser evidence are independently confirmed."
        ),
    }


def registry_core_accuracy_gates(
    *,
    gap_ids: Sequence[str],
    validation_matrix: Sequence[Mapping[str, object]],
    details: Mapping[str, object],
) -> list[dict[str, object]]:
    matrix_ids = {
        str(item.get("id"))
        for item in validation_matrix
        if isinstance(item, Mapping) and item.get("passed")
    }
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"cell_offset:{details.get('cell_offset', '')}",
    ]
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    gates: list[dict[str, object]] = []
    if "#4" in gap_ids:
        item4_checks: list[str] = []
        key_tree_diff = (
            details.get("registry_key_tree_diff")
            if isinstance(details.get("registry_key_tree_diff"), Mapping)
            else {}
        )
        if "root-reachability" in matrix_ids:
            item4_checks.append("root-cell reachability")
        if "child-parent-backlinks" in matrix_ids or details.get("parent_link_consistency"):
            item4_checks.append("parent-child backlink consistency")
        if "value-list-resolution" in matrix_ids or details.get("value_list_offset"):
            item4_checks.append("value-list ownership")
        if details.get("last_written_at"):
            item4_checks.append("last-write timestamp preservation")
        if key_tree_diff.get("status") == "pass":
            item4_checks.append("trusted registry key-tree diff pass")
        item4_checks.append("transaction-log replay disclosure")
        gates.append(build_accuracy_gate(4, satisfied_checks=item4_checks, evidence_refs=evidence_refs))
    if "#5" in gap_ids:
        item5_checks: list[str] = []
        deleted_cell_diff = (
            details.get("registry_deleted_cell_diff")
            if isinstance(details.get("registry_deleted_cell_diff"), Mapping)
            else {}
        )
        if details.get("positive_size_free_cell") or "deleted-value-cell" in matrix_ids or "deleted-key-cell" in matrix_ids:
            item5_checks.append("positive-size free-cell validation")
        if details.get("parent_key_confidence") == "key-value-list" or "parent-key-link" in matrix_ids:
            item5_checks.append("parent-key confirmation")
        if details.get("decoded_data_preview") or "value-type-present" in matrix_ids:
            item5_checks.append("data-type and data-length plausibility")
        if details.get("recovery_evidence"):
            item5_checks.append("allocator-state evidence")
        if isinstance(details.get("allocator_context"), Mapping):
            item5_checks.append("allocator reportability context")
        if isinstance(details.get("allocator_neighbor_context"), Mapping) and details["allocator_neighbor_context"]:
            item5_checks.append("allocator neighbor context")
        recovery_identity_profile = (
            details.get("recovery_identity_profile")
            if isinstance(details.get("recovery_identity_profile"), Mapping)
            else {}
        )
        if recovery_identity_profile.get("identity_hash"):
            item5_checks.append("stable recovery identity hash")
        if isinstance(details.get("transaction_log_evidence"), Mapping) and details["transaction_log_evidence"].get("status"):
            item5_checks.append("transaction-log context disclosure")
        if details.get("recovery_profile"):
            item5_checks.append("reportability blocked until independent confirmation")
        if deleted_cell_diff.get("status") == "pass":
            item5_checks.append("trusted deleted-cell offset diff pass")
        gates.append(build_accuracy_gate(5, satisfied_checks=item5_checks, evidence_refs=evidence_refs))
    return gates


def registry_commercial_uplift_evidence(
    *,
    gap_ids: Sequence[str],
    details: Mapping[str, object],
) -> dict[str, object]:
    validation_matrix = (
        details.get("registry_validation_matrix")
        if isinstance(details.get("registry_validation_matrix"), list)
        else []
    )
    report_grade = (
        details.get("registry_report_grade_assessment")
        if isinstance(details.get("registry_report_grade_assessment"), Mapping)
        else {}
    )
    recovery_profile = (
        details.get("recovery_profile")
        if isinstance(details.get("recovery_profile"), Mapping)
        else {}
    )
    recovery_identity_profile = (
        details.get("recovery_identity_profile")
        if isinstance(details.get("recovery_identity_profile"), Mapping)
        else {}
    )
    transaction_log_evidence = (
        details.get("transaction_log_evidence")
        if isinstance(details.get("transaction_log_evidence"), Mapping)
        else {}
    )
    replay_validation_profile = (
        transaction_log_evidence.get("replay_validation_profile")
        if isinstance(transaction_log_evidence.get("replay_validation_profile"), Mapping)
        else {}
    )
    key_tree_diff = (
        details.get("registry_key_tree_diff")
        if isinstance(details.get("registry_key_tree_diff"), Mapping)
        else {}
    )
    deleted_cell_diff = (
        details.get("registry_deleted_cell_diff")
        if isinstance(details.get("registry_deleted_cell_diff"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    passed_matrix = [
        str(item.get("id"))
        for item in validation_matrix
        if isinstance(item, Mapping) and item.get("passed")
    ]
    failed_matrix = [
        str(item.get("id"))
        for item in validation_matrix
        if isinstance(item, Mapping) and not item.get("passed")
    ]
    item_numbers = [int(gap_id.lstrip("#")) for gap_id in gap_ids if gap_id.lstrip("#").isdigit()]
    return {
        "batch_id": "commercial-uplift-001-005",
        "item_numbers": item_numbers,
        "implementation_track": "native-parser-depth",
        "objective": (
            "Expose registry key-tree and deleted-cell validation evidence directly on native rows so "
            "analysts can distinguish allocated key reconstruction from recovery candidates."
        ),
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"cell_offset:{details.get('cell_offset', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
        ],
        "passed_validation_matrix_ids": passed_matrix,
        "failed_validation_matrix_ids": failed_matrix,
        "recovery_profile_version": str(recovery_profile.get("profile_version") or ""),
        "recovery_identity_hash": str(recovery_identity_profile.get("identity_hash") or ""),
        "recovery_identity_profile_version": str(recovery_identity_profile.get("profile_version") or ""),
        "allocator_context_hash": str(recovery_identity_profile.get("allocator_context_hash") or ""),
        "allocator_neighbor_context_hash": str(
            recovery_identity_profile.get("allocator_neighbor_context_hash") or ""
        ),
        "recovery_reportability_decision": dict(recovery_profile.get("reportability_decision") or {}),
        "transaction_log_status": str(transaction_log_evidence.get("status") or ""),
        "transaction_replay_validation": {
            "status": str(replay_validation_profile.get("validation_status") or "not-attached"),
            "profile_hash": str(transaction_log_evidence.get("replay_validation_profile_hash") or ""),
            "recognized_replay_input_count": int(
                replay_validation_profile.get("recognized_replay_input_count") or 0
            ),
            "complete_log_pair_present": bool(replay_validation_profile.get("complete_log_pair_present")),
            "ready_for_internal_replay_preflight": bool(
                replay_validation_profile.get("ready_for_internal_replay_preflight")
            ),
            "blockers": list(replay_validation_profile.get("blockers") or []),
        },
        "key_tree_diff": {
            "status": str(key_tree_diff.get("status") or "not-attached"),
            "trusted_tool": str(key_tree_diff.get("trusted_tool") or ""),
            "matched_count": int(key_tree_diff.get("matched_count") or 0),
            "mismatch_count": int(key_tree_diff.get("mismatch_count") or 0),
            "missing_in_trusted_count": int(key_tree_diff.get("missing_in_trusted_count") or 0),
            "extra_in_trusted_count": int(key_tree_diff.get("extra_in_trusted_count") or 0),
            "commercial_grade_evidence": bool(key_tree_diff.get("commercial_grade_evidence")),
        },
        "deleted_cell_diff": {
            "status": str(deleted_cell_diff.get("status") or "not-attached"),
            "oracle": str(deleted_cell_diff.get("oracle") or ""),
            "matched_count": int(deleted_cell_diff.get("matched_count") or 0),
            "mismatch_count": int(deleted_cell_diff.get("mismatch_count") or 0),
            "missing_in_oracle_count": int(deleted_cell_diff.get("missing_in_oracle_count") or 0),
            "extra_in_oracle_count": int(deleted_cell_diff.get("extra_in_oracle_count") or 0),
            "commercial_grade_evidence": bool(deleted_cell_diff.get("commercial_grade_evidence")),
        },
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "commercial_blocker_analysis": registry_commercial_blocker_analysis(
            list(report_grade.get("blockers") or [])
        ),
        "large_data_controls": {
            "bounded_cell_scan_bytes": MAX_HIVE_CELL_SCAN_BYTES,
            "bounded_string_scan_bytes": MAX_HIVE_STRING_SCAN_BYTES,
            "cell_record_limit": MAX_HIVE_CELL_RECORDS,
            "max_cell_size_bytes": MAX_HIVE_CELL_SIZE,
            "reader": "bounded-hbin-cell-scan",
            "transaction_log_replay_required_for_commercial_claims": True,
        },
        "next_internal_step": (
            "Add transaction-log replay detection, full binary value decoding, and second-parser offset "
            "diff fixtures before removing registry commercial blockers."
        ),
        "external_evidence_required": True,
    }


def registry_native_depth_readiness_profile(
    *,
    family: str,
    artifact_scope: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    validation_matrix = (
        details.get("registry_validation_matrix")
        if isinstance(details.get("registry_validation_matrix"), list)
        else []
    )
    report_grade = (
        details.get("registry_report_grade_assessment")
        if isinstance(details.get("registry_report_grade_assessment"), Mapping)
        else {}
    )
    transaction_log_evidence = (
        details.get("transaction_log_evidence")
        if isinstance(details.get("transaction_log_evidence"), Mapping)
        else details.get("registry_transaction_log_evidence")
        if isinstance(details.get("registry_transaction_log_evidence"), Mapping)
        else {}
    )
    recovery_profile = (
        details.get("recovery_profile")
        if isinstance(details.get("recovery_profile"), Mapping)
        else details.get("registry_recovery_validation_profile")
        if isinstance(details.get("registry_recovery_validation_profile"), Mapping)
        else {}
    )
    replay_validation_profile = (
        transaction_log_evidence.get("replay_validation_profile")
        if isinstance(transaction_log_evidence.get("replay_validation_profile"), Mapping)
        else {}
    )
    decoded_components = registry_depth_components(family, details, transaction_log_evidence, recovery_profile)
    total_components = len(decoded_components)
    decoded_count = sum(1 for value in decoded_components.values() if value)
    blockers = sorted(
        set(str(item) for item in report_grade.get("blockers") or [])
        | set(REGISTRY_REPORT_GRADE_BLOCKERS)
    )
    return {
        "profile_version": "registry-native-depth-readiness-v1",
        "parser_version": PARSER_VERSION,
        "family": family,
        "artifact_scope": artifact_scope,
        "commercial_grade_ready": False,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "status": "triage-depth-improved-report-grade-blocked",
        "depth_score": round(decoded_count / total_components, 3) if total_components else 0.0,
        "decoded_component_count": decoded_count,
        "total_component_count": total_components,
        "decoded_components": decoded_components,
        "validation_summary": {
            "passed_ids": [
                str(item.get("id"))
                for item in validation_matrix
                if isinstance(item, Mapping) and item.get("passed")
            ],
            "failed_ids": [
                str(item.get("id"))
                for item in validation_matrix
                if isinstance(item, Mapping) and not item.get("passed")
            ],
            "transaction_log_status": str(transaction_log_evidence.get("status") or "unknown"),
            "transaction_log_replay_applied": bool(transaction_log_evidence.get("transaction_log_replay_applied")),
            "transaction_replay_validation_status": str(
                replay_validation_profile.get("validation_status") or ""
            ),
            "transaction_replay_validation_hash": str(
                transaction_log_evidence.get("replay_validation_profile_hash") or ""
            ),
            "recovery_validation_status": str(recovery_profile.get("independent_validation_status") or ""),
        },
        "source_citation_requirements": [
            "source_path",
            "source_sha256",
            "parser_version",
            "hive_name",
            "cell_offset",
            "key_path_or_value_name",
            "transaction_log_status",
            "validation_status",
        ],
        "source_provenance": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": (
                details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
            ).get("sha256", ""),
            "hive_name": str(details.get("hive_name") or ""),
            "hive_hint": str(details.get("hive_hint") or ""),
            "cell_offset": details.get("cell_offset", ""),
            "key_path": str(details.get("key_path") or details.get("key_path_candidate") or ""),
            "value_name": str(details.get("name") or ""),
        },
        "registry_subkey_list_profile": dict(details.get("registry_subkey_list_profile") or {})
        if isinstance(details.get("registry_subkey_list_profile"), Mapping)
        else {},
        "registry_value_list_profile": dict(details.get("registry_value_list_profile") or {})
        if isinstance(details.get("registry_value_list_profile"), Mapping)
        else {},
        "registry_key_tree_reconstruction_profile": dict(details.get("registry_key_tree_reconstruction_profile") or {})
        if isinstance(details.get("registry_key_tree_reconstruction_profile"), Mapping)
        else {},
        "blockers": blockers,
        "next_internal_actions": [
            "Implement LOG1/LOG2 transaction replay or attach explicit absence proof.",
            "Diff key paths/value ownership/deleted-cell offsets against RECmd or Registry Explorer output.",
            "Validate deleted/free cells against known-answer allocated, deleted, overwritten, and false-positive hive fixtures.",
            "Decode binary value/security descriptor structures before report-grade claims.",
        ],
        "analyst_warning": (
            "Use registry rows as source-linked triage/review pivots until transaction replay, trusted parser diff, "
            "and deleted-cell corpus evidence are attached."
        ),
    }


def registry_depth_components(
    family: str,
    details: Mapping[str, object],
    transaction_log_evidence: Mapping[str, object],
    recovery_profile: Mapping[str, object],
) -> dict[str, bool]:
    if family == "key-tree":
        subkey_profile = (
            details.get("registry_subkey_list_profile")
            if isinstance(details.get("registry_subkey_list_profile"), Mapping)
            else {}
        )
        value_profile = (
            details.get("registry_value_list_profile")
            if isinstance(details.get("registry_value_list_profile"), Mapping)
            else {}
        )
        return {
            "regf_header": bool(details.get("registry_native_capabilities", {}).get("regf_header", False))
            if isinstance(details.get("registry_native_capabilities"), Mapping)
            else True,
            "hbin_cell_walk": True,
            "nk_key_cell_decode": bool(details.get("name") or details.get("key_path")),
            "parent_chain_path_reconstruction": bool(details.get("key_path_confidence") == "parent-chain"),
            "subkey_list_linking": subkey_profile.get("list_validation_status") == "resolved"
            or bool(details.get("subkey_cell_offsets") is not None),
            "value_list_linking": str(value_profile.get("status") or "") in {"not-declared", "resolved"}
            or bool(details.get("value_cell_offsets") is not None),
            "transaction_log_context_recorded": bool(transaction_log_evidence.get("status")),
            "transaction_log_replay": bool(transaction_log_evidence.get("transaction_log_replay_applied")),
            "trusted_key_tree_diff": False,
        }
    return {
        "regf_header": True,
        "hbin_cell_walk": True,
        "deleted_free_cell_candidate_labeling": bool(details.get("allocation_status") == "free-or-deleted-candidate"),
        "cell_signature_confirmed": str(details.get("candidate_kind") or "").startswith("deleted-or-free")
        or bool((details.get("registry_recovery_evidence") or {}).get("cell_signature"))
        if isinstance(details.get("registry_recovery_evidence"), Mapping)
        else bool(details.get("candidate_kind")),
        "parent_or_path_context": bool(details.get("parent_key_path_candidate") or details.get("key_path_candidate")),
        "inline_value_preview": bool(details.get("decoded_data_preview")),
        "recovery_reportability_decision": bool(recovery_profile.get("reportability_decision")),
        "transaction_log_context_recorded": bool(transaction_log_evidence.get("status")),
        "transaction_log_replay": bool(transaction_log_evidence.get("transaction_log_replay_applied")),
        "trusted_deleted_cell_diff": False,
    }


def registry_commercial_blocker_analysis(blockers: Sequence[object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for raw in blockers:
        blocker = str(raw)
        if "independent" in blocker or "corpus" in blocker or "validation-required" in blocker:
            category = "external_validation"
            owner = "operator-or-independent-validator"
            next_step = "Attach real hive corpus, transaction-log context, second-parser diff output, and reviewer signoff."
        elif "transaction-log" in blocker:
            category = "internal_implementation"
            owner = "engineering"
            next_step = "Implement LOG1/LOG2 transaction-log discovery/replay evidence and fixture-backed pass/fail checks."
        elif "binary-value" in blocker or "security-descriptor" in blocker:
            category = "internal_implementation"
            owner = "engineering"
            next_step = "Decode the native value/security structure with offset-preserving tests before changing reportability."
        elif "large" in blocker or "bounded" in blocker:
            category = "large_data_proof"
            owner = "engineering-plus-benchmark-lab"
            next_step = "Run large hive benchmark corpus with memory and cursor evidence."
        else:
            category = "internal_implementation"
            owner = "engineering"
            next_step = "Reduce parser-depth blocker with source-offset-preserving implementation and fixture coverage."
        rows.append(
            {
                "blocker": blocker,
                "category": category,
                "owner": owner,
                "next_step": next_step,
            }
        )
    return rows


def build_registry_key_tree_diff(
    rapid_nodes: Sequence[Mapping[str, object]],
    trusted_nodes: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    """Compare native registry key-tree rows against a trusted parser or exported .reg view."""

    tool_name = str(trusted_tool or "").strip()
    rapid_by_path = {
        key: normalized
        for node in rapid_nodes
        for key, normalized in [_normalize_registry_key_tree_node(node)]
        if key
    }
    trusted_by_path = {
        key: normalized
        for node in trusted_nodes
        for key, normalized in [_normalize_registry_key_tree_node(node)]
        if key
    }
    missing_in_trusted = sorted(path for path in rapid_by_path if path not in trusted_by_path)
    extra_in_trusted = sorted(path for path in trusted_by_path if path not in rapid_by_path)
    mismatches: list[dict[str, object]] = []
    matched_count = 0
    for key in sorted(set(rapid_by_path) & set(trusted_by_path)):
        rapid = rapid_by_path[key]
        trusted = trusted_by_path[key]
        field_diffs = []
        for field in (
            "cell_offset",
            "parent_cell_offset",
            "subkey_names",
            "value_names",
            "linked_subkey_count",
            "linked_value_count",
            "last_written_at",
            "root_reachable",
            "parent_link_consistency",
        ):
            left = rapid.get(field, "")
            right = trusted.get(field, "")
            if left or right:
                if left != right:
                    field_diffs.append({"field": field, "rapid": left, "trusted": right})
        if field_diffs:
            mismatches.append({"key_path": key, "field_diffs": field_diffs})
        else:
            matched_count += 1

    status = "pass"
    if not tool_name or not rapid_by_path or not trusted_by_path:
        status = "not-enough-evidence"
    elif missing_in_trusted or extra_in_trusted or mismatches:
        status = "diffs-present"
    normalized_tool = re.sub(r"[^a-z0-9]+", "", tool_name.lower())
    trusted_tool_recognized = any(hint in normalized_tool for hint in REGISTRY_TRUSTED_TOOL_HINTS)
    return {
        "profile_version": "registry-key-tree-diff-v1",
        "trusted_tool": tool_name,
        "trusted_tool_recognized": trusted_tool_recognized,
        "compare_fields": [
            "key_path",
            "cell_offset",
            "parent_cell_offset",
            "subkey_names",
            "value_names",
            "linked_subkey_count",
            "linked_value_count",
            "last_written_at",
            "root_reachable",
            "parent_link_consistency",
        ],
        "rapid_node_count": len(rapid_by_path),
        "trusted_node_count": len(trusted_by_path),
        "matched_count": matched_count,
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing_in_trusted),
        "extra_in_trusted_count": len(extra_in_trusted),
        "status": status,
        "commercial_grade_evidence": status == "pass" and trusted_tool_recognized,
        "missing_in_trusted": missing_in_trusted[:100],
        "extra_in_trusted": extra_in_trusted[:100],
        "mismatches": mismatches[:100],
        "reportability_decision": {
            "decision": "key-tree-diff-passed" if status == "pass" else "do-not-use-native-key-tree-as-final",
            "allowed_use": (
                "support report-grade registry key-tree assertions with attached transaction-log/reviewer evidence"
                if status == "pass" and trusted_tool_recognized
                else "triage-only key-tree pivot until trusted key-tree diff is clean"
            ),
            "blockers": [] if status == "pass" and trusted_tool_recognized else ["registry-key-tree-cross-tool-diff-required"],
        },
    }


def build_registry_deleted_cell_diff(
    rapid_candidates: Sequence[Mapping[str, object]],
    oracle_candidates: Sequence[Mapping[str, object]],
    *,
    oracle: str,
) -> dict[str, object]:
    """Compare deleted/free registry cell candidates with a labeled corpus or second parser."""

    oracle_name = str(oracle or "").strip()
    compare_fields = [
        "candidate_class",
        "cell_signature",
        "cell_size",
        "hbin_offset",
        "allocation_status",
        "name",
        "value_type",
        "value_data_size",
        "data_preview_sha256",
        "parent_key_path",
        "parent_key_confidence",
        "allocator_context_hash",
        "allocator_neighbor_context_hash",
        "recovery_identity_hash",
    ]
    required_commercial_fields = [
        "candidate_class",
        "cell_signature",
        "cell_size",
        "hbin_offset",
        "allocation_status",
        "name",
    ]
    rapid_by_offset = {
        key: normalized
        for candidate in rapid_candidates
        for key, normalized in [_normalize_registry_deleted_cell_candidate(candidate)]
        if key
    }
    oracle_by_offset = {
        key: normalized
        for candidate in oracle_candidates
        for key, normalized in [_normalize_registry_deleted_cell_candidate(candidate)]
        if key
    }
    missing_in_oracle = sorted(key for key in rapid_by_offset if key not in oracle_by_offset)
    extra_in_oracle = sorted(key for key in oracle_by_offset if key not in rapid_by_offset)
    mismatches: list[dict[str, object]] = []
    matched_count = 0
    for key in sorted(set(rapid_by_offset) & set(oracle_by_offset)):
        rapid = rapid_by_offset[key]
        oracle_row = oracle_by_offset[key]
        field_diffs = []
        for field in compare_fields:
            left = rapid.get(field, "")
            right = oracle_row.get(field, "")
            if left or right:
                if left != right:
                    field_diffs.append({"field": field, "rapid": left, "oracle": right})
        if field_diffs:
            mismatches.append({"cell_offset": key, "field_diffs": field_diffs})
        else:
            matched_count += 1

    status = "pass"
    if not oracle_name or not rapid_by_offset or not oracle_by_offset:
        status = "not-enough-evidence"
    elif missing_in_oracle or extra_in_oracle or mismatches:
        status = "diffs-present"
    recognized_oracle = bool(re.search(r"(hand|labeled|oracle|regripper|registry|recmd|python)", oracle_name, re.IGNORECASE))
    rapid_present_fields = sorted(
        field for field in compare_fields if any(row.get(field, "") for row in rapid_by_offset.values())
    )
    oracle_present_fields = sorted(
        field for field in compare_fields if any(row.get(field, "") for row in oracle_by_offset.values())
    )
    missing_oracle_required_fields = [
        field
        for field in required_commercial_fields
        if any(row.get(field, "") for row in rapid_by_offset.values())
        and not any(row.get(field, "") for row in oracle_by_offset.values())
    ]
    commercial_grade_evidence = (
        status == "pass"
        and recognized_oracle
        and not missing_oracle_required_fields
    )
    blockers = []
    if not commercial_grade_evidence:
        blockers.append("registry-deleted-cell-cross-tool-diff-required")
    if missing_oracle_required_fields:
        blockers.append("registry-deleted-cell-oracle-field-coverage-required")
    return {
        "profile_version": "registry-deleted-cell-diff-v1",
        "oracle": oracle_name,
        "oracle_recognized": recognized_oracle,
        "compare_fields": ["cell_offset", *compare_fields],
        "required_commercial_fields": ["cell_offset", *required_commercial_fields],
        "field_coverage": {
            "rapid_present_fields": rapid_present_fields,
            "oracle_present_fields": oracle_present_fields,
            "missing_oracle_required_fields": missing_oracle_required_fields,
        },
        "rapid_candidate_count": len(rapid_by_offset),
        "oracle_candidate_count": len(oracle_by_offset),
        "matched_count": matched_count,
        "mismatch_count": len(mismatches),
        "missing_in_oracle_count": len(missing_in_oracle),
        "extra_in_oracle_count": len(extra_in_oracle),
        "status": status,
        "commercial_grade_evidence": commercial_grade_evidence,
        "missing_in_oracle": missing_in_oracle[:100],
        "extra_in_oracle": extra_in_oracle[:100],
        "mismatches": mismatches[:100],
        "reportability_decision": {
            "decision": "deleted-cell-diff-passed" if commercial_grade_evidence else "do-not-report-deleted-cell-as-fact",
            "allowed_use": (
                "support report-grade deleted-cell assertions with attached transaction-log/reviewer evidence"
                if commercial_grade_evidence
                else "triage-only deleted-cell pivot until offset oracle diff is clean"
            ),
            "blockers": blockers,
        },
    }


def _normalize_registry_key_tree_node(node: Mapping[str, object]) -> tuple[str, dict[str, str]]:
    node = _registry_row_payload(node)
    citation_manifest = node.get("registry_report_citation_manifest")
    row_identity = (
        citation_manifest.get("row_identity")
        if isinstance(citation_manifest, Mapping) and isinstance(citation_manifest.get("row_identity"), Mapping)
        else {}
    )
    relationships = (
        node.get("registry_key_tree_relationships")
        if isinstance(node.get("registry_key_tree_relationships"), Mapping)
        else {}
    )
    reconstruction = (
        node.get("registry_key_tree_reconstruction_profile")
        if isinstance(node.get("registry_key_tree_reconstruction_profile"), Mapping)
        else {}
    )
    key_path = str(node.get("key_path") or node.get("path") or node.get("key") or "").strip()
    if not key_path and row_identity:
        key_path = str(row_identity.get("key_path") or row_identity.get("key") or "").strip()
    if not key_path:
        return "", {}
    values = _normalize_registry_name_list(node.get("value_names") or row_identity.get("value_names"))
    subkeys = _normalize_registry_name_list(node.get("subkey_names") or row_identity.get("subkey_names"))
    cell_offset = (
        node.get("cell_offset")
        or row_identity.get("cell_offset")
        or node.get("offset")
        or row_identity.get("offset")
        or ""
    )
    parent_cell_offset = (
        node.get("parent_cell_offset")
        or row_identity.get("parent_cell_offset")
        or relationships.get("parent_cell_offset")
        or node.get("parent_offset")
        or ""
    )
    linked_subkey_count = (
        node.get("linked_subkey_count")
        or row_identity.get("linked_subkey_count")
        or reconstruction.get("decoded_subkey_count")
        or ""
    )
    linked_value_count = (
        node.get("linked_value_count")
        or row_identity.get("linked_value_count")
        or reconstruction.get("decoded_value_count")
        or ""
    )
    root_reachable = node.get("root_reachable", row_identity.get("root_reachable", relationships.get("root_reachable", True)))
    parent_link_consistency = node.get(
        "parent_link_consistency",
        row_identity.get("parent_link_consistency", relationships.get("parent_link_consistency", "")),
    )
    return normalize_registry_key_path(key_path), {
        "key_path": normalize_registry_key_path(key_path),
        "cell_offset": _normalize_registry_numeric_string(str(cell_offset)) if str(cell_offset) else "",
        "parent_cell_offset": _normalize_registry_numeric_string(str(parent_cell_offset)) if str(parent_cell_offset) else "",
        "subkey_names": "|".join(sorted(subkeys, key=str.lower)),
        "value_names": "|".join(sorted(values, key=str.lower)),
        "linked_subkey_count": str(linked_subkey_count) if str(linked_subkey_count) else "",
        "linked_value_count": str(linked_value_count) if str(linked_value_count) else "",
        "last_written_at": str(node.get("last_written_at") or node.get("last_write_time") or ""),
        "root_reachable": _normalize_registry_bool_string(root_reachable, default=True),
        "parent_link_consistency": _normalize_registry_bool_string(parent_link_consistency, default=None),
    }


def _normalize_registry_name_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [str(item) for item in value if str(item)]
    return []


def _normalize_registry_bool_string(value: object, *, default: bool | None) -> str:
    if value is None or value == "":
        if default is None:
            return ""
        return str(default).lower()
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return "true"
        if lowered in {"false", "0", "no", "n"}:
            return "false"
    return str(bool(value)).lower()


def _normalize_registry_deleted_cell_candidate(candidate: Mapping[str, object]) -> tuple[str, dict[str, str]]:
    candidate = _registry_row_payload(candidate)
    citation_manifest = candidate.get("registry_report_citation_manifest")
    row_identity = (
        citation_manifest.get("row_identity")
        if isinstance(citation_manifest, Mapping) and isinstance(citation_manifest.get("row_identity"), Mapping)
        else {}
    )
    recovery_profile = (
        candidate.get("registry_recovery_validation_profile")
        if isinstance(candidate.get("registry_recovery_validation_profile"), Mapping)
        else {}
    )
    recovery_evidence = (
        candidate.get("registry_recovery_evidence")
        if isinstance(candidate.get("registry_recovery_evidence"), Mapping)
        else {}
    )
    recovery_identity = (
        candidate.get("registry_recovery_identity_profile")
        if isinstance(candidate.get("registry_recovery_identity_profile"), Mapping)
        else recovery_profile.get("recovery_identity_profile")
        if isinstance(recovery_profile.get("recovery_identity_profile"), Mapping)
        else {}
    )
    recovery_identity_values = (
        recovery_identity.get("identity")
        if isinstance(recovery_identity.get("identity"), Mapping)
        else {}
    )
    offset = str(
        candidate.get("cell_offset")
        or row_identity.get("cell_offset")
        or recovery_identity_values.get("cell_offset")
        or candidate.get("offset")
        or candidate.get("byte_offset")
        or ""
    ).strip()
    if not offset:
        return "", {}
    key = _normalize_registry_numeric_string(offset)
    data_preview = str(candidate.get("decoded_data_preview") or candidate.get("data_preview") or "")
    data_preview_sha256 = str(
        row_identity.get("decoded_data_preview_sha256")
        or recovery_identity_values.get("decoded_data_preview_sha256")
        or candidate.get("decoded_data_preview_sha256")
        or candidate.get("data_preview_sha256")
        or ""
    )
    if not data_preview_sha256 and data_preview:
        data_preview_sha256 = hashlib.sha256(data_preview.encode("utf-8", errors="replace")).hexdigest()
    candidate_class = str(
        candidate.get("candidate_class")
        or recovery_profile.get("candidate_class")
        or row_identity.get("candidate_class")
        or recovery_identity_values.get("candidate_class")
        or candidate.get("candidate_kind")
        or row_identity.get("candidate_kind")
        or candidate.get("cell_kind")
        or ""
    )
    if candidate_class == "deleted-or-free-value-cell":
        candidate_class = "deleted-value-cell"
    elif candidate_class == "deleted-or-free-key-cell":
        candidate_class = "deleted-key-cell"
    parent_key_path = str(
        candidate.get("parent_key_path_candidate")
        or row_identity.get("parent_key_path_candidate")
        or recovery_identity_values.get("parent_key_path_candidate")
        or candidate.get("parent_key_path")
        or recovery_evidence.get("parent_path")
        or ""
    )
    return key, {
        "cell_offset": key,
        "candidate_class": candidate_class,
        "cell_signature": str(candidate.get("cell_signature") or row_identity.get("cell_signature") or recovery_identity_values.get("cell_signature") or recovery_profile.get("cell_signature") or recovery_evidence.get("cell_signature") or ""),
        "cell_size": _normalize_registry_numeric_string(str(candidate.get("cell_size") or row_identity.get("cell_size") or recovery_identity_values.get("cell_size") or "")) if str(candidate.get("cell_size") or row_identity.get("cell_size") or recovery_identity_values.get("cell_size") or "") else "",
        "hbin_offset": _normalize_registry_numeric_string(str(candidate.get("hbin_offset") or row_identity.get("hbin_offset") or recovery_identity_values.get("hbin_offset") or "")) if str(candidate.get("hbin_offset") or row_identity.get("hbin_offset") or recovery_identity_values.get("hbin_offset") or "") else "",
        "allocation_status": str(candidate.get("allocation_status") or row_identity.get("allocation_status") or recovery_identity_values.get("allocation_status") or recovery_profile.get("allocation_status") or recovery_evidence.get("allocation_status") or ""),
        "name": str(candidate.get("name") or row_identity.get("name") or recovery_identity_values.get("name") or candidate.get("value_name") or ""),
        "value_type": str(candidate.get("value_type") or row_identity.get("value_type") or recovery_identity_values.get("value_type") or ""),
        "value_data_size": _normalize_registry_numeric_string(str(candidate.get("value_data_size") or row_identity.get("value_data_size") or recovery_identity_values.get("value_data_size") or "")) if str(candidate.get("value_data_size") or row_identity.get("value_data_size") or recovery_identity_values.get("value_data_size") or "") else "",
        "data_preview_sha256": data_preview_sha256,
        "parent_key_path": normalize_registry_key_path(parent_key_path),
        "parent_key_confidence": str(candidate.get("parent_key_confidence") or row_identity.get("parent_key_confidence") or recovery_identity_values.get("parent_key_confidence") or recovery_profile.get("parent_confidence") or recovery_evidence.get("parent_confidence") or ""),
        "allocator_context_hash": str(candidate.get("allocator_context_hash") or row_identity.get("allocator_context_hash") or recovery_identity_values.get("allocator_context_hash") or recovery_profile.get("allocator_context_hash") or recovery_evidence.get("allocator_context_hash") or ""),
        "allocator_neighbor_context_hash": str(candidate.get("allocator_neighbor_context_hash") or row_identity.get("allocator_neighbor_context_hash") or recovery_identity_values.get("allocator_neighbor_context_hash") or recovery_profile.get("allocator_neighbor_context_hash") or recovery_evidence.get("allocator_neighbor_context_hash") or ""),
        "recovery_identity_hash": str(candidate.get("recovery_identity_hash") or row_identity.get("recovery_identity_hash") or recovery_identity.get("identity_hash") or recovery_profile.get("recovery_identity_hash") or ""),
    }


def _registry_row_payload(record: Mapping[str, object]) -> Mapping[str, object]:
    """Accept flat registry exports and RapidTriage artifact rows with nested details."""

    details = record.get("details") if isinstance(record.get("details"), Mapping) else {}
    if not details:
        return record
    flattened = dict(details)
    for key, value in record.items():
        if key == "details":
            continue
        flattened.setdefault(key, value)
    return flattened


def _normalize_registry_numeric_string(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return text


def normalize_registry_key_path(key_path: str) -> str:
    text = re.sub(r"\\+", r"\\", str(key_path or "").strip())
    aliases = {
        "HKCU": "HKEY_CURRENT_USER",
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKU": "HKEY_USERS",
        "HKCR": "HKEY_CLASSES_ROOT",
    }
    prefix, sep, rest = text.partition("\\")
    return f"{aliases.get(prefix.upper(), prefix.upper())}{sep}{rest}".rstrip("\\")


def build_registry_record(
    path: Path,
    key: str,
    values: dict[str, str],
    source_hashes: Mapping[str, str] | None = None,
) -> ArtifactRecord:
    resolved_hashes = dict(source_hashes or file_hashes(path))
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
            "source_hashes": resolved_hashes,
            "source_viewer_locator": registry_record_source_viewer_locator(
                source_path=str(path.resolve()),
                source_hashes=resolved_hashes,
                hive_name="",
                hive_hint=key.split("\\", 1)[0],
                key_path=key,
                cell_offset=0,
                allocation_status="exported-reg-key",
                transaction_log_evidence={},
            ),
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
    normalized_rows = build_normalized_user_activity_rows(
        key=key,
        classification=classification,
        decoded_values=decoded_values,
        source_format="reg",
    )
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
            "normalized_activity_rows": normalized_rows,
            "normalized_activity_row_count": len(normalized_rows),
            "registry_user_activity_profile": registry_user_activity_profile(
                source_format="reg",
                key=key,
                classification=classification,
                decoded_values=decoded_values,
                normalized_rows=normalized_rows,
                metadata={"source_hashes": dict(source_hashes), "regf_valid": True},
            ),
            "registry_analyst_review_profile": registry_analyst_review_profile(
                artifact_type="registry-user-activity",
                category=classification["category"],
                source_format="reg",
                hive_hint=key.split("\\", 1)[0],
                key_path=key,
                decoded_values=decoded_values,
                normalized_rows=normalized_rows,
                risk_flags=risk_flags,
                validation_required=False,
            ),
            "parser_confidence": 0.86,
            "evidence_strength": "registry-export-key",
            "risk_flags": risk_flags,
            "risk_score": min(100, 20 + len(risk_flags) * 20),
            "validation_required": False,
            "validation_guidance": "Registry export keys preserve explicit paths and values, but report-grade user activity should still be cross-checked against source hive hashes and collection context.",
            "raw_preview": f"[{key}]",
        },
    )


def build_registry_summary(
    root: Path,
    records: Sequence[ArtifactRecord],
    *,
    key_tree_counts: Mapping[str, int] | None = None,
) -> ArtifactRecord | None:
    if not records and not key_tree_counts:
        return None
    native_facts = registry_native_summary_facts(records)
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
        "key_count": native_facts["native_key_count"]
        + sum(1 for record in records if record.artifact_type in {"registry-key", "registry-run-key", "registry-usb"}),
        "exported_key_count": sum(
            1 for record in records if record.artifact_type in {"registry-key", "registry-run-key", "registry-usb"}
        ),
        "native_key_count": native_facts["native_key_count"],
        "native_value_count": native_facts["native_value_count"],
        "hive_file_count": sum(1 for record in records if record.artifact_type == "registry-hive"),
        "hive_string_row_count": sum(1 for record in records if record.artifact_type == "registry-hive-strings"),
        "hive_cell_row_count": sum(1 for record in records if record.artifact_type == "registry-hive-cell"),
        "key_tree_node_count": sum(1 for record in records if record.artifact_type == "registry-key-tree-node")
        + sum((key_tree_counts or {}).values()),
        "key_tree_node_counts_by_hive": dict(sorted((key_tree_counts or {}).items())),
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
        "persistence_entries": [*persistence_entries, *native_facts["persistence_entries"]],
        "usb_devices": [*usb_devices, *native_facts["usb_devices"]],
        "computer_name": native_facts["computer_name"],
        "timezone": native_facts["timezone"],
        "current_control_set": native_facts["current_control_set"],
        "last_shutdown_at": native_facts["last_shutdown_at"],
        "os_version": native_facts["os_version"],
        "hives": native_facts["hives"],
        "transaction_log_disclosures": native_facts["transaction_log_disclosures"],
        "summary_list_limit": 100,
        "summary_list_totals": {
            "hive_string_hits": len(hive_string_hits),
            "hive_cell_hits": len(hive_cell_hits),
            "key_tree_nodes": len(key_tree_nodes) + sum((key_tree_counts or {}).values()),
            "deleted_cell_candidates": len(deleted_cell_candidates),
            "key_recovery_candidates": len(key_recovery_candidates),
            "value_recovery_candidates": len(value_recovery_candidates),
            "user_activity_entries": len(user_activity_entries),
            "suspicious_entries": len(suspicious_entries),
        },
        "cap_disclosure": (
            "요약 목록(hive_string_hits·key_tree_nodes·deleted_cell_candidates·recovery·user_activity_entries·"
            "suspicious_entries)은 미리보기로 최대 100개만 담고 총계는 summary_list_totals에 기록합니다. "
            "persistence_entries·usb_devices·hives는 전수입니다. 하이브 키/값 해석에는 읽기·셀 상한이 없습니다."
        ),
        "suspicious_entries": sorted(
            suspicious_entries,
            key=lambda item: int(item.get("risk_score") or 0),
            reverse=True,
        )[:100],
        "summary_notes": [
            "Registry hives are walked natively from the root cell (nk/vk/lf/lh/li/ri/db, no read or cell cap); key paths use the logical mount (HKLM\\SYSTEM, HKU\\<SID>, HKU\\<SID>_Classes) and never repeat the root key name.",
            "Free (deleted) nk/vk cells are listed as recovery candidates over the whole hive; transaction logs are detected and disclosed, never replayed.",
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
        payload_bytes = reg_export_hex_to_bytes(cleaned)
        payload_strings = extract_utf16le_strings(payload_bytes)[:8] if payload_bytes else []
        item: dict[str, object] = {
            "raw": cleaned,
            "value_name": name,
            "mru_position": mru_position_from_value_name(name),
        }
        if payload_bytes:
            item["binary_payload"] = {
                "byte_count": len(payload_bytes),
                "sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "utf16le_strings": payload_strings,
                "decode_status": "bounded-payload-hash-and-string-scan",
            }
        if "userassist" in lowered_key:
            item["decoded_name"] = decode_rot13_registry_value_name(name)
            item["activity_value"] = item["decoded_name"]
            item["note"] = "UserAssist value names are ROT13 encoded; binary counters require a dedicated parser for run counts and timestamps."
        elif "typedurls" in lowered_key or "typedpaths" in lowered_key:
            item["typed_value"] = cleaned
            item["activity_value"] = cleaned
        elif "runmru" in lowered_key:
            item["command"] = cleaned
            item["activity_value"] = cleaned
        elif "run" in lowered_key:
            item["command"] = cleaned
            item["executable_hint"] = executable_hint(cleaned)
            item["activity_value"] = cleaned
        elif "recentdocs" in lowered_key:
            item["recent_document_hint"] = payload_strings[0] if payload_strings else cleaned
            item["activity_value"] = item["recent_document_hint"]
        elif "opensavepidlmru" in lowered_key or "lastvisitedpidlmru" in lowered_key:
            item["file_dialog_hint"] = payload_strings[0] if payload_strings else cleaned
            item["activity_value"] = item["file_dialog_hint"]
        elif "muicache" in lowered_key:
            item["application_path_hint"] = name
            item["application_display_name_hint"] = cleaned
            item["activity_value"] = f"{name} -> {cleaned}" if cleaned else name
            item["note"] = "MUICache is an application display cache and is not standalone proof of execution."
        elif "clipboard" in lowered_key:
            item["clipboard_value_preview"] = payload_strings[0] if payload_strings else cleaned[:240]
            item["activity_value"] = item["clipboard_value_preview"]
            item["sensitive_content_warning"] = True
            item["note"] = "Clipboard-related values may contain sensitive content or sync settings; review authority and minimize disclosure."
        elif "mountpoints2" in lowered_key:
            item["mount_point_hint"] = name.strip("#")
            item["activity_value"] = item["mount_point_hint"]
        elif "\\network\\" in lowered_key:
            item["network_share_hint"] = key.split("\\Network\\", 1)[-1] if "\\Network\\" in key else cleaned
            item["activity_value"] = item["network_share_hint"]
        else:
            item["value"] = cleaned
            item["activity_value"] = cleaned
        decoded[name] = item
    return decoded


def build_normalized_user_activity_rows(
    *,
    key: str,
    classification: Mapping[str, str],
    decoded_values: Mapping[str, object],
    source_format: str,
) -> list[dict[str, object]]:
    category = str(classification.get("category") or "")
    label = str(classification.get("label") or "")
    if not decoded_values:
        return [
            {
                "activity_family": category,
                "activity_label": label,
                "key": key,
                "value_name": "",
                "display_value": key,
                "source_format": source_format,
                "confidence": 0.52 if source_format == "registry-hive" else 0.7,
                "reportability": "triage-pivot",
                "normalization_status": "key-or-string-only",
                "citation": {"registry_key": key, "value_name": ""},
            }
        ]
    rows: list[dict[str, object]] = []
    for value_name, raw_item in sorted(decoded_values.items()):
        item = raw_item if isinstance(raw_item, Mapping) else {"activity_value": str(raw_item)}
        display_value = str(
            item.get("activity_value")
            or item.get("typed_value")
            or item.get("command")
            or item.get("recent_document_hint")
            or item.get("file_dialog_hint")
            or item.get("value")
            or item.get("raw")
            or ""
        )
        payload = item.get("binary_payload") if isinstance(item.get("binary_payload"), Mapping) else {}
        rows.append(
            {
                "activity_family": category,
                "activity_label": label,
                "key": key,
                "value_name": str(value_name),
                "display_value": display_value,
                "source_format": source_format,
                "mru_position": item.get("mru_position"),
                "binary_payload_sha256": str(payload.get("sha256") or ""),
                "binary_payload_byte_count": int(payload.get("byte_count") or 0),
                "confidence": 0.86 if source_format == "reg" else 0.52,
                "reportability": "review-pivot" if source_format == "reg" else "triage-pivot",
                "normalization_status": "value-normalized",
                "citation": {"registry_key": key, "value_name": str(value_name)},
            }
        )
    return rows


def registry_user_activity_profile(
    *,
    source_format: str,
    key: str,
    classification: Mapping[str, str],
    decoded_values: Mapping[str, object],
    normalized_rows: Sequence[Mapping[str, object]] | None = None,
    metadata: Mapping[str, object],
) -> dict[str, object]:
    category = str(classification.get("category") or "")
    decoded_count = len(decoded_values)
    normalized_rows = list(normalized_rows or [])
    reg_export = source_format == "reg"
    regf_valid = bool(metadata.get("regf_valid", reg_export))
    source_hashes = metadata.get("source_hashes") if isinstance(metadata.get("source_hashes"), Mapping) else {}
    return {
        "profile_version": "registry-user-activity-normalization-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 11,
        "target_artifacts": [
            "UserAssist",
            "RecentDocs",
            "RunMRU",
            "TypedURLs",
            "TypedPaths",
            "OpenSavePidlMRU",
            "LastVisitedPidlMRU",
            "MUICache",
            "Clipboard",
            "ShellBags",
            "MountPoints2",
            "Network",
            "ComDlg32",
        ],
        "activity_category": category,
        "activity_label": str(classification.get("label") or ""),
        "matched_pattern": str(classification.get("matched_pattern") or ""),
        "source_format": source_format,
        "current_decode_level": "normalized-values" if reg_export else "native-hive-string-pivot",
        "decoded_value_count": decoded_count,
        "normalized_activity_row_count": len(normalized_rows),
        "normalized_activity_schema": {
            "fields": [
                "activity_family",
                "activity_label",
                "key",
                "value_name",
                "display_value",
                "mru_position",
                "binary_payload_sha256",
                "citation",
            ],
            "safe_for_search_index": True,
            "binary_payload_policy": "hash-and-bounded-string-scan-only",
        },
        "target_artifact_coverage": user_activity_target_coverage(category, key, decoded_values),
        "source_integrity": {
            "source_sha256": source_hashes.get("sha256", ""),
            "regf_valid": regf_valid,
            "key_or_string_present": bool(key),
        },
        "reportability_decision": {
            "decision": "review-grade-user-activity-pivot" if reg_export else "do-not-report-as-final-user-activity",
            "allowed_use": "searchable-user-activity-row",
            "validation_required": not reg_export,
            "required_before_report": [
                "replay NTUSER.DAT/UsrClass.dat LOG transaction files when present",
                "decode binary UserAssist/ShellBag/MRU payloads with source offsets",
                "cross-check timestamps and user attribution against profile path and account SID",
                "diff critical rows against RECmd/ShellBagsExplorer/UserAssist parser output",
            ],
        },
        "large_data_controls": {
            "normalized_row_is_small": True,
            "raw_binary_payloads_are_not_expanded": True,
            "safe_for_case_db_indexing": True,
        },
        "analyst_wording": (
            "Registry export row normalized into a user activity artifact."
            if reg_export
            else "Hive string pivot only; treat as a lead until a native key/value parser confirms the path and values."
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "native-user-hive-binary-payload-decode-required",
            "ntuser-usrclass-transaction-log-replay-required",
            "trusted-user-activity-parser-diff-required",
        ],
    }


def registry_analyst_review_profile(
    *,
    artifact_type: str,
    category: str,
    source_format: str,
    hive_name: str = "",
    hive_hint: str = "",
    key_path: str = "",
    name: str = "",
    value_names: Sequence[str] | None = None,
    decoded_values: Mapping[str, object] | None = None,
    normalized_rows: Sequence[Mapping[str, object]] | None = None,
    risk_flags: Sequence[str] | None = None,
    validation_required: bool = True,
    transaction_log_evidence: Mapping[str, object] | None = None,
    report_grade_assessment: Mapping[str, object] | None = None,
    recovery_profile: Mapping[str, object] | None = None,
    source_values: Mapping[str, object] | None = None,
) -> dict[str, object]:
    catalog_key = "deleted-cell" if "recovery" in artifact_type or "deleted" in artifact_type else category
    catalog = REGISTRY_ANALYST_REVIEW_CATALOG.get(catalog_key) or REGISTRY_ANALYST_REVIEW_CATALOG.get("key-tree", {})
    transaction_log_evidence = transaction_log_evidence if isinstance(transaction_log_evidence, Mapping) else {}
    report_grade_assessment = report_grade_assessment if isinstance(report_grade_assessment, Mapping) else {}
    recovery_profile = recovery_profile if isinstance(recovery_profile, Mapping) else {}
    normalized_rows = list(normalized_rows or [])
    decoded_values = dict(decoded_values or {})
    source_values = dict(source_values or {})
    source_field_values: dict[str, object] = {}
    for field in catalog.get("primary_pivots", []):
        field_name = str(field)
        if field_name == "key_path" and key_path:
            source_field_values[field_name] = key_path
        elif field_name == "name" and name:
            source_field_values[field_name] = name
        elif field_name == "value_names" and value_names:
            source_field_values[field_name] = list(value_names)[:50]
        elif field_name == "decoded_values" and decoded_values:
            source_field_values[field_name] = bounded_jsonable(decoded_values)
        elif field_name == "normalized_activity_rows" and normalized_rows:
            source_field_values[field_name] = [bounded_jsonable(row) for row in normalized_rows[:20]]
        elif field_name in source_values and source_values[field_name] not in ("", None):
            source_field_values[field_name] = source_values[field_name]

    blockers = list(report_grade_assessment.get("blockers") or [])
    reportability_decision = recovery_profile.get("reportability_decision")
    if isinstance(reportability_decision, Mapping):
        blockers.extend(reportability_decision.get("blockers", []))
    if transaction_log_evidence.get("status") == "present-not-replayed":
        blockers.append("transaction-log-present-not-replayed")
    if validation_required:
        blockers.append("trusted-registry-parser-diff-required")

    return {
        "profile_version": "registry-analyst-review-profile-v1",
        "artifact_type": artifact_type,
        "category": category,
        "catalog_key": catalog_key,
        "source_format": source_format,
        "hive_name": hive_name,
        "hive_hint": hive_hint,
        "key_path": key_path,
        "name": name,
        "severity": str(catalog.get("severity") or "medium"),
        "summary": str(catalog.get("summary") or "Registry artifact review pivot."),
        "analyst_questions": list(catalog.get("analyst_questions") or []),
        "primary_pivots": list(catalog.get("primary_pivots") or []),
        "source_field_values": source_field_values,
        "correlation_targets": list(catalog.get("correlation_targets") or []),
        "risk_tags": sorted(
            set([str(item) for item in catalog.get("risk_tags", [])] + [str(item) for item in risk_flags or []])
        ),
        "validation_required": validation_required,
        "transaction_log_status": str(transaction_log_evidence.get("status") or "not-evaluated"),
        "report_grade_ready": bool(report_grade_assessment.get("report_grade_ready")),
        "commercial_blockers": sorted(set(str(item) for item in blockers if str(item))),
        "report_guidance": (
            "Use this registry row as a review/search pivot. Final reporting needs source hive hash, "
            "transaction-log handling, parser-version disclosure, and trusted parser or known-answer validation."
        ),
    }


def bounded_jsonable(value: object) -> object:
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)[:500]
    if len(text) <= 2000:
        return value
    return {"truncated_json_preview": text[:2000], "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def decode_rot13_registry_value_name(value: str) -> str:
    return value.translate(ROT13_TRANS)


def reg_export_hex_to_bytes(value: str) -> bytes:
    text = value.strip()
    if not text.lower().startswith("hex"):
        return b""
    _, _, body = text.partition(":")
    if not body:
        return b""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", body)
    if len(cleaned) < 2:
        return b""
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def mru_position_from_value_name(value_name: str) -> int | None:
    try:
        return int(value_name)
    except ValueError:
        match = re.search(r"(\d+)$", value_name)
        return int(match.group(1)) if match else None


def user_activity_target_coverage(
    category: str,
    key: str,
    decoded_values: Mapping[str, object],
) -> dict[str, object]:
    lowered_key = key.lower()
    value_text = " ".join(str(item) for item in decoded_values.values()).lower()
    combined = f"{lowered_key} {value_text}"
    targets = {
        "UserAssist": category == "execution" or "userassist" in combined,
        "RecentDocs": category == "recent-document" or "recentdocs" in combined,
        "RunMRU": category == "run-dialog-mru" or "runmru" in combined,
        "TypedURLs": category == "browser-typed-url" or "typedurls" in combined,
        "TypedPaths": category == "typed-path" or "typedpaths" in combined,
        "OpenSavePidlMRU": category == "file-dialog-mru" or "opensavepidlmru" in combined,
        "LastVisitedPidlMRU": category == "file-dialog-mru" or "lastvisitedpidlmru" in combined,
        "MUICache": category == "muicache" or "muicache" in combined,
        "Clipboard": category == "clipboard-history" or "clipboard" in combined,
        "ShellBags": category == "shellbag" or "bagmru" in combined or "\\bags" in combined,
        "MountPoints2": category == "mounted-device" or "mountpoints2" in combined,
        "Network": category == "network-share" or "\\network\\" in combined,
        "ComDlg32": "comdlg32" in combined,
    }
    return {
        "matched_targets": [name for name, matched in targets.items() if matched],
        "missing_in_this_row": [name for name, matched in targets.items() if not matched],
        "coverage_note": "Coverage is row-local; full case coverage is summarized by registry-summary user_activity_entries.",
    }


def user_activity_risk_flags(category: object, key: str, decoded_values: Mapping[str, object]) -> list[str]:
    flags = [f"user-activity:{category}"] if category else []
    lowered = " ".join([key, " ".join(str(value) for value in decoded_values.values())]).lower()
    if category == "persistence":
        flags.append("user-hive-persistence")
    if category in {"browser-typed-url", "typed-path", "recent-document", "file-dialog-mru", "run-dialog-mru", "muicache", "clipboard-history"}:
        flags.append("user-interaction-history")
    if category == "clipboard-history":
        flags.append("sensitive-content-review")
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


def iter_registry_cell_candidates(
    blob: bytes,
    *,
    record_limit: int = MAX_HIVE_CELL_RECORDS,
) -> list[dict[str, object]]:
    scan_blob = blob[:MAX_HIVE_CELL_SCAN_BYTES]
    candidates: list[dict[str, object]] = []
    seen_offsets: set[int] = set()
    for hbin in iter_registry_hbin_descriptors(scan_blob):
        hbin_offset = int(hbin.get("hbin_offset") or 0)
        hbin_size = int(hbin.get("hbin_size") or 0)
        cursor = hbin_offset + HIVE_BIN_HEADER_SIZE
        hbin_end = min(len(scan_blob), hbin_offset + hbin_size)
        while cursor + 8 <= hbin_end and len(candidates) < record_limit:
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
        while len(candidates) < record_limit:
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
    name, encoding = decode_registry_cell_name(blob[name_start:name_end], compressed=bool(flags & REGF_KEY_COMP_NAME))
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
    list_start = value_list_offset + 4
    end = list_start + value_count * 4
    if end > len(blob):
        return []
    offsets: list[int] = []
    for index in range(value_count):
        relative = read_u32(blob, list_start + index * 4)
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
    *,
    root_cell_offset: int = 0,
) -> tuple[str, str]:
    names = [str(key_node.get("name") or "")]
    current = key_node
    seen = {int(key_node.get("cell_offset") or 0)}
    confidence = "root-cell" if root_cell_offset and int(key_node.get("cell_offset") or 0) == root_cell_offset else "orphan-name"
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


def registry_transaction_log_evidence(
    path: Path,
    *,
    hive_metadata: Mapping[str, object] | None = None,
) -> dict[str, object]:
    candidates = registry_transaction_log_candidates(path)
    present: list[dict[str, object]] = []
    missing: list[str] = []
    seen_present: set[tuple[int, int]] = set()
    for candidate in candidates:
        if candidate.is_file():
            stat = candidate.stat()
            identity = (stat.st_dev, stat.st_ino)
            if identity in seen_present:
                continue
            seen_present.add(identity)
            resolved = candidate.resolve()
            header = parse_registry_transaction_log_header(candidate)
            present.append(
                {
                    "path": str(resolved),
                    "name": candidate.name,
                    "size": stat.st_size,
                    "hashes": file_hashes(candidate),
                    "header": header,
                    "signature_status": header["signature_status"],
                    "replay_readiness": registry_transaction_log_replay_readiness(header, stat.st_size),
                }
            )
        elif candidate.name.upper().endswith((".LOG1", ".LOG2")) and candidate.name.upper() not in {
            name.upper() for name in missing
        }:
            missing.append(candidate.name)
    if present:
        status = "present-not-replayed"
    else:
        status = "absent"
    expected_names = [candidate.name for candidate in candidates]
    valid_log_count = sum(1 for item in present if item.get("signature_status") == "recognized-transaction-log")
    invalid_log_count = len(present) - valid_log_count
    replay_inputs = registry_transaction_replay_inputs(present)
    hive_secondary = int((hive_metadata or {}).get("sequence_secondary") or 0)
    hive_primary = int((hive_metadata or {}).get("sequence_primary") or 0)
    newer_sequences: list[int] = []
    if hive_metadata is not None:
        threshold = hive_secondary or hive_primary
        for item in present:
            header = item.get("header") if isinstance(item.get("header"), Mapping) else {}
            for sequence in header.get("log_entry_sequences") or []:
                if isinstance(sequence, int) and threshold and sequence >= threshold:
                    newer_sequences.append(sequence)
    newer_sequences = sorted(set(newer_sequences))
    return {
        "hive_sequence_primary": hive_primary,
        "hive_sequence_secondary": hive_secondary,
        "newer_sequence_not_replayed": bool(newer_sequences),
        "newer_log_entry_count": len(newer_sequences),
        "newer_sequence_range": [newer_sequences[0], newer_sequences[-1]] if newer_sequences else [],
        "profile_version": "registry-transaction-log-evidence-v1",
        "status": status,
        "transaction_log_replay_applied": False,
        "replay_policy": "detect-and-disclose-only",
        "replay_status": "not-applied",
        "present_count": len(present),
        "recognized_log_count": valid_log_count,
        "unrecognized_log_count": invalid_log_count,
        "missing_count": len(missing),
        "present_logs": present,
        "missing_log_names": missing,
        "expected_log_names": expected_names,
        "replay_inputs": replay_inputs,
        "transaction_context_quality": registry_transaction_context_quality(
            present_count=len(present),
            recognized_log_count=valid_log_count,
            expected_names=expected_names,
            missing_names=missing,
        ),
        "impact_statement": (
            "Transaction logs are present but not replayed; recent committed or rolled-back key/value changes may "
            "be absent from native rows until replay or second-parser comparison is attached."
            if present
            else "No adjacent transaction logs were found; native rows reflect the hive file as supplied, but absence should be confirmed against collection scope."
        ),
        "commercial_blocker": "transaction-log-replay-not-implemented",
        "validation_guidance": (
            "LOG1/LOG2 presence is recorded so analysts can distinguish absent transaction context from "
            "present-but-not-replayed transaction logs. Commercial-grade reconstruction still requires replay "
            "or second-parser diff evidence."
        ),
    }


def registry_transaction_log_candidates(path: Path) -> list[Path]:
    expected = [path.with_name(f"{path.name}.LOG1"), path.with_name(f"{path.name}.LOG2")]
    wanted = {f"{path.name}.log".casefold(), f"{path.name}.log1".casefold(), f"{path.name}.log2".casefold()}
    try:
        actual = sorted(
            (child for child in path.parent.iterdir() if child.name.casefold() in wanted),
            key=lambda item: item.name.casefold(),
        )
    except OSError:
        actual = []
    present_names = {child.name.casefold() for child in actual}
    return [*actual, *(item for item in expected if item.name.casefold() not in present_names)]


def parse_registry_transaction_log_header(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            header = handle.read(512)
    except OSError as exc:
        return {
            "profile_version": "registry-transaction-log-header-v1",
            "signature": "",
            "signature_hex": "",
            "signature_status": "unreadable",
            "read_error": str(exc)[:200],
            "header_size_observed": 0,
            "likely_log_version": "unknown",
            "sequence_number": 0,
            "hive_sequence_hint": 0,
            "flags": 0,
        }
    signature = header[:4]
    signature_text = signature.decode("ascii", errors="replace")
    entries: dict[str, object] = {"log_entry_count": 0, "log_entry_sequences": []}
    log_format = "unknown"
    file_type = read_u32(header, 28) if signature == b"regf" else 0
    marker = b""
    if signature == b"regf":
        # Modern logs (Windows 8.1+) start with a base-block copy (file type 6) followed by
        # HvLE log entries at offset 512; legacy logs carry a DIRT dirty vector there.
        try:
            with path.open("rb") as handle:
                handle.seek(512)
                marker = handle.read(4)
        except OSError:
            marker = b""
        if marker == b"HvLE":
            log_format = "new-hvle"
            entries = parse_registry_transaction_log_entries(path)
        elif marker == b"DIRT":
            log_format = "legacy-dirt"
        else:
            log_format = "base-block-only"
    elif signature in {b"HvLE", b"HvLG"}:
        log_format = "hvle-at-offset-0"
    recognized = log_format in {"new-hvle", "legacy-dirt", "hvle-at-offset-0"}
    if recognized:
        signature_status = "recognized-transaction-log"
    elif signature == b"regf":
        signature_status = "hive-like-header"
    else:
        signature_status = "unrecognized"
    return {
        "profile_version": "registry-transaction-log-header-v2",
        "signature": signature_text,
        "signature_hex": signature.hex(),
        "signature_status": signature_status,
        "read_error": "",
        "header_size_observed": len(header),
        "likely_log_version": "windows-registry-transaction-log" if recognized else "unknown",
        "log_format": log_format,
        "log_file_type": file_type,
        "sequence_number": read_u32(header, 4),
        "hive_sequence_hint": read_u32(header, 8),
        "flags": read_u32(header, 12),
        "replay_applied": False,
        **entries,
    }


def registry_transaction_log_replay_readiness(header: Mapping[str, object], size: int) -> dict[str, object]:
    recognized = header.get("signature_status") == "recognized-transaction-log"
    sufficient_size = size >= 512
    return {
        "profile_version": "registry-transaction-log-replay-readiness-v1",
        "header_recognized": recognized,
        "size_bytes": size,
        "minimum_header_present": sufficient_size,
        "candidate_for_future_replay": bool(recognized and sufficient_size),
        "blockers": []
        if recognized and sufficient_size
        else [
            blocker
            for blocker, failed in (
                ("transaction-log-header-not-recognized", not recognized),
                ("transaction-log-header-too-small", not sufficient_size),
            )
            if failed
        ],
    }


def registry_transaction_replay_inputs(present_logs: Sequence[Mapping[str, object]]) -> dict[str, object]:
    names = {str(item.get("name") or "").lower(): item for item in present_logs}
    log1 = next((item for name, item in names.items() if name.endswith(".log1")), None)
    log2 = next((item for name, item in names.items() if name.endswith(".log2")), None)
    valid_logs = [
        item
        for item in present_logs
        if isinstance(item.get("replay_readiness"), Mapping)
        and item["replay_readiness"].get("candidate_for_future_replay")
    ]
    return {
        "profile_version": "registry-transaction-replay-inputs-v1",
        "log1_present": log1 is not None,
        "log2_present": log2 is not None,
        "recognized_replay_input_count": len(valid_logs),
        "complete_log_pair_present": log1 is not None and log2 is not None,
        "ready_for_future_internal_replay": bool(valid_logs),
        "replay_input_names": [str(item.get("name") or "") for item in valid_logs],
        "remaining_before_internal_replay": [
            "implement HvLE/HvLG log block replay",
            "verify sequence handling against dirty hive base block",
            "diff replayed hive tree against Registry Explorer/RECmd output",
        ],
    }


def registry_transaction_replay_validation_profile(
    hive_metadata: Mapping[str, object],
    transaction_log_evidence: Mapping[str, object],
) -> dict[str, object]:
    present_logs = [
        item for item in transaction_log_evidence.get("present_logs", []) if isinstance(item, Mapping)
    ]
    replay_inputs = (
        transaction_log_evidence.get("replay_inputs")
        if isinstance(transaction_log_evidence.get("replay_inputs"), Mapping)
        else registry_transaction_replay_inputs(present_logs)
    )
    primary_sequence = int(hive_metadata.get("sequence_primary") or 0)
    secondary_sequence = int(hive_metadata.get("sequence_secondary") or 0)
    dirty = bool(hive_metadata.get("dirty"))
    sequence_targets = {value for value in (primary_sequence, secondary_sequence) if value}
    log_sequence_rows: list[dict[str, object]] = []
    for item in present_logs:
        header = item.get("header") if isinstance(item.get("header"), Mapping) else {}
        sequence_number = int(header.get("sequence_number") or 0)
        hive_sequence_hint = int(header.get("hive_sequence_hint") or 0)
        if sequence_number in sequence_targets or hive_sequence_hint in sequence_targets:
            relation = "matches-hive-sequence"
        elif primary_sequence and sequence_number > primary_sequence:
            relation = "ahead-of-hive-primary"
        elif primary_sequence and sequence_number < primary_sequence:
            relation = "behind-hive-primary"
        else:
            relation = "unknown"
        log_sequence_rows.append(
            {
                "name": str(item.get("name") or ""),
                "signature_status": str(item.get("signature_status") or ""),
                "sequence_number": sequence_number,
                "hive_sequence_hint": hive_sequence_hint,
                "flags": int(header.get("flags") or 0),
                "sequence_relation": relation,
                "hashes": dict(item.get("hashes") or {}) if isinstance(item.get("hashes"), Mapping) else {},
                "candidate_for_replay": bool(
                    isinstance(item.get("replay_readiness"), Mapping)
                    and item["replay_readiness"].get("candidate_for_future_replay")
                ),
            }
        )
    recognized_count = int(transaction_log_evidence.get("recognized_log_count") or 0)
    present_count = int(transaction_log_evidence.get("present_count") or 0)
    complete_pair = bool(replay_inputs.get("complete_log_pair_present"))
    if present_count == 0 and not dirty:
        validation_status = "no-log-clean-hive-disclosed"
    elif present_count == 0 and dirty:
        validation_status = "dirty-hive-missing-transaction-logs"
    elif recognized_count and dirty:
        validation_status = "dirty-hive-replay-required"
    elif recognized_count:
        validation_status = "recognized-logs-replay-validation-required"
    else:
        validation_status = "present-unrecognized-log-review-required"
    blockers: list[str] = []
    if dirty:
        blockers.append("dirty-hive-sequence-requires-transaction-replay")
    if recognized_count:
        blockers.extend(
            [
                "transaction-log-replay-not-implemented",
                "transaction-log-sequence-diff-required",
                "recmd-or-registry-explorer-replay-diff-required",
            ]
        )
    elif present_count:
        blockers.append("transaction-log-header-recognition-required")
    if recognized_count and not complete_pair:
        blockers.append("complete-log-pair-or-explicit-missing-log-proof-required")
    if present_count == 0 and dirty:
        blockers.append("missing-log-files-for-dirty-hive")
    return {
        "profile_version": "registry-transaction-replay-validation-v1",
        "parser_version": PARSER_VERSION,
        "validation_status": validation_status,
        "commercial_grade_ready": False,
        "report_grade_ready": present_count == 0 and not dirty,
        "hive_sequence": {
            "primary": primary_sequence,
            "secondary": secondary_sequence,
            "dirty": dirty,
            "sequence_delta": primary_sequence - secondary_sequence,
        },
        "log_sequence_rows": log_sequence_rows,
        "recognized_replay_input_count": int(replay_inputs.get("recognized_replay_input_count") or 0),
        "complete_log_pair_present": complete_pair,
        "ready_for_internal_replay_preflight": bool(
            replay_inputs.get("ready_for_future_internal_replay")
        ),
        "sequence_relations": sorted({str(row["sequence_relation"]) for row in log_sequence_rows}),
        "blockers": sorted(set(blockers)),
        "trusted_diff_required_fields": [
            "hive_path",
            "hive_sha256",
            "log1_sha256",
            "log2_sha256",
            "sequence_primary",
            "sequence_secondary",
            "replayed_key_path",
            "replayed_value_name",
            "cell_offset",
            "last_written_at",
            "allocation_status",
        ],
        "analyst_warning": (
            "This is a transaction replay preflight, not LOG1/LOG2 replay. Treat affected registry rows as "
            "triage evidence until replay output or RECmd/Registry Explorer diff evidence is attached."
        ),
    }


def registry_transaction_context_quality(
    *,
    present_count: int,
    recognized_log_count: int,
    expected_names: Sequence[str],
    missing_names: Sequence[str],
) -> dict[str, object]:
    if present_count == 0:
        level = "absent"
    elif recognized_log_count == present_count:
        level = "recognized-logs-present"
    elif recognized_log_count:
        level = "mixed-recognized-and-unrecognized"
    else:
        level = "present-but-unrecognized"
    return {
        "profile_version": "registry-transaction-context-quality-v1",
        "level": level,
        "present_count": present_count,
        "recognized_log_count": recognized_log_count,
        "expected_count": len(expected_names),
        "missing_count": len(missing_names),
        "analyst_note": (
            "Recognized LOG files are available as replay inputs, but RapidTriage has not applied replay."
            if recognized_log_count
            else "No recognized LOG replay input is available from the supplied collection."
        ),
    }


def registry_transaction_replay_profile(transaction_log_evidence: Mapping[str, object], *, dirty: bool = False) -> dict[str, object]:
    status = str(transaction_log_evidence.get("status") or "unknown")
    replay_applied = bool(transaction_log_evidence.get("transaction_log_replay_applied"))
    required = status == "present-not-replayed" or dirty
    replay_inputs = (
        transaction_log_evidence.get("replay_inputs")
        if isinstance(transaction_log_evidence.get("replay_inputs"), Mapping)
        else {}
    )
    quality = (
        transaction_log_evidence.get("transaction_context_quality")
        if isinstance(transaction_log_evidence.get("transaction_context_quality"), Mapping)
        else {}
    )
    replay_validation_profile = (
        transaction_log_evidence.get("replay_validation_profile")
        if isinstance(transaction_log_evidence.get("replay_validation_profile"), Mapping)
        else {}
    )
    blockers = []
    if required and not replay_applied:
        blockers.append("transaction-log-replay-or-second-parser-diff-required")
    if dirty:
        blockers.append("dirty-hive-sequence-requires-transaction-context")
    blockers.extend(str(item) for item in replay_validation_profile.get("blockers") or [])
    return {
        "profile_version": "registry-transaction-replay-profile-v1",
        "transaction_log_status": status,
        "transaction_log_replay_applied": replay_applied,
        "dirty_hive_sequence": dirty,
        "replay_required_for_report_grade": required,
        "replay_policy": "detect-and-disclose-only",
        "recognized_replay_input_count": int(replay_inputs.get("recognized_replay_input_count") or 0),
        "complete_log_pair_present": bool(replay_inputs.get("complete_log_pair_present")),
        "transaction_context_quality": str(quality.get("level") or ""),
        "replay_validation_status": str(replay_validation_profile.get("validation_status") or ""),
        "replay_validation_profile_hash": str(transaction_log_evidence.get("replay_validation_profile_hash") or ""),
        "ready_for_internal_replay_preflight": bool(
            replay_validation_profile.get("ready_for_internal_replay_preflight")
        ),
        "sequence_relations": list(replay_validation_profile.get("sequence_relations") or []),
        "blockers": sorted(set(blockers)),
        "impact_statement": str(transaction_log_evidence.get("impact_statement") or ""),
        "required_before_report": [
            "apply LOG1/LOG2 replay with verified parser",
            "or attach second-parser/export diff proving current hive rows",
        ] if required else ["document transaction log absence and collection scope"],
    }


def registry_key_tree_validation_matrix(
    key_node: Mapping[str, object],
    path_confidence: str,
    missing_subkey_offsets: Sequence[int],
    missing_value_offsets: Sequence[int],
    hive_valid: bool,
    relationship_profile: Mapping[str, object] | None = None,
    transaction_log_evidence: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    relationship_profile = relationship_profile or {}
    transaction_log_evidence = transaction_log_evidence or {}
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
            "passed": path_confidence in {"parent-chain", "root-cell"},
            "severity": "high",
            "detail": path_confidence,
        },
        {
            "id": "root-reachability",
            "label": "Root-cell reachability",
            "passed": bool(relationship_profile.get("root_reachable")),
            "severity": "high",
            "detail": f"root={relationship_profile.get('root_cell_offset', 0)} cell={relationship_profile.get('cell_offset', 0)}",
        },
        {
            "id": "child-parent-backlinks",
            "label": "Child parent backlinks",
            "passed": not bool(relationship_profile.get("missing_child_backlink_cell_offsets")),
            "severity": "medium",
            "detail": f"missing={len(relationship_profile.get('missing_child_backlink_cell_offsets', []) or [])}",
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
        {
            "id": "transaction-log-context-recorded",
            "label": "Transaction-log context recorded",
            "passed": bool(transaction_log_evidence.get("status")),
            "severity": "medium",
            "detail": str(transaction_log_evidence.get("status") or "unknown"),
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


def registry_report_citation_manifest(
    *,
    artifact_type: str,
    source_path: str,
    source_hashes: Mapping[str, str],
    row_identity: Mapping[str, object],
    validation_matrix: Sequence[Mapping[str, object]],
    report_grade_assessment: Mapping[str, object],
    transaction_log_evidence: Mapping[str, object],
    recovery_profile: Mapping[str, object] | None = None,
    citation_scope: str,
) -> dict[str, object]:
    cell_offset = int(row_identity.get("cell_offset") or 0)
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "registry-hive-source",
            "ref_id": "registry-hive-source",
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_viewer_locator": {
                "viewer": "registry-hive",
                "hive_name": row_identity.get("hive_name", ""),
                "hive_hint": row_identity.get("hive_hint", ""),
            },
        },
        {
            "kind": "registry-cell-offset",
            "ref_id": "registry-cell-offset",
            "cell_offset": cell_offset,
            "cell_relative_offset": row_identity.get("cell_relative_offset", 0),
            "hbin_offset": row_identity.get("hbin_offset", 0),
            "allocation_status": row_identity.get("allocation_status", ""),
            "source_viewer_locator": {
                "viewer": "registry-cell-offset",
                "cell_offset": cell_offset,
                "cell_relative_offset": row_identity.get("cell_relative_offset", 0),
            },
        },
    ]
    key_path = row_identity.get("key_path") or row_identity.get("key_path_candidate") or row_identity.get("parent_key_path_candidate")
    if key_path:
        citation_refs.append(
            {
                "kind": "registry-key-path",
                "ref_id": "registry-key-path",
                "key_path": key_path,
                "key_path_sha256": sha256_text(str(key_path)),
                "source_viewer_locator": {
                    "viewer": "registry-key-tree",
                    "key_path": key_path,
                    "cell_offset": cell_offset,
                },
            }
        )
    if row_identity.get("name") or row_identity.get("value_data_offset"):
        citation_refs.append(
            {
                "kind": "registry-value-or-name",
                "ref_id": "registry-value-or-name",
                "name": row_identity.get("name", ""),
                "name_sha256": sha256_text(str(row_identity.get("name") or "")),
                "value_type": row_identity.get("value_type", ""),
                "value_data_size": row_identity.get("value_data_size", 0),
                "value_data_offset": row_identity.get("value_data_offset", 0),
                "decoded_data_preview_sha256": row_identity.get("decoded_data_preview_sha256", ""),
                "source_viewer_locator": {
                    "viewer": "registry-value-cell",
                    "cell_offset": cell_offset,
                    "value_data_offset": row_identity.get("value_data_offset", 0),
                },
            }
        )
    if int(transaction_log_evidence.get("present_count") or 0):
        replay_validation_profile = (
            transaction_log_evidence.get("replay_validation_profile")
            if isinstance(transaction_log_evidence.get("replay_validation_profile"), Mapping)
            else {}
        )
        citation_refs.append(
            {
                "kind": "registry-transaction-log-context",
                "ref_id": "registry-transaction-log-context",
                "status": transaction_log_evidence.get("status", ""),
                "present_count": transaction_log_evidence.get("present_count", 0),
                "recognized_log_count": transaction_log_evidence.get("recognized_log_count", 0),
                "transaction_log_replay_applied": bool(transaction_log_evidence.get("transaction_log_replay_applied")),
                "replay_validation_status": replay_validation_profile.get("validation_status", ""),
                "replay_validation_profile_hash": transaction_log_evidence.get("replay_validation_profile_hash", ""),
                "complete_log_pair_present": bool(replay_validation_profile.get("complete_log_pair_present")),
                "sequence_relations": list(replay_validation_profile.get("sequence_relations") or []),
                "source_viewer_locator": {
                    "viewer": "registry-transaction-log-evidence",
                    "hive_path": source_path,
                },
            }
        )
    if recovery_profile:
        citation_refs.append(
            {
                "kind": "registry-recovery-validation",
                "ref_id": "registry-recovery-validation",
                "candidate_class": recovery_profile.get("candidate_class", ""),
                "confidence": recovery_profile.get("confidence", 0),
                "independent_validation_status": recovery_profile.get("independent_validation_status", ""),
                "recovery_identity_hash": recovery_profile.get("recovery_identity_hash", ""),
                "allocator_context_hash": recovery_profile.get("allocator_context_hash", ""),
                "allocator_neighbor_context_hash": recovery_profile.get("allocator_neighbor_context_hash", ""),
                "reportability_decision": recovery_profile.get("reportability_decision", {}),
                "source_viewer_locator": {
                    "viewer": "registry-recovery-context",
                    "cell_offset": cell_offset,
                },
            }
        )
    passed = [
        str(item.get("id"))
        for item in validation_matrix
        if isinstance(item, Mapping) and item.get("id") and item.get("passed")
    ]
    failed = [
        str(item.get("id"))
        for item in validation_matrix
        if isinstance(item, Mapping) and item.get("id") and not item.get("passed")
    ]
    manifest: dict[str, object] = {
        "manifest_version": "registry-report-citation-manifest-v1",
        "artifact_type": artifact_type,
        "parser": PARSER_VERSION,
        "citation_scope": citation_scope,
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": "registry-hive",
        },
        "row_identity": dict(row_identity),
        "row_identity_hash": stable_registry_json_sha256(dict(row_identity)),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "passed_matrix_ids": passed,
            "failed_matrix_ids": failed,
            "report_grade_status": report_grade_assessment.get("status", ""),
            "transaction_log_status": transaction_log_evidence.get("status", "not-evaluated"),
            "transaction_log_replay_applied": bool(transaction_log_evidence.get("transaction_log_replay_applied")),
            "transaction_replay_validation_status": (
                transaction_log_evidence.get("replay_validation_profile", {}).get("validation_status", "")
                if isinstance(transaction_log_evidence.get("replay_validation_profile"), Mapping)
                else ""
            ),
            "transaction_replay_validation_hash": transaction_log_evidence.get(
                "replay_validation_profile_hash",
                "",
            ),
        },
        "reportability": {
            "allowed_use": "registry-native-triage-review-pivot",
            "ready_for_court_report": bool(report_grade_assessment.get("report_grade_ready")),
            "validation_required": not bool(report_grade_assessment.get("report_grade_ready")),
            "blockers": list(report_grade_assessment.get("blockers") or []),
        },
    }
    manifest["manifest_sha256"] = stable_registry_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_registry_json_sha256(value: Mapping[str, object] | Sequence[object] | str) -> str:
    return sha256_text(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


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
        data_start = data_offset + 4
        if data_offset <= 0 or data_start + value_size > len(blob):
            return ""
        raw = blob[data_start : data_start + value_size]
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
    return filetime_to_iso_ticks(value)


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


# ---------------------------------------------------------------------------
# Native regf reader: full nk/vk/lf/lh/li/ri/db walk over a memory-mapped hive.
#
# The reader follows the live key tree from the base-block root cell, so key and
# value counts equal what a dedicated hive parser reports (no read or cell cap).
# Names honour the KEY_COMP_NAME / VALUE_COMP_NAME flags (Latin-1 when set,
# UTF-16LE otherwise -- Korean key names are UTF-16LE). Transaction logs are
# never replayed; ``registry_transaction_log_evidence`` discloses newer log
# sequences instead.
# ---------------------------------------------------------------------------

FILETIME_TICKS_PER_SECOND = 10_000_000
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
FILETIME_MAX_TICKS = (
    int((dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc) - FILETIME_EPOCH).total_seconds())
    * FILETIME_TICKS_PER_SECOND
)
REGF_BIG_DATA_SEGMENT_SIZE = 16344
REGF_KEY_COMP_NAME = 0x0020
REGF_VALUE_COMP_NAME = 0x0001
REGF_MAX_SUBKEY_LIST_DEPTH = 8
REGISTRY_NATIVE_HIVE_NAMES = REGISTRY_HIVE_NAMES | {"DRIVERS", "ELAM", "BBI", "BCD-TEMPLATE", "USERDIFF"}
REGISTRY_MACHINE_MOUNTS = {
    "SYSTEM": "HKLM\\SYSTEM",
    "SOFTWARE": "HKLM\\SOFTWARE",
    "SAM": "HKLM\\SAM",
    "SECURITY": "HKLM\\SECURITY",
    "COMPONENTS": "HKLM\\COMPONENTS",
    "DRIVERS": "HKLM\\DRIVERS",
    "ELAM": "HKLM\\ELAM",
    "BBI": "HKLM\\BBI",
    "BCD-TEMPLATE": "HKLM\\BCD-Template",
    "USERDIFF": "HKLM\\USERDIFF",
    "DEFAULT": "HKU\\.DEFAULT",
}
REGISTRY_SID_PATTERN = re.compile(r"^S-1-\d+(?:-\d+)+$", re.IGNORECASE)


def filetime_to_iso_ticks(value: object) -> str:
    """FILETIME (100 ns ticks since 1601-01-01 UTC) to ISO-8601 with integer math.

    Whole seconds render without a fraction; otherwise all seven 100 ns digits
    are kept (``datetime`` arithmetic alone would round to microseconds).
    """
    try:
        ticks = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return ""
    if ticks <= 0 or ticks > FILETIME_MAX_TICKS:
        return ""
    seconds, fraction = divmod(ticks, FILETIME_TICKS_PER_SECOND)
    moment = FILETIME_EPOCH + dt.timedelta(seconds=seconds)
    text = (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
    )
    if fraction:
        text += f".{fraction:07d}"
    return text + "+00:00"


class NativeRegistryKey:
    __slots__ = (
        "allocated",
        "flags",
        "last_written_filetime",
        "name",
        "name_encoding",
        "offset",
        "parent_offset",
        "subkey_count",
        "subkey_list_offset",
        "value_count",
        "value_list_offset",
    )

    def __init__(self, **fields: object) -> None:
        for slot in self.__slots__:
            setattr(self, slot, fields.get(slot))

    @property
    def last_written_at(self) -> str:
        return filetime_to_iso_ticks(self.last_written_filetime)


class NativeRegistryValue:
    __slots__ = ("data_offset", "data_size", "flags", "inline", "name", "name_encoding", "offset", "value_type")

    def __init__(self, **fields: object) -> None:
        for slot in self.__slots__:
            setattr(self, slot, fields.get(slot))


class NativeRegistryHive:
    """Read-only regf reader over ``mmap`` (bytes for in-memory blobs)."""

    def __init__(self, data: object, *, path: Path | None = None, handle: object = None) -> None:
        self._data = data
        self._handle = handle
        self.path = path
        self.size = len(data)  # type: ignore[arg-type]
        self.header = parse_registry_hive_header(bytes(data[:4096]))  # type: ignore[index]
        hbin_size = int(self.header.get("hbin_data_size") or 0)
        self.hbin_end = min(self.size, HIVE_BIN_BASE_OFFSET + hbin_size) if hbin_size else self.size
        self.minor_version = int(self.header.get("minor_version") or 0)
        self.errors: Counter[str] = Counter()
        self._root: NativeRegistryKey | None = None

    @classmethod
    def open(cls, path: Path) -> NativeRegistryHive | None:
        import mmap

        try:
            handle = path.open("rb")
        except OSError:
            return None
        try:
            head = handle.read(4096)
            if len(head) < 512 or not head.startswith(REGISTRY_HIVE_SIGNATURE):
                handle.close()
                return None
            handle.seek(0)
            try:
                data: object = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            except (OSError, ValueError):
                data = handle.read()
        except OSError:
            handle.close()
            return None
        return cls(data, path=path, handle=handle)

    @classmethod
    def from_bytes(cls, blob: bytes) -> NativeRegistryHive | None:
        if len(blob) < 512 or not blob.startswith(REGISTRY_HIVE_SIGNATURE):
            return None
        return cls(blob)

    def close(self) -> None:
        closer = getattr(self._data, "close", None)
        if callable(closer):
            closer()
        if self._handle is not None:
            self._handle.close()  # type: ignore[attr-defined]
            self._handle = None

    def __enter__(self) -> NativeRegistryHive:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- primitive reads -------------------------------------------------
    def _u16(self, offset: int) -> int:
        return int.from_bytes(self._data[offset : offset + 2], "little")  # type: ignore[index]

    def _u32(self, offset: int) -> int:
        return int.from_bytes(self._data[offset : offset + 4], "little")  # type: ignore[index]

    def _u64(self, offset: int) -> int:
        return int.from_bytes(self._data[offset : offset + 8], "little")  # type: ignore[index]

    def _cell(self, relative_offset: int) -> tuple[int, int, bool] | None:
        """Return (data_start, data_length, allocated) for a cell, or None."""
        if relative_offset in (0, 0xFFFFFFFF):
            return None
        if relative_offset % 8:
            self.errors["misaligned-cell-offset"] += 1
            return None
        offset = HIVE_BIN_BASE_OFFSET + relative_offset
        if offset + 8 > self.hbin_end:
            self.errors["cell-offset-out-of-bounds"] += 1
            return None
        raw_size = int.from_bytes(self._data[offset : offset + 4], "little", signed=True)  # type: ignore[index]
        size = abs(raw_size)
        if size < 8 or offset + size > self.hbin_end:
            self.errors["cell-size-invalid"] += 1
            return None
        if raw_size > 0:
            self.errors["free-cell-referenced"] += 1
        return offset + 4, size - 4, raw_size < 0

    # -- keys -------------------------------------------------------------
    @property
    def root(self) -> NativeRegistryKey | None:
        if self._root is None:
            self._root = self.key_at(int(self.header.get("root_cell_offset") or 0))
        return self._root

    def key_at(self, relative_offset: int) -> NativeRegistryKey | None:
        cell = self._cell(relative_offset)
        if cell is None:
            return None
        start, length, allocated = cell
        if length < 76 or self._data[start : start + 2] != b"nk":  # type: ignore[index]
            self.errors["nk-signature-mismatch"] += 1
            return None
        flags = self._u16(start + 2)
        name_length = self._u16(start + 72)
        raw_name = bytes(self._data[start + 76 : start + 76 + min(name_length, length - 76)])  # type: ignore[index]
        name, encoding = decode_native_registry_name(raw_name, compressed=bool(flags & REGF_KEY_COMP_NAME))
        return NativeRegistryKey(
            offset=relative_offset,
            name=name,
            name_encoding=encoding,
            flags=flags,
            last_written_filetime=self._u64(start + 4),
            parent_offset=self._u32(start + 16),
            subkey_count=self._u32(start + 20),
            subkey_list_offset=self._u32(start + 28),
            value_count=self._u32(start + 36),
            value_list_offset=self._u32(start + 40),
            allocated=allocated,
        )

    def _subkey_offsets(self, list_offset: int, depth: int = 0) -> list[int]:
        if depth > REGF_MAX_SUBKEY_LIST_DEPTH:
            self.errors["subkey-list-depth-exceeded"] += 1
            return []
        cell = self._cell(list_offset)
        if cell is None:
            return []
        start, length, _allocated = cell
        signature = bytes(self._data[start : start + 2])  # type: ignore[index]
        count = self._u16(start + 2)
        offsets: list[int] = []
        if signature in (b"lf", b"lh"):
            for index in range(min(count, (length - 4) // 8)):
                offsets.append(self._u32(start + 4 + index * 8))
        elif signature == b"li":
            for index in range(min(count, (length - 4) // 4)):
                offsets.append(self._u32(start + 4 + index * 4))
        elif signature == b"ri":
            for index in range(min(count, (length - 4) // 4)):
                offsets.extend(self._subkey_offsets(self._u32(start + 4 + index * 4), depth + 1))
        else:
            self.errors["subkey-list-signature-unknown"] += 1
        return offsets

    def subkeys(self, key: NativeRegistryKey) -> list[NativeRegistryKey]:
        if not key.subkey_count:
            return []
        children: list[NativeRegistryKey] = []
        for offset in self._subkey_offsets(int(key.subkey_list_offset or 0)):
            child = self.key_at(offset)
            if child is not None:
                children.append(child)
        if len(children) != key.subkey_count:
            self.errors["subkey-count-mismatch"] += 1
        return children

    def subkey(self, key: NativeRegistryKey, name: str) -> NativeRegistryKey | None:
        wanted = name.casefold()
        for child in self.subkeys(key):
            if str(child.name).casefold() == wanted:
                return child
        return None

    def open_key(self, relative_path: str, *, start: NativeRegistryKey | None = None) -> NativeRegistryKey | None:
        current = start or self.root
        for part in [segment for segment in relative_path.replace("/", "\\").split("\\") if segment]:
            if current is None:
                return None
            current = self.subkey(current, part)
        return current

    def iter_keys(
        self,
        start: NativeRegistryKey | None = None,
        components: tuple[str, ...] = (),
    ) -> Iterable[tuple[tuple[str, ...], NativeRegistryKey]]:
        """Depth-first walk yielding (root-relative name components, key)."""
        first = start or self.root
        if first is None:
            return
        visited: set[int] = set()
        stack: list[tuple[tuple[str, ...], NativeRegistryKey]] = [(components, first)]
        while stack:
            parts, key = stack.pop()
            offset = int(key.offset or 0)
            if offset in visited:
                self.errors["key-cycle-skipped"] += 1
                continue
            visited.add(offset)
            yield parts, key
            children = self.subkeys(key)
            for child in reversed(children):
                stack.append(((*parts, str(child.name)), child))

    # -- values -----------------------------------------------------------
    def values(self, key: NativeRegistryKey) -> list[NativeRegistryValue]:
        count = int(key.value_count or 0)
        if not count:
            return []
        cell = self._cell(int(key.value_list_offset or 0))
        if cell is None:
            return []
        start, length, _allocated = cell
        result: list[NativeRegistryValue] = []
        for index in range(min(count, length // 4)):
            value = self.value_at(self._u32(start + index * 4))
            if value is not None:
                result.append(value)
        return result

    def value_at(self, relative_offset: int) -> NativeRegistryValue | None:
        cell = self._cell(relative_offset)
        if cell is None:
            return None
        start, length, _allocated = cell
        if length < 20 or self._data[start : start + 2] != b"vk":  # type: ignore[index]
            self.errors["vk-signature-mismatch"] += 1
            return None
        name_length = self._u16(start + 2)
        raw_size = self._u32(start + 4)
        flags = self._u16(start + 16)
        raw_name = bytes(self._data[start + 20 : start + 20 + min(name_length, length - 20)])  # type: ignore[index]
        name, encoding = decode_native_registry_name(raw_name, compressed=bool(flags & REGF_VALUE_COMP_NAME))
        return NativeRegistryValue(
            offset=relative_offset,
            name=name,
            name_encoding=encoding,
            value_type=self._u32(start + 12),
            data_size=raw_size & 0x7FFFFFFF,
            data_offset=self._u32(start + 8),
            inline=bool(raw_size & 0x80000000),
            flags=flags,
        )

    def value(self, key: NativeRegistryKey, name: str) -> NativeRegistryValue | None:
        wanted = name.casefold()
        for value in self.values(key):
            if str(value.name).casefold() == wanted:
                return value
        return None

    def value_bytes(self, value: NativeRegistryValue) -> bytes:
        size = int(value.data_size or 0)
        if value.inline:
            return int(value.data_offset or 0).to_bytes(4, "little")[: min(size, 4)]
        if size <= 0:
            return b""
        cell = self._cell(int(value.data_offset or 0))
        if cell is None:
            return b""
        start, length, _allocated = cell
        if (
            size > REGF_BIG_DATA_SEGMENT_SIZE
            and self.minor_version >= 4
            and self._data[start : start + 2] == b"db"  # type: ignore[index]
        ):
            segment_count = self._u16(start + 2)
            list_cell = self._cell(self._u32(start + 4))
            if list_cell is None:
                return b""
            list_start, list_length, _ = list_cell
            parts: list[bytes] = []
            remaining = size
            for index in range(min(segment_count, list_length // 4)):
                segment = self._cell(self._u32(list_start + index * 4))
                if segment is None:
                    self.errors["big-data-segment-missing"] += 1
                    break
                segment_start, segment_length, _ = segment
                take = min(remaining, segment_length, REGF_BIG_DATA_SEGMENT_SIZE)
                parts.append(bytes(self._data[segment_start : segment_start + take]))  # type: ignore[index]
                remaining -= take
                if remaining <= 0:
                    break
            return b"".join(parts)
        return bytes(self._data[start : start + min(size, length)])  # type: ignore[index]

    def value_data(self, value: NativeRegistryValue) -> object:
        return decode_registry_value_data(int(value.value_type or 0), self.value_bytes(value))

    def values_dict(self, key: NativeRegistryKey) -> dict[str, object]:
        return {str(value.name): self.value_data(value) for value in self.values(key)}


def decode_native_registry_name(raw: bytes, *, compressed: bool) -> tuple[str, str]:
    if compressed:
        return raw.decode("latin-1"), "latin-1"
    return raw.decode("utf-16-le", errors="replace"), "utf-16le"


def decode_registry_value_data(value_type: int, raw: bytes) -> object:
    if value_type in (1, 2, 6):
        return decode_registry_sz(raw)
    if value_type == 7:
        text = raw[: len(raw) - (len(raw) % 2)].decode("utf-16-le", errors="replace")
        return [item for item in text.split("\x00") if item]
    if value_type == 4:
        return int.from_bytes(raw[:4], "little")
    if value_type == 5:
        return int.from_bytes(raw[:4], "big")
    if value_type == 11:
        return int.from_bytes(raw[:8], "little")
    return raw


def decode_registry_sz(raw: bytes) -> str:
    even = raw[: len(raw) - (len(raw) % 2)]
    for index in range(0, len(even), 2):
        if even[index : index + 2] == b"\x00\x00":
            even = even[:index]
            break
    return even.decode("utf-16-le", errors="replace")


def registry_value_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)


# ---------------------------------------------------------------------------
# Hive mount resolution (HKLM\SYSTEM, HKU\<SID>, HKU\<SID>_Classes ...).
# ---------------------------------------------------------------------------


def find_child_case_insensitive(directory: Path, *names: str) -> Path | None:
    current = directory
    for name in names:
        try:
            match = next((child for child in current.iterdir() if child.name.casefold() == name.casefold()), None)
        except OSError:
            return None
        if match is None:
            return None
        current = match
    return current


def registry_root_key_name(path: Path) -> str:
    hive = NativeRegistryHive.open(path)
    if hive is None:
        return ""
    try:
        root = hive.root
        return str(root.name) if root is not None else ""
    finally:
        hive.close()


class RegistryCollectionContext:
    """Per-collection cache: profile folder -> SID (UsrClass root name / ProfileList)."""

    def __init__(self, root: Path | None) -> None:
        self.root = root
        self._profile_list: dict[str, str] | None = None

    def _profile_list_sids(self) -> dict[str, str]:
        if self._profile_list is not None:
            return self._profile_list
        self._profile_list = {}
        if self.root is None:
            return self._profile_list
        software = find_child_case_insensitive(self.root, "Windows", "System32", "config", "SOFTWARE")
        if software is None or not software.is_file():
            return self._profile_list
        hive = NativeRegistryHive.open(software)
        if hive is None:
            return self._profile_list
        try:
            profile_list = hive.open_key(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
            for key in hive.subkeys(profile_list) if profile_list is not None else []:
                value = hive.value(key, "ProfileImagePath")
                image = str(hive.value_data(value)) if value is not None else ""
                folder = image.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
                if folder and REGISTRY_SID_PATTERN.match(str(key.name)):
                    self._profile_list[folder.casefold()] = str(key.name)
        finally:
            hive.close()
        return self._profile_list

    def user_sid_for_hive(self, path: Path, root_name: str = "") -> tuple[str, str]:
        name = path.name.upper()
        if name == "USRCLASS.DAT":
            if root_name.lower().endswith("_classes") and REGISTRY_SID_PATTERN.match(root_name[: -len("_classes")]):
                return root_name[: -len("_classes")], "usrclass-root-key-name"
        elif name == "NTUSER.DAT":
            profile = path.parent
            usrclass = find_child_case_insensitive(profile, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat")
            if usrclass is not None and usrclass.is_file():
                classes_root = registry_root_key_name(usrclass)
                if classes_root.lower().endswith("_classes") and REGISTRY_SID_PATTERN.match(classes_root[:-8]):
                    return classes_root[:-8], "sibling-usrclass-root-key-name"
        else:
            return "", ""
        folder = registry_profile_folder(path)
        sid = self._profile_list_sids().get(folder.casefold(), "") if folder else ""
        return (sid, "software-profilelist") if sid else ("", "")


def registry_profile_folder(path: Path) -> str:
    """Profile folder name for Users\\<name>\\NTUSER.DAT or ...\\<name>\\AppData\\...\\UsrClass.dat."""
    parents = list(path.parents)
    index = 0 if path.name.upper() == "NTUSER.DAT" else 4
    if index and [part.name.casefold() for part in parents[:4]] != ["windows", "microsoft", "local", "appdata"]:
        return ""
    if len(parents) > index + 1 and parents[index + 1].name.casefold() == "users":
        return parents[index].name
    return ""


def registry_hive_mount(path: Path, hive: NativeRegistryHive, context: RegistryCollectionContext | None) -> dict[str, str]:
    """Logical mount for root-relative key paths; the root key name is never repeated."""
    root = hive.root
    root_name = str(root.name) if root is not None else ""
    upper = path.name.upper()
    sid, sid_source = ("", "")
    if upper in {"NTUSER.DAT", "USRCLASS.DAT"}:
        sid, sid_source = (context or RegistryCollectionContext(None)).user_sid_for_hive(path, root_name)
    if upper in REGISTRY_MACHINE_MOUNTS:
        mount = REGISTRY_MACHINE_MOUNTS[upper]
    elif upper == "NTUSER.DAT":
        profile = registry_profile_folder(path)
        mount = f"HKU\\{sid}" if sid else (f"HKU\\{profile}" if profile else "HKCU")
    elif upper == "USRCLASS.DAT":
        profile = registry_profile_folder(path)
        if sid:
            mount = f"HKU\\{sid}_Classes"
        else:
            mount = f"HKU\\{profile}_Classes" if profile else "HKCU\\Software\\Classes"
    else:
        mount = path.name
    return {"mount": mount, "user_sid": sid, "user_sid_source": sid_source, "root_key_name": root_name}


def candidate_native_registry_hive_paths(root: Path) -> Iterable[Path]:
    return candidate_registry_hive_paths(root, names=REGISTRY_NATIVE_HIVE_NAMES)


# ---------------------------------------------------------------------------
# Transaction log disclosure (detect only; never replayed).
# ---------------------------------------------------------------------------


def parse_registry_transaction_log_entries(path: Path) -> dict[str, object]:
    """Read the HvLE entry headers (sequence numbers) of a new-format log."""
    sequences: list[int] = []
    try:
        with path.open("rb") as handle:
            handle.seek(512)
            offset = 512
            while True:
                head = handle.read(40)
                if len(head) < 40 or head[:4] != b"HvLE":
                    break
                size = int.from_bytes(head[4:8], "little")
                if size < 40 or size % 512:
                    break
                sequences.append(int.from_bytes(head[12:16], "little"))
                offset += size
                handle.seek(offset)
    except OSError:
        return {"log_entry_count": 0, "log_entry_sequences": []}
    return {
        "log_entry_count": len(sequences),
        "log_entry_sequence_min": min(sequences) if sequences else 0,
        "log_entry_sequence_max": max(sequences) if sequences else 0,
        "log_entry_sequences": sequences,
    }


def registry_transaction_disclosure(evidence: Mapping[str, object]) -> dict[str, str]:
    newer = int(evidence.get("newer_log_entry_count") or 0)
    status = str(evidence.get("status") or "unknown")
    if newer:
        low, high = evidence.get("newer_sequence_range") or (0, 0)  # type: ignore[misc]
        message = (
            f"트랜잭션 로그(LOG1/LOG2)에 하이브 기록보다 새로운 시퀀스 {newer}개({low}–{high})가 있으나 "
            "재생(replay)하지 않았습니다. 최근 키·값 변경이 결과에 반영되지 않았을 수 있습니다."
        )
        return {"status": "newer-sequence-not-replayed", "message_ko": message}
    if status == "present-not-replayed":
        return {
            "status": status,
            "message_ko": "트랜잭션 로그가 있으나 하이브보다 새로운 시퀀스는 없습니다(재생하지 않음).",
        }
    return {"status": status, "message_ko": "인접 트랜잭션 로그 없음 — 하이브 파일 상태 그대로 해석했습니다."}


# ---------------------------------------------------------------------------
# Semantic plugins over the native reader.
# ---------------------------------------------------------------------------

SERVICE_START_LABELS = {0: "부팅(Boot)", 1: "시스템(System)", 2: "자동(Auto)", 3: "수동(Manual)", 4: "사용 안 함(Disabled)"}
SERVICE_TYPE_LABELS = {
    0x1: "커널 드라이버",
    0x2: "파일 시스템 드라이버",
    0x4: "어댑터",
    0x8: "인식기 드라이버",
    0x10: "독립 프로세스 서비스",
    0x20: "공유 프로세스 서비스",
    0x50: "사용자 독립 프로세스 서비스",
    0x60: "사용자 공유 프로세스 서비스",
    0x110: "대화형 독립 프로세스 서비스",
    0x120: "대화형 공유 프로세스 서비스",
}
USB_DEVICE_PROPERTY_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
USB_DEVICE_PROPERTY_FIELDS = {
    0x64: "first_install_at",
    0x65: "install_at",
    0x66: "last_arrival_at",
    0x67: "last_removal_at",
}
DEVICE_CLASS_DISK = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
DEVICE_CLASS_VOLUME = "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
TIME_ZONE_KO_LABELS = {
    "Korea Standard Time": "대한민국 표준시(KST)",
    "Tokyo Standard Time": "일본 표준시(JST)",
    "China Standard Time": "중국 표준시(CST)",
    "UTC": "협정 세계시(UTC)",
    "Pacific Standard Time": "미국 태평양 표준시",
}
RUN_KEY_SUFFIXES = (
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Microsoft\Windows\CurrentVersion\RunServices",
    r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
)
WINLOGON_PERSISTENCE_VALUES = ("Shell", "Userinit", "Taskman", "AppSetup", "GinaDLL", "VmApplet")
WINDOWS_PERSISTENCE_VALUES = ("Load", "Run", "AppInit_DLLs")
USER_ACTIVITY_KO_LABELS = {
    "wordwheel-query": "탐색기 검색어(WordWheelQuery)",
    "recent-document": "최근 문서(RecentDocs)",
    "typed-path": "탐색기 주소 입력(TypedPaths)",
    "typed-url": "IE/Edge 주소 입력(TypedURLs)",
    "run-dialog-mru": "실행 창 기록(RunMRU)",
    "file-dialog-mru": "열기/저장 대화상자(OpenSavePidlMRU)",
    "file-dialog-folder-mru": "대화상자 최근 폴더(LastVisitedPidlMRU)",
}


class NativeHiveRowContext:
    def __init__(
        self,
        path: Path,
        hive: NativeRegistryHive,
        mount: Mapping[str, str],
        source_hashes: Mapping[str, str],
        transaction_disclosure: Mapping[str, str],
    ) -> None:
        self.path = path
        self.source_path = str(path.resolve())
        self.hive = hive
        self.mount = str(mount.get("mount") or path.name)
        self.user_sid = str(mount.get("user_sid") or "")
        self.source_hashes = dict(source_hashes)
        self.transaction_disclosure = dict(transaction_disclosure)
        self.hive_hint = hive_hint_from_path(path)

    def key_path(self, relative: str) -> str:
        relative = relative.strip("\\")
        return f"{self.mount}\\{relative}" if relative else self.mount

    def row(
        self,
        artifact_type: str,
        *,
        label: str,
        relative_key: str,
        key: NativeRegistryKey | None,
        fields: Mapping[str, object],
        timestamp: str = "",
        timestamp_label: str = "",
        raw_preview: str = "",
        risk_flags: Sequence[str] = (),
    ) -> ArtifactRecord:
        key_last_written_at = key.last_written_at if key is not None else ""
        details: dict[str, object] = {
            "parser": "windows-registry-native-hive-plugin",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-hive-decoded",
            "reportability": "review",
            "label": label,
            "source_path": self.source_path,
            "source_format": "registry-hive",
            "source_hashes": self.source_hashes,
            "hive_name": self.path.name,
            "hive_hint": self.hive_hint,
            "hive_mount": self.mount,
            "user_sid": self.user_sid,
            "key_path": self.key_path(relative_key),
            "key": self.key_path(relative_key),
            "key_last_written_at": key_last_written_at,
            "key_cell_offset": HIVE_BIN_BASE_OFFSET + int(key.offset or 0) if key is not None else 0,
            **dict(fields),
            "timestamp": timestamp,
            "timestamp_label": timestamp_label if timestamp else "",
            "transaction_log_status": self.transaction_disclosure.get("status", ""),
            "risk_flags": sorted(set(risk_flags)),
            "risk_score": min(100, 25 * len(set(risk_flags))),
            "raw_preview": (raw_preview or self.key_path(relative_key))[:2000],
        }
        return ArtifactRecord(
            provider=WindowsRegistryProvider.name,
            artifact_type=artifact_type,
            path=self.source_path,
            supported=True,
            details=details,
        )


def registry_signed_dword(value: object) -> int | None:
    if not isinstance(value, int):
        return None
    return value - 0x100000000 if value & 0x80000000 else value


def registry_unix_time_iso(value: object) -> str:
    if not isinstance(value, int) or value <= 0:
        return ""
    try:
        return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def registry_filetime_from_bytes(raw: object) -> str:
    if isinstance(raw, int):
        return filetime_to_iso_ticks(raw)
    if isinstance(raw, (bytes, bytearray)) and len(raw) >= 8:
        return filetime_to_iso_ticks(int.from_bytes(raw[:8], "little"))
    return ""


def registry_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, (bytes, bytearray)):
        return decode_registry_sz(bytes(value))
    return str(value)


def registry_native_semantic_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    upper = context.path.name.upper()
    if upper == "SYSTEM":
        yield from system_hive_records(context)
    elif upper == "SOFTWARE":
        yield from software_hive_records(context)
    elif upper == "NTUSER.DAT":
        yield from ntuser_hive_records(context)


def resolve_current_control_set(hive: NativeRegistryHive) -> tuple[str, dict[str, object]]:
    select = hive.open_key("Select")
    values = hive.values_dict(select) if select is not None else {}
    current = values.get("Current")
    if isinstance(current, int) and current > 0:
        name = f"ControlSet{current:03d}"
        if hive.open_key(name) is not None:
            return name, {"source": "Select\\Current", **{str(k): v for k, v in values.items() if isinstance(v, int)}}
    root = hive.root
    for child in hive.subkeys(root) if root is not None else []:
        if str(child.name).lower().startswith("controlset"):
            return str(child.name), {"source": "first-controlset-fallback"}
    return "", {"source": "not-found"}


def system_hive_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    hive = context.hive
    ccs, select_info = resolve_current_control_set(hive)
    select_key = hive.open_key("Select")
    shutdown_key = hive.open_key(f"{ccs}\\Control\\Windows") if ccs else None
    shutdown_value = hive.value(shutdown_key, "ShutdownTime") if shutdown_key is not None else None
    shutdown_at = registry_filetime_from_bytes(hive.value_bytes(shutdown_value)) if shutdown_value is not None else ""
    yield context.row(
        "windows-control-set",
        label="현재 컨트롤 세트",
        relative_key="Select",
        key=select_key,
        fields={
            "current_control_set": ccs,
            "resolution_source": select_info.get("source", ""),
            "select_values": {k: v for k, v in select_info.items() if k != "source"},
            "last_shutdown_at": shutdown_at,
        },
        timestamp=shutdown_at,
        timestamp_label="shutdown",
        raw_preview=f"CurrentControlSet = {ccs}" if ccs else "CurrentControlSet 미확인",
    )
    if not ccs:
        return
    name_key = hive.open_key(f"{ccs}\\Control\\ComputerName\\ComputerName")
    active_key = hive.open_key(f"{ccs}\\Control\\ComputerName\\ActiveComputerName")
    tcpip_key = hive.open_key(f"{ccs}\\Services\\Tcpip\\Parameters")
    computer_name = registry_text(hive.values_dict(name_key).get("ComputerName")) if name_key is not None else ""
    tcpip = hive.values_dict(tcpip_key) if tcpip_key is not None else {}
    if name_key is not None or active_key is not None:
        yield context.row(
            "windows-computer-name",
            label="컴퓨터 이름",
            relative_key=f"{ccs}\\Control\\ComputerName\\ComputerName",
            key=name_key,
            fields={
                "computer_name": computer_name,
                "active_computer_name": registry_text(hive.values_dict(active_key).get("ComputerName"))
                if active_key is not None
                else "",
                "tcpip_hostname": registry_text(tcpip.get("Hostname")),
                "tcpip_domain": registry_text(tcpip.get("Domain")),
                "current_control_set": ccs,
            },
            raw_preview=f"컴퓨터 이름: {computer_name}",
        )
    yield from timezone_records(context, ccs)
    yield from service_records(context, ccs)
    yield from network_interface_records(context, ccs)
    yield from usb_and_mounted_device_records(context, ccs)


def timezone_records(context: NativeHiveRowContext, ccs: str) -> Iterable[ArtifactRecord]:
    hive = context.hive
    relative = f"{ccs}\\Control\\TimeZoneInformation"
    key = hive.open_key(relative)
    if key is None:
        return
    values = hive.values_dict(key)
    bias = registry_signed_dword(values.get("Bias"))
    active_bias = registry_signed_dword(values.get("ActiveTimeBias"))
    offset_minutes = -(active_bias if active_bias is not None else (bias or 0))
    sign = "+" if offset_minutes >= 0 else "-"
    utc_offset = f"{sign}{abs(offset_minutes) // 60:02d}:{abs(offset_minutes) % 60:02d}"
    key_name = registry_text(values.get("TimeZoneKeyName"))
    yield context.row(
        "windows-timezone",
        label="시간대 설정",
        relative_key=relative,
        key=key,
        fields={
            "time_zone_key_name": key_name,
            "time_zone_label_ko": TIME_ZONE_KO_LABELS.get(key_name, key_name),
            "standard_name": registry_text(values.get("StandardName")),
            "daylight_name": registry_text(values.get("DaylightName")),
            "bias_minutes": bias,
            "active_time_bias_minutes": active_bias,
            "standard_bias_minutes": registry_signed_dword(values.get("StandardBias")),
            "daylight_bias_minutes": registry_signed_dword(values.get("DaylightBias")),
            "dynamic_daylight_time_disabled": values.get("DynamicDaylightTimeDisabled"),
            "utc_offset": utc_offset,
            "utc_offset_minutes": offset_minutes,
            "bias_semantics": "Bias = UTC − 현지시각(분). UTC 오프셋은 −ActiveTimeBias(없으면 −Bias)",
        },
        raw_preview=f"시간대: {key_name} (UTC{utc_offset})",
    )


def service_records(context: NativeHiveRowContext, ccs: str) -> Iterable[ArtifactRecord]:
    hive = context.hive
    services = hive.open_key(f"{ccs}\\Services")
    if services is None:
        return
    for service in hive.subkeys(services):
        values = hive.values_dict(service)
        parameters = hive.subkey(service, "Parameters")
        service_dll = registry_text(values.get("ServiceDll"))
        if not service_dll and parameters is not None:
            service_dll = registry_text(hive.values_dict(parameters).get("ServiceDll"))
        start = values.get("Start") if isinstance(values.get("Start"), int) else None
        service_type = values.get("Type") if isinstance(values.get("Type"), int) else None
        image_path = registry_text(values.get("ImagePath"))
        flags = service_risk_flags_native(image_path, service_dll, start)
        name = str(service.name)
        yield context.row(
            "windows-service-config",
            label="서비스 설정",
            relative_key=f"{ccs}\\Services\\{name}",
            key=service,
            fields={
                "service_name": name,
                "display_name": registry_text(values.get("DisplayName")),
                "image_path": image_path,
                "service_dll": service_dll,
                "start": start,
                "start_label": SERVICE_START_LABELS.get(start, "") if start is not None else "",
                "service_type": service_type,
                "service_type_label": SERVICE_TYPE_LABELS.get(service_type, "") if service_type is not None else "",
                "object_name": registry_text(values.get("ObjectName")),
                "group": registry_text(values.get("Group")),
                "description": registry_text(values.get("Description")),
                "control_set": ccs,
                "autostart": start in (0, 1, 2),
            },
            timestamp=service.last_written_at,
            timestamp_label="last_written",
            raw_preview=f"{name}: {image_path or service_dll}",
            risk_flags=flags,
        )


def service_risk_flags_native(image_path: str, service_dll: str, start: int | None) -> list[str]:
    flags = []
    for candidate in (image_path, service_dll):
        lowered = candidate.lower()
        if not lowered:
            continue
        flags.extend(suspicious_value_flags(candidate))
        system_like = any(
            token in lowered
            for token in ("\\windows\\", "system32\\", "\\systemroot\\", "%systemroot%", "\\program files", "\\driverstore\\")
        )
        if not system_like and start in (0, 1, 2):
            flags.append("autostart-service-outside-system-dirs")
    return sorted(set(flags))


def network_interface_records(context: NativeHiveRowContext, ccs: str) -> Iterable[ArtifactRecord]:
    hive = context.hive
    interfaces = hive.open_key(f"{ccs}\\Services\\Tcpip\\Parameters\\Interfaces")
    if interfaces is None:
        return
    connection_names: dict[str, str] = {}
    network = hive.open_key(f"{ccs}\\Control\\Network\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}")
    for adapter in hive.subkeys(network) if network is not None else []:
        connection = hive.subkey(adapter, "Connection")
        if connection is not None:
            connection_names[str(adapter.name).lower()] = registry_text(hive.values_dict(connection).get("Name"))
    for interface in hive.subkeys(interfaces):
        values = hive.values_dict(interface)
        name = str(interface.name)
        fields = {
            "interface_guid": name,
            "connection_name": connection_names.get(name.lower(), ""),
            "dhcp_enabled": bool(values.get("EnableDHCP")) if isinstance(values.get("EnableDHCP"), int) else None,
            "ip_address": registry_text(values.get("IPAddress")),
            "subnet_mask": registry_text(values.get("SubnetMask")),
            "default_gateway": registry_text(values.get("DefaultGateway")),
            "name_server": registry_text(values.get("NameServer")),
            "domain": registry_text(values.get("Domain")),
            "dhcp_ip_address": registry_text(values.get("DhcpIPAddress")),
            "dhcp_subnet_mask": registry_text(values.get("DhcpSubnetMask")),
            "dhcp_server": registry_text(values.get("DhcpServer")),
            "dhcp_default_gateway": registry_text(values.get("DhcpDefaultGateway")),
            "dhcp_name_server": registry_text(values.get("DhcpNameServer")),
            "dhcp_domain": registry_text(values.get("DhcpDomain")),
            "lease_obtained_at": registry_unix_time_iso(values.get("LeaseObtainedTime")),
            "lease_terminates_at": registry_unix_time_iso(values.get("LeaseTerminatesTime")),
        }
        address = fields["ip_address"] or fields["dhcp_ip_address"]
        yield context.row(
            "windows-network-interface",
            label="네트워크 인터페이스",
            relative_key=f"{ccs}\\Services\\Tcpip\\Parameters\\Interfaces\\{name}",
            key=interface,
            fields=fields,
            timestamp=str(fields["lease_obtained_at"] or ""),
            timestamp_label="dhcp_lease_obtained",
            raw_preview=f"{name} {address}".strip(),
        )


def parse_usbstor_device_class(name: str) -> dict[str, str]:
    parts = {}
    for token in name.split("&"):
        prefix, _, rest = token.partition("_")
        if prefix in {"Ven", "Prod", "Rev"}:
            parts[prefix.lower()] = rest.replace("_", " ").strip()
        elif not parts:
            parts["device_type"] = token
    return {
        "device_type": parts.get("device_type", ""),
        "vendor": parts.get("ven", ""),
        "product": parts.get("prod", ""),
        "revision": parts.get("rev", ""),
    }


def usb_device_property_times(hive: NativeRegistryHive, instance: NativeRegistryKey) -> dict[str, str]:
    times: dict[str, str] = {}
    properties = hive.subkey(instance, "Properties")
    group = hive.subkey(properties, USB_DEVICE_PROPERTY_GUID) if properties is not None else None
    for prop in hive.subkeys(group) if group is not None else []:
        try:
            code = int(str(prop.name), 16)
        except ValueError:
            continue
        field = USB_DEVICE_PROPERTY_FIELDS.get(code)
        if field is None:
            continue
        candidates = [prop, *hive.subkeys(prop)]
        for holder in candidates:
            for value in hive.values(holder):
                raw = hive.value_bytes(value)
                if len(raw) == 8:
                    times[field] = filetime_to_iso_ticks(int.from_bytes(raw, "little"))
                    break
            if field in times:
                break
    return times


def decode_mounted_device_data(raw: bytes) -> dict[str, object]:
    if raw.startswith(b"DMIO:ID:") and len(raw) >= 24:
        import uuid

        return {"data_kind": "gpt-partition-guid", "partition_guid": "{" + str(uuid.UUID(bytes_le=raw[8:24])) + "}"}
    if len(raw) == 12:
        return {
            "data_kind": "mbr-disk-signature",
            "disk_signature": raw[:4][::-1].hex(),
            "partition_offset": int.from_bytes(raw[4:12], "little"),
        }
    text = decode_registry_sz(raw)
    if text and all(ch.isprintable() for ch in text):
        return {"data_kind": "device-path", "device_path": text}
    return {"data_kind": "unknown", "data_hex": raw[:64].hex()}


def match_usbstor_to_usb(
    serial_core: str,
    container_id: str,
    usb_by_serial: Mapping[str, Mapping[str, str]],
    usb_by_parent_prefix: Mapping[str, Mapping[str, str]],
    usb_by_container: Mapping[str, Sequence[Mapping[str, str]]],
    *,
    full_serial: str = "",
) -> tuple[Mapping[str, str], str]:
    """Join a USBSTOR instance to its Enum\\USB parent: ``(usb_entry, join_method)``.

    Order: exact serial, truncated serial prefix (USBSTOR clips long serials), the USB
    instance's ParentIdPrefix (OS-generated ``7&...&0`` serials), then a ContainerID shared by
    exactly one VID/PID. ``join_method`` is ``""`` when nothing matched.
    """
    serial_lower = serial_core.lower()
    if serial_lower in usb_by_serial:
        return usb_by_serial[serial_lower], "serial"
    if len(serial_lower) >= 16:
        prefixed = [entry for name, entry in usb_by_serial.items() if name.startswith(serial_lower)]
        if len({(entry["vid"], entry["pid"]) for entry in prefixed}) == 1:
            return prefixed[0], "serial-prefix"
    for prefix in (full_serial.lower(), serial_lower):
        if prefix and prefix in usb_by_parent_prefix:
            return usb_by_parent_prefix[prefix], "parent-id-prefix"
    candidates = list(usb_by_container.get(container_id.lower(), [])) if container_id else []
    storage = [entry for entry in candidates if entry.get("usb_service", "").lower() in {"usbstor", "uaspstor"}]
    candidates = storage or candidates
    if candidates and len({(entry["vid"], entry["pid"]) for entry in candidates}) == 1:
        usbstor_first = sorted(candidates, key=lambda entry: entry.get("usb_service", "").lower() != "usbstor")
        return usbstor_first[0], "container-id"
    return {}, ""


def usb_and_mounted_device_records(context: NativeHiveRowContext, ccs: str) -> Iterable[ArtifactRecord]:
    hive = context.hive
    mounted_key = hive.open_key("MountedDevices")
    mounted: list[dict[str, object]] = []
    for value in hive.values(mounted_key) if mounted_key is not None else []:
        name = str(value.name)
        decoded = decode_mounted_device_data(hive.value_bytes(value))
        entry: dict[str, object] = {"mount_name": name, **decoded}
        if name.lower().startswith("\\dosdevices\\"):
            entry["mount_kind"] = "drive-letter"
            entry["drive_letter"] = name[len("\\DosDevices\\") :]
        elif name.lower().startswith("\\??\\volume"):
            entry["mount_kind"] = "volume-guid"
            entry["volume_guid"] = name[len("\\??\\Volume") :]
        else:
            entry["mount_kind"] = "other"
        mounted.append(entry)
    device_class_times: dict[str, list[tuple[str, str]]] = {}
    for class_guid in (DEVICE_CLASS_DISK, DEVICE_CLASS_VOLUME):
        class_key = hive.open_key(f"{ccs}\\Control\\DeviceClasses\\{class_guid}")
        for interface in hive.subkeys(class_key) if class_key is not None else []:
            device_class_times.setdefault(str(interface.name).lower(), []).append((class_guid, interface.last_written_at))
    usb_by_serial: dict[str, dict[str, str]] = {}
    usb_by_parent_prefix: dict[str, dict[str, str]] = {}
    usb_by_container: dict[str, list[dict[str, str]]] = {}
    usb_root = hive.open_key(f"{ccs}\\Enum\\USB")
    for vid_pid in hive.subkeys(usb_root) if usb_root is not None else []:
        vid_match = re.search(r"VID_([0-9A-Fa-f]{4})", str(vid_pid.name))
        pid_match = re.search(r"PID_([0-9A-Fa-f]{4})", str(vid_pid.name))
        for instance in hive.subkeys(vid_pid):
            instance_values = hive.values_dict(instance)
            entry = {
                "vid": vid_match.group(1).upper() if vid_match else "",
                "pid": pid_match.group(1).upper() if pid_match else "",
                "usb_key_path": context.key_path(f"{ccs}\\Enum\\USB\\{vid_pid.name}\\{instance.name}"),
                "usb_key_last_written_at": instance.last_written_at,
                "usb_instance_id": str(instance.name),
                "usb_service": registry_text(instance_values.get("Service")),
            }
            usb_by_serial.setdefault(str(instance.name).lower(), entry)
            parent_prefix = registry_text(instance_values.get("ParentIdPrefix")).lower()
            if parent_prefix:
                usb_by_parent_prefix.setdefault(parent_prefix, entry)
            container = registry_text(instance_values.get("ContainerID")).lower()
            if container and "&mi_" not in str(vid_pid.name).lower():
                usb_by_container.setdefault(container, []).append(entry)
    usbstor = hive.open_key(f"{ccs}\\Enum\\USBSTOR")
    matched_mounts: dict[str, str] = {}
    for device_class in hive.subkeys(usbstor) if usbstor is not None else []:
        identity = parse_usbstor_device_class(str(device_class.name))
        for instance in hive.subkeys(device_class):
            serial = str(instance.name)
            serial_core = re.sub(r"&\d+$", "", serial)
            values = hive.values_dict(instance)
            times = usb_device_property_times(hive, instance)
            needle = f"#{serial.lower()}#"
            drive_letters = sorted(
                str(item.get("drive_letter"))
                for item in mounted
                if item.get("drive_letter") and needle in str(item.get("device_path") or "").lower()
            )
            volume_guids = sorted(
                str(item.get("volume_guid"))
                for item in mounted
                if item.get("volume_guid") and needle in str(item.get("device_path") or "").lower()
            )
            for item in mounted:
                if needle in str(item.get("device_path") or "").lower():
                    matched_mounts[str(item["mount_name"])] = serial
            interface_times = sorted(
                {stamp for name, rows in device_class_times.items() if needle in name for _guid, stamp in rows}
            )
            container_id = registry_text(values.get("ContainerID"))
            usb, usb_join_method = match_usbstor_to_usb(
                serial_core, container_id, usb_by_serial, usb_by_parent_prefix, usb_by_container, full_serial=serial
            )
            friendly = registry_text(values.get("FriendlyName"))
            timestamp = times.get("last_arrival_at") or times.get("first_install_at") or ""
            yield context.row(
                "windows-usb-device",
                label="USB 저장장치",
                relative_key=f"{ccs}\\Enum\\USBSTOR\\{device_class.name}\\{serial}",
                key=instance,
                fields={
                    **identity,
                    "device_class_id": str(device_class.name),
                    "serial_number": serial,
                    "serial_is_os_generated": len(serial) > 1 and serial[1] == "&",
                    "friendly_name": friendly,
                    "container_id": container_id,
                    "driver": registry_text(values.get("Driver")),
                    "vid": usb.get("vid", ""),
                    "pid": usb.get("pid", ""),
                    "usb_join_method": usb_join_method,
                    "usb_instance_id": usb.get("usb_instance_id", ""),
                    "usb_key_path": usb.get("usb_key_path", ""),
                    "usb_key_last_written_at": usb.get("usb_key_last_written_at", ""),
                    "first_install_at": times.get("first_install_at", ""),
                    "install_at": times.get("install_at", ""),
                    "last_arrival_at": times.get("last_arrival_at", ""),
                    "last_removal_at": times.get("last_removal_at", ""),
                    "device_interface_last_written_at": interface_times,
                    "drive_letters": drive_letters,
                    "volume_guids": volume_guids,
                    "timeline_events": [
                        {"kind": field, "timestamp": times[field]}
                        for field in ("first_install_at", "install_at", "last_arrival_at", "last_removal_at")
                        if times.get(field)
                    ],
                    "control_set": ccs,
                },
                timestamp=timestamp,
                timestamp_label="last_arrival" if times.get("last_arrival_at") else "first_install",
                raw_preview=f"{friendly or device_class.name} [{serial}]",
            )
    for item in mounted:
        name = str(item["mount_name"])
        device_path = str(item.get("device_path") or "")
        identity = {}
        match = re.search(r"USBSTOR#([^#]+)#", device_path, re.IGNORECASE)
        if match:
            identity = parse_usbstor_device_class(match.group(1))
        yield context.row(
            "windows-mounted-device",
            label="마운트된 장치",
            relative_key="MountedDevices",
            key=mounted_key,
            fields={
                **item,
                "usb_serial_number": matched_mounts.get(name, ""),
                "usb_vendor": identity.get("vendor", ""),
                "usb_product": identity.get("product", ""),
                "removable_usb": "usbstor#" in device_path.lower(),
                "value_name": name,
            },
            raw_preview=f"{name} → {device_path or item.get('partition_guid') or item.get('disk_signature') or ''}",
        )


def software_hive_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    hive = context.hive
    version_key = hive.open_key(r"Microsoft\Windows NT\CurrentVersion")
    if version_key is not None:
        values = hive.values_dict(version_key)
        yield context.row(
            "windows-os-version",
            label="운영체제 정보",
            relative_key=r"Microsoft\Windows NT\CurrentVersion",
            key=version_key,
            fields={
                "product_name": registry_text(values.get("ProductName")),
                "display_version": registry_text(values.get("DisplayVersion")),
                "edition_id": registry_text(values.get("EditionID")),
                "current_build": registry_text(values.get("CurrentBuild") or values.get("CurrentBuildNumber")),
                "ubr": values.get("UBR"),
                "registered_owner": registry_text(values.get("RegisteredOwner")),
                "registered_organization": registry_text(values.get("RegisteredOrganization")),
                "install_date": registry_unix_time_iso(values.get("InstallDate")),
                "install_time": registry_filetime_from_bytes(values.get("InstallTime")),
            },
            raw_preview=f"{registry_text(values.get('ProductName'))} {registry_text(values.get('DisplayVersion'))}",
        )
    profile_list = hive.open_key(r"Microsoft\Windows NT\CurrentVersion\ProfileList")
    for profile in hive.subkeys(profile_list) if profile_list is not None else []:
        values = hive.values_dict(profile)
        high, low = values.get("LocalProfileLoadTimeHigh"), values.get("LocalProfileLoadTimeLow")
        load_time = filetime_to_iso_ticks((high << 32) | low) if isinstance(high, int) and isinstance(low, int) else ""
        yield context.row(
            "windows-profile-list-entry",
            label="사용자 프로필(ProfileList)",
            relative_key=f"Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{profile.name}",
            key=profile,
            fields={
                "sid": str(profile.name),
                "profile_image_path": registry_text(values.get("ProfileImagePath")),
                "state": values.get("State"),
                "flags": values.get("Flags"),
                "local_profile_load_time": load_time,
            },
            timestamp=load_time or profile.last_written_at,
            timestamp_label="profile_load" if load_time else "last_written",
            raw_preview=f"{profile.name} {registry_text(values.get('ProfileImagePath'))}",
        )
    yield from persistence_records(context, prefix="")
    winlogon = hive.open_key(r"Microsoft\Windows NT\CurrentVersion\Winlogon")
    if winlogon is not None:
        yield from winlogon_records(context, r"Microsoft\Windows NT\CurrentVersion\Winlogon", winlogon)
    for base in (r"Microsoft\Windows\CurrentVersion\Uninstall", r"Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
        yield from installed_program_records(context, base)


def persistence_records(context: NativeHiveRowContext, *, prefix: str) -> Iterable[ArtifactRecord]:
    hive = context.hive
    for suffix in RUN_KEY_SUFFIXES:
        relative = f"{prefix}{suffix}"
        key = hive.open_key(relative)
        if key is None:
            continue
        for value in hive.values(key):
            command = registry_text(hive.value_data(value))
            name = str(value.name) or "(default)"
            yield context.row(
                "registry-persistence-entry",
                label="자동 실행(Run/RunOnce)",
                relative_key=relative,
                key=key,
                fields={
                    "persistence_category": suffix.rsplit("\\", 1)[-1],
                    "value_name": name,
                    "command": command,
                    "executable_hint": executable_hint(command),
                    "evidence_note": "자동 실행 등록은 실행 증거가 아닙니다(등록 사실).",
                },
                timestamp=key.last_written_at,
                timestamp_label="last_written",
                raw_preview=f"{name} = {command}",
                risk_flags=suspicious_value_flags(command),
            )


def winlogon_records(context: NativeHiveRowContext, relative: str, key: NativeRegistryKey) -> Iterable[ArtifactRecord]:
    values = context.hive.values_dict(key)
    for name in WINLOGON_PERSISTENCE_VALUES:
        if name not in values:
            continue
        command = registry_text(values[name])
        yield context.row(
            "registry-persistence-entry",
            label="Winlogon 설정",
            relative_key=relative,
            key=key,
            fields={
                "persistence_category": "Winlogon",
                "value_name": name,
                "command": command,
                "executable_hint": executable_hint(command),
                "evidence_note": "Winlogon 값은 기본값(explorer.exe, userinit.exe)과 비교해 판단합니다.",
            },
            timestamp=key.last_written_at,
            timestamp_label="last_written",
            raw_preview=f"{name} = {command}",
            risk_flags=suspicious_value_flags(command),
        )


def installed_program_records(context: NativeHiveRowContext, base: str) -> Iterable[ArtifactRecord]:
    hive = context.hive
    uninstall = hive.open_key(base)
    for program in hive.subkeys(uninstall) if uninstall is not None else []:
        values = hive.values_dict(program)
        display_name = registry_text(values.get("DisplayName"))
        yield context.row(
            "windows-installed-program",
            label="설치된 프로그램",
            relative_key=f"{base}\\{program.name}",
            key=program,
            fields={
                "program_key": str(program.name),
                "display_name": display_name,
                "display_version": registry_text(values.get("DisplayVersion")),
                "publisher": registry_text(values.get("Publisher")),
                "install_date": registry_text(values.get("InstallDate")),
                "install_location": registry_text(values.get("InstallLocation")),
                "install_source": registry_text(values.get("InstallSource")),
                "uninstall_string": registry_text(values.get("UninstallString")),
            },
            timestamp=program.last_written_at,
            timestamp_label="last_written",
            raw_preview=display_name or str(program.name),
        )


NTUSER_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer"


def ntuser_hive_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    hive = context.hive
    yield from persistence_records(context, prefix="Software\\")
    winlogon = hive.open_key(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
    if winlogon is not None:
        yield from winlogon_records(context, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", winlogon)
    windows_key = hive.open_key(r"Software\Microsoft\Windows NT\CurrentVersion\Windows")
    if windows_key is not None:
        values = hive.values_dict(windows_key)
        for name in WINDOWS_PERSISTENCE_VALUES:
            command = registry_text(values.get(name))
            if not command:
                continue
            yield context.row(
                "registry-persistence-entry",
                label="자동 실행(Windows\\Load/Run)",
                relative_key=r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                key=windows_key,
                fields={"persistence_category": f"Windows\\{name}", "value_name": name, "command": command},
                timestamp=windows_key.last_written_at,
                timestamp_label="last_written",
                raw_preview=f"{name} = {command}",
                risk_flags=suspicious_value_flags(command),
            )
    yield from mru_string_records(context, f"{NTUSER_EXPLORER}\\WordWheelQuery", "wordwheel-query", recurse=True)
    yield from recent_docs_records(context)
    yield from numbered_string_records(context, f"{NTUSER_EXPLORER}\\TypedPaths", "typed-path", prefix="url")
    yield from numbered_string_records(context, r"Software\Microsoft\Internet Explorer\TypedURLs", "typed-url", prefix="url")
    yield from run_mru_records(context)
    yield from open_save_records(context)
    yield from last_visited_records(context)
    yield from installed_program_records(context, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")


def activity_row(
    context: NativeHiveRowContext,
    *,
    category: str,
    relative_key: str,
    key: NativeRegistryKey,
    value_name: str,
    activity_value: str,
    mru_position: int | None,
    extra: Mapping[str, object] | None = None,
    timestamp: str = "",
    timestamp_label: str = "",
) -> ArtifactRecord:
    is_latest = mru_position == 0
    if not timestamp and is_latest:
        timestamp, timestamp_label = key.last_written_at, "last_written_mru_head"
    return context.row(
        "registry-user-activity",
        label=USER_ACTIVITY_KO_LABELS.get(category, category),
        relative_key=relative_key,
        key=key,
        fields={
            "user_activity_category": category,
            "activity_label": USER_ACTIVITY_KO_LABELS.get(category, category),
            "user_hive_scope": "ntuser",
            "value_name": value_name,
            "activity_value": activity_value,
            "mru_position": mru_position,
            "mru_position_note": "0 = 가장 최근(MRU 목록 첫 항목)",
            "timestamp_semantics": "키 최종 수정 시각은 MRU 최상위(0번) 항목에만 해당합니다."
            if timestamp_label == "last_written_mru_head"
            else "",
            **dict(extra or {}),
        },
        timestamp=timestamp,
        timestamp_label=timestamp_label,
        raw_preview=activity_value,
    )


def mru_positions(hive: NativeRegistryHive, key: NativeRegistryKey) -> dict[str, int]:
    value = hive.value(key, "MRUListEx")
    if value is not None:
        raw = hive.value_bytes(value)
        order = []
        for index in range(0, len(raw) - 3, 4):
            item = int.from_bytes(raw[index : index + 4], "little")
            if item == 0xFFFFFFFF:
                break
            order.append(item)
        return {str(item): position for position, item in enumerate(order)}
    value = hive.value(key, "MRUList")
    if value is not None:
        text = registry_text(hive.value_data(value))
        return {char: position for position, char in enumerate(text)}
    return {}


def mru_string_records(
    context: NativeHiveRowContext, relative: str, category: str, *, recurse: bool
) -> Iterable[ArtifactRecord]:
    hive = context.hive
    key = hive.open_key(relative)
    if key is None:
        return
    targets = [(relative, key)]
    if recurse:
        targets.extend((f"{relative}\\{child.name}", child) for child in hive.subkeys(key))
    for target_relative, target in targets:
        positions = mru_positions(hive, target)
        for value in hive.values(target):
            name = str(value.name)
            if not name.isdigit():
                continue
            text = decode_registry_sz(hive.value_bytes(value))
            yield activity_row(
                context,
                category=category,
                relative_key=target_relative,
                key=target,
                value_name=name,
                activity_value=text,
                mru_position=positions.get(name),
                extra={"search_scope": str(target.name) if target is not key else ""},
            )


def recent_docs_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    from .shellbags import decode_shell_item_list

    hive = context.hive
    relative = f"{NTUSER_EXPLORER}\\RecentDocs"
    key = hive.open_key(relative)
    if key is None:
        return
    for target_relative, target in [(relative, key), *((f"{relative}\\{c.name}", c) for c in hive.subkeys(key))]:
        positions = mru_positions(hive, target)
        for value in hive.values(target):
            name = str(value.name)
            if not name.isdigit():
                continue
            raw = hive.value_bytes(value)
            text = decode_registry_sz(raw)
            consumed = (len(text.encode("utf-16-le")) + 2) if text else 0
            _path, items = decode_shell_item_list(raw[consumed:]) if consumed < len(raw) else ("", [])
            lnk_name = next((str(item.get("name") or "") for item in items if item.get("name")), "")
            yield activity_row(
                context,
                category="recent-document",
                relative_key=target_relative,
                key=target,
                value_name=name,
                activity_value=text,
                mru_position=positions.get(name),
                extra={
                    "extension_scope": str(target.name) if target is not key else "",
                    "lnk_name": lnk_name,
                },
            )


def numbered_string_records(
    context: NativeHiveRowContext, relative: str, category: str, *, prefix: str
) -> Iterable[ArtifactRecord]:
    hive = context.hive
    key = hive.open_key(relative)
    if key is None:
        return
    times_key = hive.open_key(relative + "Time") if category == "typed-url" else None
    times = hive.values_dict(times_key) if times_key is not None else {}
    for value in hive.values(key):
        name = str(value.name)
        if not name.lower().startswith(prefix) or not name[len(prefix) :].isdigit():
            continue
        position = int(name[len(prefix) :]) - 1
        typed_time = registry_filetime_from_bytes(times.get(name)) if name in times else ""
        yield activity_row(
            context,
            category=category,
            relative_key=relative,
            key=key,
            value_name=name,
            activity_value=registry_text(hive.value_data(value)),
            mru_position=position,
            timestamp=typed_time,
            timestamp_label="typed_url_time" if typed_time else "",
        )


def run_mru_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    hive = context.hive
    relative = f"{NTUSER_EXPLORER}\\RunMRU"
    key = hive.open_key(relative)
    if key is None:
        return
    positions = mru_positions(hive, key)
    for value in hive.values(key):
        name = str(value.name)
        if name == "MRUList":
            continue
        command = registry_text(hive.value_data(value))
        yield activity_row(
            context,
            category="run-dialog-mru",
            relative_key=relative,
            key=key,
            value_name=name,
            activity_value=command.removesuffix("\\1"),
            mru_position=positions.get(name),
        )


def open_save_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    from .shellbags import decode_shell_item_list

    hive = context.hive
    relative = f"{NTUSER_EXPLORER}\\ComDlg32\\OpenSavePidlMRU"
    key = hive.open_key(relative)
    if key is None:
        return
    for extension in hive.subkeys(key):
        positions = mru_positions(hive, extension)
        for value in hive.values(extension):
            name = str(value.name)
            if not name.isdigit():
                continue
            path, _items = decode_shell_item_list(hive.value_bytes(value))
            yield activity_row(
                context,
                category="file-dialog-mru",
                relative_key=f"{relative}\\{extension.name}",
                key=extension,
                value_name=name,
                activity_value=path,
                mru_position=positions.get(name),
                extra={"extension_scope": str(extension.name)},
            )


def last_visited_records(context: NativeHiveRowContext) -> Iterable[ArtifactRecord]:
    from .shellbags import decode_shell_item_list

    hive = context.hive
    relative = f"{NTUSER_EXPLORER}\\ComDlg32\\LastVisitedPidlMRU"
    key = hive.open_key(relative)
    if key is None:
        return
    positions = mru_positions(hive, key)
    for value in hive.values(key):
        name = str(value.name)
        if not name.isdigit():
            continue
        raw = hive.value_bytes(value)
        program = decode_registry_sz(raw)
        consumed = len(program.encode("utf-16-le")) + 2
        folder, _items = decode_shell_item_list(raw[consumed:])
        yield activity_row(
            context,
            category="file-dialog-folder-mru",
            relative_key=relative,
            key=key,
            value_name=name,
            activity_value=folder,
            mru_position=positions.get(name),
            extra={"program": program},
        )


# ---------------------------------------------------------------------------
# Native key tree rows and free-cell (deleted) candidates.
# ---------------------------------------------------------------------------


def build_native_key_tree_record(
    context: NativeHiveRowContext,
    components: tuple[str, ...],
    key: NativeRegistryKey,
    value_names: Sequence[str],
) -> ArtifactRecord:
    relative = "\\".join(components)
    key_path = context.key_path(relative)
    return ArtifactRecord(
        provider=WindowsRegistryProvider.name,
        artifact_type="registry-key-tree-node",
        path=context.source_path,
        supported=True,
        details={
            "parser": "windows-registry-hive-key-tree",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-hive-key-tree",
            "reportability": "triage",
            "source_path": context.source_path,
            "source_format": "registry-hive",
            "source_hashes": context.source_hashes,
            "hive_name": context.path.name,
            "hive_hint": context.hive_hint,
            "hive_mount": context.mount,
            "user_sid": context.user_sid,
            "key_path": key_path,
            "key_depth": len(components),
            "key_path_confidence": "tree-walk",
            "is_root_key": not components,
            "root_reachable": True,
            "name": str(key.name),
            "name_encoding": key.name_encoding,
            "last_written_at": key.last_written_at,
            "last_written_filetime": key.last_written_filetime,
            "subkey_count": key.subkey_count,
            "value_count": key.value_count,
            "value_names": list(value_names),
            "cell_offset": HIVE_BIN_BASE_OFFSET + int(key.offset or 0),
            "parent_cell_offset": HIVE_BIN_BASE_OFFSET + int(key.parent_offset or 0) if components else 0,
            "allocation_status": "allocated" if key.allocated else "free-cell-referenced",
            "transaction_log_status": context.transaction_disclosure.get("status", ""),
        },
    )


def iter_registry_free_cell_candidates(hive: NativeRegistryHive) -> tuple[list[dict[str, object]], dict[str, int]]:
    """hbin walk over the whole hive; returns free nk/vk cells (no cap) and allocator stats."""
    data = hive._data
    candidates: list[dict[str, object]] = []
    stats: Counter[str] = Counter()
    offset = HIVE_BIN_BASE_OFFSET
    end = hive.hbin_end
    while offset + HIVE_BIN_HEADER_SIZE <= end:
        if data[offset : offset + 4] != REGISTRY_HBIN_SIGNATURE:  # type: ignore[index]
            stats["hbin-signature-gap"] += 1
            offset += 4096
            continue
        hbin_size = int.from_bytes(data[offset + 8 : offset + 12], "little")  # type: ignore[index]
        if hbin_size < 4096 or hbin_size % 4096:
            stats["hbin-size-invalid"] += 1
            offset += 4096
            continue
        stats["hbin_count"] += 1
        hbin_end = min(end, offset + hbin_size)
        cursor = offset + HIVE_BIN_HEADER_SIZE
        while cursor + 8 <= hbin_end:
            raw_size = int.from_bytes(data[cursor : cursor + 4], "little", signed=True)  # type: ignore[index]
            size = abs(raw_size)
            if size < 8 or cursor + size > hbin_end:
                stats["cell-walk-break"] += 1
                break
            signature = bytes(data[cursor + 4 : cursor + 6])  # type: ignore[index]
            if signature == b"nk":
                stats["allocated_nk" if raw_size < 0 else "free_nk"] += 1
            elif signature == b"vk":
                stats["allocated_vk" if raw_size < 0 else "free_vk"] += 1
            if raw_size > 0 and signature in (b"nk", b"vk"):
                cell = bytes(data[cursor : cursor + size])  # type: ignore[index]
                if signature == b"nk":
                    candidate = parse_registry_nk_cell(cell, 0, 4, size, raw_size)
                else:
                    candidate = parse_registry_vk_cell(cell, 0, 4, size, raw_size)
                if candidate is not None:
                    candidate["cell_offset"] = cursor
                    candidate["cell_relative_offset"] = cursor - HIVE_BIN_BASE_OFFSET
                    candidate["cell_scan_method"] = "hbin-walk"
                    candidate["hbin_offset"] = offset
                    candidate["cell_index"] = len(candidates)
                    if signature == b"nk":
                        relative_parent = int(candidate.get("parent_cell_relative_offset") or 0)
                        candidate["parent_cell_offset"] = registry_relative_to_file_offset(relative_parent)
                        candidate["stable_subkey_list_offset"] = 0
                        candidate["volatile_subkey_list_offset"] = 0
                        candidate["value_list_offset"] = registry_relative_to_file_offset(
                            int(candidate.get("value_list_relative_offset") or 0)
                        )
                    else:
                        if not candidate.get("value_data_inline"):
                            candidate["value_data_offset"] = registry_relative_to_file_offset(
                                int(candidate.get("value_data_relative_offset") or 0)
                            )
                    candidates.append(candidate)
            cursor += align_registry_cell_size(size)
        offset += hbin_size
    return candidates, dict(stats)


def native_parent_key_candidates(
    hive: NativeRegistryHive,
    free_candidates: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Allocated ancestor nk cells for free key cells, root renamed to '' (mount replaces it)."""
    root_offset = int(hive.header.get("root_cell_offset") or 0)
    seen: set[int] = set()
    ancestors: list[dict[str, object]] = []
    for candidate in free_candidates:
        relative = int(candidate.get("parent_cell_relative_offset") or 0) if candidate.get("cell_kind") == "key-node" else 0
        depth = 0
        while relative and relative not in seen and depth < 64:
            key = hive.key_at(relative)
            if key is None:
                break
            seen.add(relative)
            ancestors.append(
                {
                    "cell_kind": "key-node",
                    "cell_signature": "nk",
                    "cell_offset": HIVE_BIN_BASE_OFFSET + relative,
                    "cell_relative_offset": relative,
                    "allocation_status": "allocated",
                    "name": "" if relative == root_offset else str(key.name),
                    "name_encoding": key.name_encoding,
                    "last_written_at": key.last_written_at,
                    "parent_cell_offset": 0 if relative == root_offset else HIVE_BIN_BASE_OFFSET + int(key.parent_offset or 0),
                    "value_count": key.value_count,
                    "value_list_offset": HIVE_BIN_BASE_OFFSET + int(key.value_list_offset or 0),
                    "subkey_count": key.subkey_count,
                    "cell_scan_method": "native-tree-ancestor",
                    "hbin_offset": registry_hbin_offset_for_cell(HIVE_BIN_BASE_OFFSET + relative),
                    "cell_size": 0,
                }
            )
            if relative == root_offset:
                break
            relative = int(key.parent_offset or 0)
            depth += 1
    return ancestors


SERVICE_PROCESS_TYPES = {0x10, 0x20, 0x50, 0x60, 0x110, 0x120}


def registry_native_summary_facts(records: Sequence[ArtifactRecord]) -> dict[str, object]:
    """Report-facing facts (computer name, TZ, CCS, USB, persistence) from native plugin rows."""
    facts: dict[str, object] = {
        "native_key_count": 0,
        "native_value_count": 0,
        "computer_name": "",
        "timezone": {},
        "current_control_set": "",
        "last_shutdown_at": "",
        "os_version": {},
        "hives": [],
        "transaction_log_disclosures": [],
        "persistence_entries": [],
        "usb_devices": [],
    }
    hives: list[dict[str, object]] = []
    disclosures: list[dict[str, object]] = []
    persistence: list[dict[str, object]] = []
    usb_devices: list[dict[str, object]] = []
    for record in records:
        details = record.details
        artifact_type = record.artifact_type
        if artifact_type == "registry-hive" and details.get("native_walk"):
            facts["native_key_count"] = int(facts["native_key_count"]) + int(details.get("key_count") or 0)
            facts["native_value_count"] = int(facts["native_value_count"]) + int(details.get("value_count") or 0)
            hives.append(
                {
                    "source_path": details.get("source_path", record.path),
                    "hive_name": details.get("hive_name", ""),
                    "hive_mount": details.get("hive_mount", ""),
                    "root_key_name": details.get("root_key_name", ""),
                    "key_count": details.get("key_count", 0),
                    "value_count": details.get("value_count", 0),
                    "transaction_log_status": details.get("transaction_log_disclosure_status", ""),
                }
            )
            if details.get("transaction_log_disclosure_status") == "newer-sequence-not-replayed":
                disclosures.append(
                    {
                        "hive_mount": details.get("hive_mount", ""),
                        "source_path": details.get("source_path", record.path),
                        "message_ko": details.get("transaction_log_disclosure", ""),
                    }
                )
        elif artifact_type == "windows-computer-name" and not facts["computer_name"]:
            facts["computer_name"] = str(details.get("computer_name") or details.get("active_computer_name") or "")
        elif artifact_type == "windows-timezone" and not facts["timezone"]:
            facts["timezone"] = {
                "time_zone_key_name": details.get("time_zone_key_name", ""),
                "time_zone_label_ko": details.get("time_zone_label_ko", ""),
                "standard_name": details.get("standard_name", ""),
                "bias_minutes": details.get("bias_minutes"),
                "active_time_bias_minutes": details.get("active_time_bias_minutes"),
                "utc_offset": details.get("utc_offset", ""),
                "utc_offset_minutes": details.get("utc_offset_minutes"),
                "source_key": details.get("key_path", ""),
            }
        elif artifact_type == "windows-control-set" and not facts["current_control_set"]:
            facts["current_control_set"] = str(details.get("current_control_set") or "")
            facts["last_shutdown_at"] = str(details.get("last_shutdown_at") or "")
        elif artifact_type == "windows-os-version" and not facts["os_version"]:
            facts["os_version"] = {
                key: details.get(key)
                for key in ("product_name", "display_version", "current_build", "edition_id", "install_date")
            }
        elif artifact_type == "registry-persistence-entry":
            persistence.append(
                {
                    "category": details.get("persistence_category", ""),
                    "key": details.get("key_path", ""),
                    "value_name": details.get("value_name", ""),
                    "command": details.get("command", ""),
                    "key_last_written_at": details.get("key_last_written_at", ""),
                    "user_sid": details.get("user_sid", ""),
                    "risk_flags": list(details.get("risk_flags") or []),
                }
            )
        elif artifact_type == "windows-service-config" and details.get("autostart"):
            if details.get("service_type") in SERVICE_PROCESS_TYPES:
                persistence.append(
                    {
                        "category": "service",
                        "key": details.get("key_path", ""),
                        "value_name": details.get("service_name", ""),
                        "command": details.get("image_path", ""),
                        "service_dll": details.get("service_dll", ""),
                        "start_label": details.get("start_label", ""),
                        "key_last_written_at": details.get("key_last_written_at", ""),
                        "risk_flags": list(details.get("risk_flags") or []),
                    }
                )
        elif artifact_type == "windows-usb-device":
            usb_devices.append(
                {
                    "key": details.get("key_path", ""),
                    "vendor": details.get("vendor", ""),
                    "product": details.get("product", ""),
                    "friendly_name": details.get("friendly_name", ""),
                    "serial_number": details.get("serial_number", ""),
                    "serial_hint": details.get("serial_number", ""),
                    "vid": details.get("vid", ""),
                    "pid": details.get("pid", ""),
                    "first_install_at": details.get("first_install_at", ""),
                    "last_arrival_at": details.get("last_arrival_at", ""),
                    "last_removal_at": details.get("last_removal_at", ""),
                    "drive_letters": list(details.get("drive_letters") or []),
                    "volume_guids": list(details.get("volume_guids") or []),
                }
            )
    facts["hives"] = hives
    facts["transaction_log_disclosures"] = disclosures
    facts["persistence_entries"] = persistence
    facts["usb_devices"] = usb_devices
    return facts
