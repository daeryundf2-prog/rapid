from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.models import ArtifactRecord
from .common import build_forensic_review
from .registry import (
    MAX_HIVE_CELL_SCAN_BYTES,
    MAX_HIVE_STRING_SCAN_BYTES,
    build_registry_key_tree_records,
    candidate_registry_hive_paths,
    collect_reg_export,
    extract_utf16le_strings,
    file_hashes,
    hive_hint_from_path,
    iter_registry_cell_candidates,
    parse_registry_hive_header,
    registry_value_data_preview,
)

PARSER_VERSION = "windows-shellbags-native-v2"
SHELLBAG_USER_HIVES = {"NTUSER.DAT", "USRCLASS.DAT"}
SHELLBAG_BLOCKERS = [
    "binary shell item payload decoding is not report-grade yet",
    "bag/node relationships require validation against a dedicated ShellBags parser",
    "registry transaction logs are not replayed",
    "deleted or slack ShellBag testimony is not validated",
]
SHELLBAG_CAPABILITIES = {
    "reg_export_shellbag_key_mapping": True,
    "native_user_hive_key_tree_candidates": True,
    "native_string_pivot_candidates": True,
    "bag_id_candidate_extraction": True,
    "node_id_candidate_extraction": True,
    "key_last_write_timestamp_hint": True,
    "binary_shell_item_decode": False,
    "bag_node_relationship_validation": False,
    "transaction_log_replay": False,
    "deleted_slack_shellbag_validation": False,
}
MAX_NATIVE_SHELLBAG_CANDIDATES = 200


class WindowsShellbagsProvider:
    name = "windows-shellbags"
    description = "Windows ShellBags from Registry exports and native user-hive candidates"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        emitted = 0
        for path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            for record in collect_reg_export(path):
                key = str(record.details.get("key") or "").lower()
                if "shell\\bagmru" not in key and "shellnoroam\\bagmru" not in key:
                    continue
                details = dict(record.details)
                details["parser"] = "windows-shellbags-reg-export"
                yield ArtifactRecord(
                    provider=self.name,
                    artifact_type="shellbag-key",
                    path=record.path,
                    supported=True,
                    details=details,
                )
        for path in candidate_registry_hive_paths(root):
            if path.name.upper() not in SHELLBAG_USER_HIVES:
                continue
            for record in collect_native_shellbag_hive(path):
                if emitted >= MAX_NATIVE_SHELLBAG_CANDIDATES:
                    return
                emitted += 1
                yield record


def collect_native_shellbag_hive(path: Path) -> Iterable[ArtifactRecord]:
    try:
        stat_result = path.stat()
        with path.open("rb") as handle:
            header = handle.read(4096)
            handle.seek(0)
            blob = handle.read(min(stat_result.st_size, max(MAX_HIVE_STRING_SCAN_BYTES, MAX_HIVE_CELL_SCAN_BYTES)))
    except OSError:
        return

    metadata = parse_registry_hive_header(header)
    source_hashes = file_hashes(path)
    cell_candidates = iter_registry_cell_candidates(blob)
    value_by_offset = {
        int(candidate.get("cell_offset") or 0): candidate
        for candidate in cell_candidates
        if candidate.get("cell_kind") == "value"
    }
    emitted_paths: set[str] = set()

    for key_tree_record in build_registry_key_tree_records(path, blob, cell_candidates, metadata, source_hashes):
        key_details = key_tree_record.details
        source_key_path = str(key_details.get("key_path") or "")
        if not is_shellbag_source(source_key_path):
            continue
        value_offsets = [
            int(offset)
            for offset in key_details.get("value_cell_offsets", [])
            if isinstance(offset, int) or str(offset).isdigit()
        ]
        value_previews = {
            str(value_by_offset[offset].get("name") or ""): registry_value_data_preview(blob, value_by_offset[offset])
            for offset in value_offsets
            if offset in value_by_offset
        }
        emitted_paths.add(source_key_path.lower())
        yield build_native_shellbag_record(
            path,
            metadata,
            source_hashes,
            candidate_source="native-key-tree",
            source_key_path=source_key_path,
            value_names=[str(value) for value in key_details.get("value_names", [])],
            value_previews=value_previews,
            key_last_written_at=str(key_details.get("last_written_at") or ""),
            key_path_confidence=str(key_details.get("key_path_confidence") or ""),
            cell_offset=int(key_details.get("cell_offset") or 0),
            hbin_offset=int(key_details.get("hbin_offset") or 0),
            allocation_status=str(key_details.get("allocation_status") or ""),
        )

    for string_index, value in enumerate(extract_utf16le_strings(blob)):
        if not is_shellbag_source(value):
            continue
        if value.lower() in emitted_paths:
            continue
        yield build_native_shellbag_record(
            path,
            metadata,
            source_hashes,
            candidate_source="native-string-pivot",
            source_key_path=value,
            value_names=[],
            value_previews={},
            key_last_written_at="",
            key_path_confidence="string-pivot",
            cell_offset=0,
            hbin_offset=0,
            allocation_status="unknown",
            string_index=string_index,
        )


def build_native_shellbag_record(
    path: Path,
    metadata: Mapping[str, object],
    source_hashes: Mapping[str, str],
    *,
    candidate_source: str,
    source_key_path: str,
    value_names: Sequence[str],
    value_previews: Mapping[str, str],
    key_last_written_at: str,
    key_path_confidence: str,
    cell_offset: int,
    hbin_offset: int,
    allocation_status: str,
    string_index: int | None = None,
) -> ArtifactRecord:
    section = shellbag_section(source_key_path)
    bag_ids = shellbag_bag_id_candidates(source_key_path, value_names, value_previews, section)
    node_ids = shellbag_node_id_candidates(source_key_path, value_names, section)
    path_candidates = shellbag_path_candidates(source_key_path, value_previews.values())
    timestamp_candidates = shellbag_timestamp_candidates(key_last_written_at, metadata)
    checks = shellbag_validation_checks(
        metadata,
        candidate_source=candidate_source,
        source_key_path=source_key_path,
        key_last_written_at=key_last_written_at,
        bag_ids=bag_ids,
        node_ids=node_ids,
    )
    confidence = shellbag_candidate_confidence(checks, key_path_confidence, candidate_source)
    report_grade = shellbag_report_grade_assessment(
        shellbag_validation_matrix(checks),
        validation_required=True,
        extra_blockers=SHELLBAG_BLOCKERS,
    )
    details: dict[str, object] = {
        "parser": "windows-shellbags-native-hive",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-hive-key-tree-candidate"
        if candidate_source == "native-key-tree"
        else "native-hive-string-candidate",
        "reportability": "review",
        "source_path": str(path.resolve()),
        "source_format": "registry-hive",
        "source_hashes": dict(source_hashes),
        "hive_name": path.name,
        "hive_hint": hive_hint_from_path(path),
        "user_hive_scope": "ntuser" if path.name.upper() == "NTUSER.DAT" else "usrclass",
        "candidate_source": candidate_source,
        "source_key_path": source_key_path,
        "shellbag_section": section,
        "shellbag_path_candidates": path_candidates,
        "bag_id_candidates": bag_ids,
        "node_id_candidates": node_ids,
        "value_names": sorted(value_names),
        "value_previews": dict(sorted(value_previews.items())),
        "timestamp_candidates": timestamp_candidates,
        "shellbag_evidence": shellbag_evidence(
            source_key_path=source_key_path,
            section=section,
            bag_ids=bag_ids,
            node_ids=node_ids,
            path_candidates=path_candidates,
            timestamp_candidates=timestamp_candidates,
            value_names=value_names,
            candidate_source=candidate_source,
            allocation_status=allocation_status,
            cell_offset=cell_offset,
            hbin_offset=hbin_offset,
        ),
        "key_last_written_at": key_last_written_at,
        "key_path_confidence": key_path_confidence,
        "cell_offset": cell_offset,
        "hbin_offset": hbin_offset,
        "allocation_status": allocation_status,
        "parser_confidence": confidence,
        "evidence_strength": "registry-hive-shellbag-key-tree-candidate"
        if candidate_source == "native-key-tree"
        else "registry-hive-shellbag-string-candidate",
        "validation_required": True,
        "validation_guidance": (
            "Native ShellBags candidates expose key paths, bag/node IDs, and timestamp hints from bounded "
            "registry hive parsing. Validate folder shell-item payload decoding, transaction logs, and bag/node "
            "relationships with a dedicated ShellBags parser before report-grade use."
        ),
        "validation_checks": checks,
        "shellbag_validation_matrix": shellbag_validation_matrix(checks),
        "shellbag_report_grade_assessment": report_grade,
        "shellbag_native_capabilities": SHELLBAG_CAPABILITIES,
        "forensic_review": build_forensic_review(
            gap_id="#15",
            artifact_goal="ShellBags folder view history evidence",
            primary_evidence=[
                f"section={section}",
                f"bags={len(bag_ids)}",
                f"nodes={len(node_ids)}",
                f"timestamps={len(timestamp_candidates)}",
            ],
            validation_required=True,
            report_grade_assessment=report_grade,
            commercial_grade_ready=False,
            caveats=[
                "Binary shell item payload decoding is not complete.",
                "Bag/node relationships and transaction logs require external validation.",
            ],
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "risk_flags": ["folder-view-history", "native-shellbag-candidate", "user-activity:shellbag"],
        "risk_score": 45 if candidate_source == "native-key-tree" else 30,
        "raw_preview": source_key_path[:2000],
    }
    if string_index is not None:
        details["string_index"] = string_index
    return ArtifactRecord(
        provider=WindowsShellbagsProvider.name,
        artifact_type="shellbag-native-candidate",
        path=str(path.resolve()),
        supported=bool(metadata.get("regf_valid")),
        details=details,
    )


def shellbag_evidence(
    *,
    source_key_path: str,
    section: str,
    bag_ids: Sequence[str],
    node_ids: Sequence[str],
    path_candidates: Sequence[str],
    timestamp_candidates: Sequence[Mapping[str, object]],
    value_names: Sequence[str],
    candidate_source: str,
    allocation_status: str,
    cell_offset: int,
    hbin_offset: int,
) -> dict[str, object]:
    return {
        "key_evidence": {
            "source_key_path": source_key_path,
            "shellbag_section": section,
            "candidate_source": candidate_source,
            "allocation_status": allocation_status,
            "cell_offset": cell_offset,
            "hbin_offset": hbin_offset,
        },
        "relationship_evidence": {
            "bag_id_candidates": list(bag_ids),
            "node_id_candidates": list(node_ids),
            "bag_node_relationship_status": "candidate-from-key-path-and-values",
            "value_names": sorted(value_names),
        },
        "activity_evidence": {
            "path_candidates": list(path_candidates),
            "timestamp_candidates": [dict(item) for item in timestamp_candidates],
            "primary_timestamp": str(timestamp_candidates[0].get("timestamp") or "") if timestamp_candidates else "",
            "primary_timestamp_source": str(timestamp_candidates[0].get("source") or "") if timestamp_candidates else "",
        },
        "report_limitations": [
            "binary shell item payloads are not decoded",
            "BagMRU/Bags relationship is candidate-level only",
            "transaction logs and deleted shellbag slack are not replayed",
        ],
    }


def is_shellbag_source(value: str) -> bool:
    normalized = value.lower().replace("/", "\\")
    parts = [part for part in normalized.split("\\") if part]
    return "bagmru" in parts or ("bags" in parts and "shell" in parts)


def shellbag_section(source_key_path: str) -> str:
    normalized = source_key_path.lower().replace("/", "\\")
    parts = [part for part in normalized.split("\\") if part]
    if "bagmru" in parts:
        return "bagmru"
    if "bags" in parts:
        return "bags"
    return "unknown"


def shellbag_bag_id_candidates(
    source_key_path: str,
    value_names: Sequence[str],
    value_previews: Mapping[str, str],
    section: str,
) -> list[str]:
    candidates: set[str] = set()
    parts = [part for part in source_key_path.replace("/", "\\").split("\\") if part]
    if section == "bags":
        candidates.update(part for part in parts if part.isdigit())
    node_slot = value_previews.get("NodeSlot", "")
    if node_slot.isdigit():
        candidates.add(node_slot)
    for value in value_names:
        if value.lower() not in {"nodeslot", "bagid"}:
            continue
        preview = value_previews.get(value, "")
        if preview.isdigit():
            candidates.add(preview)
    return sorted(candidates, key=lambda item: (len(item), item))


def shellbag_node_id_candidates(source_key_path: str, value_names: Sequence[str], section: str) -> list[str]:
    candidates: set[str] = set()
    parts = [part for part in source_key_path.replace("/", "\\").split("\\") if part]
    if section == "bagmru":
        candidates.update(part for part in parts if part.isdigit())
        candidates.update(value for value in value_names if value.isdigit())
    return sorted(candidates, key=lambda item: (len(item), item))


def shellbag_path_candidates(source_key_path: str, values: Iterable[str]) -> list[str]:
    candidates: set[str] = set()
    for value in [source_key_path, *list(values)]:
        if re.search(r"(?i)[a-z]:\\", value) or value.startswith("\\\\"):
            candidates.add(value)
        if is_shellbag_source(value):
            candidates.add(value)
    return sorted(candidates)


def shellbag_timestamp_candidates(key_last_written_at: str, metadata: Mapping[str, object]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    if key_last_written_at:
        candidates.append(
            {
                "timestamp": key_last_written_at,
                "source": "registry_key_last_write",
                "confidence": "candidate",
            }
        )
    hive_timestamp = str(metadata.get("last_written_at") or "")
    if hive_timestamp:
        candidates.append(
            {
                "timestamp": hive_timestamp,
                "source": "hive_header_last_write",
                "confidence": "context",
            }
        )
    return candidates


def shellbag_validation_checks(
    metadata: Mapping[str, object],
    *,
    candidate_source: str,
    source_key_path: str,
    key_last_written_at: str,
    bag_ids: Sequence[str],
    node_ids: Sequence[str],
) -> dict[str, object]:
    return {
        "regf_header_valid": bool(metadata.get("regf_valid")),
        "native_key_tree_candidate": candidate_source == "native-key-tree",
        "native_string_pivot_candidate": candidate_source == "native-string-pivot",
        "key_path_contains_shellbags_root": is_shellbag_source(source_key_path),
        "has_key_last_write_timestamp": bool(key_last_written_at),
        "has_bag_id_candidate": bool(bag_ids),
        "has_node_id_candidate": bool(node_ids),
        "binary_shell_item_decoding_available": False,
        "transaction_log_replay_available": False,
        "deleted_shellbag_validation_available": False,
        "requires_dedicated_shellbags_parser": True,
    }


def shellbag_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    labels = {
        "regf_header_valid": ("Registry hive header", "critical"),
        "native_key_tree_candidate": ("Native key tree candidate", "high"),
        "native_string_pivot_candidate": ("Native string pivot candidate", "medium"),
        "key_path_contains_shellbags_root": ("ShellBags key path", "high"),
        "has_key_last_write_timestamp": ("Key last-write timestamp", "medium"),
        "has_bag_id_candidate": ("Bag ID candidate", "medium"),
        "has_node_id_candidate": ("Node ID candidate", "medium"),
        "binary_shell_item_decoding_available": ("Binary shell item decode", "critical"),
        "transaction_log_replay_available": ("Transaction log replay", "critical"),
        "deleted_shellbag_validation_available": ("Deleted ShellBag validation", "critical"),
        "requires_dedicated_shellbags_parser": ("Dedicated ShellBags parser", "critical"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append({"id": key.replace("_", "-"), "label": label, "passed": passed, "severity": severity, "detail": value})
    return matrix


def shellbag_report_grade_assessment(
    validation_matrix: list[dict[str, object]],
    *,
    validation_required: bool,
    extra_blockers: Sequence[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if not item.get("passed")]
    blockers = set(extra_blockers)
    blockers.update(f"validation-check-failed:{item}" for item in failed)
    if validation_required:
        blockers.add("shellbags-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if item.get("passed")],
        "commercial_gap_ids": ["#15"],
        "next_validation_step": "Validate ShellBag binary shell-item payloads, bag/node relationships, transaction logs, and deleted/slack candidates with a dedicated parser before report-grade use.",
    }


def shellbag_candidate_confidence(
    checks: Mapping[str, object],
    key_path_confidence: str,
    candidate_source: str,
) -> float:
    score = 0.3
    if checks.get("regf_header_valid"):
        score += 0.12
    if candidate_source == "native-key-tree":
        score += 0.12
    if key_path_confidence == "parent-chain":
        score += 0.1
    if checks.get("has_key_last_write_timestamp"):
        score += 0.08
    if checks.get("has_bag_id_candidate"):
        score += 0.06
    if checks.get("has_node_id_candidate"):
        score += 0.06
    return round(min(score, 0.74), 2)
