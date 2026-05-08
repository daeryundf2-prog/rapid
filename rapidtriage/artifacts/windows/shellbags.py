from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.forensic_accuracy import build_accuracy_gate
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
    registry_transaction_log_evidence,
    registry_transaction_replay_profile,
)

PARSER_VERSION = "windows-shellbags-native-v3"
SHELLBAG_USER_HIVES = {"NTUSER.DAT", "USRCLASS.DAT"}
SHELLBAG_BLOCKERS = [
    "binary shell item payload decoding is not report-grade yet",
    "bag/node relationships require validation against a dedicated ShellBags parser",
    "registry transaction logs are not replayed",
    "deleted or slack ShellBag testimony is not validated",
    "trusted ShellBags parser diff is required",
]
SHELLBAG_TRUSTED_TOOLS = {"shellbagsexplorer", "sbecmd", "recmd", "registryexplorer", "regripper"}
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
    transaction_log_evidence = registry_transaction_log_evidence(path)
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
            transaction_log_evidence=transaction_log_evidence,
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
            transaction_log_evidence=transaction_log_evidence,
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
    transaction_log_evidence: Mapping[str, object],
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
        transaction_log_evidence=transaction_log_evidence,
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
        "registry_transaction_log_evidence": dict(transaction_log_evidence),
        "registry_transaction_replay_profile": registry_transaction_replay_profile(
            transaction_log_evidence,
            dirty=bool(metadata.get("dirty")),
        ),
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
            transaction_log_evidence=transaction_log_evidence,
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
        "core_accuracy_gates": shellbag_core_accuracy_gates(
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "hive_name": path.name,
                "user_hive_scope": "ntuser" if path.name.upper() == "NTUSER.DAT" else "usrclass",
                "candidate_source": candidate_source,
                "source_key_path": source_key_path,
                "shellbag_section": section,
                "bag_id_candidates": bag_ids,
                "node_id_candidates": node_ids,
                "path_candidates": path_candidates,
                "timestamp_candidates": timestamp_candidates,
                "allocation_status": allocation_status,
                "cell_offset": cell_offset,
                "hbin_offset": hbin_offset,
                "validation_checks": checks,
            }
        ),
        "shellbag_validation_matrix": shellbag_validation_matrix(checks),
        "shellbag_report_grade_assessment": report_grade,
        "shellbag_native_capabilities": SHELLBAG_CAPABILITIES,
        "commercial_uplift_evidence": shellbag_commercial_uplift_evidence(
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "candidate_source": candidate_source,
                "source_key_path": source_key_path,
                "shellbag_section": section,
                "cell_offset": cell_offset,
                "hbin_offset": hbin_offset,
                "allocation_status": allocation_status,
                "shellbag_validation_matrix": shellbag_validation_matrix(checks),
                "shellbag_report_grade_assessment": report_grade,
            }
        ),
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
    transaction_log_evidence: Mapping[str, object],
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
            "transaction_log_status": str(transaction_log_evidence.get("status") or ""),
            "transaction_log_replay_applied": bool(transaction_log_evidence.get("transaction_log_replay_applied")),
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
    transaction_log_evidence: Mapping[str, object],
) -> dict[str, object]:
    return {
        "regf_header_valid": bool(metadata.get("regf_valid")),
        "native_key_tree_candidate": candidate_source == "native-key-tree",
        "native_string_pivot_candidate": candidate_source == "native-string-pivot",
        "key_path_contains_shellbags_root": is_shellbag_source(source_key_path),
        "has_key_last_write_timestamp": bool(key_last_written_at),
        "has_bag_id_candidate": bool(bag_ids),
        "has_node_id_candidate": bool(node_ids),
        "transaction_log_context_recorded": bool(transaction_log_evidence.get("status")),
        "transaction_log_input_present": int(transaction_log_evidence.get("present_count") or 0) > 0,
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
        "transaction_log_context_recorded": ("Transaction-log context recorded", "medium"),
        "transaction_log_input_present": ("Transaction-log input present", "medium"),
        "binary_shell_item_decoding_available": ("Binary shell item decode", "critical"),
        "transaction_log_replay_available": ("Transaction log replay", "critical"),
        "deleted_shellbag_validation_available": ("Deleted ShellBag validation", "critical"),
        "requires_dedicated_shellbags_parser": ("Dedicated ShellBags parser", "critical"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key == "transaction_log_input_present":
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append({"id": key.replace("_", "-"), "label": label, "passed": passed, "severity": severity, "detail": value})
    return matrix


def shellbag_core_accuracy_gates(details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("shellbag_trusted_diff")
        if isinstance(details.get("shellbag_trusted_diff"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"cell_offset:{details.get('cell_offset', '')}",
        f"hbin_offset:{details.get('hbin_offset', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if details.get("bag_id_candidates") or details.get("node_id_candidates") or details.get("shellbag_section") in {"bagmru", "bags"}:
        satisfied.append("BagMRU/Bags relationship")
    if checks.get("binary_shell_item_decoding_available"):
        satisfied.append("shell item binary decoding")
    if details.get("timestamp_candidates"):
        satisfied.append("timestamp source labeling")
    if details.get("user_hive_scope") in {"ntuser", "usrclass"} or str(details.get("hive_name") or "").upper() in {"NTUSER.DAT", "USRCLASS.DAT"}:
        satisfied.append("UsrClass/NTUSER correlation")
    if checks.get("transaction_log_context_recorded") or details.get("registry_transaction_log_evidence"):
        satisfied.append("transaction log context recorded")
    if not SHELLBAG_CAPABILITIES["deleted_slack_shellbag_validation"]:
        satisfied.append("deleted/slack validation warning")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted ShellBags parser diff pass")
    return [build_accuracy_gate(15, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


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


def shellbag_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("shellbag_validation_matrix") if isinstance(details.get("shellbag_validation_matrix"), list) else []
    report_grade = (
        details.get("shellbag_report_grade_assessment")
        if isinstance(details.get("shellbag_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("shellbag_trusted_diff")
        if isinstance(details.get("shellbag_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    reportability_decision = shellbag_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-011-015",
        "item_numbers": [15],
        "implementation_track": "native-parser-depth",
        "objective": "Expose ShellBags key-tree evidence, offset provenance, shell-item decoding blockers, and transaction-log gaps.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"cell_offset:{details.get('cell_offset', '')}",
            f"hbin_offset:{details.get('hbin_offset', '')}",
            f"section:{details.get('shellbag_section', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": reportability_decision,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "shellbag_trusted_diff": trusted_diff,
        "large_data_controls": {
            "bounded_hive_scan": True,
            "max_hive_scan_bytes": MAX_HIVE_CELL_SCAN_BYTES,
            "allocation_status": str(details.get("allocation_status") or ""),
            "shell_item_binary_decode_required_for_commercial_claims": True,
            "transaction_log_replay_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish Shell Item binary decoding, BagMRU/Bags relationship validation, and transaction-log replay.",
        "external_evidence_required": True,
    }


def shellbag_reportability_decision(
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("shellbag-binary-shell-item-decode-required")
    blockers.add("shellbag-transaction-log-replay-required")
    blockers.add("shellbags-trusted-diff-required")
    return {
        "profile_version": "shellbag-reportability-decision-v1",
        "commercial_gap_id": "#15",
        "decision": "do-not-report-folder-access-as-final",
        "allowed_use": "folder-view-history-triage-pivot",
        "blockers": sorted(blockers),
        "source_location_available": bool(details.get("cell_offset") not in (None, "") or details.get("source_hashes")),
        "required_before_report": [
            "binary shell-item payload decoded and validated",
            "BagMRU/Bags relationship diffed against dedicated parser",
            "transaction logs replayed or explicit absence documented",
            "deleted/slack ShellBag candidates validated before testimony",
        ],
    }


def build_shellbag_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_shellbag_diff_payload(
        index_shellbag_rows(rapid_rows),
        index_shellbag_rows(trusted_rows),
        trusted_tool=trusted_tool,
    )


def index_shellbag_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = shellbag_diff_row_payload(row)
        evidence = payload.get("shellbag_evidence") if isinstance(payload.get("shellbag_evidence"), Mapping) else {}
        key_evidence = evidence.get("key_evidence") if isinstance(evidence.get("key_evidence"), Mapping) else {}
        relationship = evidence.get("relationship_evidence") if isinstance(evidence.get("relationship_evidence"), Mapping) else {}
        activity = evidence.get("activity_evidence") if isinstance(evidence.get("activity_evidence"), Mapping) else {}

        source_key_path = normalized_diff_value(
            first_present(
                first_alias(payload, "source_key_path", "key_path", "registry_path", "keypath"),
                first_alias(key_evidence, "source_key_path", "key_path", "registry_path", "keypath"),
            )
        )
        folder_path = normalized_diff_list(
            first_present(
                first_alias(payload, "folder_path", "shellbag_path", "path", "target_path", "shellbag_path_candidates", "path_candidates"),
                first_alias(activity, "folder_path", "shellbag_path", "path", "target_path", "path_candidates"),
            )
        )
        bag_id = normalized_diff_list(
            first_present(
                first_alias(payload, "bag_id", "bag", "bag_id_candidates", "bagid"),
                first_alias(relationship, "bag_id", "bag", "bag_id_candidates", "bagid"),
            )
        )
        node_id = normalized_diff_list(
            first_present(
                first_alias(payload, "node_id", "node", "node_id_candidates", "nodeid"),
                first_alias(relationship, "node_id", "node", "node_id_candidates", "nodeid"),
            )
        )
        key = source_key_path or "|".join(item for item in (folder_path, bag_id, node_id) if item)
        if not key:
            continue
        indexed[key] = {
            "source_key_path": source_key_path,
            "folder_path": folder_path,
            "bag_id": bag_id,
            "node_id": node_id,
            "timestamp": normalized_diff_value(
                first_present(
                    first_alias(payload, "timestamp", "key_last_written_at", "last_write_time", "lastwritetime"),
                    first_alias(activity, "primary_timestamp", "timestamp", "key_last_written_at", "last_write_time"),
                )
            ),
            "hive": normalized_diff_value(first_alias(payload, "hive_name", "hive", "source_hive")),
            "section": normalized_diff_value(
                first_present(
                    first_alias(payload, "shellbag_section", "section"),
                    first_alias(key_evidence, "shellbag_section", "section"),
                )
            ),
            "cell_offset": normalized_int_text(
                first_present(
                    first_alias(payload, "cell_offset", "key_cell_offset", "source_offset"),
                    first_alias(key_evidence, "cell_offset", "key_cell_offset", "source_offset"),
                )
            ),
            "hbin_offset": normalized_int_text(
                first_present(
                    first_alias(payload, "hbin_offset", "hbin"),
                    first_alias(key_evidence, "hbin_offset", "hbin"),
                )
            ),
            "allocation_status": normalized_diff_value(
                first_present(
                    first_alias(payload, "allocation_status", "allocated", "cell_state"),
                    first_alias(key_evidence, "allocation_status", "allocated", "cell_state"),
                )
            ),
            "transaction_status": normalized_diff_value(
                first_present(
                    first_alias(payload, "transaction_log_status", "transaction_status"),
                    first_alias(key_evidence, "transaction_log_status", "transaction_status"),
                )
            ),
        }
    return indexed


def shellbag_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def build_shellbag_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in SHELLBAG_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        "shellbag_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "shellbags-trusted-diff-v1",
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(common) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-shellbags-output-as-final",
            "blockers": [] if status == "pass" else ["shellbags-trusted-diff-required"],
        },
    }


def first_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def normalized_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def first_present(*values: object) -> object:
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [normalize_shellbag_list_item(item) for item in value]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalize_shellbag_list_item(value: object) -> str:
    if isinstance(value, Mapping):
        return str(first_alias(value, "path", "folder_path", "timestamp", "value", "id", "name") or "").strip()
    return str(value).strip()


def normalized_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return normalized_diff_value(text)


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
