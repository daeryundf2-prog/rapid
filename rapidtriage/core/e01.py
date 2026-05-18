from __future__ import annotations

import json
import hashlib
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from .audit import compute_sha256
from .forensic_accuracy import build_accuracy_gate
from .vsc import build_vsc_image_workflow_handoff

E01_REQUIRED_TOOLS = ("ewfmount", "mmls", "tsk_recover")
E01_SUFFIXES = (".e01", ".ex01")
DIRECT_IMAGE_HASH_LIMIT_BYTES = 128 * 1024 * 1024
E01_STAGE_CHECKPOINT_NAME = "rapidtriage-e01-stage-status.json"
E01_INTEGRATED_WORKFLOW_MANIFEST_VERSION = "e01-ex01-integrated-workflow-manifest-v1"
E01_REPORT_GRADE_VALIDATION_PLAN_VERSION = "e01-ex01-report-grade-validation-plan-v1"
IMAGE_STRESS_KNOWN_ANSWER_PROFILE_VERSION = "image-stress-known-answer-workflow-v1"
TOOL_PREFLIGHT_PROFILES: dict[str, dict[str, object]] = {
    "ewfmount": {
        "purpose": "Expose E01/Ex01 evidence as a read-only raw image through libewf.",
        "package": "libewf",
        "version_commands": (("ewfmount", "--version"), ("ewfmount", "-V")),
        "install_hint": "Install libewf/ewf-tools, then verify `ewfmount` is on PATH.",
        "windows_hint": "On Windows, use WSL2 with libewf installed or mount/export the image with a trusted forensic suite.",
    },
    "mmls": {
        "purpose": "Enumerate partitions and filesystem offsets before recovery.",
        "package": "sleuthkit",
        "version_commands": (("mmls", "--version"), ("mmls", "-V")),
        "install_hint": "Install Sleuth Kit, then verify `mmls` is on PATH.",
        "windows_hint": "On Windows, install Sleuth Kit in WSL2 or use a trusted tool to export the filesystem folder.",
    },
    "tsk_recover": {
        "purpose": "Recover files from the selected partition into the run output directory.",
        "package": "sleuthkit",
        "version_commands": (("tsk_recover", "--version"), ("tsk_recover", "-V")),
        "install_hint": "Install Sleuth Kit, then verify `tsk_recover` is on PATH.",
        "windows_hint": "On Windows, prefer WSL2 or a vendor export if native Sleuth Kit recovery is unavailable.",
    },
}
E01_NATIVE_CAPABILITIES = {
    "ewf_libewf_mount_orchestration": True,
    "source_integrity_preflight": True,
    "partition_table_enumeration": True,
    "sleuthkit_filesystem_recovery": True,
    "command_history_capture": True,
    "native_e01_segment_metadata_decode": False,
    "native_compression_error_recovery": False,
    "encrypted_volume_unlock_workflow": False,
    "large_known_answer_validation_corpus": False,
}
E01_REPORT_GRADE_BLOCKERS = [
    "native-e01-ex01-segment-metadata-decoding-not-implemented",
    "external-tool-fuse-platform-behavior-validation-required",
    "encrypted-volume-unlock-workflow-not-implemented",
    "deleted-corrupt-filesystem-recovery-delegated-to-sleuthkit",
    "large-known-answer-e01-ex01-corpus-required",
]
E01_VALIDATION_TOOLS = ("ewfverify", "fls", "fsstat")
E01_FAILURE_GUIDANCE: dict[str, dict[str, object]] = {
    "missing-tool": {
        "title": "Required E01 tool is missing",
        "analyst_message": "Direct E01 extraction cannot start until libewf/Sleuth Kit tools are available.",
        "next_actions": [
            "Install libewf/ewf-tools and Sleuth Kit, preferably in WSL2 on Windows.",
            "Or mount/export the image read-only with a trusted forensic suite and scan the exported folder.",
        ],
    },
    "unsupported-image": {
        "title": "Unsupported or missing E01 input",
        "analyst_message": "The selected path is not a readable E01/Ex01 image.",
        "next_actions": [
            "Confirm the path exists and has a supported .E01 or .Ex01 suffix.",
            "For split EWF sets, keep all segments together and select the first image segment.",
        ],
    },
    "encrypted-volume": {
        "title": "Encrypted or locked volume suspected",
        "analyst_message": "The image may contain an encrypted volume that needs a lawful unlock workflow before filesystem recovery.",
        "next_actions": [
            "Record the encryption indicator in case notes.",
            "Unlock or export the decrypted filesystem with an authorized forensic workflow, then scan that folder.",
        ],
    },
    "corrupt-image": {
        "title": "Corrupt or damaged image suspected",
        "analyst_message": "The image or exposed raw stream appears damaged, truncated, or unreadable.",
        "next_actions": [
            "Run ewfverify or the acquisition tool's validation workflow and preserve the transcript.",
            "Try a trusted forensic suite export and attach the export log if direct recovery fails.",
        ],
    },
    "unsupported-filesystem": {
        "title": "Unsupported filesystem or volume layout",
        "analyst_message": "RapidForensic did not find a supported filesystem partition for direct recovery.",
        "next_actions": [
            "Review the partition table manually and confirm the correct start sector.",
            "If the filesystem is unsupported, export the filesystem with a trusted tool and scan the exported folder.",
        ],
    },
    "partition-ambiguity": {
        "title": "Partition selection needs analyst review",
        "analyst_message": "RapidForensic could not confidently select a supported filesystem partition.",
        "next_actions": [
            "Review the partition table with mmls or a trusted forensic suite.",
            "Retry with --e01-partition-start-sector when the correct filesystem start sector is known.",
        ],
    },
    "permission": {
        "title": "Permission or mount access problem",
        "analyst_message": "The workstation could not access the image, mount point, or recovered output path.",
        "next_actions": [
            "Check filesystem permissions and confirm the output directory is writable.",
            "On macOS/Linux, verify FUSE/libewf permissions; on Windows, prefer WSL2 or trusted export.",
        ],
    },
    "external-tool-failure": {
        "title": "External forensic tool failed",
        "analyst_message": "libewf or Sleuth Kit returned an error during mount, partition enumeration, or recovery.",
        "next_actions": [
            "Review the captured command history and stderr in the E01 output JSON.",
            "Validate the image with a trusted tool and retry using a mounted/exported folder if needed.",
        ],
    },
}
IMAGE_WORKFLOW_TRUSTED_TOOLS = {
    "ewfverify",
    "libewf",
    "mmls",
    "fls",
    "tsk_recover",
    "sleuth kit",
    "qemu-img",
    "ftk imager",
    "encase",
    "x-ways",
    "magnet axiom",
    "axiom",
    "afflib",
    "aff4imager",
    "vendor export manifest",
}
IMAGE_WORKFLOW_TRUSTED_DIFF_BLOCKERS = {
    22: "e01-ex01-trusted-workflow-diff-required",
    23: "raw-split-trusted-recovery-diff-required",
    24: "virtual-disk-trusted-conversion-diff-required",
    25: "forensic-container-verified-export-manifest-required",
}
CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], Optional[str]]


class E01ExtractionError(RuntimeError):
    """Raised when an E01 image cannot be exposed as a triageable folder."""


@dataclass(frozen=True)
class E01ExtractionResult:
    source_path: Path
    stage_dir: Path
    mount_dir: Path
    raw_image_path: Path
    extract_dir: Path
    partition_start_sector: int
    partition_selection: dict[str, object] = field(default_factory=dict)
    source_integrity: dict[str, object] = field(default_factory=dict)
    tool_preflight: tuple[dict[str, object], ...] = ()
    partition_table: tuple[dict[str, object], ...] = ()
    command_history: tuple[dict[str, object], ...] = ()
    warnings: tuple[str, ...] = ()
    resume_status: dict[str, object] = field(default_factory=dict)
    recovered_root_manifest: dict[str, object] = field(default_factory=dict)
    segment_set_profile: dict[str, object] = field(default_factory=dict)
    commercial_grade_ready: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "command": "e01-extract",
            "source_path": str(self.source_path),
            "stage_dir": str(self.stage_dir),
            "mount_dir": str(self.mount_dir),
            "raw_image_path": str(self.raw_image_path),
            "extract_dir": str(self.extract_dir),
            "partition_start_sector": self.partition_start_sector,
            "tools": list(E01_REQUIRED_TOOLS),
            "source_integrity": self.source_integrity,
            "tool_preflight": list(self.tool_preflight),
            "preflight_summary": e01_preflight_summary(self.tool_preflight, missing_tools=[]),
            "partition_table": list(self.partition_table),
            "command_history": list(self.command_history),
            "warnings": list(self.warnings),
            "partition_selection": self.partition_selection,
            "partition_browser": build_e01_partition_browser_contract(
                partition_selection=self.partition_selection,
                partition_table=self.partition_table,
                direct_extract_ready=True,
                blocked_reason="",
            ),
            "vsc_workflow_handoff": build_vsc_image_workflow_handoff(
                current_root=self.extract_dir,
                source_kind="e01-ex01",
                source_path=self.source_path,
                stage_dir=self.stage_dir,
            ),
            "stage_control_contract": build_image_stage_control_contract(
                source_kind="e01-ex01",
                stage_dir=self.stage_dir,
                checkpoint_path=self.stage_dir / E01_STAGE_CHECKPOINT_NAME,
                resume_status=self.resume_status,
                stages=list(
                    (self.resume_status or {}).get("stage_rows")
                    or [
                        {"id": "dependency-preflight", "status": "completed"},
                        {"id": "partition-selection", "status": "completed"},
                        {"id": "filesystem-extraction", "status": "completed"},
                    ]
                ),
                checkpoint_supported=True,
                resume_supported=True,
            ),
            "resume_status": self.resume_status,
            "recovered_root_manifest": self.recovered_root_manifest,
            "segment_set_profile": self.segment_set_profile,
            "e01_provenance_profile": build_e01_provenance_profile(
                source_path=self.source_path,
                source_integrity=self.source_integrity,
                segment_set_profile=self.segment_set_profile,
                tool_preflight=self.tool_preflight,
                partition_selection=self.partition_selection,
                partition_table=self.partition_table,
                command_history=self.command_history,
                recovered_root_manifest=self.recovered_root_manifest,
                resume_status=self.resume_status,
                run_outputs=None,
            ),
            "e01_ex01_workflow_manifest": build_e01_ex01_integrated_workflow_manifest(
                source_path=self.source_path,
                source_integrity=self.source_integrity,
                segment_set_profile=self.segment_set_profile,
                tool_preflight=self.tool_preflight,
                preflight_summary=e01_preflight_summary(self.tool_preflight, missing_tools=[]),
                partition_selection=self.partition_selection,
                partition_table=self.partition_table,
                command_history=self.command_history,
                recovered_root_manifest=self.recovered_root_manifest,
                resume_status=self.resume_status,
                run_outputs=None,
                status_context="extraction-result",
            ),
            "commercial_grade_ready": self.commercial_grade_ready,
            "commercial_gap_ids": ["#22"],
            "validation_matrix": image_validation_matrix(
                gap_id="#22",
                source_integrity=bool(self.source_integrity),
                tool_preflight=bool(self.tool_preflight),
                partition_table=bool(self.partition_table),
                command_history=bool(self.command_history),
                native_complete=False,
            ),
            "core_accuracy_gates": image_core_accuracy_gates(
                22,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": self.source_integrity,
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.partition_table),
                    "partition_start_sector": self.partition_start_sector,
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "segment_set_profile": self.segment_set_profile,
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                },
            ),
            "image_report_grade_assessment": image_report_grade_assessment("#22", E01_REPORT_GRADE_BLOCKERS),
            "commercial_uplift_evidence": image_commercial_uplift_evidence(
                22,
                {
                    "source_path": str(self.source_path),
                    "source_integrity": self.source_integrity,
                    "tool_preflight": list(self.tool_preflight),
                    "partition_table": list(self.partition_table),
                    "partition_start_sector": self.partition_start_sector,
                    "command_history": list(self.command_history),
                    "warnings": list(self.warnings),
                    "segment_set_profile": self.segment_set_profile,
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                },
            ),
            "native_capabilities": dict(E01_NATIVE_CAPABILITIES),
            "commercial_grade_blockers": [
                "Requires independent known-answer validation across libewf/Sleuth Kit versions and malformed E01/Ex01 corpora.",
                "Mount/extract workflow depends on external tools and platform FUSE behavior.",
                "Deleted/corrupt filesystem recovery remains delegated to Sleuth Kit and must be validated per case.",
            ],
            "safety": {
                "read_only_source": True,
                "writes_to_stage_dir_only": True,
                "recommended_fallback": "Mount/export with a trusted forensic workflow, preserve that log, then scan the exported folder.",
            },
}


def is_e01_path(path: Path) -> bool:
    return path.suffix.lower() in E01_SUFFIXES


def ewf_segment_number(path: Path) -> int | None:
    suffix = path.suffix
    match = re.fullmatch(r"\.E(?P<number>\d{2})", suffix, flags=re.IGNORECASE)
    if match:
        return int(match.group("number"))
    match = re.fullmatch(r"\.Ex(?P<number>\d{2})", suffix, flags=re.IGNORECASE)
    if match:
        return int(match.group("number"))
    return None


def discover_e01_segments(source_path: Path) -> list[Path]:
    number = ewf_segment_number(source_path)
    if number is None:
        return [source_path]
    family_match = re.fullmatch(r"\.(?P<family>E|Ex)\d{2}", source_path.suffix, flags=re.IGNORECASE)
    if not family_match:
        return [source_path]
    family = family_match.group("family").lower()
    candidates: list[Path] = []
    for candidate in source_path.parent.iterdir():
        if candidate.stem != source_path.stem:
            continue
        candidate_number = ewf_segment_number(candidate)
        if candidate_number is None:
            continue
        candidate_family = "ex" if candidate.suffix.lower().startswith(".ex") else "e"
        if candidate_family != family:
            continue
        candidates.append(candidate.resolve())
    return sorted(candidates or [source_path], key=lambda path: ewf_segment_number(path) or 0)


def build_e01_segment_set_profile(source_path: Path) -> dict[str, object]:
    segments = discover_e01_segments(source_path)
    numbers = [number for path in segments if (number := ewf_segment_number(path)) is not None]
    warnings: list[str] = []
    if numbers:
        expected = list(range(min(numbers), max(numbers) + 1))
        missing = sorted(set(expected) - set(numbers))
        if missing:
            warnings.append(f"EWF split sequence appears to have missing segment numbers: {missing}")
        if min(numbers) != 1:
            warnings.append(f"EWF split sequence starts at {min(numbers)}; select the first segment or confirm earlier segments are absent.")
    if source_path.resolve() != segments[0].resolve():
        warnings.append(f"Selected segment is not the first discovered EWF segment: first={segments[0].name}")
    return {
        "profile_version": "ewf-segment-set-v1",
        "selected_segment": str(source_path.resolve()),
        "segment_count": len(segments),
        "segment_numbers": numbers,
        "contiguous": not warnings or not any("missing segment" in warning for warning in warnings),
        "selected_is_first_segment": source_path.resolve() == segments[0].resolve(),
        "total_size_bytes": sum(path.stat().st_size for path in segments if path.is_file()),
        "segments": [
            {
                "path": str(path),
                "name": path.name,
                "segment_number": ewf_segment_number(path),
                "size": path.stat().st_size if path.is_file() else 0,
                "mtime_ns": path.stat().st_mtime_ns if path.is_file() else None,
            }
            for path in segments
        ],
        "warnings": warnings,
        "validation_status": "review-required" if warnings else "sequence-contiguous",
        "commercial_note": "This is filename/segment-order provenance, not native EWF segment-table decoding.",
    }


def build_e01_intake_profile(
    source_path: Path,
    *,
    source_integrity: Mapping[str, object] | None = None,
    segment_set_profile: Mapping[str, object] | None = None,
    max_hash_bytes: int = DIRECT_IMAGE_HASH_LIMIT_BYTES,
) -> dict[str, object]:
    """Describe what the analyst selected before any E01 processing starts.

    This is the GUI/API contract for checklist item #1. It intentionally avoids
    claiming native EWF parsing; it records the selected source, split-set
    inventory, bounded hash feasibility, and read-only posture so a user can
    decide whether to proceed or switch to a trusted export workflow.
    """

    resolved = source_path.expanduser().resolve()
    exists = resolved.is_file()
    supported_extension = is_e01_path(resolved)
    stat_payload: dict[str, object] = {}
    if exists:
        stat_result = resolved.stat()
        stat_payload = {
            "size_bytes": stat_result.st_size,
            "mtime_ns": stat_result.st_mtime_ns,
        }
    integrity = dict(source_integrity or (describe_source_integrity(resolved) if exists else {}))
    segment_profile = dict(
        segment_set_profile
        or (
            build_e01_segment_set_profile(resolved)
            if exists and supported_extension
            else {
                "profile_version": "ewf-segment-set-v1",
                "selected_segment": str(resolved),
                "segment_count": 0,
                "segment_numbers": [],
                "segments": [],
                "warnings": ["source image is missing or is not a supported E01/Ex01 path"],
                "validation_status": "missing-or-unsupported",
            }
        )
    )
    source_size = int(stat_payload.get("size_bytes") or integrity.get("size") or 0)
    profile: dict[str, object] = {
        "profile_version": "e01-intake-profile-v1",
        "checklist_item": 1,
        "qc_gap_id": "#1",
        "source": {
            "path": str(resolved),
            "filename": resolved.name,
            "extension": resolved.suffix.lower(),
            "exists": exists,
            "supported_extension": supported_extension,
            **stat_payload,
        },
        "source_signature": {
            "path": str(resolved),
            "filename": resolved.name,
            "size_bytes": source_size,
            "mtime_ns": stat_payload.get("mtime_ns"),
            "segment_count": int(segment_profile.get("segment_count") or 0),
            "selected_segment": segment_profile.get("selected_segment") or str(resolved),
        },
        "segment_set_profile": segment_profile,
        "hash_feasibility": {
            "preflight_hash_algorithm": integrity.get("hash_algorithm", "sha256"),
            "preflight_hash_status": integrity.get("hash_status", "not-run"),
            "preflight_sha256": integrity.get("sha256"),
            "max_preflight_hash_bytes": max_hash_bytes,
            "source_size_bytes": source_size,
            "full_hash_feasible_in_preflight": bool(exists and source_size <= max_hash_bytes),
            "full_image_hash_required_before_report": True,
            "acquisition_hash_warning": (
                "Full source hash was computed in preflight."
                if integrity.get("hash_status") == "computed"
                else "Attach an acquisition/full-image hash before report-grade use."
            ),
        },
        "read_only_posture": {
            "source_open_mode": "read-only",
            "writes_to_source": False,
            "writes_to_source_folder": False,
            "writes_to_stage_or_output_only": True,
            "operator_warning": "Do not write outputs next to the original evidence image unless the location is a separate working copy.",
        },
        "processing_decision": {
            "can_continue_to_dependency_preflight": bool(exists and supported_extension),
            "blocked_reason": ""
            if exists and supported_extension
            else "Select a readable .E01/.Ex01 first segment before processing.",
            "next_stage": "dependency-preflight" if exists and supported_extension else "select-supported-e01",
        },
        "reportability_decision": {
            "decision": "intake-ready-for-triage" if exists and supported_extension else "intake-blocked",
            "allowed_use": "source-selection-and-preflight-context",
            "not_allowed_use": "native-EWF-parser-completeness-claim",
            "required_before_report": [
                "full source/acquisition hash",
                "segment set inventory",
                "dependency preflight",
                "partition selection",
                "trusted-tool or known-answer validation when making report-grade claims",
            ],
        },
    }
    profile["manifest_sha256"] = stable_manifest_sha256(profile)
    return profile


def missing_e01_tools(tool_resolver: ToolResolver = shutil.which) -> list[str]:
    return [tool for tool in E01_REQUIRED_TOOLS if tool_resolver(tool) is None]


def e01_preflight_summary(
    tool_preflight: Sequence[Mapping[str, object]],
    *,
    missing_tools: Sequence[str] | None = None,
) -> dict[str, object]:
    rows = list(tool_preflight)
    missing = list(missing_tools) if missing_tools is not None else [
        str(row.get("tool")) for row in rows if not row.get("available")
    ]
    available = [str(row.get("tool")) for row in rows if row.get("available")]
    version_missing = [
        str(row.get("tool"))
        for row in rows
        if row.get("available") and not row.get("version")
    ]
    status = "ready" if rows and not missing else "blocked"
    if status == "ready" and version_missing:
        status = "ready-version-unverified"
    remediation_steps = [
        str(TOOL_PREFLIGHT_PROFILES.get(tool, {}).get("install_hint") or f"Install {tool} and ensure it is on PATH.")
        for tool in missing
    ]
    if missing:
        remediation_steps.append("If this workstation cannot install the tools, mount/export the image read-only with a trusted forensic suite and scan the exported folder.")
    return {
        "profile_version": "e01-dependency-preflight-v2",
        "status": status,
        "required_tools": list(E01_REQUIRED_TOOLS),
        "available_tools": available,
        "missing_tools": missing,
        "available_count": len(available),
        "missing_count": len(missing),
        "version_unverified_tools": version_missing,
        "blocked": bool(missing),
        "direct_extract_ready": bool(rows and not missing),
        "remediation_steps": remediation_steps,
        "windows_guidance": [
            "Use WSL2 with libewf and Sleuth Kit installed for direct extraction, or scan a trusted read-only export folder.",
            "Keep the external mount/export log with the RapidForensic run output.",
        ],
        "fallback_strategy": "mount-or-export-first" if missing else "auto-extract-then-scan",
        "operator_message": (
            f"Missing E01 tools: {', '.join(missing)}. Install libewf/Sleuth Kit or mount/export first."
            if missing
            else "All required E01 tools are available; direct extraction can be attempted."
        ),
    }


def e01_failure_guidance(message: str) -> dict[str, object]:
    lowered = message.lower()
    if "requires external tools" in lowered or "missing e01 tools" in lowered:
        category = "missing-tool"
    elif any(token in lowered for token in ("bitlocker", "encrypted", "locked volume", "decrypt")):
        category = "encrypted-volume"
    elif any(token in lowered for token in ("corrupt", "damaged", "truncated", "checksum", "bad sector", "read error")):
        category = "corrupt-image"
    elif any(token in lowered for token in ("unsupported filesystem", "supported filesystem", "unsupported fs", "unsupported volume")):
        category = "unsupported-filesystem"
    elif any(token in lowered for token in ("could not find", "requested partition", "partition start sector")):
        category = "partition-ambiguity"
    elif "not found" in lowered or "unsupported e01 image extension" in lowered:
        category = "unsupported-image"
    elif any(token in lowered for token in ("permission", "operation not permitted", "access denied")):
        category = "permission"
    else:
        category = "external-tool-failure"
    profile = E01_FAILURE_GUIDANCE[category]
    return {
        "profile_version": "e01-failure-guidance-v1",
        "category": category,
        "title": profile["title"],
        "analyst_message": profile["analyst_message"],
        "next_actions": list(profile["next_actions"]),
        "raw_error": message,
    }


def build_e01_operator_runbook(
    source_path: Path,
    *,
    direct_extract_ready: bool,
    blocked_reason: str = "",
    partition_start_sector: int | None = None,
    output_dir_hint: str = "./rapidtriage-run-e01",
    mode: str = "hacking",
) -> dict[str, object]:
    source_text = str(source_path)
    partition_arg = (
        f" --e01-partition-start-sector {partition_start_sector}"
        if partition_start_sector is not None
        else ""
    )
    run_command = (
        f"rapidtriage run {json.dumps(source_text)} --mode {mode} "
        f"--output-dir {output_dir_hint}{partition_arg} --resume"
    )
    return {
        "profile_version": "windows11-e01-operator-runbook-v1",
        "goal": "Move one Windows 11 E01/Ex01 case from input selection through extraction, analysis, search, review, and report export.",
        "direct_extract_ready": direct_extract_ready,
        "blocked_reason": blocked_reason,
        "recommended_commands": {
            "preflight": f"rapidtriage evidence {json.dumps(source_text)} --json --output {output_dir_hint}/rapidtriage-evidence-preflight.json",
            "plan_or_smoke": f"rapidtriage e01-smoke {json.dumps(source_text)} --output-dir {output_dir_hint}/e01-smoke --plan-only --json",
            "run": run_command,
            "review": f"rapidtriage web --root {output_dir_hint}",
        },
        "gui_flow": [
            {
                "step": 1,
                "label": "Select E01/Ex01",
                "user_action": "Select the first EWF segment; keep all E01/E02/... or Ex01/Ex02/... segments in the same folder.",
                "success_evidence": "segment_set_profile shows selected_is_first_segment=true and no missing segment warnings.",
            },
            {
                "step": 2,
                "label": "Dependency check",
                "user_action": "Confirm ewfmount, mmls, and tsk_recover are available, or switch to trusted export folder input.",
                "success_evidence": "preflight_summary.status is ready or ready-version-unverified.",
            },
            {
                "step": 3,
                "label": "Partition selection",
                "user_action": "Use automatic largest supported Windows filesystem first, or enter a verified mmls start sector.",
                "success_evidence": "partition_selection.selected_start_sector is recorded with requested/recommended sector provenance.",
            },
            {
                "step": 4,
                "label": "Read-only extraction",
                "user_action": "Recover to the run output stage; never write into the source image folder.",
                "success_evidence": "rapidtriage-e01.json records command_history and recovered_root_manifest hashes.",
            },
            {
                "step": 5,
                "label": "Artifact analysis",
                "user_action": "Run Windows artifact collectors, file/document indexing, timeline, and indicators from the extracted root.",
                "success_evidence": "run summary contains manifest/docs/files/artifacts/timeline/indicators outputs.",
            },
            {
                "step": 6,
                "label": "Search, review, report",
                "user_action": "Search globally, open source viewers, tag evidence, then export reviewed report candidates.",
                "success_evidence": "report/export items preserve source hashes, parser versions, offsets or source locators, and review status.",
            },
        ],
        "expected_outputs": [
            "rapidtriage-evidence-preflight.json",
            "rapidtriage-e01.json",
            "rapidtriage-run-summary.json",
            "rapidtriage-run-report.md",
            "rapidtriage-case.db when web/review workflow is used",
        ],
        "large_case_controls": [
            "Use --resume so extraction and analysis can continue after interruption.",
            "Use --max-file-count and --max-extract-size-bytes for first-pass triage on very large evidence.",
            "Use the web result table cursor/virtualized views instead of opening full raw JSON for review.",
        ],
        "report_limitations": [
            "Direct E01 support orchestrates libewf and Sleuth Kit; it is not a native commercial-grade EWF parser.",
            "Encrypted, malformed, corrupt, or deleted filesystem claims require trusted-tool comparison and known-answer validation.",
        ],
    }


def build_e01_partition_browser_contract(
    *,
    partition_selection: Mapping[str, object] | None,
    partition_table: Sequence[Mapping[str, object]] | None,
    direct_extract_ready: bool,
    blocked_reason: str = "",
) -> dict[str, object]:
    selection = dict(partition_selection or {})
    rows = []
    selected_sector = _optional_int(selection.get("selected_start_sector"))
    recommended_sector = _optional_int(selection.get("recommended_start_sector"))
    requested_sector = _optional_int(selection.get("requested_start_sector"))
    for index, partition in enumerate(partition_table or [], start=1):
        start_sector = _optional_int(partition.get("start_sector"))
        row = {
            "partition_number": partition.get("partition_number", partition.get("slot", index)),
            "start_sector": start_sector,
            "byte_offset": partition.get("byte_offset"),
            "size_bytes": partition.get("size_bytes"),
            "sector_count": partition.get("sector_count"),
            "filesystem_guess": partition.get("filesystem_guess") or "unknown",
            "description": partition.get("description") or "",
            "supported_filesystem_hint": bool(partition.get("supported_filesystem_hint")),
            "recommended_for_recovery": bool(partition.get("recommended_for_recovery"))
            or (recommended_sector is not None and start_sector == recommended_sector),
            "selected_for_recovery": bool(partition.get("selected_for_recovery"))
            or (selected_sector is not None and start_sector == selected_sector),
            "manual_override_allowed": True,
        }
        if row["recommended_for_recovery"]:
            row["recommendation"] = "recommended"
        elif row["supported_filesystem_hint"]:
            row["recommendation"] = "supported-alternative"
        else:
            row["recommendation"] = "review-before-use"
        rows.append(row)
    if selected_sector is None and rows:
        selected = next((row for row in rows if row["selected_for_recovery"]), None)
        selected_sector = _optional_int((selected or {}).get("start_sector"))
    status = "ready" if rows else ("pending-mmls" if direct_extract_ready else "blocked")
    return {
        "profile_version": "e01-partition-browser-v1",
        "qc_prep_item": 2,
        "goal": "Let analysts inspect the mmls partition table, accept the recommendation, or manually override the start sector before extraction.",
        "status": status,
        "blocked_reason": blocked_reason if status == "blocked" else "",
        "columns": [
            "partition_number",
            "start_sector",
            "size_bytes",
            "filesystem_guess",
            "recommendation",
            "manual_override",
        ],
        "partition_count": len(rows),
        "supported_partition_count": sum(1 for row in rows if row["supported_filesystem_hint"]),
        "partitions": rows,
        "selected_start_sector": selected_sector,
        "recommended_start_sector": recommended_sector,
        "requested_start_sector": requested_sector,
        "manual_override": {
            "enabled": True,
            "input_id": "e01PartitionStartSectorInput",
            "field": "start_sector",
            "warning": "Only override the sector after reviewing mmls or trusted-tool partition evidence.",
        },
        "empty_state": (
            "Run E01 extraction/smoke or attach trusted mmls output to populate the partition table."
            if direct_extract_ready
            else "Resolve E01 preflight blockers before partition enumeration."
        ),
        "validation_evidence_required": [
            "mmls partition table transcript",
            "selected/recommended start-sector provenance",
            "manual override reason when the selected sector differs from the recommendation",
        ],
    }


def _optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_image_stage_control_contract(
    *,
    source_kind: str,
    stage_dir: Path | str | None,
    checkpoint_path: Path | str | None = None,
    resume_status: Mapping[str, object] | None = None,
    stages: Sequence[Mapping[str, object]] | None = None,
    failure_category: str | None = None,
    failure_guidance: Mapping[str, object] | None = None,
    checkpoint_supported: bool = True,
    resume_supported: bool = True,
    run_id_token: str = "<run-id>",
) -> dict[str, object]:
    stage_rows = []
    for index, stage in enumerate(stages or [], start=1):
        if not isinstance(stage, Mapping):
            continue
        evidence = stage.get("evidence")
        stage_rows.append(
            {
                "index": index,
                "id": str(stage.get("id") or stage.get("label") or f"stage-{index}"),
                "label": str(stage.get("label") or stage.get("id") or f"Stage {index}"),
                "status": str(stage.get("status") or "pending"),
                "evidence_present": bool(evidence),
            }
        )
    resume = dict(resume_status or {})
    checkpoint_text = str(checkpoint_path) if checkpoint_path else str(resume.get("checkpoint_path") or "")
    failed_stages = [
        str(row["id"])
        for row in stage_rows
        if row["status"] in {"failed", "blocked", "canceled"}
    ]
    if resume.get("failed_stages"):
        failed_stages = sorted(set(failed_stages + [str(item) for item in resume.get("failed_stages") or []]))
    completed_stages = [
        str(row["id"])
        for row in stage_rows
        if row["status"] in {"complete", "completed", "ready", "ready-after-extraction", "ready-after-analysis"}
    ]
    if resume.get("completed_stages"):
        completed_stages = sorted(set(completed_stages + [str(item) for item in resume.get("completed_stages") or []]))
    category = str(failure_category or (failure_guidance or {}).get("category") or "")
    control_status = "failed-stage-present" if failed_stages else ("resume-ready" if resume.get("resume_ready") else "controls-ready")
    payload: dict[str, object] = {
        "profile_version": "image-stage-control-contract-v1",
        "qc_prep_item": 4,
        "source_kind": source_kind,
        "stage_dir": str(stage_dir or ""),
        "status": control_status,
        "stage_count": len(stage_rows),
        "stage_rows": stage_rows,
        "checkpoint": {
            "supported": checkpoint_supported,
            "path": checkpoint_text,
            "exists": bool(resume.get("checkpoint_exists")),
            "resume_ready": bool(resume.get("resume_ready")),
            "completed": bool(resume.get("completed")),
            "resumed_from_checkpoint": bool(resume.get("resumed_from_checkpoint")),
            "sidecar_required_for_report": checkpoint_supported,
        },
        "resume": {
            "supported": resume_supported,
            "cli_flag": "--resume",
            "completed_stages": completed_stages,
            "failed_stages": failed_stages,
            "reuse_reasons": list(resume.get("reuse_reasons") or []),
            "warning": str(resume.get("resume_warning") or ""),
        },
        "cancel_retry": {
            "cancel_supported": True,
            "retry_supported_for": ["failed", "canceled"],
            "cancel_route": f"/api/runs/{run_id_token}/cancel",
            "retry_route": f"/api/runs/{run_id_token}/retry",
            "running_cancel_policy": "cooperative-stage-boundary",
            "partial_output_policy": "preserve-stage-output-and-record-warning",
        },
        "failure_classification": {
            "category": category or "none",
            "known_categories": sorted(E01_FAILURE_GUIDANCE),
            "guidance_title": str((failure_guidance or {}).get("title") or ""),
            "retry_after_fix": bool(category),
        },
        "validation_evidence_required": [
            "stage checkpoint or explicit no-checkpoint limitation",
            "resume decision with completed/failed stage list",
            "cancel/retry transition log from web job API when used",
            "failure category and operator guidance for blocked stages",
        ],
        "commercial_blockers": [
            "long-running-cancel-under-load-validation-required",
            "trusted-checkpoint-resume-diff-required",
            "partial-output-cleanup-validation-required",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def build_e01_ingest_workflow_profile(
    source_path: Path,
    *,
    supported: bool,
    ready: bool,
    preflight_summary: Mapping[str, object] | None = None,
    segment_set_profile: Mapping[str, object] | None = None,
    source_integrity: Mapping[str, object] | None = None,
    failure_guidance: Mapping[str, object] | None = None,
) -> dict[str, object]:
    missing_tools = list((preflight_summary or {}).get("missing_tools") or [])
    dependency_status = str((preflight_summary or {}).get("status") or "not-run")
    selection_ready = bool(source_path.is_file() and supported)
    direct_extract_ready = bool(ready and not missing_tools)
    blocked_reason = ""
    if not selection_ready:
        blocked_reason = "Select a readable .E01/.Ex01 first segment before analysis."
    elif missing_tools:
        blocked_reason = "Install libewf/Sleuth Kit or scan a trusted read-only export folder."
    elif not ready:
        blocked_reason = "Evidence support is not ready for direct extraction."
    stages = [
        {
            "id": "select-e01",
            "label": "Select E01/Ex01",
            "status": "complete" if selection_ready else "blocked",
            "operator_action": "Choose the first EWF segment and keep all split segments in the same folder.",
            "evidence": [
                f"source={source_path.name}",
                f"segments={(segment_set_profile or {}).get('segment_count', 'unknown')}",
                f"hash_status={(source_integrity or {}).get('hash_status', 'not-run')}",
            ],
        },
        {
            "id": "dependency-preflight",
            "label": "Dependency preflight",
            "status": "complete" if dependency_status.startswith("ready") else "blocked",
            "operator_action": "Verify ewfmount, mmls, and tsk_recover before direct extraction.",
            "evidence": [
                f"status={dependency_status}",
                f"available={(preflight_summary or {}).get('available_count', 0)}",
                f"missing={(preflight_summary or {}).get('missing_count', 0)}",
            ],
        },
        {
            "id": "partition-selection",
            "label": "Partition selection",
            "status": "ready" if direct_extract_ready else "blocked",
            "operator_action": "Use auto largest supported filesystem first, or enter a known start sector for manual override.",
            "evidence": ["mmls partition table will be captured during extraction."],
        },
        {
            "id": "filesystem-extraction",
            "label": "Read-only extraction",
            "status": "ready" if direct_extract_ready else "blocked",
            "operator_action": "Recover the selected filesystem into the output stage and preserve command history.",
            "evidence": ["ewfmount + tsk_recover command history becomes provenance."],
        },
        {
            "id": "artifact-analysis",
            "label": "Artifact analysis",
            "status": "pending-after-extraction" if direct_extract_ready else "blocked",
            "operator_action": "Run Windows artifact collectors, document/file indexing, OCR sidecars, and timeline generation.",
            "evidence": ["analysis starts from the extracted filesystem root."],
        },
        {
            "id": "search-review-report",
            "label": "Search, review, report",
            "status": "pending-after-analysis" if direct_extract_ready else "blocked",
            "operator_action": "Search all evidence, verify in source viewer, mark review decisions, and export report material.",
            "evidence": ["Case DB review marks and report bundles keep source citations."],
        },
    ]
    runbook = build_e01_operator_runbook(
        source_path,
        direct_extract_ready=direct_extract_ready,
        blocked_reason=blocked_reason,
    )
    partition_browser = build_e01_partition_browser_contract(
        partition_selection=None,
        partition_table=None,
        direct_extract_ready=direct_extract_ready,
        blocked_reason=blocked_reason,
    )
    vsc_handoff = build_vsc_image_workflow_handoff(
        current_root=None,
        source_kind="e01-ex01",
        source_path=source_path,
        stage_dir="./rapidtriage-run-e01",
        status="pending-after-extraction" if direct_extract_ready else "blocked",
    )
    handoff_contract = {
        "profile_version": "qc-prep-e01-end-to-end-handoff-v1",
        "qc_prep_item": 1,
        "goal": "Keep E01 preflight, partition selection, extraction, artifact run, search, review, and report actions connected as one analyst workflow.",
        "gui_entrypoints": [
            {
                "id": "e01-evidence-check",
                "label": "Check evidence support",
                "required_before": "start-run",
                "status": "complete" if selection_ready else "blocked",
            },
            {
                "id": "start-configured-run",
                "label": "Start configured E01 analysis",
                "required_before": "search",
                "status": "ready" if direct_extract_ready else "blocked",
            },
            {
                "id": "search-review-report",
                "label": "Search, review, report after run completion",
                "required_before": "qc-signoff",
                "status": "pending-after-run" if direct_extract_ready else "blocked",
            },
        ],
        "required_output_chain": [
            "rapidtriage-evidence-preflight.json",
            "rapidtriage-e01.json",
            "rapidtriage-run-summary.json",
            "source viewer citations",
            "review decisions",
            "rapidtriage-run-report.md or reviewer bundle",
        ],
        "blocked_reason": blocked_reason,
        "run_command": runbook["recommended_commands"]["run"],
        "review_url_hint": runbook["recommended_commands"]["review"],
        "commercial_note": "This is an end-to-end usability/QC-prep handoff, not proof of native commercial EWF parser completeness.",
    }
    return {
        "profile_version": "windows11-e01-single-case-workflow-v1",
        "qc_prep_item": 1,
        "workflow_goal": "Select an E01, verify dependencies, choose a partition, extract read-only, analyze artifacts, search/review, and export report evidence from one flow.",
        "source_path": str(source_path),
        "direct_extract_ready": direct_extract_ready,
        "blocked": not direct_extract_ready,
        "blocked_reason": blocked_reason,
        "failure_category": (failure_guidance or {}).get("category"),
        "recommended_processing_profile": "fast-first-pass",
        "recommended_input_kind": "e01-derived" if direct_extract_ready else "mounted-or-exported-folder",
        "ui_primary_action": "Start run" if direct_extract_ready else "Mount/export first or install tools",
        "large_case_controls": [
            "Use Fast first pass before deep extraction.",
            "Keep extraction caps unless a focused deep review requires more output.",
            "Use cursor pages and virtualized tables for high-volume result sets.",
        ],
        "stages": stages,
        "operator_runbook": runbook,
        "recommended_commands": runbook["recommended_commands"],
        "handoff_contract": handoff_contract,
        "partition_browser": partition_browser,
        "vsc_workflow_handoff": vsc_handoff,
        "stage_control_contract": build_image_stage_control_contract(
            source_kind="e01-ex01",
            stage_dir="./rapidtriage-run-e01/_e01",
            checkpoint_path="./rapidtriage-run-e01/_e01/rapidtriage-e01-stage-status.json",
            resume_status=None,
            stages=stages,
            failure_category=str((failure_guidance or {}).get("category") or ""),
            failure_guidance=failure_guidance,
            checkpoint_supported=True,
            resume_supported=True,
        ),
        "commercial_gap_ids": ["#22", "#23", "#78", "#79"],
        "commercial_note": "This workflow is usable for triage, but commercial-grade E01 claims still require external corpus validation and trusted tool logs.",
    }


def build_e01_ex01_integrated_workflow_manifest(
    *,
    source_path: Path,
    source_integrity: Mapping[str, object] | None,
    segment_set_profile: Mapping[str, object] | None,
    tool_preflight: Sequence[Mapping[str, object]] | None,
    preflight_summary: Mapping[str, object] | None,
    partition_selection: Mapping[str, object] | None,
    partition_table: Sequence[Mapping[str, object]] | None,
    command_history: Sequence[Mapping[str, object]] | None,
    recovered_root_manifest: Mapping[str, object] | None,
    resume_status: Mapping[str, object] | None,
    run_outputs: Mapping[str, object] | None = None,
    status_context: str = "extraction-result",
) -> dict[str, object]:
    """Build the #22 E01/Ex01 single-case workflow contract.

    This is intentionally workflow-level evidence, not a claim that RapidForensic
    has a complete native EWF parser. It gives GUI/API/report code one stable
    object that connects source selection through report export readiness.
    """

    tool_rows = [dict(row) for row in tool_preflight or []]
    partition_rows = [dict(row) for row in partition_table or []]
    command_rows = [dict(row) for row in command_history or []]
    recovered_manifest = dict(recovered_root_manifest or {})
    outputs = dict(run_outputs or {})
    output_status = {
        key: {
            "path": str(value),
            "expected": key
            in {
                "e01",
                "manifest",
                "docs",
                "docs_index",
                "files",
                "timeline",
                "timeline_report",
                "indicators",
                "summary",
                "report",
            }
            or key.startswith("artifacts_"),
        }
        for key, value in outputs.items()
    }
    analysis_outputs = [
        key
        for key in output_status
        if key
        in {
            "manifest",
            "docs",
            "docs_index",
            "files",
            "timeline",
            "timeline_report",
            "indicators",
        }
        or key.startswith("artifacts_")
    ]
    report_outputs = [key for key in output_status if key in {"summary", "report"}]
    provenance_profile = build_e01_provenance_profile(
        source_path=source_path,
        source_integrity=source_integrity,
        segment_set_profile=segment_set_profile,
        tool_preflight=tool_preflight,
        partition_selection=partition_selection,
        partition_table=partition_table,
        command_history=command_history,
        recovered_root_manifest=recovered_root_manifest,
        resume_status=resume_status,
        run_outputs=run_outputs,
    )
    source_hash_status = str((source_integrity or {}).get("hash_status") or "not-recorded")
    dependency_status = str((preflight_summary or {}).get("status") or "not-recorded")
    selected_sector = (partition_selection or {}).get("selected_start_sector")
    recovered_count = int(
        recovered_manifest.get("visited_file_count")
        or recovered_manifest.get("hashed_file_count")
        or recovered_manifest.get("file_count")
        or 0
    )
    extraction_complete = bool(recovered_count or any(row.get("purpose") == "read-only-filesystem-recovery" and row.get("returncode") == 0 for row in command_rows))
    vsc_ready = extraction_complete or bool(analysis_outputs) or (status_context == "run-summary" and bool(outputs))
    stage_hint = Path(str(outputs.get("e01") or source_path.parent))
    if stage_hint.suffix:
        stage_hint = stage_hint.parent
    vsc_handoff = build_vsc_image_workflow_handoff(
        current_root=str((recovered_manifest or {}).get("root") or "<analysis-root>") if vsc_ready else None,
        source_kind="e01-ex01",
        source_path=source_path,
        stage_dir=stage_hint,
        status="ready-after-extraction" if vsc_ready else "blocked",
    )
    stages = [
        {
            "id": "select-e01",
            "label": "E01/Ex01 selection",
            "status": "complete" if source_path.is_file() else "blocked",
            "evidence": {
                "source_path": str(source_path),
                "hash_status": source_hash_status,
                "segment_count": int((segment_set_profile or {}).get("segment_count") or 0),
                "selected_is_first_segment": bool((segment_set_profile or {}).get("selected_is_first_segment", True)),
            },
        },
        {
            "id": "dependency-preflight",
            "label": "Dependency preflight",
            "status": "complete" if dependency_status.startswith("ready") else "blocked",
            "evidence": {
                "status": dependency_status,
                "available_tools": list((preflight_summary or {}).get("available_tools") or []),
                "missing_tools": list((preflight_summary or {}).get("missing_tools") or []),
                "tool_count": len(tool_rows),
            },
        },
        {
            "id": "partition-selection",
            "label": "Partition selection",
            "status": "complete" if selected_sector is not None else "blocked",
            "evidence": {
                "selected_start_sector": selected_sector,
                "requested_start_sector": (partition_selection or {}).get("requested_start_sector"),
                "recommended_start_sector": (partition_selection or {}).get("recommended_start_sector"),
                "partition_count": len(partition_rows),
                "supported_partition_count": (partition_selection or {}).get("supported_partition_count"),
            },
        },
        {
            "id": "filesystem-extraction",
            "label": "Read-only filesystem extraction",
            "status": "complete" if extraction_complete else "blocked",
            "evidence": {
                "command_history_count": len(command_rows),
                "recovered_file_count": recovered_count,
                "resume_ready": bool((resume_status or {}).get("resume_ready")),
                "resumed_from_checkpoint": bool((resume_status or {}).get("resumed_from_checkpoint")),
            },
        },
        {
            "id": "vsc-discovery-extraction",
            "label": "Volume Shadow Copy discovery/extraction handoff",
            "status": "ready-after-extraction" if vsc_ready else "blocked",
            "evidence": {
                "handoff_profile": vsc_handoff["profile_version"],
                "direct_image_level_mount_supported": vsc_handoff["direct_image_level_mount_supported"],
                "discover_command_available": bool(vsc_handoff["commands"].get("discover")),
                "extract_command_available": bool(vsc_handoff["commands"].get("extract")),
            },
        },
        {
            "id": "artifact-analysis",
            "label": "Artifact analysis",
            "status": "complete" if analysis_outputs else ("ready-after-extraction" if extraction_complete else "blocked"),
            "evidence": {
                "analysis_output_keys": sorted(analysis_outputs),
                "artifact_output_count": sum(1 for key in output_status if key.startswith("artifacts_")),
            },
        },
        {
            "id": "unified-search-indexing",
            "label": "Unified search and indexing",
            "status": "complete" if {"docs", "docs_index", "files"}.issubset(output_status) else ("ready-after-analysis" if analysis_outputs else "blocked"),
            "evidence": {
                "docs_output": "docs" in output_status,
                "docs_index_output": "docs_index" in output_status,
                "files_output": "files" in output_status,
            },
        },
        {
            "id": "review-workflow",
            "label": "Review and source verification",
            "status": "ready" if analysis_outputs else "blocked",
            "evidence": {
                "source_viewer_required": True,
                "case_db_review_required": True,
                "report_only_reviewed_items": True,
            },
        },
        {
            "id": "report-export",
            "label": "Report/export package",
            "status": "complete" if report_outputs else ("ready-after-review" if analysis_outputs else "blocked"),
            "evidence": {
                "report_output_keys": sorted(report_outputs),
                "source_hash_required": True,
                "trusted_tool_diff_required": True,
            },
        },
    ]
    blockers = [
        "native-e01-ex01-segment-metadata-decoding-not-implemented",
        "trusted-e01-ex01-known-answer-diff-required",
        "real-windows11-e01-run-log-required",
        "encrypted-corrupt-image-corpus-required",
    ]
    stage_control = build_image_stage_control_contract(
        source_kind="e01-ex01",
        stage_dir=stage_hint,
        checkpoint_path=Path(str(stage_hint)) / E01_STAGE_CHECKPOINT_NAME,
        resume_status=resume_status,
        stages=stages,
        checkpoint_supported=True,
        resume_supported=True,
    )
    payload: dict[str, object] = {
        "profile_version": E01_INTEGRATED_WORKFLOW_MANIFEST_VERSION,
        "item_number": 22,
        "gap_id": "#22",
        "status_context": status_context,
        "workflow_goal": "One Windows 11 E01/Ex01 case flows from selection, dependency preflight, partition selection, read-only extraction, artifact analysis, unified search, review, and report export.",
        "source_ref": {
            "path": str(source_path),
            "hash_status": source_hash_status,
            "sha256": (source_integrity or {}).get("sha256"),
        },
        "segment_set_profile": dict(segment_set_profile or {}),
        "dependency_preflight": dict(preflight_summary or {}),
        "partition_selection": dict(partition_selection or {}),
        "partition_table_row_count": len(partition_rows),
        "command_history_count": len(command_rows),
        "recovered_root_summary": {
            "profile_version": recovered_manifest.get("profile_version"),
            "visited_file_count": recovered_manifest.get("visited_file_count", 0),
            "hashed_file_count": recovered_manifest.get("hashed_file_count", 0),
            "skipped_large_file_count": recovered_manifest.get("skipped_large_file_count", 0),
            "truncated": bool(recovered_manifest.get("truncated", False)),
        },
        "run_output_status": output_status,
        "provenance_profile": provenance_profile,
        "vsc_workflow_handoff": vsc_handoff,
        "stage_control_contract": stage_control,
        "stages": stages,
        "large_data_controls": {
            "direct_image_hash_limit_bytes": DIRECT_IMAGE_HASH_LIMIT_BYTES,
            "bounded_recovered_root_manifest": True,
            "cursor_table_required_for_gui": True,
            "virtualized_table_required_for_gui": True,
            "checkpoint_resume_profile": (resume_status or {}).get("profile_version"),
        },
        "reportability_decision": image_reportability_decision(
            22,
            blockers=blockers,
            failed_validation_matrix_ids=["#22-native-commercial-parser"],
            details={
                "source_integrity": source_integrity or {},
                "image_trusted_diff": {"status": "not-attached"},
            },
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": blockers,
        "operator_next_steps": [
            "Run against a real Windows 11 E01 with libewf/Sleuth Kit or a trusted export.",
            "Attach ewfverify/mmls/tsk_recover or vendor transcripts and trusted-tool diff output.",
            "Mount/export any VSC snapshots read-only, then run vsc-discover, vsc-compare, and vsc-extract against the recovered current root.",
            "Use review/source viewer citations before report export.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def build_e01_provenance_profile(
    *,
    source_path: Path,
    source_integrity: Mapping[str, object] | None,
    segment_set_profile: Mapping[str, object] | None,
    tool_preflight: Sequence[Mapping[str, object]] | None,
    partition_selection: Mapping[str, object] | None,
    partition_table: Sequence[Mapping[str, object]] | None,
    command_history: Sequence[Mapping[str, object]] | None,
    recovered_root_manifest: Mapping[str, object] | None,
    resume_status: Mapping[str, object] | None,
    run_outputs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    output_rows: list[dict[str, object]] = []
    for key, value in dict(run_outputs or {}).items():
        path = Path(str(value))
        row: dict[str, object] = {"key": str(key), "path": str(path), "exists": path.is_file()}
        if path.is_file():
            try:
                stat_result = path.stat()
                row.update({"size_bytes": stat_result.st_size, "sha256": compute_sha256(path)})
            except OSError as exc:
                row.update({"hash_status": "unavailable", "error": str(exc)})
        output_rows.append(row)
    command_rows = [
        {
            "purpose": str(row.get("purpose") or ""),
            "command": list(row.get("command") or []),
            "returncode": row.get("returncode"),
            "stdout_sha256": hashlib.sha256(str(row.get("stdout_preview") or "").encode("utf-8")).hexdigest()
            if row.get("stdout_preview")
            else "",
            "stderr_sha256": hashlib.sha256(str(row.get("stderr_preview") or "").encode("utf-8")).hexdigest()
            if row.get("stderr_preview")
            else "",
        }
        for row in command_history or []
        if isinstance(row, Mapping)
    ]
    profile: dict[str, object] = {
        "profile_version": "e01-provenance-profile-v1",
        "checklist_item": 7,
        "qc_gap_id": "#7",
        "source_image": {
            "path": str(source_path),
            "name": source_path.name,
            "sha256": (source_integrity or {}).get("sha256"),
            "hash_status": (source_integrity or {}).get("hash_status", "not-recorded"),
            "size_bytes": (source_integrity or {}).get("size"),
        },
        "segment_set": {
            "profile_version": (segment_set_profile or {}).get("profile_version"),
            "segment_count": (segment_set_profile or {}).get("segment_count", 0),
            "selected_is_first_segment": (segment_set_profile or {}).get("selected_is_first_segment"),
            "warnings": list((segment_set_profile or {}).get("warnings") or []),
        },
        "selected_partition": {
            "selected_start_sector": (partition_selection or {}).get("selected_start_sector"),
            "selected_byte_offset": (partition_selection or {}).get("selected_byte_offset"),
            "selected_filesystem_guess": (partition_selection or {}).get("selected_filesystem_guess"),
            "partition_table_row_count": len(list(partition_table or [])),
        },
        "tool_versions": [
            {
                "tool": str(row.get("tool") or ""),
                "path": row.get("path"),
                "available": bool(row.get("available")),
                "version": row.get("version"),
                "version_attempts": list(row.get("version_attempts") or []),
            }
            for row in tool_preflight or []
            if isinstance(row, Mapping)
        ],
        "command_history": command_rows,
        "recovered_root": {
            "profile_version": (recovered_root_manifest or {}).get("profile_version"),
            "root": (recovered_root_manifest or {}).get("root"),
            "visited_file_count": (recovered_root_manifest or {}).get("visited_file_count", 0),
            "hashed_file_count": (recovered_root_manifest or {}).get("hashed_file_count", 0),
            "truncated": bool((recovered_root_manifest or {}).get("truncated", False)),
        },
        "run_outputs": output_rows,
        "resume_status": dict(resume_status or {}),
        "read_only_posture": {
            "source_mutation_allowed": False,
            "writes_to_stage_or_output_only": True,
            "provenance_required_before_report": True,
        },
    }
    profile["manifest_sha256"] = stable_manifest_sha256(profile)
    return profile


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True)


def extract_e01_to_directory(
    e01_path: Path,
    stage_dir: Path,
    *,
    partition_start_sector: int | None = None,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> E01ExtractionResult:
    source_path = e01_path.expanduser().resolve()
    if not source_path.is_file():
        raise E01ExtractionError(f"E01 image not found: {source_path}")
    if not is_e01_path(source_path):
        raise E01ExtractionError(f"unsupported E01 image extension: {source_path.name}")

    stage = stage_dir.expanduser().resolve()
    mount_dir = stage / "_ewfmount"
    raw_image = mount_dir / "ewf1"
    extract_dir = stage / "filesystem"
    stage.mkdir(parents=True, exist_ok=True)
    mount_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = stage / E01_STAGE_CHECKPOINT_NAME
    source_signature = e01_source_signature(source_path)
    segment_set_profile = build_e01_segment_set_profile(source_path)

    missing = missing_e01_tools(tool_resolver)
    tool_preflight = collect_tool_preflight(E01_REQUIRED_TOOLS, runner=runner, tool_resolver=tool_resolver)
    checkpoint = load_e01_stage_checkpoint(checkpoint_path)
    if e01_checkpoint_resume_ready(
        checkpoint,
        source_signature=source_signature,
        requested_start_sector=partition_start_sector,
        extract_dir=extract_dir,
    ):
        partition_selection = dict(checkpoint.get("partition_selection") or {})
        partition_table = list(checkpoint.get("partition_table") or [])
        selected_start_sector = int(partition_selection.get("selected_start_sector") or 0)
        return E01ExtractionResult(
            source_path=source_path,
            stage_dir=stage,
            mount_dir=mount_dir,
            raw_image_path=raw_image,
            extract_dir=extract_dir,
            partition_start_sector=selected_start_sector,
            source_integrity=describe_source_integrity(source_path),
            tool_preflight=tuple(tool_preflight),
            partition_table=tuple(partition_table),
            partition_selection=partition_selection,
            command_history=tuple(checkpoint.get("command_history") or ()),
            recovered_root_manifest=dict(checkpoint.get("recovered_root_manifest") or {}),
            segment_set_profile=dict(checkpoint.get("segment_set_profile") or segment_set_profile),
            warnings=(
                "E01 extraction resumed from a completed filesystem recovery checkpoint; verify checkpoint provenance before report use.",
            ),
            resume_status=build_e01_resume_status(checkpoint_path, checkpoint, resumed=True),
        )
    if missing:
        write_e01_stage_checkpoint(
            checkpoint_path,
            {
                "profile_version": "e01-stage-checkpoint-v1",
                "source_signature": source_signature,
                "requested_start_sector": partition_start_sector,
                "segment_set_profile": segment_set_profile,
                "completed": False,
                "resume_ready": False,
                "stages": {
                    "dependency-preflight": {
                        "status": "blocked",
                        "missing_tools": missing,
                    }
                },
            },
        )
        joined = ", ".join(missing)
        raise E01ExtractionError(
            f"E01 direct input requires external tools: {joined}. "
            "Install libewf/Sleuth Kit, run `rapidtriage evidence IMAGE.E01 --json` for preflight, "
            "or mount/export the image read-only with a trusted forensic tool and scan that folder."
        )

    command_history: list[dict[str, object]] = []
    partition_table: list[dict[str, object]] = []
    checkpoint_payload: dict[str, object] = {
        "profile_version": "e01-stage-checkpoint-v1",
        "source_signature": source_signature,
        "requested_start_sector": partition_start_sector,
        "segment_set_profile": segment_set_profile,
        "completed": False,
        "resume_ready": False,
        "stages": {
            "dependency-preflight": {
                "status": "completed",
                "missing_tools": [],
                "preflight_summary": e01_preflight_summary(tool_preflight, missing_tools=[]),
            }
        },
    }
    write_e01_stage_checkpoint(checkpoint_path, checkpoint_payload)

    try:
        mount_result = runner(["ewfmount", str(source_path), str(mount_dir)])
        command_history.append(command_record("mount-ewf", ["ewfmount", str(source_path), str(mount_dir)], mount_result))
        checkpoint_payload["command_history"] = command_history
        checkpoint_payload["stages"] = {
            **dict(checkpoint_payload.get("stages") or {}),
            "mount-ewf": {"status": "completed" if mount_result.returncode == 0 else "failed"},
        }
        write_e01_stage_checkpoint(checkpoint_path, checkpoint_payload)
        if mount_result.returncode != 0:
            raise E01ExtractionError(f"ewfmount failed: {mount_result.stderr.strip()}")
        if not raw_image.exists():
            raise E01ExtractionError(f"ewfmount did not expose expected raw image: {raw_image}")

        mmls_result = runner(["mmls", str(raw_image)])
        command_history.append(command_record("partition-enumeration", ["mmls", str(raw_image)], mmls_result))
        checkpoint_payload["command_history"] = command_history
        checkpoint_payload["stages"] = {
            **dict(checkpoint_payload.get("stages") or {}),
            "partition-enumeration": {"status": "completed" if mmls_result.returncode == 0 else "failed"},
        }
        write_e01_stage_checkpoint(checkpoint_path, checkpoint_payload)
        if mmls_result.returncode != 0:
            raise E01ExtractionError(f"mmls failed: {mmls_result.stderr.strip()}")
        partition_table = parse_mmls_partitions(mmls_result.stdout)
        recommended_sector = mmls_first_filesystem(mmls_result.stdout)
        start_sector = select_mmls_filesystem(
            mmls_result.stdout,
            preferred_start_sector=partition_start_sector,
        )
        if start_sector is None:
            raise E01ExtractionError("mmls could not find a FAT/exFAT/NTFS/basic-data filesystem partition")
        partition_selection = build_partition_selection_metadata(
            partition_table,
            selected_start_sector=start_sector,
            recommended_start_sector=recommended_sector,
            requested_start_sector=partition_start_sector,
        )
        checkpoint_payload["partition_table"] = mark_selected_partition(
            partition_table,
            start_sector,
            recommended_start_sector=recommended_sector,
        )
        checkpoint_payload["partition_selection"] = partition_selection
        write_e01_stage_checkpoint(checkpoint_path, checkpoint_payload)

        recover_command = ["tsk_recover", "-e", "-a", "-o", str(start_sector), str(raw_image), str(extract_dir)]
        recover_result = runner(recover_command)
        command_history.append(command_record("read-only-filesystem-recovery", recover_command, recover_result))
        checkpoint_payload["command_history"] = command_history
        checkpoint_payload["stages"] = {
            **dict(checkpoint_payload.get("stages") or {}),
            "read-only-filesystem-recovery": {"status": "completed" if recover_result.returncode == 0 else "failed"},
        }
        if recover_result.returncode != 0:
            write_e01_stage_checkpoint(checkpoint_path, checkpoint_payload)
            raise E01ExtractionError(f"tsk_recover failed: {recover_result.stderr.strip()}")
        recovered_manifest = build_recovered_root_manifest(extract_dir)
        checkpoint_payload["completed"] = True
        checkpoint_payload["resume_ready"] = True
        checkpoint_payload["extract_dir"] = str(extract_dir)
        checkpoint_payload["raw_image_path"] = str(raw_image)
        checkpoint_payload["recovered_root_manifest"] = recovered_manifest
        write_e01_stage_checkpoint(checkpoint_path, checkpoint_payload)
        return E01ExtractionResult(
            source_path=source_path,
            stage_dir=stage,
            mount_dir=mount_dir,
            raw_image_path=raw_image,
            extract_dir=extract_dir,
            partition_start_sector=start_sector,
            source_integrity=describe_source_integrity(source_path),
            tool_preflight=tuple(tool_preflight),
            partition_table=tuple(
                mark_selected_partition(
                    partition_table,
                    start_sector,
                    recommended_start_sector=recommended_sector,
                )
            ),
            partition_selection=partition_selection,
            command_history=tuple(command_history),
            warnings=(
                "E01/Ex01 direct extraction is an orchestrated libewf/Sleuth Kit workflow; validate results against case requirements.",
            ),
            resume_status=build_e01_resume_status(checkpoint_path, checkpoint_payload, resumed=False),
            recovered_root_manifest=recovered_manifest,
            segment_set_profile=segment_set_profile,
        )
    finally:
        unmount_e01_mount(mount_dir, runner=runner, tool_resolver=tool_resolver)


def e01_source_signature(path: Path) -> dict[str, object]:
    stat = path.stat()
    return {
        "path": str(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def load_e01_stage_checkpoint(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_e01_stage_checkpoint(path: Path, payload: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    temp_path.replace(path)


def e01_checkpoint_resume_ready(
    checkpoint: Mapping[str, object],
    *,
    source_signature: Mapping[str, object],
    requested_start_sector: int | None,
    extract_dir: Path,
) -> bool:
    if not checkpoint.get("completed") or not checkpoint.get("resume_ready"):
        return False
    if checkpoint.get("source_signature") != dict(source_signature):
        return False
    if checkpoint.get("requested_start_sector") != requested_start_sector:
        return False
    partition_selection = checkpoint.get("partition_selection")
    if not isinstance(partition_selection, Mapping):
        return False
    if partition_selection.get("selected_start_sector") in (None, ""):
        return False
    if not extract_dir.is_dir():
        return False
    return any(extract_dir.iterdir())


def build_e01_resume_status(
    checkpoint_path: Path,
    checkpoint: Mapping[str, object],
    *,
    resumed: bool,
) -> dict[str, object]:
    stages = checkpoint.get("stages") if isinstance(checkpoint.get("stages"), Mapping) else {}
    return {
        "profile_version": "e01-resume-status-v1",
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_exists": checkpoint_path.is_file(),
        "resumed_from_checkpoint": resumed,
        "resume_ready": bool(checkpoint.get("resume_ready")),
        "completed": bool(checkpoint.get("completed")),
        "completed_stages": [
            name
            for name, stage in dict(stages).items()
            if isinstance(stage, Mapping) and stage.get("status") == "completed"
        ],
        "failed_stages": [
            name
            for name, stage in dict(stages).items()
            if isinstance(stage, Mapping) and stage.get("status") == "failed"
        ],
        "reuse_reasons": [
            "completed checkpoint was present",
            "source signature matched current image",
            "requested partition start sector matched",
            "recovered filesystem output directory still contains files",
        ]
        if resumed
        else [],
        "resume_warning": (
            "Completed extraction stages were reused; preserve checkpoint JSON and verify source signature before report use."
            if resumed
            else ""
        ),
    }


def build_recovered_root_manifest(
    root: Path,
    *,
    max_files: int = 5000,
    max_hash_bytes: int = DIRECT_IMAGE_HASH_LIMIT_BYTES,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    total_size = 0
    visited_count = 0
    hashed_count = 0
    skipped_large_count = 0
    error_count = 0
    truncated = False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if visited_count >= max_files:
            truncated = True
            break
        visited_count += 1
        try:
            stat = path.stat()
        except OSError as exc:
            error_count += 1
            entries.append(
                {
                    "relative_path": str(path.relative_to(root)),
                    "hash_status": "stat-error",
                    "error": str(exc),
                }
            )
            continue
        total_size += stat.st_size
        row: dict[str, object] = {
            "relative_path": str(path.relative_to(root)),
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }
        if stat.st_size <= max_hash_bytes:
            try:
                row["sha256"] = compute_sha256(path)
                row["hash_status"] = "computed"
                hashed_count += 1
            except OSError as exc:
                row["hash_status"] = "hash-error"
                row["error"] = str(exc)
                error_count += 1
        else:
            row["hash_status"] = "skipped-large-file"
            row["hash_limit_bytes"] = max_hash_bytes
            skipped_large_count += 1
        entries.append(row)
    return {
        "profile_version": "e01-recovered-root-manifest-v1",
        "root": str(root),
        "max_files": max_files,
        "max_hash_bytes": max_hash_bytes,
        "visited_file_count": visited_count,
        "hashed_file_count": hashed_count,
        "skipped_large_file_count": skipped_large_count,
        "error_count": error_count,
        "total_size_bytes": total_size,
        "truncated": truncated,
        "files": entries,
    }


def mmls_first_filesystem(text: str) -> int | None:
    best_start = None
    best_size = -1
    for line in text.splitlines():
        match = re.search(r"^\s*\d+:\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if not match:
            continue
        start = int(match.group(1))
        size = int(match.group(2))
        description = match.group(3).lower()
        if "swap" in description:
            continue
        if any(
            token in description
            for token in ("fat", "exfat", "ntfs", "basic data", "msdos", "ext2", "ext3", "ext4", "linux", "xfs")
        ):
            if size > best_size:
                best_start = start
                best_size = size
    return best_start


def select_mmls_filesystem(text: str, *, preferred_start_sector: int | None = None) -> int | None:
    partitions = parse_mmls_partitions(text)
    if preferred_start_sector is None:
        return mmls_first_filesystem(text)
    for partition in partitions:
        if int(partition.get("start_sector") or -1) == preferred_start_sector:
            if not partition.get("supported_filesystem_hint"):
                raise E01ExtractionError(
                    f"requested partition start sector {preferred_start_sector} does not look like a supported filesystem"
                )
            return preferred_start_sector
    raise E01ExtractionError(f"requested partition start sector {preferred_start_sector} was not found in mmls output")


def parse_mmls_partitions(text: str) -> list[dict[str, object]]:
    partitions: list[dict[str, object]] = []
    sector_size = mmls_sector_size_bytes(text)
    for line in text.splitlines():
        match = re.search(r"^\s*(\d+):\s+(\d+)\s+(\d+)\s+(.+)$", line)
        if not match:
            continue
        description = match.group(4).strip()
        start_sector = int(match.group(2))
        sector_count = int(match.group(3))
        filesystem_guess = guess_partition_filesystem(description)
        partitions.append(
            {
                "slot": int(match.group(1)),
                "partition_number": int(match.group(1)),
                "start_sector": start_sector,
                "sector_count": sector_count,
                "sector_size_bytes": sector_size,
                "byte_offset": start_sector * sector_size,
                "size_bytes": sector_count * sector_size,
                "description": description,
                "filesystem_guess": filesystem_guess,
                "boot_flag": bool(re.search(r"\bboot\b|\*", description, re.IGNORECASE)),
                "supported_filesystem_hint": is_supported_mmls_description(description),
                "recommended_for_recovery": False,
                "selected_for_recovery": False,
                "manual_override_allowed": True,
            }
        )
    return partitions


def mark_selected_partition(
    partitions: Sequence[dict[str, object]],
    start_sector: int | None,
    *,
    recommended_start_sector: int | None = None,
) -> list[dict[str, object]]:
    marked: list[dict[str, object]] = []
    for partition in partitions:
        row = dict(partition)
        row["selected_for_recovery"] = start_sector is not None and row.get("start_sector") == start_sector
        row["recommended_for_recovery"] = (
            recommended_start_sector is not None and row.get("start_sector") == recommended_start_sector
        )
        marked.append(row)
    return marked


def build_partition_selection_metadata(
    partitions: Sequence[dict[str, object]],
    *,
    selected_start_sector: int,
    recommended_start_sector: int | None,
    requested_start_sector: int | None,
) -> dict[str, object]:
    selected = next(
        (partition for partition in partitions if int(partition.get("start_sector") or -1) == selected_start_sector),
        {},
    )
    marked_partitions = mark_selected_partition(
        partitions,
        selected_start_sector,
        recommended_start_sector=recommended_start_sector,
    )
    return {
        "profile_version": "e01-partition-selection-v1",
        "selected_start_sector": selected_start_sector,
        "selected_byte_offset": selected.get("byte_offset"),
        "selected_size_bytes": selected.get("size_bytes"),
        "selected_filesystem_guess": selected.get("filesystem_guess", ""),
        "recommended_start_sector": recommended_start_sector,
        "requested_start_sector": requested_start_sector,
        "selection_source": "user-request" if requested_start_sector is not None else "largest-supported-filesystem",
        "selected_supported_filesystem_hint": bool(selected.get("supported_filesystem_hint")),
        "selected_description": selected.get("description", ""),
        "partition_count": len(partitions),
        "supported_partition_count": sum(1 for item in partitions if item.get("supported_filesystem_hint")),
        "partition_browser_columns": [
            "partition_number",
            "start_sector",
            "byte_offset",
            "filesystem_guess",
            "size_bytes",
            "boot_flag",
            "recommended_for_recovery",
            "selected_for_recovery",
        ],
        "partition_browser_rows": marked_partitions,
        "manual_override": {
            "allowed": True,
            "field": "start_sector",
            "requested_start_sector": requested_start_sector,
            "warning_required_when_differs_from_recommendation": bool(
                requested_start_sector is not None and requested_start_sector != recommended_start_sector
            ),
        },
        "selection_warning": (
            ""
            if requested_start_sector is None or requested_start_sector == recommended_start_sector
            else "User-selected partition differs from the automatic recommendation; preserve the reason in case notes."
        ),
    }


def mmls_sector_size_bytes(text: str) -> int:
    match = re.search(r"Units are in\s+(\d+)[-\s]*byte sectors", text, re.IGNORECASE)
    if not match:
        return 512
    try:
        return int(match.group(1))
    except ValueError:
        return 512


def guess_partition_filesystem(description: str) -> str:
    lowered = description.lower()
    if "ntfs" in lowered:
        return "ntfs"
    if "exfat" in lowered:
        return "exfat"
    if "fat" in lowered:
        return "fat"
    if "xfs" in lowered:
        return "xfs"
    if "ext4" in lowered:
        return "ext4"
    if "ext3" in lowered:
        return "ext3"
    if "ext2" in lowered:
        return "ext2"
    if "swap" in lowered:
        return "swap"
    if "linux" in lowered:
        return "linux"
    if "basic data" in lowered:
        return "windows-basic-data"
    if "unallocated" in lowered:
        return "unallocated"
    return "unknown"


def is_supported_mmls_description(description: str) -> bool:
    lowered = description.lower()
    if "swap" in lowered:
        return False
    return any(token in lowered for token in ("fat", "exfat", "ntfs", "basic data", "msdos", "ext2", "ext3", "ext4", "linux", "xfs"))


def describe_source_integrity(path: Path, *, max_hash_bytes: int = DIRECT_IMAGE_HASH_LIMIT_BYTES) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    try:
        stat_result = resolved.stat()
    except OSError as exc:
        return {"path": str(resolved), "hash_status": "unavailable", "error": str(exc)}
    payload: dict[str, object] = {
        "path": str(resolved),
        "size": stat_result.st_size,
        "modified_at": stat_result.st_mtime,
        "hash_algorithm": "sha256",
    }
    if stat_result.st_size <= max_hash_bytes:
        payload["sha256"] = compute_sha256(resolved)
        payload["hash_status"] = "computed"
    else:
        payload["sha256"] = None
        payload["hash_status"] = "deferred-large-source"
        payload["hash_note"] = (
            "Source is larger than the preflight hash limit; acquire a full evidence hash in the acquisition workflow."
        )
    return payload


def build_windows11_e01_known_answer_manifest(
    source_path: Path,
    *,
    case_id: str = "windows11-e01-known-answer",
    expected_partition_start_sector: int | None = None,
    expected_artifacts: Sequence[str] | None = None,
    validation_commands: Sequence[str] | None = None,
) -> dict[str, object]:
    source = source_path.expanduser().resolve()
    source_integrity = describe_source_integrity(source)
    segment_profile = build_e01_segment_set_profile(source) if source.is_file() and is_e01_path(source) else {
        "profile_version": "ewf-segment-set-v1",
        "selected_segment": str(source),
        "segment_count": 0,
        "segments": [],
        "warnings": ["source image is missing or is not a supported E01/Ex01 path"],
        "validation_status": "missing-or-unsupported",
    }
    intake_profile = build_e01_intake_profile(
        source,
        source_integrity=source_integrity,
        segment_set_profile=segment_profile,
    )
    expected_artifact_rows = [
        {
            "id": f"artifact-{index + 1:03d}",
            "description": str(item),
            "required": True,
            "validation_status": "not-run",
        }
        for index, item in enumerate(expected_artifacts or [])
        if str(item).strip()
    ]
    validation_command_values = list(default_windows11_e01_validation_commands(source))
    validation_command_values.extend(
        str(command)
        for command in validation_commands or []
        if str(command).strip() and str(command) not in validation_command_values
    )
    command_rows = [
        {
            "id": f"validation-command-{index + 1:03d}",
            "command": str(command),
            "purpose": "known-answer-validation",
            "status": "not-run",
        }
        for index, command in enumerate(validation_command_values)
        if str(command).strip()
    ]
    partition_rows = []
    if expected_partition_start_sector is not None:
        partition_rows.append(
            {
                "start_sector": expected_partition_start_sector,
                "expected_filesystem": "NTFS or analyst-confirmed Windows filesystem",
                "required": True,
                "validation_status": "not-run",
            }
        )
    details = {
        "source_path": str(source),
        "source_integrity": source_integrity,
        "segment_set_profile": segment_profile,
        "partition_start_sector": expected_partition_start_sector,
        "command_history": command_rows,
        "warnings": segment_profile.get("warnings", []),
        "limitations": E01_REPORT_GRADE_BLOCKERS,
    }
    validation_matrix = image_validation_matrix(
        gap_id="#22",
        source_integrity=source_integrity.get("hash_status") in {"computed", "deferred-large-source"},
        tool_preflight=False,
        partition_table=bool(partition_rows),
        command_history=bool(command_rows),
        native_complete=False,
    )
    payload: dict[str, object] = {
        "schema": "rapidforensic-windows11-e01-known-answer-manifest-v1",
        "compatible_known_answer_schema": "rapidtriage-known-answer-manifest-v1",
        "case_id": case_id,
        "name": f"{case_id} Windows 11 E01 known-answer manifest",
        "status": "draft-needs-execution",
        "commercial_grade_ready": False,
        "generated_for": {
            "workflow": "Windows 11 E01 single-case validation",
            "backlog_items": [22],
            "commercial_gap_ids": ["#22"],
        },
        "source_image": {
            "path": str(source),
            "name": source.name,
            "exists": source.is_file(),
            "is_supported_e01": is_e01_path(source),
            "integrity": source_integrity,
            "segment_set_profile": segment_profile,
            "intake_profile": intake_profile,
        },
        "expected": {
            "partitions": partition_rows,
            "high_value_artifacts": expected_artifact_rows,
            "minimum_workflow_outputs": [
                "dependency preflight",
                "partition table and selected offset",
                "read-only extraction command history",
                "artifact collection summary",
                "search/review/report bundle metadata",
            ],
        },
        "validation_commands": command_rows,
        "report_grade_validation_plan": build_e01_report_grade_validation_plan(
            source,
            case_id=case_id,
            expected_partition_start_sector=expected_partition_start_sector,
            expected_artifacts=expected_artifacts,
            validation_commands=validation_commands,
            source_integrity=source_integrity,
            segment_set_profile=segment_profile,
        ),
        "trusted_diff_targets": [
            "libewf/ewfverify source integrity transcript",
            "mmls partition table transcript",
            "tsk_recover or trusted export manifest",
            "RapidForensic run summary",
            "selected trusted suite export log when direct extraction is unavailable",
        ],
        "required_evidence_slots": {
            "source_image_hash": "Full E01/Ex01 acquisition hash or deferred-large-source acquisition hash record.",
            "segment_set_inventory": "All EWF split segments with path, size, order, and missing-segment warnings.",
            "partition_assertions": "Expected Windows partition start sector and filesystem description.",
            "artifact_assertions": "Expected EVTX/Registry/MFT/USN/browser/document rows for this case.",
            "command_transcripts": "Tool versions, commands, stdout/stderr, and exit codes for extraction and validation.",
            "report_bundle": "Generated report/manifest hashes and citation coverage after the smoke run.",
        },
        "validation_matrix": validation_matrix,
        "core_accuracy_gates": image_core_accuracy_gates(22, details),
        "commercial_grade_blockers": list(E01_REPORT_GRADE_BLOCKERS),
        "reportability_decision": image_reportability_decision(
            22,
            blockers=E01_REPORT_GRADE_BLOCKERS,
            failed_validation_matrix_ids=[
                str(item.get("id"))
                for item in validation_matrix
                if isinstance(item, Mapping) and not item.get("passed")
            ],
            details=details,
        ),
        "operator_next_steps": [
            "Fill expected high-value artifacts from a trusted baseline case review.",
            "Run the validation commands and attach command transcripts plus output hashes.",
            "Diff extracted artifacts against trusted parser/export outputs before changing status to pass.",
            "Keep this manifest with the case validation package and cite it in commercial-readiness input.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def default_windows11_e01_validation_commands(source: Path) -> list[str]:
    source_arg = str(source)
    return [
        f"rapidtriage e01-hash {json.dumps(source_arg)} --output-dir rapidforensic-e01-validation/source-hash --json",
        f"rapidtriage evidence {json.dumps(source_arg)} --json",
        f"rapidtriage run {json.dumps(source_arg)} --mode hacking --output-dir rapidforensic-e01-smoke --read-only",
        "rapidtriage image-workflow-validate --item-number 22 --rapid-output rapidforensic-e01-smoke/run/rapidtriage-e01.json --trusted-output rapidforensic-e01-validation/trusted-e01-workflow.csv --trusted-tool ewfverify --output rapidforensic-e01-validation/e01-trusted-diff.json --json",
        "rapidtriage commercial-readiness --json",
    ]


def build_e01_report_grade_validation_plan(
    source_path: Path,
    *,
    case_id: str = "windows11-e01-validation",
    output_dir: Path | str | None = None,
    expected_partition_start_sector: int | None = None,
    expected_artifacts: Sequence[str] | None = None,
    validation_commands: Sequence[str] | None = None,
    source_integrity: Mapping[str, object] | None = None,
    segment_set_profile: Mapping[str, object] | None = None,
    tool_preflight: Sequence[Mapping[str, object]] | None = None,
    preflight_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Create the #22 report-grade validation handoff.

    The plan is executable guidance: it tells the analyst which machine-readable
    artifacts to produce before E01/Ex01 output can be cited as report-grade.
    It does not mark #22 commercial-grade by itself.
    """

    source = source_path.expanduser().resolve()
    output_root = Path(output_dir).expanduser().resolve() if output_dir else Path("rapidforensic-e01-validation")
    expected_artifact_rows = [
        {
            "id": f"expected-artifact-{index + 1:03d}",
            "description": str(item),
            "status": "pending-trusted-comparison",
        }
        for index, item in enumerate(expected_artifacts or [])
        if str(item).strip()
    ]
    segment_profile = dict(segment_set_profile or {})
    integrity = dict(source_integrity or {})
    preflight = dict(preflight_summary or {})
    tool_rows = [dict(row) for row in tool_preflight or []]
    smoke_argv = [
        "rapidtriage",
        "e01-smoke",
        str(source),
        "--output-dir",
        str(output_root / "smoke"),
        "--case-id",
        case_id,
    ]
    if expected_partition_start_sector is not None:
        smoke_argv.extend(["--expected-partition-start-sector", str(expected_partition_start_sector)])
    command_rows = [
        _e01_validation_command(
            "source-full-hash",
            ["rapidtriage", "e01-hash", str(source), "--output-dir", str(output_root / "source-hash"), "--json"],
            purpose="Compute full source-image hashes with checkpoint evidence.",
            expected_output=str(output_root / "source-hash" / "e01-streaming-hash.json"),
        ),
        _e01_validation_command(
            "dependency-preflight",
            ["rapidtriage", "evidence", str(source), "--output", str(output_root / "rapidtriage-evidence-preflight.json"), "--json"],
            purpose="Record E01 adapter, dependency versions, segment inventory, and blocker guidance.",
            expected_output=str(output_root / "rapidtriage-evidence-preflight.json"),
        ),
        _e01_validation_command(
            "trusted-ewfverify",
            ["ewfverify", str(source)],
            purpose="Preserve libewf/acquisition validation transcript for source integrity comparison.",
            expected_output=str(output_root / "ewfverify-transcript.txt"),
            trusted_tool=True,
        ),
        _e01_validation_command(
            "workflow-smoke",
            smoke_argv,
            purpose="Run the end-to-end smoke workflow and preserve stage status, extraction, analysis, and report outputs.",
            expected_output=str(output_root / "smoke" / "rapidforensic-e01-smoke.json"),
        ),
        _e01_validation_command(
            "trusted-workflow-diff",
            [
                "rapidtriage",
                "image-workflow-validate",
                "--item-number",
                "22",
                "--rapid-output",
                str(output_root / "smoke" / "run" / "rapidtriage-e01.json"),
                "--trusted-output",
                str(output_root / "trusted-e01-workflow.csv"),
                "--trusted-tool",
                "ewfverify",
                "--output",
                str(output_root / "e01-trusted-diff.json"),
                "--json",
            ],
            purpose="Compare RapidForensic source/partition/recovered-file provenance against trusted workflow rows.",
            expected_output=str(output_root / "e01-trusted-diff.json"),
            trusted_tool=True,
        ),
    ]
    for index, command in enumerate(validation_commands or [], start=1):
        if not str(command).strip():
            continue
        command_rows.append(
            {
                "id": f"custom-validation-command-{index:03d}",
                "command": str(command),
                "argv": [],
                "purpose": "Analyst-provided known-answer validation command.",
                "expected_output": "",
                "status": "pending-run",
                "trusted_tool_required": False,
            }
        )
    evidence_slots = [
        {
            "id": "full-source-hash",
            "label": "Full E01/Ex01 source hash evidence",
            "status": "available-from-preflight" if integrity.get("hash_status") == "computed" else "pending-e01-hash-run",
            "required_before_report": True,
            "accepted_artifacts": ["e01-streaming-hash.json", "acquisition hash log", "ewfverify transcript"],
        },
        {
            "id": "segment-inventory",
            "label": "EWF segment inventory and order",
            "status": "complete" if segment_profile.get("segment_count") else "pending-source-scan",
            "required_before_report": True,
            "warnings": list(segment_profile.get("warnings") or []),
        },
        {
            "id": "dependency-version-matrix",
            "label": "libewf/Sleuth Kit path and version matrix",
            "status": "complete" if preflight.get("direct_extract_ready") and not preflight.get("version_unverified_tools") else "pending-preflight",
            "required_before_report": True,
            "tool_count": len(tool_rows),
            "optional_validation_tools": list(E01_VALIDATION_TOOLS),
        },
        {
            "id": "partition-and-recovery-diff",
            "label": "Trusted partition/recovered-file diff",
            "status": "pending-image-workflow-validate",
            "required_before_report": True,
            "required_fields": [
                "source_sha256",
                "selected_start_sector",
                "workflow",
                "segment_count",
                "segment_numbers",
                "recovered_file_count",
                "recovered_file_sha256",
            ],
        },
        {
            "id": "corrupt-encrypted-corpus",
            "label": "Malformed/corrupt/encrypted E01 corpus coverage",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["clean", "split", "missing-segment", "corrupt", "encrypted-or-locked"],
        },
        {
            "id": "platform-tool-matrix",
            "label": "macOS/Linux/Windows tool behavior matrix",
            "status": "external-run-required",
            "required_before_commercial_grade": True,
            "platforms": ["macOS", "Windows WSL2", "Linux"],
        },
    ]
    ready_slots = [slot["id"] for slot in evidence_slots if str(slot.get("status", "")).startswith(("complete", "available"))]
    blocker_slots = [
        slot["id"]
        for slot in evidence_slots
        if slot.get("required_before_report") and not str(slot.get("status", "")).startswith(("complete", "available"))
    ]
    payload: dict[str, object] = {
        "profile_version": E01_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 22,
        "gap_id": "#22",
        "case_id": case_id,
        "source_path": str(source),
        "output_root": str(output_root),
        "status": "report-validation-blocked" if blocker_slots else "ready-for-report-review",
        "commercial_grade_ready": False,
        "expected_partition_start_sector": expected_partition_start_sector,
        "expected_artifacts": expected_artifact_rows,
        "source_integrity": integrity,
        "segment_set_profile": segment_profile,
        "dependency_preflight": preflight,
        "tool_preflight": tool_rows,
        "validation_commands": command_rows,
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slots,
        "blocking_slot_ids": blocker_slots,
        "report_claim_boundary": (
            "This plan can make one E01/Ex01 case reviewable when all report-required slots pass; "
            "commercial-grade product claims still require external corpus and platform matrix evidence."
        ),
        "commercial_grade_blockers": list(E01_REPORT_GRADE_BLOCKERS),
        "operator_next_steps": [
            "Run source-full-hash and dependency-preflight first.",
            "Run trusted-ewfverify or preserve the acquisition suite validation transcript.",
            "Run workflow-smoke, then normalize trusted rows and run trusted-workflow-diff.",
            "Attach this plan, command transcripts, output hashes, and reviewer signoff to the validation package.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def _e01_validation_command(
    command_id: str,
    argv: Sequence[str],
    *,
    purpose: str,
    expected_output: str,
    trusted_tool: bool = False,
) -> dict[str, object]:
    clean_argv = [str(item) for item in argv if str(item) != ""]
    return {
        "id": command_id,
        "argv": clean_argv,
        "command": " ".join(shlex.quote(item) for item in clean_argv),
        "purpose": purpose,
        "expected_output": expected_output,
        "status": "pending-run",
        "trusted_tool_required": trusted_tool,
    }


def stable_manifest_sha256(payload: Mapping[str, object]) -> str:
    redacted = {key: value for key, value in payload.items() if key != "manifest_sha256"}
    encoded = json.dumps(redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_image_stress_known_answer_profile(
    number: int,
    *,
    source_path: Path | str,
    detected_format: str,
    source_integrity: Mapping[str, object] | Sequence[Mapping[str, object]] | None = None,
    tool_preflight: Sequence[Mapping[str, object]] | None = None,
    workflow_plan: Mapping[str, object] | None = None,
    report_grade_assessment: Mapping[str, object] | None = None,
    recovery_unlock_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """One compact stress/corpus readiness profile for image-like inputs.

    E01, RAW/split, VM disks, and proprietary forensic containers each expose
    different validation plans. This profile normalizes the most important
    analyst question: can this exact input be handled as triage evidence now,
    and what corrupt/encrypted/large known-answer evidence is still needed
    before report-grade or commercial-grade claims?
    """

    source = Path(source_path).expanduser()
    gap_id = f"#{number}"
    integrity_rows = _image_source_integrity_rows(source_integrity)
    hash_statuses = sorted(
        {
            str(row.get("hash_status") or "not-recorded")
            for row in integrity_rows
            if isinstance(row, Mapping)
        }
    )
    sizes = [
        _image_optional_int(row.get("size_bytes", row.get("size")))
        for row in integrity_rows
        if isinstance(row, Mapping)
    ]
    source_size_bytes = sum(size for size in sizes if size is not None)
    large_input = (
        any(status in {"deferred-large-source", "skipped-large-file"} for status in hash_statuses)
        or source_size_bytes > DIRECT_IMAGE_HASH_LIMIT_BYTES
    )
    tool_rows = [dict(row) for row in tool_preflight or []]
    missing_tools = [str(row.get("tool")) for row in tool_rows if not row.get("available")]
    plan = dict(workflow_plan or {})
    evidence_slots = [
        dict(slot)
        for slot in plan.get("evidence_slots", [])
        if isinstance(slot, Mapping)
    ]
    slot_statuses = {str(slot.get("id")): str(slot.get("status") or "") for slot in evidence_slots}
    report_grade = dict(report_grade_assessment or {})
    fde_profile = dict(recovery_unlock_profile or {})
    fde_workflow = (
        fde_profile.get("fde_unlock_workflow")
        if isinstance(fde_profile.get("fde_unlock_workflow"), Mapping)
        else fde_profile
    )
    fde_status = str((fde_workflow or {}).get("status") or "not-inspected")
    fde_indicators = [
        dict(item)
        for item in (fde_workflow or {}).get("indicators", [])
        if isinstance(item, Mapping)
    ]
    suspected_encryption = bool(fde_indicators) or fde_status in {
        "indicator-found",
        "unlock-material-required",
        "external-unlock-required-if-detected",
    }
    case_rows = _image_stress_case_rows(
        number,
        large_input=large_input,
        suspected_encryption=suspected_encryption,
        slot_statuses=slot_statuses,
    )
    internal_ready = bool(integrity_rows) and not missing_tools and bool(plan or tool_rows or number == 25)
    external_cases_required = [
        row["id"]
        for row in case_rows
        if str(row.get("status")) in {"external-corpus-required", "external-unlock-required", "external-run-required"}
    ]
    blocker_ids = list(dict.fromkeys(
        [
            *[str(item) for item in report_grade.get("blockers") or [] if str(item)],
            *[str(item) for item in plan.get("blocking_slot_ids") or [] if str(item)],
            *external_cases_required,
        ]
    ))
    status = "triage-ready-external-corpus-required" if internal_ready else "preflight-blocked"
    if suspected_encryption:
        status = "lawful-unlock-or-decrypted-export-required"
    elif large_input:
        status = "large-evidence-hash-and-stress-validation-required" if internal_ready else status
    payload: dict[str, object] = {
        "profile_version": IMAGE_STRESS_KNOWN_ANSWER_PROFILE_VERSION,
        "item_number": number,
        "gap_id": gap_id,
        "detected_format": detected_format,
        "source_path": str(source),
        "status": status,
        "commercial_grade_ready": False,
        "external_evidence_required": True,
        "source_size_bytes": source_size_bytes,
        "source_size_class": "large-or-deferred" if large_input else ("recorded-small" if source_size_bytes else "not-recorded"),
        "source_hash_statuses": hash_statuses,
        "input_risk_flags": [
            flag
            for flag, enabled in {
                "large-source-or-deferred-hash": large_input,
                "encryption-indicator-or-unlock-required": suspected_encryption,
                "missing-direct-tooling": bool(missing_tools),
                "trusted-diff-not-attached": "trusted-workflow-diff" in str(plan),
                "commercial-parser-incomplete": not bool(report_grade.get("ready_for_court_report")),
            }.items()
            if enabled
        ],
        "tooling": {
            "tool_count": len(tool_rows),
            "missing_tools": missing_tools,
            "all_required_tools_available": bool(tool_rows) and not missing_tools,
        },
        "known_answer_case_matrix": case_rows,
        "report_required_slots": [
            {
                "id": str(slot.get("id") or ""),
                "status": str(slot.get("status") or ""),
                "required_before_report": bool(slot.get("required_before_report")),
            }
            for slot in evidence_slots
            if slot.get("required_before_report")
        ][:25],
        "workflow_plan_ref": {
            "profile_version": plan.get("profile_version", ""),
            "manifest_sha256": plan.get("manifest_sha256", ""),
            "status": plan.get("status", ""),
            "blocking_slot_ids": list(plan.get("blocking_slot_ids") or []),
        },
        "large_data_policy": {
            "preflight_hash_limit_bytes": DIRECT_IMAGE_HASH_LIMIT_BYTES,
            "full_acquisition_hash_required_before_report": True,
            "checkpoint_or_resume_required_for_large_runs": number in {22, 23, 24},
            "cursor_or_bounded_review_required": True,
        },
        "unlock_policy": {
            "suspected_encryption": suspected_encryption,
            "fde_status": fde_status,
            "indicator_count": len(fde_indicators),
            "rapidtriage_unlock_engine": "not-implemented",
            "accepted_workaround": "lawful decrypted export or externally unlocked mounted root with hash/log evidence",
        },
        "blocker_ids": blocker_ids,
        "operator_next_steps": _image_stress_next_steps(number, large_input=large_input, suspected_encryption=suspected_encryption),
        "report_claim_boundary": (
            "Use this as an input/workflow readiness profile only. Report-grade conclusions need source hashes, "
            "trusted-tool diffs, known-answer/corpus evidence, and disclosure of corrupt/encrypted/large limitations."
        ),
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def _image_source_integrity_rows(
    source_integrity: Mapping[str, object] | Sequence[Mapping[str, object]] | None,
) -> list[Mapping[str, object]]:
    if not source_integrity:
        return []
    if isinstance(source_integrity, Mapping):
        parts = source_integrity.get("parts")
        if isinstance(parts, Sequence) and not isinstance(parts, (str, bytes, bytearray)):
            return [item for item in parts if isinstance(item, Mapping)]
        return [source_integrity]
    if isinstance(source_integrity, Sequence) and not isinstance(source_integrity, (str, bytes, bytearray)):
        return [item for item in source_integrity if isinstance(item, Mapping)]
    return []


def _image_optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _image_stress_case_rows(
    number: int,
    *,
    large_input: bool,
    suspected_encryption: bool,
    slot_statuses: Mapping[str, str],
) -> list[dict[str, object]]:
    rows_by_number = {
        22: [
            ("clean-e01", "Clean single-segment E01/Ex01", "segment-inventory"),
            ("split-e01", "Contiguous split E01/Ex01 set", "segment-inventory"),
            ("missing-segment", "Missing segment or non-first segment selection", "corrupt-encrypted-corpus"),
            ("corrupt-e01", "Malformed/truncated/checksum-failing EWF", "corrupt-encrypted-corpus"),
            ("encrypted-or-locked-volume", "BitLocker/FileVault/LUKS inside image", "corrupt-encrypted-corpus"),
            ("large-e01", "Large E01/Ex01 with deferred hash and resume", "platform-tool-matrix"),
        ],
        23: [
            ("single-raw", "Single RAW/DD/IMG image", "split-part-inventory"),
            ("contiguous-split", "Contiguous split RAW set", "split-part-inventory"),
            ("gapped-or-damaged-split", "Gapped, out-of-order, or damaged split set", "damaged-gapped-corpus"),
            ("encrypted-volume", "Encrypted partition requiring external unlock", "encrypted-volume-workflow"),
            ("large-raw", "Large RAW/split image stress case", "damaged-gapped-corpus"),
        ],
        24: [
            ("single-base-disk", "Single base VHD/VHDX/VMDK/VDI/QCOW", "qemu-info-and-format-profile"),
            ("snapshot-chain", "Snapshot/differencing/backing-file chain", "snapshot-differencing-chain-corpus"),
            ("missing-parent", "Missing backing/parent disk", "snapshot-differencing-chain-corpus"),
            ("encrypted-compressed-corrupt-vm", "Encrypted, compressed, or corrupt VM disk", "encrypted-compressed-corrupt-vm-corpus"),
            ("large-vm-disk", "Large virtual disk conversion and nested recovery", "encrypted-compressed-corrupt-vm-corpus"),
        ],
        25: [
            ("plain-container-export", "Plain AD1/L01/Lx01/AFF/AFF4 vendor export", "verified-export-manifest"),
            ("encrypted-container", "Encrypted or password-protected container", "encrypted-compressed-container-corpus"),
            ("compressed-container", "Compressed or chunked proprietary container", "encrypted-compressed-container-corpus"),
            ("corrupt-partial-container", "Corrupt/partial proprietary container", "encrypted-compressed-container-corpus"),
            ("metadata-deleted-entry", "Embedded metadata and deleted-entry validation", "metadata-deleted-entry-validation"),
        ],
    }
    rows: list[dict[str, object]] = []
    for case_id, label, slot_id in rows_by_number.get(number, []):
        slot_status = slot_statuses.get(slot_id, "")
        if case_id.startswith("large") and large_input:
            status = "case-triggered"
        elif "encrypted" in case_id and suspected_encryption:
            status = "external-unlock-required"
        elif slot_status.startswith("complete"):
            status = "internally-covered"
        elif slot_status:
            status = slot_status
        else:
            status = "external-corpus-required"
        rows.append(
            {
                "id": case_id,
                "label": label,
                "mapped_evidence_slot": slot_id,
                "status": status,
                "required_before_commercial_grade": status not in {"internally-covered"},
            }
        )
    return rows


def _image_stress_next_steps(number: int, *, large_input: bool, suspected_encryption: bool) -> list[str]:
    next_steps = {
        22: [
            "Run E01 evidence preflight and source/full hash capture.",
            "Run e01-smoke and image-workflow-validate against ewfverify/Sleuth Kit or vendor rows.",
            "Attach malformed, missing-segment, encrypted/locked, and large E01 corpus results before commercial-grade claims.",
        ],
        23: [
            "Inventory split parts and capture per-part hashes before recovery.",
            "Preserve mmls/fsstat/tsk_recover transcripts and diff recovered paths/hashes against a trusted baseline.",
            "Attach damaged/gapped split-set, encrypted-volume, and large RAW stress results before commercial-grade claims.",
        ],
        24: [
            "Preserve qemu-img info, conversion command, converted RAW hash, and nested recovery transcript.",
            "Validate snapshot/backing-chain completeness and converted output against trusted qemu/Sleuth Kit rows.",
            "Attach encrypted/compressed/corrupt and large VM disk corpus results before commercial-grade claims.",
        ],
        25: [
            "Hash the original proprietary container and require a vendor export manifest sidecar.",
            "Scan only the verified derived export folder and keep vendor tool/version/export logs.",
            "Attach encrypted/compressed/corrupt, metadata, deleted-entry, and native-parser version matrix evidence before commercial-grade claims.",
        ],
    }
    steps = list(next_steps.get(number, ["Attach trusted-tool diff and known-answer corpus evidence."]))
    if large_input:
        steps.insert(0, "Capture or attach a full acquisition hash because preflight hashing was deferred for size.")
    if suspected_encryption:
        steps.insert(0, "Use a lawful external unlock/decrypted export workflow and attach source/decrypted hashes plus unlock logs.")
    return steps


def image_validation_matrix(
    *,
    gap_id: str,
    source_integrity: bool,
    tool_preflight: bool,
    partition_table: bool,
    command_history: bool,
    native_complete: bool,
) -> list[dict[str, object]]:
    return [
        {
            "id": f"{gap_id}-source-integrity",
            "label": "Source integrity metadata is captured",
            "passed": source_integrity,
            "severity": "critical",
        },
        {
            "id": f"{gap_id}-tool-preflight",
            "label": "External tool availability/version preflight is captured",
            "passed": tool_preflight,
            "severity": "high",
        },
        {
            "id": f"{gap_id}-partition-or-container-metadata",
            "label": "Partition/container metadata is captured when available",
            "passed": partition_table,
            "severity": "high",
        },
        {
            "id": f"{gap_id}-command-history",
            "label": "Read-only extraction command history is preserved",
            "passed": command_history,
            "severity": "high",
        },
        {
            "id": f"{gap_id}-native-commercial-parser",
            "label": "Native parser is complete enough for standalone commercial/report-grade testimony",
            "passed": native_complete,
            "severity": "critical",
        },
    ]


def image_report_grade_assessment(gap_id: str, blockers: Sequence[str]) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": [gap_id],
        "blockers": list(blockers),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Preserve original acquisition hash, tool versions, command logs, and export/mount logs with the case.",
            "Validate extracted filesystem contents against a trusted forensic tool before report-grade conclusions.",
        ],
    }


def build_image_workflow_trusted_diff(
    number: int,
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blocker = IMAGE_WORKFLOW_TRUSTED_DIFF_BLOCKERS.get(number, "image-workflow-trusted-diff-required")
    rapid_index = index_image_workflow_rows(rapid_rows)
    trusted_index = index_image_workflow_rows(trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in IMAGE_WORKFLOW_TRUSTED_TOOLS
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
                        "image_workflow_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "image-workflow-trusted-diff-v1",
        "gap_id": f"#{number}",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-image-workflow-output-as-final",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def index_image_workflow_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        for payload in image_workflow_diff_payloads(row):
            source_integrity = image_source_integrity_payload(payload)
            partition_selection = (
                payload.get("partition_selection")
                if isinstance(payload.get("partition_selection"), Mapping)
                else {}
            )
            segment_set_profile = (
                payload.get("segment_set_profile")
                if isinstance(payload.get("segment_set_profile"), Mapping)
                else {}
            )
            split_set_profile = (
                payload.get("split_set_profile")
                if isinstance(payload.get("split_set_profile"), Mapping)
                else {}
            )
            recovered_root_manifest = (
                payload.get("recovered_root_manifest")
                if isinstance(payload.get("recovered_root_manifest"), Mapping)
                else {}
            )
            source_path = normalized_image_diff_value(
                first_present(
                    first_image_alias(payload, "source_path", "source", "source_file", "image_path", "container_path"),
                    first_image_alias(source_integrity, "path", "source_path"),
                )
            )
            source_sha256 = normalized_image_diff_value(
                first_present(
                    first_image_alias(payload, "source_sha256", "sha256", "source_hash"),
                    first_image_alias(source_integrity, "sha256", "source_sha256", "source_hash"),
                )
            )
            partition_start = normalized_image_int_text(
                first_present(
                    first_image_alias(payload, "partition_start_sector", "start_sector", "offset_sector"),
                    first_image_alias(partition_selection, "selected_start_sector", "start_sector", "offset_sector"),
                )
            )
            recovery_mode = normalized_image_diff_value(
                first_image_alias(payload, "recovery_mode", "mode", "workflow")
                or ("partition-offset" if partition_start else "")
            )
            converted_raw_sha256 = normalized_image_diff_value(
                first_present(
                    first_image_alias(payload, "converted_raw_sha256", "converted_sha256", "raw_sha256"),
                    first_image_alias(
                        payload.get("converted_raw_integrity")
                        if isinstance(payload.get("converted_raw_integrity"), Mapping)
                        else {},
                        "sha256",
                    ),
                )
            )
            virtual_disk_chain_profile = (
                payload.get("virtual_disk_chain_profile")
                if isinstance(payload.get("virtual_disk_chain_profile"), Mapping)
                else {}
            )
            container_type = normalized_image_diff_value(
                first_present(
                    first_image_alias(payload, "container_type", "detected_format", "format", "virtual_disk_format"),
                    first_image_alias(virtual_disk_chain_profile, "detected_format", "format"),
                )
            )
            export_manifest_sha256 = normalized_image_diff_value(
                first_present(
                    first_image_alias(payload, "export_manifest_sha256", "manifest_sha256", "vendor_manifest_sha256"),
                    first_image_alias(
                        payload.get("verified_export_manifest_profile")
                        if isinstance(payload.get("verified_export_manifest_profile"), Mapping)
                        else {},
                        "manifest_sha256",
                    ),
                )
            )
            extracted_path = normalized_image_diff_value(
                first_image_alias(payload, "extracted_file_path", "file_path", "relative_path", "path", "name")
            )
            extracted_sha256 = normalized_image_diff_value(
                first_image_alias(payload, "extracted_sha256", "file_sha256", "recovered_sha256", "sha256")
            )
            key = "|".join(
                item
                for item in (
                    source_path,
                    partition_start,
                    recovery_mode,
                    container_type,
                    extracted_path,
                )
                if item
            )
            if not key:
                continue
            indexed[key] = {
                "source_path": source_path,
                "source_sha256": source_sha256,
                "partition_start_sector": partition_start,
                "recovery_mode": recovery_mode,
                "converted_raw_sha256": converted_raw_sha256,
                "container_type": container_type,
                "export_manifest_sha256": export_manifest_sha256,
                "extracted_file_path": extracted_path,
                "extracted_sha256": extracted_sha256,
                "virtual_disk_format": normalized_image_diff_value(
                    first_present(
                        first_image_alias(payload, "virtual_disk_format"),
                        first_image_alias(virtual_disk_chain_profile, "detected_format"),
                    )
                ),
                "virtual_disk_chain_status": normalized_image_diff_value(
                    first_present(
                        first_image_alias(payload, "virtual_disk_chain_status", "chain_status"),
                        first_image_alias(virtual_disk_chain_profile, "chain_validation_status"),
                    )
                ),
                "suspected_snapshot_or_differencing_member": normalized_image_bool_text(
                    first_present(
                        first_image_alias(payload, "suspected_snapshot_or_differencing_member", "snapshot_member"),
                        first_image_alias(virtual_disk_chain_profile, "suspected_snapshot_or_differencing_member"),
                    )
                ),
                "parent_chain_resolution": normalized_image_diff_value(
                    first_present(
                        first_image_alias(payload, "parent_chain_resolution"),
                        first_image_alias(virtual_disk_chain_profile, "parent_chain_resolution"),
                    )
                ),
                "ewf_segment_count": normalized_image_int_text(
                    first_present(
                        first_image_alias(payload, "ewf_segment_count", "segment_count"),
                        first_image_alias(segment_set_profile, "segment_count"),
                    )
                ),
                "ewf_segment_numbers": normalized_image_list(
                    first_present(
                        first_image_alias(payload, "ewf_segment_numbers", "segment_numbers"),
                        first_image_alias(segment_set_profile, "segment_numbers"),
                    )
                ),
                "ewf_segments_contiguous": normalized_image_bool_text(
                    first_present(
                        first_image_alias(payload, "ewf_segments_contiguous", "contiguous"),
                        first_image_alias(segment_set_profile, "contiguous"),
                    )
                ),
                "selected_is_first_segment": normalized_image_bool_text(
                    first_present(
                        first_image_alias(payload, "selected_is_first_segment", "first_segment"),
                        first_image_alias(segment_set_profile, "selected_is_first_segment"),
                        first_image_alias(split_set_profile, "selected_is_first_segment"),
                    )
                ),
                "split_part_count": normalized_image_int_text(
                    first_present(
                        first_image_alias(payload, "split_part_count", "part_count"),
                        first_image_alias(split_set_profile, "part_count"),
                    )
                ),
                "split_segment_numbers": normalized_image_list(
                    first_present(
                        first_image_alias(payload, "split_segment_numbers", "split_part_numbers"),
                        first_image_alias(split_set_profile, "segment_numbers"),
                    )
                ),
                "split_set_contiguous": normalized_image_bool_text(
                    first_present(
                        first_image_alias(payload, "split_set_contiguous"),
                        first_image_alias(split_set_profile, "contiguous"),
                    )
                ),
                "recovered_file_count": normalized_image_int_text(
                    first_present(
                        first_image_alias(payload, "recovered_file_count", "visited_file_count"),
                        first_image_alias(recovered_root_manifest, "visited_file_count"),
                    )
                ),
                "hashed_file_count": normalized_image_int_text(
                    first_present(
                        first_image_alias(payload, "hashed_file_count"),
                        first_image_alias(recovered_root_manifest, "hashed_file_count"),
                    )
                ),
            }
    return indexed


def image_workflow_diff_payloads(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    payload = image_workflow_row_payload(row)
    raw_extraction = payload.get("raw_extraction") if isinstance(payload.get("raw_extraction"), Mapping) else {}
    if raw_extraction:
        raw_payload = dict(raw_extraction)
        if payload.get("source_path"):
            raw_payload["source_path"] = payload.get("source_path")
        if payload.get("source_integrity"):
            raw_payload["source_integrity"] = payload.get("source_integrity")
        for key in (
            "converted_raw_path",
            "converted_raw_integrity",
            "conversion_tool",
            "virtual_disk_chain_profile",
            "qemu_img_info_profile",
            "container_type",
            "detected_format",
        ):
            raw_payload.setdefault(key, payload.get(key))
        expanded_raw = image_workflow_diff_payloads(raw_payload)
        if expanded_raw:
            return expanded_raw
    recovered_root_manifest = (
        payload.get("recovered_root_manifest")
        if isinstance(payload.get("recovered_root_manifest"), Mapping)
        else {}
    )
    files = recovered_root_manifest.get("files")
    if isinstance(files, Sequence) and not isinstance(files, (str, bytes, bytearray)):
        expanded: list[Mapping[str, object]] = []
        for item in files:
            if not isinstance(item, Mapping):
                continue
            child = dict(item)
            if child.get("sha256") and not child.get("extracted_sha256"):
                child["extracted_sha256"] = child.get("sha256")
                child.pop("sha256", None)
            for key in (
                "source_path",
                "source_integrity",
                "converted_raw_path",
                "converted_raw_integrity",
                "conversion_tool",
                "virtual_disk_chain_profile",
                "qemu_img_info_profile",
                "partition_start_sector",
                "partition_selection",
                "recovery_mode",
                "segment_set_profile",
                "split_set_profile",
                "recovered_root_manifest",
                "container_type",
                "detected_format",
            ):
                child.setdefault(key, payload.get(key))
            expanded.append(child)
        if expanded:
            return expanded
    return [payload]


def image_workflow_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def image_source_integrity_payload(payload: Mapping[str, object]) -> Mapping[str, object]:
    source_integrity = payload.get("source_integrity")
    if isinstance(source_integrity, Mapping):
        return source_integrity
    if isinstance(source_integrity, Sequence) and not isinstance(source_integrity, (str, bytes, bytearray)):
        source_path = normalized_image_diff_value(
            first_image_alias(payload, "source_path", "source", "source_file", "image_path", "container_path")
        )
        first_mapping: Mapping[str, object] | None = None
        for item in source_integrity:
            if not isinstance(item, Mapping):
                continue
            if first_mapping is None:
                first_mapping = item
            item_path = normalized_image_diff_value(first_image_alias(item, "path", "source_path"))
            if source_path and item_path == source_path:
                return item
        if first_mapping is not None:
            return first_mapping
    return {}


def first_present(*values: object) -> object:
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def normalized_image_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return normalized_image_diff_value(text)


def normalized_image_bool_text(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalized_image_diff_value(value)
    if text in {"1", "yes", "y", "true", "contiguous"}:
        return "true"
    if text in {"0", "no", "n", "false", "not-contiguous"}:
        return "false"
    return text


def normalized_image_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[\r\n,;|]", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_image_diff_value(part) for part in parts if part}))


def first_image_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_image_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_image_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalize_image_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def normalized_image_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def image_reportability_decision(
    number: int,
    *,
    blockers: Sequence[str],
    failed_validation_matrix_ids: Sequence[str],
    details: Mapping[str, object],
) -> dict[str, object]:
    decisions = {
        22: ("do-not-report-e01-ex01-workflow-as-native-complete", "e01-ex01-extraction-triage-pivot"),
        23: ("do-not-report-raw-split-workflow-as-native-complete", "raw-split-extraction-triage-pivot"),
        24: ("do-not-report-virtual-disk-workflow-as-chain-complete", "virtual-disk-extraction-triage-pivot"),
        25: ("do-not-report-proprietary-container-as-natively-parsed", "vendor-export-container-triage-pivot"),
    }
    decision, allowed_use = decisions.get(number, ("do-not-report-image-workflow-as-commercial-grade", "image-workflow-triage-pivot"))
    source_integrity = details.get("source_integrity")
    trusted_diff = details.get("image_trusted_diff") if isinstance(details.get("image_trusted_diff"), Mapping) else {}
    if isinstance(source_integrity, Mapping):
        source_hash_statuses = [str(source_integrity.get("hash_status") or "")]
    elif isinstance(source_integrity, list):
        source_hash_statuses = [
            str(item.get("hash_status") or "") for item in source_integrity if isinstance(item, Mapping)
        ]
    else:
        source_hash_statuses = []
    required_before_report = {
        22: [
            "validate E01/Ex01 segment metadata and extraction against known-answer images",
            "attach libewf/Sleuth Kit versions, commands, hashes, and corrupt/encrypted image limitations",
            "confirm extracted filesystem contents against a trusted forensic suite before final testimony",
        ],
        23: [
            "validate split-set order/gap handling with damaged and large known-answer corpora",
            "attach native partition/filesystem or trusted-tool comparison evidence",
            "document encrypted-volume and deleted-file recovery limitations per case",
        ],
        24: [
            "resolve or explicitly exclude snapshot and differencing-disk chains",
            "preserve qemu-img conversion provenance and compare converted raw content against a trusted workflow",
            "capture hypervisor metadata and encryption limitations before report-grade claims",
        ],
        25: [
            "parse the proprietary container natively or attach a verified vendor export manifest",
            "hash the original container and derived export payloads",
            "validate embedded metadata, deleted entries, compression, and encryption behavior for the format",
        ],
    }
    decision_blockers = sorted({str(item) for item in blockers if str(item)})
    if trusted_diff.get("status") != "pass":
        trusted_blocker = IMAGE_WORKFLOW_TRUSTED_DIFF_BLOCKERS.get(number)
        if trusted_blocker:
            decision_blockers = sorted({*decision_blockers, trusted_blocker})
    return {
        "profile_version": "image-workflow-reportability-decision-v1",
        "commercial_gap_ids": [f"#{number}"],
        "decision": decision,
        "allowed_use": allowed_use,
        "blockers": decision_blockers,
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "source_hash_statuses": [status for status in source_hash_statuses if status],
        "native_parser_complete": False,
        "external_tool_or_vendor_workflow_required": True,
        "ready_for_court_report": False,
        "required_before_report": required_before_report.get(
            number,
            ["attach known-answer validation and independent reviewer evidence before report-grade claims"],
        ),
    }


def image_commercial_uplift_evidence(number: int, details: Mapping[str, object]) -> dict[str, object]:
    gap_id = f"#{number}"
    matrix = image_validation_matrix(
        gap_id=gap_id,
        source_integrity=bool(details.get("source_integrity")),
        tool_preflight=bool(details.get("tool_preflight")),
        partition_table=bool(details.get("partition_table"))
        or bool(details.get("detected_format"))
        or bool(details.get("container_type")),
        command_history=bool(details.get("command_history")),
        native_complete=False,
    )
    source_integrity = details.get("source_integrity")
    if isinstance(source_integrity, Mapping):
        source_hashes = [str(source_integrity.get("sha256") or "")]
        hash_statuses = [str(source_integrity.get("hash_status") or "")]
        split_part_count = 1 if source_integrity else 0
    elif isinstance(source_integrity, list):
        parts = [item for item in source_integrity if isinstance(item, Mapping)]
        source_hashes = [str(item.get("sha256") or "") for item in parts]
        hash_statuses = [str(item.get("hash_status") or "") for item in parts]
        split_part_count = len(parts)
    else:
        source_hashes = []
        hash_statuses = []
        split_part_count = 0
    report_grade = details.get("image_report_grade_assessment")
    blockers = (
        report_grade.get("blockers")
        if isinstance(report_grade, Mapping) and isinstance(report_grade.get("blockers"), list)
        else details.get("limitations")
    )
    objectives = {
        22: "Make E01/Ex01 workflow evidence explicit: source integrity, tool preflight, partition selection, read-only extraction provenance, and blockers.",
        23: "Make RAW/split image handling evidence explicit: segment order, gap checks, partition selection, filesystem recovery audit, and encrypted-volume blockers.",
        24: "Make virtual-disk workflow evidence explicit: qemu-img conversion provenance, converted raw integrity, nested recovery, and snapshot/differencing blockers.",
        25: "Make forensic container support evidence explicit: format detection, source integrity, export-first workflow, and native parser blockers.",
    }
    next_steps = {
        22: "Add native E01/Ex01 segment metadata parsing and run encrypted/corrupt image known-answer corpora.",
        23: "Add native partition/filesystem parsing, large damaged split-set tests, and encrypted-volume workflow evidence.",
        24: "Add snapshot/differencing-chain resolution, hypervisor metadata capture, and qemu-img version-matrix validation.",
        25: "Implement/import native or verified vendor parsers for AD1/L01/Lx01/AFF/AFF4/XVA and validate metadata/deleted-entry handling.",
    }
    passed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
    ]
    failed_validation_matrix_ids = [
        str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
    ]
    reportability_decision = image_reportability_decision(
        number,
        blockers=list(blockers or []),
        failed_validation_matrix_ids=failed_validation_matrix_ids,
        details=details,
    )
    trusted_diff = (
        details.get("image_trusted_diff")
        if isinstance(details.get("image_trusted_diff"), Mapping)
        else {"status": "not-attached", "commercial_grade_evidence": False}
    )
    segment_set_profile = details.get("segment_set_profile") if isinstance(details.get("segment_set_profile"), Mapping) else {}
    split_set_profile = details.get("split_set_profile") if isinstance(details.get("split_set_profile"), Mapping) else {}
    virtual_disk_chain_profile = (
        details.get("virtual_disk_chain_profile")
        if isinstance(details.get("virtual_disk_chain_profile"), Mapping)
        else {}
    )
    return {
        "batch_id": "commercial-uplift-021-025",
        "item_numbers": [number],
        "implementation_track": "evidence-image-workflow",
        "implemented": True,
        "usable": True,
        "validated": True,
        "commercial_grade_ready": False,
        "objective": objectives.get(number, "Expose evidence-image validation evidence without overclaiming commercial-grade readiness."),
        "reportability_decision": reportability_decision,
        "image_trusted_diff": trusted_diff,
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            *[f"source_sha256:{value}" for value in source_hashes[:5] if value and value != "None"],
            f"detected_format:{details.get('detected_format', '')}",
            f"converted_raw_path:{details.get('converted_raw_path', '')}",
        ],
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "commercial_blockers": list(blockers or []),
        "large_data_controls": {
            "direct_image_hash_limit_bytes": DIRECT_IMAGE_HASH_LIMIT_BYTES,
            "source_hash_statuses": [status for status in hash_statuses if status],
            "split_part_count": int(details.get("split_part_count") or split_part_count),
            "ewf_segment_count": int(segment_set_profile.get("segment_count") or 0),
            "ewf_segment_warnings": list(segment_set_profile.get("warnings") or []),
            "split_set_contiguous": split_set_profile.get("contiguous"),
            "split_set_warnings": list(split_set_profile.get("warnings") or []),
            "virtual_disk_chain_status": virtual_disk_chain_profile.get("chain_validation_status"),
            "virtual_disk_chain_warnings": list(virtual_disk_chain_profile.get("warnings") or []),
            "export_manifest_sha256": details.get("export_manifest_sha256", ""),
            "partition_table_row_count": len(details.get("partition_table") or []),
            "tool_preflight_count": len(details.get("tool_preflight") or []),
            "command_history_count": len(details.get("command_history") or []),
            "external_tool_or_vendor_workflow_required": True,
            "native_parser_complete": False,
        },
        "next_internal_step": next_steps.get(number, "Attach known-answer corpora and close native parser blockers."),
        "external_evidence_required": True,
    }


def image_core_accuracy_gates(number: int, details: dict[str, object]) -> list[dict[str, object]]:
    source_integrity = details.get("source_integrity")
    if isinstance(source_integrity, dict):
        source_hashes = [str(source_integrity.get("sha256") or "")]
        source_parts = [source_integrity]
    elif isinstance(source_integrity, list):
        source_parts = [item for item in source_integrity if isinstance(item, dict)]
        source_hashes = [str(item.get("sha256") or "") for item in source_parts]
    else:
        source_parts = []
        source_hashes = []
    tool_preflight = [item for item in details.get("tool_preflight") or [] if isinstance(item, dict)]
    command_history = [item for item in details.get("command_history") or [] if isinstance(item, dict)]
    partition_table = [item for item in details.get("partition_table") or [] if isinstance(item, dict)]
    warnings = [str(item) for item in details.get("warnings") or [] if str(item)]
    limitations = [str(item) for item in details.get("limitations") or [] if str(item)]
    native_capabilities = details.get("native_capabilities") if isinstance(details.get("native_capabilities"), dict) else {}
    trusted_diff = details.get("image_trusted_diff") if isinstance(details.get("image_trusted_diff"), Mapping) else {}
    segment_set_profile = details.get("segment_set_profile") if isinstance(details.get("segment_set_profile"), Mapping) else {}
    split_set_profile = details.get("split_set_profile") if isinstance(details.get("split_set_profile"), Mapping) else {}
    virtual_disk_chain_profile = (
        details.get("virtual_disk_chain_profile")
        if isinstance(details.get("virtual_disk_chain_profile"), Mapping)
        else {}
    )

    evidence_refs = [f"source_path:{details.get('source_path', '')}"]
    for value in source_hashes[:5]:
        if value and value != "None":
            evidence_refs.append(f"source_sha256:{value}")
    if details.get("converted_raw_integrity") and isinstance(details["converted_raw_integrity"], dict):
        converted_hash = details["converted_raw_integrity"].get("sha256")
        if converted_hash:
            evidence_refs.append(f"converted_raw_sha256:{converted_hash}")

    satisfied: list[str] = []
    if number == 22:
        if source_parts:
            satisfied.append("source hash and segment integrity")
        if segment_set_profile:
            satisfied.append("EWF segment-set order validation")
        if tool_preflight or command_history:
            satisfied.append("tool version/command capture")
        if details.get("partition_start_sector") is not None or any(item.get("selected_for_recovery") for item in partition_table):
            satisfied.append("partition offset correctness")
        if command_history or details.get("read_only_source") or details.get("safety"):
            satisfied.append("read-only extraction provenance")
        if warnings or limitations:
            satisfied.append("corrupt/encrypted limitation reporting")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted E01/Ex01 workflow diff pass")
    elif number == 23:
        if source_parts or details.get("split_part_warnings") is not None or split_set_profile:
            satisfied.append("split-set order and gap validation")
        if split_set_profile:
            satisfied.append("split-set provenance profile")
        if partition_table or details.get("partition_start_sector") is not None:
            satisfied.append("partition table parsing")
        if command_history or details.get("recovery_mode"):
            satisfied.append("filesystem extraction audit")
        if any("tsk_recover" in " ".join(map(str, row.get("command", []))) and "-e" in row.get("command", []) for row in command_history):
            satisfied.append("deleted-file recovery expectations")
        if warnings or limitations or not native_capabilities.get("encrypted_volume_unlock_workflow", True):
            satisfied.append("encrypted volume limitation warning")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted RAW/split image recovery diff pass")
    elif number == 24:
        if any(str(item.get("tool") or "") == "qemu-img" for item in tool_preflight) or any("qemu-img" in " ".join(map(str, row.get("command", []))) for row in command_history):
            satisfied.append("qemu-img version/command capture")
        if not native_capabilities.get("snapshot_chain_validation", True) or not native_capabilities.get("differencing_disk_resolution", True):
            satisfied.append("snapshot/differencing-chain detection")
        if virtual_disk_chain_profile:
            satisfied.append("virtual disk chain risk profile")
        if details.get("converted_raw_integrity") or details.get("converted_raw_path"):
            satisfied.append("converted raw hash/provenance")
        if partition_table or details.get("raw_extraction") or details.get("nested_raw_extraction"):
            satisfied.append("nested partition extraction")
        if warnings or limitations or not native_capabilities.get("xva_direct_extraction", True):
            satisfied.append("unsupported/encrypted VM warning")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted virtual disk conversion diff pass")
    elif number == 25:
        if details.get("detected_format") or details.get("container_type"):
            satisfied.append("container type detection")
        if source_parts:
            satisfied.append("source integrity capture")
        if details.get("scan_strategy") or details.get("fallback_guidance") or details.get("native_vs_export_workflow"):
            satisfied.append("native-vs-export workflow disclosure")
        if not native_capabilities.get("deleted_entry_recovery", True) or limitations:
            satisfied.append("metadata/deleted-entry validation")
        if warnings or limitations:
            satisfied.append("encrypted/compressed limitation warning")
        if trusted_diff.get("status") == "pass":
            satisfied.append("verified vendor export manifest diff pass")

    return [build_accuracy_gate(number, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def image_workflow_analyst_review_profile(number: int, details: Mapping[str, object]) -> dict[str, object]:
    """Compact review card for image/container workflows.

    The full workflow manifests are intentionally verbose. This profile gives the UI/report
    layer a stable, low-noise summary of the same evidence and caveats without making a
    commercial-grade parser claim.
    """

    gap_id = f"#{number}"
    detected_format = str(details.get("detected_format") or details.get("container_type") or "image")
    source_path = str(details.get("source_path") or "")
    support_level = str(details.get("support_level") or "")
    scan_strategy = str(details.get("scan_strategy") or "")
    report_grade = (
        details.get("image_report_grade_assessment")
        if isinstance(details.get("image_report_grade_assessment"), Mapping)
        else image_report_grade_assessment(gap_id, [str(item) for item in details.get("limitations") or []])
    )
    native_capabilities = (
        details.get("native_capabilities") if isinstance(details.get("native_capabilities"), Mapping) else {}
    )
    workflow_manifest = (
        details.get("workflow_manifest") if isinstance(details.get("workflow_manifest"), Mapping) else {}
    )
    source_integrity = details.get("source_integrity")
    source_hash = ""
    hash_status = "not-recorded"
    if isinstance(source_integrity, Mapping):
        if isinstance(source_integrity.get("parts"), list):
            parts = [part for part in source_integrity.get("parts") or [] if isinstance(part, Mapping)]
            source_hash = str((parts[0] or {}).get("sha256") or "") if parts else ""
            hash_status = "split-parts-recorded" if parts else str(source_integrity.get("hash_status") or "not-recorded")
        else:
            source_hash = str(source_integrity.get("sha256") or "")
            hash_status = str(source_integrity.get("hash_status") or "not-recorded")
    tool_preflight = [row for row in details.get("tool_preflight") or [] if isinstance(row, Mapping)]
    missing_tools = [str(item) for item in details.get("missing_tools") or [] if str(item)]
    if not missing_tools:
        missing_tools = [str(row.get("tool") or "") for row in tool_preflight if not row.get("available")]
    blockers = [str(item) for item in report_grade.get("blockers") or [] if str(item)]
    stages = workflow_manifest.get("stages") if isinstance(workflow_manifest.get("stages"), list) else []
    blocked_stages = [
        str(stage.get("id") or stage.get("label") or "")
        for stage in stages
        if isinstance(stage, Mapping) and str(stage.get("status") or "").startswith("blocked")
    ]
    review_required_stages = [
        str(stage.get("id") or stage.get("label") or "")
        for stage in stages
        if isinstance(stage, Mapping) and "review" in str(stage.get("status") or "")
    ]

    type_guidance = {
        22: {
            "artifact_type": "e01-ex01-workflow",
            "interpretation": "E01/Ex01 source can be identified, integrity-checked, and routed through preflight/extraction/review workflow evidence.",
            "not_proof_of": [
                "native EWF parser completeness",
                "encrypted or corrupt image support",
                "all deleted files recovered",
            ],
            "correlations": ["partition table", "filesystem extraction log", "case run outputs", "trusted EWF/TSK diff"],
        },
        23: {
            "artifact_type": "raw-split-workflow",
            "interpretation": "RAW/split image parts, split continuity, and Sleuth Kit recovery readiness are preserved as review pivots.",
            "not_proof_of": [
                "native filesystem parser completeness",
                "gapped split set correctness",
                "encrypted volume access",
            ],
            "correlations": ["acquisition segment log", "mmls output", "tsk_recover output", "known-answer file hashes"],
        },
        24: {
            "artifact_type": "virtual-disk-workflow",
            "interpretation": "Virtual disk conversion and nested RAW recovery are tracked with qemu-img/Sleuth Kit provenance.",
            "not_proof_of": [
                "snapshot or differencing chain completeness",
                "hypervisor metadata reconstruction",
                "XVA direct parsing",
            ],
            "correlations": ["qemu-img info", "converted raw hash", "parent disk inventory", "nested RAW manifest"],
        },
        25: {
            "artifact_type": "forensic-container-workflow",
            "interpretation": "Proprietary forensic containers are detected and routed to a verified vendor-export workflow.",
            "not_proof_of": [
                "native AD1/L01/Lx01/AFF/AFF4 parsing",
                "deleted-entry recovery",
                "embedded metadata or compression validation",
            ],
            "correlations": ["vendor export manifest", "source container hash", "export log", "derived folder scan"],
        },
    }.get(number, {})

    return {
        "profile_version": "image-workflow-analyst-review-profile-v1",
        "gap_id": gap_id,
        "artifact_type": type_guidance.get("artifact_type", "image-workflow"),
        "detected_format": detected_format,
        "severity": "high" if blockers or missing_tools or blocked_stages else "medium",
        "summary": f"{detected_format} workflow is usable as a triage/review path, not a native commercial parser claim.",
        "evidence_interpretation": type_guidance.get("interpretation", "Image workflow evidence is a triage pivot."),
        "not_proof_of": type_guidance.get("not_proof_of", []),
        "analyst_questions": [
            "Is the source hash recorded and matched to the acquisition record?",
            "Which external tool versions/commands produced the derived evidence?",
            "Was the selected partition or vendor export validated against a trusted baseline?",
            "Are blocked/review-required stages disclosed in the report?",
        ],
        "primary_pivots": [
            "source_path",
            "detected_format",
            "source_sha256",
            "support_level",
            "scan_strategy",
            "workflow_manifest_hash",
            "partition_start_sector",
            "converted_raw_sha256",
            "export_manifest_sha256",
        ],
        "source_field_values": {
            "source_path": source_path,
            "detected_format": detected_format,
            "source_sha256": source_hash,
            "hash_status": hash_status,
            "support_level": support_level,
            "scan_strategy": scan_strategy,
            "workflow_manifest_hash": str(workflow_manifest.get("manifest_sha256") or ""),
            "partition_start_sector": details.get("partition_start_sector"),
            "converted_raw_sha256": (
                (details.get("converted_raw_integrity") or {}).get("sha256")
                if isinstance(details.get("converted_raw_integrity"), Mapping)
                else ""
            ),
            "export_manifest_sha256": str(details.get("export_manifest_sha256") or ""),
            "missing_tools": missing_tools,
            "blocked_stages": blocked_stages,
            "review_required_stages": review_required_stages,
        },
        "correlation_targets": type_guidance.get("correlations", []),
        "risk_tags": [
            tag
            for tag, enabled in {
                "external-tool-dependency": bool(tool_preflight or missing_tools),
                "native-parser-incomplete": not bool(native_capabilities.get("native_e01_ex01_parser"))
                and not bool(native_capabilities.get("native_partition_filesystem_parser"))
                and not bool(native_capabilities.get("direct_ad1_l01_lx01_aff_aff4_parser")),
                "encrypted-or-corrupt-corpus-required": any("encrypted" in item or "corrupt" in item for item in blockers),
                "vendor-export-required": number == 25 or scan_strategy == "vendor-export-first",
            }.items()
            if enabled
        ],
        "validation_required": True,
        "report_grade_ready": bool(report_grade.get("ready_for_court_report")),
        "commercial_blockers": blockers,
        "report_guidance": "Cite this as workflow/provenance evidence only. Attach trusted-tool diff, known-answer results, and source hashes before report-grade image/container claims.",
    }


def collect_tool_preflight(
    tools: Sequence[str],
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> list[dict[str, object]]:
    preflight: list[dict[str, object]] = []
    for tool in tools:
        resolved = tool_resolver(tool)
        profile = TOOL_PREFLIGHT_PROFILES.get(tool, {})
        version_commands = profile.get("version_commands")
        if not isinstance(version_commands, tuple):
            version_commands = ((tool, "--version"),)
        row: dict[str, object] = {
            "tool": tool,
            "path": resolved,
            "available": resolved is not None,
            "version": None,
            "purpose": profile.get("purpose") or "External tool required by the selected evidence workflow.",
            "package": profile.get("package") or tool,
            "install_hint": profile.get("install_hint") or f"Install {tool} and ensure it is on PATH.",
            "windows_hint": profile.get("windows_hint") or "Use WSL2 or a trusted mounted/exported evidence folder when the tool is unavailable.",
            "version_command": list(version_commands[0]),
            "version_commands": [list(command) for command in version_commands],
            "remediation": None if resolved is not None else profile.get("install_hint") or f"Install {tool} and ensure it is on PATH.",
        }
        if resolved is not None:
            attempts: list[dict[str, object]] = []
            try:
                for command in version_commands:
                    command_list = list(command)
                    result = runner(command_list)
                    text = (result.stdout or result.stderr or "").strip().splitlines()
                    attempt = {
                        "command": command_list,
                        "returncode": result.returncode,
                        "preview": text[0] if text else "",
                    }
                    attempts.append(attempt)
                    if result.returncode == 0 and text:
                        row["version"] = text[0]
                        row["version_command"] = command_list
                        row["version_returncode"] = result.returncode
                        break
                else:
                    row["version_returncode"] = attempts[-1]["returncode"] if attempts else None
            except (OSError, IndexError) as exc:
                row["version_error"] = str(exc)
            row["version_attempts"] = attempts
        preflight.append(row)
    return preflight


def command_record(
    purpose: str,
    command: Sequence[str],
    result: subprocess.CompletedProcess[str],
    *,
    limit: int = 2000,
) -> dict[str, object]:
    return {
        "purpose": purpose,
        "command": list(command),
        "returncode": result.returncode,
        "stdout_preview": (result.stdout or "")[:limit],
        "stderr_preview": (result.stderr or "")[:limit],
    }


def unmount_e01_mount(
    mount_dir: Path,
    *,
    runner: CommandRunner = default_runner,
    tool_resolver: ToolResolver = shutil.which,
) -> None:
    if not mount_dir.exists():
        return
    if tool_resolver("umount") is not None:
        runner(["umount", str(mount_dir)])
    if tool_resolver("fusermount") is not None:
        runner(["fusermount", "-u", str(mount_dir)])
