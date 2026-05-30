from __future__ import annotations

import json
import shlex
import shutil
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Mapping, Protocol

from .audit import compute_sha256
from .archive_image import ARCHIVE_IMAGE_SUFFIXES, ARCHIVE_IMAGE_TOOLS, missing_archive_image_tools
from .carving import DEFAULT_MAX_CANDIDATES, DEFAULT_MAX_SCAN_BYTES, SIGNATURES
from .disk_image import (
    RAW_IMAGE_REQUIRED_TOOLS,
    RAW_IMAGE_SUFFIXES,
    build_raw_split_report_grade_validation_plan,
    build_split_set_profile,
    discover_split_image_parts,
    missing_raw_image_tools,
)
from .e01 import (
    E01_REPORT_GRADE_BLOCKERS,
    E01_SUFFIXES,
    E01_REQUIRED_TOOLS,
    build_e01_intake_profile,
    build_e01_report_grade_validation_plan,
    collect_tool_preflight,
    build_e01_segment_set_profile,
    build_e01_ingest_workflow_profile,
    build_image_stress_known_answer_profile,
    describe_source_integrity,
    e01_failure_guidance,
    e01_preflight_summary,
    image_core_accuracy_gates,
    image_commercial_uplift_evidence,
    image_report_grade_assessment,
    image_reportability_decision,
    image_workflow_analyst_review_profile,
    missing_e01_tools,
    stable_manifest_sha256,
)
from .virtual_disk import (
    VIRTUAL_DISK_REQUIRED_TOOLS,
    VIRTUAL_DISK_SUFFIXES,
    build_virtual_disk_chain_profile,
    build_virtual_disk_report_grade_validation_plan,
    missing_virtual_disk_tools,
)


class EvidenceAdapter(Protocol):
    name: str
    supported_suffixes: tuple[str, ...]

    def identify(self, source: Path) -> "EvidenceAdapterResult":
        ...


@dataclass(frozen=True)
class EvidenceAdapterResult:
    adapter: str
    source_path: str
    detected_format: str
    supported: bool
    can_mount: bool
    can_extract: bool
    required_tools: list[str]
    missing_tools: list[str]
    message: str
    support_level: str
    scan_strategy: str
    next_actions: list[str]
    warnings: list[str]
    external_validation_required: bool = True
    source_integrity: dict[str, object] | None = None
    tool_preflight: list[dict[str, object]] | None = None
    preflight_summary: dict[str, object] | None = None
    commercial_grade_ready: bool = False
    commercial_gap_ids: list[str] | None = None
    report_grade_assessment: dict[str, object] | None = None
    forensic_review: dict[str, object] | None = None
    native_capabilities: dict[str, object] | None = None
    limitations: list[str] | None = None
    fallback_guidance: list[str] | None = None
    safety_notes: list[str] | None = None
    core_accuracy_gates: list[dict[str, object]] | None = None
    commercial_uplift_evidence: dict[str, object] | None = None
    failure_guidance: dict[str, object] | None = None
    segment_set_profile: dict[str, object] | None = None
    split_set_profile: dict[str, object] | None = None
    virtual_disk_chain_profile: dict[str, object] | None = None
    container_export_profile: dict[str, object] | None = None
    verified_export_manifest_profile: dict[str, object] | None = None
    forensic_container_workflow_manifest: dict[str, object] | None = None
    forensic_container_validation_plan: dict[str, object] | None = None
    ingest_workflow: dict[str, object] | None = None
    image_analyst_review_profile: dict[str, object] | None = None
    e01_intake_profile: dict[str, object] | None = None
    e01_validation_plan: dict[str, object] | None = None
    raw_split_validation_plan: dict[str, object] | None = None
    virtual_disk_validation_plan: dict[str, object] | None = None
    recovery_unlock_profile: dict[str, object] | None = None
    image_stress_workflow_profile: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evidence_forensic_review(
    *,
    gap_id: str,
    artifact_goal: str,
    primary_evidence: list[str],
    report_grade_assessment: dict[str, object],
    caveats: list[str],
) -> dict[str, object]:
    blockers = report_grade_assessment.get("blockers")
    return {
        "gap_id": gap_id,
        "artifact_goal": artifact_goal,
        "review_status": "triage-review",
        "report_grade_ready": bool(report_grade_assessment.get("ready_for_court_report")),
        "validation_required": True,
        "primary_evidence": [item for item in primary_evidence if item],
        "blockers": list(blockers) if isinstance(blockers, list) else [],
        "caveats": caveats,
    }


FDE_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"-FVE-FS-", "bitlocker-fve-signature", "BitLocker"),
    (b"LUKS\xba\xbe", "luks-signature", "LUKS"),
    (b"EFI PART", "gpt-partition-table", "partition-table-not-encryption"),
)
SNAPSHOT_NAME_PATTERNS: tuple[tuple[str, str], ...] = (
    ("com.apple.timemachine.localsnapshots", "apfs-time-machine-local-snapshot"),
    (".snapshots", "apfs-or-time-machine-snapshot"),
    ("system volume information", "windows-system-volume-information"),
    ("snapshot", "snapshot-export"),
)
VOLUME_SHADOW_COPY_PATH_PARTS = {
    "vss",
    "volume shadow copy",
    "volume shadow copies",
    "volume-shadow-copy",
    "volume-shadow-copies",
    "shadowcopy",
    "shadowcopies",
    "shadow copy",
    "shadow copies",
}


def build_recovery_unlock_profile(source: Path, *, source_kind: str, support_level: str) -> dict[str, object]:
    snapshot_candidates = discover_snapshot_candidates(source) if source.is_dir() else []
    fde_profile = detect_fde_indicators(source)
    carving_signatures = [
        {
            "kind": signature.kind,
            "extension": signature.extension,
            "has_footer": signature.end is not None,
        }
        for signature in SIGNATURES
    ]
    source_is_container = source.is_file() and source.suffix.lower() in {
        *E01_SUFFIXES,
        *RAW_IMAGE_SUFFIXES,
        *ARCHIVE_IMAGE_SUFFIXES,
        *VIRTUAL_DISK_SUFFIXES,
    }
    return {
        "profile_version": "evidence-recovery-unlock-profile-v1",
        "source_path": str(source),
        "source_kind": source_kind,
        "support_level": support_level,
        "snapshot_workflow": {
            "status": "candidates-found"
            if snapshot_candidates
            else ("post-extraction-handoff" if source_is_container else "not-detected"),
            "candidate_count": len(snapshot_candidates),
            "candidates": snapshot_candidates[:25],
            "direct_image_level_mount_supported": False,
            "supported_user_action": "run-vsc-discover-compare-extract-after-mount-or-extraction",
            "gui_terms": ["VSS", "APFS snapshot", "Volume Shadow Copy", "Time Machine local snapshot"],
        },
        "fde_unlock_workflow": fde_profile,
        "unallocated_carving_workflow": {
            "status": "available-on-mounted-or-recovered-root",
            "native_unallocated_space_parser": False,
            "bounded_signature_carving_available": True,
            "default_max_scan_bytes_per_file": DEFAULT_MAX_SCAN_BYTES,
            "default_max_candidates": DEFAULT_MAX_CANDIDATES,
            "supported_signatures": carving_signatures,
            "recommended_command": "rapidtriage carve <mounted-or-recovered-root> --output-dir <case-output>/carving",
            "report_blockers": [
                "full-filesystem-unallocated-map-not-implemented",
                "sqlite-record-carving-known-answer-corpus-required",
                "trusted-carving-tool-diff-required",
            ],
        },
        "gui_actions": [
            "Show this profile in the evidence preflight panel before extraction.",
            "Offer VSC/APFS snapshot discovery after the image is mounted or recovered.",
            "Offer bounded carving as an explicit analyst-started queued job, not a default scan.",
            "If FDE indicators are present, require lawful key/password workflow outside RapidTriage before reporting filesystem absence.",
        ],
        "commercial_grade_ready": False,
        "validation_required": True,
    }


def discover_snapshot_candidates(root: Path, *, limit: int = 50) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    try:
        iterator = root.rglob("*")
        for path in iterator:
            if len(candidates) >= limit:
                break
            name = path.name.lower()
            full = str(path).lower()
            parts = {part.lower() for part in path.parts}
            for pattern, snapshot_kind in SNAPSHOT_NAME_PATTERNS:
                if pattern in name or pattern in full:
                    try:
                        relative_path = str(path.relative_to(root))
                    except ValueError:
                        relative_path = str(path)
                    candidates.append(
                        {
                            "path": str(path),
                            "relative_path": relative_path,
                            "snapshot_kind": snapshot_kind,
                            "is_directory": path.is_dir(),
                            "review_status": "candidate-needs-manual-confirmation",
                        }
                    )
                    break
            else:
                matched_part = parts.intersection(VOLUME_SHADOW_COPY_PATH_PARTS)
                if not matched_part:
                    continue
                try:
                    relative_path = str(path.relative_to(root))
                except ValueError:
                    relative_path = str(path)
                candidates.append(
                    {
                        "path": str(path),
                        "relative_path": relative_path,
                        "snapshot_kind": "volume-shadow-copy-export",
                        "is_directory": path.is_dir(),
                        "review_status": "candidate-needs-manual-confirmation",
                    }
                )
    except OSError:
        return candidates
    return candidates


def detect_fde_indicators(source: Path, *, scan_limit: int = 4 * 1024 * 1024) -> dict[str, object]:
    indicators: list[dict[str, object]] = []
    scan_status = "not-inspected"
    if source.is_file():
        scan_status = "completed"
        try:
            with source.open("rb") as handle:
                blob = handle.read(scan_limit)
        except OSError as exc:
            profile = {
                "status": "scan-failed",
                "error": str(exc)[:160],
                "indicators": [],
                "lawful_unlock_supported": False,
                "on_the_fly_decryption_supported": False,
                "report_blockers": [
                    "fde-indicator-scan-failed",
                    "trusted-decryption-workflow-log-required",
                ],
                "validation_required": True,
            }
            profile["operator_runbook"] = build_fde_operator_runbook(profile)
            return profile
        for signature, indicator_id, product in FDE_SIGNATURES:
            offset = blob.find(signature)
            if offset < 0:
                continue
            indicators.append(
                {
                    "indicator": indicator_id,
                    "product_hint": product,
                    "offset": offset,
                    "confidence": "medium" if product in {"BitLocker", "LUKS"} else "low",
                }
            )
    status = "indicator-found" if any(item["product_hint"] in {"BitLocker", "LUKS"} for item in indicators) else scan_status
    profile: dict[str, object] = {
        "status": status,
        "scan_limit_bytes": scan_limit if source.is_file() else 0,
        "indicators": indicators,
        "lawful_unlock_supported": False,
        "on_the_fly_decryption_supported": False,
        "required_user_materials": [
            "BitLocker recovery key or decrypted export",
            "FileVault password/recovery key or decrypted APFS export",
            "LUKS passphrase/header/key material or decrypted export",
            "case authority/audit note for any unlock attempt",
        ],
        "report_blockers": [
            "no-built-in-fde-unlock-engine",
            "no-key-material-handling-vault",
            "trusted-decryption-workflow-log-required",
        ],
        "validation_required": True,
    }
    profile["operator_runbook"] = build_fde_operator_runbook(profile)
    return profile


def build_fde_operator_runbook(fde_profile: Mapping[str, object]) -> dict[str, object]:
    indicators = [
        item for item in fde_profile.get("indicators", []) if isinstance(item, Mapping)
    ]
    product_hints = sorted(
        {
            str(item.get("product_hint"))
            for item in indicators
            if str(item.get("product_hint") or "") in {"BitLocker", "FileVault", "LUKS"}
        }
    )
    status = "unlock-material-required" if product_hints else "standby-no-indicator"
    return {
        "profile_version": "fde-operator-runbook-v1",
        "status": status,
        "product_hints": product_hints,
        "authority_required": True,
        "rapidtriage_unlock_engine": "not-implemented",
        "supported_rapidtriage_role": "detect-required-materials-and-verify-decrypted-export",
        "accepted_inputs": [
            "operator-provided decrypted mounted folder",
            "operator-provided decrypted raw/export image",
            "vendor/tool export manifest with source/decrypted hashes",
            "case authority note and unlock command log",
        ],
        "unlock_tracks": [
            {
                "product": "BitLocker",
                "required_material": "48-digit recovery key, BEK file, TPM/key protector evidence, or decrypted export",
                "operator_tool_examples": ["manage-bde", "dislocker", "libbde/bdemount", "FTK/AXIOM/EnCase export"],
                "proof_to_attach": ["source image hash", "unlock command log", "decrypted volume hash or exported-root manifest"],
            },
            {
                "product": "FileVault",
                "required_material": "password/recovery key/keychain-derived authority or decrypted APFS export",
                "operator_tool_examples": ["diskutil apfs unlockVolume", "APFS-aware forensic suite export"],
                "proof_to_attach": ["source container hash", "unlock command log", "decrypted APFS export manifest"],
            },
            {
                "product": "LUKS",
                "required_material": "passphrase, key file, header/keyslot evidence, or decrypted export",
                "operator_tool_examples": ["cryptsetup luksOpen", "libguestfs/qemu-nbd with authorized key material"],
                "proof_to_attach": ["source image hash", "cryptsetup log", "decrypted mapper/export hash manifest"],
            },
        ],
        "post_unlock_next_steps": [
            "Run rapidtriage evidence on the decrypted export or mounted folder.",
            "Run rapidtriage run on the decrypted root so artifacts/search/review/report stages use decrypted content.",
            "Attach source/decrypted hash manifest and operator authority note to the report bundle.",
        ],
        "qc_checklist": [
            {"id": "authority-note-attached", "label": "Case authority/audit note attached", "required": True},
            {"id": "source-hash-recorded", "label": "Original encrypted source hash recorded", "required": True},
            {"id": "unlock-log-attached", "label": "External unlock command/tool log attached", "required": True},
            {"id": "decrypted-export-hash-recorded", "label": "Decrypted export or mounted-root manifest hash recorded", "required": True},
            {"id": "rapidtriage-rerun-on-decrypted-root", "label": "RapidTriage rerun on decrypted content", "required": True},
        ],
        "report_blockers": list(fde_profile.get("report_blockers") or ()),
        "commercial_grade_ready": False,
        "validation_required": True,
    }


class FolderAdapter:
    name = "folder"
    supported_suffixes: tuple[str, ...] = ()

    def identify(self, source: Path) -> EvidenceAdapterResult:
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="folder",
            supported=source.is_dir(),
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="Directory evidence can be scanned directly." if source.is_dir() else "Source is not a directory.",
            support_level="direct-folder" if source.is_dir() else "unsupported",
            scan_strategy="scan-folder" if source.is_dir() else "select-folder-or-supported-image",
            next_actions=[
                "Run rapidtriage run on this folder in read-only mode.",
                "Use collect-plan first for large mounted Windows/macOS evidence.",
            ]
            if source.is_dir()
            else ["Select a mounted/exported evidence folder or a recognized evidence image."],
            warnings=[] if source.is_dir() else ["Path is not a directory."],
            external_validation_required=False,
            commercial_grade_ready=False,
            limitations=["Folder scan correctness depends on the analyst-provided mounted/exported evidence root."],
            safety_notes=["RapidTriage treats folder input as read-only and writes outputs outside the source tree."],
        )


class EwfAdapter:
    name = "ewf"
    supported_suffixes = E01_SUFFIXES

    def identify(self, source: Path) -> EvidenceAdapterResult:
        missing = missing_e01_tools()
        supported = source.suffix.lower() in self.supported_suffixes
        ready = supported and not missing
        report_grade = image_report_grade_assessment("#22", E01_REPORT_GRADE_BLOCKERS)
        source_integrity = describe_source_integrity(source) if source.is_file() else None
        segment_set_profile = build_e01_segment_set_profile(source) if source.is_file() and supported else None
        e01_intake_profile = build_e01_intake_profile(
            source,
            source_integrity=source_integrity,
            segment_set_profile=segment_set_profile,
        )
        tool_preflight = collect_tool_preflight(E01_REQUIRED_TOOLS) if supported else None
        preflight_summary = e01_preflight_summary(tool_preflight or [], missing_tools=missing) if supported else None
        failure_guidance = (
            None
            if ready
            else e01_failure_guidance(
                "E01 direct input requires external tools: " + ", ".join(missing)
                if missing
                else f"unsupported E01 image extension or unreadable path: {source}"
                )
        )
        ingest_workflow = build_e01_ingest_workflow_profile(
            source,
            supported=supported and source.is_file(),
            ready=ready,
            preflight_summary=preflight_summary,
            segment_set_profile=segment_set_profile,
            source_integrity=source_integrity,
            failure_guidance=failure_guidance,
        )
        e01_validation_plan = (
            build_e01_report_grade_validation_plan(
                source,
                source_integrity=source_integrity,
                segment_set_profile=segment_set_profile,
                tool_preflight=tool_preflight or [],
                preflight_summary=preflight_summary or {},
            )
            if source.is_file() and supported
            else None
        )
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="e01" if source.suffix.lower() == ".e01" else "ex01",
            supported=ready,
            can_mount=ready,
            can_extract=ready,
            required_tools=list(E01_REQUIRED_TOOLS),
            missing_tools=missing,
            message=(
                "E01/Ex01 can be extracted with libewf and Sleuth Kit tools."
                if supported and not missing
                else "E01/Ex01 detected, but required external tools are missing. Use WSL2 or a mounted/extracted folder."
            ),
            support_level="direct-extract" if supported and not missing else "tooling-required",
            scan_strategy="auto-extract-then-scan" if supported and not missing else "mount-or-export-first",
            next_actions=(
                ["Run rapidtriage run IMAGE.E01 --mode hacking --output-dir OUTPUT."]
                if supported and not missing
                else [
                    "Install libewf and Sleuth Kit tools, or use WSL2 where they are available.",
                    "Alternatively mount/export the E01/Ex01 with a trusted forensic tool and scan the resulting folder.",
                ]
            ),
            warnings=[] if ready else ["Direct E01/Ex01 extraction is disabled until required tools are present."],
            external_validation_required=True,
            source_integrity=source_integrity,
            tool_preflight=tool_preflight,
            preflight_summary=preflight_summary,
            commercial_grade_ready=False,
            commercial_gap_ids=["#22"],
            report_grade_assessment=report_grade,
            forensic_review=evidence_forensic_review(
                gap_id="#22",
                artifact_goal="E01/Ex01 read-only workflow, source integrity, external tool preflight, extraction and resume context",
                primary_evidence=[
                    f"detected_format={'e01' if source.suffix.lower() == '.e01' else 'ex01'}",
                    f"ready={ready}",
                    f"missing_tools={','.join(missing)}",
                    f"preflight_status={(preflight_summary or {}).get('status', 'not-run')}",
                ],
                report_grade_assessment=report_grade,
                caveats=[
                    "Workflow orchestrates libewf/Sleuth Kit rather than a native E01/Ex01 parser.",
                    "Encrypted, corrupt, and malformed images require independent validation.",
                ],
            ),
            native_capabilities={
                "ewf_libewf_mount_orchestration": True,
                "auto_extract_then_scan": ready,
                "native_e01_ex01_parser": False,
                "encrypted_volume_unlock_workflow": False,
            },
            limitations=[
                "Direct E01/Ex01 support orchestrates libewf and Sleuth Kit rather than native commercial-grade parsing.",
                "Deleted/corrupt records, encrypted volumes, and malformed images require independent validation.",
            ],
            fallback_guidance=[
                "Use a write-blocked/read-only forensic mount or vendor export if direct tools are unavailable or fail.",
                "Preserve libewf/Sleuth Kit or vendor export logs with the RapidTriage run outputs.",
                *list((preflight_summary or {}).get("remediation_steps") or []),
            ],
            safety_notes=["RapidTriage never writes to the source image; extraction writes only under the selected output directory."],
            core_accuracy_gates=image_core_accuracy_gates(
                22,
                {
                    "source_path": str(source),
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "partition_table": [],
                    "partition_start_sector": None,
                    "command_history": [],
                    "warnings": [] if ready else ["Direct E01/Ex01 extraction is disabled until required tools are present."],
                    "segment_set_profile": segment_set_profile or {},
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                },
            ),
            commercial_uplift_evidence=image_commercial_uplift_evidence(
                22,
                {
                    "source_path": str(source),
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "partition_table": [],
                    "command_history": [],
                    "warnings": [] if ready else ["Direct E01/Ex01 extraction is disabled until required tools are present."],
                    "segment_set_profile": segment_set_profile or {},
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                    "image_report_grade_assessment": report_grade,
                    "detected_format": "e01" if source.suffix.lower() == ".e01" else "ex01",
                },
            ),
            failure_guidance=failure_guidance,
            segment_set_profile=segment_set_profile,
            ingest_workflow=ingest_workflow,
            e01_intake_profile=e01_intake_profile,
            e01_validation_plan=e01_validation_plan,
            image_analyst_review_profile=image_workflow_analyst_review_profile(
                22,
                {
                    "source_path": str(source),
                    "detected_format": "e01" if source.suffix.lower() == ".e01" else "ex01",
                    "support_level": "direct-extract" if supported and not missing else "tooling-required",
                    "scan_strategy": "auto-extract-then-scan" if supported and not missing else "mount-or-export-first",
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "missing_tools": missing,
                    "workflow_manifest": ingest_workflow or {},
                    "native_capabilities": {
                        "ewf_libewf_mount_orchestration": True,
                        "auto_extract_then_scan": ready,
                        "native_e01_ex01_parser": False,
                        "encrypted_volume_unlock_workflow": False,
                    },
                    "limitations": E01_REPORT_GRADE_BLOCKERS,
                    "image_report_grade_assessment": report_grade,
                },
            ),
        )


class RawImageAdapter:
    name = "raw-image"
    supported_suffixes = RAW_IMAGE_SUFFIXES

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        missing = missing_raw_image_tools()
        ready = supported and not missing
        split_parts = discover_raw_parts_for_guidance(source) if supported and source.is_file() else []
        split_set_profile = build_split_set_profile(split_parts, selected_path=source) if split_parts else None
        report_grade = image_report_grade_assessment(
            "#23",
            [
                "native-partition-filesystem-parser-not-implemented",
                "split-image-gap-and-damaged-set-known-answer-validation-required",
                "encrypted-volume-unlock-workflow-not-implemented",
            ],
        )
        source_integrity = {
            "parts": [describe_source_integrity(path) for path in split_parts],
            "split_part_count": len(split_parts),
        } if split_parts else (describe_source_integrity(source) if source.is_file() else None)
        tool_preflight = collect_tool_preflight(RAW_IMAGE_REQUIRED_TOOLS) if supported else None
        raw_validation_plan = build_raw_split_report_grade_validation_plan(
            source,
            image_paths=split_parts or None,
            source_integrity=source_integrity,
            split_set_profile=split_set_profile,
            tool_preflight=tool_preflight or [],
        ) if supported and source.is_file() else None
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format="raw",
            supported=ready,
            can_mount=False,
            can_extract=ready,
            required_tools=list(RAW_IMAGE_REQUIRED_TOOLS),
            missing_tools=missing,
            message=(
                "Raw/split disk image can be recovered with Sleuth Kit tools and scanned automatically."
                if ready
                else "Raw/split image detected, but Sleuth Kit tools are missing. Mount/recover it first, then scan the folder."
            ),
            support_level="direct-extract" if ready else "tooling-required",
            scan_strategy="auto-extract-then-scan" if ready else "mount-or-recover-first",
            next_actions=(
                ["Run rapidtriage run IMAGE.001 --mode hacking --output-dir OUTPUT."]
                if ready
                else [
                    "Install Sleuth Kit tools (`mmls` and `tsk_recover`) or use a trusted forensic suite to recover files.",
                    "Scan the mounted/exported folder with rapidtriage run.",
                ]
            ),
            warnings=[] if ready else ["Direct raw/split extraction is disabled until Sleuth Kit tools are present."],
            external_validation_required=True,
            source_integrity=source_integrity,
            tool_preflight=tool_preflight,
            commercial_grade_ready=False,
            commercial_gap_ids=["#23"],
            report_grade_assessment=report_grade,
            forensic_review=evidence_forensic_review(
                gap_id="#23",
                artifact_goal="RAW/split image detection, split sequence guidance, partition selection and filesystem recovery workflow",
                primary_evidence=[
                    f"ready={ready}",
                    f"split_part_count={len(split_parts)}",
                    f"missing_tools={','.join(missing)}",
                ],
                report_grade_assessment=report_grade,
                caveats=[
                    "Partition and filesystem recovery are delegated to Sleuth Kit.",
                    "Split set gaps and encrypted volumes require case-specific validation.",
                ],
            ),
            native_capabilities={
                "split_segment_discovery": True,
                "auto_extract_then_scan": ready,
                "native_partition_filesystem_parser": False,
                "encrypted_volume_unlock_workflow": False,
            },
            limitations=[
                "Partition/filesystem recovery is delegated to Sleuth Kit and must be validated for the evidence filesystem.",
                "Split sequence discovery is filename-based and should be cross-checked against acquisition notes.",
            ],
            fallback_guidance=[
                "If direct recovery fails, recover/mount the image read-only with a trusted forensic suite and scan the folder.",
                "Preserve partition offsets, tool versions, and full acquisition hashes in the case record.",
            ],
            safety_notes=["Direct recovery reads source segments and writes recovered files under the output directory only."],
            core_accuracy_gates=image_core_accuracy_gates(
                23,
                {
                    "source_path": str(source),
                    "source_integrity": (source_integrity or {}).get("parts", []) if isinstance(source_integrity, dict) and "parts" in source_integrity else source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "partition_table": [],
                    "split_part_warnings": list((split_set_profile or {}).get("warnings") or []),
                    "split_set_profile": split_set_profile or {},
                    "command_history": [],
                    "warnings": [] if ready else ["Direct raw/split extraction is disabled until Sleuth Kit tools are present."],
                    "native_capabilities": {"encrypted_volume_unlock_workflow": False},
                    "limitations": [
                        "native-partition-filesystem-parser-not-implemented",
                        "encrypted-volume-unlock-workflow-not-implemented",
                    ],
                },
            ),
            commercial_uplift_evidence=image_commercial_uplift_evidence(
                23,
                {
                    "source_path": str(source),
                    "source_integrity": (source_integrity or {}).get("parts", [])
                    if isinstance(source_integrity, dict) and "parts" in source_integrity
                    else source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "partition_table": [],
                    "command_history": [],
                    "split_part_count": len(split_parts) if split_parts else 0,
                    "split_set_profile": split_set_profile or {},
                    "warnings": [] if ready else ["Direct raw/split extraction is disabled until Sleuth Kit tools are present."],
                    "limitations": [
                        "native-partition-filesystem-parser-not-implemented",
                        "split-image-gap-and-damaged-set-known-answer-validation-required",
                        "encrypted-volume-unlock-workflow-not-implemented",
                    ],
                    "image_report_grade_assessment": report_grade,
                    "detected_format": "raw",
                },
            ),
            split_set_profile=split_set_profile,
            raw_split_validation_plan=raw_validation_plan,
            image_analyst_review_profile=image_workflow_analyst_review_profile(
                23,
                {
                    "source_path": str(source),
                    "detected_format": "raw",
                    "support_level": "direct-extract" if ready else "tooling-required",
                    "scan_strategy": "auto-extract-then-scan" if ready else "mount-or-recover-first",
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "missing_tools": missing,
                    "split_set_profile": split_set_profile or {},
                    "native_capabilities": {
                        "split_segment_discovery": True,
                        "auto_extract_then_scan": ready,
                        "native_partition_filesystem_parser": False,
                        "encrypted_volume_unlock_workflow": False,
                    },
                    "limitations": [
                        "native-partition-filesystem-parser-not-implemented",
                        "split-image-gap-and-damaged-set-known-answer-validation-required",
                        "encrypted-volume-unlock-workflow-not-implemented",
                    ],
                    "image_report_grade_assessment": report_grade,
                },
            ),
        )


class IsoAdapter:
    name = "iso"
    supported_suffixes = ARCHIVE_IMAGE_SUFFIXES

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        missing = missing_archive_image_tools(source.suffix.lower())
        ready = supported and not missing
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "optical-archive-image",
            supported=ready,
            can_mount=False,
            can_extract=ready,
            required_tools=list(ARCHIVE_IMAGE_TOOLS),
            missing_tools=missing,
            message=(
                f"{suffix.upper()} image can be extracted with available archive tooling and scanned automatically."
                if ready
                else f"{suffix.upper()} image detected, but archive extraction tools are missing. Mount/export it first."
            ),
            support_level="direct-extract" if ready else "tooling-required",
            scan_strategy="auto-extract-then-scan" if ready else "mount-or-extract-first",
            next_actions=(
                [f"Run rapidtriage run IMAGE.{suffix} --mode hacking --output-dir OUTPUT."]
                if ready
                else [
                    "Install 7-Zip/7zz or bsdtar where supported, or mount/export with trusted platform tooling.",
                    "Run RapidTriage against the mounted/exported folder.",
                ]
            ),
            warnings=[] if ready else [f"Direct {suffix.upper()} extraction is disabled until archive tooling is present."],
            external_validation_required=True,
            source_integrity=describe_source_integrity(source) if source.is_file() else None,
            tool_preflight=collect_tool_preflight(ARCHIVE_IMAGE_TOOLS) if supported else None,
            commercial_grade_ready=False,
            limitations=["Archive image extraction relies on external extractors and is not full native forensic image parsing."],
            fallback_guidance=["Mount/export the image read-only with platform or forensic tooling if direct extraction is unsuitable."],
            safety_notes=["Archive extraction writes only into the configured output/stage directory."],
        )


class VirtualDiskAdapter:
    name = "virtual-disk"
    supported_suffixes = VIRTUAL_DISK_SUFFIXES

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        if source.suffix.lower() == ".xva":
            chain_profile = build_virtual_disk_chain_profile(source) if source.is_file() else None
            report_grade = image_report_grade_assessment(
                "#24",
                [
                    "xva-direct-extraction-not-implemented",
                    "hypervisor-metadata-decoding-not-implemented",
                    "vendor-export-validation-required",
                ],
            )
            return EvidenceAdapterResult(
                adapter=self.name,
                source_path=str(source),
                detected_format="xva",
                supported=supported,
                can_mount=False,
                can_extract=False,
                required_tools=["XVA export/mount tooling"],
                missing_tools=["XVA export/mount tooling"],
                message=(
                    "XVA virtual appliance detected. Direct XVA extraction is not implemented yet; "
                    "export or mount the VM disk with Xen/XCP-ng tooling, then scan the resulting folder or converted disk."
                ),
                support_level="detected-only",
                scan_strategy="xva-export-or-convert-first",
                next_actions=[
                    "Export or mount the XVA contents with XenCenter, XCP-ng Center, xe, or a trusted forensic VM workflow.",
                    "If a VHD/VMDK/QCOW disk is produced, run RapidTriage evidence support on that disk.",
                    "Scan the mounted/exported filesystem folder with rapidtriage run.",
                ],
                warnings=["Direct XVA extraction is not implemented; preserve the export/conversion log for reporting."],
                external_validation_required=True,
                source_integrity=describe_source_integrity(source) if source.is_file() else None,
                commercial_grade_ready=False,
                commercial_gap_ids=["#24"],
                report_grade_assessment=report_grade,
                forensic_review=evidence_forensic_review(
                    gap_id="#24",
                    artifact_goal="XVA detection and safe vendor export/convert workflow",
                    primary_evidence=["detected_format=xva", "ready=False", f"source={source.name}"],
                    report_grade_assessment=report_grade,
                    caveats=[
                        "Direct XVA extraction is not implemented.",
                        "Preserve Xen/XCP-ng export logs and hashes before scanning derived disks or folders.",
                    ],
                ),
                native_capabilities={
                    "xva_detection": True,
                    "xva_direct_extraction": False,
                    "vendor_export_guidance": True,
                },
                limitations=[
                    "XVA is detected only; direct virtual-appliance extraction and VDI/VHD chain validation are not implemented.",
                ],
                fallback_guidance=[
                    "Export or mount with XenCenter/XCP-ng/xe, preserve the export log and hashes, then scan the produced disk or folder.",
                ],
                safety_notes=["Do not boot or modify the VM; use read-only export/mount workflows where possible."],
                core_accuracy_gates=image_core_accuracy_gates(
                    24,
                    {
                        "source_path": str(source),
                        "source_integrity": describe_source_integrity(source) if source.is_file() else None,
                        "detected_format": "xva",
                        "warnings": ["Direct XVA extraction is not implemented; preserve the export/conversion log for reporting."],
                        "virtual_disk_chain_profile": chain_profile or {},
                        "native_capabilities": {
                            "snapshot_chain_validation": False,
                            "differencing_disk_resolution": False,
                            "xva_direct_extraction": False,
                        },
                        "limitations": ["xva-direct-extraction-not-implemented"],
                    },
                ),
                commercial_uplift_evidence=image_commercial_uplift_evidence(
                    24,
                    {
                        "source_path": str(source),
                        "source_integrity": describe_source_integrity(source) if source.is_file() else None,
                        "tool_preflight": [],
                        "partition_table": [],
                        "command_history": [],
                        "warnings": [
                            "Direct XVA extraction is not implemented; preserve the export/conversion log for reporting."
                        ],
                        "virtual_disk_chain_profile": chain_profile or {},
                        "limitations": [
                            "xva-direct-extraction-not-implemented",
                            "hypervisor-metadata-decoding-not-implemented",
                            "vendor-export-validation-required",
                        ],
                        "image_report_grade_assessment": report_grade,
                        "detected_format": "xva",
                    },
                ),
                virtual_disk_chain_profile=chain_profile,
                image_analyst_review_profile=image_workflow_analyst_review_profile(
                    24,
                    {
                        "source_path": str(source),
                        "detected_format": "xva",
                        "support_level": "detected-only",
                        "scan_strategy": "xva-export-or-convert-first",
                        "source_integrity": describe_source_integrity(source) if source.is_file() else None,
                        "virtual_disk_chain_profile": chain_profile or {},
                        "native_capabilities": {
                            "xva_detection": True,
                            "xva_direct_extraction": False,
                            "vendor_export_guidance": True,
                            "snapshot_chain_validation": False,
                            "differencing_disk_resolution": False,
                        },
                        "limitations": [
                            "xva-direct-extraction-not-implemented",
                            "hypervisor-metadata-decoding-not-implemented",
                            "vendor-export-validation-required",
                        ],
                        "image_report_grade_assessment": report_grade,
                    },
                ),
            )
        missing = missing_virtual_disk_tools(source.suffix.lower())
        ready = supported and not missing
        report_grade = image_report_grade_assessment(
            "#24",
            [
                "snapshot-chain-validation-not-implemented",
                "differencing-disk-resolution-not-implemented",
                "hypervisor-metadata-decoding-not-implemented",
                "large-virtual-disk-known-answer-corpus-required",
            ],
        )
        source_integrity = describe_source_integrity(source) if source.is_file() else None
        chain_profile = build_virtual_disk_chain_profile(source) if source.is_file() and supported else None
        tool_preflight = collect_tool_preflight(VIRTUAL_DISK_REQUIRED_TOOLS) if supported else None
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=source.suffix.lower().lstrip(".") or "virtual-disk",
            supported=ready,
            can_mount=False,
            can_extract=ready,
            required_tools=list(VIRTUAL_DISK_REQUIRED_TOOLS),
            missing_tools=missing,
            message=(
                "Virtual disk can be converted with qemu-img, recovered with Sleuth Kit, and scanned automatically."
                if ready
                else "Virtual disk detected. Install qemu-img/Sleuth Kit where supported or mount/export it first."
            ),
            support_level="direct-extract" if ready else "tooling-required",
            scan_strategy="auto-convert-extract-then-scan" if ready else "mount-virtual-disk-first",
            next_actions=(
                [f"Run rapidtriage run IMAGE{source.suffix.lower()} --mode hacking --output-dir OUTPUT."]
                if ready
                else virtual_disk_next_actions(source.suffix.lower())
            ),
            warnings=[] if ready else ["Direct virtual disk extraction is disabled until required tooling is present."],
            external_validation_required=True,
            source_integrity=source_integrity,
            tool_preflight=tool_preflight,
            commercial_grade_ready=False,
            commercial_gap_ids=["#24"],
            report_grade_assessment=report_grade,
            forensic_review=evidence_forensic_review(
                gap_id="#24",
                artifact_goal="Virtual disk conversion, provenance-preserving raw recovery, snapshot-chain risk disclosure",
                primary_evidence=[
                    f"detected_format={source.suffix.lower().lstrip('.') or 'virtual-disk'}",
                    f"ready={ready}",
                    f"missing_tools={','.join(missing)}",
                ],
                report_grade_assessment=report_grade,
                caveats=[
                    "qemu-img conversion and Sleuth Kit recovery must be preserved with tool versions and logs.",
                    "Snapshot/differencing chains, encryption, and hypervisor metadata are not fully validated.",
                ],
            ),
            native_capabilities={
                "qemu_img_raw_conversion": True,
                "auto_convert_extract_then_scan": ready,
                "snapshot_chain_validation": False,
                "differencing_disk_resolution": False,
                "xva_direct_extraction": False,
            },
            limitations=[
                "Virtual disk support depends on qemu-img conversion and Sleuth Kit recovery.",
                "Snapshot chains, differencing disks, encryption, and hypervisor metadata are not fully validated.",
            ],
            fallback_guidance=virtual_disk_next_actions(source.suffix.lower()),
            safety_notes=["RapidTriage reads the source disk and writes a converted raw image only under the selected output directory."],
            core_accuracy_gates=image_core_accuracy_gates(
                24,
                {
                    "source_path": str(source),
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "command_history": [],
                    "warnings": [] if ready else ["Direct virtual disk extraction is disabled until required tooling is present."],
                    "virtual_disk_chain_profile": chain_profile or {},
                    "native_capabilities": {
                        "snapshot_chain_validation": False,
                        "differencing_disk_resolution": False,
                        "xva_direct_extraction": False,
                    },
                    "limitations": [
                        "snapshot-chain-validation-not-implemented",
                        "differencing-disk-resolution-not-implemented",
                    ],
                },
            ),
            commercial_uplift_evidence=image_commercial_uplift_evidence(
                24,
                {
                    "source_path": str(source),
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "partition_table": [],
                    "command_history": [],
                    "warnings": [] if ready else ["Direct virtual disk extraction is disabled until required tooling is present."],
                    "virtual_disk_chain_profile": chain_profile or {},
                    "limitations": [
                        "snapshot-chain-validation-not-implemented",
                        "differencing-disk-resolution-not-implemented",
                        "hypervisor-metadata-decoding-not-implemented",
                        "large-virtual-disk-known-answer-corpus-required",
                    ],
                    "image_report_grade_assessment": report_grade,
                    "detected_format": source.suffix.lower().lstrip(".") or "virtual-disk",
                },
            ),
            virtual_disk_chain_profile=chain_profile,
            virtual_disk_validation_plan=build_virtual_disk_report_grade_validation_plan(
                source,
                source_integrity=source_integrity,
                tool_preflight=tool_preflight or [],
                virtual_disk_chain_profile=chain_profile or {},
            ),
            image_analyst_review_profile=image_workflow_analyst_review_profile(
                24,
                {
                    "source_path": str(source),
                    "detected_format": source.suffix.lower().lstrip(".") or "virtual-disk",
                    "support_level": "direct-extract" if ready else "tooling-required",
                    "scan_strategy": "auto-convert-extract-then-scan" if ready else "mount-virtual-disk-first",
                    "source_integrity": source_integrity,
                    "tool_preflight": tool_preflight or [],
                    "missing_tools": missing,
                    "virtual_disk_chain_profile": chain_profile or {},
                    "native_capabilities": {
                        "qemu_img_raw_conversion": True,
                        "auto_convert_extract_then_scan": ready,
                        "snapshot_chain_validation": False,
                        "differencing_disk_resolution": False,
                        "xva_direct_extraction": False,
                    },
                    "limitations": [
                        "snapshot-chain-validation-not-implemented",
                        "differencing-disk-resolution-not-implemented",
                        "hypervisor-metadata-decoding-not-implemented",
                        "large-virtual-disk-known-answer-corpus-required",
                    ],
                    "image_report_grade_assessment": report_grade,
                },
            ),
        )


FORENSIC_CONTAINER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "forensic-container-report-grade-validation-plan-v1"

FORENSIC_CONTAINER_REPORT_GRADE_BLOCKERS = (
    "proprietary-container-direct-parser-not-implemented",
    "embedded-metadata-compression-deleted-entry-validation-required",
    "vendor-export-log-required",
    "forensic-container-verified-export-manifest-required",
    "encrypted-compressed-proprietary-container-corpus-required",
    "native-parser-version-matrix-required",
)


def build_forensic_container_export_profile(source: Path) -> dict[str, object]:
    suffix = source.suffix.lower().lstrip(".") or "forensic-container"
    required_export_artifacts = [
        "original container hash",
        "vendor tool name and version",
        "export settings/log",
        "derived export root hash or manifest hash",
        "deleted/compressed/encrypted item limitation statement",
    ]
    return {
        "profile_version": "forensic-container-export-first-v1",
        "container_type": suffix,
        "source_path": str(source.resolve()),
        "direct_parser_available": False,
        "workflow": "vendor-export-first",
        "supported_internal_action": "detect-hash-guide",
        "required_export_artifacts": required_export_artifacts,
        "derived_evidence_policy": "Treat mounted/exported files as derived evidence and preserve original container plus vendor logs.",
        "native_parser_blockers": [
            "proprietary-container-direct-parser-not-implemented",
            "embedded-metadata-compression-deleted-entry-validation-required",
            "vendor-export-log-required",
        ],
        "review_status": "external-export-required",
    }


def build_forensic_container_workflow_manifest(
    *,
    source: Path,
    detected_format: str,
    source_integrity: dict[str, object] | None,
    container_export_profile: dict[str, object] | None,
    verified_export_manifest_profile: dict[str, object] | None,
) -> dict[str, object]:
    export_profile = dict(container_export_profile or {})
    manifest_profile = dict(verified_export_manifest_profile or {})
    manifest_present = bool(manifest_profile.get("manifest_present"))
    manifest_linked = manifest_profile.get("validation_status") == "manifest-linked"
    blockers = [
        "proprietary-container-direct-parser-not-implemented",
        "embedded-metadata-compression-deleted-entry-validation-required",
        "vendor-export-log-required",
        "forensic-container-verified-export-manifest-required",
    ]
    stages = [
        {
            "id": "detect-container",
            "label": "Detect proprietary forensic container",
            "status": "complete" if source.is_file() else "blocked",
            "evidence": {
                "source_path": str(source),
                "detected_format": detected_format,
                "hash_status": (source_integrity or {}).get("hash_status", "not-recorded"),
            },
        },
        {
            "id": "source-integrity",
            "label": "Source integrity preflight",
            "status": "complete" if source_integrity else "blocked",
            "evidence": {
                "sha256": (source_integrity or {}).get("sha256"),
                "hash_status": (source_integrity or {}).get("hash_status", "not-recorded"),
            },
        },
        {
            "id": "export-first-guidance",
            "label": "Vendor export-first workflow guidance",
            "status": "complete" if export_profile else "blocked",
            "evidence": {
                "workflow": export_profile.get("workflow"),
                "required_export_artifacts": list(export_profile.get("required_export_artifacts") or []),
                "derived_evidence_policy": export_profile.get("derived_evidence_policy"),
            },
        },
        {
            "id": "verified-export-manifest",
            "label": "Verified vendor export manifest sidecar",
            "status": "complete" if manifest_linked else ("review-required" if manifest_present else "blocked"),
            "evidence": {
                "manifest_present": manifest_present,
                "validation_status": manifest_profile.get("validation_status"),
                "manifest_sha256": manifest_profile.get("manifest_sha256"),
                "vendor_tool": manifest_profile.get("vendor_tool"),
                "source_hash_matches_manifest": manifest_profile.get("source_hash_matches_manifest"),
                "file_count": manifest_profile.get("file_count", 0),
                "hashed_file_count": manifest_profile.get("hashed_file_count", 0),
            },
        },
        {
            "id": "scan-derived-export",
            "label": "Scan mounted/exported derived evidence",
            "status": "ready-after-export" if manifest_linked else "blocked",
            "evidence": {
                "next_action": "Run RapidTriage against the verified vendor export folder and keep this manifest with the case.",
                "requires_original_container_retention": True,
            },
        },
        {
            "id": "report-limitations",
            "label": "Report limitation disclosure",
            "status": "complete",
            "evidence": {
                "allowed_use": "vendor-export-container-triage-pivot",
                "native_parser_complete": False,
                "direct_parser_available": bool(export_profile.get("direct_parser_available")),
            },
        },
    ]
    payload: dict[str, object] = {
        "profile_version": "forensic-container-export-workflow-manifest-v1",
        "item_number": 25,
        "gap_id": "#25",
        "workflow_goal": "Detect proprietary AD1/L01/Lx01/AFF/AFF4 containers, preserve source integrity, require vendor export evidence, link a verified export manifest when present, and block native-parser overclaims.",
        "source_ref": {
            "path": str(source),
            "detected_format": detected_format,
            "sha256": (source_integrity or {}).get("sha256"),
            "hash_status": (source_integrity or {}).get("hash_status"),
        },
        "container_export_profile": export_profile,
        "verified_export_manifest_profile": manifest_profile,
        "stages": stages,
        "large_data_controls": {
            "bounded_file_samples": len(manifest_profile.get("sample_files") or []),
            "export_manifest_file_count": manifest_profile.get("file_count", 0),
            "export_manifest_hashed_file_count": manifest_profile.get("hashed_file_count", 0),
            "scan_derived_export_with_cursor_tables": True,
            "retain_original_container": True,
        },
        "reportability_decision": image_reportability_decision(
            25,
            blockers=blockers,
            failed_validation_matrix_ids=["#25-native-commercial-parser"],
            details={
                "source_integrity": source_integrity or {},
                "image_trusted_diff": {"status": "not-attached"},
            },
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": blockers,
        "operator_next_steps": [
            "Export or mount the container with the vendor/acquisition tool and preserve logs.",
            "Place a JSON export manifest sidecar next to the container with source/export hashes and file samples.",
            "Scan the exported folder and cite both original container and derived export provenance.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def build_forensic_container_report_grade_validation_plan(
    source: Path,
    *,
    detected_format: str | None = None,
    output_dir: Path | str | None = None,
    expected_export_entries: list[str] | None = None,
    source_integrity: dict[str, object] | None = None,
    container_export_profile: dict[str, object] | None = None,
    verified_export_manifest_profile: dict[str, object] | None = None,
) -> dict[str, object]:
    """Create the #25 report-grade validation handoff for export-first containers."""

    source_path = source.expanduser().resolve()
    output_root = (
        Path(output_dir).expanduser().resolve() if output_dir else Path("rapidforensic-container-validation")
    )
    container_type = detected_format or source.suffix.lower().lstrip(".") or "forensic-container"
    source_row = dict(source_integrity or {})
    if not source_row and source.is_file():
        source_row = describe_source_integrity(source)
    export_profile = dict(container_export_profile or build_forensic_container_export_profile(source_path))
    manifest_profile = dict(
        verified_export_manifest_profile
        or build_verified_export_manifest_profile(
            source_path,
            discover_forensic_container_export_manifest(source_path),
            source_integrity=source_row,
        )
    )
    manifest_present = bool(manifest_profile.get("manifest_present"))
    manifest_linked = manifest_profile.get("validation_status") == "manifest-linked"
    vendor_logged = bool(manifest_profile.get("vendor_tool") and manifest_profile.get("vendor_tool_version"))
    export_root_hashed = bool(manifest_profile.get("export_root_sha256"))
    hashed_file_count = int(manifest_profile.get("hashed_file_count") or 0)
    expected_rows = [
        {
            "id": f"expected-export-entry-{index + 1:03d}",
            "description": str(item),
            "status": "pending-trusted-comparison",
        }
        for index, item in enumerate(expected_export_entries or [])
        if str(item).strip()
    ]
    validation_commands = [
        _forensic_container_validation_command(
            "source-container-hash",
            ["rapidtriage", "e01-hash", str(source_path), "--output-dir", str(output_root / "source-hash"), "--json"],
            purpose="Compute and preserve the original proprietary container hash.",
            expected_output=str(output_root / "source-hash" / "e01-streaming-hash.json"),
        ),
        _forensic_container_validation_command(
            "evidence-preflight",
            [
                "rapidtriage",
                "evidence",
                str(source_path),
                "--output",
                str(output_root / "rapidtriage-evidence-preflight.json"),
                "--json",
            ],
            purpose="Record adapter detection, source integrity, export-first blockers, and sidecar manifest status.",
            expected_output=str(output_root / "rapidtriage-evidence-preflight.json"),
        ),
        _forensic_container_validation_command(
            "vendor-export",
            [
                "<trusted-vendor-tool>",
                "export-or-mount-read-only",
                str(source_path),
                str(output_root / "vendor-export"),
            ],
            purpose="Export or mount the proprietary container read-only with the acquisition/vendor tool and preserve the transcript.",
            expected_output=str(output_root / "vendor-export"),
            trusted_tool=True,
            status="operator-action-required",
        ),
        _forensic_container_validation_command(
            "export-manifest-author",
            [
                "<analyst>",
                "create-export-manifest-json",
                str(source_path.with_suffix(source_path.suffix + ".export-manifest.json")),
            ],
            purpose="Create the vendor export manifest sidecar with source hash, vendor version, export root hash, and exported-file hashes.",
            expected_output=str(source_path.with_suffix(source_path.suffix + ".export-manifest.json")),
            trusted_tool=True,
            status="complete" if manifest_linked else "operator-action-required",
        ),
        _forensic_container_validation_command(
            "scan-derived-export",
            [
                "rapidtriage",
                "run",
                str(output_root / "vendor-export"),
                "--mode",
                "hacking",
                "--output-dir",
                str(output_root / "derived-run"),
                "--read-only",
            ],
            purpose="Scan the vendor export as derived evidence while retaining the original container and export logs.",
            expected_output=str(output_root / "derived-run" / "rapidtriage-run.json"),
            status="ready-after-verified-export" if manifest_linked else "pending-verified-export-manifest",
        ),
        _forensic_container_validation_command(
            "trusted-workflow-diff",
            [
                "rapidtriage",
                "image-workflow-validate",
                "--item-number",
                "25",
                "--rapid-output",
                str(output_root / "rapidtriage-evidence-preflight.json"),
                "--trusted-output",
                str(output_root / "trusted-container-export.csv"),
                "--trusted-tool",
                "vendor-export-manifest",
                "--output",
                str(output_root / "container-trusted-diff.json"),
                "--json",
            ],
            purpose="Compare source hash, container type, manifest hash, and exported-file rows against trusted vendor/export references.",
            expected_output=str(output_root / "container-trusted-diff.json"),
            trusted_tool=True,
        ),
    ]
    source_hash_complete = bool(source_row.get("sha256"))
    evidence_slots = [
        {
            "id": "source-container-integrity",
            "label": "Original proprietary container hash",
            "status": "complete" if source_hash_complete else "pending-source-hash",
            "required_before_report": True,
            "sha256": source_row.get("sha256"),
        },
        {
            "id": "container-type-and-export-policy",
            "label": "Container type plus export-first policy disclosure",
            "status": "complete" if container_type and export_profile else "pending-detection",
            "required_before_report": True,
            "container_type": container_type,
            "workflow": export_profile.get("workflow"),
            "direct_parser_available": export_profile.get("direct_parser_available"),
        },
        {
            "id": "vendor-tool-version-log",
            "label": "Vendor tool name, version, and export transcript",
            "status": "complete" if vendor_logged and manifest_linked else "pending-vendor-export-log",
            "required_before_report": True,
            "vendor_tool": manifest_profile.get("vendor_tool"),
            "vendor_tool_version": manifest_profile.get("vendor_tool_version"),
        },
        {
            "id": "verified-export-manifest",
            "label": "Verified vendor export manifest sidecar",
            "status": "complete" if manifest_linked else ("review-required" if manifest_present else "missing"),
            "required_before_report": True,
            "manifest_sha256": manifest_profile.get("manifest_sha256"),
            "validation_status": manifest_profile.get("validation_status"),
            "source_hash_matches_manifest": manifest_profile.get("source_hash_matches_manifest"),
        },
        {
            "id": "derived-export-root-integrity",
            "label": "Derived export root hash",
            "status": "complete" if manifest_linked and export_root_hashed else "pending-export-root-hash",
            "required_before_report": True,
            "export_root": manifest_profile.get("export_root"),
            "export_root_sha256": manifest_profile.get("export_root_sha256"),
        },
        {
            "id": "exported-file-hash-inventory",
            "label": "Exported file hash inventory",
            "status": "complete" if manifest_linked and hashed_file_count > 0 else "pending-file-hash-inventory",
            "required_before_report": True,
            "file_count": manifest_profile.get("file_count", 0),
            "hashed_file_count": hashed_file_count,
            "sample_count": len(manifest_profile.get("sample_files") or []),
        },
        {
            "id": "trusted-vendor-export-diff",
            "label": "Trusted vendor export manifest diff",
            "status": "pending-image-workflow-validate",
            "required_before_report": True,
            "required_fields": [
                "source_sha256",
                "container_format",
                "vendor_tool",
                "vendor_tool_version",
                "export_manifest_sha256",
                "exported_file_sha256",
            ],
        },
        {
            "id": "metadata-deleted-entry-validation",
            "label": "Embedded metadata and deleted-entry validation corpus",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["live-files", "deleted-files", "compressed-items", "embedded-metadata", "vendor-log"],
        },
        {
            "id": "encrypted-compressed-container-corpus",
            "label": "Encrypted/compressed proprietary container corpus",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["plain-ad1", "encrypted-ad1", "l01-lx01", "aff-aff4", "corrupt-or-partial"],
        },
        {
            "id": "native-parser-research-track",
            "label": "Native parser/library research and version matrix",
            "status": "native-parser-required-for-commercial-grade",
            "required_before_commercial_grade": True,
            "formats": ["AD1", "L01", "Lx01", "AFF", "AFF4", "XVA"],
        },
    ]
    ready_slots = [slot["id"] for slot in evidence_slots if str(slot.get("status", "")).startswith("complete")]
    blocker_slots = [
        slot["id"]
        for slot in evidence_slots
        if slot.get("required_before_report") and not str(slot.get("status", "")).startswith("complete")
    ]
    payload: dict[str, object] = {
        "profile_version": FORENSIC_CONTAINER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 25,
        "gap_id": "#25",
        "source_path": str(source_path),
        "detected_format": container_type,
        "output_root": str(output_root),
        "status": "report-validation-blocked" if blocker_slots else "ready-for-report-review",
        "commercial_grade_ready": False,
        "expected_export_entries": expected_rows,
        "source_integrity": source_row,
        "container_export_profile": export_profile,
        "verified_export_manifest_profile": manifest_profile,
        "validation_commands": validation_commands,
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slots,
        "blocking_slot_ids": blocker_slots,
        "export_manifest_policy": {
            "sidecar_names": [
                source_path.with_suffix(source_path.suffix + ".export-manifest.json").name,
                source_path.with_suffix(source_path.suffix + ".manifest.json").name,
            ],
            "required_fields": ["vendor_tool", "vendor_tool_version", "source_sha256", "export_root_sha256", "files"],
            "sample_bound": 25,
            "treat_export_as_derived_evidence": True,
        },
        "report_claim_boundary": (
            "This plan can make one proprietary-container export workflow reviewable when all report-required slots pass; "
            "commercial-grade native AD1/L01/Lx01/AFF/AFF4/XVA claims still require native parser validation, "
            "deleted-entry/metadata corpora, encrypted/compressed corpus, and independent signoff."
        ),
        "commercial_grade_blockers": list(FORENSIC_CONTAINER_REPORT_GRADE_BLOCKERS),
        "operator_next_steps": [
            "Hash the original proprietary container and run evidence-preflight.",
            "Export or mount the container read-only with the trusted vendor/acquisition tool and preserve logs.",
            "Attach a JSON export manifest sidecar with source/export hashes, vendor version, and bounded file samples.",
            "Scan the derived export folder, then run trusted-workflow-diff before citing exported paths or hashes.",
        ],
    }
    payload["manifest_sha256"] = stable_manifest_sha256(payload)
    return payload


def _forensic_container_validation_command(
    command_id: str,
    argv: list[str],
    *,
    purpose: str,
    expected_output: str,
    trusted_tool: bool = False,
    status: str = "pending-run",
) -> dict[str, object]:
    clean_argv = [str(item) for item in argv if str(item) != ""]
    return {
        "id": command_id,
        "argv": clean_argv,
        "command": " ".join(shlex.quote(item) for item in clean_argv),
        "purpose": purpose,
        "expected_output": expected_output,
        "status": status,
        "trusted_tool_required": trusted_tool,
    }


def discover_forensic_container_export_manifest(source: Path) -> Path | None:
    candidates = [
        source.with_suffix(source.suffix + ".export-manifest.json"),
        source.with_suffix(source.suffix + ".manifest.json"),
        source.with_name(source.name + ".export-manifest.json"),
        source.with_name(source.stem + "-export-manifest.json"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def build_verified_export_manifest_profile(
    source: Path,
    manifest_path: Path | None,
    *,
    source_integrity: dict[str, object] | None = None,
) -> dict[str, object]:
    if manifest_path is None:
        return {
            "profile_version": "forensic-container-verified-export-manifest-v1",
            "manifest_present": False,
            "validation_status": "missing",
            "required_sidecar_names": [
                source.with_suffix(source.suffix + ".export-manifest.json").name,
                source.with_suffix(source.suffix + ".manifest.json").name,
            ],
            "warnings": ["No vendor export manifest sidecar was found next to the proprietary container."],
        }
    profile: dict[str, object] = {
        "profile_version": "forensic-container-verified-export-manifest-v1",
        "manifest_present": True,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "validation_status": "review-required",
        "warnings": [],
    }
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        profile.update(
            {
                "parse_status": "failed",
                "error": str(exc),
                "warnings": ["Vendor export manifest exists but could not be parsed as JSON."],
            }
        )
        return profile
    if not isinstance(payload, dict):
        profile.update({"parse_status": "failed", "warnings": ["Vendor export manifest root must be a JSON object."]})
        return profile
    files = payload.get("files") if isinstance(payload.get("files"), list) else []
    source_sha256 = str((source_integrity or {}).get("sha256") or "")
    manifest_source_sha256 = str(payload.get("source_sha256") or payload.get("original_container_sha256") or "")
    required_fields = ["vendor_tool", "vendor_tool_version", "export_root_sha256", "files"]
    missing_required = [field for field in required_fields if not payload.get(field)]
    source_hash_matches = bool(source_sha256 and manifest_source_sha256 and source_sha256.lower() == manifest_source_sha256.lower())
    profile.update(
        {
            "parse_status": "json-parsed",
            "vendor_tool": str(payload.get("vendor_tool") or ""),
            "vendor_tool_version": str(payload.get("vendor_tool_version") or ""),
            "export_root": str(payload.get("export_root") or ""),
            "export_root_sha256": str(payload.get("export_root_sha256") or ""),
            "source_sha256": manifest_source_sha256,
            "source_hash_matches_manifest": source_hash_matches,
            "file_count": len(files),
            "hashed_file_count": sum(1 for item in files if isinstance(item, dict) and item.get("sha256")),
            "missing_required_fields": missing_required,
            "validation_status": "manifest-linked" if not missing_required and source_hash_matches else "review-required",
            "sample_files": [
                {
                    "path": str(item.get("path") or item.get("relative_path") or ""),
                    "sha256": str(item.get("sha256") or ""),
                    "size": item.get("size"),
                }
                for item in files[:25]
                if isinstance(item, dict)
            ],
        }
    )
    if missing_required:
        profile["warnings"].append(f"Vendor export manifest is missing required fields: {', '.join(missing_required)}")
    if manifest_source_sha256 and not source_hash_matches:
        profile["warnings"].append("Vendor export manifest source hash does not match the detected container hash.")
    return profile


class ForensicContainerAdapter:
    name = "forensic-container"
    supported_suffixes = (".ad1", ".l01", ".lx01", ".aff", ".aff4", ".aff4-l")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        report_grade = image_report_grade_assessment(
            "#25",
            [
                "proprietary-container-direct-parser-not-implemented",
                "embedded-metadata-compression-deleted-entry-validation-required",
                "vendor-export-log-required",
            ],
        )
        source_integrity = describe_source_integrity(source) if source.is_file() else None
        container_export_profile = build_forensic_container_export_profile(source) if source.is_file() and supported else None
        verified_export_manifest_profile = (
            build_verified_export_manifest_profile(
                source,
                discover_forensic_container_export_manifest(source),
                source_integrity=source_integrity,
            )
            if source.is_file() and supported
            else None
        )
        forensic_container_workflow_manifest = (
            build_forensic_container_workflow_manifest(
                source=source,
                detected_format=suffix or "forensic-container",
                source_integrity=source_integrity,
                container_export_profile=container_export_profile,
                verified_export_manifest_profile=verified_export_manifest_profile,
            )
            if source.is_file() and supported
            else None
        )
        forensic_container_validation_plan = (
            build_forensic_container_report_grade_validation_plan(
                source,
                detected_format=suffix or "forensic-container",
                source_integrity=source_integrity,
                container_export_profile=container_export_profile,
                verified_export_manifest_profile=verified_export_manifest_profile,
            )
            if source.is_file() and supported
            else None
        )
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "forensic-container",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message=(
                f"{suffix.upper()} forensic container detected. Direct parsing is not implemented yet; "
                "export or mount it with the acquisition vendor/tool, then scan the resulting folder."
            ),
            support_level="detected-only",
            scan_strategy="vendor-export-first",
            next_actions=[
                f"Open the {suffix.upper()} container in its acquisition/vendor tool.",
                "Export a filesystem folder, selected logical files, or parser CSV/JSON outputs.",
                "Run RapidTriage against the exported folder and preserve the vendor export log.",
            ],
            warnings=[f"Direct {suffix.upper()} container parsing is not implemented yet."],
            external_validation_required=True,
            source_integrity=source_integrity,
            commercial_grade_ready=False,
            commercial_gap_ids=["#25"],
            report_grade_assessment=report_grade,
            forensic_review=evidence_forensic_review(
                gap_id="#25",
                artifact_goal="AD1/L01/Lx01/AFF/AFF4 container detection and verified export workflow",
                primary_evidence=[f"detected_format={suffix}", f"source={source.name}", "direct_parser=False"],
                report_grade_assessment=report_grade,
                caveats=[
                    "Direct proprietary container parsing is not implemented.",
                    "Treat vendor export output as derived evidence and retain original container hashes/logs.",
                ],
            ),
            native_capabilities={
                "container_format_detection": True,
                "source_integrity_preflight": bool(source.is_file()),
                "vendor_export_guidance": True,
                "direct_ad1_l01_lx01_aff_aff4_parser": False,
                "deleted_entry_recovery": False,
            },
            limitations=[
                f"{suffix.upper()} is adapter-detected only; direct proprietary container parsing is not implemented.",
                "RapidTriage cannot independently validate embedded metadata, compression, deleted entries, or encryption for this format.",
            ],
            fallback_guidance=[
                f"Export or mount the {suffix.upper()} with the acquisition/vendor tool in a read-only workflow.",
                "Hash the original container and exported payload, preserve vendor logs, then scan the exported folder.",
            ],
            safety_notes=["Treat vendor export output as derived evidence and retain the original container unchanged."],
            core_accuracy_gates=image_core_accuracy_gates(
                25,
                {
                    "source_path": str(source),
                    "source_integrity": source_integrity,
                    "detected_format": suffix or "forensic-container",
                    "scan_strategy": "vendor-export-first",
                    "native_vs_export_workflow": container_export_profile or {},
                    "verified_export_manifest_profile": verified_export_manifest_profile or {},
                    "fallback_guidance": [
                        f"Export or mount the {suffix.upper()} with the acquisition/vendor tool in a read-only workflow.",
                        "Hash the original container and exported payload, preserve vendor logs, then scan the exported folder.",
                    ],
                    "native_capabilities": {
                        "deleted_entry_recovery": False,
                    },
                    "warnings": [f"Direct {suffix.upper()} container parsing is not implemented yet."],
                    "limitations": [
                        "proprietary-container-direct-parser-not-implemented",
                        "embedded-metadata-compression-deleted-entry-validation-required",
                    ],
                },
            ),
            commercial_uplift_evidence=image_commercial_uplift_evidence(
                25,
                {
                    "source_path": str(source),
                    "source_integrity": source_integrity,
                    "tool_preflight": [],
                    "partition_table": [],
                    "command_history": [],
                    "warnings": [f"Direct {suffix.upper()} container parsing is not implemented yet."],
                    "limitations": [
                        "proprietary-container-direct-parser-not-implemented",
                        "embedded-metadata-compression-deleted-entry-validation-required",
                        "vendor-export-log-required",
                    ],
                    "image_report_grade_assessment": report_grade,
                    "detected_format": suffix or "forensic-container",
                    "export_manifest_sha256": (verified_export_manifest_profile or {}).get("manifest_sha256", ""),
                    "report_grade_validation_plan_sha256": (forensic_container_validation_plan or {}).get(
                        "manifest_sha256", ""
                    ),
                    "native_vs_export_workflow": container_export_profile or {},
                    "verified_export_manifest_profile": verified_export_manifest_profile or {},
                },
            ),
            container_export_profile=container_export_profile,
            verified_export_manifest_profile=verified_export_manifest_profile,
            forensic_container_workflow_manifest=forensic_container_workflow_manifest,
            forensic_container_validation_plan=forensic_container_validation_plan,
            image_analyst_review_profile=image_workflow_analyst_review_profile(
                25,
                {
                    "source_path": str(source),
                    "detected_format": suffix or "forensic-container",
                    "support_level": "detected-only",
                    "scan_strategy": "vendor-export-first",
                    "source_integrity": source_integrity,
                    "workflow_manifest": forensic_container_workflow_manifest or {},
                    "native_vs_export_workflow": container_export_profile or {},
                    "verified_export_manifest_profile": verified_export_manifest_profile or {},
                    "native_capabilities": {
                        "container_format_detection": True,
                        "source_integrity_preflight": bool(source.is_file()),
                        "vendor_export_guidance": True,
                        "direct_ad1_l01_lx01_aff_aff4_parser": False,
                        "deleted_entry_recovery": False,
                    },
                    "limitations": [
                        "proprietary-container-direct-parser-not-implemented",
                        "embedded-metadata-compression-deleted-entry-validation-required",
                        "vendor-export-log-required",
                    ],
                    "image_report_grade_assessment": report_grade,
                    "export_manifest_sha256": (verified_export_manifest_profile or {}).get("manifest_sha256", ""),
                },
            ),
        )


class MobilePackageAdapter:
    name = "mobile-package"
    supported_suffixes = (".ab", ".ufd", ".ufdx")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "mobile-package",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message=(
                f"{suffix.upper()} mobile extraction package detected. Import/parsing is planned; "
                "for now export files/databases from Cellebrite/XRY/GrayKey/AXIOM and scan that folder."
            ),
            support_level="detected-only",
            scan_strategy="vendor-export-first",
            next_actions=[
                "Export files/databases/reports from the mobile forensic tool.",
                "Scan the exported folder and ingest APKs, documents, media, and browser/app databases where present.",
            ],
            warnings=["Full mobile extraction package import is not implemented yet."],
            external_validation_required=True,
        )


class MemoryDumpAdapter:
    name = "memory-dump"
    supported_suffixes = (".mem", ".dmp", ".vmem", ".vmss", ".vmsn", ".hpak", ".crash")

    def identify(self, source: Path) -> EvidenceAdapterResult:
        supported = source.suffix.lower() in self.supported_suffixes
        suffix = source.suffix.lower().lstrip(".")
        volatility = "vol"
        missing = [] if shutil.which(volatility) else [volatility]
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=suffix or "memory-dump",
            supported=supported,
            can_mount=False,
            can_extract=False,
            required_tools=[volatility],
            missing_tools=missing,
            message=(
                "Memory dump detected. RapidTriage can inventory/hash the file; deep memory analysis should be run "
                "with Volatility/Volatility3 and imported as reports/logs."
            ),
            support_level="import-tool-output",
            scan_strategy="run-volatility-then-import-output",
            next_actions=[
                "Run Volatility/Volatility3 against the memory image.",
                "Export process, cmdline, netscan, malfind, and related outputs as JSON/JSONL.",
                "Run rapidtriage artifacts --kind memory-volatility on the exported output folder.",
            ],
            warnings=["RapidTriage does not directly analyze raw memory dumps yet."],
            external_validation_required=True,
        )


class UnsupportedAdapter:
    name = "unsupported"
    supported_suffixes: tuple[str, ...] = ()

    def identify(self, source: Path) -> EvidenceAdapterResult:
        return EvidenceAdapterResult(
            adapter=self.name,
            source_path=str(source),
            detected_format=source.suffix.lower().lstrip(".") or "unknown",
            supported=False,
            can_mount=False,
            can_extract=False,
            required_tools=[],
            missing_tools=[],
            message="Evidence format is not supported yet. Mount or extract it first, then scan the resulting folder.",
            support_level="unsupported",
            scan_strategy="manual-export-first",
            next_actions=[
                "Identify the source format with the acquisition tool or case notes.",
                "Mount/export the contents to a folder and run RapidTriage on that folder.",
            ],
            warnings=["Unknown evidence format."],
            external_validation_required=True,
        )


ADAPTERS: tuple[EvidenceAdapter, ...] = (
    FolderAdapter(),
    EwfAdapter(),
    ForensicContainerAdapter(),
    RawImageAdapter(),
    IsoAdapter(),
    VirtualDiskAdapter(),
    MobilePackageAdapter(),
    MemoryDumpAdapter(),
)


def identify_evidence(source: Path) -> EvidenceAdapterResult:
    resolved = source.expanduser().resolve()
    if resolved.is_dir():
        return with_recovery_unlock_profile(add_source_name_warnings(FolderAdapter().identify(resolved)))
    suffix = resolved.suffix.lower()
    for adapter in ADAPTERS:
        if suffix in adapter.supported_suffixes:
            return with_recovery_unlock_profile(add_source_name_warnings(adapter.identify(resolved)))
    return with_recovery_unlock_profile(add_source_name_warnings(UnsupportedAdapter().identify(resolved)))


def with_recovery_unlock_profile(result: EvidenceAdapterResult) -> EvidenceAdapterResult:
    recovery_profile = result.recovery_unlock_profile or build_recovery_unlock_profile(
        Path(result.source_path),
        source_kind=result.detected_format,
        support_level=result.support_level,
    )
    enriched = replace(
        result,
        recovery_unlock_profile=recovery_profile,
    )
    if enriched.image_stress_workflow_profile is not None:
        return enriched
    stress_profile = build_evidence_image_stress_profile(enriched)
    if stress_profile is None:
        return enriched
    return replace(enriched, image_stress_workflow_profile=stress_profile)


def build_evidence_image_stress_profile(result: EvidenceAdapterResult) -> dict[str, object] | None:
    gap_id = (result.commercial_gap_ids or [""])[0]
    number_by_gap = {"#22": 22, "#23": 23, "#24": 24, "#25": 25}
    number = number_by_gap.get(gap_id)
    if number is None:
        return None
    workflow_plan = (
        result.e01_validation_plan
        or result.raw_split_validation_plan
        or result.virtual_disk_validation_plan
        or result.forensic_container_validation_plan
        or result.ingest_workflow
        or result.forensic_container_workflow_manifest
        or {}
    )
    return build_image_stress_known_answer_profile(
        number,
        source_path=Path(result.source_path),
        detected_format=result.detected_format,
        source_integrity=result.source_integrity,
        tool_preflight=result.tool_preflight or [],
        workflow_plan=workflow_plan,
        report_grade_assessment=result.report_grade_assessment or {},
        recovery_unlock_profile=result.recovery_unlock_profile or {},
    )


def add_source_name_warnings(result: EvidenceAdapterResult) -> EvidenceAdapterResult:
    warnings = [*result.warnings, *source_name_warnings(Path(result.source_path))]
    deduped = list(dict.fromkeys(warnings))
    if deduped == result.warnings:
        return result
    return replace(result, warnings=deduped)


def source_name_warnings(source: Path) -> list[str]:
    warnings: list[str] = []
    try:
        resolved = source.expanduser().resolve()
    except OSError:
        resolved = source.expanduser().absolute()

    home = Path.home().resolve()
    if resolved == Path(resolved.anchor):
        warnings.append("Source appears to be a filesystem or drive root. Confirm this is the intended exhibit, not the analyst host.")
    if resolved == home:
        warnings.append("Source is the current user's home directory. Confirm this is the intended exhibit root before scanning.")
    if resolved == home.parent:
        warnings.append("Source is the local user-profile parent directory. Confirm this is not the analyst workstation.")

    risky_names = {"users", "home", "desktop", "documents", "downloads"}
    if resolved.name.lower() in risky_names:
        warnings.append(
            "Source display name matches a common host folder. Confirm the selected path belongs to the evidence, not the analysis machine."
        )
    return warnings


def discover_raw_parts_for_guidance(source: Path) -> list[Path]:
    try:
        return discover_split_image_parts(source)
    except OSError:
        return [source]


def recommended_virtual_disk_tools(suffix: str) -> list[str]:
    if sys.platform.startswith("win"):
        if suffix in (".vhd", ".vhdx"):
            return ["powershell"]
        return ["qemu-img"]
    if suffix in (".vmdk", ".vdi", ".qcow", ".qcow2", ".xva"):
        return ["qemu-img"]
    return []


def virtual_disk_next_actions(suffix: str) -> list[str]:
    if sys.platform.startswith("win") and suffix in (".vhd", ".vhdx"):
        return [
            "Mount the VHD/VHDX read-only with Windows Disk Management or PowerShell where policy allows.",
            "Scan the mounted drive letter or exported folder with RapidTriage.",
        ]
    if suffix in (".vmdk", ".vdi", ".qcow", ".qcow2", ".xva"):
        return [
            "Use qemu-img/qemu-nbd, guestmount, or a trusted forensic VM tool to expose the filesystem read-only.",
            "Export or mount the filesystem and scan that folder with RapidTriage.",
        ]
    return [
        "Mount the virtual disk read-only with platform or forensic tooling.",
        "Scan the mounted/exported filesystem folder with RapidTriage.",
    ]


def supported_evidence_formats() -> list[dict[str, object]]:
    return [
        {
            "adapter": adapter.name,
            "suffixes": list(adapter.supported_suffixes),
            "support_level": adapter_support_level(adapter),
        }
        for adapter in ADAPTERS
    ]


def adapter_support_level(adapter: EvidenceAdapter) -> str:
    if isinstance(adapter, EwfAdapter):
        return "direct-extract-when-tools-present"
    if isinstance(adapter, RawImageAdapter):
        return "direct-extract-when-tools-present"
    if isinstance(adapter, IsoAdapter):
        return "direct-extract-when-tools-present"
    if isinstance(adapter, VirtualDiskAdapter):
        return "direct-extract-when-tools-present"
    if isinstance(adapter, FolderAdapter):
        return "direct-folder"
    if isinstance(adapter, MemoryDumpAdapter):
        return "import-tool-output"
    return "detected-only"
