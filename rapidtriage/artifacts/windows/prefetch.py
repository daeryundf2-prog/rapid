from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Iterable, Mapping, Sequence

from ...core.audit import compute_sha256
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review, isoformat_from_timestamp

PREFETCH_ROOT = ("Windows", "Prefetch")
PARSER_VERSION = "prefetch-inventory-v9"
QC_PREP_PREFETCH_ITEM = 31
QC_PREP_PREFETCH_GOAL = (
    "Deepen Prefetch version 17/23/26/30/31 support, compressed PF handling, "
    "volume/file metrics, and trace-chain evidence."
)
QC_PREP_PREFETCH_CONTRACT = {
    "item_number": QC_PREP_PREFETCH_ITEM,
    "goal": QC_PREP_PREFETCH_GOAL,
    "implemented_outputs": [
        "version-specific common-header profile for versions 17, 23, 26, 30, and observed 31",
        "compressed MAM/PF detection with explicit decompression limitation",
        "version-aware section bounds profile for file metrics, trace chains, filename strings, and volume locators",
        "bounded referenced-path, volume-device, and file-reference candidate pivots",
        "execution-depth manifest with source hash, offsets, validation checks, and report blockers",
    ],
    "commercial_blockers": [
        "native file metrics array decoding",
        "authoritative volume table decoding",
        "trace-chain/directory section validation",
        "PECmd/known-answer cross-version corpus diff evidence",
    ],
}
MAX_PREFETCH_SCAN_BYTES = 1024 * 1024
MAX_REFERENCED_PATHS = 200
MAX_CANDIDATES = 200
MAX_REASONABLE_RUN_COUNT = 1_000_000
PREFETCH_VERSION_LAYOUTS = {
    17: {
        "layout_name": "windows-xp-2003",
        "windows_family": "Windows XP/Server 2003",
        "run_count_offset": 0x90,
        "last_run_time_offset": 0x78,
        "last_run_time_slots": 1,
    },
    23: {
        "layout_name": "windows-vista-7",
        "windows_family": "Windows Vista/7",
        "run_count_offset": 0x98,
        "last_run_time_offset": 0x80,
        "last_run_time_slots": 1,
    },
    26: {
        "layout_name": "windows-8-8.1",
        "windows_family": "Windows 8/8.1",
        "run_count_offset": 0xD0,
        "last_run_time_offset": 0x80,
        "last_run_time_slots": 8,
    },
    30: {
        "layout_name": "windows-10",
        "windows_family": "Windows 10",
        "run_count_offset": 0xD0,
        "last_run_time_offset": 0x80,
        "last_run_time_slots": 8,
    },
    31: {
        "layout_name": "windows-11-observed",
        "windows_family": "Windows 11 observed layouts",
        "run_count_offset": 0xD0,
        "last_run_time_offset": 0x80,
        "last_run_time_slots": 8,
    },
}
PREFETCH_SECTION_FIELD_OFFSETS = {
    "file_metrics_array": {"offset": 0x54, "count": 0x58},
    "trace_chains": {"offset": 0x5C, "count": 0x60},
    "filename_strings": {"offset": 0x64, "size": 0x68},
    "volume_information": {"offset": 0x6C, "count": 0x70, "size": 0x74},
}
PREFETCH_SECTION_ENTRY_SIZE_HINTS = {
    "file_metrics_array": {17: 20, 23: 32, 26: 32, 30: 32, 31: 32},
    "trace_chains": {17: 8, 23: 8, 26: 8, 30: 8, 31: 8},
}
PREFETCH_COMMERCIAL_BLOCKERS = [
    "Full file metrics array decoding and MFT file-reference extraction are not implemented.",
    "Volume information is surfaced as bounded string/path candidates, not decoded from the authoritative volume table.",
    "Trace chains, directory strings, and file information sections are not fully version-validated.",
    "Known-answer corpus validation across malformed, compressed, and cross-version Prefetch files is incomplete.",
]
PREFETCH_NATIVE_CAPABILITIES = {
    "scca_signature_validation": True,
    "compressed_prefetch_detection": True,
    "compressed_prefetch_decompression": False,
    "common_header_version_offsets": True,
    "section_locator_bounds_profile": True,
    "run_count_and_last_run_times": True,
    "bounded_referenced_path_pivots": True,
    "volume_candidate_pivots": True,
    "full_file_metrics_array_decode": False,
    "mft_file_reference_decode": False,
    "authoritative_volume_table_decode": False,
    "trace_chain_decode": False,
    "cross_version_known_answer_corpus": False,
}
PREFETCH_REPORT_GRADE_BLOCKERS = [
    "full-file-metrics-array-decoding-not-implemented",
    "mft-file-reference-decoding-not-implemented",
    "authoritative-volume-table-decoding-not-implemented",
    "trace-chain-directory-section-validation-required",
    "known-answer-prefetch-corpus-required",
    "prefetch-trusted-parser-diff-required",
]
PREFETCH_TRUSTED_TOOLS = {"pecmd", "winprefetchview", "velociraptor", "prefetchparser"}


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
            validation_checks = header.get("prefetch_validation_checks") or {}
            report_grade = prefetch_report_grade_assessment(validation_checks)
            core_accuracy_gates = prefetch_core_accuracy_gates(
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "validation_checks": validation_checks,
                    **header,
                }
            )
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="prefetch-file",
                path=str(path.resolve()),
                supported=True,
                details=with_prefetch_depth_manifest({
                    "parser": "windows-prefetch-inventory",
                    "parser_version": PARSER_VERSION,
                    "artifact_type": "prefetch-file",
                    "coverage_status": "detected",
                    "reportability": "triage",
                    "parser_confidence": header.get("parser_confidence", "low"),
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
                    "validation_required": True,
                    "core_accuracy_gates": core_accuracy_gates,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": list(PREFETCH_REPORT_GRADE_BLOCKERS),
                    "commercial_readiness_blockers": list(PREFETCH_COMMERCIAL_BLOCKERS),
                    "prefetch_validation_matrix": prefetch_validation_matrix(validation_checks),
                    "prefetch_report_grade_assessment": report_grade,
                    "prefetch_native_capabilities": dict(PREFETCH_NATIVE_CAPABILITIES),
                    "commercial_uplift_evidence": prefetch_commercial_uplift_evidence(
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "artifact_type": "prefetch-file",
                            "prefetch_validation_matrix": prefetch_validation_matrix(validation_checks),
                            "prefetch_report_grade_assessment": report_grade,
                            "size": stat_result.st_size,
                            "referenced_path_count": header.get("referenced_path_count", 0),
                            "prefetch_version": header.get("prefetch_version", 0),
                            "prefetch_section_bounds_profile": header.get("prefetch_section_bounds_profile", {}),
                        }
                    ),
                    "forensic_review": build_forensic_review(
                        gap_id="#16",
                        artifact_goal="Prefetch execution, run count, last-run, volume and file-reference evidence",
                        primary_evidence=[
                            f"executable={header_executable_name or filename_executable_hint}",
                            f"version={header.get('prefetch_version', '')}",
                            f"run_count={header.get('run_count', 0)}",
                            f"last_run_at={header.get('last_run_at', '')}",
                            f"referenced_paths={header.get('referenced_path_count', 0)}",
                        ],
                        validation_required=True,
                        report_grade_assessment=report_grade,
                        blockers=PREFETCH_REPORT_GRADE_BLOCKERS,
                        caveats=[
                            "Execution indicator only; correlate with Amcache, ShimCache, SRUM, BAM, EVTX, MFT and USN.",
                            "Full file metrics and authoritative volume table are not native-report-grade yet.",
                        ],
                    ),
                    "note": "Prefetch triage parser uses version-specific common-header offsets plus bounded native candidates; validate critical findings with a dedicated parser such as PECmd.",
                }),
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
    compression_probe = prefetch_compression_probe(blob)
    is_scca = len(header) >= 8 and header[4:8] == b"SCCA"
    prefetch_version = int.from_bytes(header[:4], "little") if is_scca else 0
    version_metadata = prefetch_version_metadata(prefetch_version)
    section_bounds_profile = prefetch_section_bounds_profile(blob, version_metadata, compression_probe)
    hints: dict[str, object] = {
        "binary_format_detected": is_scca,
        "prefetch_parse_status": "parsed-common-header" if version_metadata["supported_common_layout"] else "inventory-only",
        "prefetch_version": prefetch_version,
        "prefetch_version_metadata": version_metadata,
        "declared_file_size": 0,
        "header_executable_name": "",
        "run_count": 0,
        "last_run_at": "",
        "last_run_times": [],
        "referenced_paths": [],
        "referenced_path_count": 0,
        "volume_candidates": [],
        "volume_candidate_count": 0,
        "file_reference_candidates": [],
        "file_reference_candidate_count": 0,
        "prefetch_compression": compression_probe,
        "prefetch_section_bounds_profile": section_bounds_profile,
        "prefetch_validation_checks": prefetch_validation_checks(
            is_scca=is_scca,
            prefetch_version=prefetch_version,
            blob_size=len(blob),
            declared_file_size=0,
            run_count=0,
            run_times=[],
            referenced_paths=[],
            volume_candidates=[],
            compression_probe=compression_probe,
            section_bounds_profile=section_bounds_profile,
        ),
        "parser_confidence": "medium" if is_scca else "low",
    }
    if not is_scca:
        return hints
    hints["declared_file_size"] = read_u32(blob, 0x0C)
    run_count_offset = version_metadata.get("run_count_offset")
    last_run_offset = version_metadata.get("last_run_time_offset")
    last_run_slots = int(version_metadata.get("last_run_time_slots") or 0)
    if run_count_offset is not None:
        hints["run_count"] = read_u32(blob, int(run_count_offset))
    if last_run_offset is not None:
        run_times = prefetch_run_times(blob, int(last_run_offset), slots=last_run_slots)
        hints["last_run_times"] = run_times
        hints["last_run_at"] = run_times[0] if run_times else ""
    strings = extract_utf16le_strings(blob[: min(len(blob), MAX_PREFETCH_SCAN_BYTES)])
    fixed_header_name = read_prefetch_executable_name(blob)
    executable_names = [item for item in strings if ".exe" in item.lower()]
    if fixed_header_name:
        hints["header_executable_name"] = fixed_header_name
    elif executable_names:
        hints["header_executable_name"] = executable_names[0]
    referenced_paths = referenced_prefetch_paths(strings)
    volume_candidates = prefetch_volume_candidates(referenced_paths)
    file_reference_candidates = prefetch_file_reference_candidates(referenced_paths)
    hints["referenced_paths"] = referenced_paths[:MAX_REFERENCED_PATHS]
    hints["referenced_path_count"] = len(referenced_paths)
    hints["volume_candidates"] = volume_candidates[:MAX_CANDIDATES]
    hints["volume_candidate_count"] = len(volume_candidates)
    hints["file_reference_candidates"] = file_reference_candidates[:MAX_CANDIDATES]
    hints["file_reference_candidate_count"] = len(file_reference_candidates)
    hints["prefetch_validation_checks"] = prefetch_validation_checks(
        is_scca=is_scca,
        prefetch_version=prefetch_version,
        blob_size=len(blob),
        declared_file_size=int(hints["declared_file_size"]),
        run_count=int(hints["run_count"]),
        run_times=list(hints["last_run_times"]),
        referenced_paths=referenced_paths,
        volume_candidates=volume_candidates,
        compression_probe=compression_probe,
        section_bounds_profile=section_bounds_profile,
    )
    hints["parser_confidence"] = "medium" if version_metadata["supported_common_layout"] else "low"
    return hints


def prefetch_compression_probe(blob: bytes) -> dict[str, object]:
    magic = blob[:4]
    detected = magic[:3] == b"MAM"
    declared_uncompressed_size = int.from_bytes(blob[4:8], "little") if detected and len(blob) >= 8 else 0
    return {
        "detected": detected,
        "format": "windows-prefetch-mam" if detected else "plain-or-unknown",
        "magic_hex": magic.hex(),
        "declared_uncompressed_size": declared_uncompressed_size,
        "decompression_status": "not-implemented-recorded" if detected else "not-needed",
        "reportability": "external-decompression-required" if detected else "normal-scca-path",
    }


def prefetch_version_metadata(prefetch_version: int) -> dict[str, object]:
    layout = PREFETCH_VERSION_LAYOUTS.get(prefetch_version)
    if not layout:
        return {
            "supported_common_layout": False,
            "version": prefetch_version,
            "layout_name": "unsupported-or-unidentified",
            "windows_family": "",
            "run_count_offset": None,
            "run_count_offset_hex": "",
            "last_run_time_offset": None,
            "last_run_time_offset_hex": "",
            "last_run_time_slots": 0,
            "signature": "SCCA",
            "section_field_offsets": {},
        }
    run_count_offset = int(layout["run_count_offset"])
    last_run_time_offset = int(layout["last_run_time_offset"])
    return {
        "supported_common_layout": True,
        "version": prefetch_version,
        "layout_name": layout["layout_name"],
        "windows_family": layout["windows_family"],
        "run_count_offset": run_count_offset,
        "run_count_offset_hex": hex(run_count_offset),
        "last_run_time_offset": last_run_time_offset,
        "last_run_time_offset_hex": hex(last_run_time_offset),
        "last_run_time_slots": layout["last_run_time_slots"],
        "signature": "SCCA",
        "section_field_offsets": dict(PREFETCH_SECTION_FIELD_OFFSETS),
    }


def prefetch_section_bounds_profile(
    blob: bytes,
    version_metadata: Mapping[str, object],
    compression_probe: Mapping[str, object],
) -> dict[str, object]:
    version = int(version_metadata.get("version") or 0)
    supported = bool(version_metadata.get("supported_common_layout"))
    declared_file_size = read_u32(blob, 0x0C) if len(blob) >= 0x10 else 0
    profile: dict[str, object] = {
        "profile_version": "prefetch-section-bounds-profile-v1",
        "parser_version": PARSER_VERSION,
        "prefetch_version": version,
        "layout_name": str(version_metadata.get("layout_name") or ""),
        "actual_file_size": len(blob),
        "declared_file_size": declared_file_size,
        "compressed_prefetch_detected": bool(compression_probe.get("detected")),
        "bounds_status": "unsupported-layout",
        "section_count_declared": 0,
        "declared_sections_within_file": False,
        "sections": [],
        "decode_boundary": (
            "section-locator-only; file metrics, trace chains, and volume records are not decoded as report-grade rows"
        ),
    }
    if compression_probe.get("detected"):
        profile["bounds_status"] = "compressed-not-decompressed"
        profile["section_profile_hash"] = prefetch_stable_sha256(profile)
        return profile
    if not supported:
        profile["section_profile_hash"] = prefetch_stable_sha256(profile)
        return profile

    sections: list[dict[str, object]] = []
    for section_name, offset_fields in PREFETCH_SECTION_FIELD_OFFSETS.items():
        offset_value = read_u32(blob, int(offset_fields["offset"]))
        count_value = read_u32(blob, int(offset_fields["count"])) if "count" in offset_fields else 0
        size_value = read_u32(blob, int(offset_fields["size"])) if "size" in offset_fields else 0
        entry_size = int(PREFETCH_SECTION_ENTRY_SIZE_HINTS.get(section_name, {}).get(version, 0))
        derived_size = size_value or (count_value * entry_size if count_value and entry_size else 0)
        end_offset = offset_value + derived_size if offset_value and derived_size else 0
        declared = bool(offset_value or count_value or size_value)
        within_file = bool(declared and offset_value > 0 and end_offset > offset_value and end_offset <= len(blob))
        if within_file:
            bounds_status = "bounded-locator"
        elif declared:
            bounds_status = "declared-out-of-bounds-or-size-missing"
        else:
            bounds_status = "not-declared"
        sections.append(
            {
                "section": section_name,
                "offset": offset_value,
                "offset_hex": hex(offset_value) if offset_value else "",
                "count": count_value,
                "declared_size": size_value,
                "entry_size_assumption": entry_size,
                "derived_size": derived_size,
                "end_offset": end_offset,
                "within_file": within_file,
                "bounds_status": bounds_status,
                "decode_status": "locator-only-not-decoded",
            }
        )
    declared_sections = [section for section in sections if section["bounds_status"] != "not-declared"]
    profile["sections"] = sections
    profile["section_count_declared"] = len(declared_sections)
    profile["declared_sections_within_file"] = bool(declared_sections) and all(
        bool(section["within_file"]) for section in declared_sections
    )
    profile["bounds_status"] = (
        "declared-sections-bounded"
        if profile["declared_sections_within_file"]
        else "section-locators-recorded"
    )
    profile["section_profile_hash"] = prefetch_stable_sha256(profile)
    return profile


def build_prefetch_reference_record(
    path: Path,
    referenced_path: str,
    index: int,
    header: dict[str, object],
    source_hashes: dict[str, str],
) -> ArtifactRecord:
    executable_name = str(header.get("header_executable_name") or executable_hint(path.name))
    validation_checks = header.get("prefetch_validation_checks") or {}
    report_grade = prefetch_report_grade_assessment(validation_checks)
    core_accuracy_gates = prefetch_core_accuracy_gates(
        {
            "source_path": str(path.resolve()),
            "source_hashes": dict(source_hashes),
            "source_index": index,
            "validation_checks": validation_checks,
            **header,
            "referenced_path": referenced_path,
        }
    )
    return ArtifactRecord(
        provider=WindowsPrefetchProvider.name,
        artifact_type="prefetch-reference",
        path=str(path.resolve()),
        supported=True,
        details=with_prefetch_depth_manifest({
            "parser": "windows-prefetch-reference",
            "parser_version": PARSER_VERSION,
            "artifact_type": "prefetch-reference",
            "coverage_status": "native-reference-string",
            "reportability": "triage",
            "parser_confidence": "low",
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
            "volume_device_path": prefetch_volume_device_path(referenced_path),
            "run_count": header.get("run_count", 0),
            "last_run_at": header.get("last_run_at", ""),
            "timestamp": header.get("last_run_at", ""),
            "timestamp_source": "prefetch_last_run_at",
            "evidence_strength": "prefetch-file-reference",
            "validation_required": True,
            "core_accuracy_gates": core_accuracy_gates,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": list(PREFETCH_REPORT_GRADE_BLOCKERS),
            "commercial_readiness_blockers": list(PREFETCH_COMMERCIAL_BLOCKERS),
            "prefetch_validation_matrix": prefetch_validation_matrix(validation_checks),
            "prefetch_report_grade_assessment": report_grade,
            "prefetch_native_capabilities": dict(PREFETCH_NATIVE_CAPABILITIES),
            "commercial_uplift_evidence": prefetch_commercial_uplift_evidence(
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": dict(source_hashes),
                    "source_index": index,
                    "artifact_type": "prefetch-reference",
                    "prefetch_validation_matrix": prefetch_validation_matrix(validation_checks),
                    "prefetch_report_grade_assessment": report_grade,
                    "referenced_path": referenced_path,
                    "prefetch_version": header.get("prefetch_version", 0),
                    "prefetch_section_bounds_profile": header.get("prefetch_section_bounds_profile", {}),
                }
            ),
            "forensic_review": build_forensic_review(
                gap_id="#16",
                artifact_goal="Prefetch referenced file/volume pivot evidence",
                primary_evidence=[
                    f"executable={executable_name}",
                    f"referenced_path={referenced_path}",
                    f"last_run_at={header.get('last_run_at', '')}",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                blockers=PREFETCH_REPORT_GRADE_BLOCKERS,
                caveats=["Reference rows are bounded native string pivots, not complete decoded file metrics entries."],
            ),
            "validation_guidance": "Prefetch reference rows are recovered from bounded native strings; validate complete file metrics and volumes with PECmd before final testimony.",
            "raw_preview": referenced_path,
        }),
    )


def prefetch_run_times(blob: bytes, offset: int, *, slots: int) -> list[str]:
    values = []
    for index in range(max(0, slots)):
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


def prefetch_volume_candidates(referenced_paths: list[str]) -> list[dict[str, object]]:
    candidates: dict[str, dict[str, object]] = {}
    for path in referenced_paths:
        device_path = prefetch_volume_device_path(path)
        if not device_path:
            continue
        item = candidates.setdefault(
            device_path.upper(),
            {
                "volume_device_path": device_path,
                "source": "referenced_path_prefix",
                "confidence": "candidate",
                "referenced_path_count": 0,
                "sample_referenced_paths": [],
            },
        )
        item["referenced_path_count"] = int(item["referenced_path_count"]) + 1
        samples = item["sample_referenced_paths"]
        if isinstance(samples, list) and len(samples) < 5:
            samples.append(path)
    return list(candidates.values())


def prefetch_file_reference_candidates(referenced_paths: list[str]) -> list[dict[str, object]]:
    candidates = []
    for index, path in enumerate(referenced_paths[:MAX_CANDIDATES]):
        windows_path = PureWindowsPath(path)
        candidates.append(
            {
                "candidate_index": index,
                "referenced_path": path,
                "referenced_file_name": windows_path.name,
                "referenced_extension": windows_path.suffix.lower(),
                "volume_device_path": prefetch_volume_device_path(path),
                "source": "bounded_utf16_path_string",
                "confidence": "candidate",
            }
        )
    return candidates


def prefetch_volume_device_path(path: str) -> str:
    upper_path = path.upper()
    marker = "\\DEVICE\\HARDDISKVOLUME"
    if marker in upper_path:
        start = upper_path.index(marker)
        end = path.find("\\", start + len(marker))
        return path[start:] if end == -1 else path[start:end]
    volume_marker = "\\?\\VOLUME{"
    if volume_marker in upper_path:
        start = upper_path.index(volume_marker)
        end = path.find("\\", start + len(volume_marker))
        return path[start:] if end == -1 else path[start:end]
    return ""


def prefetch_validation_checks(
    *,
    is_scca: bool,
    prefetch_version: int,
    blob_size: int,
    declared_file_size: int,
    run_count: int,
    run_times: list[str],
    referenced_paths: list[str],
    volume_candidates: list[dict[str, object]],
    compression_probe: Mapping[str, object] | None = None,
    section_bounds_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    compression = compression_probe or {}
    section_profile = section_bounds_profile or {}
    now = datetime.now(tz=timezone.utc)
    parsed_run_times = [parse_iso_datetime(item) for item in run_times]
    valid_run_times = [item for item in parsed_run_times if item is not None]
    file_size_matches_declared = None
    if declared_file_size > 0:
        file_size_matches_declared = declared_file_size == blob_size
    return {
        "has_scca_signature": is_scca,
        "compressed_prefetch_detected": bool(compression.get("detected")),
        "compressed_prefetch_status_recorded": bool(compression.get("decompression_status")),
        "compressed_prefetch_decompressed": False,
        "supported_common_layout": prefetch_version in PREFETCH_VERSION_LAYOUTS,
        "declared_file_size": declared_file_size,
        "actual_file_size": blob_size,
        "file_size_matches_declared": file_size_matches_declared,
        "run_count_present": run_count > 0,
        "run_count_plausible": 0 <= run_count <= MAX_REASONABLE_RUN_COUNT,
        "last_run_times_present": bool(run_times),
        "last_run_time_count": len(run_times),
        "last_run_times_parseable": len(valid_run_times) == len(run_times),
        "last_run_times_not_future": all(item <= now for item in valid_run_times),
        "has_referenced_paths": bool(referenced_paths),
        "referenced_path_count": len(referenced_paths),
        "has_volume_candidates": bool(volume_candidates),
        "volume_candidate_count": len(volume_candidates),
        "section_bounds_profile_emitted": bool(section_profile.get("section_profile_hash")),
        "section_count_declared": int(section_profile.get("section_count_declared") or 0),
        "declared_sections_within_file": bool(section_profile.get("declared_sections_within_file")),
        "full_file_metrics_decoded": False,
        "full_volume_table_decoded": False,
        "commercial_validation_required": True,
    }


def prefetch_validation_matrix(checks: object) -> list[dict[str, object]]:
    check_map = checks if isinstance(checks, dict) else {}
    return [
        {
            "id": "scca-signature",
            "label": "PF SCCA signature present",
            "passed": bool(check_map.get("has_scca_signature")),
            "severity": "critical",
        },
        {
            "id": "supported-common-layout",
            "label": "Common header offsets are known for this Prefetch version",
            "passed": bool(check_map.get("supported_common_layout")),
            "severity": "high",
        },
        {
            "id": "compressed-prefetch-status-recorded",
            "label": "Compressed Prefetch status is detected and disclosed",
            "passed": (not bool(check_map.get("compressed_prefetch_detected")))
            or bool(check_map.get("compressed_prefetch_status_recorded")),
            "severity": "medium",
        },
        {
            "id": "section-bounds-profile",
            "label": "Declared section offsets are profiled and bounded when present",
            "passed": bool(check_map.get("section_bounds_profile_emitted"))
            and (
                bool(check_map.get("declared_sections_within_file"))
                or int(check_map.get("section_count_declared") or 0) == 0
                or bool(check_map.get("compressed_prefetch_detected"))
            ),
            "severity": "high",
        },
        {
            "id": "declared-size-match",
            "label": "Declared file size matches actual size when present",
            "passed": check_map.get("file_size_matches_declared") is True,
            "severity": "medium",
        },
        {
            "id": "execution-counters-present",
            "label": "Run count and last-run timestamps are present/plausible",
            "passed": bool(check_map.get("run_count_plausible"))
            and bool(check_map.get("last_run_times_parseable"))
            and bool(check_map.get("last_run_times_not_future")),
            "severity": "high",
        },
        {
            "id": "file-metrics-report-grade",
            "label": "Full file metrics, MFT references, volume tables, and trace chains decoded",
            "passed": False,
            "severity": "critical",
        },
    ]


def prefetch_report_grade_assessment(checks: object) -> dict[str, object]:
    matrix = prefetch_validation_matrix(checks)
    failed = [item for item in matrix if not item["passed"]]
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#16"],
        "failed_check_ids": [str(item["id"]) for item in failed],
        "blockers": list(PREFETCH_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Validate key execution claims with PECmd or another known-answer-validated Prefetch parser.",
            "Correlate Prefetch run counts/timestamps with Amcache, ShimCache, SRUM, BAM, EVTX, and $MFT/$UsnJrnl.",
        ],
    }


def prefetch_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("prefetch_validation_matrix") if isinstance(details.get("prefetch_validation_matrix"), list) else []
    report_grade = (
        details.get("prefetch_report_grade_assessment")
        if isinstance(details.get("prefetch_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("prefetch_trusted_diff")
        if isinstance(details.get("prefetch_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    section_profile = (
        details.get("prefetch_section_bounds_profile")
        if isinstance(details.get("prefetch_section_bounds_profile"), Mapping)
        else {}
    )
    reportability_decision = prefetch_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-016-020",
        "item_numbers": [16],
        "qc_prep_item_numbers": [QC_PREP_PREFETCH_ITEM],
        "qc_prep_contracts": [dict(QC_PREP_PREFETCH_CONTRACT)],
        "implementation_track": "native-parser-depth",
        "objective": "Expose Prefetch version/layout validation, referenced-path evidence, and commercial blockers.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_index:{details.get('source_index', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
            f"section_profile_hash:{section_profile.get('section_profile_hash', '')}",
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
        "prefetch_trusted_diff": trusted_diff,
        "large_data_controls": {
            "bounded_prefetch_scan": True,
            "scan_limit_bytes": MAX_PREFETCH_SCAN_BYTES,
            "max_referenced_paths": MAX_REFERENCED_PATHS,
            "prefetch_version": int(details.get("prefetch_version") or 0),
            "section_bounds_status": str(section_profile.get("bounds_status") or ""),
            "section_count_declared": int(section_profile.get("section_count_declared") or 0),
            "section_profile_hash": str(section_profile.get("section_profile_hash") or ""),
            "full_file_metrics_decode_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish file metrics, MFT reference, authoritative volume, compressed PF, and cross-version corpus validation.",
        "external_evidence_required": True,
    }


def prefetch_reportability_decision(
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("prefetch-file-metrics-and-volume-table-validation-required")
    blockers.add("prefetch-cross-tool-execution-correlation-required")
    blockers.add("prefetch-trusted-parser-diff-required")
    return {
        "profile_version": "prefetch-reportability-decision-v1",
        "commercial_gap_id": "#16",
        "qc_prep_item_number": QC_PREP_PREFETCH_ITEM,
        "qc_prep_item_goal": QC_PREP_PREFETCH_GOAL,
        "qc_prep_contract": dict(QC_PREP_PREFETCH_CONTRACT),
        "decision": "report-only-with-execution-correlation",
        "allowed_use": "prefetch-execution-triage-pivot",
        "blockers": sorted(blockers),
        "required_before_report": [
            "compressed Prefetch handling validated where applicable",
            "declared section offsets and bounds diffed against a trusted Prefetch parser for critical claims",
            "file metrics and volume tables decoded",
            "run counts and timestamps diffed against PECmd or known-answer corpus",
            "execution claim correlated with Amcache, BAM, SRUM, EventLog, MFT, or USN",
        ],
    }


def with_prefetch_depth_manifest(details: dict[str, object]) -> dict[str, object]:
    details["prefetch_analyst_review_profile"] = prefetch_analyst_review_profile(details)
    details["prefetch_execution_depth_manifest"] = prefetch_execution_depth_manifest(details)
    details["prefetch_execution_depth_manifest_hash"] = details["prefetch_execution_depth_manifest"]["manifest_sha256"]
    return details


def prefetch_analyst_review_profile(details: Mapping[str, object]) -> dict[str, object]:
    report_grade = (
        details.get("prefetch_report_grade_assessment")
        if isinstance(details.get("prefetch_report_grade_assessment"), Mapping)
        else {}
    )
    checks = details.get("prefetch_validation_checks") if isinstance(details.get("prefetch_validation_checks"), Mapping) else {}
    section_profile = (
        details.get("prefetch_section_bounds_profile")
        if isinstance(details.get("prefetch_section_bounds_profile"), Mapping)
        else {}
    )
    source_values = {
        "entry_name": str(details.get("entry_name") or details.get("prefetch_entry_name") or ""),
        "executable_hint": str(details.get("executable_hint") or ""),
        "prefetch_hash": str(details.get("prefetch_hash") or ""),
        "prefetch_version": int(details.get("prefetch_version") or 0),
        "section_bounds_status": str(section_profile.get("bounds_status") or ""),
        "section_count_declared": int(section_profile.get("section_count_declared") or 0),
        "section_profile_hash": str(section_profile.get("section_profile_hash") or ""),
        "run_count": int(details.get("run_count") or 0),
        "last_run_at": str(details.get("last_run_at") or ""),
        "referenced_path": str(details.get("referenced_path") or ""),
        "referenced_path_count": int(details.get("referenced_path_count") or 0),
    }
    failed_checks = sorted(str(key) for key, value in checks.items() if value is False)
    blockers = sorted(set(str(item) for item in report_grade.get("blockers", []) if str(item)) | set(PREFETCH_REPORT_GRADE_BLOCKERS))
    return {
        "profile_version": "prefetch-analyst-review-profile-v1",
        "qc_prep_item_number": QC_PREP_PREFETCH_ITEM,
        "qc_prep_item_goal": QC_PREP_PREFETCH_GOAL,
        "artifact_type": str(details.get("artifact_type") or ""),
        "severity": "high" if int(details.get("run_count") or 0) or details.get("last_run_at") else "medium",
        "summary": "Prefetch execution pivot with run count, last-run time, version layout, and referenced-file context.",
        "evidence_interpretation": "application execution indicator that needs correlation before final execution testimony",
        "not_proof_of": ["user intent", "complete file metrics table", "authoritative volume mapping", "standalone execution attribution"],
        "analyst_questions": [
            "Does PECmd or another trusted parser confirm the executable, hash, run count, and last-run timestamp?",
            "Do Amcache, ShimCache, BAM/DAM, SRUM, EVTX, MFT, or USN corroborate the execution?",
            "Is the PF compressed or version-specific in a way that requires external validation?",
        ],
        "primary_pivots": [
            "entry_name",
            "executable_hint",
            "prefetch_hash",
            "prefetch_version",
            "section_bounds_status",
            "section_profile_hash",
            "run_count",
            "last_run_at",
            "referenced_path",
            "referenced_path_count",
        ],
        "source_field_values": {key: value for key, value in source_values.items() if value not in ("", None, [], {})},
        "correlation_targets": ["Amcache", "ShimCache", "BAM/DAM", "SRUM", "EVTX", "MFT", "USN"],
        "risk_tags": ["execution-indicator", "prefetch-validation-required"],
        "validation_required": True,
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": blockers,
        "report_guidance": (
            "Use Prefetch as an execution-review pivot. Do not report final execution conclusions without "
            "trusted Prefetch diff evidence and cross-artifact correlation."
        ),
    }


def prefetch_stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def prefetch_execution_depth_manifest(details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    checks = details.get("prefetch_validation_checks") if isinstance(details.get("prefetch_validation_checks"), Mapping) else {}
    version_metadata = (
        details.get("prefetch_version_metadata")
        if isinstance(details.get("prefetch_version_metadata"), Mapping)
        else {}
    )
    compression = (
        details.get("prefetch_compression")
        if isinstance(details.get("prefetch_compression"), Mapping)
        else {}
    )
    section_profile = (
        details.get("prefetch_section_bounds_profile")
        if isinstance(details.get("prefetch_section_bounds_profile"), Mapping)
        else {}
    )
    report_grade = (
        details.get("prefetch_report_grade_assessment")
        if isinstance(details.get("prefetch_report_grade_assessment"), Mapping)
        else {}
    )
    reportability = prefetch_reportability_decision(report_grade, details)
    referenced_paths = [str(item) for item in details.get("referenced_paths") or []]
    if details.get("referenced_path"):
        referenced_paths = [str(details.get("referenced_path") or "")]
    row_identity = {
        "entry_name": str(details.get("entry_name") or details.get("prefetch_entry_name") or ""),
        "executable_hint": str(details.get("executable_hint") or ""),
        "prefetch_hash": str(details.get("prefetch_hash") or ""),
        "artifact_type": str(details.get("artifact_type") or ""),
        "source_index": details.get("source_index", ""),
    }
    manifest_payload = {
        "manifest_version": "prefetch-execution-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 16,
        "gap_id": "#16",
        "qc_prep_item_number": QC_PREP_PREFETCH_ITEM,
        "qc_prep_item_goal": QC_PREP_PREFETCH_GOAL,
        "qc_prep_contract": dict(QC_PREP_PREFETCH_CONTRACT),
        "artifact_type": str(details.get("artifact_type") or "prefetch-file"),
        "source": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "source_format": str(details.get("source_format") or ""),
            "source_index": details.get("source_index", ""),
            "size": details.get("size", ""),
        },
        "row_identity": row_identity,
        "row_identity_hash": prefetch_stable_sha256(row_identity),
        "format_validation": {
            "binary_format_detected": bool(details.get("binary_format_detected")),
            "scca_signature": bool(checks.get("has_scca_signature")),
            "prefetch_version": int(details.get("prefetch_version") or 0),
            "layout_name": str(version_metadata.get("layout_name") or ""),
            "windows_family": str(version_metadata.get("windows_family") or ""),
            "supported_common_layout": bool(version_metadata.get("supported_common_layout")),
            "declared_file_size": int(details.get("declared_file_size") or checks.get("declared_file_size") or 0),
            "actual_file_size": int(checks.get("actual_file_size") or details.get("size") or 0),
            "file_size_matches_declared": checks.get("file_size_matches_declared"),
            "section_bounds_profile_hash": str(section_profile.get("section_profile_hash") or ""),
            "section_bounds_status": str(section_profile.get("bounds_status") or ""),
            "section_count_declared": int(section_profile.get("section_count_declared") or 0),
            "declared_sections_within_file": bool(section_profile.get("declared_sections_within_file")),
        },
        "execution_counters": {
            "run_count": int(details.get("run_count") or 0),
            "run_count_present": bool(checks.get("run_count_present")),
            "run_count_plausible": bool(checks.get("run_count_plausible")),
            "last_run_at": str(details.get("last_run_at") or ""),
            "last_run_times": list(details.get("last_run_times") or [])[:16],
            "last_run_time_count": int(checks.get("last_run_time_count") or len(list(details.get("last_run_times") or []))),
            "last_run_times_not_future": bool(checks.get("last_run_times_not_future")),
        },
        "referenced_file_metrics": {
            "referenced_path_count": len(referenced_paths) or int(details.get("referenced_path_count") or 0),
            "referenced_paths_preview": referenced_paths[:25],
            "volume_candidate_count": int(details.get("volume_candidate_count") or 0),
            "volume_candidates": [dict(item) for item in details.get("volume_candidates") or [] if isinstance(item, Mapping)][:25],
            "file_reference_candidate_count": int(details.get("file_reference_candidate_count") or 0),
            "file_reference_candidates": [
                dict(item) for item in details.get("file_reference_candidates") or [] if isinstance(item, Mapping)
            ][:25],
            "file_metrics_section_status": prefetch_section_status(section_profile, "file_metrics_array"),
            "filename_strings_section_status": prefetch_section_status(section_profile, "filename_strings"),
            "volume_information_section_status": prefetch_section_status(section_profile, "volume_information"),
            "full_file_metrics_decoded": bool(checks.get("full_file_metrics_decoded")),
            "mft_file_reference_decode_available": bool(PREFETCH_NATIVE_CAPABILITIES["mft_file_reference_decode"]),
            "authoritative_volume_table_decoded": bool(checks.get("full_volume_table_decoded")),
        },
        "section_bounds": {
            "profile_version": str(section_profile.get("profile_version") or ""),
            "bounds_status": str(section_profile.get("bounds_status") or ""),
            "section_count_declared": int(section_profile.get("section_count_declared") or 0),
            "declared_sections_within_file": bool(section_profile.get("declared_sections_within_file")),
            "section_profile_hash": str(section_profile.get("section_profile_hash") or ""),
            "sections": [dict(item) for item in section_profile.get("sections") or [] if isinstance(item, Mapping)],
            "decode_boundary": str(section_profile.get("decode_boundary") or ""),
        },
        "compression": {
            "detected": bool(compression.get("detected")),
            "format": str(compression.get("format") or ""),
            "declared_uncompressed_size": int(compression.get("declared_uncompressed_size") or 0),
            "decompression_status": str(compression.get("decompression_status") or ""),
            "decompressed_by_rapidforensic": bool(checks.get("compressed_prefetch_decompressed")),
        },
        "citation_refs": [
            {
                "kind": "prefetch-source-file",
                "source_path": str(details.get("source_path") or ""),
                "source_sha256": str(hashes.get("sha256") or ""),
            },
            {
                "kind": "prefetch-header-layout",
                "prefetch_version": int(details.get("prefetch_version") or 0),
                "layout_name": str(version_metadata.get("layout_name") or ""),
            },
            {
                "kind": "prefetch-execution-counters",
                "run_count": int(details.get("run_count") or 0),
                "last_run_at": str(details.get("last_run_at") or ""),
            },
            {
                "kind": "prefetch-reference-candidates",
                "referenced_path_count": len(referenced_paths) or int(details.get("referenced_path_count") or 0),
                "volume_candidate_count": int(details.get("volume_candidate_count") or 0),
            },
            {
                "kind": "prefetch-section-bounds",
                "bounds_status": str(section_profile.get("bounds_status") or ""),
                "section_profile_hash": str(section_profile.get("section_profile_hash") or ""),
            },
            {
                "kind": "prefetch-compression-state",
                "format": str(compression.get("format") or ""),
                "decompression_status": str(compression.get("decompression_status") or ""),
            },
        ],
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "ready_for_court_report": bool(report_grade.get("ready_for_court_report")),
            "commercial_grade_ready": False,
            "execution_claim_requires_correlation": True,
            "file_metrics_complete": False,
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "decode full file metrics array and MFT file references",
            "decode authoritative volume table and trace chains",
            "decompress and validate MAM-compressed Prefetch files when present",
            "diff run counts, timestamps, paths, and volume data against PECmd or trusted known-answer corpus",
            "correlate execution claim with Amcache, BAM/DAM, SRUM, EVTX, MFT, or USN evidence",
        ],
    }
    manifest_payload["manifest_sha256"] = prefetch_stable_sha256(manifest_payload)
    return manifest_payload


def prefetch_section_status(section_profile: Mapping[str, object], section_name: str) -> str:
    for section in section_profile.get("sections") or []:
        if isinstance(section, Mapping) and section.get("section") == section_name:
            return str(section.get("bounds_status") or "")
    return ""


def prefetch_core_accuracy_gates(details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    version_metadata = (
        details.get("prefetch_version_metadata")
        if isinstance(details.get("prefetch_version_metadata"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("prefetch_trusted_diff")
        if isinstance(details.get("prefetch_trusted_diff"), Mapping)
        else {}
    )
    section_profile = (
        details.get("prefetch_section_bounds_profile")
        if isinstance(details.get("prefetch_section_bounds_profile"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"source_index:{details.get('source_index', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if checks.get("has_scca_signature") or details.get("binary_format_detected"):
        satisfied.append("SCCA/header validation")
    if version_metadata.get("supported_common_layout"):
        satisfied.append("version-specific section offsets")
    if checks.get("run_count_present") or checks.get("last_run_times_present") or details.get("last_run_times"):
        satisfied.append("run count and last-run timestamps")
    if details.get("volume_candidates") or details.get("file_reference_candidates") or details.get("referenced_path"):
        satisfied.append("volume/file metrics")
    if checks.get("compressed_prefetch_status_recorded") or details.get("prefetch_compression"):
        satisfied.append("compressed PF handling")
    if section_profile.get("section_profile_hash") or checks.get("section_bounds_profile_emitted"):
        satisfied.append("section bounds profile")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted Prefetch parser diff pass")
    return [build_accuracy_gate(16, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_prefetch_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_prefetch_diff_payload(
        index_prefetch_rows(rapid_rows),
        index_prefetch_rows(trusted_rows),
        trusted_tool=trusted_tool,
    )


def index_prefetch_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = prefetch_diff_row_payload(row)
        version_metadata = (
            payload.get("prefetch_version_metadata")
            if isinstance(payload.get("prefetch_version_metadata"), Mapping)
            else {}
        )
        compression = (
            payload.get("prefetch_compression")
            if isinstance(payload.get("prefetch_compression"), Mapping)
            else {}
        )
        section_profile = (
            payload.get("prefetch_section_bounds_profile")
            if isinstance(payload.get("prefetch_section_bounds_profile"), Mapping)
            else {}
        )
        executable = normalized_diff_value(
            first_alias(payload, "executable_hint", "executable", "filename", "application_name", "executable_name")
        )
        pf_hash = normalized_diff_value(first_alias(payload, "prefetch_hash", "hash", "prefetchhash"))
        key = "|".join(item for item in (executable, pf_hash) if item)
        if not key:
            continue
        indexed[key] = {
            "executable": executable,
            "prefetch_hash": pf_hash,
            "run_count": normalized_int_text(first_alias(payload, "run_count", "runcount")),
            "last_run": normalized_diff_value(first_alias(payload, "last_run_at", "last_run", "lastrun")),
            "last_run_times": normalized_diff_list(first_alias(payload, "last_run_times", "previous_run_times", "run_times")),
            "prefetch_version": normalized_int_text(first_alias(payload, "prefetch_version", "version")),
            "layout_name": normalized_diff_value(
                first_present(
                    first_alias(payload, "layout_name", "prefetch_layout"),
                    first_alias(version_metadata, "layout_name", "prefetch_layout"),
                )
            ),
            "declared_file_size": normalized_int_text(first_alias(payload, "declared_file_size", "filesize", "file_size")),
            "referenced_path": normalized_diff_list(
                first_alias(payload, "referenced_path", "referenced_paths", "file_name", "files_loaded", "path")
            ),
            "volume_device_path": normalized_diff_list(
                first_alias(payload, "volume_device_path", "volume_candidates", "volume_paths", "volumedevicepath")
            ),
            "file_reference": normalized_diff_list(
                first_alias(payload, "file_reference", "file_reference_candidates", "mft_reference", "filemetrics")
            ),
            "compression_format": normalized_diff_value(
                first_present(
                    first_alias(payload, "compression_format", "prefetch_compression_format"),
                    first_alias(compression, "format", "compression_format"),
                )
            ),
            "compression_status": normalized_diff_value(
                first_present(
                    first_alias(payload, "decompression_status", "compression_status"),
                    first_alias(compression, "decompression_status", "compression_status"),
                )
            ),
            "section_bounds_status": normalized_diff_value(
                first_present(
                    first_alias(payload, "section_bounds_status", "prefetch_section_bounds_status"),
                    first_alias(section_profile, "bounds_status", "section_bounds_status"),
                )
            ),
            "section_profile_hash": normalized_diff_value(
                first_present(
                    first_alias(payload, "section_profile_hash", "prefetch_section_profile_hash"),
                    first_alias(section_profile, "section_profile_hash"),
                )
            ),
        }
    return indexed


def prefetch_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def build_prefetch_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in PREFETCH_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append({"prefetch_key": key, "field": field, "rapid_value": rapid_value, "trusted_value": trusted_value})
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "prefetch-trusted-parser-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-prefetch-output-as-final",
            "blockers": [] if status == "pass" else ["prefetch-trusted-parser-diff-required"],
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


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in value.replace("\n", ";").split(";") if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [normalize_prefetch_list_item(item) for item in value]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalize_prefetch_list_item(value: object) -> str:
    if isinstance(value, Mapping):
        return str(
            first_alias(
                value,
                "referenced_path",
                "path",
                "file_name",
                "volume_device_path",
                "device_path",
                "file_reference",
                "mft_reference",
                "timestamp",
                "value",
            )
            or ""
        ).strip()
    return str(value).strip()


def read_prefetch_executable_name(blob: bytes) -> str:
    if len(blob) < 0x12:
        return ""
    raw_name = blob[0x10:0x80]
    terminator = raw_name.find(b"\x00\x00")
    if terminator >= 0:
        raw_name = raw_name[: terminator + (terminator % 2)]
    name = raw_name.decode("utf-16le", errors="ignore").strip("\x00").strip()
    if name.lower().endswith((".exe", ".dll", ".scr", ".com")):
        return name
    return ""


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


def parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def read_u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little")


def read_u64(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 8], "little")
