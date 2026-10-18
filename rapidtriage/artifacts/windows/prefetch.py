from __future__ import annotations

import binascii
import functools
import hashlib
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

from ...core.artifact_profiles import cap_list_field
from ...core.audit import compute_sha256
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review, isoformat_from_timestamp
from .filesystem import CONTENT_KIND_LABELS_KO, sniff_content_kind
from .xpress_huffman import MAX_OUTPUT_BYTES, XpressHuffmanError
from .xpress_huffman import decompress as xpress_huffman_decompress

PREFETCH_ROOT = ("Windows", "Prefetch")
PARSER_VERSION = "prefetch-inventory-v10"
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
        "pure-Python MAM (XPRESS Huffman) decompression bounded at 16 MB on every host",
        "version-aware section bounds profile for file metrics, trace chains, filename strings, and volume locators",
        "bounded referenced-path, volume-device, and file-reference candidate pivots",
        "execution-depth manifest with source hash, offsets, validation checks, and report blockers",
    ],
    "commercial_blockers": [
        "PECmd/known-answer cross-version corpus diff evidence",
    ],
}
MAX_PREFETCH_SCAN_BYTES = 1024 * 1024
# Per-record list caps (run-pipeline-mitigations §7 I12). Lists longer than
# the cap are cut and marked ``<key>_truncated: true`` / ``<key>_total: n``.
# referenced_paths stays at 200 (within the ≤256 contract); the per-file
# file_reference_candidates list is capped at 64 entries.
MAX_REFERENCED_PATHS = 200
MAX_CANDIDATES = 200
MAX_FILE_REFERENCE_CANDIDATES = 64
MAX_REASONABLE_RUN_COUNT = 1_000_000
# ``referenced_files`` (decoded file-metrics entries) on the prefetch-file row.
MAX_REFERENCED_FILES = 1000
MAM_ALGORITHM_XPRESS_HUFFMAN = 4
# Trace-chain entry size: 12 bytes before Windows 8 (v17/v23), 8 bytes after.
PREFETCH_TRACE_CHAIN_ENTRY_SIZE = {17: 12, 23: 12, 26: 8, 30: 8, 31: 8}
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
    "trace_chains": PREFETCH_TRACE_CHAIN_ENTRY_SIZE,
}
PREFETCH_COMMERCIAL_BLOCKERS = [
    "Full file metrics array decoding (load-order paths, MFT references) is native but not yet diffed against a PECmd known-answer corpus.",
    "Volume information (device path, serial, creation time, directory strings) is decoded natively but not yet corpus-validated.",
    "Trace chains are counted and bounds-checked only (entries are not interpreted); file information layouts are validated only for the observed v17/23/26/30/31 variants.",
    "Known-answer corpus validation across malformed, compressed, and cross-version Prefetch files is incomplete.",
]
PREFETCH_NATIVE_CAPABILITIES = {
    "scca_signature_validation": True,
    "compressed_prefetch_detection": True,
    "compressed_prefetch_decompression": True,
    "compressed_prefetch_decompression_platform": "pure-python-any-host",
    "common_header_version_offsets": True,
    "section_locator_bounds_profile": True,
    "run_count_and_last_run_times": True,
    "bounded_referenced_path_pivots": True,
    "volume_candidate_pivots": True,
    "full_file_metrics_array_decode": True,
    "mft_file_reference_decode": True,
    "authoritative_volume_table_decode": True,
    "trace_chain_count_decode": True,
    "trace_chain_decode": False,
    "cross_version_known_answer_corpus": False,
}
PREFETCH_REPORT_GRADE_BLOCKERS = [
    "trace-chain-entry-interpretation-not-implemented",
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
            if not header.get("binary_format_detected"):
                yield build_prefetch_invalid_content_record(path, header, stat_result)
                continue
            all_referenced_paths = list(header.pop("referenced_paths_all", None) or header.get("referenced_paths") or [])
            reference_offsets = list(header.pop("referenced_source_offsets_all", None) or [])
            filename_executable_hint = executable_hint(path.name)
            header_executable_name = str(header.get("header_executable_name") or "")
            source_hashes = {"sha256": compute_sha256(path)}
            validation_checks = header.get("prefetch_validation_checks") or {}
            report_grade = prefetch_report_grade_assessment(validation_checks)
            core_accuracy_gates = prefetch_core_accuracy_gates(
                {
                    "source_path": resolved_path_text(path),
                    "source_hashes": source_hashes,
                    "validation_checks": validation_checks,
                    **header,
                }
            )
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="prefetch-file",
                path=resolved_path_text(path),
                supported=True,
                details=with_prefetch_depth_manifest({
                    "parser": "windows-prefetch-inventory",
                    "parser_version": PARSER_VERSION,
                    "artifact_type": "prefetch-file",
                    "coverage_status": "detected",
                    "reportability": "triage",
                    "parser_confidence": header.get("parser_confidence", "low"),
                    "source_path": resolved_path_text(path),
                    "source_format": "pf",
                    "source_hashes": source_hashes,
                    "executable_hint": header_executable_name or filename_executable_hint,
                    "executable_hint_source": "prefetch_header" if header_executable_name else "filename",
                    "filename_executable_hint": filename_executable_hint,
                    **header,
                    "prefetch_hash": prefetch_hash_hint(path.name),
                    "entry_name": path.name,
                    "size": stat_result.st_size,
                    # Host mtime of the acquired copy is provenance only, never an event.
                    "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
                    "timestamp": header.get("last_run_at", ""),
                    "timestamp_source": "prefetch_last_run_time" if header.get("last_run_at") else "missing_prefetch_run_time",
                    "timestamp_kind": "run",
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
                            "source_path": resolved_path_text(path),
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
                            "File metrics and volume table are decoded natively but not yet diffed against a PECmd known-answer corpus.",
                        ],
                    ),
                    "note": "Prefetch triage parser uses version-specific common-header offsets plus bounded native candidates; validate critical findings with a dedicated parser such as PECmd.",
                }),
            )
            for index, referenced_path in enumerate(all_referenced_paths):
                yield build_prefetch_reference_record(
                    path,
                    str(referenced_path),
                    index,
                    header,
                    source_hashes,
                    source_offset=reference_offsets[index] if index < len(reference_offsets) else None,
                )


def build_prefetch_invalid_content_record(path: Path, header: Mapping[str, object], stat_result: os.stat_result) -> ArtifactRecord:
    """A ``.pf`` file whose content is not Prefetch (SCCA/valid MAM).

    Typical on acquired images where the Prefetch directory entry survives but
    its clusters were reallocated (JPEG, PE, JSON, zeros ...). The row is kept
    for provenance but carries no executable hint, run count or run time and
    is excluded from execution summaries.
    """
    try:
        with path.open("rb") as handle:
            prefix = handle.read(4096)
    except OSError:
        prefix = b""
    content = sniff_content_kind(prefix)
    decompression = header.get("prefetch_decompression") if isinstance(header.get("prefetch_decompression"), Mapping) else {}
    content_kind = str(content["kind"])
    if content_kind == "windows-prefetch-mam":
        content_kind = "mam-decompression-failed"
        content_label = "MAM 압축 해제 실패(손상)"
    else:
        content_label = CONTENT_KIND_LABELS_KO.get(content_kind, content_kind)
    source_path = resolved_path_text(path)
    return ArtifactRecord(
        provider=WindowsPrefetchProvider.name,
        artifact_type="prefetch-invalid-content",
        path=source_path,
        supported=True,
        details={
            "parser": "windows-prefetch-inventory",
            "parser_version": PARSER_VERSION,
            "artifact_type": "prefetch-invalid-content",
            "coverage_status": "invalid-content",
            "reportability": "excluded-from-execution-evidence",
            "parser_confidence": "high",
            "source_path": source_path,
            "source_format": "pf",
            "source_hashes": {"sha256": compute_sha256(path)},
            "entry_name": path.name,
            "size": stat_result.st_size,
            "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
            "prefetch_parse_status": "invalid-content",
            "binary_format_detected": False,
            "detected_content_kind": content_kind,
            "detected_content_label": content_label,
            "detected_content_basis": content["basis"],
            "content_entropy": content["entropy"],
            "content_zero_ratio": content["zero_ratio"],
            "header_hex": prefix[:16].hex(),
            "prefetch_decompression": dict(decompression),
            "execution_evidence": False,
            "risk_flags": ["prefetch-invalid-content", "signature-extension-mismatch"],
            "validation_required": True,
            "note": (
                "파일명은 Prefetch(.pf)이지만 내용이 SCCA/MAM Prefetch 구조가 아닙니다"
                f"({content_label}). 실행 근거·실행 횟수·실행 시각으로 쓰지 않으며, "
                "파일명에서 실행 파일명을 추정하지 않습니다. 클러스터 재할당 잔존물인지 MFT/USN으로 확인하십시오."
            ),
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
        blob = path.read_bytes()
    except OSError:
        return {"binary_format_detected": False}
    compression_probe = prefetch_compression_probe(blob)
    decompressed, decompression = decompress_mam_prefetch(blob)
    if decompressed:
        parse_blob = decompressed
    else:
        parse_blob = blob
    header = parse_blob[:4096]
    is_scca = len(header) >= 8 and header[4:8] == b"SCCA"
    prefetch_version = int.from_bytes(header[:4], "little") if is_scca else 0
    version_metadata = prefetch_version_metadata(prefetch_version)
    section_bounds_profile = prefetch_section_bounds_profile(
        parse_blob, version_metadata, compression_probe, decompressed=bool(decompressed)
    )
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
        "prefetch_decompression": decompression,
        "prefetch_section_bounds_profile": section_bounds_profile,
        "prefetch_validation_checks": prefetch_validation_checks(
            is_scca=is_scca,
            prefetch_version=prefetch_version,
            blob_size=len(parse_blob),
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
    hints["declared_file_size"] = read_u32(parse_blob, 0x0C)
    decoded = decode_scca_structure(parse_blob, prefetch_version)
    version_metadata = dict(version_metadata)
    if decoded["run_count_offset"] is not None:
        version_metadata["run_count_offset"] = decoded["run_count_offset"]
        version_metadata["run_count_offset_hex"] = hex(int(decoded["run_count_offset"]))
    hints["prefetch_version_metadata"] = version_metadata
    hints["run_count"] = decoded["run_count"]
    hints["run_count_offset"] = decoded["run_count_offset"]
    hints["run_count_layout_rule"] = decoded["run_count_layout_rule"]
    hints["run_count_cross_check"] = decoded["run_count_cross_check"]
    hints["file_information_layout"] = decoded["file_information_layout"]
    run_times = list(decoded["run_times"])
    hints["last_run_times"] = run_times
    hints["last_run_filetimes"] = list(decoded["run_filetimes"])
    hints["last_run_at"] = run_times[0] if run_times else ""
    for index, value in enumerate(run_times[:8], start=1):
        hints[f"run_time_{index}"] = value
    hints["header_executable_name"] = decoded["header_executable_name"]
    hints["header_executable_name_may_be_truncated"] = decoded["header_executable_name_may_be_truncated"]
    hints["header_prefetch_hash"] = decoded["header_prefetch_hash"]
    referenced_paths = list(decoded["referenced_paths"])
    hints["referenced_path_source"] = decoded["referenced_path_source"]
    hints["file_metrics_count"] = decoded["file_metrics_count"]
    hints["file_metrics_decoded_count"] = decoded["file_metrics_decoded_count"]
    hints["trace_chain_count"] = decoded["trace_chain_count"]
    hints["trace_chain_status"] = decoded["trace_chain_status"]
    # Decoded file-metrics entries in load order (path, MFT reference, flags,
    # trace-chain span, offset of the name in the decompressed SCCA stream).
    hints["referenced_files"] = [
        {
            "path": item["path"],
            **({"mft_entry": item["mft_entry"], "mft_sequence": item["mft_sequence"]} if "mft_entry" in item else {}),
            "flags": item["flags"],
            "trace_chain_count": item["trace_chain_count"],
            "source_offset": item["source_offset"],
        }
        for item in decoded["file_metrics"]
    ]
    hints["referenced_file_count"] = len(hints["referenced_files"])
    cap_list_field(hints, "referenced_files", MAX_REFERENCED_FILES)
    # The row's own record starts at the SCCA header (offset 0 of the file, or
    # of the decompressed stream for MAM files: see source_offset_space).
    hints["source_offset"] = 0
    hints["source_offset_space"] = "decompressed-scca" if decompressed else "file"
    if decoded["volumes"]:
        volume_candidates = prefetch_volume_candidates_from_table(decoded["volumes"], referenced_paths)
    else:
        volume_candidates = prefetch_volume_candidates(referenced_paths)
    hints["volumes"] = decoded["volumes"]
    hints["volume_count"] = len(decoded["volumes"])
    hints["volume_information_status"] = decoded["volume_information_status"]
    file_reference_candidates = prefetch_file_reference_candidates(referenced_paths, decoded["file_metrics"])
    # Every referenced path becomes its own ``prefetch-reference`` row (no cap);
    # only the inline list on the file row is capped and disclosed.
    hints["referenced_paths_all"] = referenced_paths
    if decoded["referenced_path_source"] == "file-metrics-filename-strings":
        hints["referenced_source_offsets_all"] = [int(item["source_offset"]) for item in decoded["file_metrics"]]
    hints["referenced_paths"] = list(referenced_paths)
    cap_list_field(hints, "referenced_paths", MAX_REFERENCED_PATHS)
    hints["referenced_path_count"] = len(referenced_paths)
    hints["volume_candidates"] = volume_candidates[:MAX_CANDIDATES]
    hints["volume_candidate_count"] = len(volume_candidates)
    hints["file_reference_candidates"] = list(file_reference_candidates)
    cap_list_field(hints, "file_reference_candidates", MAX_FILE_REFERENCE_CANDIDATES)
    hints["file_reference_candidate_count"] = len(file_reference_candidates)
    hints["prefetch_decode_coverage"] = {
        "file_information": "decoded" if decoded["run_count_offset"] is not None else "unsupported-version",
        "file_metrics": "decoded" if decoded["file_metrics_decoded_count"] else "not-decoded",
        "filename_strings": decoded["referenced_path_source"],
        "volume_information": decoded["volume_information_status"],
        "trace_chains": "counted" if decoded["trace_chain_status"] == "counted" else decoded["trace_chain_status"],
    }
    hints["prefetch_validation_checks"] = prefetch_validation_checks(
        is_scca=is_scca,
        prefetch_version=prefetch_version,
        blob_size=len(parse_blob),
        declared_file_size=int(hints["declared_file_size"]),
        run_count=int(hints["run_count"]),
        run_times=list(hints["last_run_times"]),
        referenced_paths=referenced_paths,
        volume_candidates=volume_candidates,
        compression_probe=compression_probe,
        section_bounds_profile=section_bounds_profile,
    )
    hints["prefetch_validation_checks"]["run_count_consistent_with_run_times"] = bool(
        decoded["run_count_cross_check"].get("consistent")
    )
    hints["prefetch_validation_checks"]["compressed_prefetch_decompressed"] = bool(decompressed)
    hints["prefetch_validation_checks"]["full_file_metrics_decoded"] = bool(
        decoded["file_metrics_count"] and decoded["file_metrics_decoded_count"] == decoded["file_metrics_count"]
    )
    hints["prefetch_validation_checks"]["full_volume_table_decoded"] = decoded["volume_information_status"] == "decoded"
    hints["prefetch_validation_checks"]["trace_chains_counted"] = decoded["trace_chain_status"] == "counted"
    hints["parser_confidence"] = "medium" if version_metadata["supported_common_layout"] else "low"
    return hints


# File-information layouts. Version 30/31 has two observed variants that are
# told apart by the file metrics array offset (= end of file information):
#   0x130 (file information 224 bytes): run count at 0xD0
#   0x128 / 0x12C (212/216 bytes):      run count at 0xC8
# Both keep the eight last-run FILETIMEs at 0x80.
PREFETCH_V30_RUN_COUNT_BY_METRICS_OFFSET = {0x128: 0xC8, 0x12C: 0xC8, 0x130: 0xD0}
PREFETCH_FILE_METRICS_ENTRY_SIZE = {17: 20, 23: 32, 26: 32, 30: 32, 31: 32}
PREFETCH_VOLUME_ENTRY_SIZE = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}
PREFETCH_HEADER_NAME_CHARS = 29  # 60-byte UTF-16 field: 29 characters + NUL


def decode_scca_structure(blob: bytes, version: int) -> dict[str, object]:
    layout = PREFETCH_VERSION_LAYOUTS.get(version) or {}
    metrics_offset = read_u32(blob, 0x54)
    metrics_count = read_u32(blob, 0x58)
    trace_offset = read_u32(blob, 0x5C)
    trace_count = read_u32(blob, 0x60)
    filename_offset = read_u32(blob, 0x64)
    filename_size = read_u32(blob, 0x68)
    volume_offset = read_u32(blob, 0x6C)
    volume_count = read_u32(blob, 0x70)
    volume_size = read_u32(blob, 0x74)

    raw_name = blob[0x10:0x4C].decode("utf-16le", errors="replace")
    header_name = raw_name.split("\x00", 1)[0].strip()
    result: dict[str, object] = {
        "header_executable_name": header_name,
        "header_executable_name_may_be_truncated": len(header_name) >= PREFETCH_HEADER_NAME_CHARS,
        "header_prefetch_hash": f"{read_u32(blob, 0x4C):08X}" if len(blob) >= 0x50 else "",
        "run_count": 0,
        "run_count_offset": None,
        "run_count_layout_rule": "unsupported-version",
        "run_count_cross_check": {},
        "file_information_layout": "",
        "run_times": [],
        "run_filetimes": [],
        "file_metrics": [],
        "file_metrics_count": metrics_count,
        "file_metrics_decoded_count": 0,
        "referenced_paths": [],
        "referenced_path_source": "not-decoded",
        "volumes": [],
        "volume_information_status": "not-decoded",
        "trace_chain_count": trace_count,
        "trace_chain_offset": trace_offset,
        "trace_chain_status": "not-decoded",
    }
    if not layout:
        return result
    result["trace_chain_status"] = prefetch_trace_chain_status(blob, version, trace_offset, trace_count)

    run_slots = int(layout["last_run_time_slots"])
    run_time_offset = int(layout["last_run_time_offset"])
    filetimes = [read_u64(blob, run_time_offset + index * 8) for index in range(run_slots)]
    nonzero_filetimes = [value for value in filetimes if value]
    result["run_filetimes"] = nonzero_filetimes
    result["run_times"] = [text for text in (filetime_to_iso(value) for value in nonzero_filetimes) if text]

    if version in (30, 31):
        selected = PREFETCH_V30_RUN_COUNT_BY_METRICS_OFFSET.get(metrics_offset)
        if selected is None:
            selected = 0xD0
            rule = f"v{version}-metrics-offset-0x{metrics_offset:x}-unrecognized-default-0xd0"
            info_layout = f"v{version}-unrecognized"
        else:
            rule = f"v{version}-metrics-offset-0x{metrics_offset:x}-run-count-0x{selected:x}"
            info_layout = f"v{version}-file-information-{metrics_offset - 0x54}-bytes"
        alternate = 0xC8 if selected == 0xD0 else 0xD0
    else:
        selected = int(layout["run_count_offset"])
        rule = f"v{version}-fixed-0x{selected:x}"
        info_layout = str(layout["layout_name"])
        alternate = None
    run_count = read_u32(blob, selected)
    cross_check: dict[str, object] = {
        "nonzero_run_time_count": len(nonzero_filetimes),
        "run_time_slots": run_slots,
        "selected_offset_hex": hex(selected),
        "selected_value": run_count,
    }
    consistent = run_count >= len(nonzero_filetimes) and (len(nonzero_filetimes) == run_slots or run_count == len(nonzero_filetimes))
    if alternate is not None:
        alternate_value = read_u32(blob, alternate)
        cross_check["alternate_offset_hex"] = hex(alternate)
        cross_check["alternate_value"] = alternate_value
        alternate_consistent = alternate_value >= len(nonzero_filetimes) and (
            len(nonzero_filetimes) == run_slots or alternate_value == len(nonzero_filetimes)
        )
        if not consistent and alternate_consistent and 0 < alternate_value <= MAX_REASONABLE_RUN_COUNT:
            cross_check["switched_to_alternate"] = True
            rule = f"{rule}-cross-check-switched-0x{alternate:x}"
            selected, run_count, consistent = alternate, alternate_value, True
    cross_check["consistent"] = consistent
    result.update(
        {
            "run_count": run_count,
            "run_count_offset": selected,
            "run_count_layout_rule": rule,
            "run_count_cross_check": cross_check,
            "file_information_layout": info_layout,
        }
    )

    # Filename strings, in file-metrics (load) order. Each metrics entry names
    # its string by (offset, character count) inside the filename section.
    filename_section = b""
    if filename_offset and filename_size and filename_offset + filename_size <= len(blob):
        filename_section = blob[filename_offset : filename_offset + filename_size]
    entry_size = PREFETCH_FILE_METRICS_ENTRY_SIZE.get(version, 0)
    metrics: list[dict[str, object]] = []
    if (
        filename_section
        and entry_size
        and metrics_offset
        and metrics_count
        and metrics_offset + metrics_count * entry_size <= len(blob)
    ):
        name_field = 8 if version == 17 else 12
        for index in range(metrics_count):
            base = metrics_offset + index * entry_size
            name_offset = read_u32(blob, base + name_field)
            name_chars = read_u32(blob, base + name_field + 4)
            if not name_chars or name_offset + name_chars * 2 > len(filename_section):
                continue
            entry: dict[str, object] = {
                "index": index,
                "path": filename_section[name_offset : name_offset + name_chars * 2].decode("utf-16le", errors="replace"),
                "flags": read_u32(blob, base + name_field + 8),
                "trace_chain_start": read_u32(blob, base),
                "trace_chain_count": read_u32(blob, base + 4),
                # Offset of the UTF-16 name inside the (decompressed) SCCA stream.
                "source_offset": filename_offset + name_offset,
            }
            if version != 17:
                reference = read_u64(blob, base + 24)
                if reference:
                    entry["mft_entry"] = reference & 0xFFFFFFFFFFFF
                    entry["mft_sequence"] = reference >> 48
            metrics.append(entry)
    if metrics:
        result["file_metrics"] = metrics
        result["file_metrics_decoded_count"] = len(metrics)
        result["referenced_paths"] = [str(item["path"]) for item in metrics]
        result["referenced_path_source"] = "file-metrics-filename-strings"
    elif filename_section:
        names = [item for item in filename_section.decode("utf-16le", errors="replace").split("\x00") if item]
        result["referenced_paths"] = names[:metrics_count] if metrics_count else names
        result["referenced_path_source"] = "filename-strings-section"
    else:
        strings = extract_utf16le_strings(blob[: min(len(blob), MAX_PREFETCH_SCAN_BYTES)])
        result["referenced_paths"] = referenced_prefetch_paths(strings)
        result["referenced_path_source"] = "utf16-string-scan-fallback"

    volume_entry_size = PREFETCH_VOLUME_ENTRY_SIZE.get(version, 0)
    if volume_offset and volume_count and volume_entry_size:
        section_end = volume_offset + volume_size if volume_size else len(blob)
        if volume_offset + volume_count * volume_entry_size > min(section_end, len(blob)):
            result["volume_information_status"] = "declared-out-of-bounds"
        else:
            result["volumes"] = [
                decode_prefetch_volume(blob, volume_offset, index, volume_entry_size, min(section_end, len(blob)))
                for index in range(volume_count)
            ]
            result["volume_information_status"] = "decoded"
    elif not volume_count:
        result["volume_information_status"] = "not-declared"
    return result


def prefetch_trace_chain_status(blob: bytes, version: int, offset: int, count: int) -> str:
    """Bounds check of the trace-chain array (entries are counted, not interpreted)."""
    if not count:
        return "not-declared"
    entry_size = PREFETCH_TRACE_CHAIN_ENTRY_SIZE.get(version, 0)
    if not entry_size or not offset or offset + count * entry_size > len(blob):
        return "declared-out-of-bounds"
    return "counted"


def decode_prefetch_volume(blob: bytes, section_offset: int, index: int, entry_size: int, section_end: int) -> dict[str, object]:
    base = section_offset + index * entry_size
    device_offset = read_u32(blob, base)
    device_chars = read_u32(blob, base + 4)
    created = read_u64(blob, base + 8)
    serial = read_u32(blob, base + 16)
    file_reference_offset = read_u32(blob, base + 20)
    file_reference_size = read_u32(blob, base + 24)
    directory_offset = read_u32(blob, base + 28)
    directory_count = read_u32(blob, base + 32)
    device_start = section_offset + device_offset
    device_path = ""
    if device_chars and device_start + device_chars * 2 <= section_end:
        device_path = blob[device_start : device_start + device_chars * 2].decode("utf-16le", errors="replace")
    directories: list[str] = []
    cursor = section_offset + directory_offset
    for _ in range(directory_count if directory_offset else 0):
        if cursor + 2 > section_end:
            break
        length = read_u16(blob, cursor)
        cursor += 2
        if cursor + length * 2 > section_end:
            break
        directories.append(blob[cursor : cursor + length * 2].decode("utf-16le", errors="replace"))
        cursor += (length + 1) * 2
    file_reference_count = 0
    if file_reference_offset and file_reference_size >= 8:
        file_reference_count = read_u32(blob, section_offset + file_reference_offset + 4)
    return {
        "volume_index": index,
        "volume_device_path": device_path,
        "volume_serial_number": f"{serial:08X}",
        "volume_created_at": filetime_to_iso(created),
        "volume_created_filetime": created,
        "directory_string_count": directory_count,
        "directory_strings_decoded": len(directories),
        "directory_strings": directories,
        "file_reference_count": file_reference_count,
        "source": "volume_information_section",
        "source_offset": base,
    }


def prefetch_volume_candidates_from_table(
    volumes: Sequence[Mapping[str, object]], referenced_paths: Sequence[str]
) -> list[dict[str, object]]:
    candidates = []
    for volume in volumes:
        device_path = str(volume.get("volume_device_path") or "")
        upper = device_path.upper()
        samples = [path for path in referenced_paths if upper and path.upper().startswith(upper)]
        candidates.append(
            {
                "volume_device_path": device_path,
                "volume_serial_number": volume.get("volume_serial_number", ""),
                "volume_created_at": volume.get("volume_created_at", ""),
                "source": "volume_information_section",
                "confidence": "decoded",
                "referenced_path_count": len(samples),
                "sample_referenced_paths": samples[:5],
            }
        )
    return candidates


def filetime_to_iso(value: int) -> str:
    """FILETIME (100 ns since 1601) -> ISO-8601 UTC using integer arithmetic.

    No float/fromtimestamp: pre-1970 values and sub-second precision survive
    (100 ns remainders are truncated to microseconds, the datetime limit).
    """
    if value <= 0:
        return ""
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat()
    except OverflowError:
        return ""


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def decompress_mam_prefetch(blob: bytes) -> tuple[bytes, dict[str, object]]:
    # MAM container: u32 signature ("MAM" + compression-algorithm nibble +
    # CRC flag), u32 declared uncompressed size, optional u32 CRC32, then
    # the compressed stream. Algorithm 4 (XPRESS Huffman, the Windows 8+
    # Prefetch format) is decompressed by the bounded pure-Python decoder in
    # ``xpress_huffman`` on every host; other algorithm ids are reported.
    status: dict[str, object] = {"attempted": bool(blob[:3] == b"MAM" and len(blob) >= 8)}
    if not status["attempted"]:
        status["status"] = "not-mam"
        return b"", status
    signature = int.from_bytes(blob[:4], "little")
    declared_size = int.from_bytes(blob[4:8], "little")
    algorithm_id = (signature & 0x0F000000) >> 24
    compressed = blob[8:]
    status["algorithm_id"] = algorithm_id
    status["declared_uncompressed_size"] = declared_size
    if signature & 0xF0000000 and len(compressed) >= 4:
        declared_crc = int.from_bytes(compressed[:4], "little")
        crc = binascii.crc32(blob[:8])
        crc = binascii.crc32(b"\x00\x00\x00\x00", crc)
        crc = binascii.crc32(compressed[4:], crc)
        status["crc32_ok"] = crc == declared_crc
        compressed = compressed[4:]
        if not status["crc32_ok"]:
            status["status"] = "crc-mismatch"
            return b"", status
    if algorithm_id != MAM_ALGORITHM_XPRESS_HUFFMAN:
        status["status"] = f"unsupported-algorithm-{algorithm_id}"
        return b"", status
    if not 0 < declared_size <= MAX_OUTPUT_BYTES:
        status["status"] = "declared-size-out-of-bounds"
        status["max_uncompressed_size"] = MAX_OUTPUT_BYTES
        return b"", status
    try:
        target = xpress_huffman_decompress(compressed, declared_size)
    except XpressHuffmanError as exc:
        status["status"] = "decompress-error"
        status["error"] = str(exc)
        return b"", status
    status.update(
        {
            "status": "decompressed",
            "method": "pure-python-xpress-huffman",
            "compressed_size": len(compressed),
        }
    )
    return target, status


def prefetch_compression_probe(blob: bytes) -> dict[str, object]:
    magic = blob[:4]
    detected = magic[:3] == b"MAM"
    declared_uncompressed_size = int.from_bytes(blob[4:8], "little") if detected and len(blob) >= 8 else 0
    return {
        "detected": detected,
        "format": "windows-prefetch-mam" if detected else "plain-or-unknown",
        "magic_hex": magic.hex(),
        "declared_uncompressed_size": declared_uncompressed_size,
        "decompression_status": "native-pure-python-attempt" if detected else "not-needed",
        "reportability": "native-pure-python-decompression" if detected else "normal-scca-path",
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
    decompressed: bool = False,
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
        "decompressed_for_analysis": decompressed,
        "bounds_status": "unsupported-layout",
        "section_count_declared": 0,
        "declared_sections_within_file": False,
        "sections": [],
        "decode_boundary": (
            "file metrics, filename strings and volume records are decoded natively (not corpus-validated); trace chains are counted only"
        ),
    }
    if compression_probe.get("detected") and not decompressed:
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
                "decode_status": "counted-only" if section_name == "trace_chains" else "decoded-natively",
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


@functools.lru_cache(maxsize=4096)
def resolved_path_text(path: Path) -> str:
    """``str(path.resolve())`` memoized: every reference row of a PF shares its file."""
    return str(path.resolve())


def build_prefetch_reference_record(
    path: Path,
    referenced_path: str,
    index: int,
    header: dict[str, object],
    source_hashes: dict[str, str],
    *,
    source_offset: int | None = None,
) -> ArtifactRecord:
    executable_name = str(header.get("header_executable_name") or executable_hint(path.name))
    validation_checks = header.get("prefetch_validation_checks") or {}
    report_grade = prefetch_report_grade_assessment(validation_checks)
    core_accuracy_gates = prefetch_core_accuracy_gates(
        {
            "source_path": resolved_path_text(path),
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
        path=resolved_path_text(path),
        supported=True,
        details=with_prefetch_depth_manifest({
            "parser": "windows-prefetch-reference",
            "parser_version": PARSER_VERSION,
            "artifact_type": "prefetch-reference",
            "coverage_status": "native-reference-string",
            "reportability": "triage",
            "parser_confidence": "low",
            "source_path": resolved_path_text(path),
            "source_format": "pf",
            "source_hashes": dict(source_hashes),
            "source_index": index,
            # Offset of the referenced name in the (decompressed) SCCA stream;
            # None when the path came from a string scan, not a metrics entry.
            "source_offset": source_offset,
            "source_offset_space": header.get("source_offset_space", "file"),
            "prefetch_entry_name": path.name,
            "executable_hint": executable_name,
            "prefetch_hash": prefetch_hash_hint(path.name),
            "referenced_path": referenced_path,
            "referenced_file_name": PureWindowsPath(referenced_path).name,
            "referenced_extension": PureWindowsPath(referenced_path).suffix.lower(),
            "volume_device_path": prefetch_volume_device_path(referenced_path),
            "run_count": header.get("run_count", 0),
            "last_run_at": header.get("last_run_at", ""),
            # Reference rows are not separate events: the run time lives on the
            # prefetch-file row (run_time_1..8).
            "timestamp": "",
            "timestamp_source": "none-reference-row-see-prefetch-file-run-times",
            "load_order_index": index,
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
                    "source_path": resolved_path_text(path),
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
        }, summary_only=True),
    )


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
    return paths


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


def prefetch_file_reference_candidates(
    referenced_paths: list[str], file_metrics: Sequence[Mapping[str, object]] = ()
) -> list[dict[str, object]]:
    metrics_by_index = list(file_metrics)
    candidates = []
    for index, path in enumerate(referenced_paths):
        windows_path = PureWindowsPath(path)
        candidate: dict[str, object] = {
            "candidate_index": index,
            "referenced_path": path,
            "referenced_file_name": windows_path.name,
            "referenced_extension": windows_path.suffix.lower(),
            "volume_device_path": prefetch_volume_device_path(path),
            "source": "file_metrics_entry" if metrics_by_index else "filename_string",
            "confidence": "decoded" if metrics_by_index else "candidate",
        }
        if index < len(metrics_by_index):
            metric = metrics_by_index[index]
            if "mft_entry" in metric:
                candidate["mft_entry"] = metric["mft_entry"]
                candidate["mft_sequence"] = metric["mft_sequence"]
        candidates.append(candidate)
    return candidates


def prefetch_volume_device_path(path: str) -> str:
    upper_path = path.upper()
    marker = "\\DEVICE\\HARDDISKVOLUME"
    if marker in upper_path:
        start = upper_path.index(marker)
        end = path.find("\\", start + len(marker))
        return path[start:] if end == -1 else path[start:end]
    volume_marker = "\\VOLUME{"
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
            "label": "Full file metrics, MFT references and volume tables decoded; trace chains counted within bounds",
            "passed": bool(check_map.get("full_file_metrics_decoded"))
            and bool(check_map.get("full_volume_table_decoded"))
            and bool(check_map.get("trace_chains_counted")),
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
        "next_internal_step": "Diff decoded file metrics, MFT references, volumes and run times against a PECmd known-answer cross-version corpus.",
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
            "file metrics and volume tables diffed against a trusted parser",
            "run counts and timestamps diffed against PECmd or known-answer corpus",
            "execution claim correlated with Amcache, BAM, SRUM, EventLog, MFT, or USN",
        ],
    }


def with_prefetch_depth_manifest(details: dict[str, object], *, summary_only: bool = False) -> dict[str, object]:
    details["prefetch_analyst_review_profile"] = prefetch_analyst_review_profile(details)
    manifest = prefetch_execution_depth_manifest(details)
    details["prefetch_execution_depth_manifest"] = (
        prefetch_execution_depth_manifest_summary(manifest) if summary_only else manifest
    )
    details["prefetch_execution_depth_manifest_hash"] = manifest["manifest_sha256"]
    return details


def prefetch_execution_depth_manifest_summary(manifest: Mapping[str, object]) -> dict[str, object]:
    """Counts-only view of a per-row depth manifest (§7 I12).

    Reference rows repeat their parent PF's layout, section, compression and
    reportability context; the full manifest stays on the ``prefetch-file``
    row and the reference row keeps counts, statuses, and the full
    manifest's ``manifest_sha256``.
    """
    metrics = manifest.get("referenced_file_metrics") if isinstance(manifest.get("referenced_file_metrics"), Mapping) else {}
    counters = manifest.get("execution_counters") if isinstance(manifest.get("execution_counters"), Mapping) else {}
    section = manifest.get("section_bounds") if isinstance(manifest.get("section_bounds"), Mapping) else {}
    reportability = manifest.get("reportability") if isinstance(manifest.get("reportability"), Mapping) else {}
    row_identity = manifest.get("row_identity") if isinstance(manifest.get("row_identity"), Mapping) else {}
    return {
        "manifest_version": manifest.get("manifest_version"),
        "manifest_detail": "counts-summary",
        "full_manifest_row": "prefetch-file",
        "artifact_type": manifest.get("artifact_type"),
        "entry_name": row_identity.get("entry_name", ""),
        "source_index": row_identity.get("source_index", ""),
        "row_identity_hash": manifest.get("row_identity_hash"),
        "counts": {
            "referenced_path_count": metrics.get("referenced_path_count", 0),
            "volume_candidate_count": metrics.get("volume_candidate_count", 0),
            "file_reference_candidate_count": metrics.get("file_reference_candidate_count", 0),
            "run_count": counters.get("run_count", 0),
            "last_run_time_count": counters.get("last_run_time_count", 0),
            "section_count_declared": section.get("section_count_declared", 0),
            "citation_ref_count": len(manifest.get("citation_refs") or []),
        },
        "section_bounds_status": section.get("bounds_status", ""),
        "reportability_decision": reportability.get("decision", ""),
        "manifest_sha256": manifest.get("manifest_sha256"),
    }


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
            "file_metrics_complete": bool(checks.get("full_file_metrics_decoded")),
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "interpret trace-chain entries (currently counted and bounds-checked only)",
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
    return blob[0x10:0x4C].decode("utf-16le", errors="replace").split("\x00", 1)[0].strip()


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
    return filetime_to_iso(value)


def parse_iso_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def read_u16(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 2], "little")


def read_u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little")


def read_u64(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 8], "little")
