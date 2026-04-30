from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Iterable

from ...core.audit import compute_sha256
from ...core.models import ArtifactRecord
from .common import build_forensic_review, isoformat_from_timestamp

PREFETCH_ROOT = ("Windows", "Prefetch")
PARSER_VERSION = "prefetch-inventory-v7"
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
PREFETCH_COMMERCIAL_BLOCKERS = [
    "Full file metrics array decoding and MFT file-reference extraction are not implemented.",
    "Volume information is surfaced as bounded string/path candidates, not decoded from the authoritative volume table.",
    "Trace chains, directory strings, and file information sections are not fully version-validated.",
    "Known-answer corpus validation across malformed, compressed, and cross-version Prefetch files is incomplete.",
]
PREFETCH_NATIVE_CAPABILITIES = {
    "scca_signature_validation": True,
    "common_header_version_offsets": True,
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
]


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
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": list(PREFETCH_REPORT_GRADE_BLOCKERS),
                    "commercial_readiness_blockers": list(PREFETCH_COMMERCIAL_BLOCKERS),
                    "prefetch_validation_matrix": prefetch_validation_matrix(validation_checks),
                    "prefetch_report_grade_assessment": report_grade,
                    "prefetch_native_capabilities": dict(PREFETCH_NATIVE_CAPABILITIES),
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
    version_metadata = prefetch_version_metadata(prefetch_version)
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
        "prefetch_validation_checks": prefetch_validation_checks(
            is_scca=is_scca,
            prefetch_version=prefetch_version,
            blob_size=len(blob),
            declared_file_size=0,
            run_count=0,
            run_times=[],
            referenced_paths=[],
            volume_candidates=[],
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
    )
    hints["parser_confidence"] = "medium" if version_metadata["supported_common_layout"] else "low"
    return hints


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
    }


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
            "commercial_grade_ready": False,
            "commercial_grade_blockers": list(PREFETCH_REPORT_GRADE_BLOCKERS),
            "commercial_readiness_blockers": list(PREFETCH_COMMERCIAL_BLOCKERS),
            "prefetch_validation_matrix": prefetch_validation_matrix(validation_checks),
            "prefetch_report_grade_assessment": report_grade,
            "prefetch_native_capabilities": dict(PREFETCH_NATIVE_CAPABILITIES),
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
        },
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
) -> dict[str, object]:
    now = datetime.now(tz=timezone.utc)
    parsed_run_times = [parse_iso_datetime(item) for item in run_times]
    valid_run_times = [item for item in parsed_run_times if item is not None]
    file_size_matches_declared = None
    if declared_file_size > 0:
        file_size_matches_declared = declared_file_size == blob_size
    return {
        "has_scca_signature": is_scca,
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
