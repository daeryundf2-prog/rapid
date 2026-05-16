from __future__ import annotations

import codecs
import csv
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review, iter_windows_user_homes
from .ese import ESE_SCAN_READ_SIZE, build_ese_string_pivots, probe_ese_database
from .os_account import decode_reg_export
from .srum_ese import analyze_srudb_native

PARSER_VERSION = "windows-execution-v11"
REGISTRY_EXPORT_EXT = ".reg"
SRUM_IMPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
AMCACHE_HIVE_NAME = "AMCACHE.HVE"
SYSTEM_HIVE_NAME = "SYSTEM"
MAX_NATIVE_AMCACHE_SCAN_BYTES = 8 * 1024 * 1024
AMCACHE_ROW_CLUSTER_WINDOW_BYTES = 4096
MAX_NATIVE_SHIMCACHE_SCAN_BYTES = 8 * 1024 * 1024
SHIMCACHE_ROW_CLUSTER_WINDOW_BYTES = 4096
MAX_NATIVE_BAM_DAM_SCAN_BYTES = 8 * 1024 * 1024
BAM_DAM_ROW_CLUSTER_WINDOW_BYTES = 4096
POWERSHELL_HISTORY = ("AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")

EXECUTION_KEYWORDS = {
    "amcache": ("Amcache", "InventoryApplicationFile", "InventoryApplication", "Root\\File"),
    "shimcache": ("AppCompatCache", "AppCompatFlags\\Compatibility Assistant\\Store"),
    "userassist": ("UserAssist",),
    "bam": ("Services\\bam\\State\\UserSettings", "Services\\dam\\State\\UserSettings"),
}
SUSPICIOUS_COMMAND_TERMS = (
    "powershell -enc",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "rundll32",
    "regsvr32",
    "wmic",
    "certutil",
    "bitsadmin",
    "schtasks",
    "vssadmin delete shadows",
)
EXECUTION_NATIVE_CAPABILITIES = {
    "amcache_export_mapping": True,
    "amcache_native_string_pivots": True,
    "shimcache_export_mapping": True,
    "shimcache_native_string_pivots": True,
    "bam_export_mapping": True,
    "bam_native_string_pivots": True,
    "srum_export_mapping": True,
    "srum_ese_header_probe": True,
    "srum_native_string_pivots": True,
    "srum_table_marker_candidates": True,
    "srum_row_string_candidates": True,
    "native_amcache_schema_decode": False,
    "native_shimcache_binary_decode": False,
    "native_bam_system_hive_decode": False,
    "native_ese_catalog_decode": False,
    "native_srum_page_row_decode": False,
}
EXECUTION_REPORT_GRADE_BLOCKERS = [
    "execution-artifact-trusted-diff-required",
    "native-amcache-schema-decoding-required",
    "native-appcompatcache-layout-decoding-required",
    "native-system-hive-bam-decoding-required",
    "native-ese-catalog-decoding-required",
    "native-ese-page-row-decoding-required",
    "known-answer-execution-artifact-validation-required",
]
EXECUTION_TRUSTED_TOOL_HINTS = ("amcacheparser", "appcompatcacheparser", "shimcacheparser", "srumecmd", "recmd", "velociraptor")
EXECUTION_DIFF_COMPARE_FIELDS = (
    "executable_path",
    "device_path",
    "timestamp",
    "timestamp_source",
    "sha1",
    "user_sid",
    "user",
    "table_family",
    "url",
    "network_profile",
    "interface_luid",
    "bytes_sent",
    "bytes_received",
    "energy_usage",
    "cpu_time",
    "program_name",
    "publisher",
    "file_description",
    "product_name",
    "source_format",
    "source_key",
    "source_offset",
    "cache_order",
    "os_build",
    "counter_sha256",
    "semantics_warning",
)
EXECUTION_DIFF_REQUIRED_FIELDS_BY_FAMILY = {
    "amcache": ("executable_path", "sha1", "semantics_warning"),
    "shimcache-appcompatcache": ("executable_path", "cache_order", "semantics_warning"),
    "bam-dam": ("executable_path", "user_sid", "timestamp", "semantics_warning"),
    "srum": ("executable_path", "timestamp", "table_family"),
}
QC_PREP_EXECUTION_ITEM_NUMBERS = {
    "amcache-entry": 22,
    "amcache-hive": 22,
    "shimcache-entry": 23,
    "bam-entry": 24,
    "srum-network-usage": 25,
    "srum-app-resource-usage": 25,
    "srum-database-file": 25,
    "srum-database-pivot": 25,
    "srum-table-candidate": 25,
    "srum-row-candidate": 25,
}
EXECUTION_ANALYST_REVIEW_CATALOG = {
    "amcache-entry": {
        "severity": "medium",
        "summary": "Amcache program inventory/execution-related pivot; useful for path/hash/install context but not standalone execution proof.",
        "evidence_interpretation": "program presence, install, and execution-related metadata depending on schema/version",
        "not_proof_of": ["standalone execution", "precise last-run time without schema validation"],
        "primary_pivots": ["executable_path", "sha1", "sha1_candidates", "program_name", "publisher", "timestamp"],
        "correlation_targets": ["Prefetch", "BAM/DAM", "SRUM", "ShimCache", "MFT/USN", "EventLog 4688/Sysmon 1"],
        "analyst_questions": [
            "Does a trusted Amcache parser confirm the same row and schema version?",
            "Do Prefetch/BAM/SRUM/EventLog/MFT corroborate actual execution?",
            "Is the path/hash suspicious or located in a user-writable directory?",
        ],
        "risk_tags": ["program-inventory", "execution-related-pivot"],
    },
    "amcache-hive": {
        "severity": "medium",
        "summary": "Native Amcache.hve inventory; bounded string pivots expose candidate paths/hashes until schema decoding is validated.",
        "evidence_interpretation": "candidate Amcache paths and hashes from bounded native hive scan",
        "not_proof_of": ["decoded row semantics", "execution timestamp"],
        "primary_pivots": ["path_candidates", "sha1_candidates", "amcache_candidate_cluster_count"],
        "correlation_targets": ["AmcacheParser", "RECmd", "Prefetch", "BAM/DAM", "SRUM", "MFT/USN"],
        "analyst_questions": [
            "Which candidate path/hash needs row-level Amcache validation?",
            "Does a trusted parser decode the same inventory row?",
            "Are suspicious paths corroborated by filesystem and execution artifacts?",
        ],
        "risk_tags": ["native-string-pivot", "schema-validation-required"],
    },
    "shimcache-entry": {
        "severity": "medium",
        "summary": "ShimCache/AppCompatCache presence/order pivot; never treat it as standalone proof of execution.",
        "evidence_interpretation": "program presence/cache order with OS-build-dependent timestamp semantics",
        "not_proof_of": ["program execution", "exact run time"],
        "primary_pivots": ["executable_path", "cache_order", "timestamp", "source_offset"],
        "correlation_targets": ["Amcache", "Prefetch", "BAM/DAM", "MFT/USN", "EventLog 4688/Sysmon 1"],
        "analyst_questions": [
            "What OS build/layout applies to this AppCompatCache record?",
            "Does another execution artifact corroborate the executable actually ran?",
            "Is the cache order/path suspicious or user-writable?",
        ],
        "risk_tags": ["presence-pivot", "not-execution-proof"],
    },
    "bam-entry": {
        "severity": "high",
        "summary": "BAM/DAM recent-execution pivot; strong when SID, device path, and FILETIME are validated.",
        "evidence_interpretation": "recent execution indicator candidate tied to user SID and device path",
        "not_proof_of": ["complete execution timeline without correlation", "decoded binary FILETIME unless validated"],
        "primary_pivots": ["executable_path", "device_path", "user_sid", "timestamp", "source_key"],
        "correlation_targets": ["Prefetch", "SRUM", "UserAssist", "EventLog 4688/Sysmon 1", "MFT/USN"],
        "analyst_questions": [
            "Does the SID map to the expected account?",
            "Can Prefetch/SRUM/UserAssist/EventLog corroborate execution?",
            "Was the device path normalized to a filesystem path?",
        ],
        "risk_tags": ["recent-execution-pivot", "correlation-required"],
    },
    "srum-network-usage": {
        "severity": "medium",
        "summary": "SRUM network/resource usage export; pivot by application, user, timestamp, counters, and network profile.",
        "evidence_interpretation": "application resource/network usage from source-tool export",
        "not_proof_of": ["full process lineage", "payload content"],
        "primary_pivots": ["app_id", "user", "timestamp", "bytes_total", "network_profile"],
        "correlation_targets": ["Process execution", "DNS", "Browser history", "Firewall", "MFT/USN", "SRUDB.dat"],
        "analyst_questions": [
            "Which application generated network/resource counters?",
            "Do process, DNS, browser, or firewall artifacts explain the network usage?",
            "Does source-tool provenance confirm table and timestamp semantics?",
        ],
        "risk_tags": ["resource-usage", "network-usage"],
    },
    "srum-database-file": {
        "severity": "medium",
        "summary": "Native SRUDB.dat inventory; ESE header/string pivots need dedicated SRUM row decoding for report-grade usage.",
        "evidence_interpretation": "SRUM database presence plus table/string/row candidates",
        "not_proof_of": ["decoded SRUM row facts", "validated counters or timestamps"],
        "primary_pivots": ["native_srum_table_candidate_count", "native_srum_row_candidate_count", "path_candidates", "url_candidates"],
        "correlation_targets": ["SrumECmd", "libesedb", "Process execution", "Network artifacts", "MFT/USN"],
        "analyst_questions": [
            "Does a dedicated SRUM parser decode the same rows?",
            "Which candidate app/URL/table should be validated first?",
            "Are database page size and file alignment plausible?",
        ],
        "risk_tags": ["ese-database", "native-row-validation-required"],
    },
    "srum-database-pivot": {
        "severity": "info",
        "summary": "SRUDB native string pivot; useful for search/correlation but not decoded row semantics.",
        "evidence_interpretation": "app/path/URL string presence inside SRUDB.dat",
        "not_proof_of": ["usage timestamp", "counter value", "row ownership"],
        "primary_pivots": ["candidate_kind", "candidate_value", "app_id", "url"],
        "correlation_targets": ["SrumECmd", "Browser history", "DNS", "MFT/USN", "EventLog"],
        "analyst_questions": [
            "Which decoded SRUM row contains this string?",
            "Does the app/URL appear in browser, DNS, or filesystem artifacts?",
            "Is the string only a schema/resource marker or actual usage data?",
        ],
        "risk_tags": ["string-pivot", "validation-required"],
    },
    "srum-table-candidate": {
        "severity": "info",
        "summary": "SRUDB table-family candidate from native markers; validate catalog and row decoding before reporting.",
        "evidence_interpretation": "bounded native marker cluster that suggests a SRUM table family",
        "not_proof_of": ["decoded table catalog", "decoded row facts"],
        "primary_pivots": ["table_family", "matched_marker_count", "source_offset"],
        "correlation_targets": ["SrumECmd", "libesedb", "SRUDB.dat row candidates"],
        "analyst_questions": [
            "Does a dedicated ESE/SRUM parser confirm this table family?",
            "Do decoded rows exist for this marker cluster?",
            "Are marker offsets plausible within ESE page boundaries?",
        ],
        "risk_tags": ["table-candidate", "validation-required"],
    },
    "srum-row-candidate": {
        "severity": "medium",
        "summary": "SRUM row candidate clustered from nearby strings; validate ESE row decoding before reporting facts.",
        "evidence_interpretation": "bounded native string cluster that resembles a SRUM usage row",
        "not_proof_of": ["decoded row fact", "final counter/timestamp semantics"],
        "primary_pivots": ["app_id", "timestamp", "table_family", "bytes_received", "bytes_sent", "source_offset"],
        "correlation_targets": ["SrumECmd", "libesedb", "Process execution", "Network artifacts", "MFT/USN"],
        "analyst_questions": [
            "Can a trusted SRUM parser confirm table, row, counters, and timestamp?",
            "Do process/network artifacts corroborate the app and usage window?",
            "Is this cluster a false positive from nearby strings?",
        ],
        "risk_tags": ["row-candidate", "validation-required"],
    },
}


class WindowsExecutionProvider:
    name = "windows-execution"
    collector_kind = "windows-execution"
    description = "Windows execution artifacts from registry exports and PowerShell history"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records = [
            *collect_execution_reg_exports(root),
            *collect_native_amcache_hives(root),
            *collect_native_shimcache_system_hives(root),
            *collect_native_bam_dam_system_hives(root),
            *collect_powershell_history(root),
            *collect_srum_imports(root),
            *collect_srum_dat_inventory(root),
        ]
        yield from records
        summary = build_execution_summary(root, records)
        if summary is not None:
            yield summary


def collect_execution_reg_exports(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob(f"*{REGISTRY_EXPORT_EXT}"), key=lambda item: str(item).lower()):
        try:
            text = decode_reg_export(path.read_bytes())
        except OSError:
            continue
        if not any(token.lower() in text.lower() for tokens in EXECUTION_KEYWORDS.values() for token in tokens):
            continue
        yield from parse_execution_reg_export(path, text)


def parse_execution_reg_export(path: Path, text: str) -> Iterable[ArtifactRecord]:
    current_key = ""
    values: dict[str, str] = {}
    for line in [*text.splitlines(), ""]:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if current_key:
                record = build_execution_registry_record(path, current_key, values)
                if record is not None:
                    yield record
            current_key = stripped.strip("[]")
            values = {}
            continue
        name, value = parse_reg_value(stripped)
        if current_key and name:
            values[name] = value
    if current_key:
        record = build_execution_registry_record(path, current_key, values)
        if record is not None:
            yield record


def build_execution_registry_record(path: Path, key: str, values: Mapping[str, str]) -> ArtifactRecord | None:
    lowered_key = key.lower()
    artifact_type = ""
    parser = "windows-execution-reg-export"
    evidence_strength = "execution-indicator"
    decoded_values = {decode_userassist_name(name) if "userassist" in lowered_key else name: value for name, value in values.items()}

    if any(token.lower() in lowered_key for token in EXECUTION_KEYWORDS["amcache"]):
        artifact_type = "amcache-entry"
        evidence_strength = "program-presence-or-execution"
    elif any(token.lower() in lowered_key for token in EXECUTION_KEYWORDS["shimcache"]):
        artifact_type = "shimcache-entry"
        evidence_strength = "program-presence-not-proof-of-execution"
    elif "userassist" in lowered_key:
        artifact_type = "userassist-entry"
        evidence_strength = "user-execution-indicator"
    elif any(token.lower() in lowered_key for token in EXECUTION_KEYWORDS["bam"]):
        artifact_type = "bam-entry"
        evidence_strength = "execution-indicator"
    else:
        return None

    executable_path = extract_executable_path(key, decoded_values)
    timestamp, timestamp_source = extract_execution_timestamp(artifact_type, decoded_values)
    user_sid = user_sid_from_key(key)
    execution_metadata = execution_artifact_metadata(artifact_type, key, decoded_values)
    execution_fields = extract_execution_fields(artifact_type, key, decoded_values)
    if not executable_path and execution_fields.get("executable_path"):
        executable_path = str(execution_fields.get("executable_path") or "")
    risk_flags = execution_risk_flags(artifact_type, executable_path, decoded_values)
    validation_checks = execution_validation_checks(artifact_type, executable_path, timestamp, decoded_values)
    report_grade = execution_report_grade_assessment(
        execution_validation_matrix(validation_checks),
        validation_required=bool(execution_metadata.get("validation_required", artifact_type == "shimcache-entry")),
        gap_ids=execution_gap_ids(artifact_type),
        extra_blockers=[str(item) for item in execution_metadata.get("commercial_grade_blockers", [])],
    )
    source_hashes = file_hashes(path)
    amcache_schema_version = {}
    amcache_manifest = {}
    if artifact_type == "amcache-entry":
        amcache_schema_version = amcache_schema_version_profile(
            source_format="reg",
            source_key=key,
            executable_path=executable_path,
            execution_fields=execution_fields,
            timestamp_source=timestamp_source,
            decoded_values=decoded_values,
            row_cluster_evidence={},
        )
        amcache_manifest = amcache_row_manifest(
            source_path=str(path.resolve()),
            source_hashes=source_hashes,
            source_format="reg",
            source_key=key,
            source_index=0,
            executable_path=executable_path,
            sha1_candidates=[str(execution_fields.get("sha1") or "")],
            timestamp=timestamp,
            timestamp_source=timestamp_source,
            source_offset=0,
            row_cluster_evidence={},
            schema_version_profile=amcache_schema_version,
            report_grade=report_grade,
        )
    core_accuracy_gates = execution_core_accuracy_gates(
        artifact_type,
        {
            "source_path": str(path.resolve()),
            "source_hashes": source_hashes,
            "source_key": key,
            "source_index": 0,
            "source_format": "reg",
            "executable_path": executable_path,
            "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
            "user_sid": user_sid,
            "timestamp": timestamp,
            "timestamp_source": timestamp_source,
            "program_name": execution_fields.get("program_name", ""),
            "publisher": execution_fields.get("publisher", ""),
            "sha1": execution_fields.get("sha1", ""),
            "amcache_row_manifest_hash": amcache_manifest.get("manifest_sha256", ""),
            "validation_checks": validation_checks,
            "decoded_values": decoded_values,
        },
    )
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": parser,
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "source_hashes": source_hashes,
            "key": key,
            "hive_hint": key.split("\\", 1)[0],
            "executable_path": executable_path,
            "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
            "user_sid": user_sid,
            "timestamp": timestamp,
            "timestamp_source": timestamp_source or (execution_metadata.get("timestamp_source", "registry_value") if timestamp else ""),
            "program_name": execution_fields.get("program_name", ""),
            "publisher": execution_fields.get("publisher", ""),
            "sha1": execution_fields.get("sha1", ""),
            "file_description": execution_fields.get("file_description", ""),
            "product_name": execution_fields.get("product_name", ""),
            "amcache_evidence": amcache_entry_evidence(
                source_format="reg",
                source_key=key,
                executable_path=executable_path,
                execution_fields=execution_fields,
                timestamp=timestamp,
                timestamp_source=timestamp_source,
                decoded_values=decoded_values,
            ) if artifact_type == "amcache-entry" else {},
            "amcache_schema_profile": amcache_schema_profile(
                source_format="reg",
                timestamp_source=timestamp_source,
                validation_checks=validation_checks,
                report_grade=report_grade,
                executable_path=executable_path,
                sha1=str(execution_fields.get("sha1") or ""),
            ) if artifact_type == "amcache-entry" else {},
            "amcache_schema_version_profile": amcache_schema_version,
            "amcache_row_manifest": amcache_manifest,
            "amcache_row_manifest_hash": amcache_manifest.get("manifest_sha256", ""),
            "amcache_report_citation_manifest": amcache_report_citation_manifest(
                source_path=str(path.resolve()),
                source_hashes=source_hashes,
                source_format="reg",
                source_key=key,
                source_index=0,
                executable_path=executable_path,
                sha1_candidates=[str(execution_fields.get("sha1") or "")],
                timestamp=timestamp,
                timestamp_source=timestamp_source,
                source_offset=0,
                row_cluster_evidence={},
                report_grade=report_grade,
            ) if artifact_type == "amcache-entry" else {},
            "shimcache_evidence": shimcache_entry_evidence(
                key=key,
                executable_path=executable_path,
                timestamp=timestamp,
                timestamp_source=timestamp_source,
                decoded_values=decoded_values,
            ) if artifact_type == "shimcache-entry" else {},
            "shimcache_execution_caveat_profile": shimcache_execution_caveat_profile(
                validation_checks=validation_checks,
                report_grade=report_grade,
                executable_path=executable_path,
                timestamp=timestamp,
            ) if artifact_type == "shimcache-entry" else {},
            "shimcache_report_citation_manifest": shimcache_report_citation_manifest(
                source_path=str(path.resolve()),
                source_hashes=file_hashes(path),
                source_format="reg",
                source_key=key,
                source_index=0,
                executable_path=executable_path,
                timestamp=timestamp,
                timestamp_source=timestamp_source,
                source_offset=0,
                cache_order=None,
                row_cluster_evidence={},
                report_grade=report_grade,
            ) if artifact_type == "shimcache-entry" else {},
            "bam_dam_evidence": bam_dam_entry_evidence(
                key=key,
                executable_path=executable_path,
                user_sid=user_sid,
                timestamp=timestamp,
                timestamp_source=timestamp_source,
                decoded_values=decoded_values,
            ) if artifact_type == "bam-entry" else {},
            "bam_dam_decode_profile": bam_dam_decode_profile(
                validation_checks=validation_checks,
                report_grade=report_grade,
                executable_path=executable_path,
                user_sid=user_sid,
                timestamp=timestamp,
                timestamp_source=timestamp_source,
            ) if artifact_type == "bam-entry" else {},
            "bam_dam_report_citation_manifest": bam_dam_report_citation_manifest(
                source_path=str(path.resolve()),
                source_hashes=file_hashes(path),
                source_format="reg",
                source_key=key,
                source_index=0,
                executable_path=executable_path,
                user_sid=user_sid,
                timestamp=timestamp,
                timestamp_source=timestamp_source,
                source_offset=0,
                row_cluster_evidence={},
                report_grade=report_grade,
            ) if artifact_type == "bam-entry" else {},
            "evidence_strength": evidence_strength,
            "parser_confidence": execution_metadata.get("parser_confidence", 0.76),
            "validation_required": execution_metadata.get("validation_required", artifact_type == "shimcache-entry"),
            "validation_guidance": execution_metadata.get("validation_guidance", ""),
            "validation_checks": validation_checks,
            "execution_validation_matrix": execution_validation_matrix(validation_checks),
            "execution_report_grade_assessment": report_grade,
            "core_accuracy_gates": core_accuracy_gates,
            "commercial_uplift_evidence": execution_commercial_uplift_evidence(
                artifact_type,
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "source_key": key,
                    "source_index": 0,
                    "source_format": "reg",
                    "amcache_row_manifest_hash": amcache_manifest.get("manifest_sha256", ""),
                    "execution_validation_matrix": execution_validation_matrix(validation_checks),
                    "execution_report_grade_assessment": report_grade,
                },
            ),
            "execution_analyst_review_profile": execution_analyst_review_profile(
                artifact_type=artifact_type,
                source_format="reg",
                validation_checks=validation_checks,
                report_grade=report_grade,
                risk_flags=risk_flags,
                evidence_fields={
                    "executable_path": executable_path,
                    "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
                    "user_sid": user_sid,
                    "timestamp": timestamp,
                    "program_name": execution_fields.get("program_name", ""),
                    "publisher": execution_fields.get("publisher", ""),
                    "sha1": execution_fields.get("sha1", ""),
                    "source_key": key,
                    "decoded_values": decoded_values,
                },
            ),
            "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
            "forensic_review": build_forensic_review(
                gap_id=execution_gap_ids(artifact_type)[0] if execution_gap_ids(artifact_type) else "#7",
                artifact_goal=execution_review_goal(artifact_type),
                primary_evidence=[
                    f"path={executable_path}" if executable_path else "",
                    f"timestamp={timestamp}" if timestamp else "",
                    f"user_sid={user_sid}" if user_sid else "",
                    f"hash={execution_fields.get('sha1', '')}" if execution_fields.get("sha1") else "",
                ],
                validation_required=bool(execution_metadata.get("validation_required", artifact_type == "shimcache-entry")),
                report_grade_assessment=report_grade,
                commercial_grade_ready=bool(execution_metadata.get("commercial_grade_ready", False)),
                caveats=[str(execution_metadata.get("execution_caveat") or "")],
            ),
            "commercial_grade_ready": execution_metadata.get("commercial_grade_ready", False),
            "commercial_grade_blockers": report_grade["blockers"],
            "artifact_family": execution_metadata.get("artifact_family", ""),
            "execution_caveat": execution_metadata.get("execution_caveat", ""),
            "values": dict(sorted(decoded_values.items())),
            "risk_flags": risk_flags,
            "risk_score": min(100, len(risk_flags) * 25),
            "raw_preview": f"[{key}]",
        },
    )


def collect_native_amcache_hives(root: Path) -> Iterable[ArtifactRecord]:
    seen: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.name.upper() != AMCACHE_HIVE_NAME:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield from build_native_amcache_records(path)


def collect_native_shimcache_system_hives(root: Path) -> Iterable[ArtifactRecord]:
    seen: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.name.upper() != SYSTEM_HIVE_NAME:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield from build_native_shimcache_records(path)


def build_native_shimcache_records(path: Path) -> Iterable[ArtifactRecord]:
    try:
        stat_result = path.stat()
        with path.open("rb") as handle:
            blob = handle.read(min(stat_result.st_size, MAX_NATIVE_SHIMCACHE_SCAN_BYTES))
    except OSError:
        return

    source_hashes = file_hashes(path)
    occurrences = list(iter_registry_like_string_occurrences(blob))
    strings = list(unique_preserve_order(item["text"] for item in occurrences))
    appcompat_markers = [
        item
        for item in occurrences
        if "appcompatcache" in str(item.get("text") or "").lower()
        or "appcompatflags" in str(item.get("text") or "").lower()
    ]
    clusters = collect_shimcache_candidate_clusters(occurrences)
    if not clusters and not appcompat_markers:
        return
    validation_checks = {
        "has_executable_path": any(cluster.get("executable_path") for cluster in clusters),
        "has_native_binary_path_candidates": bool(clusters),
        "has_source_offsets": any(cluster.get("source_offset") is not None for cluster in clusters),
        "has_cache_order": bool(clusters),
        "has_timestamp_candidate": any(cluster.get("timestamp_candidates") for cluster in clusters),
        "requires_correlation": True,
        "requires_second_parser_validation": True,
        "native_binary_layout_decoding_available": False,
        "correlation_targets": execution_correlation_targets("shimcache-entry"),
    }
    report_grade = execution_report_grade_assessment(
        execution_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#8"],
        extra_blockers=["native-appcompatcache-layout-decoding-required", "os-build-layout-validation-required"],
    )
    for index, cluster in enumerate(clusters[:100]):
        executable_path = str(cluster.get("executable_path") or "")
        timestamp_candidates = [
            str(value) for value in cluster.get("timestamp_candidates", []) if str(value)
        ] if isinstance(cluster.get("timestamp_candidates"), list) else []
        timestamp = timestamp_candidates[0] if timestamp_candidates else ""
        row_checks = {
            **validation_checks,
            "has_executable_path": bool(executable_path),
            "has_source_offset": cluster.get("source_offset") is not None,
            "has_timestamp_candidate": bool(timestamp),
            "has_nearby_metadata_candidates": bool(cluster.get("nearby_metadata_candidates")),
        }
        row_report_grade = execution_report_grade_assessment(
            execution_validation_matrix(row_checks),
            validation_required=True,
            gap_ids=["#8"],
            extra_blockers=["native-appcompatcache-layout-decoding-required", "os-build-layout-validation-required"],
        )
        core_accuracy_gates = execution_core_accuracy_gates(
            "shimcache-entry",
            {
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "source_format": "system-hive-native-shimcache-scan",
                "executable_path": executable_path,
                "timestamp": timestamp,
                "source_offset": cluster.get("source_offset"),
                "cache_order": cluster.get("cache_order"),
                "validation_checks": row_checks,
            },
        )
        row_cluster_evidence = shimcache_row_cluster_evidence(cluster)
        citation_manifest = shimcache_report_citation_manifest(
            source_path=str(path.resolve()),
            source_hashes=source_hashes,
            source_format="system-hive-native-shimcache-scan",
            source_key="SYSTEM\\ControlSet*\\Control\\Session Manager\\AppCompatCache",
            source_index=index,
            executable_path=executable_path,
            timestamp=timestamp,
            timestamp_source="native-shimcache-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
            source_offset=int(cluster.get("source_offset") or 0),
            cache_order=int(cluster.get("cache_order") or index),
            row_cluster_evidence=row_cluster_evidence,
            report_grade=row_report_grade,
        )
        yield ArtifactRecord(
            provider=WindowsExecutionProvider.name,
            artifact_type="shimcache-entry",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-shimcache-native-system-hive-scan",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-system-hive-string-pivot",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "system-hive-native-shimcache-scan",
                "source_hashes": source_hashes,
                "source_key": "SYSTEM\\ControlSet*\\Control\\Session Manager\\AppCompatCache",
                "source_index": index,
                "source_offset": cluster.get("source_offset", 0),
                "source_encoding": cluster.get("source_encoding", ""),
                "cache_order": cluster.get("cache_order", index),
                "executable_path": executable_path,
                "timestamp": timestamp,
                "timestamp_source": "native-shimcache-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
                "nearby_metadata_candidates": cluster.get("nearby_metadata_candidates", []),
                "shimcache_evidence": shimcache_entry_evidence(
                    key="SYSTEM\\ControlSet*\\Control\\Session Manager\\AppCompatCache",
                    executable_path=executable_path,
                    timestamp=timestamp,
                    timestamp_source="native-shimcache-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
                    decoded_values={},
                    source_format="system-hive-native-shimcache-scan",
                    source_offset=int(cluster.get("source_offset") or 0),
                    cache_order=int(cluster.get("cache_order") or index),
                    nearby_metadata_candidates=[
                        str(value) for value in cluster.get("nearby_metadata_candidates", [])
                    ] if isinstance(cluster.get("nearby_metadata_candidates"), list) else [],
                ),
                "shimcache_execution_caveat_profile": shimcache_execution_caveat_profile(
                    validation_checks=row_checks,
                    report_grade=row_report_grade,
                    executable_path=executable_path,
                    timestamp=timestamp,
                    source_format="system-hive-native-shimcache-scan",
                ),
                "shimcache_report_citation_manifest": citation_manifest,
                "shimcache_report_citation_manifest_hash": citation_manifest["manifest_sha256"],
                "evidence_strength": "program-presence-not-proof-of-execution",
                "parser_confidence": float(cluster.get("parser_confidence") or 0.52),
                "validation_required": True,
                "validation_checks": row_checks,
                "execution_validation_matrix": execution_validation_matrix(row_checks),
                "execution_report_grade_assessment": row_report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "commercial_uplift_evidence": execution_commercial_uplift_evidence(
                    "shimcache-entry",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": source_hashes,
                        "source_index": index,
                        "source_format": "system-hive-native-shimcache-scan",
                        "execution_validation_matrix": execution_validation_matrix(row_checks),
                        "execution_report_grade_assessment": row_report_grade,
                    },
                ),
                "execution_analyst_review_profile": execution_analyst_review_profile(
                    artifact_type="shimcache-entry",
                    source_format="system-hive-native-shimcache-scan",
                    validation_checks=row_checks,
                    report_grade=row_report_grade,
                    risk_flags=execution_risk_flags("shimcache-entry", executable_path, {}),
                    evidence_fields={
                        "executable_path": executable_path,
                        "cache_order": cluster.get("cache_order", index),
                        "timestamp": timestamp,
                        "source_offset": cluster.get("source_offset", 0),
                        "nearby_metadata_candidates": cluster.get("nearby_metadata_candidates", []),
                    },
                ),
                "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
                "execution_caveat": "Presence in ShimCache is not proof the executable ran.",
                "validation_guidance": "Native SYSTEM hive scan preserves ShimCache/AppCompatCache path/order pivots only; validate OS build layout and trusted parser parity before report-grade use.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": row_report_grade["blockers"],
                "risk_flags": execution_risk_flags("shimcache-entry", executable_path, {}),
                "risk_score": min(100, len(execution_path_risk_flags(executable_path)) * 25 + 10),
                "raw_preview": executable_path,
            },
        )


def collect_native_bam_dam_system_hives(root: Path) -> Iterable[ArtifactRecord]:
    seen: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.name.upper() != SYSTEM_HIVE_NAME:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield from build_native_bam_dam_records(path)


def build_native_bam_dam_records(path: Path) -> Iterable[ArtifactRecord]:
    try:
        stat_result = path.stat()
        with path.open("rb") as handle:
            blob = handle.read(min(stat_result.st_size, MAX_NATIVE_BAM_DAM_SCAN_BYTES))
    except OSError:
        return

    source_hashes = file_hashes(path)
    occurrences = list(iter_registry_like_string_occurrences(blob))
    markers = [
        item
        for item in occurrences
        if "\\services\\bam\\" in str(item.get("text") or "").lower()
        or "\\services\\dam\\" in str(item.get("text") or "").lower()
    ]
    clusters = collect_bam_dam_candidate_clusters(occurrences)
    if not clusters and not markers:
        return

    for index, cluster in enumerate(clusters[:100]):
        executable_path = str(cluster.get("executable_path") or "")
        timestamp_candidates = [
            str(value) for value in cluster.get("timestamp_candidates", []) if str(value)
        ] if isinstance(cluster.get("timestamp_candidates"), list) else []
        timestamp = timestamp_candidates[0] if timestamp_candidates else ""
        user_sid = str(cluster.get("user_sid") or "")
        source_key = str(cluster.get("source_key") or "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings")
        row_checks = {
            "has_executable_path": bool(executable_path),
            "has_user_or_sid": bool(user_sid),
            "has_user": bool(user_sid),
            "has_timestamp": bool(timestamp),
            "has_source_offset": cluster.get("source_offset") is not None,
            "has_nearby_metadata_candidates": bool(cluster.get("nearby_metadata_candidates")),
            "requires_correlation": True,
            "native_binary_layout_decoding_available": False,
            "correlation_targets": execution_correlation_targets("bam-entry"),
        }
        row_report_grade = execution_report_grade_assessment(
            execution_validation_matrix(row_checks),
            validation_required=True,
            gap_ids=["#9"],
            extra_blockers=["native-system-hive-bam-decoding-required", "bam-dam-filetime-row-validation-required"],
        )
        core_accuracy_gates = execution_core_accuracy_gates(
            "bam-entry",
            {
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "source_format": "system-hive-native-bam-dam-scan",
                "source_key": source_key,
                "executable_path": executable_path,
                "device_path": executable_path,
                "user_sid": user_sid,
                "timestamp": timestamp,
                "validation_checks": row_checks,
            },
        )
        row_cluster_evidence = bam_dam_row_cluster_evidence(cluster)
        citation_manifest = bam_dam_report_citation_manifest(
            source_path=str(path.resolve()),
            source_hashes=source_hashes,
            source_format="system-hive-native-bam-dam-scan",
            source_key=source_key,
            source_index=index,
            executable_path=executable_path,
            user_sid=user_sid,
            timestamp=timestamp,
            timestamp_source="native-bam-dam-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
            source_offset=int(cluster.get("source_offset") or 0),
            row_cluster_evidence=row_cluster_evidence,
            report_grade=row_report_grade,
        )
        yield ArtifactRecord(
            provider=WindowsExecutionProvider.name,
            artifact_type="bam-entry",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-bam-dam-native-system-hive-scan",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-system-hive-string-pivot",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "system-hive-native-bam-dam-scan",
                "source_hashes": source_hashes,
                "source_index": index,
                "source_key": source_key,
                "source_offset": cluster.get("source_offset", 0),
                "source_encoding": cluster.get("source_encoding", ""),
                "executable_path": executable_path,
                "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
                "user_sid": user_sid,
                "timestamp": timestamp,
                "timestamp_source": "native-bam-dam-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
                "nearby_metadata_candidates": cluster.get("nearby_metadata_candidates", []),
                "bam_dam_evidence": bam_dam_entry_evidence(
                    key=source_key,
                    executable_path=executable_path,
                    user_sid=user_sid,
                    timestamp=timestamp,
                    timestamp_source="native-bam-dam-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
                    decoded_values={},
                    source_format="system-hive-native-bam-dam-scan",
                    source_offset=int(cluster.get("source_offset") or 0),
                    nearby_metadata_candidates=[
                        str(value) for value in cluster.get("nearby_metadata_candidates", [])
                    ] if isinstance(cluster.get("nearby_metadata_candidates"), list) else [],
                ),
                "bam_dam_decode_profile": bam_dam_decode_profile(
                    validation_checks=row_checks,
                    report_grade=row_report_grade,
                    executable_path=executable_path,
                    user_sid=user_sid,
                    timestamp=timestamp,
                    timestamp_source="native-bam-dam-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot",
                    source_format="system-hive-native-bam-dam-scan",
                ),
                "bam_dam_report_citation_manifest": citation_manifest,
                "bam_dam_report_citation_manifest_hash": citation_manifest["manifest_sha256"],
                "evidence_strength": "recent-execution-indicator-candidate",
                "parser_confidence": float(cluster.get("parser_confidence") or 0.54),
                "validation_required": True,
                "validation_checks": row_checks,
                "execution_validation_matrix": execution_validation_matrix(row_checks),
                "execution_report_grade_assessment": row_report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "commercial_uplift_evidence": execution_commercial_uplift_evidence(
                    "bam-entry",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": source_hashes,
                        "source_index": index,
                        "source_format": "system-hive-native-bam-dam-scan",
                        "execution_validation_matrix": execution_validation_matrix(row_checks),
                        "execution_report_grade_assessment": row_report_grade,
                    },
                ),
                "execution_analyst_review_profile": execution_analyst_review_profile(
                    artifact_type="bam-entry",
                    source_format="system-hive-native-bam-dam-scan",
                    validation_checks=row_checks,
                    report_grade=row_report_grade,
                    risk_flags=execution_risk_flags("bam-entry", executable_path, {}),
                    evidence_fields={
                        "executable_path": executable_path,
                        "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
                        "user_sid": user_sid,
                        "timestamp": timestamp,
                        "source_key": source_key,
                        "source_offset": cluster.get("source_offset", 0),
                    },
                ),
                "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
                "execution_caveat": "BAM/DAM should be correlated with other execution artifacts for final conclusions.",
                "validation_guidance": "Native SYSTEM hive scan preserves BAM/DAM path/SID/timestamp pivots only; validate binary FILETIME row decoding before report-grade execution claims.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": row_report_grade["blockers"],
                "risk_flags": execution_risk_flags("bam-entry", executable_path, {}),
                "risk_score": min(100, len(execution_path_risk_flags(executable_path)) * 25 + 25),
                "raw_preview": executable_path,
            },
        )
def build_native_amcache_records(path: Path) -> Iterable[ArtifactRecord]:
    try:
        stat_result = path.stat()
        with path.open("rb") as handle:
            blob = handle.read(min(stat_result.st_size, MAX_NATIVE_AMCACHE_SCAN_BYTES))
    except OSError:
        return
    source_hashes = file_hashes(path)
    occurrences = list(iter_registry_like_string_occurrences(blob))
    strings = list(unique_preserve_order(item["text"] for item in occurrences))
    amcache_clusters = collect_amcache_candidate_clusters(occurrences)
    path_candidates = [
        str(cluster.get("executable_path") or "")
        for cluster in amcache_clusters
        if str(cluster.get("executable_path") or "")
    ][:100]
    if not path_candidates:
        path_candidates = [value for value in strings if looks_like_executable_path(value)][:100]
    sha1_candidates = sorted(set(re.findall(r"(?i)\b[0-9a-f]{40}\b", "\n".join(strings))))[:100]
    hive_validation_checks = {
        "has_path_candidates": bool(path_candidates),
        "has_sha1_candidates": bool(sha1_candidates),
        "has_row_cluster_candidates": bool(amcache_clusters),
        "has_source_offsets": any(cluster.get("source_offset") is not None for cluster in amcache_clusters),
        "native_schema_decoding_available": False,
        "requires_second_parser_validation": True,
    }
    hive_report_grade = execution_report_grade_assessment(
        execution_validation_matrix(hive_validation_checks),
        validation_required=True,
        gap_ids=["#7"],
        extra_blockers=["native-amcache-schema-decoding-required", "install-and-execution-timestamp-validation-required"],
    )
    hive_schema_version = amcache_schema_version_profile(
        source_format="amcache-hive",
        source_key="Amcache.hve",
        executable_path=path_candidates[0] if path_candidates else "",
        execution_fields={
            "program_name": display_name_for_execution_key(path_candidates[0]) if path_candidates else "",
            "sha1": sha1_candidates[0] if sha1_candidates else "",
        },
        timestamp_source="not_available_native_string_pivot",
        decoded_values={},
        row_cluster_evidence={},
    )
    hive_manifest = amcache_row_manifest(
        source_path=str(path.resolve()),
        source_hashes=source_hashes,
        source_format="amcache-hive",
        source_key="Amcache.hve",
        source_index=0,
        executable_path=path_candidates[0] if path_candidates else "",
        sha1_candidates=sha1_candidates,
        timestamp="",
        timestamp_source="not_available_native_string_pivot",
        source_offset=0,
        row_cluster_evidence={},
        schema_version_profile=hive_schema_version,
        report_grade=hive_report_grade,
    )
    hive_core_accuracy_gates = execution_core_accuracy_gates(
        "amcache-entry",
        {
            "source_path": str(path.resolve()),
            "source_hashes": source_hashes,
            "source_format": "amcache-hive",
            "executable_path": path_candidates[0] if path_candidates else "",
            "sha1_candidates": sha1_candidates,
            "amcache_row_manifest_hash": hive_manifest["manifest_sha256"],
            "validation_checks": hive_validation_checks,
        },
    )
    hive_citation_manifest = amcache_report_citation_manifest(
        source_path=str(path.resolve()),
        source_hashes=source_hashes,
        source_format="amcache-hive",
        source_key="",
        source_index=0,
        executable_path=path_candidates[0] if path_candidates else "",
        sha1_candidates=sha1_candidates,
        timestamp="",
        timestamp_source="not_available_native_string_pivot",
        source_offset=0,
        row_cluster_evidence={},
        report_grade=hive_report_grade,
    )
    yield ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type="amcache-hive",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "windows-amcache-native-hive-scan",
            "parser_version": PARSER_VERSION,
            "coverage_status": "native-hive-string-pivot",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "amcache-hive",
            "source_hashes": source_hashes,
            "size": stat_result.st_size,
            "extracted_string_count": len(strings),
            "path_candidates": path_candidates,
            "sha1_candidates": sha1_candidates,
            "amcache_candidate_clusters": amcache_clusters[:100],
            "amcache_candidate_cluster_count": len(amcache_clusters),
            "amcache_hive_evidence": amcache_hive_evidence(path_candidates, sha1_candidates, strings, amcache_clusters),
            "amcache_schema_version_profile": hive_schema_version,
            "amcache_row_manifest": hive_manifest,
            "amcache_row_manifest_hash": hive_manifest["manifest_sha256"],
            "amcache_report_citation_manifest": hive_citation_manifest,
            "amcache_schema_profile": amcache_schema_profile(
                source_format="amcache-hive",
                timestamp_source="not_available_native_string_pivot",
                validation_checks=hive_validation_checks,
                report_grade=hive_report_grade,
                executable_path=path_candidates[0] if path_candidates else "",
                sha1=sha1_candidates[0] if sha1_candidates else "",
            ),
            "parser_confidence": 0.46,
            "evidence_strength": "amcache-native-string-pivot",
            "validation_required": True,
            "validation_checks": hive_validation_checks,
            "execution_validation_matrix": execution_validation_matrix(hive_validation_checks),
            "execution_report_grade_assessment": hive_report_grade,
            "core_accuracy_gates": hive_core_accuracy_gates,
            "commercial_uplift_evidence": execution_commercial_uplift_evidence(
                "amcache-hive",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "source_format": "amcache-hive",
                    "amcache_row_manifest_hash": hive_manifest["manifest_sha256"],
                    "execution_validation_matrix": execution_validation_matrix(hive_validation_checks),
                    "execution_report_grade_assessment": hive_report_grade,
                },
            ),
            "execution_analyst_review_profile": execution_analyst_review_profile(
                artifact_type="amcache-hive",
                source_format="amcache-hive",
                validation_checks=hive_validation_checks,
                report_grade=hive_report_grade,
                risk_flags=sorted({flag for value in path_candidates for flag in execution_path_risk_flags(value)}),
                evidence_fields={
                    "path_candidates": path_candidates,
                    "sha1_candidates": sha1_candidates,
                    "amcache_candidate_cluster_count": len(amcache_clusters),
                },
            ),
            "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
            "validation_guidance": "Native Amcache.hve string pivots identify program/hash candidates only; validate install/execution timestamps with a dedicated Amcache parser.",
            "commercial_grade_ready": False,
            "commercial_grade_blockers": hive_report_grade["blockers"],
            "risk_flags": sorted({flag for value in path_candidates for flag in execution_path_risk_flags(value)}),
            "risk_score": min(100, len(path_candidates) * 5),
            "raw_preview": " ".join(strings[:25])[:2000],
        },
    )
    clusters_by_path = {normalize_execution_path(str(cluster.get("executable_path") or "")): cluster for cluster in amcache_clusters}
    for index, candidate in enumerate(path_candidates[:100]):
        cluster = clusters_by_path.get(normalize_execution_path(candidate), {})
        cluster_sha1_candidates = [
            str(value) for value in cluster.get("sha1_candidates", []) if str(value)
        ] if isinstance(cluster.get("sha1_candidates"), list) else []
        row_sha1_candidates = sorted(set([*cluster_sha1_candidates, *sha1_candidates]))[:100]
        timestamp_candidates = [
            str(value) for value in cluster.get("timestamp_candidates", []) if str(value)
        ] if isinstance(cluster.get("timestamp_candidates"), list) else []
        timestamp = timestamp_candidates[0] if timestamp_candidates else ""
        timestamp_source = "native-amcache-nearby-string-timestamp-candidate" if timestamp else "not_available_native_string_pivot"
        entry_validation_checks = {
            "has_executable_path": bool(candidate),
            "has_hash_candidates": bool(row_sha1_candidates),
            "has_row_cluster_candidate": bool(cluster),
            "has_source_offset": cluster.get("source_offset") is not None,
            "has_timestamp_candidate": bool(timestamp_candidates),
            "has_nearby_metadata_candidates": bool(cluster.get("metadata_candidates")),
            "native_schema_decoding_available": False,
            "requires_second_parser_validation": True,
            "correlation_targets": execution_correlation_targets("amcache-entry"),
        }
        entry_report_grade = execution_report_grade_assessment(
            execution_validation_matrix(entry_validation_checks),
            validation_required=True,
            gap_ids=["#7"],
            extra_blockers=["native-amcache-schema-decoding-required", "row-level-timestamp-extraction-required"],
        )
        row_cluster_evidence = amcache_row_cluster_evidence(cluster)
        entry_schema_version = amcache_schema_version_profile(
            source_format="amcache-hive",
            source_key="Amcache.hve",
            executable_path=candidate,
            execution_fields={
                "program_name": display_name_for_execution_key(candidate),
                "sha1": row_sha1_candidates[0] if row_sha1_candidates else "",
            },
            timestamp_source=timestamp_source,
            decoded_values={},
            row_cluster_evidence=row_cluster_evidence,
        )
        entry_manifest = amcache_row_manifest(
            source_path=str(path.resolve()),
            source_hashes=source_hashes,
            source_format="amcache-hive",
            source_key="Amcache.hve",
            source_index=index,
            executable_path=candidate,
            sha1_candidates=row_sha1_candidates,
            timestamp=timestamp,
            timestamp_source=timestamp_source,
            source_offset=int(cluster.get("source_offset") or 0) if isinstance(cluster, Mapping) else 0,
            row_cluster_evidence=row_cluster_evidence,
            schema_version_profile=entry_schema_version,
            report_grade=entry_report_grade,
        )
        entry_core_accuracy_gates = execution_core_accuracy_gates(
            "amcache-entry",
            {
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "source_format": "amcache-hive",
                "executable_path": candidate,
                "program_name": display_name_for_execution_key(candidate),
                "sha1_candidates": sha1_candidates,
                "amcache_row_manifest_hash": entry_manifest["manifest_sha256"],
                "validation_checks": entry_validation_checks,
            },
        )
        entry_citation_manifest = amcache_report_citation_manifest(
            source_path=str(path.resolve()),
            source_hashes=source_hashes,
            source_format="amcache-hive",
            source_key="",
            source_index=index,
            executable_path=candidate,
            sha1_candidates=row_sha1_candidates,
            timestamp=timestamp,
            timestamp_source=timestamp_source,
            source_offset=int(cluster.get("source_offset") or 0) if isinstance(cluster, Mapping) else 0,
            row_cluster_evidence=row_cluster_evidence,
            report_grade=entry_report_grade,
        )
        yield ArtifactRecord(
            provider=WindowsExecutionProvider.name,
            artifact_type="amcache-entry",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-amcache-native-hive-scan",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-hive-string-pivot",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "amcache-hive",
                "source_hashes": source_hashes,
                "source_index": index,
                "executable_path": candidate,
                "program_name": display_name_for_execution_key(candidate),
                "sha1_candidates": row_sha1_candidates,
                "amcache_row_cluster_evidence": row_cluster_evidence,
                "amcache_evidence": amcache_entry_evidence(
                    source_format="amcache-hive",
                    source_key="",
                    executable_path=candidate,
                    execution_fields={
                        "program_name": display_name_for_execution_key(candidate),
                        "sha1": row_sha1_candidates[0] if row_sha1_candidates else "",
                    },
                    timestamp=timestamp,
                    timestamp_source=timestamp_source,
                    decoded_values={},
                    sha1_candidates=row_sha1_candidates,
                ),
                "amcache_schema_profile": amcache_schema_profile(
                    source_format="amcache-hive",
                    timestamp_source=timestamp_source,
                    validation_checks=entry_validation_checks,
                    report_grade=entry_report_grade,
                    executable_path=candidate,
                    sha1=row_sha1_candidates[0] if row_sha1_candidates else "",
                ),
                "amcache_schema_version_profile": entry_schema_version,
                "amcache_row_manifest": entry_manifest,
                "amcache_row_manifest_hash": entry_manifest["manifest_sha256"],
                "amcache_report_citation_manifest": entry_citation_manifest,
                "timestamp": timestamp,
                "timestamp_source": timestamp_source,
                "source_offset": cluster.get("source_offset", 0) if isinstance(cluster, Mapping) else 0,
                "source_encoding": cluster.get("source_encoding", "") if isinstance(cluster, Mapping) else "",
                "nearby_metadata_candidates": cluster.get("metadata_candidates", []) if isinstance(cluster, Mapping) else [],
                "artifact_family": "amcache",
                "evidence_strength": "program-presence-or-execution-candidate",
                "parser_confidence": float(cluster.get("parser_confidence") or 0.44) if isinstance(cluster, Mapping) else 0.44,
                "validation_required": True,
                "validation_checks": entry_validation_checks,
                "execution_validation_matrix": execution_validation_matrix(entry_validation_checks),
                "execution_report_grade_assessment": entry_report_grade,
                "core_accuracy_gates": entry_core_accuracy_gates,
                "commercial_uplift_evidence": execution_commercial_uplift_evidence(
                    "amcache-entry",
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": source_hashes,
                        "source_index": index,
                        "source_format": "amcache-hive",
                        "amcache_row_manifest_hash": entry_manifest["manifest_sha256"],
                        "execution_validation_matrix": execution_validation_matrix(entry_validation_checks),
                        "execution_report_grade_assessment": entry_report_grade,
                    },
                ),
                "execution_analyst_review_profile": execution_analyst_review_profile(
                    artifact_type="amcache-entry",
                    source_format="amcache-hive",
                    validation_checks=entry_validation_checks,
                    report_grade=entry_report_grade,
                    risk_flags=execution_path_risk_flags(candidate),
                    evidence_fields={
                        "executable_path": candidate,
                        "sha1_candidates": row_sha1_candidates,
                        "program_name": display_name_for_execution_key(candidate),
                        "timestamp": timestamp,
                        "source_offset": cluster.get("source_offset", 0) if isinstance(cluster, Mapping) else 0,
                    },
                ),
                "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
                "validation_guidance": "Validate native Amcache string-pivot rows with AmcacheParser/RECmd before report-grade install/execution claims.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": entry_report_grade["blockers"],
                "risk_flags": execution_path_risk_flags(candidate),
                "risk_score": min(100, len(execution_path_risk_flags(candidate)) * 25),
                "raw_preview": candidate,
            },
        )


def collect_powershell_history(root: Path) -> Iterable[ArtifactRecord]:
    for user_root in iter_windows_user_homes(root):
        path = user_root.joinpath(*POWERSHELL_HISTORY)
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        modified_at = path_modified_at(path)
        for index, command in enumerate(lines):
            command = command.strip()
            if not command:
                continue
            risk_flags = [f"suspicious-command:{term}" for term in SUSPICIOUS_COMMAND_TERMS if term in command.lower()]
            yield ArtifactRecord(
                provider=WindowsExecutionProvider.name,
                artifact_type="powershell-history-command",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-powershell-history",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "parsed",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "text",
                    "source_hashes": file_hashes(path),
                    "source_index": index,
                    "user": user_root.name,
                    "command_line": command,
                    "timestamp": modified_at,
                    "timestamp_source": "history_file_modified_at",
                    "risk_flags": risk_flags,
                    "risk_score": min(100, len(risk_flags) * 25),
                },
            )


def collect_srum_imports(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in SRUM_IMPORT_SUFFIXES:
            continue
        if "srum" not in str(path).lower() and "srudb" not in str(path).lower():
            continue
        rows = iter_csv_rows(path) if path.suffix.lower() == ".csv" else iter_json_rows(path)
        for index, row in enumerate(rows):
            if isinstance(row, Mapping):
                yield build_srum_record(path, row, index)


def collect_srum_dat_inventory(root: Path) -> Iterable[ArtifactRecord]:
    seen: set[Path] = set()
    canonical_path = root / "Windows" / "System32" / "sru" / "SRUDB.dat"
    if canonical_path.is_file():
        inventory = build_srum_database_inventory_record(canonical_path)
        yield inventory
        yield from build_srum_database_pivot_records(canonical_path, inventory.details)
        seen.add(canonical_path.resolve())
    for path in sorted(root.rglob("SRUDB.dat"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        inventory = build_srum_database_inventory_record(path)
        yield inventory
        yield from build_srum_database_pivot_records(path, inventory.details)
        seen.add(resolved)


def build_srum_database_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    ese_header = probe_ese_database(path)
    pivots = build_ese_string_pivots(path)
    native_srudb = analyze_srudb_native(path, ese_header=ese_header)
    native_validation = native_srudb["native_srudb_validation"]
    table_candidates = native_srudb["native_srum_table_candidates"]
    row_candidates = native_srudb["native_srum_row_candidates"]
    validation_checks = {
        "ese_header_readable": bool(ese_header.get("header_readable")),
        "ese_signature_valid": bool(ese_header.get("signature_valid")),
        "native_srudb_page_size_plausible": bool(dict(native_validation).get("page_size_plausible")),
        "native_srudb_file_size_page_aligned": bool(dict(native_validation).get("file_size_page_aligned")),
        "has_path_pivots": bool(pivots.get("path_candidates")),
        "has_url_pivots": bool(pivots.get("url_candidates")),
        "has_native_srum_table_candidates": bool(table_candidates),
        "has_native_srum_row_candidates": bool(row_candidates),
        "row_level_decoding_available": False,
        "native_table_catalog_decoding_available": False,
        "requires_srum_parser": True,
    }
    report_grade = execution_report_grade_assessment(
        execution_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#10"],
        extra_blockers=[
            "native-ese-catalog-decoding-required",
            "native-ese-page-row-decoding-required",
            "native-srum-row-decoding-required",
            "large-known-answer-validation-required",
        ],
    )
    core_accuracy_gates = execution_core_accuracy_gates(
        "srum-database-file",
        {
            "source_path": str(path.resolve()),
            "source_hashes": file_hashes(path),
            "source_format": "ese-srum",
            "ese_header": ese_header,
            "native_srudb_validation": native_validation,
            "table_candidate_count": len(table_candidates),
            "row_candidate_count": len(row_candidates),
            "validation_checks": validation_checks,
        },
    )
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type="srum-database-file",
        path=str(path.resolve()),
        supported=False,
        details={
            "parser": "windows-srum-ese-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "ese-header-string-scan" if ese_header.get("header_readable") else "detected",
            "reportability": "inventory-only",
            "source_path": str(path.resolve()),
            "source_format": "ese-srum",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "modified_at": stat_result.st_mtime,
            "ese_header": ese_header,
            "native_srudb_validation": native_validation,
            "native_srum_table_candidates": table_candidates,
            "native_srum_table_candidate_count": len(table_candidates),
            "native_srum_row_candidate_count": len(row_candidates),
            "native_srum_row_candidates": row_candidates[:20],
            "srum_database_evidence": srum_database_evidence(
                ese_header,
                native_validation,
                table_candidates,
                row_candidates,
                pivots,
            ),
            "srum_ese_validation_profile": srum_ese_validation_profile(
                artifact_scope="database",
                validation_checks=validation_checks,
                report_grade=report_grade,
                evidence_fields={
                    "ese_signature_valid": bool(ese_header.get("signature_valid")),
                    "table_candidate_count": len(table_candidates),
                    "row_candidate_count": len(row_candidates),
                    "page_size": ese_header.get("page_size", 0),
                },
            ),
            "srum_report_citation_manifest": srum_report_citation_manifest(
                source_path=str(path.resolve()),
                source_hashes=file_hashes(path),
                artifact_type="srum-database-file",
                artifact_scope="database",
                source_format="ese-srum",
                source_index=0,
                table_family="srudb",
                app_id="",
                timestamp="",
                counters={
                    "table_candidate_count": len(table_candidates),
                    "row_candidate_count": len(row_candidates),
                    "page_size": ese_header.get("page_size", 0),
                },
                source_offset=0,
                row_cluster_evidence={},
                report_grade=report_grade,
            ),
            "parser_confidence": 0.65 if ese_header.get("signature_valid") else 0.35,
            "evidence_strength": "application-resource-usage-database-presence",
            "validation_required": True,
            "validation_checks": validation_checks,
            "execution_validation_matrix": execution_validation_matrix(validation_checks),
            "execution_report_grade_assessment": report_grade,
            "core_accuracy_gates": core_accuracy_gates,
            "commercial_uplift_evidence": execution_commercial_uplift_evidence(
                "srum-database-file",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "source_format": "ese-srum",
                    "source_index": 0,
                    "execution_validation_matrix": execution_validation_matrix(validation_checks),
                    "execution_report_grade_assessment": report_grade,
                    "native_srudb_validation": native_validation,
                },
            ),
            "execution_analyst_review_profile": execution_analyst_review_profile(
                artifact_type="srum-database-file",
                source_format="ese-srum",
                validation_checks=validation_checks,
                report_grade=report_grade,
                risk_flags=[],
                evidence_fields={
                    "native_srum_table_candidate_count": len(table_candidates),
                    "native_srum_row_candidate_count": len(row_candidates),
                    "path_candidates": pivots.get("path_candidates", []),
                    "url_candidates": pivots.get("url_candidates", []),
                },
            ),
            "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
            "forensic_review": build_forensic_review(
                gap_id="#10",
                artifact_goal="SRUM application/network/resource usage",
                primary_evidence=[
                    f"tables={len(table_candidates)}",
                    f"row_candidates={len(row_candidates)}",
                    f"page_size={ese_header.get('page_size', 0)}",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                commercial_grade_ready=False,
                caveats=["Native SRUDB rows are not fully decoded from ESE pages."],
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            **pivots,
            "recommended_parsers": ["SrumECmd", "ESEDatabaseView", "libesedb/esedbexport"],
            "note": "SRUDB.dat is inventoried directly with bounded ESE header/string pivots; use a dedicated SRUM parser for full table decoding and timeline-grade rows.",
        },
    )


def build_srum_database_pivot_records(path: Path, inventory_details: Mapping[str, object]) -> Iterable[ArtifactRecord]:
    source_hashes = file_hashes(path)
    candidates: list[tuple[str, str]] = []
    for value in inventory_details.get("path_candidates") or []:
        candidates.append(("path", str(value)))
    for value in inventory_details.get("url_candidates") or []:
        candidates.append(("url", str(value)))
    for value in inventory_details.get("suspicious_strings") or []:
        candidates.append(("string", str(value)))

    seen: set[tuple[str, str]] = set()
    for index, (candidate_kind, candidate_value) in enumerate(candidates):
        key = (candidate_kind, candidate_value)
        if key in seen:
            continue
        seen.add(key)
        executable_path = executable_path_from_candidate(candidate_value)
        url = candidate_value if candidate_kind == "url" else first_url(candidate_value)
        risk_flags = srum_candidate_risk_flags("srum-pivot", candidate_value)
        if url:
            risk_flags.append("srum-network-url-pivot")
        validation_checks = {
            "has_app_id": bool(executable_path),
            "has_url": bool(url),
            "row_level_decoding_available": False,
            "native_table_catalog_decoding_available": False,
            "requires_srum_parser": True,
        }
        report_grade = execution_report_grade_assessment(
            execution_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#10"],
            extra_blockers=["native-ese-catalog-decoding-required", "native-srum-row-decoding-required"],
        )
        core_accuracy_gates = execution_core_accuracy_gates(
            "srum-database-pivot",
            {
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "candidate_kind": candidate_kind,
                "app_id": display_name_for_execution_key(executable_path) if executable_path else "",
                "executable_path": executable_path,
                "url": url,
                "validation_checks": validation_checks,
            },
        )
        yield ArtifactRecord(
            provider=WindowsExecutionProvider.name,
            artifact_type="srum-database-pivot",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-srum-ese-string-pivot",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-ese-string-pivot",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_format": "ese-srum",
                "source_hashes": source_hashes,
                "source_index": index,
                "candidate_kind": candidate_kind,
                "candidate_value": candidate_value,
                "app_id": display_name_for_execution_key(executable_path) if executable_path else "",
                "executable_path": executable_path,
                "url": url,
                "srum_pivot_evidence": srum_pivot_evidence(candidate_kind, candidate_value, executable_path, url),
                "srum_ese_validation_profile": srum_ese_validation_profile(
                    artifact_scope="string-pivot",
                    validation_checks=validation_checks,
                    report_grade=report_grade,
                    evidence_fields={
                        "candidate_kind": candidate_kind,
                        "app_id": display_name_for_execution_key(executable_path) if executable_path else "",
                        "url": url,
                    },
                ),
                "srum_report_citation_manifest": srum_report_citation_manifest(
                    source_path=str(path.resolve()),
                    source_hashes=source_hashes,
                    artifact_type="srum-database-pivot",
                    artifact_scope="string-pivot",
                    source_format="ese-srum",
                    source_index=index,
                    table_family="unknown",
                    app_id=display_name_for_execution_key(executable_path) if executable_path else "",
                    timestamp="",
                    counters={},
                    source_offset=0,
                    row_cluster_evidence={"candidate_kind": candidate_kind, "candidate_value": candidate_value, "url": url},
                    report_grade=report_grade,
                ),
                "timestamp": "",
                "timestamp_source": "not_available_native_string_pivot",
                "parser_confidence": 0.4,
                "evidence_strength": "application-resource-usage-string-pivot",
                "validation_required": True,
                "validation_checks": validation_checks,
                "execution_validation_matrix": execution_validation_matrix(validation_checks),
                "execution_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
                "execution_analyst_review_profile": execution_analyst_review_profile(
                    artifact_type="srum-database-pivot",
                    source_format="ese-srum",
                    validation_checks=validation_checks,
                    report_grade=report_grade,
                    risk_flags=risk_flags,
                    evidence_fields={
                        "candidate_kind": candidate_kind,
                        "candidate_value": candidate_value,
                        "app_id": display_name_for_execution_key(executable_path) if executable_path else "",
                        "url": url,
                    },
                ),
                "forensic_review": build_forensic_review(
                    gap_id="#10",
                    artifact_goal="SRUM native ESE string pivot",
                    primary_evidence=[
                        f"candidate_kind={candidate_kind}",
                        f"app={display_name_for_execution_key(executable_path)}" if executable_path else "",
                        f"url={url}" if url else "",
                    ],
                    validation_required=True,
                    report_grade_assessment=report_grade,
                    commercial_grade_ready=False,
                    caveats=["String pivots prove presence in SRUDB, not decoded row semantics."],
                ),
                "validation_guidance": "SRUDB.dat native string pivots identify apps/URLs present in the database; validate row timestamps and counters with SrumECmd or another dedicated SRUM parser.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "risk_flags": sorted(set(risk_flags)),
                "risk_score": min(100, len(set(risk_flags)) * 20),
                "raw_preview": candidate_value[:2000],
            },
        )
    yield from build_srum_database_table_candidate_records(path, inventory_details)
    yield from build_srum_database_row_candidate_records(path, inventory_details)


def build_srum_database_table_candidate_records(path: Path, inventory_details: Mapping[str, object]) -> Iterable[ArtifactRecord]:
    source_hashes = file_hashes(path)
    table_candidates = [item for item in inventory_details.get("native_srum_table_candidates") or [] if isinstance(item, Mapping)]
    strings = [str(value) for value in inventory_details.get("extracted_strings") or []]
    for index, candidate in enumerate(table_candidates):
        table_family = str(candidate.get("table_family") or "unknown")
        matched = [str(value) for value in candidate.get("matched_markers") or []]
        if not matched:
            continue
        validation_checks = {
            "table_family_marker_count": len(matched),
            "has_source_offsets": bool(candidate.get("source_offsets")),
            "row_level_decoding_available": False,
            "requires_srum_parser": True,
        }
        report_grade = execution_report_grade_assessment(
            execution_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#10"],
            extra_blockers=[
                "native-ese-catalog-decoding-required",
                "native-ese-page-row-decoding-required",
                "native-srum-row-decoding-required",
            ],
        )
        core_accuracy_gates = execution_core_accuracy_gates(
            "srum-table-candidate",
            {
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "table_family": table_family,
                "matched_marker_count": len(matched),
                "source_offsets": [int(value) for value in candidate.get("source_offsets") or []],
                "validation_checks": validation_checks,
            },
        )
        yield ArtifactRecord(
            provider=WindowsExecutionProvider.name,
            artifact_type="srum-table-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-srum-ese-table-candidate",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-ese-table-string-candidate",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_format": "ese-srum",
                "source_hashes": source_hashes,
                "source_index": index,
                "table_family": table_family,
                "matched_markers": matched,
                "matched_marker_count": len(matched),
                "candidate_basis": str(candidate.get("candidate_basis") or "bounded-native-string-marker-scan"),
                "candidate_strings": [str(value) for value in candidate.get("candidate_strings") or []],
                "source_offsets": [int(value) for value in candidate.get("source_offsets") or []],
                "srum_ese_validation_profile": srum_ese_validation_profile(
                    artifact_scope="table-candidate",
                    validation_checks=validation_checks,
                    report_grade=report_grade,
                    evidence_fields={
                        "table_family": table_family,
                        "matched_marker_count": len(matched),
                        "source_offset_count": len(candidate.get("source_offsets") or []),
                    },
                ),
                "srum_report_citation_manifest": srum_report_citation_manifest(
                    source_path=str(path.resolve()),
                    source_hashes=source_hashes,
                    artifact_type="srum-table-candidate",
                    artifact_scope="table-candidate",
                    source_format="ese-srum",
                    source_index=index,
                    table_family=table_family,
                    app_id="",
                    timestamp="",
                    counters={"matched_marker_count": len(matched)},
                    source_offset=int((candidate.get("source_offsets") or [0])[0] or 0),
                    row_cluster_evidence={
                        "matched_markers": matched,
                        "source_offsets": [int(value) for value in candidate.get("source_offsets") or []],
                    },
                    report_grade=report_grade,
                ),
                "parser_confidence": float(candidate.get("candidate_confidence") or (0.38 + min(0.24, len(matched) * 0.06))),
                "evidence_strength": "srum-table-presence-candidate",
                "validation_required": True,
                "validation_guidance": "This row identifies likely SRUM table families from native ESE strings only; validate rows, counters, and timestamps with a full ESE/SRUM parser.",
                "validation_checks": validation_checks,
                "execution_validation_matrix": execution_validation_matrix(validation_checks),
                "execution_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
                "execution_analyst_review_profile": execution_analyst_review_profile(
                    artifact_type="srum-table-candidate",
                    source_format="ese-srum",
                    validation_checks=validation_checks,
                    report_grade=report_grade,
                    risk_flags=[],
                    evidence_fields={
                        "table_family": table_family,
                        "matched_marker_count": len(matched),
                        "source_offset": int((candidate.get("source_offsets") or [0])[0] or 0),
                    },
                ),
                "forensic_review": build_forensic_review(
                    gap_id="#10",
                    artifact_goal="SRUM native table-family candidate",
                    primary_evidence=[
                        f"table={table_family}",
                        f"markers={len(matched)}",
                        f"offsets={len(candidate.get('source_offsets') or [])}",
                    ],
                    validation_required=True,
                    report_grade_assessment=report_grade,
                    commercial_grade_ready=False,
                    caveats=["Table family is detected from native strings, not decoded from the ESE catalog."],
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "risk_flags": [f"srum-table:{table_family}"],
                "risk_score": 20,
                "raw_preview": " ".join(strings[:20])[:2000],
            },
        )


def build_srum_database_row_candidate_records(path: Path, inventory_details: Mapping[str, object]) -> Iterable[ArtifactRecord]:
    source_hashes = file_hashes(path)
    row_candidates = [item for item in inventory_details.get("native_srum_row_candidates") or [] if isinstance(item, Mapping)]
    for index, candidate in enumerate(row_candidates):
        app_id = str(candidate.get("app_id") or "")
        executable_path = str(candidate.get("executable_path") or "")
        url = str(candidate.get("url") or "")
        raw_candidate = str(candidate.get("raw_candidate") or "")
        risk_flags = srum_candidate_risk_flags("srum-row-candidate", raw_candidate)
        if url:
            risk_flags.append("srum-network-url-pivot")
        validation_checks = {
            "has_app_id": bool(app_id),
            "has_executable_path": bool(executable_path),
            "has_user_or_sid": bool(candidate.get("user") or candidate.get("user_sid")),
            "has_timestamp_candidate": bool(candidate.get("timestamp")),
            "has_counter_candidates": bool(candidate.get("counter_candidates")),
            "has_source_offset": candidate.get("source_offset") is not None,
            "has_srum_row_cluster_context": bool(candidate.get("nearby_string_count")),
            "has_srum_field_presence_profile": bool(candidate.get("field_presence_profile")),
            "row_level_decoding_available": False,
            "requires_srum_parser": True,
        }
        report_grade = execution_report_grade_assessment(
            execution_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#10"],
            extra_blockers=[
                "native-ese-catalog-decoding-required",
                "native-ese-page-row-decoding-required",
                "native-srum-row-decoding-required",
                "known-answer-row-validation-required",
            ],
        )
        core_accuracy_gates = execution_core_accuracy_gates(
            "srum-row-candidate",
            {
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "table_family": str(candidate.get("table_family") or "unknown"),
                "app_id": app_id,
                "executable_path": executable_path,
                "user": str(candidate.get("user") or ""),
                "user_sid": str(candidate.get("user_sid") or ""),
                "timestamp": str(candidate.get("timestamp") or ""),
                "counter_candidates": dict(candidate.get("counter_candidates") or {}),
                "validation_checks": validation_checks,
            },
        )
        yield ArtifactRecord(
            provider=WindowsExecutionProvider.name,
            artifact_type="srum-row-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-srum-ese-row-candidate",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-ese-string-row-candidate",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "ese-srum",
                "source_hashes": source_hashes,
                "source_index": index,
                "candidate_basis": str(candidate.get("candidate_basis") or "bounded-native-string-row-cluster"),
                "source_offset": int(candidate.get("source_offset") or 0),
                "source_encoding": str(candidate.get("source_encoding") or ""),
                "cluster_window_bytes": int(candidate.get("cluster_window_bytes") or 0),
                "nearby_string_count": int(candidate.get("nearby_string_count") or 0),
                "nearby_offsets": [int(value) for value in candidate.get("nearby_offsets") or []],
                "row_cluster_strings": [str(value) for value in candidate.get("row_cluster_strings") or []],
                "table_family": str(candidate.get("table_family") or "unknown"),
                "app_id": app_id,
                "executable_path": executable_path,
                "user": str(candidate.get("user") or ""),
                "user_sid": str(candidate.get("user_sid") or ""),
                "timestamp": str(candidate.get("timestamp") or ""),
                "timestamp_source": "native-string-candidate-not-row-decoded" if candidate.get("timestamp") else "",
                "url": url,
                "bytes_sent": candidate.get("bytes_sent", 0),
                "bytes_received": candidate.get("bytes_received", 0),
                "energy_usage": candidate.get("energy_usage", 0),
                "cpu_time": candidate.get("cpu_time", 0),
                "counter_candidates": dict(candidate.get("counter_candidates") or {}),
                "field_presence_profile": dict(candidate.get("field_presence_profile") or {}),
                "interface_luid": str(candidate.get("interface_luid") or ""),
                "network_profile": str(candidate.get("network_profile") or ""),
                "srum_row_evidence": srum_row_evidence(candidate),
                "srum_ese_validation_profile": srum_ese_validation_profile(
                    artifact_scope="row-candidate",
                    validation_checks=validation_checks,
                    report_grade=report_grade,
                    evidence_fields={
                        "table_family": str(candidate.get("table_family") or "unknown"),
                        "app_id": app_id,
                        "timestamp": str(candidate.get("timestamp") or ""),
                        "counter_candidate_count": len(dict(candidate.get("counter_candidates") or {})),
                    },
                ),
                "srum_report_citation_manifest": srum_report_citation_manifest(
                    source_path=str(path.resolve()),
                    source_hashes=source_hashes,
                    artifact_type="srum-row-candidate",
                    artifact_scope="row-candidate",
                    source_format="ese-srum",
                    source_index=index,
                    table_family=str(candidate.get("table_family") or "unknown"),
                    app_id=app_id,
                    timestamp=str(candidate.get("timestamp") or ""),
                    counters=dict(candidate.get("counter_candidates") or {}),
                    source_offset=int(candidate.get("source_offset") or 0),
                    row_cluster_evidence=srum_row_evidence(candidate),
                    report_grade=report_grade,
                ),
                "parser_confidence": float(candidate.get("candidate_confidence") or 0.42),
                "evidence_strength": "srum-native-row-string-candidate",
                "validation_required": True,
                "validation_guidance": "This bounded native SRUDB row candidate is extracted from nearby strings only; validate ESE catalog/page/row decoding, counters, and timestamps with a dedicated SRUM parser before reporting conclusions.",
                "validation_checks": validation_checks,
                "execution_validation_matrix": execution_validation_matrix(validation_checks),
                "execution_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
                "execution_analyst_review_profile": execution_analyst_review_profile(
                    artifact_type="srum-row-candidate",
                    source_format="ese-srum",
                    validation_checks=validation_checks,
                    report_grade=report_grade,
                    risk_flags=risk_flags,
                    evidence_fields={
                        "app_id": app_id,
                        "timestamp": str(candidate.get("timestamp") or ""),
                        "table_family": str(candidate.get("table_family") or "unknown"),
                        "bytes_received": candidate.get("bytes_received", 0),
                        "bytes_sent": candidate.get("bytes_sent", 0),
                        "source_offset": int(candidate.get("source_offset") or 0),
                    },
                ),
                "forensic_review": build_forensic_review(
                    gap_id="#10",
                    artifact_goal="SRUM native row candidate",
                    primary_evidence=[
                        f"app={app_id}" if app_id else "",
                        f"timestamp={candidate.get('timestamp', '')}" if candidate.get("timestamp") else "",
                        f"table={candidate.get('table_family', 'unknown')}",
                    ],
                    validation_required=True,
                    report_grade_assessment=report_grade,
                    commercial_grade_ready=False,
                    caveats=["Candidate is clustered from nearby native strings, not decoded from ESE row columns."],
                ),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "risk_flags": sorted(set(risk_flags)),
                "risk_score": min(100, len(set(risk_flags)) * 20),
                "raw_preview": raw_candidate[:2000],
            },
        )


def build_srum_record(path: Path, row: Mapping[str, object], index: int) -> ArtifactRecord:
    lowered = {normalize_key(key): value for key, value in row.items()}
    app_id = str(first_value(lowered, "app", "appid", "application", "applicationname", "executable", "executablepath") or "")
    user = str(first_value(lowered, "user", "username", "useraccount", "sid") or "")
    timestamp = str(first_value(lowered, "timestamp", "eventtime", "starttime", "endtime", "time") or "").replace("Z", "+00:00")
    bytes_sent = number_value(first_value(lowered, "bytessent", "sendbytes", "sentbytes", "networkbytessent"))
    bytes_received = number_value(first_value(lowered, "bytesreceived", "receivebytes", "receivedbytes", "networkbytesreceived"))
    bytes_total = numeric_total(bytes_sent, bytes_received)
    cpu_time = number_value(first_value(lowered, "cputime", "cpu", "cpucycletime"))
    energy = number_value(first_value(lowered, "energy", "energyusage", "energyusagemwh"))
    interface_luid = str(first_value(lowered, "interfaceluid", "interface", "networkinterface") or "")
    network_profile = str(first_value(lowered, "networkprofile", "profile", "ssid") or "")
    artifact_type = "srum-network-usage" if bytes_sent or bytes_received else "srum-app-resource-usage"
    risk_flags = [f"suspicious-app:{term}" for term in SUSPICIOUS_COMMAND_TERMS if term.split()[0] in app_id.lower()]
    validation_checks = {
        "has_timestamp": bool(timestamp),
        "has_app_id": bool(app_id),
        "has_user": bool(user),
        "has_network_counters": bool(bytes_sent or bytes_received),
        "has_resource_counters": bool(cpu_time or energy),
        "counter_fields_normalized": True,
        "source_tool_export_validation_required": True,
    }
    report_grade = execution_report_grade_assessment(
        execution_validation_matrix(validation_checks),
        validation_required=False,
        gap_ids=["#10"],
        extra_blockers=["source-tool-export-validation-required"],
    )
    core_accuracy_gates = execution_core_accuracy_gates(
        artifact_type,
        {
            "source_path": str(path.resolve()),
            "source_hashes": file_hashes(path),
            "source_index": index,
            "source_format": path.suffix.lower().lstrip("."),
            "app_id": app_id,
            "executable_path": app_id if looks_like_executable_path(app_id) else "",
            "user": user,
            "timestamp": timestamp,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "energy_usage": energy,
            "cpu_time": cpu_time,
            "validation_checks": validation_checks,
        },
    )
    details = {
        "parser": "windows-srum-import",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": path.suffix.lower().lstrip("."),
        "source_hashes": file_hashes(path),
        "source_index": index,
        "app_id": app_id,
        "executable_path": app_id if looks_like_executable_path(app_id) else "",
        "user": user,
        "timestamp": timestamp,
        "timestamp_source": "srum_import_timestamp",
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "bytes_total": bytes_total,
        "cpu_time": cpu_time,
        "energy_usage": energy,
        "interface_luid": interface_luid,
        "network_profile": network_profile,
        "srum_table_family": "network-usage" if artifact_type == "srum-network-usage" else "app-resource",
        "srum_usage_evidence": srum_usage_evidence(
            artifact_type=artifact_type,
            app_id=app_id,
            user=user,
            timestamp=timestamp,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            cpu_time=cpu_time,
            energy=energy,
            interface_luid=interface_luid,
            network_profile=network_profile,
        ),
        "srum_report_citation_manifest": srum_report_citation_manifest(
            source_path=str(path.resolve()),
            source_hashes=file_hashes(path),
            artifact_type=artifact_type,
            artifact_scope="source-tool-export",
            source_format=path.suffix.lower().lstrip("."),
            source_index=index,
            table_family="network-usage" if artifact_type == "srum-network-usage" else "app-resource",
            app_id=app_id,
            timestamp=timestamp,
            counters={
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "bytes_total": bytes_total,
                "cpu_time": cpu_time,
                "energy_usage": energy,
            },
            source_offset=0,
            row_cluster_evidence={},
            report_grade=report_grade,
        ),
        "parser_confidence": 0.82,
        "evidence_strength": "application-resource-usage-indicator",
        "validation_required": False,
        "validation_checks": validation_checks,
        "execution_validation_matrix": execution_validation_matrix(validation_checks),
        "execution_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "execution_native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
        "execution_analyst_review_profile": execution_analyst_review_profile(
            artifact_type=artifact_type,
            source_format=path.suffix.lower().lstrip("."),
            validation_checks=validation_checks,
            report_grade=report_grade,
            risk_flags=risk_flags,
            evidence_fields={
                "app_id": app_id,
                "executable_path": app_id if looks_like_executable_path(app_id) else "",
                "user": user,
                "timestamp": timestamp,
                "bytes_total": bytes_total,
                "network_profile": network_profile,
            },
        ),
        "forensic_review": build_forensic_review(
            gap_id="#10",
            artifact_goal="SRUM source-tool usage export",
            primary_evidence=[
                f"app={app_id}" if app_id else "",
                f"timestamp={timestamp}" if timestamp else "",
                f"bytes_total={bytes_total}" if bytes_total else "",
                f"user={user}" if user else "",
            ],
            validation_required=False,
            report_grade_assessment=report_grade,
            commercial_grade_ready=False,
            caveats=["Source-tool SRUM exports still require provenance validation for testimony."],
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 20),
        "raw": dict(row),
        "raw_preview": json.dumps(row, ensure_ascii=False, sort_keys=True)[:2000],
    }
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type=artifact_type,
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def srum_database_evidence(
    ese_header: Mapping[str, object],
    native_validation: Mapping[str, object],
    table_candidates: list[Mapping[str, object]],
    row_candidates: list[Mapping[str, object]],
    pivots: Mapping[str, object],
) -> dict[str, object]:
    return {
        "ese_signature_valid": bool(ese_header.get("signature_valid")),
        "page_size": int(ese_header.get("page_size") or 0),
        "validation_status": str(native_validation.get("validation_status") or ""),
        "table_candidate_count": len(table_candidates),
        "row_candidate_count": len(row_candidates),
        "path_pivot_count": len(pivots.get("path_candidates") or []),
        "url_pivot_count": len(pivots.get("url_candidates") or []),
        "schema_decode_status": "not-implemented-header-and-string-pivot-only",
        "row_level_decode_status": "not-implemented",
        "report_grade_ready": False,
        "validation_required": True,
    }


def srum_pivot_evidence(candidate_kind: str, candidate_value: str, executable_path: str, url: str) -> dict[str, object]:
    return {
        "candidate_kind": candidate_kind,
        "candidate_value": candidate_value,
        "normalized_path": normalize_execution_path(executable_path),
        "url": url,
        "pivot_basis": "native-ese-string-pivot",
        "counter_decode_status": "not-row-decoded",
        "timestamp_decode_status": "not-row-decoded",
        "validation_required": True,
    }


def srum_row_evidence(candidate: Mapping[str, object]) -> dict[str, object]:
    counters = candidate.get("counter_candidates") if isinstance(candidate.get("counter_candidates"), Mapping) else {}
    field_presence = (
        candidate.get("field_presence_profile")
        if isinstance(candidate.get("field_presence_profile"), Mapping)
        else {}
    )
    return {
        "candidate_basis": str(candidate.get("candidate_basis") or "bounded-native-string-row-cluster"),
        "source_offset": int(candidate.get("source_offset") or 0),
        "source_encoding": str(candidate.get("source_encoding") or ""),
        "cluster_window_bytes": int(candidate.get("cluster_window_bytes") or 0),
        "nearby_string_count": int(candidate.get("nearby_string_count") or 0),
        "nearby_offsets": [int(value) for value in candidate.get("nearby_offsets") or []][:100],
        "table_family": str(candidate.get("table_family") or "unknown"),
        "has_app_id": bool(candidate.get("app_id")),
        "has_timestamp_candidate": bool(candidate.get("timestamp")),
        "field_presence_profile": dict(field_presence),
        "counter_candidate_names": sorted(str(key) for key in counters),
        "counter_candidate_count": len(counters),
        "row_cluster_quality": "multi-string-context" if int(candidate.get("nearby_string_count") or 0) > 1 else "single-string-context",
        "row_level_decode_status": "not-implemented-string-cluster-only",
        "validation_required": True,
        "report_grade_ready": False,
    }


def srum_usage_evidence(
    *,
    artifact_type: str,
    app_id: str,
    user: str,
    timestamp: str,
    bytes_sent: int | float,
    bytes_received: int | float,
    cpu_time: int | float,
    energy: int | float,
    interface_luid: str,
    network_profile: str,
) -> dict[str, object]:
    return {
        "table_family": "network-usage" if artifact_type == "srum-network-usage" else "app-resource",
        "app_id": app_id,
        "user": user,
        "timestamp": timestamp,
        "counter_fields_present": sorted(
            name
            for name, value in {
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "cpu_time": cpu_time,
                "energy_usage": energy,
                "interface_luid": interface_luid,
                "network_profile": network_profile,
            }.items()
            if value
        ),
        "counter_normalization_status": "normalized-from-source-tool-export",
        "source_tool_export_validation_required": True,
        "report_grade_ready": False,
    }


def srum_report_citation_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    artifact_type: str,
    artifact_scope: str,
    source_format: str,
    source_index: int,
    table_family: str,
    app_id: str,
    timestamp: str,
    counters: Mapping[str, object],
    source_offset: int,
    row_cluster_evidence: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    normalized_app = normalize_execution_path(app_id) if looks_like_executable_path(app_id) else app_id.lower()
    counter_map = {str(key): value for key, value in counters.items() if value not in ("", None, 0)}
    row_identity = {
        "artifact_scope": artifact_scope,
        "source_format": source_format,
        "source_index": source_index,
        "source_offset": source_offset,
        "table_family": table_family,
        "app_id": app_id,
        "normalized_app": normalized_app,
        "timestamp": timestamp,
        "timestamp_semantics": "source-tool-export-timestamp" if artifact_scope == "source-tool-export" else "native-string-candidate-not-row-decoded",
        "counter_names": sorted(counter_map),
    }
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "srum-source",
            "ref_id": "srum-source",
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_format": source_format,
            "source_viewer_locator": {
                "viewer": "table-row" if artifact_scope == "source-tool-export" else "source-hex",
                "source_index": source_index,
                "source_offset": source_offset,
            },
        },
        {
            "kind": "srum-table-or-app",
            "ref_id": "srum-table-or-app",
            "table_family": table_family,
            "app_id": app_id,
            "normalized_app_hash": stable_execution_json_sha256(normalized_app),
        },
        {
            "kind": "srum-counter-semantics",
            "ref_id": "srum-counter-semantics",
            "counter_names": sorted(counter_map),
            "counters": counter_map,
            "counter_decode_status": "source-tool-normalized" if artifact_scope == "source-tool-export" else "native-row-not-decoded",
        },
    ]
    if timestamp:
        citation_refs.append(
            {
                "kind": "srum-timestamp",
                "ref_id": "srum-timestamp",
                "timestamp": timestamp,
                "timestamp_semantics": row_identity["timestamp_semantics"],
            }
        )
    if row_cluster_evidence:
        citation_refs.append(
            {
                "kind": "srum-row-cluster",
                "ref_id": "srum-row-cluster",
                "cluster_status": row_cluster_evidence.get("row_level_decode_status")
                or row_cluster_evidence.get("cluster_status")
                or "bounded-native-context",
                "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                "nearby_string_count": row_cluster_evidence.get("nearby_string_count", 0),
                "nearby_offsets": list(row_cluster_evidence.get("nearby_offsets") or row_cluster_evidence.get("source_offsets") or [])[:25],
                "source_viewer_locator": {
                    "viewer": "source-hex",
                    "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                    "length": row_cluster_evidence.get("cluster_window_bytes", ESE_SCAN_READ_SIZE),
                },
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "srum-report-citation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "artifact_type": artifact_type,
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": source_format,
        },
        "row_identity": row_identity,
        "row_identity_hash": stable_execution_json_sha256(row_identity),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or ["#10"]),
            "native_ese_catalog_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_ese_catalog_decode"]),
            "native_srum_page_row_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_srum_page_row_decode"]),
            "trusted_srum_parser_diff_required": artifact_scope != "source-tool-export",
        },
        "reportability": {
            "allowed_use": "srum-usage-triage-pivot",
            "standalone_execution_proof": False,
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "blockers": sorted(
                set(str(item) for item in report_grade.get("blockers") or [])
                | {"native-ese-page-row-decoding-required", "trusted-srum-parser-diff-required"}
            ),
        },
    }
    manifest["manifest_sha256"] = stable_execution_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def srum_candidate_risk_flags(prefix: str, value: str) -> list[str]:
    lowered = value.lower()
    return [
        f"{prefix}:{term}"
        for term in SUSPICIOUS_COMMAND_TERMS
        if term in lowered or (" " not in term and term.split()[0] in lowered)
    ]


def build_execution_summary(root: Path, records: Iterable[ArtifactRecord]) -> ArtifactRecord | None:
    groups: dict[str, dict[str, object]] = {}
    report_grade_status_counts: dict[str, int] = {}
    for record in records:
        details = record.details
        assessment = (
            details.get("execution_report_grade_assessment")
            if isinstance(details.get("execution_report_grade_assessment"), Mapping)
            else {}
        )
        if assessment:
            status = str(assessment.get("status") or "unknown")
            report_grade_status_counts[status] = report_grade_status_counts.get(status, 0) + 1
        key = execution_group_key(record.artifact_type, details)
        if not key:
            continue
        group = groups.setdefault(
            key,
            {
                "executable_key": key,
                "display_name": display_name_for_execution_key(key),
                "signal_count": 0,
                "signal_types": set(),
                "evidence_strengths": set(),
                "users": set(),
                "timestamps": set(),
                "risk_flags": set(),
                "source_paths": set(),
                "command_line_samples": [],
                "validation_required_count": 0,
                "correlation_targets": set(),
                "source_formats": set(),
                "source_artifact_refs": [],
            },
        )
        group["signal_count"] = int(group["signal_count"]) + 1
        cast_set(group["signal_types"]).add(record.artifact_type)
        if details.get("evidence_strength"):
            cast_set(group["evidence_strengths"]).add(str(details["evidence_strength"]))
        if details.get("user"):
            cast_set(group["users"]).add(str(details["user"]))
        if details.get("timestamp"):
            cast_set(group["timestamps"]).add(str(details["timestamp"]))
        if details.get("source_path"):
            cast_set(group["source_paths"]).add(str(details["source_path"]))
        if details.get("source_format"):
            cast_set(group["source_formats"]).add(str(details["source_format"]))
        refs = group.get("source_artifact_refs")
        if isinstance(refs, list) and len(refs) < 25:
            refs.append(
                {
                    "artifact_type": record.artifact_type,
                    "source_path": str(details.get("source_path") or ""),
                    "source_format": str(details.get("source_format") or ""),
                    "timestamp": str(details.get("timestamp") or ""),
                    "evidence_strength": str(details.get("evidence_strength") or ""),
                    "validation_required": bool(details.get("validation_required")),
                }
            )
        for flag in details.get("risk_flags", []):
            cast_set(group["risk_flags"]).add(str(flag))
        if details.get("validation_required"):
            group["validation_required_count"] = int(group["validation_required_count"]) + 1
        checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
        for target in checks.get("correlation_targets", []) if isinstance(checks.get("correlation_targets"), list) else []:
            cast_set(group["correlation_targets"]).add(str(target))
        command_line = str(details.get("command_line") or "")
        samples = group["command_line_samples"]
        if command_line and isinstance(samples, list) and command_line not in samples and len(samples) < 3:
            samples.append(command_line)
    if not groups:
        return None

    normalized_groups = [normalize_execution_group(group) for group in groups.values()]
    normalized_groups.sort(key=lambda item: (-int(item["signal_count"]), str(item["display_name"]).lower()))
    correlation_profile = execution_summary_correlation_profile(normalized_groups)
    return ArtifactRecord(
        provider=WindowsExecutionProvider.name,
        artifact_type="windows-execution-summary",
        path=str(root.resolve()),
        supported=True,
        details={
            "parser": "windows-execution-summary",
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(root.resolve()),
            "group_count": len(normalized_groups),
            "groups": normalized_groups,
            "execution_correlation_profile": correlation_profile,
            "native_capabilities": EXECUTION_NATIVE_CAPABILITIES,
            "report_grade_status_counts": counter_items_from_mapping(report_grade_status_counts),
            "report_grade_blockers": EXECUTION_REPORT_GRADE_BLOCKERS,
            "reporting_note": "Summary groups execution-related signals; review each source artifact before concluding proof of execution.",
        },
    )


def execution_group_key(artifact_type: str, details: Mapping[str, object]) -> str:
    executable_path = str(details.get("executable_path") or "").strip()
    if executable_path:
        return normalize_execution_path(executable_path)
    command_line = str(details.get("command_line") or "").strip()
    if command_line:
        return normalize_command_execution_key(command_line)
    key = str(details.get("key") or "").strip()
    if key:
        return normalize_execution_path(key.rsplit("\\", 1)[-1])
    return artifact_type


def execution_artifact_metadata(artifact_type: str, key: str, values: Mapping[str, str]) -> dict[str, object]:
    if artifact_type == "amcache-entry":
        return {
            "artifact_family": "amcache",
            "parser_confidence": 0.82,
            "validation_required": True,
            "validation_guidance": "Amcache indicates program presence/install/execution-related metadata depending on source fields; validate timestamps and hashes with a dedicated parser.",
            "execution_caveat": "Amcache is not always direct proof of execution.",
            "commercial_grade_ready": False,
            "commercial_grade_blockers": ["native-amcache-schema-decoding-required", "timestamp-semantic-validation-required"],
        }
    if artifact_type == "shimcache-entry":
        return {
            "artifact_family": "shimcache",
            "parser_confidence": 0.78,
            "validation_required": True,
            "validation_guidance": "ShimCache/AppCompatCache is useful for program presence/order and sometimes timestamps, but it is not direct proof of execution.",
            "execution_caveat": "Presence in ShimCache is not proof the executable ran.",
            "commercial_grade_ready": False,
            "commercial_grade_blockers": ["native-appcompatcache-layout-decoding-required", "os-version-specific-validation-required"],
        }
    if artifact_type == "bam-entry":
        return {
            "artifact_family": "bam-dam",
            "parser_confidence": 0.86,
            "validation_required": False,
            "validation_guidance": "BAM/DAM values commonly indicate recent execution by user SID; correlate with Prefetch, SRUM, UserAssist, and event logs.",
            "execution_caveat": "BAM/DAM should be correlated with other execution artifacts for final conclusions.",
            "commercial_grade_ready": False,
            "commercial_grade_blockers": ["native-system-hive-bam-decoding-required", "broad-windows-version-validation-required"],
        }
    return {"artifact_family": artifact_type, "parser_confidence": 0.74, "validation_required": False}


def extract_execution_fields(artifact_type: str, key: str, values: Mapping[str, str]) -> dict[str, object]:
    lowered = {normalize_key(name): value for name, value in values.items()}
    if artifact_type == "amcache-entry":
        return {
            "executable_path": str(first_value(lowered, "path", "fullpath", "filepath", "filename") or ""),
            "program_name": str(first_value(lowered, "name", "programname", "filename") or display_name_for_execution_key(key)),
            "publisher": str(first_value(lowered, "publisher", "companyname", "company") or ""),
            "sha1": first_hash_value(values, 40),
            "file_description": str(first_value(lowered, "filedescription", "description") or ""),
            "product_name": str(first_value(lowered, "productname", "product") or ""),
        }
    if artifact_type == "shimcache-entry":
        return {
            "executable_path": extract_executable_path(key, values),
            "program_name": display_name_for_execution_key(extract_executable_path(key, values) or key),
            "publisher": "",
            "sha1": "",
            "file_description": "",
            "product_name": "",
        }
    return {"executable_path": extract_executable_path(key, values)}


def amcache_entry_evidence(
    *,
    source_format: str,
    source_key: str,
    executable_path: str,
    execution_fields: Mapping[str, object],
    timestamp: str,
    timestamp_source: str,
    decoded_values: Mapping[str, str],
    sha1_candidates: list[str] | None = None,
) -> dict[str, object]:
    sha1 = str(execution_fields.get("sha1") or "")
    candidate_hashes = sorted(set([sha1, *list(sha1_candidates or [])]) - {""})
    metadata_fields = [
        field
        for field in ("program_name", "publisher", "file_description", "product_name")
        if str(execution_fields.get(field) or "")
    ]
    return {
        "source_format": source_format,
        "source_key": source_key,
        "normalized_path": normalize_execution_path(executable_path),
        "file_name": execution_file_name(executable_path),
        "path_present": bool(executable_path),
        "sha1": sha1,
        "sha1_candidates": candidate_hashes,
        "hash_present": bool(candidate_hashes),
        "metadata_fields_present": metadata_fields,
        "metadata_field_count": len(metadata_fields),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": amcache_timestamp_semantics(timestamp_source, source_format),
        "source_value_names": sorted(str(key) for key in decoded_values),
        "source_value_count": len(decoded_values),
        "execution_caveat": "Amcache supports program presence/install/execution-related pivots but is not standalone proof of execution.",
        "report_grade_ready": False,
        "validation_required": True,
    }


def amcache_schema_profile(
    *,
    source_format: str,
    timestamp_source: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    executable_path: str,
    sha1: str,
) -> dict[str, object]:
    reportability_decision = execution_reportability_decision(
        artifact_type="amcache-entry",
        artifact_scope="amcache-reg-export" if source_format == "reg" else "amcache-native-hive",
        report_grade=report_grade,
        validation_checks=validation_checks,
    )
    return {
        "profile_version": "amcache-schema-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "readiness_item_number": 15,
        "qc_prep_item_number": QC_PREP_EXECUTION_ITEM_NUMBERS["amcache-entry"],
        "qc_prep_item_goal": "Deepen Amcache schema/version decoding and timestamp semantics.",
        "commercial_gap_id": "#7",
        "artifact_family": "amcache",
        "source_format": source_format,
        "current_decode_level": "reg-export-mapping" if source_format == "reg" else "native-string-pivot-only",
        "qc_prep_contract": {
            "implemented": [
                "reg-export Amcache row mapping",
                "native Amcache.hve bounded path/hash string pivots",
                "path, SHA1, publisher, product, description, and timestamp-source normalization",
                "row citation manifest and reportability decision",
            ],
            "usable_outputs": ["amcache-entry", "amcache-hive"],
            "validated_by_current_tests": [
                "trusted AmcacheParser-style row diff helper",
                "metadata mismatch blocking",
                "timestamp-source and not-standalone-execution wording",
            ],
            "not_report_grade_until": [
                "native Amcache schema row decoder is implemented by Windows build",
                "timestamp semantics are validated with known-answer fixtures",
                "trusted parser diffs are attached for the case evidence",
            ],
        },
        "schema_components": {
            "inventory_application_file": True,
            "inventory_application": True,
            "root_file_paths": bool(executable_path),
            "sha1_candidates": bool(sha1 or validation_checks.get("has_hash_candidates")),
            "native_schema_row_decode": bool(EXECUTION_NATIVE_CAPABILITIES["native_amcache_schema_decode"]),
            "timestamp_semantics_validated": timestamp_source not in {"", "not_available_native_string_pivot"}
            and not bool(validation_checks.get("requires_second_parser_validation")),
        },
        "timestamp_semantics": amcache_timestamp_semantics(timestamp_source, source_format),
        "reportability_decision": reportability_decision,
        "evidence_fields": {
            "executable_path": executable_path,
            "sha1": sha1,
            "timestamp_source": timestamp_source,
        },
        "execution_artifact_validation_profile": execution_artifact_validation_profile(
            artifact_family="amcache",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={
                "executable_path": executable_path,
                "sha1": sha1,
                "timestamp_source": timestamp_source,
            },
        ),
        "required_independent_checks": [
            "validate Amcache.hve schema map by Windows build",
            "decode row-level timestamps and distinguish install/presence/execution-related semantics",
            "cross-check hash/path with MFT, Prefetch, BAM/DAM, UserAssist, and event logs",
            "run known-answer fixtures for AmcacheParser/RECmd parity",
        ],
        "standalone_execution_proof": False,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": list(report_grade.get("blockers") or []),
    }


def amcache_hive_evidence(
    path_candidates: list[str],
    sha1_candidates: list[str],
    strings: list[str],
    clusters: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    cluster_rows = list(clusters or [])
    return {
        "candidate_path_count": len(path_candidates),
        "candidate_sha1_count": len(sha1_candidates),
        "candidate_row_cluster_count": len(cluster_rows),
        "clustered_path_count": sum(1 for cluster in cluster_rows if cluster.get("executable_path")),
        "clustered_hash_count": sum(1 for cluster in cluster_rows if cluster.get("sha1_candidates")),
        "clustered_timestamp_candidate_count": sum(1 for cluster in cluster_rows if cluster.get("timestamp_candidates")),
        "candidate_program_names": sorted({display_name_for_execution_key(path) for path in path_candidates if path})[:100],
        "schema_decode_status": "not-implemented-string-pivot-only",
        "row_cluster_status": "bounded-nearby-string-clusters" if cluster_rows else "not-available",
        "row_cluster_window_bytes": AMCACHE_ROW_CLUSTER_WINDOW_BYTES,
        "string_sample_count": min(len(strings), 25),
        "report_grade_ready": False,
        "validation_required": True,
        "commercial_grade_blockers": ["native-amcache-schema-decoding-required", "row-level-timestamp-extraction-required"],
    }


def amcache_row_cluster_evidence(cluster: Mapping[str, object]) -> dict[str, object]:
    if not cluster:
        return {
            "cluster_status": "not-available",
            "validation_required": True,
            "report_grade_ready": False,
        }
    return {
        "cluster_status": "bounded-nearby-string-cluster",
        "source_offset": int(cluster.get("source_offset") or 0),
        "source_encoding": str(cluster.get("source_encoding") or ""),
        "cluster_window_bytes": AMCACHE_ROW_CLUSTER_WINDOW_BYTES,
        "nearby_string_count": int(cluster.get("nearby_string_count") or 0),
        "nearby_offsets": [int(value) for value in cluster.get("nearby_offsets", []) if str(value).isdigit()][:25]
        if isinstance(cluster.get("nearby_offsets"), list)
        else [],
        "sha1_candidates": [str(value) for value in cluster.get("sha1_candidates", [])][:25]
        if isinstance(cluster.get("sha1_candidates"), list)
        else [],
        "timestamp_candidates": [str(value) for value in cluster.get("timestamp_candidates", [])][:25]
        if isinstance(cluster.get("timestamp_candidates"), list)
        else [],
        "metadata_candidates": [str(value) for value in cluster.get("metadata_candidates", [])][:25]
        if isinstance(cluster.get("metadata_candidates"), list)
        else [],
        "schema_decode_status": "not-implemented-cluster-only",
        "row_level_timestamp_status": (
            "nearby-string-timestamp-candidate" if cluster.get("timestamp_candidates") else "not-row-decoded"
        ),
        "validation_required": True,
        "report_grade_ready": False,
        "reportability_warning": (
            "Nearby Amcache strings preserve review pivots, not decoded InventoryApplicationFile row semantics. "
            "Validate with AmcacheParser/RECmd before report-grade use."
        ),
    }


def amcache_report_citation_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    source_format: str,
    source_key: str,
    source_index: int,
    executable_path: str,
    sha1_candidates: Sequence[str],
    timestamp: str,
    timestamp_source: str,
    source_offset: int,
    row_cluster_evidence: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    normalized_path = normalize_execution_path(executable_path)
    row_identity = {
        "source_format": source_format,
        "source_key": source_key,
        "source_index": source_index,
        "executable_path": executable_path,
        "normalized_path": normalized_path,
        "file_name": execution_file_name(executable_path),
        "sha1_candidates": sorted({str(value).lower() for value in sha1_candidates if str(value)}),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": amcache_timestamp_semantics(timestamp_source, source_format),
        "source_offset": source_offset,
    }
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "amcache-source",
            "ref_id": "amcache-source",
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_format": source_format,
            "source_viewer_locator": {
                "viewer": "registry-export" if source_format == "reg" else "source-hex",
                "source_key": source_key,
                "source_offset": source_offset,
            },
        },
        {
            "kind": "amcache-program-identity",
            "ref_id": "amcache-program-identity",
            "normalized_path_sha256": stable_execution_json_sha256(normalized_path),
            "sha1_candidates": row_identity["sha1_candidates"],
            "file_name": row_identity["file_name"],
        },
        {
            "kind": "amcache-timestamp-semantics",
            "ref_id": "amcache-timestamp-semantics",
            "timestamp": timestamp,
            "timestamp_source": timestamp_source,
            "timestamp_semantics": row_identity["timestamp_semantics"],
            "standalone_execution_proof": False,
        },
    ]
    if row_cluster_evidence:
        citation_refs.append(
            {
                "kind": "amcache-row-cluster",
                "ref_id": "amcache-row-cluster",
                "cluster_status": row_cluster_evidence.get("cluster_status", ""),
                "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                "cluster_window_bytes": row_cluster_evidence.get("cluster_window_bytes", 0),
                "nearby_string_count": row_cluster_evidence.get("nearby_string_count", 0),
                "nearby_offsets": list(row_cluster_evidence.get("nearby_offsets") or [])[:25],
                "source_viewer_locator": {
                    "viewer": "source-hex",
                    "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                    "length": row_cluster_evidence.get("cluster_window_bytes", AMCACHE_ROW_CLUSTER_WINDOW_BYTES),
                },
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "amcache-report-citation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "artifact_type": "amcache-entry",
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": source_format,
        },
        "row_identity": row_identity,
        "row_identity_hash": stable_execution_json_sha256(row_identity),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or ["#7"]),
            "timestamp_semantics_validated": False,
            "native_schema_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_amcache_schema_decode"]),
        },
        "reportability": {
            "allowed_use": "program-presence-install-execution-related-pivot",
            "standalone_execution_proof": False,
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "blockers": list(report_grade.get("blockers") or []),
        },
    }
    manifest["manifest_sha256"] = stable_execution_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def amcache_schema_version_profile(
    *,
    source_format: str,
    source_key: str,
    executable_path: str,
    execution_fields: Mapping[str, object],
    timestamp_source: str,
    decoded_values: Mapping[str, str],
    row_cluster_evidence: Mapping[str, object],
) -> dict[str, object]:
    haystack = " ".join(
        [
            source_key,
            source_format,
            executable_path,
            " ".join(str(key) for key in decoded_values),
            " ".join(str(value) for value in decoded_values.values()),
            " ".join(str(value) for value in row_cluster_evidence.get("metadata_candidates") or []),
        ]
    ).lower()
    if "inventoryapplicationfile" in haystack:
        schema_family = "inventory-application-file"
        windows_generation_hint = "windows-10-11"
        expected_fields = ["path", "sha1", "publisher", "file_description", "product_name"]
    elif "inventoryapplication" in haystack:
        schema_family = "inventory-application"
        windows_generation_hint = "windows-10-11"
        expected_fields = ["program_name", "publisher"]
    elif "root\\file" in haystack or "\\file\\" in haystack:
        schema_family = "root-file"
        windows_generation_hint = "windows-8-8.1-early-10"
        expected_fields = ["path", "sha1"]
    elif source_format == "amcache-hive":
        schema_family = "native-string-pivot-unresolved"
        windows_generation_hint = "unknown-native-hive"
        expected_fields = ["path", "sha1", "schema_marker"]
    else:
        schema_family = "registry-export-unclassified"
        windows_generation_hint = "unknown-export"
        expected_fields = ["path", "sha1"]

    present_fields: set[str] = set()
    if executable_path:
        present_fields.add("path")
    if str(execution_fields.get("program_name") or ""):
        present_fields.add("program_name")
    if str(execution_fields.get("publisher") or ""):
        present_fields.add("publisher")
    if str(execution_fields.get("file_description") or ""):
        present_fields.add("file_description")
    if str(execution_fields.get("product_name") or ""):
        present_fields.add("product_name")
    if str(execution_fields.get("sha1") or "") or row_cluster_evidence.get("sha1_candidates"):
        present_fields.add("sha1")
    if "inventoryapplication" in haystack or "root\\file" in haystack or source_format == "amcache-hive":
        present_fields.add("schema_marker")
    if timestamp_source and timestamp_source != "not_available_native_string_pivot":
        present_fields.add("timestamp")

    missing_expected = [field for field in expected_fields if field not in present_fields]
    confidence = 0.35
    if schema_family not in {"registry-export-unclassified", "native-string-pivot-unresolved"}:
        confidence += 0.2
    confidence += min(0.3, len(present_fields) * 0.05)
    if row_cluster_evidence.get("cluster_status") == "bounded-nearby-string-cluster":
        confidence += 0.08

    return {
        "profile_version": "amcache-schema-version-profile-v1",
        "commercial_gap_id": "#7",
        "source_format": source_format,
        "source_key": source_key,
        "detected_schema_family": schema_family,
        "windows_generation_hint": windows_generation_hint,
        "decode_level": "registry-export-mapped" if source_format == "reg" else "native-string-pivot-only",
        "expected_fields": expected_fields,
        "present_fields": sorted(present_fields),
        "missing_expected_fields": missing_expected,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": amcache_timestamp_semantics(timestamp_source, source_format),
        "row_cluster_status": str(row_cluster_evidence.get("cluster_status") or "not-available"),
        "confidence": round(min(confidence, 0.9), 2),
        "validation_required": True,
        "schema_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_amcache_schema_decode"]),
        "commercial_grade_blockers": sorted(
            {
                "native-amcache-schema-decoding-required",
                "amcache-windows-version-schema-map-required",
                "amcache-timestamp-semantics-validation-required",
            }
        ),
    }


def amcache_row_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    source_format: str,
    source_key: str,
    source_index: int,
    executable_path: str,
    sha1_candidates: Sequence[str],
    timestamp: str,
    timestamp_source: str,
    source_offset: int,
    row_cluster_evidence: Mapping[str, object],
    schema_version_profile: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    required_fields = execution_diff_required_fields("amcache")
    row_identity = {
        "source_format": source_format,
        "source_key": source_key,
        "source_index": source_index,
        "source_offset": source_offset,
        "executable_path": executable_path,
        "normalized_path": normalize_execution_path(executable_path),
        "file_name": execution_file_name(executable_path),
        "sha1_candidates": sorted({str(value).lower() for value in sha1_candidates if str(value)}),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": amcache_timestamp_semantics(timestamp_source, source_format),
    }
    row_manifest: dict[str, object] = {
        "manifest_version": "amcache-row-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_gap_id": "#7",
        "artifact_type": "amcache-entry",
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": source_format,
        },
        "row_identity": row_identity,
        "row_identity_hash": stable_execution_json_sha256(row_identity),
        "schema_version_profile": dict(schema_version_profile),
        "source_viewer_locator": {
            "viewer": "registry-export" if source_format == "reg" else "source-hex",
            "source_key": source_key,
            "source_offset": source_offset,
            "length": row_cluster_evidence.get("cluster_window_bytes", AMCACHE_ROW_CLUSTER_WINDOW_BYTES)
            if row_cluster_evidence
            else 0,
        },
        "trusted_diff_contract": {
            "profile_version": "execution-artifact-trusted-diff-v1",
            "artifact_family": "amcache",
            "compare_fields": list(EXECUTION_DIFF_COMPARE_FIELDS),
            "required_fields": required_fields,
        },
        "validation_summary": {
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or ["#7"]),
            "native_schema_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_amcache_schema_decode"]),
            "trusted_parser_diff_required": True,
            "timestamp_semantics_validated": False,
            "row_cluster_status": str(row_cluster_evidence.get("cluster_status") or "not-available"),
        },
        "reportability": {
            "allowed_use": "program-presence-install-execution-related-pivot",
            "standalone_execution_proof": False,
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "blockers": sorted(
                set(str(item) for item in report_grade.get("blockers") or [])
                | {
                    "amcache-timestamp-semantics-validation-required",
                    "amcache-trusted-parser-diff-required",
                }
            ),
        },
        "large_data_controls": {
            "bounded_native_string_scan_bytes": MAX_NATIVE_AMCACHE_SCAN_BYTES,
            "row_cluster_window_bytes": AMCACHE_ROW_CLUSTER_WINDOW_BYTES,
            "native_row_decode_required_for_commercial_claims": True,
        },
    }
    row_manifest["manifest_sha256"] = stable_execution_json_sha256(
        {key: value for key, value in row_manifest.items() if key != "manifest_sha256"}
    )
    return row_manifest


def shimcache_row_cluster_evidence(cluster: Mapping[str, object]) -> dict[str, object]:
    if not cluster:
        return {
            "cluster_status": "not-available",
            "validation_required": True,
            "report_grade_ready": False,
        }
    return {
        "cluster_status": "bounded-native-string-cluster",
        "source_offset": int(cluster.get("source_offset") or 0),
        "source_encoding": str(cluster.get("source_encoding") or ""),
        "cluster_window_bytes": SHIMCACHE_ROW_CLUSTER_WINDOW_BYTES,
        "cache_order": int(cluster.get("cache_order") or 0),
        "nearby_string_count": int(cluster.get("nearby_string_count") or 0),
        "nearby_offsets": [int(value) for value in cluster.get("nearby_offsets", []) if str(value).isdigit()][:25]
        if isinstance(cluster.get("nearby_offsets"), list)
        else [],
        "timestamp_candidates": [str(value) for value in cluster.get("timestamp_candidates", [])][:25]
        if isinstance(cluster.get("timestamp_candidates"), list)
        else [],
        "nearby_metadata_candidates": [str(value) for value in cluster.get("nearby_metadata_candidates", [])][:25]
        if isinstance(cluster.get("nearby_metadata_candidates"), list)
        else [],
        "row_layout_decode_status": "not-implemented-cluster-only",
        "timestamp_semantics": (
            "nearby-string-timestamp-candidate-not-execution-proof"
            if cluster.get("timestamp_candidates")
            else "not-available"
        ),
        "validation_required": True,
        "report_grade_ready": False,
        "reportability_warning": (
            "Native ShimCache/AppCompatCache string clusters preserve program path/order pivots only. "
            "They must not be reported as standalone execution proof without OS-build layout decoding, "
            "trusted parser diff, and cross-artifact correlation."
        ),
    }


def shimcache_report_citation_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    source_format: str,
    source_key: str,
    source_index: int,
    executable_path: str,
    timestamp: str,
    timestamp_source: str,
    source_offset: int,
    cache_order: int | None,
    row_cluster_evidence: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    normalized_path = normalize_execution_path(executable_path)
    row_identity = {
        "source_format": source_format,
        "source_key": source_key,
        "source_index": source_index,
        "source_offset": source_offset,
        "cache_order": cache_order,
        "executable_path": executable_path,
        "normalized_path": normalized_path,
        "file_name": execution_file_name(executable_path),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": "os-version-dependent-and-not-proof-of-execution" if timestamp else "not-available",
    }
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "shimcache-source",
            "ref_id": "shimcache-source",
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_format": source_format,
            "source_viewer_locator": {
                "viewer": "registry-export" if source_format == "reg" else "source-hex",
                "source_key": source_key,
                "source_offset": source_offset,
            },
        },
        {
            "kind": "shimcache-program-identity",
            "ref_id": "shimcache-program-identity",
            "normalized_path_sha256": stable_execution_json_sha256(normalized_path),
            "file_name": row_identity["file_name"],
            "standalone_execution_proof": False,
        },
        {
            "kind": "shimcache-cache-order-or-timestamp",
            "ref_id": "shimcache-cache-order-or-timestamp",
            "cache_order": cache_order,
            "timestamp": timestamp,
            "timestamp_source": timestamp_source,
            "timestamp_semantics": row_identity["timestamp_semantics"],
            "interpretation": "program-presence-cache-order-pivot",
            "standalone_execution_proof": False,
        },
        {
            "kind": "shimcache-caveat",
            "ref_id": "shimcache-caveat",
            "warning": "Presence in ShimCache/AppCompatCache is not proof the executable ran.",
            "required_correlation": execution_correlation_targets("shimcache-entry"),
        },
    ]
    if row_cluster_evidence:
        citation_refs.append(
            {
                "kind": "shimcache-row-cluster",
                "ref_id": "shimcache-row-cluster",
                "cluster_status": row_cluster_evidence.get("cluster_status", ""),
                "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                "cache_order": row_cluster_evidence.get("cache_order", cache_order),
                "cluster_window_bytes": row_cluster_evidence.get("cluster_window_bytes", 0),
                "nearby_string_count": row_cluster_evidence.get("nearby_string_count", 0),
                "nearby_offsets": list(row_cluster_evidence.get("nearby_offsets") or [])[:25],
                "source_viewer_locator": {
                    "viewer": "source-hex",
                    "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                    "length": row_cluster_evidence.get("cluster_window_bytes", SHIMCACHE_ROW_CLUSTER_WINDOW_BYTES),
                },
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "shimcache-report-citation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "artifact_type": "shimcache-entry",
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": source_format,
        },
        "row_identity": row_identity,
        "row_identity_hash": stable_execution_json_sha256(row_identity),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or ["#8"]),
            "native_binary_layout_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_shimcache_binary_decode"]),
            "os_build_layout_validation_required": True,
            "trusted_parser_diff_required": True,
        },
        "reportability": {
            "allowed_use": "program-presence-cache-order-pivot",
            "standalone_execution_proof": False,
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "blockers": sorted(
                set(str(item) for item in report_grade.get("blockers") or [])
                | {"shimcache-not-proof-of-execution", "os-build-layout-validation-required"}
            ),
        },
    }
    manifest["manifest_sha256"] = stable_execution_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_execution_json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def execution_file_name(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1]


def amcache_timestamp_semantics(timestamp_source: str, source_format: str) -> str:
    if not timestamp_source:
        return "not-available"
    if source_format == "amcache-hive":
        return "native-string-pivot-does-not-prove-row-timestamp"
    lowered = timestamp_source.lower()
    if "key" in lowered:
        return "registry-key-timestamp-candidate"
    if "value" in lowered or "timestamp" in lowered:
        return "exported-amcache-field-timestamp-candidate"
    return "timestamp-candidate-validation-required"


def execution_artifact_validation_profile(
    *,
    artifact_family: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    evidence_fields: Mapping[str, object],
) -> dict[str, object]:
    family_caveats = {
        "amcache": "presence/install/execution-related pivot, not standalone execution proof",
        "shimcache-appcompatcache": "presence/cache-order pivot; never standalone proof of execution",
        "bam-dam": "recent execution pivot that still needs ControlSet/SID and cross-artifact correlation",
        "srum-srudb-ese": "resource/network/application usage pivot requiring ESE row-level validation",
    }
    return {
        "profile_version": "execution-artifact-validation-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 15,
        "artifact_family": artifact_family,
        "normalized_row_contract": {
            "source_path_required": True,
            "parser_version_required": True,
            "timestamp_semantics_required": True,
            "execution_caveat_required": True,
            "correlation_targets_required": True,
            "validation_matrix_required": True,
        },
        "evidence_fields": dict(evidence_fields),
        "validation_summary": {
            "passed_check_count": sum(1 for value in validation_checks.values() if bool(value)),
            "failed_check_names": sorted(str(key) for key, value in validation_checks.items() if not bool(value)),
            "report_grade_status": str(report_grade.get("status") or ""),
        },
        "analyst_caveat": family_caveats.get(artifact_family, "execution artifact requires source-specific validation"),
        "required_before_report": [
            "cross-correlate with at least one independent execution artifact family",
            "preserve timestamp semantics and source artifact limitation wording in report citations",
            "diff critical rows against trusted parser output or known-answer fixtures",
            "validate Windows build/version-specific binary layouts where native decoding is used",
        ],
        "large_data_controls": {
            "normalized_row_is_small": True,
            "raw_binary_payloads_are_not_expanded": True,
            "safe_for_case_db_indexing": True,
        },
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": sorted(set(report_grade.get("blockers") or []) | {"execution-artifact-trusted-diff-required"}),
    }


def execution_analyst_review_profile(
    *,
    artifact_type: str,
    source_format: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    risk_flags: Sequence[str] | None = None,
    evidence_fields: Mapping[str, object] | None = None,
) -> dict[str, object]:
    catalog = EXECUTION_ANALYST_REVIEW_CATALOG.get(artifact_type) or {
        "severity": "info",
        "summary": "Windows execution-related artifact requiring source-specific validation.",
        "evidence_interpretation": "execution-related pivot",
        "not_proof_of": ["standalone execution without corroboration"],
        "primary_pivots": ["executable_path", "timestamp", "user_sid"],
        "correlation_targets": execution_correlation_targets(artifact_type),
        "analyst_questions": [
            "What independent artifact can corroborate this row?",
            "Are timestamp semantics and parser limitations preserved?",
            "Does a trusted parser or known-answer fixture confirm the row?",
        ],
        "risk_tags": ["execution-review"],
    }
    evidence_fields = dict(evidence_fields or {})
    source_values: dict[str, object] = {}
    for pivot in catalog.get("primary_pivots", []):
        pivot_name = str(pivot)
        value = evidence_fields.get(pivot_name)
        if value not in ("", None, [], {}):
            source_values[pivot_name] = bounded_execution_value(value)

    blockers = sorted(
        set(str(item) for item in report_grade.get("blockers", []) if str(item))
        | {"execution-artifact-trusted-diff-required"}
    )
    failed_checks = sorted(str(key) for key, value in validation_checks.items() if not bool(value))
    return {
        "profile_version": "execution-analyst-review-profile-v1",
        "artifact_type": artifact_type,
        "source_format": source_format,
        "severity": str(catalog.get("severity") or "info"),
        "summary": str(catalog.get("summary") or ""),
        "evidence_interpretation": str(catalog.get("evidence_interpretation") or ""),
        "not_proof_of": list(catalog.get("not_proof_of") or []),
        "analyst_questions": list(catalog.get("analyst_questions") or []),
        "primary_pivots": list(catalog.get("primary_pivots") or []),
        "source_field_values": source_values,
        "correlation_targets": list(catalog.get("correlation_targets") or execution_correlation_targets(artifact_type)),
        "risk_tags": sorted(set([str(item) for item in catalog.get("risk_tags", [])] + [str(item) for item in risk_flags or []])),
        "validation_required": bool(report_grade.get("status") != "report-grade-ready" or failed_checks),
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": blockers,
        "report_guidance": (
            "Use this row as an execution/resource-usage review pivot. Final reporting requires source hash, "
            "timestamp semantics, parser limitation wording, and trusted parser or known-answer validation."
        ),
    }


def bounded_execution_value(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        text = str(value)
        return text[:1000] if len(text) > 1000 else value
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)[:1000]
    if len(text) <= 2000:
        return value
    return {"truncated_json_preview": text[:2000], "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def shimcache_entry_evidence(
    *,
    key: str,
    executable_path: str,
    timestamp: str,
    timestamp_source: str,
    decoded_values: Mapping[str, str],
    source_format: str = "reg",
    source_offset: int | None = None,
    cache_order: int | None = None,
    nearby_metadata_candidates: Sequence[str] | None = None,
) -> dict[str, object]:
    return {
        "source_key": key,
        "source_format": source_format,
        "source_offset": source_offset,
        "cache_order": cache_order,
        "normalized_path": normalize_execution_path(executable_path),
        "file_name": execution_file_name(executable_path),
        "path_present": bool(executable_path),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": "shimcache-timestamp-is-version-dependent-and-not-proof-of-execution" if timestamp else "not-available",
        "source_value_names": sorted(str(name) for name in decoded_values),
        "source_value_count": len(decoded_values),
        "nearby_metadata_candidates": list(nearby_metadata_candidates or [])[:25],
        "native_scan_status": "bounded-path-cluster" if source_format != "reg" else "registry-export-row",
        "row_layout_decode_status": "not-implemented-native-layout-required" if source_format != "reg" else "source-export-mapping",
        "execution_caveat": "ShimCache/AppCompatCache can show program presence/order, but it is not standalone proof of execution.",
        "requires_os_version_layout_validation": True,
        "report_grade_ready": False,
        "validation_required": True,
    }


def shimcache_execution_caveat_profile(
    *,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    executable_path: str,
    timestamp: str,
    source_format: str = "reg",
) -> dict[str, object]:
    reportability_decision = execution_reportability_decision(
        artifact_type="shimcache-entry",
        artifact_scope="shimcache-export" if source_format == "reg" else "system-hive-native-shimcache-scan",
        report_grade=report_grade,
        validation_checks=validation_checks,
    )
    return {
        "profile_version": "shimcache-caveat-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "readiness_item_number": 15,
        "qc_prep_item_number": QC_PREP_EXECUTION_ITEM_NUMBERS["shimcache-entry"],
        "qc_prep_item_goal": (
            "Deepen ShimCache/AppCompatCache OS-version binary layouts and preserve the "
            "not-direct-execution-proof analyst warning."
        ),
        "commercial_gap_id": "#8",
        "artifact_family": "shimcache-appcompatcache",
        "source_format": source_format,
        "current_decode_level": "reg-export-mapping" if source_format == "reg" else "native-system-hive-string-pivot",
        "qc_prep_contract": {
            "implemented": [
                "reg-export ShimCache mapping",
                "native SYSTEM hive bounded AppCompatCache path cluster scan",
                "cache-order, source-offset, timestamp-candidate, and caveat preservation",
                "trusted-diff helper that compares path/order/offset/timestamp/warning",
            ],
            "usable_outputs": ["shimcache-entry"],
            "validated_by_current_tests": [
                "native cluster order/offset preservation",
                "trusted AppCompatCacheParser-style diff pass",
                "order mismatch blocking",
                "not-proof-of-execution UX wording",
            ],
            "not_report_grade_until": [
                "OS-build-specific binary AppCompatCache layouts are decoded",
                "malformed layout fixtures and known-answer image diffs pass",
                "execution claims are corroborated by independent artifacts",
            ],
        },
        "standalone_execution_proof": False,
        "interpretation": "program-presence-and-cache-order-candidate",
        "timestamp_semantics": "os-version-dependent-and-not-proof-of-execution" if timestamp else "not-available",
        "reportability_decision": reportability_decision,
        "decoded_components": {
            "path_candidate": bool(executable_path),
            "timestamp_candidate": bool(timestamp),
            "cache_order_candidate": bool(validation_checks.get("has_cache_order")),
            "source_offset_candidate": bool(validation_checks.get("has_source_offset") or validation_checks.get("has_source_offsets")),
            "native_binary_layout_decode": bool(EXECUTION_NATIVE_CAPABILITIES["native_shimcache_binary_decode"]),
            "correlation_required": bool(validation_checks.get("requires_correlation", True)),
        },
        "evidence_fields": {
            "executable_path": executable_path,
            "timestamp": timestamp,
        },
        "execution_artifact_validation_profile": execution_artifact_validation_profile(
            artifact_family="shimcache-appcompatcache",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={"executable_path": executable_path, "timestamp": timestamp},
        ),
        "required_independent_checks": [
            "select AppCompatCache binary layout by OS build",
            "validate cache order and timestamp interpretation against known-answer images",
            "correlate with Prefetch, Amcache, BAM/DAM, UserAssist, SRUM, and Event Logs before execution claims",
            "preserve the UX warning that ShimCache is not proof of execution",
        ],
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": list(report_grade.get("blockers") or []),
    }


def bam_dam_entry_evidence(
    *,
    key: str,
    executable_path: str,
    user_sid: str,
    timestamp: str,
    timestamp_source: str,
    decoded_values: Mapping[str, str],
    source_format: str = "reg",
    source_offset: int | None = None,
    nearby_metadata_candidates: Sequence[str] | None = None,
) -> dict[str, object]:
    return {
        "source_key": key,
        "source_format": source_format,
        "source_offset": source_offset,
        "normalized_path": normalize_execution_path(executable_path),
        "file_name": execution_file_name(executable_path),
        "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
        "user_sid": user_sid,
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": "bam-dam-last-execution-filetime-candidate" if timestamp_source == "bam_value_filetime" else "timestamp-candidate-validation-required",
        "source_value_names": sorted(str(name) for name in decoded_values),
        "source_value_count": len(decoded_values),
        "nearby_metadata_candidates": list(nearby_metadata_candidates or [])[:25],
        "native_scan_status": "bounded-path-sid-cluster" if source_format != "reg" else "registry-export-row",
        "row_layout_decode_status": "not-implemented-native-layout-required" if source_format != "reg" else "source-export-mapping",
        "execution_caveat": "BAM/DAM is a strong recent-execution pivot but should be correlated with Prefetch, SRUM, UserAssist, and event logs.",
        "requires_native_system_hive_validation": True,
        "report_grade_ready": False,
        "validation_required": True,
    }


def bam_dam_decode_profile(
    *,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    executable_path: str,
    user_sid: str,
    timestamp: str,
    timestamp_source: str,
    source_format: str = "reg",
) -> dict[str, object]:
    reportability_decision = execution_reportability_decision(
        artifact_type="bam-entry",
        artifact_scope="bam-dam-export" if source_format == "reg" else "system-hive-native-bam-dam-scan",
        report_grade=report_grade,
        validation_checks=validation_checks,
    )
    return {
        "profile_version": "bam-dam-decode-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "readiness_item_number": 15,
        "qc_prep_item_number": QC_PREP_EXECUTION_ITEM_NUMBERS["bam-entry"],
        "qc_prep_item_goal": "Deepen BAM/DAM binary value decoding and SID/path/timestamp correlation.",
        "commercial_gap_id": "#9",
        "artifact_family": "bam-dam",
        "source_format": source_format,
        "current_decode_level": "reg-export-mapping" if source_format == "reg" else "native-system-hive-string-pivot",
        "qc_prep_contract": {
            "implemented": [
                "reg-export BAM/DAM row mapping",
                "native SYSTEM hive bounded SID/path/timestamp cluster scan",
                "device-path, user SID, FILETIME/timestamp-source, ControlSet, and source-offset normalization",
                "trusted-diff helper that compares SID, device path, timestamp, source key, and warning",
            ],
            "usable_outputs": ["bam-entry"],
            "validated_by_current_tests": [
                "native cluster SID/path/timestamp/source extraction",
                "trusted RECmd-style BAM/DAM diff pass",
                "SID mismatch blocking",
            ],
            "not_report_grade_until": [
                "native BAM/DAM binary value layout is decoded by Windows build",
                "ControlSet and rotated/disabled BAM edge cases are known-answer tested",
                "recent execution is correlated with Prefetch, SRUM, UserAssist, or Event Logs",
            ],
        },
        "decoded_components": {
            "sid": bool(user_sid),
            "path": bool(executable_path),
            "filetime_timestamp": timestamp_source == "bam_value_filetime" and bool(timestamp),
            "native_system_hive_binary_decode": bool(EXECUTION_NATIVE_CAPABILITIES["native_bam_system_hive_decode"]),
        },
        "timestamp_semantics": "bam-dam-last-execution-filetime-candidate"
        if timestamp_source == "bam_value_filetime"
        else "timestamp-candidate-validation-required",
        "reportability_decision": reportability_decision,
        "evidence_fields": {
            "user_sid": user_sid,
            "executable_path": executable_path,
            "timestamp": timestamp,
            "timestamp_source": timestamp_source,
        },
        "execution_artifact_validation_profile": execution_artifact_validation_profile(
            artifact_family="bam-dam",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={
                "user_sid": user_sid,
                "executable_path": executable_path,
                "timestamp": timestamp,
                "timestamp_source": timestamp_source,
            },
        ),
        "required_independent_checks": [
            "decode SYSTEM hive BAM/DAM binary values natively",
            "validate SID/path/timestamp by Windows build and ControlSet",
            "correlate recent-execution claims with Prefetch, SRUM, Amcache, UserAssist, and Event Logs",
            "test broad Windows versions and disabled/rotated BAM edge cases",
        ],
        "standalone_execution_proof": True,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": list(report_grade.get("blockers") or []),
    }


def bam_dam_row_cluster_evidence(cluster: Mapping[str, object]) -> dict[str, object]:
    if not cluster:
        return {
            "cluster_status": "not-available",
            "validation_required": True,
            "report_grade_ready": False,
        }
    return {
        "cluster_status": "bounded-native-string-cluster",
        "source_offset": int(cluster.get("source_offset") or 0),
        "source_encoding": str(cluster.get("source_encoding") or ""),
        "cluster_window_bytes": BAM_DAM_ROW_CLUSTER_WINDOW_BYTES,
        "user_sid": str(cluster.get("user_sid") or ""),
        "nearby_string_count": int(cluster.get("nearby_string_count") or 0),
        "nearby_offsets": [int(value) for value in cluster.get("nearby_offsets", []) if str(value).isdigit()][:25]
        if isinstance(cluster.get("nearby_offsets"), list)
        else [],
        "timestamp_candidates": [str(value) for value in cluster.get("timestamp_candidates", [])][:25]
        if isinstance(cluster.get("timestamp_candidates"), list)
        else [],
        "nearby_metadata_candidates": [str(value) for value in cluster.get("nearby_metadata_candidates", [])][:25]
        if isinstance(cluster.get("nearby_metadata_candidates"), list)
        else [],
        "row_layout_decode_status": "not-implemented-cluster-only",
        "timestamp_semantics": (
            "nearby-string-timestamp-candidate-requires-filetime-row-validation"
            if cluster.get("timestamp_candidates")
            else "not-available"
        ),
        "validation_required": True,
        "report_grade_ready": False,
        "reportability_warning": (
            "Native BAM/DAM string clusters preserve SID/path/timestamp pivots only. "
            "Report-grade recent-execution claims need native SYSTEM hive binary value decoding, "
            "ControlSet validation, and cross-artifact correlation."
        ),
    }


def bam_dam_report_citation_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    source_format: str,
    source_key: str,
    source_index: int,
    executable_path: str,
    user_sid: str,
    timestamp: str,
    timestamp_source: str,
    source_offset: int,
    row_cluster_evidence: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    normalized_path = normalize_execution_path(executable_path)
    row_identity = {
        "source_format": source_format,
        "source_key": source_key,
        "source_index": source_index,
        "source_offset": source_offset,
        "user_sid": user_sid,
        "executable_path": executable_path,
        "device_path": executable_path if executable_path.lower().startswith("\\device\\") else "",
        "normalized_path": normalized_path,
        "file_name": execution_file_name(executable_path),
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "timestamp_semantics": "bam-dam-last-execution-filetime-candidate"
        if timestamp_source == "bam_value_filetime"
        else "timestamp-candidate-validation-required",
    }
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "bam-dam-source",
            "ref_id": "bam-dam-source",
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_format": source_format,
            "source_viewer_locator": {
                "viewer": "registry-export" if source_format == "reg" else "source-hex",
                "source_key": source_key,
                "source_offset": source_offset,
            },
        },
        {
            "kind": "bam-dam-user-sid",
            "ref_id": "bam-dam-user-sid",
            "user_sid": user_sid,
            "sid_present": bool(user_sid),
        },
        {
            "kind": "bam-dam-program-identity",
            "ref_id": "bam-dam-program-identity",
            "normalized_path_sha256": stable_execution_json_sha256(normalized_path),
            "file_name": row_identity["file_name"],
            "device_path": row_identity["device_path"],
        },
        {
            "kind": "bam-dam-timestamp",
            "ref_id": "bam-dam-timestamp",
            "timestamp": timestamp,
            "timestamp_source": timestamp_source,
            "timestamp_semantics": row_identity["timestamp_semantics"],
            "required_validation": "native FILETIME row decode and ControlSet attribution",
        },
    ]
    if row_cluster_evidence:
        citation_refs.append(
            {
                "kind": "bam-dam-row-cluster",
                "ref_id": "bam-dam-row-cluster",
                "cluster_status": row_cluster_evidence.get("cluster_status", ""),
                "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                "cluster_window_bytes": row_cluster_evidence.get("cluster_window_bytes", 0),
                "nearby_string_count": row_cluster_evidence.get("nearby_string_count", 0),
                "nearby_offsets": list(row_cluster_evidence.get("nearby_offsets") or [])[:25],
                "source_viewer_locator": {
                    "viewer": "source-hex",
                    "source_offset": row_cluster_evidence.get("source_offset", source_offset),
                    "length": row_cluster_evidence.get("cluster_window_bytes", BAM_DAM_ROW_CLUSTER_WINDOW_BYTES),
                },
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "bam-dam-report-citation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "artifact_type": "bam-entry",
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": source_format,
        },
        "row_identity": row_identity,
        "row_identity_hash": stable_execution_json_sha256(row_identity),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or ["#9"]),
            "native_system_hive_binary_decode_available": bool(EXECUTION_NATIVE_CAPABILITIES["native_bam_system_hive_decode"]),
            "controlset_validation_required": True,
            "trusted_parser_diff_required": True,
        },
        "reportability": {
            "allowed_use": "recent-execution-pivot-corroborate-before-testimony",
            "standalone_execution_proof": False,
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "blockers": sorted(
                set(str(item) for item in report_grade.get("blockers") or [])
                | {"bam-dam-native-system-hive-validation-required", "cross-artifact-correlation-required"}
            ),
        },
    }
    manifest["manifest_sha256"] = stable_execution_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def srum_ese_validation_profile(
    *,
    artifact_scope: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    evidence_fields: Mapping[str, object],
) -> dict[str, object]:
    reportability_decision = execution_reportability_decision(
        artifact_type="srum-row-candidate" if artifact_scope == "row-candidate" else "srum-database-file",
        artifact_scope=artifact_scope,
        report_grade=report_grade,
        validation_checks=validation_checks,
    )
    return {
        "profile_version": "srum-ese-validation-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "readiness_item_number": 15,
        "qc_prep_item_number": QC_PREP_EXECUTION_ITEM_NUMBERS["srum-database-file"],
        "qc_prep_item_goal": "Deepen SRUM native ESE table/page decoding and counter semantics.",
        "commercial_gap_id": "#10",
        "artifact_family": "srum-srudb-ese",
        "artifact_scope": artifact_scope,
        "current_decode_level": "source-export-or-native-header-string-candidate",
        "qc_prep_contract": {
            "implemented": [
                "SrumECmd-style source export mapping",
                "native SRUDB.dat ESE header probe",
                "bounded table marker, string pivot, and row-candidate clustering",
                "counter/timestamp semantics labeling and citation manifest",
            ],
            "usable_outputs": [
                "srum-network-usage",
                "srum-app-resource-usage",
                "srum-database-file",
                "srum-database-pivot",
                "srum-table-candidate",
                "srum-row-candidate",
            ],
            "validated_by_current_tests": [
                "source export counter normalization",
                "native row candidate field presence profile",
                "trusted SrumECmd-style counter diff helper",
                "counter mismatch blocking",
            ],
            "not_report_grade_until": [
                "native ESE catalog/page/tagged-column decoder is implemented",
                "SRUM table GUID schemas are mapped by Windows build",
                "row-level counters/timestamps/SIDs/app IDs are trusted-diff validated",
                "large SRUDB cursor pagination is stress tested",
            ],
        },
        "decoded_components": {
            "ese_header": bool(validation_checks.get("ese_header_readable") or artifact_scope != "database"),
            "ese_signature": bool(validation_checks.get("ese_signature_valid") or artifact_scope != "database"),
            "table_family_candidates": bool(validation_checks.get("has_native_srum_table_candidates") or artifact_scope == "table-candidate"),
            "row_string_candidates": bool(validation_checks.get("has_native_srum_row_candidates") or artifact_scope == "row-candidate"),
            "row_level_decoding": bool(validation_checks.get("row_level_decoding_available")),
            "native_catalog_decoding": bool(validation_checks.get("native_table_catalog_decoding_available")),
        },
        "evidence_fields": dict(evidence_fields),
        "execution_artifact_validation_profile": execution_artifact_validation_profile(
            artifact_family="srum-srudb-ese",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields=evidence_fields,
        ),
        "reportability_decision": reportability_decision,
        "required_independent_checks": [
            "decode ESE catalog pages and tagged columns",
            "map SRUM table GUIDs to Windows build-specific schemas",
            "decode row-level timestamps, SIDs, app IDs, counters, and network profiles",
            "validate 100k+ row cursor behavior against SrumECmd/libesedb known-answer outputs",
            "document counter units and timezone normalization before report export",
        ],
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": list(report_grade.get("blockers") or []),
    }


def execution_reportability_decision(
    *,
    artifact_type: str,
    artifact_scope: str,
    report_grade: Mapping[str, object],
    validation_checks: Mapping[str, object],
) -> dict[str, object]:
    gap_ids = execution_gap_ids(artifact_type)
    gap_id = gap_ids[0] if gap_ids else "#10"
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    if artifact_type == "amcache-entry":
        allowed_use = "program-presence-install-execution-related-pivot"
        decision = "do-not-report-as-standalone-execution"
        blockers.add("amcache-timestamp-semantics-validation-required")
    elif artifact_type == "shimcache-entry":
        allowed_use = "program-presence-cache-order-pivot"
        decision = "do-not-report-as-execution-proof"
        blockers.add("shimcache-not-proof-of-execution")
    elif artifact_type == "bam-entry":
        allowed_use = "recent-execution-pivot-corroborate-before-testimony"
        decision = "report-only-with-correlation"
        blockers.add("bam-dam-native-system-hive-validation-required")
    else:
        allowed_use = "srum-usage-triage-pivot"
        decision = "do-not-report-native-row-as-decoded-fact"
        blockers.add("srum-native-row-decoder-validation-required")
    if validation_checks.get("requires_second_parser_validation") or validation_checks.get("requires_srum_parser"):
        blockers.add("trusted-tool-diff-required")
    return {
        "profile_version": "windows-execution-reportability-decision-v1",
        "commercial_gap_id": gap_id,
        "artifact_type": artifact_type,
        "artifact_scope": artifact_scope,
        "decision": decision,
        "allowed_use": allowed_use,
        "standalone_execution_proof": artifact_type == "bam-entry" and not bool(validation_checks.get("requires_correlation")),
        "blockers": sorted(blockers),
        "required_before_report": [
            "source hash and parser version captured",
            "artifact-specific timestamp semantics validated",
            "trusted-tool or known-answer diff attached",
            "correlated with at least one independent execution artifact where semantics require it",
        ],
    }


def execution_core_accuracy_gates(artifact_type: str, details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"source_index:{details.get('source_index', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")
    amcache_manifest_hash = str(details.get("amcache_row_manifest_hash") or "")
    if amcache_manifest_hash:
        evidence_refs.append(f"amcache_row_manifest_sha256:{amcache_manifest_hash}")

    if artifact_type == "amcache-hive":
        artifact_type = "amcache-entry"
    trusted_diff = (
        details.get("execution_trusted_diff")
        if isinstance(details.get("execution_trusted_diff"), Mapping)
        else {}
    )

    if artifact_type == "amcache-entry":
        satisfied: list[str] = []
        if details.get("source_format") or checks.get("native_schema_decoding_available") is not None:
            satisfied.append("schema-version detection")
        if details.get("executable_path") or details.get("sha1") or details.get("sha1_candidates") or details.get("publisher"):
            satisfied.append("path/hash/publisher extraction")
        if details.get("source_offset") or checks.get("has_row_cluster_candidate") or checks.get("has_row_cluster_candidates"):
            satisfied.append("bounded Amcache row-cluster provenance")
        if amcache_manifest_hash:
            satisfied.append("stable Amcache row manifest")
        if details.get("timestamp_source") or checks.get("has_timestamp") or checks.get("requires_second_parser_validation"):
            satisfied.append("timestamp source labeling")
        satisfied.append("execution caveat wording")
        if checks.get("requires_second_parser_validation") or not EXECUTION_NATIVE_CAPABILITIES["native_amcache_schema_decode"]:
            satisfied.append("deleted/legacy schema fallback warnings")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted Amcache parser diff pass")
        return [build_accuracy_gate(7, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    if artifact_type == "shimcache-entry":
        satisfied = []
        if checks.get("requires_correlation") or not EXECUTION_NATIVE_CAPABILITIES["native_shimcache_binary_decode"]:
            satisfied.append("OS layout selection")
        if details.get("executable_path") or details.get("timestamp"):
            satisfied.append("path/timestamp/flag decoding")
        if details.get("source_offset") is not None or checks.get("has_source_offset") or checks.get("has_source_offsets"):
            satisfied.append("bounded native AppCompatCache path provenance")
        if details.get("cache_order") is not None or checks.get("has_cache_order"):
            satisfied.append("cache order preservation")
        if details.get("source_key") or details.get("source_index", "") != "":
            satisfied.append("entry order preservation")
        satisfied.append("not-proof-of-execution warning")
        if not EXECUTION_NATIVE_CAPABILITIES["native_shimcache_binary_decode"]:
            satisfied.append("malformed binary bounds checks")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted ShimCache parser diff pass")
        return [build_accuracy_gate(8, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    if artifact_type == "bam-entry":
        satisfied = []
        if details.get("user_sid") or checks.get("has_user"):
            satisfied.append("SID extraction")
        if details.get("device_path") or details.get("executable_path"):
            satisfied.append("device path normalization")
        if details.get("timestamp") or checks.get("has_timestamp"):
            satisfied.append("FILETIME validity")
        if details.get("source_offset") is not None or checks.get("has_source_offset"):
            satisfied.append("bounded native BAM/DAM path provenance")
        if "CurrentControlSet" in str(details.get("source_key") or ""):
            satisfied.append("ControlSet attribution")
        satisfied.append("execution-semantics warning")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted BAM/DAM parser diff pass")
        return [build_accuracy_gate(9, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    if artifact_type.startswith("srum-"):
        satisfied = []
        native_validation = (
            details.get("native_srudb_validation")
            if isinstance(details.get("native_srudb_validation"), Mapping)
            else {}
        )
        if native_validation.get("page_size_plausible") or checks.get("ese_signature_valid"):
            satisfied.append("ESE page checksum validation")
        if details.get("table_family") or details.get("table_candidate_count") or checks.get("has_native_srum_table_candidates"):
            satisfied.append("catalog/table mapping")
        if details.get("counter_candidates") or details.get("bytes_sent") or details.get("bytes_received") or checks.get("has_counter_candidates"):
            satisfied.append("tagged column decoding")
        if details.get("timestamp") or checks.get("has_timestamp_candidate") or details.get("energy_usage") or details.get("cpu_time"):
            satisfied.append("counter/timestamp semantics")
        if details.get("row_candidate_count") or artifact_type == "srum-row-candidate":
            satisfied.append("native-row confidence scoring")
        if details.get("nearby_string_count") or checks.get("has_srum_row_cluster_context"):
            satisfied.append("bounded SRUM row-cluster context")
        if details.get("field_presence_profile") or checks.get("has_srum_field_presence_profile"):
            satisfied.append("SRUM field presence profile")
        if trusted_diff.get("status") == "pass":
            satisfied.append("trusted SRUM parser row diff pass")
        return [build_accuracy_gate(10, satisfied_checks=satisfied, evidence_refs=evidence_refs)]

    return []


def execution_commercial_uplift_evidence(artifact_type: str, details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("execution_validation_matrix") if isinstance(details.get("execution_validation_matrix"), list) else []
    report_grade = (
        details.get("execution_report_grade_assessment")
        if isinstance(details.get("execution_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("execution_trusted_diff")
        if isinstance(details.get("execution_trusted_diff"), Mapping)
        else {}
    )
    reportability_decision: Mapping[str, object] = {}
    for profile_key in (
        "amcache_schema_profile",
        "shimcache_execution_caveat_profile",
        "bam_dam_decode_profile",
        "srum_ese_validation_profile",
    ):
        profile = details.get(profile_key) if isinstance(details.get(profile_key), Mapping) else {}
        decision = profile.get("reportability_decision") if isinstance(profile.get("reportability_decision"), Mapping) else {}
        if decision:
            reportability_decision = decision
            break
    if not reportability_decision:
        validation_checks = (
            details.get("validation_checks")
            if isinstance(details.get("validation_checks"), Mapping)
            else {}
        )
        reportability_decision = execution_reportability_decision(
            artifact_type="amcache-entry" if artifact_type == "amcache-hive" else artifact_type,
            artifact_scope=str(details.get("source_format") or artifact_type),
            report_grade=report_grade,
            validation_checks=validation_checks,
        )
    gap_ids = execution_gap_ids(artifact_type)
    item_numbers = [int(gap_id.lstrip("#")) for gap_id in gap_ids if gap_id.lstrip("#").isdigit()]
    qc_prep_item_number = QC_PREP_EXECUTION_ITEM_NUMBERS.get(artifact_type, 25 if artifact_type.startswith("srum-") else 0)
    return {
        "batch_id": "commercial-uplift-006-010",
        "item_numbers": item_numbers,
        "qc_prep_item_numbers": [qc_prep_item_number] if qc_prep_item_number else [],
        "implementation_track": "native-parser-depth",
        "objective": "Expose execution-artifact validation evidence, commercial blockers, and large-data limits on each #7-#10 / QC-prep #22-#25 row.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_index:{details.get('source_index', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"source_format:{details.get('source_format', '')}",
            f"amcache_row_manifest_sha256:{details.get('amcache_row_manifest_hash', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": dict(reportability_decision),
        "trusted_diff": {
            "status": str(trusted_diff.get("status") or "not-attached"),
            "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            "matched_count": int(trusted_diff.get("matched_count") or 0),
            "mismatch_count": int(trusted_diff.get("mismatch_count") or 0),
            "missing_in_trusted_count": int(trusted_diff.get("missing_in_trusted_count") or 0),
            "extra_in_trusted_count": int(trusted_diff.get("extra_in_trusted_count") or 0),
            "commercial_grade_evidence": bool(trusted_diff.get("commercial_grade_evidence")),
        },
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "bounded_native_string_scan_bytes": MAX_NATIVE_AMCACHE_SCAN_BYTES
            if artifact_type in {"amcache-entry", "amcache-hive"}
            else MAX_NATIVE_SHIMCACHE_SCAN_BYTES if artifact_type == "shimcache-entry"
            else MAX_NATIVE_BAM_DAM_SCAN_BYTES if artifact_type == "bam-entry"
            else ESE_SCAN_READ_SIZE if artifact_type.startswith("srum-") else 0,
            "row_level_native_decode_required_for_commercial_claims": artifact_type.startswith("srum-"),
            "native_binary_layout_required_for_commercial_claims": artifact_type in {"shimcache-entry", "bam-entry"},
            "schema_version_matrix_required": artifact_type in {"amcache-entry", "amcache-hive", "shimcache-entry"},
        },
        "next_internal_step": (
            "Add native binary/schema row decoding plus cross-tool known-answer diffs before removing "
            "#7-#10 commercial blockers."
        ),
        "external_evidence_required": True,
    }


def first_hash_value(values: Mapping[str, str], length: int) -> str:
    for name, value in values.items():
        haystack = f"{name} {value}"
        match = re.search(rf"(?i)\b[0-9a-f]{{{length}}}\b", haystack)
        if match:
            return match.group(0).lower()
    return ""


def execution_validation_checks(
    artifact_type: str,
    executable_path: str,
    timestamp: str,
    values: Mapping[str, str],
) -> dict[str, object]:
    return {
        "artifact_type": artifact_type,
        "has_executable_path": bool(executable_path),
        "has_timestamp": bool(timestamp),
        "has_hash": bool(first_hash_value(values, 40)),
        "source_value_count": len(values),
        "requires_correlation": artifact_type in {"amcache-entry", "shimcache-entry"},
        "correlation_targets": execution_correlation_targets(artifact_type),
    }


def execution_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    labels = {
        "has_executable_path": ("Executable path", "high"),
        "has_timestamp": ("Timestamp", "high"),
        "has_hash": ("Hash", "medium"),
        "has_hash_candidates": ("Hash candidates", "medium"),
        "has_path_candidates": ("Path candidates", "medium"),
        "has_sha1_candidates": ("SHA1 candidates", "medium"),
        "has_row_cluster_candidates": ("Amcache row cluster candidates", "medium"),
        "has_row_cluster_candidate": ("Amcache row cluster candidate", "medium"),
        "has_source_offsets": ("Source offsets", "medium"),
        "has_source_offset": ("Source offset", "medium"),
        "has_nearby_metadata_candidates": ("Nearby metadata candidates", "medium"),
        "has_srum_row_cluster_context": ("SRUM row cluster context", "medium"),
        "has_srum_field_presence_profile": ("SRUM field presence profile", "medium"),
        "has_native_binary_path_candidates": ("Native binary path candidates", "medium"),
        "has_cache_order": ("Cache order", "medium"),
        "native_binary_layout_decoding_available": ("Native binary layout decoding", "critical"),
        "has_app_id": ("Application ID", "high"),
        "has_user": ("User", "medium"),
        "has_user_or_sid": ("User or SID", "medium"),
        "has_network_counters": ("Network counters", "high"),
        "has_resource_counters": ("Resource counters", "medium"),
        "has_counter_candidates": ("Counter candidates", "high"),
        "has_timestamp_candidate": ("Timestamp candidate", "high"),
        "has_url": ("URL", "medium"),
        "has_path_pivots": ("Path pivots", "medium"),
        "has_url_pivots": ("URL pivots", "medium"),
        "ese_header_readable": ("ESE header readable", "critical"),
        "ese_signature_valid": ("ESE signature valid", "critical"),
        "native_srudb_page_size_plausible": ("SRUDB page size plausible", "high"),
        "native_srudb_file_size_page_aligned": ("SRUDB file size page aligned", "medium"),
        "has_native_srum_table_candidates": ("Native SRUM table candidates", "medium"),
        "has_native_srum_row_candidates": ("Native SRUM row candidates", "medium"),
        "row_level_decoding_available": ("Row-level decoding", "critical"),
        "native_table_catalog_decoding_available": ("Native table catalog decoding", "critical"),
        "native_schema_decoding_available": ("Native schema decoding", "critical"),
        "counter_fields_normalized": ("Counter fields normalized", "medium"),
        "requires_correlation": ("Correlation required", "high"),
        "requires_second_parser_validation": ("Second parser validation", "high"),
        "requires_srum_parser": ("SRUM parser validation", "critical"),
        "source_tool_export_validation_required": ("Source tool export validation", "high"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key in {"artifact_type", "source_value_count", "correlation_targets"} or key.endswith("_count"):
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_") or key.endswith("_required")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append(
            {
                "id": key.replace("_", "-"),
                "label": label,
                "passed": passed,
                "severity": severity,
                "detail": value,
            }
        )
    return matrix


def execution_report_grade_assessment(
    validation_matrix: list[dict[str, object]],
    *,
    validation_required: bool,
    gap_ids: list[str],
    extra_blockers: list[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if not item.get("passed")]
    blockers = set(EXECUTION_REPORT_GRADE_BLOCKERS)
    blockers.update(f"validation-check-failed:{item}" for item in failed)
    blockers.update(extra_blockers)
    if validation_required:
        blockers.add("execution-artifact-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if item.get("passed")],
        "commercial_gap_ids": gap_ids,
        "next_validation_step": (
            "Correlate execution signals with Prefetch, SRUM, BAM/DAM, Amcache, ShimCache, Event Logs, and "
            "known-answer parser output before making report-grade execution conclusions."
        ),
    }


def build_execution_artifact_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    artifact_family: str,
) -> dict[str, object]:
    """Compare execution artifact rows with trusted parser exports at row granularity."""

    tool_name = str(trusted_tool or "").strip()
    rapid_by_key = {
        key: normalized
        for row in rapid_rows
        for key, normalized in [_normalize_execution_diff_row(row, artifact_family)]
        if key
    }
    trusted_by_key = {
        key: normalized
        for row in trusted_rows
        for key, normalized in [_normalize_execution_diff_row(row, artifact_family)]
        if key
    }
    missing = sorted(key for key in rapid_by_key if key not in trusted_by_key)
    extra = sorted(key for key in trusted_by_key if key not in rapid_by_key)
    mismatches: list[dict[str, object]] = []
    field_coverage: dict[str, object] = {}
    matched = 0
    required_fields = execution_diff_required_fields(artifact_family)
    for key in sorted(set(rapid_by_key) & set(trusted_by_key)):
        rapid = rapid_by_key[key]
        trusted = trusted_by_key[key]
        field_diffs = []
        missing_rapid = _missing_required_execution_fields(rapid, required_fields)
        missing_trusted = _missing_required_execution_fields(trusted, required_fields)
        field_coverage[key] = {
            "required_fields": required_fields,
            "rapid_present_fields": sorted(field for field in required_fields if field not in missing_rapid),
            "trusted_present_fields": sorted(field for field in required_fields if field not in missing_trusted),
            "rapid_missing_required_fields": missing_rapid,
            "trusted_missing_required_fields": missing_trusted,
        }
        for field in EXECUTION_DIFF_COMPARE_FIELDS:
            left = rapid.get(field, "")
            right = trusted.get(field, "")
            if left or right:
                if left != right:
                    field_diffs.append({"field": field, "rapid": left, "trusted": right})
        if field_diffs:
            mismatches.append({"row_key": key, "field_diffs": field_diffs})
        else:
            matched += 1
    status = "pass"
    if not tool_name or not rapid_by_key or not trusted_by_key:
        status = "not-enough-evidence"
    elif missing or extra or mismatches:
        status = "diffs-present"
    normalized_tool = re.sub(r"[^a-z0-9]+", "", tool_name.lower())
    trusted_tool_recognized = any(hint in normalized_tool for hint in EXECUTION_TRUSTED_TOOL_HINTS)
    coverage_pass = not any(
        item.get("rapid_missing_required_fields") or item.get("trusted_missing_required_fields")
        for item in field_coverage.values()
        if isinstance(item, Mapping)
    )
    commercial_grade_evidence = status == "pass" and trusted_tool_recognized and coverage_pass
    reportability_blockers = []
    if not commercial_grade_evidence:
        reportability_blockers.append("execution-artifact-trusted-diff-required")
    if not coverage_pass:
        reportability_blockers.append("execution-artifact-trusted-field-coverage-required")
    return {
        "profile_version": "execution-artifact-trusted-diff-v1",
        "artifact_family": str(artifact_family),
        "trusted_tool": tool_name,
        "trusted_tool_recognized": trusted_tool_recognized,
        "compare_fields": list(EXECUTION_DIFF_COMPARE_FIELDS),
        "required_fields": required_fields,
        "field_coverage": field_coverage,
        "rapid_row_count": len(rapid_by_key),
        "trusted_row_count": len(trusted_by_key),
        "matched_count": matched,
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "status": status,
        "commercial_grade_evidence": commercial_grade_evidence,
        "missing_in_trusted": missing[:100],
        "extra_in_trusted": extra[:100],
        "mismatches": mismatches[:100],
        "reportability_decision": {
            "decision": "execution-artifact-diff-passed" if commercial_grade_evidence else "do-not-report-execution-artifact-as-final",
            "allowed_use": (
                "support report-grade execution artifact assertions with attached parser corpus/signoff"
                if commercial_grade_evidence
                else "triage-only execution pivot until trusted parser diff is clean"
            ),
            "blockers": reportability_blockers,
        },
    }


def execution_diff_required_fields(artifact_family: str) -> list[str]:
    normalized_family = re.sub(r"[^a-z0-9-]+", "-", str(artifact_family or "").strip().lower()).strip("-")
    for family, fields in EXECUTION_DIFF_REQUIRED_FIELDS_BY_FAMILY.items():
        if normalized_family == family or family in normalized_family:
            return list(fields)
    return []


def _missing_required_execution_fields(row: Mapping[str, str], required_fields: Sequence[str]) -> list[str]:
    return [field for field in required_fields if not str(row.get(field, "")).strip()]


def _normalize_execution_diff_row(row: Mapping[str, object], artifact_family: str) -> tuple[str, dict[str, str]]:
    payload = execution_diff_row_payload(row)
    executable_path = str(
        execution_first_value(
            payload,
            "executable_path",
            "path",
            "file_path",
            "FilePath",
            "Path",
            "app_id",
            "AppId",
            "device_path",
            "DevicePath",
        )
        or ""
    ).strip()
    device_path = str(execution_first_value(payload, "device_path", "DevicePath") or "").strip().lower()
    timestamp = str(
        execution_first_value(payload, "timestamp", "last_run", "LastRun", "last_execution", "LastExecution", "LastModified")
        or ""
    ).strip().replace("Z", "+00:00")
    timestamp_source = str(execution_first_value(payload, "timestamp_source", "TimestampSource") or "").strip().lower()
    sha1 = str(execution_first_value(payload, "sha1", "SHA1", "hash", "Hash") or "").strip().lower()
    user_sid = str(execution_first_value(payload, "user_sid", "UserSid", "sid", "SID") or "").strip()
    user = str(execution_first_value(payload, "user", "User", "username", "UserName") or "").strip().lower()
    table_family = str(
        execution_first_value(payload, "table_family", "TableFamily", "srum_table_family", "SrumTableFamily") or ""
    ).strip().lower()
    url = str(execution_first_value(payload, "url", "URL", "Uri", "uri") or "").strip().lower()
    network_profile = str(execution_first_value(payload, "network_profile", "NetworkProfile", "profile", "Profile") or "").strip().lower()
    interface_luid = str(execution_first_value(payload, "interface_luid", "InterfaceLuid", "interface", "Interface") or "").strip().lower()
    bytes_sent = normalize_number_text(execution_first_value(payload, "bytes_sent", "BytesSent"))
    bytes_received = normalize_number_text(execution_first_value(payload, "bytes_received", "BytesReceived"))
    energy_usage = normalize_number_text(execution_first_value(payload, "energy_usage", "EnergyUsage"))
    cpu_time = normalize_number_text(execution_first_value(payload, "cpu_time", "CpuTime"))
    program_name = str(execution_first_value(payload, "program_name", "ProgramName", "name", "Name") or "").strip().lower()
    publisher = str(execution_first_value(payload, "publisher", "Publisher", "company", "CompanyName") or "").strip().lower()
    file_description = str(
        execution_first_value(payload, "file_description", "FileDescription", "description", "Description") or ""
    ).strip().lower()
    product_name = str(execution_first_value(payload, "product_name", "ProductName", "product", "Product") or "").strip().lower()
    source_format = str(execution_first_value(payload, "source_format", "SourceFormat") or "").strip().lower()
    source_key = str(execution_first_value(payload, "source_key", "SourceKey", "key", "Key") or "").strip().lower()
    source_offset = normalize_int_text(execution_first_value(payload, "source_offset", "SourceOffset", "offset", "Offset"))
    cache_order = normalize_int_text(execution_first_value(payload, "cache_order", "CacheOrder", "order", "Order"))
    os_build = str(execution_first_value(payload, "os_build", "OSBuild", "windows_build", "WindowsBuild") or "").strip().lower()
    counters = {
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "energy_usage": energy_usage,
        "cpu_time": cpu_time,
    }
    key_parts: tuple[object, ...] = (artifact_family, executable_path.lower(), timestamp, sha1)
    if str(artifact_family).lower() != "bam-dam":
        key_parts = (*key_parts, user_sid)
    key_basis = "|".join(str(item) for item in key_parts if item)
    if not key_basis:
        return "", {}
    counter_text = json.dumps(counters, sort_keys=True, ensure_ascii=True)
    semantics_warning = str(
        execution_first_value(payload, "execution_caveat", "semantics_warning", "warning", "Warning") or ""
    )
    return hashlib.sha256(key_basis.encode("utf-8", errors="replace")).hexdigest(), {
        "executable_path": executable_path.lower(),
        "device_path": device_path,
        "timestamp": timestamp,
        "timestamp_source": timestamp_source,
        "sha1": sha1,
        "user_sid": user_sid,
        "user": user,
        "table_family": table_family,
        "url": url,
        "network_profile": network_profile,
        "interface_luid": interface_luid,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "energy_usage": energy_usage,
        "cpu_time": cpu_time,
        "program_name": program_name,
        "publisher": publisher,
        "file_description": file_description,
        "product_name": product_name,
        "source_format": source_format,
        "source_key": source_key,
        "source_offset": source_offset,
        "cache_order": cache_order,
        "os_build": os_build,
        "counter_sha256": hashlib.sha256(counter_text.encode("utf-8")).hexdigest()
        if any(str(value) for value in counters.values())
        else "",
        "semantics_warning": re.sub(r"\s+", " ", semantics_warning).strip().lower(),
    }


def execution_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    if not details:
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    evidence = payload.get("amcache_evidence")
    if isinstance(evidence, Mapping):
        payload.setdefault("file_description", evidence.get("file_description", ""))
        payload.setdefault("program_name", evidence.get("program_name", ""))
        payload.setdefault("publisher", evidence.get("publisher", ""))
        payload.setdefault("source_key", evidence.get("source_key", ""))
        payload.setdefault("source_format", evidence.get("source_format", ""))
        payload.setdefault("source_offset", evidence.get("source_offset", ""))
        payload.setdefault("cache_order", evidence.get("cache_order", ""))
        sha1_candidates = evidence.get("sha1_candidates")
        if isinstance(sha1_candidates, Sequence) and not isinstance(sha1_candidates, (str, bytes)):
            payload.setdefault("sha1", next((str(item) for item in sha1_candidates if str(item).strip()), ""))
    manifest = payload.get("amcache_row_manifest")
    if isinstance(manifest, Mapping):
        identity = manifest.get("row_identity") if isinstance(manifest.get("row_identity"), Mapping) else {}
        payload.setdefault("source_format", identity.get("source_format", ""))
        payload.setdefault("source_key", identity.get("source_key", ""))
        payload.setdefault("source_offset", identity.get("source_offset", ""))
        payload.setdefault("executable_path", identity.get("executable_path", ""))
        payload.setdefault("timestamp", identity.get("timestamp", ""))
        payload.setdefault("timestamp_source", identity.get("timestamp_source", ""))
        sha1_candidates = identity.get("sha1_candidates")
        if isinstance(sha1_candidates, Sequence) and not isinstance(sha1_candidates, (str, bytes)):
            payload.setdefault("sha1", next((str(item) for item in sha1_candidates if str(item).strip()), ""))
    evidence = payload.get("shimcache_evidence")
    if isinstance(evidence, Mapping):
        payload.setdefault("source_key", evidence.get("source_key", ""))
        payload.setdefault("source_format", evidence.get("source_format", ""))
        payload.setdefault("source_offset", evidence.get("source_offset", ""))
        payload.setdefault("cache_order", evidence.get("cache_order", ""))
        payload.setdefault("execution_caveat", evidence.get("execution_caveat", ""))
        payload.setdefault("timestamp_source", evidence.get("timestamp_source", ""))
    evidence = payload.get("bam_dam_evidence")
    if isinstance(evidence, Mapping):
        payload.setdefault("source_key", evidence.get("source_key", ""))
        payload.setdefault("source_format", evidence.get("source_format", ""))
        payload.setdefault("source_offset", evidence.get("source_offset", ""))
        payload.setdefault("device_path", evidence.get("device_path", ""))
        payload.setdefault("user_sid", evidence.get("user_sid", ""))
        payload.setdefault("execution_caveat", evidence.get("execution_caveat", ""))
        payload.setdefault("timestamp_source", evidence.get("timestamp_source", ""))
    evidence = payload.get("srum_usage_evidence")
    if isinstance(evidence, Mapping):
        payload.setdefault("table_family", evidence.get("table_family", ""))
        payload.setdefault("app_id", evidence.get("app_id", ""))
        payload.setdefault("user", evidence.get("user", ""))
        payload.setdefault("timestamp", evidence.get("timestamp", ""))
        payload.setdefault("timestamp_source", evidence.get("timestamp_source", ""))
        counters = evidence.get("counter_values")
        if isinstance(counters, Mapping):
            payload.setdefault("bytes_sent", counters.get("bytes_sent", ""))
            payload.setdefault("bytes_received", counters.get("bytes_received", ""))
            payload.setdefault("energy_usage", counters.get("energy_usage", ""))
            payload.setdefault("cpu_time", counters.get("cpu_time", ""))
            payload.setdefault("interface_luid", counters.get("interface_luid", ""))
            payload.setdefault("network_profile", counters.get("network_profile", ""))
    evidence = payload.get("srum_row_evidence")
    if isinstance(evidence, Mapping):
        payload.setdefault("table_family", evidence.get("table_family", ""))
        counters = payload.get("counter_candidates")
        if isinstance(counters, Mapping):
            payload.setdefault("bytes_sent", counters.get("bytes_sent", ""))
            payload.setdefault("bytes_received", counters.get("bytes_received", ""))
            payload.setdefault("energy_usage", counters.get("energy_usage", ""))
            payload.setdefault("cpu_time", counters.get("cpu_time", ""))
    return payload


def execution_first_value(row: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    lowered = {str(key).lower(): value for key, value in row.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return value
    return ""


def normalize_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return text.lower()


def normalize_number_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        number = float(text)
    except ValueError:
        return text.lower()
    if number.is_integer():
        return str(int(number))
    return format(number, "g")


def execution_gap_ids(artifact_type: str) -> list[str]:
    if artifact_type in {"amcache-entry", "amcache-hive"}:
        return ["#7"]
    if artifact_type == "shimcache-entry":
        return ["#8"]
    if artifact_type == "bam-entry":
        return ["#9"]
    if artifact_type.startswith("srum-"):
        return ["#10"]
    return ["#7", "#8", "#9", "#10"]


def execution_review_goal(artifact_type: str) -> str:
    if artifact_type == "amcache-entry":
        return "Amcache program presence/install/execution-related evidence"
    if artifact_type == "shimcache-entry":
        return "ShimCache/AppCompatCache program presence caveated evidence"
    if artifact_type == "bam-entry":
        return "BAM/DAM last-execution candidate evidence"
    if artifact_type.startswith("srum-"):
        return "SRUM application/network/resource usage evidence"
    return "Windows execution artifact"


def counter_items_from_mapping(values: Mapping[str, int]) -> list[dict[str, object]]:
    return [
        {"value": key, "count": int(count)}
        for key, count in sorted(values.items(), key=lambda item: (-int(item[1]), str(item[0])))
    ]


def execution_correlation_targets(artifact_type: str) -> list[str]:
    if artifact_type == "bam-entry":
        return ["Prefetch", "SRUM", "UserAssist", "EventLog 4688/Sysmon 1"]
    if artifact_type == "shimcache-entry":
        return ["Amcache", "Prefetch", "BAM/DAM", "MFT"]
    if artifact_type == "amcache-entry":
        return ["ShimCache", "Prefetch", "BAM/DAM", "SRUM"]
    if artifact_type == "userassist-entry":
        return ["Prefetch", "BAM/DAM", "ShellBags", "Recent Files"]
    return []


def execution_risk_flags(artifact_type: str, executable_path: str, values: Mapping[str, str]) -> list[str]:
    haystack = " ".join([executable_path, *values.keys(), *values.values()]).lower()
    flags = [f"suspicious-command:{term}" for term in SUSPICIOUS_COMMAND_TERMS if term in haystack]
    flags.extend(execution_path_risk_flags(executable_path))
    if artifact_type == "shimcache-entry":
        flags.append("shimcache-not-proof-of-execution")
    if artifact_type == "bam-entry":
        flags.append("bam-execution-indicator")
    return sorted(set(flags))


def execution_path_risk_flags(path: str) -> list[str]:
    lowered = path.lower()
    flags: list[str] = []
    if "\\appdata\\" in lowered or "\\temp\\" in lowered:
        flags.append("user-writable-execution-path")
    if any(term.split()[0] in lowered for term in SUSPICIOUS_COMMAND_TERMS):
        flags.append("suspicious-executable-name")
    return flags


def user_sid_from_key(key: str) -> str:
    match = re.search(r"S-\d(?:-\d+)+", key)
    return match.group(0) if match else ""


def numeric_total(*values: object) -> int | float | str:
    total = 0.0
    for value in values:
        if isinstance(value, (int, float)):
            total += float(value)
        elif value not in ("", 0):
            return ""
    return int(total) if total.is_integer() else total


def normalize_command_execution_key(command_line: str) -> str:
    lowered = command_line.lower()
    if "powershell" in lowered:
        return "powershell.exe"
    match = re.search(r"([a-z0-9_ .:\\/-]+\.(?:exe|dll|ps1|bat|cmd|scr))", command_line, flags=re.IGNORECASE)
    if match:
        return normalize_execution_path(match.group(1).strip())
    return command_line.split(maxsplit=1)[0].lower()


def normalize_execution_path(value: str) -> str:
    cleaned = value.strip().strip('"').replace("/", "\\")
    display_name = display_name_for_execution_key(cleaned)
    return (display_name or cleaned).lower()


def display_name_for_execution_key(value: str) -> str:
    tail = value.replace("/", "\\").rsplit("\\", 1)[-1]
    return tail or value


def executable_path_from_candidate(value: str) -> str:
    match = re.search(r"(?i)([a-z]:\\[^\x00\r\n\t\"'<>|]{1,240}\.(?:exe|dll|ps1|bat|cmd|scr))", value)
    if match:
        return match.group(1)
    if re.fullmatch(r"(?i)[\w .-]+\.(?:exe|dll|ps1|bat|cmd|scr)", value.strip()):
        return value.strip()
    return ""


def first_url(value: str) -> str:
    match = re.search(r"(?i)https?://[^\s\x00\"'<>]{4,300}", value)
    return match.group(0).rstrip(".,);]") if match else ""


def cast_set(value: object) -> set[str]:
    if isinstance(value, set):
        return value
    return set()


def normalize_execution_group(group: Mapping[str, object]) -> dict[str, object]:
    signal_types = sorted(cast_set(group["signal_types"]))
    source_formats = sorted(cast_set(group.get("source_formats")))
    correlation_status = execution_group_correlation_status(signal_types)
    validation_required_count = int(group.get("validation_required_count", 0) or 0)
    return {
        "executable_key": group["executable_key"],
        "display_name": group["display_name"],
        "signal_count": group["signal_count"],
        "signal_types": signal_types,
        "evidence_strengths": sorted(cast_set(group["evidence_strengths"])),
        "users": sorted(cast_set(group["users"])),
        "timestamps": sorted(cast_set(group["timestamps"])),
        "risk_flags": sorted(cast_set(group["risk_flags"])),
        "source_paths": sorted(cast_set(group["source_paths"])),
        "source_formats": source_formats,
        "source_artifact_refs": list(group.get("source_artifact_refs") or [])[:25],
        "command_line_samples": list(group.get("command_line_samples", [])),
        "validation_required_count": validation_required_count,
        "correlation_targets": sorted(cast_set(group.get("correlation_targets"))),
        "correlation_profile": {
            "profile_version": "execution-group-correlation-v1",
            "status": correlation_status,
            "independent_signal_type_count": len(signal_types),
            "source_format_count": len(source_formats),
            "standalone_execution_claim_allowed": correlation_status == "multi-signal-corroborated"
            and validation_required_count == 0,
            "needs_review": validation_required_count > 0 or correlation_status != "multi-signal-corroborated",
            "blockers": execution_group_correlation_blockers(signal_types, validation_required_count),
        },
    }


def execution_group_correlation_status(signal_types: Sequence[str]) -> str:
    signals = set(signal_types)
    if len(signals) >= 2 and signals & {"bam-entry", "prefetch-file", "powershell-history-command", "srum-network-usage"}:
        return "multi-signal-corroborated"
    if len(signals) >= 2:
        return "multi-signal-review-required"
    return "single-signal-correlation-required"


def execution_group_correlation_blockers(signal_types: Sequence[str], validation_required_count: int) -> list[str]:
    blockers: set[str] = set()
    signals = set(signal_types)
    if len(signals) < 2:
        blockers.add("execution-cross-artifact-correlation-required")
    if "shimcache-entry" in signals:
        blockers.add("shimcache-is-not-standalone-execution-proof")
    if validation_required_count:
        blockers.add("source-artifact-validation-required")
    return sorted(blockers)


def execution_summary_correlation_profile(groups: Sequence[Mapping[str, object]]) -> dict[str, object]:
    statuses = [str((group.get("correlation_profile") or {}).get("status") or "") for group in groups]
    reportable_candidates = [
        str(group.get("display_name") or "")
        for group in groups
        if (group.get("correlation_profile") or {}).get("standalone_execution_claim_allowed")
    ]
    review_required = [
        str(group.get("display_name") or "")
        for group in groups
        if (group.get("correlation_profile") or {}).get("needs_review")
    ]
    return {
        "profile_version": "execution-summary-correlation-v1",
        "group_count": len(groups),
        "status_counts": counter_items_from_sequence(statuses),
        "reportable_candidate_count": len(reportable_candidates),
        "review_required_count": len(review_required),
        "reportable_candidates": reportable_candidates[:25],
        "review_required": review_required[:25],
        "commercial_grade_ready": False,
        "blockers": [
            "execution-known-answer-correlation-corpus-required",
            "execution-artifact-trusted-diff-required",
            "eventlog-prefetch-mft-correlation-required",
        ],
        "analyst_warning": "Treat summary correlation as a review aid; final execution conclusions require source artifact validation and trusted-tool/known-answer correlation.",
    }


def counter_items_from_sequence(values: Iterable[str]) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for value in values:
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    return counter_items_from_mapping(counts)


def iter_csv_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            yield from csv.DictReader(handle)
    except (OSError, UnicodeError, csv.Error):
        return


def iter_json_rows(path: Path) -> Iterable[Mapping[str, object]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        return
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, Mapping):
                yield row
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    rows = payload if isinstance(payload, list) else payload.get("rows", []) if isinstance(payload, Mapping) else []
    for row in rows:
        if isinstance(row, Mapping):
            yield row


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def first_value(row: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = row.get(normalize_key(key))
        if value not in (None, ""):
            return value
    return ""


def number_value(value: object) -> int | float | str:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        number = float(text)
    except ValueError:
        return text
    return int(number) if number.is_integer() else number


def parse_reg_value(line: str) -> tuple[str, str]:
    if "=" not in line:
        return "", ""
    raw_name, raw_value = line.split("=", 1)
    name = raw_name.strip().strip('"')
    value = raw_value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    elif value.lower().startswith("hex(b):"):
        parsed_time = parse_timestamp_value(value)
        value = parsed_time or value
    elif value.lower().startswith("hex:"):
        value = parse_hex_bytes(value.split(":", 1)[1]).hex()
    elif value.lower().startswith("dword:"):
        try:
            value = str(int(value.split(":", 1)[1], 16))
        except ValueError:
            pass
    return name, value


def decode_userassist_name(value: str) -> str:
    try:
        return codecs.decode(value, "rot_13")
    except Exception:
        return value


def extract_executable_path(key: str, values: Mapping[str, str]) -> str:
    for name, value in values.items():
        lowered = name.lower()
        if lowered in {"path", "fullpath", "filename", "programid", "name"} and value:
            return value
        if looks_like_executable_path(name):
            return name
        if looks_like_executable_path(value):
            return value
    tail = key.rsplit("\\", 1)[-1]
    return tail if looks_like_executable_path(tail) else ""


def looks_like_executable_path(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in (".exe", ".dll", ".ps1", ".bat", ".cmd", ".scr"))


def iter_registry_like_strings(blob: bytes) -> Iterable[str]:
    yield from iter_ascii_strings(blob)
    yield from iter_utf16le_strings(blob)


def iter_registry_like_string_occurrences(blob: bytes) -> Iterable[dict[str, object]]:
    yield from iter_ascii_string_occurrences(blob)
    yield from iter_utf16le_string_occurrences(blob)


def iter_ascii_strings(blob: bytes, *, min_chars: int = 5) -> Iterable[str]:
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_chars:
            yield current.decode("ascii", errors="ignore")
        current.clear()
    if len(current) >= min_chars:
        yield current.decode("ascii", errors="ignore")


def iter_ascii_string_occurrences(blob: bytes, *, min_chars: int = 5) -> Iterable[dict[str, object]]:
    current = bytearray()
    start = 0
    for index, byte in enumerate(blob):
        if 32 <= byte <= 126:
            if not current:
                start = index
            current.append(byte)
            continue
        if len(current) >= min_chars:
            yield {"text": current.decode("ascii", errors="ignore"), "offset": start, "encoding": "ascii"}
        current.clear()
    if len(current) >= min_chars:
        yield {"text": current.decode("ascii", errors="ignore"), "offset": start, "encoding": "ascii"}


def iter_utf16le_strings(blob: bytes, *, min_chars: int = 4) -> Iterable[str]:
    current = bytearray()
    for index in range(0, len(blob) - 1, 2):
        value = int.from_bytes(blob[index : index + 2], "little", signed=False)
        if 32 <= value <= 126 or value in {9, 10, 13}:
            current.extend(blob[index : index + 2])
            continue
        if len(current) >= min_chars * 2:
            yield current.decode("utf-16le", errors="ignore").strip()
        current.clear()
    if len(current) >= min_chars * 2:
        yield current.decode("utf-16le", errors="ignore").strip()


def iter_utf16le_string_occurrences(blob: bytes, *, min_chars: int = 4) -> Iterable[dict[str, object]]:
    current = bytearray()
    start = 0
    for index in range(0, len(blob) - 1, 2):
        value = int.from_bytes(blob[index : index + 2], "little", signed=False)
        if 32 <= value <= 126 or value in {9, 10, 13}:
            if not current:
                start = index
            current.extend(blob[index : index + 2])
            continue
        if len(current) >= min_chars * 2:
            text = current.decode("utf-16le", errors="ignore").strip()
            if text:
                yield {"text": text, "offset": start, "encoding": "utf-16le"}
        current.clear()
    if len(current) >= min_chars * 2:
        text = current.decode("utf-16le", errors="ignore").strip()
        if text:
            yield {"text": text, "offset": start, "encoding": "utf-16le"}


def collect_amcache_candidate_clusters(occurrences: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    path_occurrences = [
        item
        for item in occurrences
        if looks_like_executable_path(str(item.get("text") or ""))
    ]
    clusters: dict[str, dict[str, object]] = {}
    for item in path_occurrences:
        executable_path = str(item.get("text") or "")
        normalized_path = normalize_execution_path(executable_path)
        if not normalized_path:
            continue
        source_offset = int(item.get("offset") or 0)
        nearby = [
            candidate
            for candidate in occurrences
            if abs(int(candidate.get("offset") or 0) - source_offset) <= AMCACHE_ROW_CLUSTER_WINDOW_BYTES
        ]
        sha1_candidates = sorted(
            {
                match.group(0).lower()
                for candidate in nearby
                for match in re.finditer(r"(?i)\b[0-9a-f]{40}\b", str(candidate.get("text") or ""))
            }
        )
        timestamp_candidates = [
            value
            for _, value in sorted(
                {
                    (abs(int(candidate.get("offset") or 0) - source_offset), parsed)
                    for candidate in nearby
                    for parsed in [parse_timestamp_value(str(candidate.get("text") or ""))]
                    if parsed
                }
            )
        ]
        metadata_candidates = amcache_metadata_candidates(executable_path, nearby)
        existing = clusters.get(normalized_path)
        cluster = {
            "executable_path": executable_path,
            "normalized_path": normalized_path,
            "source_offset": source_offset,
            "source_encoding": str(item.get("encoding") or ""),
            "nearby_string_count": len(nearby),
            "nearby_offsets": sorted({int(candidate.get("offset") or 0) for candidate in nearby})[:100],
            "sha1_candidates": sha1_candidates,
            "timestamp_candidates": timestamp_candidates,
            "metadata_candidates": metadata_candidates,
            "parser_confidence": min(
                0.7,
                0.45
                + (0.08 if sha1_candidates else 0)
                + (0.06 if timestamp_candidates else 0)
                + (0.04 if metadata_candidates else 0),
            ),
        }
        if existing is None or len(nearby) > int(existing.get("nearby_string_count") or 0):
            clusters[normalized_path] = cluster
    return sorted(clusters.values(), key=lambda row: (int(row.get("source_offset") or 0), str(row.get("normalized_path") or "")))[:100]


def collect_shimcache_candidate_clusters(occurrences: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    path_occurrences = [
        item
        for item in occurrences
        if looks_like_executable_path(str(item.get("text") or ""))
    ]
    clusters: dict[str, dict[str, object]] = {}
    for cache_order, item in enumerate(sorted(path_occurrences, key=lambda row: int(row.get("offset") or 0))):
        executable_path = str(item.get("text") or "")
        normalized_path = normalize_execution_path(executable_path)
        if not normalized_path:
            continue
        source_offset = int(item.get("offset") or 0)
        nearby = [
            candidate
            for candidate in occurrences
            if abs(int(candidate.get("offset") or 0) - source_offset) <= SHIMCACHE_ROW_CLUSTER_WINDOW_BYTES
        ]
        timestamp_candidates = [
            value
            for _, value in sorted(
                {
                    (abs(int(candidate.get("offset") or 0) - source_offset), parsed)
                    for candidate in nearby
                    for parsed in [parse_timestamp_value(str(candidate.get("text") or ""))]
                    if parsed
                }
            )
        ]
        metadata_candidates = shimcache_metadata_candidates(executable_path, nearby)
        existing = clusters.get(normalized_path)
        cluster = {
            "executable_path": executable_path,
            "normalized_path": normalized_path,
            "source_offset": source_offset,
            "source_encoding": str(item.get("encoding") or ""),
            "cache_order": cache_order,
            "nearby_string_count": len(nearby),
            "nearby_offsets": sorted({int(candidate.get("offset") or 0) for candidate in nearby})[:100],
            "timestamp_candidates": timestamp_candidates,
            "nearby_metadata_candidates": metadata_candidates,
            "parser_confidence": min(
                0.68,
                0.5
                + (0.06 if timestamp_candidates else 0)
                + (0.04 if metadata_candidates else 0)
                + (0.04 if "\\windows\\" in normalized_path or "\\program files" in normalized_path else 0),
            ),
        }
        if existing is None or source_offset < int(existing.get("source_offset") or source_offset + 1):
            clusters[normalized_path] = cluster
    return sorted(clusters.values(), key=lambda row: (int(row.get("cache_order") or 0), int(row.get("source_offset") or 0)))[:100]


def collect_bam_dam_candidate_clusters(occurrences: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    path_occurrences = [
        item
        for item in occurrences
        if looks_like_executable_path(str(item.get("text") or ""))
    ]
    clusters: dict[str, dict[str, object]] = {}
    for item in sorted(path_occurrences, key=lambda row: int(row.get("offset") or 0)):
        executable_path = str(item.get("text") or "")
        normalized_path = normalize_execution_path(executable_path)
        if not normalized_path:
            continue
        source_offset = int(item.get("offset") or 0)
        nearby = [
            candidate
            for candidate in occurrences
            if abs(int(candidate.get("offset") or 0) - source_offset) <= BAM_DAM_ROW_CLUSTER_WINDOW_BYTES
        ]
        user_sid = next(
            (
                match.group(0)
                for candidate in nearby
                for match in re.finditer(r"S-\d(?:-\d+)+", str(candidate.get("text") or ""))
            ),
            "",
        )
        source_key = next(
            (
                str(candidate.get("text") or "")
                for candidate in nearby
                if "\\services\\bam\\" in str(candidate.get("text") or "").lower()
                or "\\services\\dam\\" in str(candidate.get("text") or "").lower()
            ),
            "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        )
        timestamp_candidates = [
            value
            for _, value in sorted(
                {
                    (abs(int(candidate.get("offset") or 0) - source_offset), parsed)
                    for candidate in nearby
                    for parsed in [parse_timestamp_value(str(candidate.get("text") or ""))]
                    if parsed
                }
            )
        ]
        metadata_candidates = bam_dam_metadata_candidates(executable_path, nearby)
        existing = clusters.get(normalized_path)
        cluster = {
            "executable_path": executable_path,
            "normalized_path": normalized_path,
            "source_offset": source_offset,
            "source_encoding": str(item.get("encoding") or ""),
            "source_key": source_key,
            "user_sid": user_sid,
            "nearby_string_count": len(nearby),
            "nearby_offsets": sorted({int(candidate.get("offset") or 0) for candidate in nearby})[:100],
            "timestamp_candidates": timestamp_candidates,
            "nearby_metadata_candidates": metadata_candidates,
            "parser_confidence": min(
                0.72,
                0.5
                + (0.08 if user_sid else 0)
                + (0.06 if timestamp_candidates else 0)
                + (0.04 if normalized_path.startswith("\\device\\") else 0),
            ),
        }
        if existing is None or bool(user_sid) > bool(existing.get("user_sid")):
            clusters[normalized_path] = cluster
    return sorted(clusters.values(), key=lambda row: (str(row.get("user_sid") or ""), int(row.get("source_offset") or 0)))[:100]


def bam_dam_metadata_candidates(executable_path: str, nearby: Sequence[Mapping[str, object]]) -> list[str]:
    blocked = {normalize_execution_path(executable_path)}
    values: list[str] = []
    for candidate in nearby:
        text = " ".join(str(candidate.get("text") or "").split()).strip()
        if not text or normalize_execution_path(text) in blocked:
            continue
        lowered = text.lower()
        if looks_like_executable_path(text) or parse_timestamp_value(text):
            continue
        if len(text) < 3 or len(text) > 220:
            continue
        if "\\services\\bam\\" in lowered or "\\services\\dam\\" in lowered or re.search(r"S-\d(?:-\d+)+", text):
            values.append(text)
    return list(unique_preserve_order(values))[:25]


def shimcache_metadata_candidates(executable_path: str, nearby: Sequence[Mapping[str, object]]) -> list[str]:
    blocked = {normalize_execution_path(executable_path)}
    values: list[str] = []
    for candidate in nearby:
        text = " ".join(str(candidate.get("text") or "").split()).strip()
        if not text or normalize_execution_path(text) in blocked:
            continue
        lowered = text.lower()
        if looks_like_executable_path(text):
            continue
        if parse_timestamp_value(text):
            continue
        if len(text) < 3 or len(text) > 200:
            continue
        if any(marker in lowered for marker in ("appcompatcache", "appcompatflags", "controlset", "session manager")):
            values.append(text)
            continue
        if lowered.startswith(("windows ", "microsoft ", "program ")):
            values.append(text)
    return list(unique_preserve_order(values))[:25]


def amcache_metadata_candidates(executable_path: str, nearby: Sequence[Mapping[str, object]]) -> list[str]:
    blocked = {normalize_execution_path(executable_path)}
    values: list[str] = []
    for candidate in nearby:
        text = " ".join(str(candidate.get("text") or "").split()).strip()
        if not text or normalize_execution_path(text) in blocked:
            continue
        if looks_like_executable_path(text):
            continue
        if re.fullmatch(r"(?i)[0-9a-f]{40}", text):
            continue
        if parse_timestamp_value(text):
            continue
        if 3 <= len(text) <= 160:
            values.append(text)
    return list(unique_preserve_order(values))[:25]


def unique_preserve_order(values: Iterable[str]) -> Iterable[str]:
    seen: set[str] = set()
    for value in values:
        cleaned = " ".join(str(value).split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        yield cleaned


def extract_execution_timestamp(artifact_type: str, values: Mapping[str, str]) -> tuple[str, str]:
    for name, value in values.items():
        lowered_name = name.lower()
        if artifact_type == "bam-entry" and looks_like_executable_path(name):
            parsed = parse_timestamp_value(value)
            if parsed:
                return parsed, "bam_value_filetime"
        if "time" not in lowered_name and "last" not in lowered_name and "date" not in lowered_name:
            continue
        parsed = parse_timestamp_value(value)
        if parsed:
            return parsed, lowered_name
    return "", ""


def extract_timestamp(values: Mapping[str, str]) -> str:
    timestamp, _ = extract_execution_timestamp("", values)
    return timestamp


def parse_timestamp_value(value: str) -> str:
    text = value.strip().strip('"')
    if re.match(r"^\d{4}-\d\d-\d\d[T ]", text):
        return text.replace("Z", "+00:00")
    embedded_iso = re.search(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)?", text)
    if embedded_iso:
        return embedded_iso.group(0).replace("Z", "+00:00")
    if text.lower().startswith("hex(b):"):
        raw = parse_hex_bytes(text[7:])
        if len(raw) >= 8:
            filetime = int.from_bytes(raw[:8], "little", signed=False)
            return filetime_to_iso(filetime)
    return ""


def parse_hex_bytes(value: str) -> bytes:
    items = []
    for item in value.replace("\\", "").replace("\n", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            items.append(int(item, 16))
        except ValueError:
            return b""
    return bytes(items)


def filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        return (base + dt.timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, ValueError):
        return ""


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}


def path_modified_at(path: Path) -> str:
    try:
        modified = path.stat().st_mtime
    except OSError:
        return ""
    return dt.datetime.fromtimestamp(modified, tz=dt.timezone.utc).isoformat()
