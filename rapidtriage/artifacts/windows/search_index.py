from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Iterable, Mapping, Sequence

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review
from .ese import build_ese_page_map, build_ese_string_pivots, probe_ese_database

PARSER_VERSION = "windows-search-index-import-v7"
SEARCH_EDB_PATH = ("ProgramData", "Microsoft", "Search", "Data", "Applications", "Windows", "Windows.edb")
SUPPORTED_EXPORT_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
EXPORT_HINTS = ("windows.edb", "windows-search", "searchindex", "search-index", "edbexport", "winsearch")
WINDOWS_SEARCH_EDB_BLOCKERS = [
    "native-ese-catalog-decoding-required",
    "windows-search-table-schema-decoding-required",
    "row-level-path-url-content-decoding-required",
    "row-level-timestamp-and-deleted-state-validation-required",
    "windows-edb-trusted-parser-diff-required",
]
WINDOWS_SEARCH_TRUSTED_TOOLS = {
    "esentutl",
    "libesedb",
    "esedbexport",
    "winsearchdbanalyzer",
    "windowssearch",
    "windows-search",
    "velociraptor",
}
WINDOWS_SEARCH_CAPABILITIES = {
    "csv_json_export_import": True,
    "ese_header_probe": True,
    "native_string_pivots": True,
    "native_page_map_triage": True,
    "page_level_marker_correlation": True,
    "table_family_marker_detection": True,
    "content_candidate_string_scan": True,
    "native_ese_catalog_decode": False,
    "native_table_schema_decode": False,
    "native_row_level_decode": False,
    "native_deleted_state_decode": False,
    "native_timestamp_decode": False,
    "native_space_tree_decode": False,
    "native_long_value_tree_decode": False,
}
WINDOWS_SEARCH_ANALYST_REVIEW_CATALOG = {
    "windows-search-index-entry": {
        "severity": "medium",
        "summary": "Windows Search export row; useful for indexed path/content review when source-tool provenance is preserved.",
        "evidence_interpretation": "source-tool decoded Windows Search index row",
        "not_proof_of": ["file existence at acquisition time without filesystem corroboration", "deleted-state certainty without source parser validation"],
        "primary_pivots": ["item_path", "file_name", "url", "content_snippet", "modified_at"],
        "correlation_targets": ["MFT", "USN", "Browser history", "Email", "Document metadata"],
        "analyst_questions": [
            "Does the source-tool export identify the same item path/content?",
            "Does MFT/USN prove the file existed or changed near the indexed timestamp?",
            "Should this hit be included in the evidence tray or only used as a search lead?",
        ],
        "risk_tags": ["search-index-hit", "source-tool-export"],
    },
    "windows-search-edb-file": {
        "severity": "medium",
        "summary": "Native Windows.edb inventory; page/string candidates support search triage but not decoded ESE row facts.",
        "evidence_interpretation": "ESE header, page map, and bounded string/page-local candidates",
        "not_proof_of": ["decoded ESE row facts", "authoritative deleted/index state", "native row timestamp"],
        "primary_pivots": ["path_candidate_count", "url_candidate_count", "content_candidate_count", "row_candidate_count", "page_count_scanned"],
        "correlation_targets": ["libesedb/esedbexport", "WinSearchDBAnalyzer", "MFT", "USN", "Browser history"],
        "analyst_questions": [
            "Which page-local candidate should be validated with a dedicated ESE parser?",
            "Do MFT/USN/browser artifacts corroborate the path, URL, or content string?",
            "Are deleted-state markers present only as strings or decoded from the actual row?",
        ],
        "risk_tags": ["native-edb-triage", "row-decoding-required"],
    },
    "windows-search-edb-row-candidate": {
        "severity": "high",
        "summary": "Page-local Windows.edb row candidate; strong search lead but still requires native ESE row validation.",
        "evidence_interpretation": "correlated page-local path, URL, content, and table marker strings",
        "not_proof_of": ["decoded row ownership", "final deleted state", "native row timestamp"],
        "primary_pivots": ["item_path", "file_name", "url", "content_snippet", "page_offset", "deleted_state"],
        "correlation_targets": ["libesedb/esedbexport", "WinSearchDBAnalyzer", "MFT", "USN", "Browser history", "Document viewer"],
        "analyst_questions": [
            "Does a trusted Windows.edb parser decode this exact item?",
            "Does the page offset/hash remain stable in the source image?",
            "What original file/web artifact should be opened to verify the hit?",
        ],
        "risk_tags": ["search-result-review", "page-local-candidate"],
    },
}
WINDOWS_SEARCH_TABLE_MARKERS = {
    "gather-path": ("systemindex_gthrpth", "gthrpth", "scope", "crawl", "file:"),
    "gather-record": ("systemindex_gthr", "workid", "documentid", "docid", "itemurl"),
    "property-store": (
        "systemindex_propertystore",
        "system.itempathdisplay",
        "system.filename",
        "system.size",
        "system.datemodified",
    ),
    "content-index": ("system.search.contents", "contents", "inverted", "phrase"),
    "deleted-state": ("isdeleted", "deleted", "tombstone", "status", "crawlstatus"),
}


class WindowsSearchIndexProvider:
    name = "windows-search-index"
    collector_kind = "windows-search-index"
    description = "Windows Search index EDB inventory and CSV/JSON export imports"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        seen: set[Path] = set()
        edb_path = root.joinpath(*SEARCH_EDB_PATH)
        if edb_path.is_file():
            inventory = build_edb_inventory_record(edb_path)
            records.append(inventory)
            records.extend(build_edb_pivot_records(edb_path, inventory.details))
            records.extend(build_edb_page_candidate_records(edb_path, inventory.details))
            records.extend(build_edb_table_candidate_records(edb_path, inventory.details))
            records.extend(build_edb_row_candidate_records(edb_path, inventory.details))
            seen.add(edb_path.resolve())

        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            lowered = str(path.relative_to(root)).lower()
            if path.name.lower() == "windows.edb":
                inventory = build_edb_inventory_record(path)
                records.append(inventory)
                records.extend(build_edb_pivot_records(path, inventory.details))
                records.extend(build_edb_page_candidate_records(path, inventory.details))
                records.extend(build_edb_table_candidate_records(path, inventory.details))
                records.extend(build_edb_row_candidate_records(path, inventory.details))
                seen.add(resolved)
                continue
            if path.suffix.lower() not in SUPPORTED_EXPORT_SUFFIXES or not any(hint in lowered for hint in EXPORT_HINTS):
                continue
            rows = iter_csv_rows(path) if path.suffix.lower() == ".csv" else iter_json_rows(path)
            source_hashes = file_hashes(path)
            for index, row in enumerate(rows):
                records.append(build_search_index_entry(path, row, index, source_hashes))

        yield from records
        summary = build_search_index_summary(root, records)
        if summary is not None:
            yield summary


def build_edb_inventory_record(path: Path) -> ArtifactRecord:
    stat_result = path.stat()
    ese_header = probe_ese_database(path)
    pivots = build_ese_string_pivots(path)
    page_map = build_ese_page_map(path, table_markers=WINDOWS_SEARCH_TABLE_MARKERS)
    content_candidates = build_search_content_candidates(pivots)
    table_families = detect_search_table_families(pivots)
    row_candidates = build_search_row_candidates({**pivots, "content_candidates": content_candidates, "ese_page_map": page_map})
    coverage_status = "ese-header-string-scan" if ese_header.get("header_readable") else "detected"
    validation_checks = {
        "ese_header_readable": bool(ese_header.get("header_readable")),
        "ese_signature_valid": bool(ese_header.get("signature_valid")),
        "has_path_pivots": bool(pivots.get("path_candidates")),
        "has_url_pivots": bool(pivots.get("url_candidates")),
        "has_content_candidates": bool(content_candidates),
        "has_table_family_candidates": bool(table_families),
        "has_native_row_candidates": bool(row_candidates),
        "ese_page_map_built": bool(page_map.get("page_map_available")),
        "page_level_marker_correlation_available": bool(page_map.get("candidate_page_count")),
        "ese_catalog_decoded": False,
        "row_level_decoding_available": False,
        "timestamps_decoded_from_native_rows": False,
        "deleted_state_decoded_from_native_rows": False,
        "requires_windows_search_parser": True,
    }
    report_grade = search_index_report_grade_assessment(
        search_index_validation_matrix(validation_checks),
        validation_required=True,
        extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
    )
    return ArtifactRecord(
        provider=WindowsSearchIndexProvider.name,
        artifact_type="windows-search-edb-file",
        path=str(path.resolve()),
        supported=False,
        details={
            "parser": "windows-search-edb-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": coverage_status,
            "reportability": "inventory-only",
            "source_path": str(path.resolve()),
            "source_format": "ese-edb",
            "source_hashes": file_hashes(path),
            "size": stat_result.st_size,
            "modified_at": stat_result.st_mtime,
            "ese_header": ese_header,
            "parser_confidence": 0.65 if ese_header.get("signature_valid") else 0.35,
            "evidence_strength": "search-index-database-presence",
            **pivots,
            "ese_page_map": page_map,
            "edb_analysis_method": {
                "method_id": page_map.get("method_id", "ese-page-map-string-correlation-v1"),
                "status": page_map.get("analysis_status", "not-built"),
                "stages": [
                    "ESE header probe",
                    "bounded page map scan",
                    "page-local Windows Search table marker correlation",
                    "page-local path/URL/content/risk string grouping",
                    "external parser diff validation before report-grade use",
                ],
                "commercial_position": "triage-grade-page-correlation-not-full-native-row-decode",
                "why_new": "Analyst review can now jump from a candidate hit to the ESE page offset/hash that contained the supporting strings, instead of relying only on a global bounded string list.",
            },
            "content_candidates": content_candidates,
            "native_candidate_metadata": {
                "path_candidate_count": len(pivots.get("path_candidates") or []),
                "url_candidate_count": len(pivots.get("url_candidates") or []),
                "content_candidate_count": len(content_candidates),
                "table_candidate_families": table_families,
                "table_candidate_count": len(table_families),
                "row_candidate_count": len(row_candidates),
                "page_count_total": int(page_map.get("page_count_total") or 0),
                "page_count_scanned": int(page_map.get("page_count_scanned") or 0),
                "page_candidate_count": int(page_map.get("candidate_page_count") or 0),
                "page_marker_family_counts": list(page_map.get("page_marker_family_counts") or []),
                "string_scan_bytes": int(pivots.get("string_scan_bytes") or 0),
            },
            "native_validation": {
                "header_signature_valid": bool(ese_header.get("signature_valid")),
                "page_size_detected": int(ese_header.get("page_size") or 0),
                "page_map_built": bool(page_map.get("page_map_available")),
                "page_map_method": page_map.get("method_id", "ese-page-map-string-correlation-v1"),
                "page_level_marker_correlation_available": bool(page_map.get("candidate_page_count")),
                "bounded_string_scan_only": True,
                "ese_catalog_decoded": False,
                "row_level_decoding_available": False,
                "row_candidate_decode_status": "correlated-native-string-candidates-only",
                "path_url_content_candidates_only": True,
                "timestamps_decoded_from_native_rows": False,
                "deleted_state_decoded_from_native_rows": False,
            },
            "windows_edb_report_citation_manifest": windows_edb_report_citation_manifest(
                source_path=str(path.resolve()),
                source_hashes=file_hashes(path),
                artifact_type="windows-search-edb-file",
                artifact_scope="database",
                source_format="ese-edb",
                source_index=0,
                item_path="",
                url="",
                content_snippet="",
                table_family="windows-search-edb",
                timestamp="",
                deleted_state="not-decoded",
                page_locator={
                    "page_count_scanned": int(page_map.get("page_count_scanned") or 0),
                    "candidate_page_count": int(page_map.get("candidate_page_count") or 0),
                    "page_size": int(ese_header.get("page_size") or 0),
                },
                row_cluster_evidence={
                    "path_candidate_count": len(pivots.get("path_candidates") or []),
                    "url_candidate_count": len(pivots.get("url_candidates") or []),
                    "content_candidate_count": len(content_candidates),
                    "table_family_candidates": table_families,
                    "row_candidate_count": len(row_candidates),
                },
                report_grade=report_grade,
            ),
            "validation_required": True,
            "validation_checks": validation_checks,
            "core_accuracy_gates": windows_search_core_accuracy_gates(
                "windows-search-edb-file",
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "ese_page_map": page_map,
                    "table_families": table_families,
                    "row_candidates": row_candidates,
                    "content_candidates": content_candidates,
                    "validation_checks": validation_checks,
                },
            ),
            "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
            "search_index_report_grade_assessment": report_grade,
            "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
            "windows_search_analyst_review_profile": windows_search_analyst_review_profile(
                artifact_type="windows-search-edb-file",
                source_format="ese-edb",
                validation_checks=validation_checks,
                report_grade=report_grade,
                risk_flags=[
                    f"ese-string:{value}"
                    for value in ("powershell", "cmd.exe", "rundll32", "regsvr32", "wmic", "certutil")
                    if any(value in str(candidate).lower() for candidate in pivots.get("suspicious_strings") or [])
                ],
                evidence_fields={
                    "path_candidate_count": len(pivots.get("path_candidates") or []),
                    "url_candidate_count": len(pivots.get("url_candidates") or []),
                    "content_candidate_count": len(content_candidates),
                    "row_candidate_count": len(row_candidates),
                    "page_count_scanned": int(page_map.get("page_count_scanned") or 0),
                },
            ),
            "commercial_uplift_evidence": windows_search_commercial_uplift_evidence(
                {
                    "source_path": str(path.resolve()),
                    "source_hashes": file_hashes(path),
                    "artifact_type": "windows-search-edb-file",
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "native_candidate_metadata": {
                        "page_count_scanned": int(page_map.get("page_count_scanned") or 0),
                        "row_candidate_count": len(row_candidates),
                        "table_candidate_count": len(table_families),
                        "string_scan_bytes": int(pivots.get("string_scan_bytes") or 0),
                    },
                }
            ),
            "forensic_review": build_forensic_review(
                gap_id="#11",
                artifact_goal="Windows.edb native ESE search-index evidence",
                primary_evidence=[
                    f"paths={len(pivots.get('path_candidates') or [])}",
                    f"urls={len(pivots.get('url_candidates') or [])}",
                    f"rows={len(row_candidates)}",
                    f"tables={len(table_families)}",
                    f"pages={int(page_map.get('candidate_page_count') or 0)}",
                ],
                validation_required=True,
                report_grade_assessment=report_grade,
                commercial_grade_ready=False,
                caveats=["Page-level ESE correlation is available, but native ESE rows and deleted state are not fully decoded."],
            ),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": report_grade["blockers"],
            "recommended_parsers": ["WinSearchDBAnalyzer", "ESEDatabaseView", "libesedb/esedbexport"],
            "note": "Windows.edb is inventoried directly with bounded ESE header/string/page-map/table candidate pivots; page candidates preserve offset/hash context for review, but export CSV/JSON rows with a trusted ESE/Search parser for full table, timestamp, and deleted-state decoding.",
        },
    )


def build_edb_pivot_records(path: Path, inventory_details: Mapping[str, object]) -> list[ArtifactRecord]:
    source_hashes = file_hashes(path)
    candidates: list[tuple[str, str]] = []
    for value in inventory_details.get("path_candidates") or []:
        candidates.append(("path", str(value)))
    for value in inventory_details.get("url_candidates") or []:
        candidates.append(("url", str(value)))
    for value in inventory_details.get("content_candidates") or []:
        candidates.append(("content", str(value)))
    for value in inventory_details.get("suspicious_strings") or []:
        candidates.append(("string", str(value)))

    records: list[ArtifactRecord] = []
    seen: set[tuple[str, str]] = set()
    for index, (candidate_kind, candidate_value) in enumerate(candidates):
        key = (candidate_kind, candidate_value)
        if key in seen:
            continue
        seen.add(key)
        item_path = candidate_value if candidate_kind == "path" else ""
        url = candidate_value if candidate_kind == "url" else first_url(candidate_value)
        file_name = filename_from_path(item_path) if item_path else ""
        risk_flags = []
        if url:
            risk_flags.append("search-index-url-pivot")
        if candidate_kind == "content":
            risk_flags.append("search-index-content-pivot")
        if any(term in candidate_value.lower() for term in ("powershell", "cmd.exe", "rundll32", "regsvr32", "wmic", "certutil")):
            risk_flags.append("search-index-suspicious-text-pivot")
        validation_checks = {
            "candidate_kind": candidate_kind,
            "has_candidate_value": bool(candidate_value),
            "has_path_or_url": bool(item_path or url),
            "row_level_decoding_available": False,
            "requires_windows_search_parser": True,
        }
        report_grade = search_index_report_grade_assessment(
            search_index_validation_matrix(validation_checks),
            validation_required=True,
            extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
        )
        records.append(
            ArtifactRecord(
                provider=WindowsSearchIndexProvider.name,
                artifact_type="windows-search-edb-pivot",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-search-edb-string-pivot",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-ese-string-pivot",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "ese-edb",
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "candidate_kind": candidate_kind,
                    "candidate_value": candidate_value,
                    "item_path": item_path,
                    "file_name": file_name,
                    "extension": extension_from_name(file_name or item_path),
                    "url": url,
                    "title": "",
                    "content_snippet": candidate_value[:1000],
                    "windows_edb_report_citation_manifest": windows_edb_report_citation_manifest(
                        source_path=str(path.resolve()),
                        source_hashes=source_hashes,
                        artifact_type="windows-search-edb-pivot",
                        artifact_scope="string-pivot",
                        source_format="ese-edb",
                        source_index=index,
                        item_path=item_path,
                        url=url,
                        content_snippet=candidate_value[:1000],
                        table_family="unknown",
                        timestamp="",
                        deleted_state="not-decoded",
                        page_locator={},
                        row_cluster_evidence={"candidate_kind": candidate_kind, "candidate_value": candidate_value},
                        report_grade=report_grade,
                    ),
                    "parser_confidence": 0.4,
                    "evidence_strength": "search-index-string-pivot",
                    "validation_required": True,
                    "validation_guidance": "Windows.edb native string pivots identify indexed paths/URLs/text present in the database; validate full table fields and timestamps with a dedicated Windows Search EDB parser.",
                    "validation_checks": validation_checks,
                    "core_accuracy_gates": windows_search_core_accuracy_gates(
                        "windows-search-edb-pivot",
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "candidate_kind": candidate_kind,
                            "candidate_value": candidate_value,
                            "item_path": item_path,
                            "url": url,
                            "content_snippet": candidate_value[:1000],
                            "validation_checks": validation_checks,
                        },
                    ),
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
                    "windows_search_analyst_review_profile": windows_search_analyst_review_profile(
                        artifact_type="windows-search-edb-pivot",
                        source_format="ese-edb",
                        validation_checks=validation_checks,
                        report_grade=report_grade,
                        risk_flags=risk_flags,
                        evidence_fields={
                            "item_path": item_path,
                            "url": url,
                            "content_snippet": candidate_value[:1000],
                            "candidate_value": candidate_value[:1000],
                        },
                    ),
                    "commercial_uplift_evidence": windows_search_commercial_uplift_evidence(
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "artifact_type": "windows-search-edb-pivot",
                            "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                            "search_index_report_grade_assessment": report_grade,
                        }
                    ),
                    "forensic_review": build_forensic_review(
                        gap_id="#11",
                        artifact_goal="Windows.edb native string pivot",
                        primary_evidence=[
                            f"path={item_path}" if item_path else "",
                            f"url={url}" if url else "",
                            f"file={file_name}" if file_name else "",
                        ],
                        validation_required=True,
                        report_grade_assessment=report_grade,
                        commercial_grade_ready=False,
                        caveats=["Row candidate is correlated from strings, not a decoded ESE table row."],
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": report_grade["blockers"],
                    "risk_flags": sorted(set(risk_flags)),
                    "risk_score": min(100, len(set(risk_flags)) * 20),
                    "raw_preview": candidate_value[:2000],
                },
            )
        )
    return records


def build_edb_page_candidate_records(path: Path, inventory_details: Mapping[str, object]) -> list[ArtifactRecord]:
    page_map = dict(inventory_details.get("ese_page_map") or {})
    page_samples = [sample for sample in page_map.get("page_samples") or [] if isinstance(sample, Mapping)]
    if not page_samples:
        return []

    source_hashes = file_hashes(path)
    records: list[ArtifactRecord] = []
    for index, sample in enumerate(page_samples):
        path_candidates = [str(value) for value in sample.get("path_candidates") or [] if str(value)]
        url_candidates = [str(value) for value in sample.get("url_candidates") or [] if str(value)]
        content_candidates = [str(value) for value in sample.get("content_candidates") or [] if str(value)]
        table_marker_hits = {
            str(family): [str(marker) for marker in markers]
            for family, markers in dict(sample.get("table_marker_hits") or {}).items()
        }
        validation_checks = {
            "ese_signature_valid": bool(dict(inventory_details.get("ese_header") or {}).get("signature_valid")),
            "ese_page_map_built": True,
            "page_level_marker_correlation_available": bool(table_marker_hits),
            "has_path_or_url": bool(path_candidates or url_candidates),
            "has_content_snippet": bool(content_candidates),
            "ese_catalog_decoded": False,
            "row_level_decoding_available": False,
            "timestamps_decoded_from_native_rows": False,
            "deleted_state_decoded_from_native_rows": False,
            "requires_windows_search_parser": True,
        }
        report_grade = search_index_report_grade_assessment(
            search_index_validation_matrix(validation_checks),
            validation_required=True,
            extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
        )
        risk_flags = list(sample.get("risk_flags") or [])
        if table_marker_hits:
            risk_flags.extend(f"windows-search-page-table:{family}" for family in table_marker_hits)
        if url_candidates:
            risk_flags.append("search-index-page-url-candidate")
        if path_candidates:
            risk_flags.append("search-index-page-path-candidate")
        records.append(
            ArtifactRecord(
                provider=WindowsSearchIndexProvider.name,
                artifact_type="windows-search-edb-page-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-search-edb-page-map",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-ese-page-map-candidate",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "ese-edb",
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "page_index": int(sample.get("page_index") or 0),
                    "page_offset": int(sample.get("page_offset") or 0),
                    "page_size": int(sample.get("page_size") or 0),
                    "page_sha256": str(sample.get("page_sha256") or ""),
                    "page_evidence_density": int(sample.get("evidence_density") or 0),
                    "printable_string_count": int(sample.get("printable_string_count") or 0),
                    "path_candidates": path_candidates,
                    "url_candidates": url_candidates,
                    "content_candidates": content_candidates,
                    "suspicious_strings": [str(value) for value in sample.get("suspicious_strings") or []],
                    "table_marker_hits": table_marker_hits,
                    "candidate_basis": {
                        "method_id": page_map.get("method_id", "ese-page-map-string-correlation-v1"),
                        "correlation_scope": "single-ese-page",
                        "page_hash_preserved": bool(sample.get("page_sha256")),
                        "page_offset_preserved": True,
                    },
                    "windows_edb_report_citation_manifest": windows_edb_report_citation_manifest(
                        source_path=str(path.resolve()),
                        source_hashes=source_hashes,
                        artifact_type="windows-search-edb-page-candidate",
                        artifact_scope="page-candidate",
                        source_format="ese-edb",
                        source_index=index,
                        item_path=path_candidates[0] if path_candidates else "",
                        url=url_candidates[0] if url_candidates else "",
                        content_snippet=content_candidates[0] if content_candidates else "",
                        table_family=",".join(sorted(table_marker_hits)) if table_marker_hits else "unknown",
                        timestamp="",
                        deleted_state="candidate-marker-present" if "deleted-state" in table_marker_hits else "not-decoded",
                        page_locator={
                            "page_index": int(sample.get("page_index") or 0),
                            "page_offset": int(sample.get("page_offset") or 0),
                            "page_size": int(sample.get("page_size") or 0),
                            "page_sha256": str(sample.get("page_sha256") or ""),
                        },
                        row_cluster_evidence={
                            "path_candidate_count": len(path_candidates),
                            "url_candidate_count": len(url_candidates),
                            "content_candidate_count": len(content_candidates),
                            "table_marker_hits": table_marker_hits,
                        },
                        report_grade=report_grade,
                    ),
                    "parser_confidence": page_candidate_confidence(path_candidates, url_candidates, content_candidates, table_marker_hits),
                    "evidence_strength": "windows-search-page-local-string-correlation",
                    "validation_required": True,
                    "validation_guidance": "This candidate groups strings found on the same ESE page and preserves page offset/hash for review. It is not a decoded Windows Search row; validate with a full ESE catalog/table decoder before report use.",
                    "validation_checks": validation_checks,
                    "core_accuracy_gates": windows_search_core_accuracy_gates(
                        "windows-search-edb-page-candidate",
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "page_index": int(sample.get("page_index") or 0),
                            "page_offset": int(sample.get("page_offset") or 0),
                            "page_sha256": str(sample.get("page_sha256") or ""),
                            "path_candidates": path_candidates,
                            "url_candidates": url_candidates,
                            "content_candidates": content_candidates,
                            "table_marker_hits": table_marker_hits,
                            "validation_checks": validation_checks,
                        },
                    ),
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
                    "windows_search_analyst_review_profile": windows_search_analyst_review_profile(
                        artifact_type="windows-search-edb-page-candidate",
                        source_format="ese-edb",
                        validation_checks=validation_checks,
                        report_grade=report_grade,
                        risk_flags=risk_flags,
                        evidence_fields={
                            "item_path": path_candidates[0] if path_candidates else "",
                            "url": url_candidates[0] if url_candidates else "",
                            "content_snippet": content_candidates[0][:1000] if content_candidates else "",
                        },
                    ),
                    "commercial_uplift_evidence": windows_search_commercial_uplift_evidence(
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "artifact_type": "windows-search-edb-page-candidate",
                            "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                            "search_index_report_grade_assessment": report_grade,
                            "native_candidate_metadata": {
                                "page_index": int(sample.get("page_index") or 0),
                                "page_offset": int(sample.get("page_offset") or 0),
                                "page_size": int(sample.get("page_size") or 0),
                            },
                        }
                    ),
                    "forensic_review": build_forensic_review(
                        gap_id="#11",
                        artifact_goal="Windows.edb ESE page-level candidate",
                        primary_evidence=[
                            f"page={int(sample.get('page_index') or 0)}",
                            f"offset={int(sample.get('page_offset') or 0)}",
                            f"paths={len(path_candidates)}",
                            f"urls={len(url_candidates)}",
                            f"tables={len(table_marker_hits)}",
                        ],
                        validation_required=True,
                        report_grade_assessment=report_grade,
                        commercial_grade_ready=False,
                        caveats=["Page-local correlation is stronger than global string scan but still not native ESE row decoding."],
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": report_grade["blockers"],
                    "risk_flags": sorted(set(risk_flags)),
                    "risk_score": min(100, len(set(risk_flags)) * 15),
                    "raw_preview": json.dumps(sample, ensure_ascii=False, sort_keys=True)[:2000],
                },
            )
        )
    return records


def build_edb_table_candidate_records(path: Path, inventory_details: Mapping[str, object]) -> list[ArtifactRecord]:
    strings = [str(value) for value in inventory_details.get("extracted_strings") or []]
    lowered_blob = "\n".join(strings).lower()
    source_hashes = file_hashes(path)
    records: list[ArtifactRecord] = []
    ese_header = dict(inventory_details.get("ese_header") or {})
    native_metadata = dict(inventory_details.get("native_candidate_metadata") or {})
    for index, (table_family, markers) in enumerate(WINDOWS_SEARCH_TABLE_MARKERS.items()):
        matched = sorted({marker for marker in markers if marker in lowered_blob})
        if not matched:
            continue
        validation_checks = {
            "table_family_marker_count": len(matched),
            "ese_signature_valid": bool(ese_header.get("signature_valid")),
            "page_size_detected": int(ese_header.get("page_size") or 0),
            "ese_catalog_decoded": False,
            "row_level_decoding_available": False,
            "timestamps_decoded_from_native_rows": False,
            "deleted_state_decoded_from_native_rows": False,
            "requires_windows_search_parser": True,
        }
        report_grade = search_index_report_grade_assessment(
            search_index_validation_matrix(validation_checks),
            validation_required=True,
            extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
        )
        records.append(
            ArtifactRecord(
                provider=WindowsSearchIndexProvider.name,
                artifact_type="windows-search-edb-table-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-search-edb-table-candidate",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-ese-table-string-candidate",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "ese-edb",
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "table_family": table_family,
                    "matched_markers": matched,
                    "matched_marker_count": len(matched),
                    "candidate_metadata": native_metadata,
                    "windows_edb_report_citation_manifest": windows_edb_report_citation_manifest(
                        source_path=str(path.resolve()),
                        source_hashes=source_hashes,
                        artifact_type="windows-search-edb-table-candidate",
                        artifact_scope="table-candidate",
                        source_format="ese-edb",
                        source_index=index,
                        item_path="",
                        url="",
                        content_snippet="",
                        table_family=table_family,
                        timestamp="",
                        deleted_state="candidate-marker-present" if table_family == "deleted-state" else "not-decoded",
                        page_locator={},
                        row_cluster_evidence={"matched_markers": matched, "candidate_metadata": native_metadata},
                        report_grade=report_grade,
                    ),
                    "parser_confidence": 0.38 + min(0.24, len(matched) * 0.06),
                    "evidence_strength": "windows-search-table-presence-candidate",
                    "validation_required": True,
                    "validation_guidance": "This row identifies likely Windows Search table families from native ESE strings only; validate rows, paths, content, timestamps, and deleted/index state with a full Windows Search EDB parser.",
                    "validation_checks": validation_checks,
                    "core_accuracy_gates": windows_search_core_accuracy_gates(
                        "windows-search-edb-table-candidate",
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "table_family": table_family,
                            "matched_markers": matched,
                            "validation_checks": validation_checks,
                        },
                    ),
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
                    "windows_search_analyst_review_profile": windows_search_analyst_review_profile(
                        artifact_type="windows-search-edb-table-candidate",
                        source_format="ese-edb",
                        validation_checks=validation_checks,
                        report_grade=report_grade,
                        evidence_fields={
                            "content_snippet": " ".join(matched)[:1000],
                        },
                    ),
                    "commercial_uplift_evidence": windows_search_commercial_uplift_evidence(
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "artifact_type": "windows-search-edb-table-candidate",
                            "table_family": table_family,
                            "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                            "search_index_report_grade_assessment": report_grade,
                        }
                    ),
                    "forensic_review": build_forensic_review(
                        gap_id="#11",
                        artifact_goal="Windows.edb native table-family candidate",
                        primary_evidence=[
                            f"table={table_family}",
                            f"markers={len(matched)}",
                        ],
                        validation_required=True,
                        report_grade_assessment=report_grade,
                        commercial_grade_ready=False,
                        caveats=["Table family is detected from native strings, not decoded from the ESE catalog."],
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": report_grade["blockers"],
                    "risk_flags": [f"windows-search-table:{table_family}"],
                    "risk_score": 20,
                    "raw_preview": " ".join(strings[:20])[:2000],
                },
            )
        )
    return records


def build_edb_row_candidate_records(path: Path, inventory_details: Mapping[str, object]) -> list[ArtifactRecord]:
    source_hashes = file_hashes(path)
    row_candidates = build_search_row_candidates(inventory_details)
    table_families = list(dict.fromkeys(str(value) for value in detect_search_table_families(inventory_details)))
    has_deleted_markers = "deleted-state" in table_families
    records: list[ArtifactRecord] = []
    for index, candidate in enumerate(row_candidates):
        item_path = str(candidate.get("item_path") or "")
        url = str(candidate.get("url") or "")
        content_snippet = str(candidate.get("content_snippet") or "")
        file_name = str(candidate.get("file_name") or "") or filename_from_path(item_path)
        validation_checks = {
            "has_source_path_or_url": bool(item_path or url),
            "has_file_name": bool(file_name),
            "has_content_snippet": bool(content_snippet),
            "has_table_family_candidates": bool(table_families),
            "has_page_source_citation": candidate.get("page_offset") is not None or bool(candidate.get("page_sha256")),
            "has_field_presence_profile": bool(candidate.get("field_presence_profile")),
            "has_page_local_table_markers": bool(candidate.get("page_table_marker_hits")),
            "row_level_decoding_available": False,
            "timestamps_decoded_from_native_rows": False,
            "deleted_state_decoded_from_native_rows": False,
            "requires_windows_search_parser": True,
        }
        report_grade = search_index_report_grade_assessment(
            search_index_validation_matrix(validation_checks),
            validation_required=True,
            extra_blockers=WINDOWS_SEARCH_EDB_BLOCKERS,
        )
        risk_flags = ["windows-search-row-candidate"]
        lowered = " ".join([item_path, url, content_snippet]).lower()
        if any(term in lowered for term in ("powershell", "cmd.exe", "rundll32", "regsvr32", "wmic", "certutil")):
            risk_flags.append("search-index-suspicious-row-text")
        if url:
            risk_flags.append("search-index-url-row")
        records.append(
            ArtifactRecord(
                provider=WindowsSearchIndexProvider.name,
                artifact_type="windows-search-edb-row-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "windows-search-edb-row-candidate",
                    "parser_version": PARSER_VERSION,
                    "coverage_status": "native-ese-correlated-string-row-candidate",
                    "reportability": "triage",
                    "source_path": str(path.resolve()),
                    "source_format": "ese-edb",
                    "source_hashes": source_hashes,
                    "source_index": index,
                    "page_index": candidate.get("page_index", ""),
                    "page_offset": candidate.get("page_offset", ""),
                    "page_sha256": candidate.get("page_sha256", ""),
                    "page_local_correlation": bool(candidate.get("page_local_correlation")),
                    "item_path": item_path,
                    "file_name": file_name,
                    "extension": extension_from_name(file_name or item_path),
                    "url": url,
                    "title": "",
                    "content_snippet": content_snippet[:1000],
                    "table_family_candidates": table_families,
                    "page_table_marker_hits": dict(candidate.get("page_table_marker_hits") or {}),
                    "field_presence_profile": dict(candidate.get("field_presence_profile") or {}),
                    "deleted_state": "candidate-marker-present" if has_deleted_markers else "not-decoded",
                    "timestamp": "",
                    "timestamp_source": "not-decoded-native-edb",
                    "candidate_basis": {
                        "path_source": candidate.get("path_source", ""),
                        "url_source": candidate.get("url_source", ""),
                        "content_source": candidate.get("content_source", ""),
                        "correlation_method": candidate.get("correlation_method", ""),
                    },
                    "windows_edb_report_citation_manifest": windows_edb_report_citation_manifest(
                        source_path=str(path.resolve()),
                        source_hashes=source_hashes,
                        artifact_type="windows-search-edb-row-candidate",
                        artifact_scope="row-candidate",
                        source_format="ese-edb",
                        source_index=index,
                        item_path=item_path,
                        url=url,
                        content_snippet=content_snippet[:1000],
                        table_family=",".join(table_families) if table_families else "unknown",
                        timestamp="",
                        deleted_state="candidate-marker-present" if has_deleted_markers else "not-decoded",
                        page_locator={
                            "page_index": candidate.get("page_index", ""),
                            "page_offset": candidate.get("page_offset", ""),
                            "page_sha256": candidate.get("page_sha256", ""),
                        },
                        row_cluster_evidence={
                            "field_presence_profile": dict(candidate.get("field_presence_profile") or {}),
                            "page_table_marker_hits": dict(candidate.get("page_table_marker_hits") or {}),
                            "candidate_basis": candidate.get("correlation_method", ""),
                        },
                        report_grade=report_grade,
                    ),
                    "parser_confidence": candidate.get("parser_confidence", 0.45),
                    "evidence_strength": "windows-search-correlated-native-string-candidate",
                    "validation_required": True,
                    "validation_guidance": "This row correlates native Windows.edb path, URL, and content strings for triage search/review. It is not a decoded ESE row; validate timestamps, deleted state, and table columns with a dedicated Windows Search EDB parser.",
                    "validation_checks": validation_checks,
                    "core_accuracy_gates": windows_search_core_accuracy_gates(
                        "windows-search-edb-row-candidate",
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "page_offset": candidate.get("page_offset", ""),
                            "page_sha256": candidate.get("page_sha256", ""),
                            "item_path": item_path,
                            "url": url,
                            "content_snippet": content_snippet,
                            "table_family_candidates": table_families,
                            "field_presence_profile": dict(candidate.get("field_presence_profile") or {}),
                            "page_table_marker_hits": dict(candidate.get("page_table_marker_hits") or {}),
                            "deleted_state": "candidate-marker-present" if has_deleted_markers else "not-decoded",
                            "candidate_basis": candidate.get("correlation_method", ""),
                            "validation_checks": validation_checks,
                        },
                    ),
                    "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                    "search_index_report_grade_assessment": report_grade,
                    "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
                    "windows_search_analyst_review_profile": windows_search_analyst_review_profile(
                        artifact_type="windows-search-edb-row-candidate",
                        source_format="ese-edb",
                        validation_checks=validation_checks,
                        report_grade=report_grade,
                        risk_flags=risk_flags,
                        evidence_fields={
                            "item_path": item_path,
                            "file_name": file_name,
                            "url": url,
                            "content_snippet": content_snippet[:1000],
                            "page_offset": candidate.get("page_offset", ""),
                            "deleted_state": "candidate-marker-present" if has_deleted_markers else "not-decoded",
                        },
                    ),
                    "commercial_uplift_evidence": windows_search_commercial_uplift_evidence(
                        {
                            "source_path": str(path.resolve()),
                            "source_hashes": source_hashes,
                            "source_index": index,
                            "artifact_type": "windows-search-edb-row-candidate",
                            "item_path": item_path,
                            "url": url,
                            "page_offset": candidate.get("page_offset", ""),
                            "page_sha256": candidate.get("page_sha256", ""),
                            "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
                            "search_index_report_grade_assessment": report_grade,
                        }
                    ),
                    "forensic_review": build_forensic_review(
                        gap_id="#11",
                        artifact_goal="Windows.edb correlated row candidate",
                        primary_evidence=[
                            f"path={item_path}" if item_path else "",
                            f"url={url}" if url else "",
                            f"file={file_name}" if file_name else "",
                            f"page_offset={candidate.get('page_offset')}" if candidate.get("page_offset") not in (None, "") else "",
                        ],
                        validation_required=True,
                        report_grade_assessment=report_grade,
                        commercial_grade_ready=False,
                        caveats=["Row candidate is correlated from strings, not a decoded ESE table row."],
                    ),
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": report_grade["blockers"],
                    "risk_flags": sorted(set(risk_flags)),
                    "risk_score": min(100, len(set(risk_flags)) * 20),
                    "raw_preview": json.dumps(candidate, ensure_ascii=False, sort_keys=True)[:2000],
                },
            )
        )
    return records


def build_search_index_entry(
    path: Path,
    row: Mapping[str, object],
    index: int,
    source_hashes: Mapping[str, str],
) -> ArtifactRecord:
    lowered = {normalize_key(key): value for key, value in row.items()}
    item_path = str(
        first_value(
            lowered,
            "System.ItemPathDisplay",
            "ItemPathDisplay",
            "ItemPath",
            "Path",
            "FilePath",
            "URL",
        )
        or ""
    )
    title = str(first_value(lowered, "System.Title", "Title", "Subject", "DisplayName") or "")
    file_name = str(first_value(lowered, "System.FileName", "FileName", "Name") or "") or filename_from_path(item_path)
    content = str(first_value(lowered, "System.Search.Contents", "Contents", "Content", "Text", "Snippet") or "")
    validation_checks = {
        "has_item_path": bool(item_path),
        "has_file_name": bool(file_name),
        "has_content": bool(content),
        "has_timestamp": bool(
            first_value(lowered, "System.DateCreated", "DateCreated", "Created", "CreationTime")
            or first_value(lowered, "System.DateModified", "DateModified", "Modified", "LastModified")
            or first_value(lowered, "System.DateAccessed", "DateAccessed", "Accessed", "LastAccessed")
        ),
        "source_tool_export_validation_required": True,
    }
    report_grade = search_index_report_grade_assessment(
        search_index_validation_matrix(validation_checks),
        validation_required=False,
        extra_blockers=["source-tool-export-validation-required"],
    )
    details = {
        "parser": "windows-search-index-import",
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": path.suffix.lower().lstrip("."),
        "source_hashes": dict(source_hashes),
        "source_index": index,
        "entry_id": str(first_value(lowered, "DocID", "DocumentID", "EntryID", "ID") or ""),
        "item_path": item_path,
        "file_name": file_name,
        "extension": extension_from_name(file_name or item_path),
        "url": str(first_value(lowered, "URL", "System.ItemUrl", "ItemUrl") or ""),
        "title": title,
        "author": str(first_value(lowered, "System.Author", "Author") or ""),
        "content_snippet": content[:1000],
        "created_at": normalize_timestamp(first_value(lowered, "System.DateCreated", "DateCreated", "Created", "CreationTime")),
        "modified_at": normalize_timestamp(first_value(lowered, "System.DateModified", "DateModified", "Modified", "LastModified")),
        "accessed_at": normalize_timestamp(first_value(lowered, "System.DateAccessed", "DateAccessed", "Accessed", "LastAccessed")),
        "size": str(first_value(lowered, "System.Size", "Size", "FileSize") or ""),
        "store": str(first_value(lowered, "Store", "Catalog", "Scope") or ""),
        "windows_edb_report_citation_manifest": windows_edb_report_citation_manifest(
            source_path=str(path.resolve()),
            source_hashes=dict(source_hashes),
            artifact_type="windows-search-index-entry",
            artifact_scope="source-tool-export",
            source_format=path.suffix.lower().lstrip("."),
            source_index=index,
            item_path=item_path,
            url=str(first_value(lowered, "URL", "System.ItemUrl", "ItemUrl") or ""),
            content_snippet=content[:1000],
            table_family=str(first_value(lowered, "Store", "Catalog", "Scope") or "source-tool-export"),
            timestamp=normalize_timestamp(
                first_value(lowered, "System.DateModified", "DateModified", "Modified", "LastModified")
                or first_value(lowered, "System.DateCreated", "DateCreated", "Created", "CreationTime")
            ),
            deleted_state=str(first_value(lowered, "IsDeleted", "Deleted", "DeletedState", "IndexState") or "not-provided"),
            page_locator={},
            row_cluster_evidence={
                "property_fields": list(lowered),
                "entry_id": str(first_value(lowered, "DocID", "DocumentID", "EntryID", "ID") or ""),
            },
            report_grade=report_grade,
        ),
        "validation_required": False,
        "validation_checks": validation_checks,
        "core_accuracy_gates": windows_search_core_accuracy_gates(
            "windows-search-index-entry",
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "item_path": item_path,
                "url": str(first_value(lowered, "URL", "System.ItemUrl", "ItemUrl") or ""),
                "content_snippet": content,
                "property_fields": list(lowered),
                "validation_checks": validation_checks,
            },
        ),
        "search_index_validation_matrix": search_index_validation_matrix(validation_checks),
        "search_index_report_grade_assessment": report_grade,
        "search_index_native_capabilities": WINDOWS_SEARCH_CAPABILITIES,
        "windows_search_analyst_review_profile": windows_search_analyst_review_profile(
            artifact_type="windows-search-index-entry",
            source_format=path.suffix.lower().lstrip("."),
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={
                "item_path": item_path,
                "file_name": file_name,
                "url": str(first_value(lowered, "URL", "System.ItemUrl", "ItemUrl") or ""),
                "content_snippet": content[:1000],
                "modified_at": normalize_timestamp(first_value(lowered, "System.DateModified", "DateModified", "Modified", "LastModified")),
            },
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "raw": dict(row),
        "raw_preview": json.dumps(row, ensure_ascii=False, sort_keys=True)[:2000],
    }
    return ArtifactRecord(
        provider=WindowsSearchIndexProvider.name,
        artifact_type="windows-search-index-entry",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def build_search_index_summary(root: Path, records: Sequence[ArtifactRecord]) -> ArtifactRecord | None:
    entries = [record for record in records if record.artifact_type == "windows-search-index-entry"]
    edb_files = [record for record in records if record.artifact_type == "windows-search-edb-file"]
    edb_pivots = [record for record in records if record.artifact_type == "windows-search-edb-pivot"]
    edb_page_candidates = [record for record in records if record.artifact_type == "windows-search-edb-page-candidate"]
    edb_table_candidates = [record for record in records if record.artifact_type == "windows-search-edb-table-candidate"]
    edb_row_candidates = [record for record in records if record.artifact_type == "windows-search-edb-row-candidate"]
    if (
        not entries
        and not edb_files
        and not edb_pivots
        and not edb_page_candidates
        and not edb_table_candidates
        and not edb_row_candidates
    ):
        return None
    extension_counts: Counter[str] = Counter()
    source_files: set[str] = set()
    for record in entries:
        details = record.details
        extension = str(details.get("extension") or "")
        if extension:
            extension_counts[extension] += 1
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
    for record in edb_pivots:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
    for record in edb_row_candidates:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
    for record in edb_page_candidates:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
    table_family_counts: Counter[str] = Counter()
    for record in edb_table_candidates:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
        table_family = str(details.get("table_family") or "")
        if table_family:
            table_family_counts[table_family] += 1
    edb_inventory = []
    edb_string_hit_count = 0
    for record in edb_files:
        details = record.details
        source_path = str(details.get("source_path") or record.path)
        source_files.add(source_path)
        hit_count = int(details.get("extracted_string_count") or 0)
        edb_string_hit_count += hit_count
        edb_inventory.append(
            {
                "source_path": source_path,
                "signature_valid": bool(dict(details.get("ese_header") or {}).get("signature_valid")),
                "extracted_string_count": hit_count,
                "native_candidate_metadata": dict(details.get("native_candidate_metadata") or {}),
                "commercial_grade_ready": bool(details.get("commercial_grade_ready")),
                "risk_flags": list(details.get("risk_flags") or [])[:10],
            }
        )
    return ArtifactRecord(
        provider=WindowsSearchIndexProvider.name,
        artifact_type="windows-search-index-summary",
        path=str(root.resolve()),
        supported=True,
        details={
            "parser": "windows-search-index-summary",
            "parser_version": PARSER_VERSION,
            "coverage_status": "summarized",
            "reportability": "triage",
            "source_path": str(root.resolve()),
            "entry_count": len(entries),
            "inventory_count": len(edb_files),
            "edb_pivot_count": len(edb_pivots),
            "edb_page_candidate_count": len(edb_page_candidates),
            "edb_table_candidate_count": len(edb_table_candidates),
            "edb_row_candidate_count": len(edb_row_candidates),
            "source_files": sorted(source_files),
            "extension_counts": [{"value": value, "count": count} for value, count in extension_counts.most_common(25)],
            "table_family_counts": [
                {"value": value, "count": count} for value, count in table_family_counts.most_common(25)
            ],
            "edb_string_hit_count": edb_string_hit_count,
            "edb_inventory": edb_inventory,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": WINDOWS_SEARCH_EDB_BLOCKERS if edb_files else [],
        },
    )


def windows_edb_report_citation_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    artifact_type: str,
    artifact_scope: str,
    source_format: str,
    source_index: int,
    item_path: str,
    url: str,
    content_snippet: str,
    table_family: str,
    timestamp: str,
    deleted_state: str,
    page_locator: Mapping[str, object],
    row_cluster_evidence: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    normalized_path = normalize_windows_search_path(item_path)
    row_identity = {
        "artifact_scope": artifact_scope,
        "source_format": source_format,
        "source_index": source_index,
        "table_family": table_family,
        "item_path": item_path,
        "normalized_path": normalized_path,
        "file_name": filename_from_path(item_path),
        "url": url,
        "content_hash": stable_search_json_sha256(content_snippet) if content_snippet else "",
        "timestamp": timestamp,
        "timestamp_semantics": "source-tool-export-timestamp" if artifact_scope == "source-tool-export" else "not-decoded-native-edb",
        "deleted_state": deleted_state,
        "deleted_state_semantics": "candidate-marker-not-row-decoded"
        if deleted_state == "candidate-marker-present"
        else "not-decoded-or-not-provided",
        "page_locator": dict(page_locator),
    }
    citation_refs: list[dict[str, object]] = [
        {
            "kind": "windows-edb-source",
            "ref_id": "windows-edb-source",
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_format": source_format,
            "source_viewer_locator": {
                "viewer": "table-row" if artifact_scope == "source-tool-export" else "source-hex",
                "source_index": source_index,
                "page_offset": page_locator.get("page_offset", ""),
            },
        },
        {
            "kind": "windows-edb-path-url-content",
            "ref_id": "windows-edb-path-url-content",
            "normalized_path_sha256": stable_search_json_sha256(normalized_path),
            "url": url,
            "content_hash": row_identity["content_hash"],
            "field_status": {
                "path_present": bool(item_path),
                "url_present": bool(url),
                "content_present": bool(content_snippet),
            },
        },
        {
            "kind": "windows-edb-table-state",
            "ref_id": "windows-edb-table-state",
            "table_family": table_family,
            "deleted_state": deleted_state,
            "deleted_state_semantics": row_identity["deleted_state_semantics"],
            "native_row_decoded": False,
        },
    ]
    if timestamp:
        citation_refs.append(
            {
                "kind": "windows-edb-timestamp",
                "ref_id": "windows-edb-timestamp",
                "timestamp": timestamp,
                "timestamp_semantics": row_identity["timestamp_semantics"],
            }
        )
    if page_locator:
        citation_refs.append(
            {
                "kind": "windows-edb-page-locator",
                "ref_id": "windows-edb-page-locator",
                "page_index": page_locator.get("page_index", ""),
                "page_offset": page_locator.get("page_offset", ""),
                "page_size": page_locator.get("page_size", ""),
                "page_sha256": page_locator.get("page_sha256", ""),
                "source_viewer_locator": {
                    "viewer": "source-hex",
                    "source_offset": page_locator.get("page_offset", 0) or 0,
                    "length": page_locator.get("page_size", 0) or 0,
                },
            }
        )
    if row_cluster_evidence:
        citation_refs.append(
            {
                "kind": "windows-edb-row-cluster",
                "ref_id": "windows-edb-row-cluster",
                "field_presence_profile": dict(row_cluster_evidence.get("field_presence_profile") or {}),
                "page_table_marker_hits": dict(row_cluster_evidence.get("page_table_marker_hits") or {}),
                "candidate_basis": row_cluster_evidence.get("candidate_basis", ""),
                "summary": {
                    key: value
                    for key, value in row_cluster_evidence.items()
                    if key not in {"field_presence_profile", "page_table_marker_hits"}
                },
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "windows-edb-report-citation-manifest-v1",
        "parser_version": PARSER_VERSION,
        "artifact_type": artifact_type,
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": source_format,
        },
        "row_identity": row_identity,
        "row_identity_hash": stable_search_json_sha256(row_identity),
        "citation_refs": citation_refs,
        "citation_ref_count": len(citation_refs),
        "validation_summary": {
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or ["#11"]),
            "native_ese_catalog_decode_available": bool(WINDOWS_SEARCH_CAPABILITIES["native_ese_catalog_decode"]),
            "native_row_level_decode_available": bool(WINDOWS_SEARCH_CAPABILITIES["native_row_level_decode"]),
            "native_deleted_state_decode_available": bool(WINDOWS_SEARCH_CAPABILITIES["native_deleted_state_decode"]),
            "trusted_windows_search_parser_diff_required": artifact_scope != "source-tool-export",
        },
        "reportability": {
            "allowed_use": "search-index-triage-pivot",
            "standalone_decoded_row_fact": False,
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "blockers": sorted(
                set(str(item) for item in report_grade.get("blockers") or [])
                | {"windows-edb-native-row-decoder-validation-required", "windows-edb-deleted-state-trusted-tool-diff-required"}
            ),
        },
    }
    manifest["manifest_sha256"] = stable_search_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_search_json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def normalize_windows_search_path(path: str) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    try:
        return str(PureWindowsPath(text)).lower()
    except ValueError:
        return re.sub(r"[\\/]+", "\\\\", text).lower()


def build_search_content_candidates(pivots: Mapping[str, object], *, limit: int = 50) -> list[str]:
    path_values = {str(value) for value in pivots.get("path_candidates") or []}
    url_values = {str(value) for value in pivots.get("url_candidates") or []}
    candidates: list[str] = []
    seen: set[str] = set()
    for value in pivots.get("extracted_strings") or []:
        text = str(value).strip()
        lowered = text.lower()
        if not text or text in path_values or text in url_values:
            continue
        if first_url(text) or re.search(r"(?i)(?:[a-z]:\\|\\\\)", text):
            continue
        if any(marker in lowered for markers in WINDOWS_SEARCH_TABLE_MARKERS.values() for marker in markers):
            continue
        if len(text) < 20 or " " not in text:
            continue
        if text in seen:
            continue
        seen.add(text)
        candidates.append(text[:1000])
        if len(candidates) >= limit:
            break
    return candidates


def build_search_row_candidates(pivots: Mapping[str, object], *, limit: int = 50) -> list[dict[str, object]]:
    page_rows = build_page_local_search_row_candidates(pivots, limit=limit)
    paths = [str(value) for value in pivots.get("path_candidates") or [] if str(value)]
    urls = [str(value) for value in pivots.get("url_candidates") or [] if str(value)]
    contents = [str(value) for value in pivots.get("content_candidates") or [] if str(value)]
    if not contents:
        contents = build_search_content_candidates(pivots)
    rows: list[dict[str, object]] = list(page_rows)
    seen: set[tuple[str, str, str]] = {
        (str(row.get("item_path") or ""), str(row.get("url") or ""), str(row.get("content_snippet") or ""))
        for row in page_rows
    }
    if page_rows or len(rows) >= limit:
        return rows[:limit]
    if paths:
        for index, item_path in enumerate(paths[:limit]):
            content = contents[index] if index < len(contents) else (contents[0] if contents else "")
            url = urls[index] if index < len(urls) else ""
            add_search_row_candidate(rows, seen, item_path, url, content, "path-content-url-position-correlation")
            if len(rows) >= limit:
                return rows
    for index, url in enumerate(urls[:limit]):
        content = contents[index] if index < len(contents) else (contents[0] if contents else "")
        add_search_row_candidate(rows, seen, "", url, content, "url-content-position-correlation")
        if len(rows) >= limit:
            return rows
    for index, content in enumerate(contents[:limit]):
        add_search_row_candidate(rows, seen, "", "", content, "content-string-candidate")
        if len(rows) >= limit:
            return rows
    return rows


def build_page_local_search_row_candidates(pivots: Mapping[str, object], *, limit: int) -> list[dict[str, object]]:
    page_map = pivots.get("ese_page_map") if isinstance(pivots.get("ese_page_map"), Mapping) else {}
    page_samples = [sample for sample in page_map.get("page_samples") or [] if isinstance(sample, Mapping)]
    rows: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, int]] = set()
    for sample in page_samples:
        path_candidates = [str(value) for value in sample.get("path_candidates") or [] if str(value)]
        url_candidates = [str(value) for value in sample.get("url_candidates") or [] if str(value)]
        content_candidates = [str(value) for value in sample.get("content_candidates") or [] if str(value)]
        if not path_candidates and not url_candidates and not content_candidates:
            continue
        page_offset = int(sample.get("page_offset") or 0)
        max_items = max(len(path_candidates), len(url_candidates), len(content_candidates), 1)
        for index in range(max_items):
            item_path = path_candidates[index] if index < len(path_candidates) else (path_candidates[0] if path_candidates else "")
            url = url_candidates[index] if index < len(url_candidates) else (url_candidates[0] if url_candidates else "")
            content = content_candidates[index] if index < len(content_candidates) else (content_candidates[0] if content_candidates else "")
            key = (item_path, url, content, page_offset)
            if key in seen or not any((item_path, url, content)):
                continue
            seen.add(key)
            rows.append(
                {
                    "item_path": item_path,
                    "file_name": filename_from_path(item_path),
                    "url": url,
                    "content_snippet": content[:1000],
                    "path_source": "page-local-native-path-string" if item_path else "",
                    "url_source": "page-local-native-url-string" if url else "",
                    "content_source": "page-local-native-content-string" if content else "",
                    "correlation_method": "page-local-path-url-content-correlation",
                    "page_local_correlation": True,
                    "page_index": int(sample.get("page_index") or 0),
                    "page_offset": page_offset,
                    "page_sha256": str(sample.get("page_sha256") or ""),
                    "page_table_marker_hits": {
                        str(family): [str(marker) for marker in markers]
                        for family, markers in dict(sample.get("table_marker_hits") or {}).items()
                    },
                    "field_presence_profile": search_row_field_presence_profile(item_path, url, content, sample),
                    "parser_confidence": search_row_candidate_confidence(
                        item_path,
                        url,
                        content,
                        "page-local-path-url-content-correlation",
                    ),
                }
            )
            if len(rows) >= limit:
                return rows
    return rows


def add_search_row_candidate(
    rows: list[dict[str, object]],
    seen: set[tuple[str, str, str]],
    item_path: str,
    url: str,
    content: str,
    method: str,
) -> None:
    key = (item_path, url, content)
    if key in seen or not any(key):
        return
    seen.add(key)
    rows.append(
        {
            "item_path": item_path,
            "file_name": filename_from_path(item_path),
            "url": url,
            "content_snippet": content[:1000],
            "path_source": "native-path-string" if item_path else "",
            "url_source": "native-url-string" if url else "",
            "content_source": "native-content-string" if content else "",
            "correlation_method": method,
            "field_presence_profile": search_row_field_presence_profile(item_path, url, content, {}),
            "parser_confidence": search_row_candidate_confidence(item_path, url, content, method),
        }
    )


def search_row_candidate_confidence(item_path: str, url: str, content: str, method: str) -> float:
    score = 0.32
    if item_path:
        score += 0.18
    if url:
        score += 0.12
    if content:
        score += 0.12
    if method.startswith("path-content"):
        score += 0.08
    if method.startswith("page-local"):
        score += 0.12
    return round(min(score, 0.74), 2)


def search_row_field_presence_profile(
    item_path: str,
    url: str,
    content: str,
    page_sample: Mapping[str, object],
) -> dict[str, bool]:
    marker_hits = dict(page_sample.get("table_marker_hits") or {}) if isinstance(page_sample, Mapping) else {}
    return {
        "item_path": bool(item_path),
        "file_name": bool(filename_from_path(item_path)),
        "url": bool(url),
        "content_snippet": bool(content),
        "page_offset": page_sample.get("page_offset") is not None if isinstance(page_sample, Mapping) else False,
        "page_hash": bool(page_sample.get("page_sha256")) if isinstance(page_sample, Mapping) else False,
        "property_store_marker": "property-store" in marker_hits,
        "content_index_marker": "content-index" in marker_hits,
        "deleted_state_marker": "deleted-state" in marker_hits,
    }


def windows_search_analyst_review_profile(
    *,
    artifact_type: str,
    source_format: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    risk_flags: Sequence[str] | None = None,
    evidence_fields: Mapping[str, object] | None = None,
) -> dict[str, object]:
    catalog = WINDOWS_SEARCH_ANALYST_REVIEW_CATALOG.get(artifact_type) or {
        "severity": "info",
        "summary": "Windows Search artifact requiring source-specific validation.",
        "evidence_interpretation": "search-index triage pivot",
        "not_proof_of": ["decoded native row fact without parser validation"],
        "primary_pivots": ["item_path", "url", "content_snippet"],
        "correlation_targets": ["MFT", "USN", "Dedicated Windows.edb parser"],
        "analyst_questions": [
            "What original source file or URL should be opened?",
            "Which source parser validates this row?",
            "Is this a search lead or reportable evidence item?",
        ],
        "risk_tags": ["search-index-review"],
    }
    values = dict(evidence_fields or {})
    source_values: dict[str, object] = {}
    for pivot in catalog.get("primary_pivots", []):
        key = str(pivot)
        value = values.get(key)
        if value not in ("", None, [], {}):
            source_values[key] = bounded_search_review_value(value)
    failed_checks = sorted(str(key) for key, value in validation_checks.items() if not bool(value))
    blockers = sorted(
        set(str(item) for item in report_grade.get("blockers", []) if str(item))
        | {"windows-edb-trusted-parser-diff-required"}
    )
    return {
        "profile_version": "windows-search-analyst-review-profile-v1",
        "artifact_type": artifact_type,
        "source_format": source_format,
        "severity": str(catalog.get("severity") or "info"),
        "summary": str(catalog.get("summary") or ""),
        "evidence_interpretation": str(catalog.get("evidence_interpretation") or ""),
        "not_proof_of": list(catalog.get("not_proof_of") or []),
        "analyst_questions": list(catalog.get("analyst_questions") or []),
        "primary_pivots": list(catalog.get("primary_pivots") or []),
        "source_field_values": source_values,
        "correlation_targets": list(catalog.get("correlation_targets") or []),
        "risk_tags": sorted(set([str(item) for item in catalog.get("risk_tags", [])] + [str(item) for item in risk_flags or []])),
        "validation_required": bool(report_grade.get("status") != "report-grade-ready" or failed_checks),
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": blockers,
        "report_guidance": (
            "Treat native Windows.edb rows as search/review pivots until row-level ESE decoding, deleted-state "
            "semantics, and trusted parser diffs are attached."
        ),
    }


def bounded_search_review_value(value: object) -> object:
    if isinstance(value, str):
        return value[:1000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)[:1000]
    if len(text) <= 2000:
        return value
    return {"truncated_json_preview": text[:2000], "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def page_candidate_confidence(
    paths: Sequence[str],
    urls: Sequence[str],
    contents: Sequence[str],
    table_marker_hits: Mapping[str, Sequence[str]],
) -> float:
    score = 0.34
    if paths:
        score += 0.14
    if urls:
        score += 0.08
    if contents:
        score += 0.12
    if table_marker_hits:
        score += min(0.18, len(table_marker_hits) * 0.05)
    return round(min(score, 0.76), 2)


def search_index_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    labels = {
        "ese_header_readable": ("ESE header readable", "critical"),
        "ese_signature_valid": ("ESE signature valid", "critical"),
        "ese_page_map_built": ("ESE page map built", "high"),
        "page_level_marker_correlation_available": ("Page marker correlation", "medium"),
        "has_path_pivots": ("Path pivots", "medium"),
        "has_url_pivots": ("URL pivots", "medium"),
        "has_content_candidates": ("Content candidates", "medium"),
        "has_table_family_candidates": ("Table family candidates", "medium"),
        "has_native_row_candidates": ("Native row candidates", "medium"),
        "has_candidate_value": ("Candidate value", "medium"),
        "has_path_or_url": ("Path or URL", "medium"),
        "has_source_path_or_url": ("Source path or URL", "high"),
        "has_item_path": ("Item path", "high"),
        "has_file_name": ("File name", "medium"),
        "has_content": ("Content", "medium"),
        "has_content_snippet": ("Content snippet", "medium"),
        "has_page_source_citation": ("Page source citation", "high"),
        "has_field_presence_profile": ("Field presence profile", "medium"),
        "has_page_local_table_markers": ("Page-local table markers", "medium"),
        "has_timestamp": ("Timestamp", "high"),
        "ese_catalog_decoded": ("ESE catalog decoded", "critical"),
        "row_level_decoding_available": ("Row-level decoding", "critical"),
        "timestamps_decoded_from_native_rows": ("Native row timestamps", "high"),
        "deleted_state_decoded_from_native_rows": ("Native deleted state", "high"),
        "requires_windows_search_parser": ("Windows Search parser validation", "critical"),
        "source_tool_export_validation_required": ("Source tool export validation", "high"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key in {"candidate_kind", "page_size_detected", "table_family_marker_count"}:
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_") or key.endswith("_required")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append({"id": key.replace("_", "-"), "label": label, "passed": passed, "severity": severity, "detail": value})
    return matrix


def search_index_report_grade_assessment(
    validation_matrix: Sequence[Mapping[str, object]],
    *,
    validation_required: bool,
    extra_blockers: Sequence[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if isinstance(item, Mapping) and not item.get("passed")]
    blockers = set(WINDOWS_SEARCH_EDB_BLOCKERS)
    blockers.update(f"validation-check-failed:{item}" for item in failed)
    blockers.update(str(item) for item in extra_blockers if str(item))
    if validation_required:
        blockers.add("windows-search-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if isinstance(item, Mapping) and item.get("passed")],
        "commercial_gap_ids": ["#11"],
        "next_validation_step": "Validate Windows.edb paths, content, timestamps, and deleted/index state with a full ESE/Search parser before report-grade use.",
    }


def windows_search_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = (
        details.get("search_index_validation_matrix")
        if isinstance(details.get("search_index_validation_matrix"), Sequence)
        else []
    )
    report_grade = (
        details.get("search_index_report_grade_assessment")
        if isinstance(details.get("search_index_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    metadata = details.get("native_candidate_metadata") if isinstance(details.get("native_candidate_metadata"), Mapping) else {}
    trusted_diff = (
        details.get("windows_edb_trusted_diff")
        if isinstance(details.get("windows_edb_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    reportability_decision = windows_search_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-011-015",
        "item_numbers": [11],
        "implementation_track": "native-parser-depth",
        "objective": "Expose Windows.edb ESE/Search validation evidence, row limits, and commercial blockers on native candidates.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_index:{details.get('source_index', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
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
        "windows_edb_trusted_diff": trusted_diff,
        "large_data_controls": {
            "bounded_page_map": True,
            "page_count_scanned": int(metadata.get("page_count_scanned") or 0),
            "string_scan_bytes": int(metadata.get("string_scan_bytes") or 0),
            "row_level_native_decode_required_for_commercial_claims": True,
            "deleted_state_decode_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish native ESE catalog/table/row decoding with Windows Search schema fixtures and cross-tool diffs.",
        "external_evidence_required": True,
    }


def windows_search_reportability_decision(
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("windows-edb-native-row-decoder-validation-required")
    blockers.add("windows-edb-deleted-state-trusted-tool-diff-required")
    return {
        "profile_version": "windows-search-reportability-decision-v1",
        "commercial_gap_id": "#11",
        "decision": "do-not-report-native-row-as-decoded-fact",
        "allowed_use": "search-index-triage-pivot",
        "blockers": sorted(blockers),
        "source_location_available": bool(details.get("page_offset") not in (None, "") or details.get("source_hashes")),
        "required_before_report": [
            "ESE catalog/table/row decoding validated",
            "row timestamps and property IDs decoded from native tables",
            "deleted/index state compared against trusted Windows Search parser output",
            "source hash, page offset, and parser version retained in report citation",
        ],
    }


def windows_search_core_accuracy_gates(artifact_type: str, details: Mapping[str, object]) -> list[dict[str, object]]:
    if not artifact_type.startswith("windows-search"):
        return []
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("windows_edb_trusted_diff")
        if isinstance(details.get("windows_edb_trusted_diff"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"source_index:{details.get('source_index', '')}",
    ]
    if details.get("page_offset") not in (None, ""):
        evidence_refs.append(f"page_offset:{details.get('page_offset')}")
    if details.get("page_sha256"):
        evidence_refs.append(f"page_sha256:{details.get('page_sha256')}")
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if details.get("ese_page_map") or details.get("table_family") or details.get("table_families") or details.get("table_family_candidates") or checks.get("ese_page_map_built"):
        satisfied.append("catalog/table/page mapping")
    if details.get("property_fields") or details.get("matched_markers") or details.get("table_marker_hits") or details.get("table_family") == "property-store":
        satisfied.append("property ID/name mapping")
    if details.get("field_presence_profile") or checks.get("has_field_presence_profile"):
        satisfied.append("field presence profile")
    if details.get("page_table_marker_hits") or checks.get("has_page_local_table_markers"):
        satisfied.append("page-local table marker correlation")
    if details.get("item_path") or details.get("url") or details.get("content_snippet") or details.get("path_candidates") or details.get("url_candidates") or details.get("content_candidates"):
        satisfied.append("path/URL/content correlation")
    if details.get("deleted_state") == "candidate-marker-present" or details.get("table_family") == "deleted-state" or "deleted-state" in list(details.get("table_family_candidates") or []):
        satisfied.append("deleted/index-state validation")
    if details.get("page_offset") not in (None, "") or details.get("page_sha256") or checks.get("ese_page_map_built") or checks.get("has_page_source_citation") or hashes.get("sha256"):
        satisfied.append("page-level source citation")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted Windows.edb parser diff pass")
    return [build_accuracy_gate(11, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_windows_edb_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    rapid_index = index_search_rows(rapid_rows)
    trusted_index = index_search_rows(trusted_rows)
    return build_simple_trusted_row_diff(
        rapid_index,
        trusted_index,
        trusted_tool=trusted_tool,
        recognized_tools=WINDOWS_SEARCH_TRUSTED_TOOLS,
        mode="windows-edb-trusted-parser-diff-v1",
        blocker="windows-edb-trusted-parser-diff-required",
        key_label="search_key",
    )


def index_search_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = search_diff_row_payload(row)
        normalized = {
            "artifact_type": normalized_diff_value(first_alias(payload, "artifact_type")),
            "path": normalized_diff_value(first_alias(payload, "item_path", "path", "file_path", "system.itempathdisplay")),
            "url": normalized_diff_value(first_alias(payload, "url", "item_url", "itemurl", "system.itemurl")),
            "content": normalized_diff_value(first_alias(payload, "content", "content_snippet", "system.search.contents", "text")),
            "deleted_state": normalized_deleted_state(first_alias(payload, "deleted_state", "isdeleted", "deleted", "index_state")),
            "table": normalized_diff_value(first_alias(payload, "table", "table_family", "table_name")),
            "table_family_candidates": normalized_diff_list(
                first_alias(payload, "table_family_candidates", "table_families", "TableFamilies")
            ),
            "page_offset": normalized_int_text(first_alias(payload, "page_offset", "PageOffset", "offset")),
            "page_sha256": normalized_diff_value(first_alias(payload, "page_sha256", "PageSHA256", "page_hash")),
            "page_index": normalized_int_text(first_alias(payload, "page_index", "PageIndex")),
            "source_format": normalized_diff_value(first_alias(payload, "source_format", "SourceFormat")),
        }
        key = search_diff_key(normalized)
        if key:
            indexed[key] = normalized
    return indexed


def search_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    if not details:
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def search_diff_key(normalized: Mapping[str, str]) -> str:
    base = normalized.get("path") or normalized.get("url") or normalized.get("content")
    if not base:
        return ""
    page_ref = normalized.get("page_sha256") or normalized.get("page_offset")
    table_ref = normalized.get("table") or normalized.get("table_family_candidates")
    return "|".join(value for value in (base, page_ref, table_ref) if value)


def build_simple_trusted_row_diff(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
    recognized_tools: set[str],
    mode: str,
    blocker: str,
    key_label: str,
) -> dict[str, object]:
    tool_key = trusted_tool.strip().lower().replace(" ", "")
    recognized = tool_key in {item.replace(" ", "") for item in recognized_tools}
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field, rapid_value in rapid.items():
            trusted_value = trusted.get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        key_label: key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": mode,
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-native-output-as-final",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def first_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalized_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence):
        parts = [str(item).strip() for item in value if str(item).strip()]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


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


def normalized_deleted_state(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = normalized_diff_value(value)
    if text in {"1", "yes", "y", "deleted", "true"}:
        return "true"
    if text in {"0", "no", "n", "active", "present", "false"}:
        return "false"
    return text


def detect_search_table_families(pivots: Mapping[str, object]) -> list[str]:
    strings = [str(value) for value in pivots.get("extracted_strings") or []]
    lowered_blob = "\n".join(strings).lower()
    return [
        table_family
        for table_family, markers in WINDOWS_SEARCH_TABLE_MARKERS.items()
        if any(marker in lowered_blob for marker in markers)
    ]


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


def normalize_timestamp(value: object) -> str:
    return str(value or "").strip().replace("Z", "+00:00")


def filename_from_path(value: str) -> str:
    if not value:
        return ""
    return PureWindowsPath(value).name


def extension_from_name(value: str) -> str:
    suffix = PureWindowsPath(value).suffix.lower()
    return suffix if suffix else ""


def first_url(value: str) -> str:
    match = re.search(r"(?i)https?://[^\s\x00\"'<>]{4,300}", value)
    return match.group(0).rstrip(".,);]") if match else ""


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
