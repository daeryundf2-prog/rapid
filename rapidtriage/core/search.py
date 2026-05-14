from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from .analysis import build_search_analysis
from .docs import build_preview, extract_text
from .files import CATEGORY_RULES
from .forensic_accuracy import build_accuracy_gate
from .search_backend import build_search_backend_contract

IMAGE_EXTS = set(CATEGORY_RULES["images"]["extensions"])
SEARCH_FEATURE_GAP_ID = "#61"
WORKBENCH_SEARCH_ITEM_NUMBER = 16
SEARCH_NATIVE_CAPABILITIES = {
    "exact_search": True,
    "regex_search": True,
    "fuzzy_levenshtein_search": True,
    "simple_suffix_stemming": True,
    "proximity_window_summary": True,
    "full_linguistic_stemming": False,
    "semantic_near_duplicate_search": False,
}
SEARCH_REPORT_GRADE_BLOCKERS = [
    "fuzzy-and-stemmed-search-are-triage-aids-not-exact-source-proof",
    "regex-pattern-quality-is-analyst-controlled-and-must-be-documented",
    "proximity-window-results-require-source-row-verification-before-reporting",
    "trusted-advanced-search-query-hit-diff-is-required-before-commercial-claim",
]
SEARCH_TRUSTED_DIFF_BLOCKER_61 = "trusted-advanced-search-query-hit-diff-missing"


class SearchError(ValueError):
    """Raised when unified search cannot load a completed run."""


def stable_search_sha256(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def run_unified_search(
    run_summary: Mapping[str, object] | Path,
    keywords: Sequence[str],
    *,
    include_ocr: bool = True,
    limit: int = 500,
    sources: Sequence[str] | None = None,
    extensions: Sequence[str] | None = None,
    path_contains: str | None = None,
    include_analysis: bool = True,
    search_mode: str = "exact",
    fuzzy_distance: int = 1,
    proximity_window: int = 0,
) -> Dict[str, object]:
    summary = load_run_summary(run_summary)
    normalized = normalize_keywords(keywords, search_mode=search_mode)
    if not normalized:
        raise SearchError("at least one keyword is required")
    normalized_search_mode = normalize_search_mode(search_mode)
    normalized_fuzzy_distance = max(0, min(int(fuzzy_distance or 0), 2))
    normalized_proximity_window = max(0, min(int(proximity_window or 0), 100))
    normalized_sources = {item.strip().lower() for item in (sources or []) if item.strip()}
    normalized_extensions = normalize_extensions(extensions or [])
    normalized_path_fragment = (path_contains or "").strip().lower()

    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping):
        raise SearchError("run summary does not include outputs")

    matches: list[dict[str, object]] = []
    document_errors: list[dict[str, str]] = []
    ocr_errors: list[dict[str, str]] = []
    search_options = {
        "search_mode": normalized_search_mode,
        "fuzzy_distance": normalized_fuzzy_distance,
        "proximity_window": normalized_proximity_window,
    }
    document_matches, document_errors = search_docs(outputs, normalized, limit=limit, search_options=search_options)
    matches.extend(document_matches)
    matches.extend(search_files(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_artifacts(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_indicators(outputs, normalized, limit=limit, search_options=search_options))
    matches.extend(search_timeline(outputs, normalized, limit=limit, search_options=search_options))
    if include_ocr:
        ocr_matches, ocr_errors = search_ocr(outputs, normalized, limit=limit, search_options=search_options)
        matches.extend(ocr_matches)
    matches = filter_matches(
        matches,
        sources=normalized_sources,
        extensions=normalized_extensions,
        path_fragment=normalized_path_fragment,
    )

    if limit:
        matches = matches[:limit]
    matches = enrich_unified_search_matches(matches, search_options=search_options)
    query_hit_manifest = build_advanced_search_query_hit_manifest(
        matches=matches,
        keywords=normalized,
        options=search_options,
        limit=limit,
    )
    source_counts: dict[str, int] = {}
    keyword_counts: dict[str, int] = {keyword: 0 for keyword in normalized}
    for match in matches:
        source = str(match.get("source", "unknown"))
        source_counts[source] = source_counts.get(source, 0) + 1
        for keyword in match.get("matched_keywords", []):
            keyword_counts[str(keyword)] = keyword_counts.get(str(keyword), 0) + 1

    core_accuracy_gates = search_core_accuracy_gates(
        matches=matches,
        options=search_options,
        query_hit_manifest=query_hit_manifest,
    )
    report_grade = search_report_grade_assessment()
    advanced_profile = advanced_search_profile(
        keywords=normalized,
        matches=matches,
        options=search_options,
        include_ocr=include_ocr,
        include_analysis=include_analysis,
        limit=limit,
        query_hit_manifest=query_hit_manifest,
    )
    search_backend_contract = build_search_backend_contract(
        keywords=normalized,
        limit=limit,
        corpus_estimate={
            "document_rows": len(source_counts),
            "artifact_rows": len(matches),
            "target_rows": 1_000_000,
        },
    )
    payload: Dict[str, object] = {
        "command": "search",
        "generated_at": dt.datetime.now().isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary", "")),
        "keywords": normalized,
        "options": {
            "include_ocr": include_ocr,
            "limit": limit,
            "sources": sorted(normalized_sources),
            "extensions": sorted(normalized_extensions),
            "path_contains": normalized_path_fragment,
            **search_options,
        },
            "summary": {
                "match_count": len(matches),
                "source_counts": source_counts,
                "keyword_counts": keyword_counts,
                "document_error_count": len(document_errors),
                "ocr_error_count": len(ocr_errors),
                "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
                "commercial_grade_ready": False,
            },
            "matches": matches,
            "documents": {
                "errors": document_errors,
            },
            "ocr": {
                "enabled": include_ocr,
                "errors": ocr_errors,
        },
        "advanced_search_profile": advanced_profile,
        "advanced_search_query_hit_manifest": query_hit_manifest,
        "advanced_search_query_hit_manifest_hash": query_hit_manifest["manifest_hash"],
        "search_backend_contract": search_backend_contract,
        "search_backend_contract_hash": search_backend_contract["contract_hash"],
        "search_native_capabilities": dict(SEARCH_NATIVE_CAPABILITIES),
        "workbench_search_profile": workbench_search_profile(
            matches=matches,
            source_counts=source_counts,
            include_ocr=include_ocr,
            include_analysis=include_analysis,
            limit=limit,
            options=search_options,
        ),
        "search_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": search_commercial_uplift_evidence(
            matches=matches,
            options=search_options,
            core_accuracy_gates=core_accuracy_gates,
            report_grade=report_grade,
            limit=limit,
            query_hit_manifest=query_hit_manifest,
        ),
    }
    if include_analysis:
        payload["analysis"] = build_search_analysis(matches, normalized)
    return payload


def workbench_search_profile(
    *,
    matches: Sequence[Mapping[str, object]],
    source_counts: Mapping[str, int],
    include_ocr: bool,
    include_analysis: bool,
    limit: int,
    options: Mapping[str, object],
) -> dict[str, object]:
    covered_sources = sorted(source for source, count in source_counts.items() if count)
    target_sources = ["documents", "files", "web", "artifacts", "timeline", "indicators", "ocr"]
    missing_sources = [source for source in target_sources if source not in covered_sources]
    verification_summary = search_source_verification_summary(matches)
    return {
        "profile_version": "analyst-workbench-unified-search-v1",
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": WORKBENCH_SEARCH_ITEM_NUMBER,
        "objective": "One search result set across documents, file metadata, web/browser artifacts, normalized artifacts, timeline, indicators, and OCR sidecars.",
        "implemented_sources": covered_sources,
        "target_sources": target_sources,
        "missing_sources_in_this_result": missing_sources,
        "search_modes": {
            "exact": True,
            "regex": True,
            "fuzzy": True,
            "active_mode": str(options.get("search_mode") or "exact"),
            "proximity_window": int(options.get("proximity_window") or 0),
        },
        "review_flow_contract": {
            "match_pointer": True,
            "path_for_viewer": True,
            "matched_keywords": True,
            "preview": True,
            "metadata": True,
            "source_verification_profile": True,
        },
        "source_verification_summary": verification_summary,
        "large_data_controls": {
            "bounded_result_limit": limit,
            "returned_match_count": len(matches),
            "ocr_optional": True,
            "ocr_enabled": include_ocr,
            "analysis_optional": True,
            "analysis_enabled": include_analysis,
        },
        "reportability_decision": {
            "decision": "do-not-report-search-hit-without-source-viewer-verification",
            "allowed_use": "case-wide-triage-and-review-routing",
            "required_before_report": [
                "open source viewer for each report candidate",
                "verify source hash or citation metadata",
                "record review decision and limitation wording",
            ],
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "large-case-search-latency-benchmark-required",
            "case-db-and-run-search-result-parity-diff-required",
            "source-viewer-verification-required-for-report-items",
        ],
    }


def enrich_unified_search_matches(
    matches: Sequence[Mapping[str, object]],
    *,
    search_options: Mapping[str, object],
) -> list[dict[str, object]]:
    enriched: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        item = dict(match)
        item["search_result_id"] = f"search-hit-{index + 1:06d}"
        item["source_verification_profile"] = search_match_source_verification_profile(item)
        hit_manifest = build_advanced_search_hit_manifest(item, search_options=search_options)
        item["advanced_search_hit_manifest"] = hit_manifest
        item["advanced_search_hit_manifest_hash"] = hit_manifest["manifest_hash"]
        enriched.append(item)
    return enriched


def build_advanced_search_hit_manifest(
    match: Mapping[str, object],
    *,
    search_options: Mapping[str, object],
) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    source_hashes = metadata.get("source_hashes") if isinstance(metadata.get("source_hashes"), Mapping) else {}
    source_sha256 = str(source_hashes.get("sha256") or metadata.get("sha256") or metadata.get("hash_sha256") or "")
    search_match = match.get("search_match") if isinstance(match.get("search_match"), Mapping) else {}
    proximity = search_match.get("proximity") if isinstance(search_match.get("proximity"), Mapping) else {}
    manifest_core: dict[str, object] = {
        "manifest_version": "advanced-search-hit-manifest-v1",
        "item_number": 61,
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "search_result_id": str(match.get("search_result_id") or ""),
        "source": str(match.get("source") or ""),
        "kind": str(match.get("kind") or ""),
        "path": str(match.get("path") or ""),
        "title": str(match.get("title") or ""),
        "pointer": str(match.get("pointer") or ""),
        "matched_keywords": [str(item) for item in match.get("matched_keywords") or []],
        "matched_keyword_hashes": [
            stable_search_sha256({"keyword": str(item)}) for item in match.get("matched_keywords") or []
        ],
        "search_mode": str(search_options.get("search_mode") or ""),
        "fuzzy_distance": int(search_options.get("fuzzy_distance") or 0),
        "proximity_window": int(search_options.get("proximity_window") or 0),
        "matched_by": str(search_match.get("matched_by") or search_match.get("mode") or ""),
        "proximity_matched": bool(proximity.get("matched")) if proximity else False,
        "source_sha256": source_sha256,
        "source_viewer_locator": {
            "viewer": "advanced-search-hit-source",
            "open_action": "open-source-viewer",
            "source": str(match.get("source") or ""),
            "path": str(match.get("path") or ""),
            "pointer": str(match.get("pointer") or ""),
        },
        "report_use_boundary": "triage-hit-only-until-source-row-is-opened-and-reviewed",
        "blockers": advanced_search_hit_report_blockers(match, source_sha256=source_sha256),
        "commercial_claim_allowed": False,
    }
    row_hash = stable_search_sha256(
        {
            "search_result_id": manifest_core["search_result_id"],
            "source": manifest_core["source"],
            "path": manifest_core["path"],
            "pointer": manifest_core["pointer"],
            "matched_keywords": manifest_core["matched_keywords"],
            "search_mode": manifest_core["search_mode"],
            "matched_by": manifest_core["matched_by"],
        }
    )
    manifest_core["hit_row_hash"] = row_hash
    return {**manifest_core, "manifest_hash": stable_search_sha256(manifest_core)}


def advanced_search_hit_report_blockers(match: Mapping[str, object], *, source_sha256: str) -> list[str]:
    blockers = ["source-row-review-required", SEARCH_TRUSTED_DIFF_BLOCKER_61]
    if not str(match.get("pointer") or ""):
        blockers.append("source-pointer-required")
    if not source_sha256:
        blockers.append("source-hash-recommended-before-report")
    search_match = match.get("search_match") if isinstance(match.get("search_match"), Mapping) else {}
    mode = str(search_match.get("mode") or "")
    if mode == "regex":
        blockers.append("regex-false-positive-review-required")
    if mode == "fuzzy":
        blockers.append("fuzzy-hit-manual-confirmation-required")
    proximity = search_match.get("proximity") if isinstance(search_match.get("proximity"), Mapping) else {}
    if proximity.get("matched"):
        blockers.append("proximity-causal-interpretation-review-required")
    return sorted(set(blockers))


def build_advanced_search_query_hit_manifest(
    *,
    matches: Sequence[Mapping[str, object]],
    keywords: Sequence[str],
    options: Mapping[str, object],
    limit: int,
) -> dict[str, object]:
    hit_rows = []
    for match in matches:
        hit_manifest = match.get("advanced_search_hit_manifest") if isinstance(match.get("advanced_search_hit_manifest"), Mapping) else {}
        source_locator = hit_manifest.get("source_viewer_locator") if isinstance(hit_manifest.get("source_viewer_locator"), Mapping) else {}
        search_match = match.get("search_match") if isinstance(match.get("search_match"), Mapping) else {}
        proximity = search_match.get("proximity") if isinstance(search_match.get("proximity"), Mapping) else {}
        hit_rows.append(
            {
                "search_result_id": str(match.get("search_result_id") or ""),
                "source": str(match.get("source") or ""),
                "kind": str(match.get("kind") or ""),
                "path": str(match.get("path") or ""),
                "pointer": str(match.get("pointer") or ""),
                "matched_keywords": [str(item) for item in match.get("matched_keywords") or []],
                "matched_by": str(search_match.get("matched_by") or search_match.get("mode") or ""),
                "proximity_matched": bool(proximity.get("matched")) if proximity else False,
                "hit_row_hash": str(hit_manifest.get("hit_row_hash") or ""),
                "hit_manifest_hash": str(hit_manifest.get("manifest_hash") or ""),
                "source_viewer_locator": dict(source_locator),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "advanced-search-query-hit-manifest-v1",
        "item_number": 61,
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "query_hash": stable_search_sha256(
            {
                "keywords": list(keywords),
                "search_mode": str(options.get("search_mode") or ""),
                "fuzzy_distance": int(options.get("fuzzy_distance") or 0),
                "proximity_window": int(options.get("proximity_window") or 0),
            }
        ),
        "keywords": list(keywords),
        "search_mode": str(options.get("search_mode") or ""),
        "fuzzy_distance": int(options.get("fuzzy_distance") or 0),
        "proximity_window": int(options.get("proximity_window") or 0),
        "result_limit": limit,
        "match_count": len(matches),
        "hit_row_hash_count": sum(1 for row in hit_rows if row.get("hit_row_hash")),
        "source_locator_count": sum(1 for row in hit_rows if row.get("source_viewer_locator")),
        "proximity_matched_count": sum(1 for row in hit_rows if row.get("proximity_matched")),
        "hits": hit_rows,
        "query_result_head_hash": stable_search_sha256(hit_rows),
        "report_use_boundary": "advanced search output is a triage manifest; report candidates still require source viewer verification and trusted diff evidence",
        "blockers": [
            "multilingual-relevance-corpus",
            "query-builder-ux-validation",
            "tuned-false-positive-false-negative-metrics",
            SEARCH_TRUSTED_DIFF_BLOCKER_61,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_search_sha256(manifest_core)}


def search_match_source_verification_profile(match: Mapping[str, object]) -> dict[str, object]:
    source = str(match.get("source") or "")
    path = str(match.get("path") or "")
    pointer = str(match.get("pointer") or "")
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    source_hashes = metadata.get("source_hashes") if isinstance(metadata.get("source_hashes"), Mapping) else {}
    source_sha256 = str(source_hashes.get("sha256") or metadata.get("sha256") or metadata.get("hash_sha256") or "")
    viewer_supported = bool(path) and source in {"documents", "files", "web", "artifacts", "timeline", "indicators", "ocr"}
    hash_or_pointer = bool(source_sha256 or pointer)
    return {
        "profile_version": "unified-search-source-verification-v1",
        "source": source,
        "path": path,
        "pointer": pointer,
        "source_sha256": source_sha256,
        "viewer_supported": viewer_supported,
        "current_file_search_supported": bool(path) and source in {"documents", "files", "ocr"},
        "source_pointer_available": bool(pointer),
        "source_hash_available": bool(source_sha256),
        "ready_for_report_selection": viewer_supported and hash_or_pointer,
        "required_before_report": [
            "open source viewer",
            "verify pointer/offset/table row against original source",
            "record review decision and limitation text",
            "capture source hash when available",
        ],
        "blockers": search_match_source_verification_blockers(
            viewer_supported=viewer_supported,
            pointer=pointer,
            source_sha256=source_sha256,
        ),
    }


def search_match_source_verification_blockers(*, viewer_supported: bool, pointer: str, source_sha256: str) -> list[str]:
    blockers: list[str] = []
    if not viewer_supported:
        blockers.append("source-viewer-route-required")
    if not pointer:
        blockers.append("source-pointer-required")
    if not source_sha256:
        blockers.append("source-hash-recommended-before-report")
    return blockers


def search_source_verification_summary(matches: Sequence[Mapping[str, object]]) -> dict[str, object]:
    ready = 0
    viewer_supported = 0
    with_pointer = 0
    with_hash = 0
    blockers: dict[str, int] = {}
    for match in matches:
        profile = match.get("source_verification_profile") if isinstance(match.get("source_verification_profile"), Mapping) else {}
        if profile.get("ready_for_report_selection"):
            ready += 1
        if profile.get("viewer_supported"):
            viewer_supported += 1
        if profile.get("source_pointer_available"):
            with_pointer += 1
        if profile.get("source_hash_available"):
            with_hash += 1
        for blocker in profile.get("blockers") or []:
            blockers[str(blocker)] = blockers.get(str(blocker), 0) + 1
    return {
        "profile_version": "unified-search-source-verification-summary-v1",
        "match_count": len(matches),
        "viewer_supported_count": viewer_supported,
        "source_pointer_count": with_pointer,
        "source_hash_count": with_hash,
        "ready_for_report_selection_count": ready,
        "blocker_counts": [
            {"value": key, "count": value}
            for key, value in sorted(blockers.items(), key=lambda item: (-item[1], item[0]))
        ],
        "commercial_grade_ready": False,
    }


def search_commercial_uplift_evidence(
    *,
    matches: Sequence[Mapping[str, object]],
    options: Mapping[str, object],
    core_accuracy_gates: Sequence[Mapping[str, object]],
    report_grade: Mapping[str, object],
    limit: int,
    query_hit_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == SEARCH_FEATURE_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    return {
        "batch_id": "commercial-uplift-061-065",
        "item_numbers": [61],
        "implementation_track": "advanced-search-query-gate",
        "source_refs": [
            f"match_count:{len(matches)}",
            f"search_mode:{options.get('search_mode', '')}",
            f"proximity_window:{options.get('proximity_window', 0)}",
            f"advanced_search_manifest_hash:{query_hit_manifest.get('manifest_hash', '') if query_hit_manifest else ''}",
        ],
        "reportability_decision": search_reportability_decision(
            failed_validation_check_ids=[
                "multilingual-relevance-corpus",
                "query-builder-ux-validation",
                "tuned-false-positive-false-negative-metrics",
                SEARCH_TRUSTED_DIFF_BLOCKER_61,
            ],
            commercial_blockers=list(report_grade.get("blockers") or []),
            options=options,
            match_count=len(matches),
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "multilingual-relevance-corpus",
            "query-builder-ux-validation",
            "tuned-false-positive-false-negative-metrics",
            SEARCH_TRUSTED_DIFF_BLOCKER_61,
        ],
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "result_limit": limit,
            "match_count": len(matches),
            "search_mode": str(options.get("search_mode") or ""),
            "fuzzy_distance": int(options.get("fuzzy_distance") or 0),
            "proximity_window": int(options.get("proximity_window") or 0),
            "full_linguistic_stemming": False,
            "semantic_near_duplicate_search": False,
            "advanced_search_manifest_hash": str(query_hit_manifest.get("manifest_hash") or "") if query_hit_manifest else "",
            "hit_row_hash_count": int(query_hit_manifest.get("hit_row_hash_count") or 0) if query_hit_manifest else 0,
            "source_locator_count": int(query_hit_manifest.get("source_locator_count") or 0) if query_hit_manifest else 0,
        },
        "reporting_status": "implemented-baseline-validation-required",
    }


def advanced_search_profile(
    *,
    keywords: Sequence[str],
    matches: Sequence[Mapping[str, object]],
    options: Mapping[str, object],
    include_ocr: bool,
    include_analysis: bool,
    limit: int,
    query_hit_manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    query_validation = validate_search_queries(keywords, search_mode=mode)
    mode_counts: dict[str, int] = {}
    proximity_matched_count = 0
    for match in matches:
        search_match = match.get("search_match") if isinstance(match.get("search_match"), Mapping) else {}
        match_mode = str(search_match.get("mode") or mode)
        mode_counts[match_mode] = mode_counts.get(match_mode, 0) + 1
        proximity = search_match.get("proximity") if isinstance(search_match.get("proximity"), Mapping) else {}
        if proximity.get("matched"):
            proximity_matched_count += 1
    return {
        "profile_version": "advanced-search-profile-v1",
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "active_mode": mode,
        "query_count": len(keywords),
        "query_validation": query_validation,
        "match_mode_counts": mode_counts,
        "proximity_matched_count": proximity_matched_count,
        "query_hit_manifest_hash": str(query_hit_manifest.get("manifest_hash") or "") if query_hit_manifest else "",
        "hit_row_hash_count": int(query_hit_manifest.get("hit_row_hash_count") or 0) if query_hit_manifest else 0,
        "source_locator_count": int(query_hit_manifest.get("source_locator_count") or 0) if query_hit_manifest else 0,
        "controls": {
            "exact_search": True,
            "regex_search": True,
            "fuzzy_levenshtein_search": True,
            "simple_suffix_stemming": True,
            "proximity_window_summary": True,
            "fuzzy_distance": int(options.get("fuzzy_distance") or 0),
            "proximity_window": int(options.get("proximity_window") or 0),
            "include_ocr": include_ocr,
            "include_analysis": include_analysis,
            "result_limit": limit,
        },
        "source_verification_required": True,
        "ready_for_court_report": False,
        "review_warnings": advanced_search_review_warnings(mode=mode, options=options),
        "report_use_warning": "Treat advanced search hits as triage until each opened source row, hash, parser limitation, and query false-positive review is recorded.",
    }


def validate_search_queries(keywords: Sequence[str], *, search_mode: str) -> list[dict[str, object]]:
    mode = normalize_search_mode(search_mode)
    output = []
    for keyword in keywords:
        record: dict[str, object] = {
            "query": keyword,
            "mode": mode,
            "valid": True,
            "warnings": [],
        }
        if mode == "regex":
            try:
                re.compile(keyword, flags=re.IGNORECASE | re.MULTILINE)
            except re.error as exc:
                record["valid"] = False
                record["error"] = str(exc)
                record["warnings"] = ["invalid-regex-pattern-will-match-nothing"]
        elif mode == "fuzzy" and not is_simple_word(keyword):
            record["warnings"] = ["fuzzy-search-is-word-token-based-for-this-query"]
        elif mode == "exact" and not is_simple_word(keyword):
            record["warnings"] = ["stemming-disabled-for-non-word-query"]
        output.append(record)
    return output


def advanced_search_review_warnings(*, mode: str, options: Mapping[str, object]) -> list[str]:
    warnings = ["open-source-viewer-and-verify-row-before-reporting"]
    if mode == "regex":
        warnings.append("regex-pattern-quality-and-false-positives-must-be-documented")
    if mode == "fuzzy":
        warnings.append("fuzzy-results-are-typo-tolerant-triage-not-exact-proof")
    if int(options.get("proximity_window") or 0) > 0:
        warnings.append("proximity-window-is-a-review-hint-not-causal-proof")
    warnings.append(SEARCH_TRUSTED_DIFF_BLOCKER_61)
    return warnings


def search_reportability_decision(
    *,
    failed_validation_check_ids: Sequence[str],
    commercial_blockers: Sequence[str],
    options: Mapping[str, object],
    match_count: int,
) -> dict[str, object]:
    blockers = {str(item) for item in commercial_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    return {
        "profile_version": "advanced-search-reportability-decision-v1",
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "decision": "do-not-report-advanced-search-hit-as-source-proof",
        "allowed_use": "advanced-search-triage-pivot",
        "blockers": sorted(blockers),
        "search_mode": str(options.get("search_mode") or ""),
        "match_count": match_count,
        "ready_for_court_report": False,
        "required_before_report": [
            "open and hash-verify source rows for every report candidate",
            "document regex/fuzzy/proximity query rationale and false-positive review",
            "attach language/domain corpus validation before claiming search completeness",
        ],
    }


def load_run_summary(run_summary: Mapping[str, object] | Path) -> Mapping[str, object]:
    if isinstance(run_summary, Mapping):
        return run_summary
    path = Path(run_summary).expanduser().resolve()
    if path.is_dir():
        path = path / "rapidtriage-run-summary.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SearchError(f"run summary not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SearchError(f"invalid run summary JSON: {path}") from exc


def search_docs(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    payload = read_json_output(outputs, "docs")
    if not payload:
        return [], []
    matches = []
    errors: list[dict[str, str]] = []
    result_index_by_path = {
        str(item.get("path")): index
        for index, item in enumerate(payload.get("results", []))
        if isinstance(item, Mapping) and item.get("path")
    }
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        path = Path(str(candidate.get("path", "")))
        kind = str(candidate.get("kind", ""))
        try:
            text = extract_text(path, kind)
        except Exception as exc:
            errors.append({"path": str(path), "kind": kind, "error": f"{type(exc).__name__}: {exc}"})
            text = ""
        matched = match_keywords(text, keywords, search_options=search_options)
        if not matched:
            continue
        matches.append(
            {
                "source": "documents",
                "kind": kind,
                "path": str(path),
                "title": path.name,
                "matched_keywords": matched,
                "preview": build_preview(text, matched[0]),
                "search_match": build_search_match_metadata(text, keywords, search_options=search_options),
                "pointer": f"/results/{result_index_by_path[str(path)]}" if str(path) in result_index_by_path else "",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches, errors


def search_files(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "files")
    if not payload:
        return []
    matches = []
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        haystack = json.dumps(candidate, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
        if not matched:
            continue
        path = str(candidate.get("path", ""))
        matches.append(
            {
                "source": "files",
                "kind": ",".join(str(item) for item in candidate.get("categories", [])),
                "path": path,
                "title": str(candidate.get("name") or Path(path).name),
                "matched_keywords": matched,
                "preview": path,
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                "pointer": f"/candidates/{index}",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_artifacts(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    matches = []
    for output_name, raw_path in sorted(outputs.items()):
        name = str(output_name)
        if not name.startswith("artifacts_"):
            continue
        payload = read_json_path(Path(str(raw_path)))
        if not payload:
            continue
        artifact_kind = name.removeprefix("artifacts_")
        source = "web" if artifact_kind == "browser" else "artifacts"
        for index, artifact in enumerate(payload.get("artifacts", [])):
            if not isinstance(artifact, Mapping):
                continue
            haystack = json.dumps(artifact, ensure_ascii=False, sort_keys=True)
            matched = match_keywords(haystack, keywords, search_options=search_options)
            if not matched:
                continue
            path = str(artifact.get("path", ""))
            title = str(artifact.get("artifact_type") or artifact_kind)
            matches.append(
                {
                    "source": source,
                    "kind": artifact_kind,
                    "path": path,
                    "title": title,
                    "matched_keywords": matched,
                    "preview": compact_json_preview(artifact),
                    "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                    "pointer": f"/artifacts/{index}",
                    "metadata": dict(artifact),
                }
            )
            if limit and len(matches) >= limit:
                return matches
    return matches


def search_timeline(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "timeline")
    if not payload:
        return []
    matches = []
    for index, event in enumerate(payload.get("events", [])):
        if not isinstance(event, Mapping):
            continue
        haystack = json.dumps(event, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
        if not matched:
            continue
        matches.append(
            {
                "source": "timeline",
                "kind": str(event.get("event_type", "")),
                "path": str(event.get("path", "")),
                "title": str(event.get("summary", "timeline event")),
                "matched_keywords": matched,
                "preview": compact_json_preview(event),
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                "pointer": f"/events/{index}",
                "metadata": dict(event),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_indicators(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    payload = read_json_output(outputs, "indicators")
    if not payload:
        return []
    matches = []
    for index, indicator in enumerate(payload.get("indicators", [])):
        if not isinstance(indicator, Mapping):
            continue
        haystack = json.dumps(indicator, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
        if not matched:
            continue
        sources = indicator.get("sources")
        first_source = sources[0] if isinstance(sources, list) and sources and isinstance(sources[0], Mapping) else {}
        path = str(first_source.get("path") or first_source.get("source_path") or "")
        indicator_type = str(indicator.get("type") or "indicator")
        indicator_value = str(indicator.get("value") or "")
        matches.append(
            {
                "source": "indicators",
                "kind": indicator_type,
                "path": path,
                "title": f"{indicator_type}: {indicator_value}" if indicator_value else indicator_type,
                "matched_keywords": matched,
                "preview": compact_json_preview(indicator),
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                "pointer": f"/indicators/{index}",
                "metadata": dict(indicator),
            }
        )
        if limit and len(matches) >= limit:
            break
    if not limit or len(matches) < limit:
        remaining_limit = 0 if not limit else limit - len(matches)
        matches.extend(
            search_ioc_scanner_hits(
                payload,
                keywords,
                limit=remaining_limit,
                search_options=search_options,
            )
        )
    return matches


def search_ioc_scanner_hits(
    payload: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    matches = []
    for index, hit in enumerate(payload.get("ioc_scanner_hits", [])):
        if not isinstance(hit, Mapping):
            continue
        haystack = json.dumps(hit, ensure_ascii=False, sort_keys=True)
        matched = match_keywords(haystack, keywords, search_options=search_options)
        if not matched:
            continue
        sources = hit.get("sources")
        first_source = sources[0] if isinstance(sources, list) and sources and isinstance(sources[0], Mapping) else {}
        path = str(first_source.get("path") or first_source.get("source_path") or "")
        hit_type = str(hit.get("type") or "ioc")
        hit_value = str(hit.get("value") or "")
        rule_id = str(hit.get("rule_id") or "")
        title = f"IOC scanner: {rule_id} {hit_type}:{hit_value}".strip()
        matches.append(
            {
                "source": "indicators",
                "kind": "ioc-scanner-hit",
                "path": path,
                "title": title,
                "matched_keywords": matched,
                "preview": compact_json_preview(hit),
                "search_match": build_search_match_metadata(haystack, keywords, search_options=search_options),
                "pointer": f"/ioc_scanner_hits/{index}",
                "metadata": dict(hit),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def search_ocr(
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int,
    search_options: Mapping[str, object] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    payload = read_json_output(outputs, "files")
    if not payload:
        return [], []
    matches = []
    errors: list[dict[str, str]] = []
    sidecar_matched_candidate_indices: set[int] = set()
    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        path = Path(str(candidate.get("path", "")))
        if path.suffix.lower() not in IMAGE_EXTS:
            continue
        for sidecar in find_ocr_sidecars(path):
            try:
                text = sidecar.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append({"path": str(sidecar), "error": str(exc)})
                continue
            matched = match_keywords(text, keywords, search_options=search_options)
            if not matched:
                continue
            matches.append(
                {
                    "source": "ocr",
                    "kind": f"{path.suffix.lower().lstrip('.')}-sidecar",
                    "path": str(path),
                    "title": f"{path.name} OCR sidecar",
                    "matched_keywords": matched,
                    "preview": build_preview(text, matched[0]),
                    "search_match": build_search_match_metadata(text, keywords, search_options=search_options),
                    "pointer": f"/candidates/{index}",
                    "metadata": {
                        **dict(candidate),
                        "ocr_source": "sidecar",
                        "ocr_sidecar_path": str(sidecar),
                    },
                }
            )
            sidecar_matched_candidate_indices.add(index)
            if limit and len(matches) >= limit:
                return matches, errors
    try:
        import cv2
        import pytesseract
    except ImportError as exc:
        if matches:
            errors.append({"path": "", "error": f"OCR engine dependencies unavailable after sidecar search: {exc}"})
            return matches, errors
        return [], [{"path": "", "error": f"OCR dependencies unavailable: {exc}"}]

    for index, candidate in enumerate(payload.get("candidates", [])):
        if not isinstance(candidate, Mapping):
            continue
        if index in sidecar_matched_candidate_indices:
            continue
        path = Path(str(candidate.get("path", "")))
        if path.suffix.lower() not in IMAGE_EXTS:
            continue
        try:
            image = cv2.imread(str(path))
            if image is None:
                raise OSError("image could not be decoded")
            text = pytesseract.image_to_string(image)
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        matched = match_keywords(text, keywords, search_options=search_options)
        if not matched:
            continue
        matches.append(
            {
                "source": "ocr",
                "kind": path.suffix.lower().lstrip("."),
                "path": str(path),
                "title": path.name,
                "matched_keywords": matched,
                "preview": build_preview(text, matched[0]),
                "search_match": build_search_match_metadata(text, keywords, search_options=search_options),
                "pointer": f"/candidates/{index}",
                "metadata": dict(candidate),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches, errors


def find_ocr_sidecars(path: Path) -> list[Path]:
    candidates = [
        path.with_suffix(path.suffix + ".ocr.txt"),
        path.with_suffix(path.suffix + ".txt"),
        path.with_suffix(".ocr.txt"),
        path.with_suffix(".txt"),
        path.with_suffix(".srt"),
        path.with_suffix(".vtt"),
    ]
    output = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        output.append(candidate)
    return output


def normalize_search_mode(value: str) -> str:
    normalized = str(value or "exact").strip().lower()
    supported = {"exact", "fuzzy", "regex"}
    if normalized not in supported:
        raise SearchError(f"unsupported search mode: {value!r}; expected one of: {', '.join(sorted(supported))}")
    return normalized


def normalize_keywords(keywords: Sequence[str], *, search_mode: str) -> list[str]:
    mode = normalize_search_mode(search_mode)
    output = []
    seen = set()
    for item in keywords:
        keyword = str(item or "").strip()
        if not keyword:
            continue
        normalized = keyword if mode == "regex" else keyword.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def match_keywords(
    text: str,
    keywords: Sequence[str],
    *,
    search_options: Mapping[str, object] | None = None,
) -> list[str]:
    options = search_options or {}
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    if mode == "regex":
        return [keyword for keyword in keywords if regex_keyword_matches(text, keyword)]
    if mode == "fuzzy":
        max_distance = max(0, min(int(options.get("fuzzy_distance") or 1), 2))
        return [keyword for keyword in keywords if fuzzy_keyword_matches(text, keyword, max_distance=max_distance)]
    lower = text.lower()
    return [keyword for keyword in keywords if exact_or_stem_matches(lower, keyword)]


def regex_keyword_matches(text: str, pattern: str) -> bool:
    try:
        return re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE) is not None
    except re.error:
        return False


def exact_or_stem_matches(lower_text: str, keyword: str) -> bool:
    if keyword in lower_text:
        return True
    if not is_simple_word(keyword):
        return False
    tokens = set(tokenize_words(lower_text))
    return any(stem in tokens for stem in keyword_stems(keyword))


def fuzzy_keyword_matches(text: str, keyword: str, *, max_distance: int) -> bool:
    lower = text.lower()
    if exact_or_stem_matches(lower, keyword):
        return True
    if not is_simple_word(keyword):
        return False
    keyword_variants = keyword_stems(keyword)
    for token in tokenize_words(lower):
        if abs(len(token) - len(keyword)) > max_distance + 1:
            continue
        if any(levenshtein_distance(token, variant, max_distance=max_distance) <= max_distance for variant in keyword_variants):
            return True
    return False


def build_search_match_metadata(
    text: str,
    keywords: Sequence[str],
    *,
    search_options: Mapping[str, object] | None = None,
) -> dict[str, object]:
    options = search_options or {}
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    proximity_window = max(0, min(int(options.get("proximity_window") or 0), 100))
    metadata: dict[str, object] = {
        "mode": mode,
        "matched_by": mode,
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "ready_for_court_report": False,
    }
    if mode == "fuzzy":
        metadata["fuzzy_distance"] = max(0, min(int(options.get("fuzzy_distance") or 1), 2))
        metadata["matched_by"] = "fuzzy-or-stem"
    if proximity_window and len(keywords) >= 2:
        proximity = proximity_summary(text, keywords, window=proximity_window)
        metadata["proximity"] = proximity
        if proximity.get("matched"):
            metadata["matched_by"] = f"{metadata['matched_by']}+proximity"
    return metadata


def build_advanced_search_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "query-hit-manifest",
) -> dict[str, object]:
    rapid_index = {advanced_search_diff_key(row): advanced_search_diff_value(row) for row in rapid_rows}
    trusted_index = {advanced_search_diff_key(row): advanced_search_diff_value(row) for row in trusted_rows}
    missing = sorted(key for key in trusted_index if key not in rapid_index)
    unexpected = sorted(key for key in rapid_index if key not in trusted_index)
    mismatched = [
        {"key": key, "rapid": rapid_index[key], "trusted": trusted_index[key]}
        for key in sorted(set(rapid_index).intersection(trusted_index))
        if rapid_index[key] != trusted_index[key]
    ]
    status = "pass" if not missing and not unexpected and not mismatched else "fail"
    return {
        "profile": "advanced-search-trusted-query-hit-diff-v1",
        "item_number": 61,
        "trusted_tool": trusted_tool,
        "status": status,
        "rapid_count": len(rapid_index),
        "trusted_count": len(trusted_index),
        "missing": missing,
        "unexpected": unexpected,
        "mismatched": mismatched,
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def advanced_search_diff_key(row: Mapping[str, object]) -> str:
    return "|".join(
        [
            str(row.get("source") or ""),
            str(row.get("path") or row.get("title") or ""),
            str(row.get("pointer") or row.get("offset") or ""),
            ",".join(str(item) for item in row.get("matched_keywords") or row.get("keywords") or []),
        ]
    )


def advanced_search_diff_value(row: Mapping[str, object]) -> dict[str, object]:
    search_match = row.get("search_match")
    search_match_map = search_match if isinstance(search_match, Mapping) else {}
    proximity = search_match_map.get("proximity")
    return {
        "mode": str(search_match_map.get("mode") or row.get("mode") or ""),
        "matched_by": str(search_match_map.get("matched_by") or row.get("matched_by") or ""),
        "proximity_matched": bool(proximity.get("matched")) if isinstance(proximity, Mapping) else bool(row.get("proximity_matched")),
        "preview": str(row.get("preview") or "")[:160],
    }


def search_report_grade_assessment(*, trusted_diff: Mapping[str, object] | None = None) -> dict[str, object]:
    blockers = list(SEARCH_REPORT_GRADE_BLOCKERS)
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(SEARCH_TRUSTED_DIFF_BLOCKER_61)
    return {
        "component": "fuzzy-regex-stemming-proximity-search",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [SEARCH_FEATURE_GAP_ID],
        "ready_for_court_report": False,
        "blockers": blockers,
        "recommended_validation": [
            "Record the exact query mode/options with any cited hit.",
            "Open the source viewer and verify the row, offset, hash, and parser limitations before report inclusion.",
        ],
        "trusted_diff": trusted_diff or {
            "status": "missing",
            "blocker": SEARCH_TRUSTED_DIFF_BLOCKER_61,
        },
    }


def search_core_accuracy_gates(
    *,
    matches: Sequence[Mapping[str, object]],
    options: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
    query_hit_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["query mode and options recorded", "source verification limitation warning"]
    mode = normalize_search_mode(str(options.get("search_mode") or "exact"))
    evidence_refs = [
        f"search_mode:{mode}",
        f"match_count:{len(matches)}",
        f"proximity_window:{int(options.get('proximity_window') or 0)}",
    ]
    if mode in {"exact", "fuzzy", "regex"} and SEARCH_NATIVE_CAPABILITIES["fuzzy_levenshtein_search"]:
        satisfied.append("fuzzy/stemming/regex matching available")
    if int(options.get("proximity_window") or 0) > 0:
        satisfied.append("proximity metadata preserved")
    if any(match.get("pointer") for match in matches):
        satisfied.append("matched hit source pointers")
    if query_hit_manifest and query_hit_manifest.get("manifest_hash"):
        satisfied.append("advanced search query-hit manifest")
        evidence_refs.append(f"advanced_search_manifest_hash:{query_hit_manifest.get('manifest_hash', '')}")
    if any(
        isinstance(match.get("advanced_search_hit_manifest"), Mapping)
        and match.get("advanced_search_hit_manifest", {}).get("hit_row_hash")
        for match in matches
    ):
        satisfied.append("search hit row hashes")
    if any(
        isinstance(match.get("advanced_search_hit_manifest"), Mapping)
        and isinstance(match.get("advanced_search_hit_manifest", {}).get("source_viewer_locator"), Mapping)
        for match in matches
    ):
        satisfied.append("advanced search source locators")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted advanced-search query-hit diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            61,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]


def proximity_summary(text: str, keywords: Sequence[str], *, window: int) -> dict[str, object]:
    tokens = tokenize_words(text.lower())
    if not tokens:
        return {"matched": False, "window": window}
    positions: dict[str, list[int]] = {}
    for keyword in keywords:
        if not is_simple_word(keyword):
            continue
        stems = set(keyword_stems(keyword))
        hits = [index for index, token in enumerate(tokens) if token == keyword or token in stems]
        if hits:
            positions[keyword] = hits
    if len(positions) < 2:
        return {"matched": False, "window": window, "matched_keyword_count": len(positions)}
    nearest: tuple[int, str, str] | None = None
    items = list(positions.items())
    for left_index, (left_keyword, left_positions) in enumerate(items):
        for right_keyword, right_positions in items[left_index + 1 :]:
            for left_pos in left_positions:
                for right_pos in right_positions:
                    distance = abs(left_pos - right_pos)
                    if nearest is None or distance < nearest[0]:
                        nearest = (distance, left_keyword, right_keyword)
    matched = nearest is not None and nearest[0] <= window
    return {
        "matched": matched,
        "window": window,
        "nearest_distance": nearest[0] if nearest else None,
        "nearest_keywords": [nearest[1], nearest[2]] if nearest else [],
        "matched_keyword_count": len(positions),
    }


def tokenize_words(text: str) -> list[str]:
    return re.findall(r"[\w가-힣]{2,}", text.lower())


def is_simple_word(value: str) -> bool:
    return re.fullmatch(r"[\w가-힣]{2,}", value.lower()) is not None


def keyword_stems(keyword: str) -> set[str]:
    lower = keyword.lower()
    stems = {lower}
    for suffix in ("ing", "edly", "edly", "ed", "es", "s"):
        if len(lower) > len(suffix) + 3 and lower.endswith(suffix):
            stems.add(lower[: -len(suffix)])
    return stems


def levenshtein_distance(left: str, right: str, *, max_distance: int) -> int:
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        row_min = current[0]
        for right_index, right_char in enumerate(right, start=1):
            cost = 0 if left_char == right_char else 1
            value = min(
                current[right_index - 1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + cost,
            )
            current.append(value)
            row_min = min(row_min, value)
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def normalize_extensions(values: Sequence[str]) -> set[str]:
    normalized: set[str] = set()
    for value in values:
        item = value.strip().lower()
        if not item:
            continue
        normalized.add(item if item.startswith(".") else f".{item}")
    return normalized


def filter_matches(
    matches: Sequence[Mapping[str, object]],
    *,
    sources: set[str],
    extensions: set[str],
    path_fragment: str,
) -> list[dict[str, object]]:
    if not sources and not extensions and not path_fragment:
        return [dict(match) for match in matches]
    filtered: list[dict[str, object]] = []
    for match in matches:
        source = str(match.get("source") or "").lower()
        path = str(match.get("path") or "")
        suffix = Path(path).suffix.lower()
        if sources and source not in sources:
            continue
        if extensions and suffix not in extensions:
            continue
        if path_fragment and path_fragment not in path.lower():
            continue
        filtered.append(dict(match))
    return filtered


def read_json_output(outputs: Mapping[str, object], name: str) -> Mapping[str, object] | None:
    raw_path = outputs.get(name)
    if not raw_path:
        return None
    return read_json_path(Path(str(raw_path)))


def read_json_path(path: Path) -> Mapping[str, object] | None:
    try:
        payload = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def compact_json_preview(value: Any, *, limit: int = 240) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text[:limit] + ("..." if len(text) > limit else "")
