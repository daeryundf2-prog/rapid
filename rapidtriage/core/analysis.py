from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .forensic_accuracy import build_accuracy_gate


ENTITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("url", re.compile(r"\bhttps?://[^\s\"'<>),]+", re.IGNORECASE)),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("hash", re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")),
    ("phone", re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")),
)
TIMESTAMP_KEYS = {
    "timestamp",
    "event_at",
    "observed_at",
    "occurred_at",
    "modified_at",
    "created_at",
    "accessed_at",
    "visited_at",
    "last_visited_at",
    "started_at",
    "ended_at",
    "sent_at",
    "received_at",
    "deleted_at",
}
MAX_CLUSTER_REPRESENTATIVES = 8
MAX_ENTITY_MATCH_REFERENCES = 15
MAX_GRAPH_MATCH_NODES = 40
ANALYSIS_GAP_IDS = ["#46", "#47", "#48", "#49", "#50", "#60"]
ANALYSIS_NATIVE_CAPABILITIES = {
    "large_result_clustering": True,
    "entity_view_email_phone_ip_domain_hash_url": True,
    "structured_person_account_entity_hints": True,
    "bounded_relationship_graph": True,
    "search_result_timeline_correlation": True,
    "hypothesis_workbook_drafts": True,
    "search_hit_deduplication": True,
    "full_case_reindex": False,
    "ml_semantic_clustering": False,
    "analyst_verified_entity_resolution": False,
    "court_ready_graph_layout": False,
}
ANALYSIS_REPORT_GRADE_BLOCKERS = [
    "analysis-derived-from-bounded-search-results-not-full-index",
    "entity-resolution-is-pattern-and-field-based-not-analyst-verified",
    "graph-edges-are-candidate-pivots-not-causal-proof",
    "timeline-events-need-source-parser-confidence-and-timezone-validation",
    "hypotheses-are-draft-review-aids-not-findings",
]
ANALYSIS_TRUSTED_DIFF_BLOCKERS = {
    46: "cluster-review-trusted-diff-required",
    47: "entity-review-trusted-diff-required",
    48: "graph-source-citation-trusted-diff-required",
    49: "timeline-known-answer-trusted-diff-required",
    50: "workbook-rubric-trusted-diff-required",
    60: "search-dedup-trusted-duplicate-manifest-required",
}
ANALYSIS_TRUSTED_DIFF_CHECKS = {
    46: "trusted cluster review diff pass",
    47: "trusted entity review diff pass",
    48: "trusted graph source-citation diff pass",
    49: "trusted timeline known-answer diff pass",
    50: "trusted workbook rubric diff pass",
    60: "trusted duplicate manifest diff pass",
}
ANALYSIS_TRUSTED_TOOLS = {
    "hand-labeled-cluster-review",
    "analyst-entity-review",
    "graph-source-citation-review",
    "timeline-known-answer",
    "workbook-rubric-review",
    "duplicate-manifest-review",
    "dedup-suppression-review",
    "case-db-review-export",
    "independent-review-export",
}
SEARCH_DEDUP_GAP_ID = "#60"
CLUSTER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "search-cluster-report-grade-validation-plan-v1"
CLUSTER_REPORT_GRADE_BLOCKERS = [
    "persistent-cluster-review-state-required",
    "near-duplicate-text-media-clustering-required",
    "cluster-review-trusted-diff-required",
    "cluster-false-positive-corpus-required",
    "large-case-cluster-performance-validation-required",
    "cluster-independent-review-required",
]
ENTITY_REPORT_GRADE_VALIDATION_PLAN_VERSION = "search-entity-report-grade-validation-plan-v1"
ENTITY_REPORT_GRADE_BLOCKERS = [
    "persistent-entity-review-state-required",
    "analyst-verified-entity-resolution-required",
    "entity-merge-split-workflow-required",
    "entity-review-trusted-diff-required",
    "entity-false-positive-corpus-required",
    "entity-independent-review-required",
]
GRAPH_REPORT_GRADE_VALIDATION_PLAN_VERSION = "search-graph-report-grade-validation-plan-v1"
GRAPH_REPORT_GRADE_BLOCKERS = [
    "interactive-graph-canvas-required",
    "server-side-graph-paging-required",
    "saved-graph-layouts-required",
    "graph-source-citation-trusted-diff-required",
    "large-case-graph-performance-validation-required",
    "graph-independent-review-required",
]
TIMELINE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "search-timeline-report-grade-validation-plan-v1"
TIMELINE_REPORT_GRADE_BLOCKERS = [
    "full-case-timeline-join-required",
    "timezone-skew-validation-required",
    "cursor-paged-timeline-required",
    "timeline-review-annotation-overlay-required",
    "timeline-known-answer-trusted-diff-required",
    "large-case-timeline-validation-required",
]
WORKBOOK_REPORT_GRADE_VALIDATION_PLAN_VERSION = "search-workbook-report-grade-validation-plan-v1"
WORKBOOK_REPORT_GRADE_BLOCKERS = [
    "editable-persistent-workbook-required",
    "source-row-evidence-attachment-workflow-required",
    "reviewer-assignment-workflow-required",
    "report-section-export-required",
    "workbook-version-history-required",
    "workbook-rubric-trusted-diff-required",
]
SEARCH_DEDUP_REPORT_GRADE_VALIDATION_PLAN_VERSION = "search-dedup-report-grade-validation-plan-v1"
SEARCH_DEDUP_REPORT_GRADE_BLOCKERS = [
    "case-db-duplicate-suppression-state-required",
    "fuzzy-near-duplicate-text-corpus-required",
    "perceptual-media-duplicate-corpus-required",
    "ocr-duplicate-corpus-required",
    "search-dedup-trusted-duplicate-manifest-required",
    "large-case-dedup-performance-validation-required",
]


def build_search_analysis(
    matches: Sequence[Mapping[str, object]],
    keywords: Sequence[str],
    *,
    max_clusters: int = 25,
    max_entities: int = 200,
    max_graph_edges: int = 350,
    max_timeline_events: int = 500,
    trusted_diffs: Mapping[int, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Build bounded analyst pivots for large search result sets.

    The output is deliberately evidence-light: it links back to match indices and
    source pointers instead of duplicating rows, keeping large cases responsive.
    """
    normalized_matches = [dict(match) for match in matches]
    clusters = build_result_clusters(normalized_matches, max_clusters=max_clusters)
    entities = build_entity_view(normalized_matches, max_entities=max_entities)
    timeline = build_correlated_timeline(normalized_matches, max_events=max_timeline_events)
    graph = build_relationship_graph(
        normalized_matches,
        entities=entities["entities"],
        max_edges=max_graph_edges,
    )
    deduplication = build_search_hit_deduplication(normalized_matches, trusted_diff=(trusted_diffs or {}).get(60))
    workbook = build_hypothesis_workbook(
        normalized_matches,
        keywords=keywords,
        clusters=clusters["clusters"],
        entities=entities["entities"],
        timeline_events=timeline["events"],
    )
    core_accuracy_gates = analysis_core_accuracy_gates(
        matches=normalized_matches,
        clusters=clusters,
        entities=entities,
        graph=graph,
        timeline=timeline,
        workbook=workbook,
        deduplication=deduplication,
        trusted_diffs=trusted_diffs or {},
    )
    report_grade = analysis_report_grade_assessment()
    return {
        "summary": {
            "match_count": len(normalized_matches),
            "cluster_count": len(clusters["clusters"]),
            "entity_count": len(entities["entities"]),
            "graph_node_count": graph["summary"]["node_count"],
            "graph_edge_count": graph["summary"]["edge_count"],
            "timeline_event_count": len(timeline["events"]),
            "workbook_hypothesis_count": len(workbook["hypotheses"]),
            "duplicate_group_count": deduplication["summary"]["duplicate_group_count"],
            "duplicate_match_count": deduplication["summary"]["duplicate_match_count"],
            "commercial_gap_ids": ANALYSIS_GAP_IDS,
            "commercial_grade_ready": False,
        },
        "clusters": clusters,
        "entities": entities,
        "graph": graph,
        "timeline": timeline,
        "deduplication": deduplication,
        "workbook": workbook,
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": analysis_commercial_uplift_evidence(
            matches=normalized_matches,
            clusters=clusters,
            entities=entities,
            graph=graph,
            timeline=timeline,
            workbook=workbook,
            core_accuracy_gates=core_accuracy_gates,
            report_grade=report_grade,
            max_clusters=max_clusters,
            max_entities=max_entities,
            max_graph_edges=max_graph_edges,
            max_timeline_events=max_timeline_events,
            trusted_diffs=trusted_diffs or {},
        ),
        "analysis_native_capabilities": dict(ANALYSIS_NATIVE_CAPABILITIES),
        "analysis_report_grade_assessment": report_grade,
        "analysis_analyst_review_profile": analysis_analyst_review_profile(
            matches=normalized_matches,
            clusters=clusters,
            entities=entities,
            graph=graph,
            timeline=timeline,
            workbook=workbook,
            deduplication=deduplication,
            report_grade=report_grade,
        ),
        "limitations": [
            "Analysis pivots are derived from bounded search results, not a full re-index.",
            "Entities and clusters are triage aids; verify source rows and hashes before reporting.",
            "Graph output is capped to keep web and CLI review responsive on large cases.",
        ],
    }


def analysis_commercial_uplift_evidence(
    *,
    matches: Sequence[Mapping[str, object]],
    clusters: Mapping[str, object],
    entities: Mapping[str, object],
    graph: Mapping[str, object],
    timeline: Mapping[str, object],
    workbook: Mapping[str, object],
    core_accuracy_gates: Sequence[Mapping[str, object]],
    report_grade: Mapping[str, object],
    max_clusters: int,
    max_entities: int,
    max_graph_edges: int,
    max_timeline_events: int,
    trusted_diffs: Mapping[int, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    passed_by_item = {
        str(gate.get("gap_id")): list(gate.get("satisfied_checks") or [])
        for gate in core_accuracy_gates
        if str(gate.get("gap_id")) in {"#46", "#47", "#48", "#49", "#50"}
    }
    failed_by_item: dict[str, list[str]] = {
        "#46": ["persistent-cluster-review-state", "near-duplicate-text-media-clustering"],
        "#47": ["analyst-verified-entity-resolution", "entity-merge-split-workflow"],
        "#48": ["interactive-graph-canvas", "server-side-graph-paging", "saved-graph-layouts"],
        "#49": ["full-case-timeline-join", "timezone-skew-validation", "cursor-paged-timeline"],
        "#50": ["editable-persistent-workbook", "evidence-attachment-workflow", "workbook-version-history"],
    }
    cluster_summary = clusters.get("summary") if isinstance(clusters.get("summary"), Mapping) else {}
    cluster_review_profile = (
        clusters.get("cluster_review_profile")
        if isinstance(clusters.get("cluster_review_profile"), Mapping)
        else {}
    )
    cluster_citation_manifest = (
        clusters.get("cluster_citation_manifest")
        if isinstance(clusters.get("cluster_citation_manifest"), Mapping)
        else {}
    )
    cluster_validation_plan = (
        clusters.get("cluster_report_grade_validation_plan")
        if isinstance(clusters.get("cluster_report_grade_validation_plan"), Mapping)
        else {}
    )
    entity_summary = entities.get("summary") if isinstance(entities.get("summary"), Mapping) else {}
    entity_review_profile = (
        entities.get("entity_review_profile")
        if isinstance(entities.get("entity_review_profile"), Mapping)
        else {}
    )
    entity_citation_manifest = (
        entities.get("entity_citation_manifest")
        if isinstance(entities.get("entity_citation_manifest"), Mapping)
        else {}
    )
    entity_validation_plan = (
        entities.get("entity_report_grade_validation_plan")
        if isinstance(entities.get("entity_report_grade_validation_plan"), Mapping)
        else {}
    )
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), Mapping) else {}
    graph_interaction_profile = (
        graph.get("graph_interaction_profile")
        if isinstance(graph.get("graph_interaction_profile"), Mapping)
        else {}
    )
    graph_citation_manifest = (
        graph.get("graph_citation_manifest")
        if isinstance(graph.get("graph_citation_manifest"), Mapping)
        else {}
    )
    graph_validation_plan = (
        graph.get("graph_report_grade_validation_plan")
        if isinstance(graph.get("graph_report_grade_validation_plan"), Mapping)
        else {}
    )
    timeline_summary = timeline.get("summary") if isinstance(timeline.get("summary"), Mapping) else {}
    timeline_correlation_profile = (
        timeline.get("timeline_correlation_profile")
        if isinstance(timeline.get("timeline_correlation_profile"), Mapping)
        else {}
    )
    timeline_citation_manifest = (
        timeline.get("timeline_citation_manifest")
        if isinstance(timeline.get("timeline_citation_manifest"), Mapping)
        else {}
    )
    timeline_validation_plan = (
        timeline.get("timeline_report_grade_validation_plan")
        if isinstance(timeline.get("timeline_report_grade_validation_plan"), Mapping)
        else {}
    )
    workbook_summary = workbook.get("summary") if isinstance(workbook.get("summary"), Mapping) else {}
    workbook_review_profile = (
        workbook.get("workbook_review_profile")
        if isinstance(workbook.get("workbook_review_profile"), Mapping)
        else {}
    )
    workbook_citation_manifest = (
        workbook.get("workbook_citation_manifest")
        if isinstance(workbook.get("workbook_citation_manifest"), Mapping)
        else {}
    )
    workbook_validation_plan = (
        workbook.get("workbook_report_grade_validation_plan")
        if isinstance(workbook.get("workbook_report_grade_validation_plan"), Mapping)
        else {}
    )
    trusted_diffs = trusted_diffs or {}
    trusted_diff_blockers = [
        blocker
        for number, blocker in ANALYSIS_TRUSTED_DIFF_BLOCKERS.items()
        if trusted_diffs.get(number, {}).get("status") != "pass"
    ]
    if cluster_validation_plan:
        passed_by_item.setdefault("#46", []).append("cluster report-grade validation plan")
        if int(cluster_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_by_item["#46"].append("cluster report-grade ready slots")
    if entity_validation_plan:
        passed_by_item.setdefault("#47", []).append("entity report-grade validation plan")
        if int(entity_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_by_item["#47"].append("entity report-grade ready slots")
    if graph_validation_plan:
        passed_by_item.setdefault("#48", []).append("graph report-grade validation plan")
        if int(graph_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_by_item["#48"].append("graph report-grade ready slots")
    if timeline_validation_plan:
        passed_by_item.setdefault("#49", []).append("timeline report-grade validation plan")
        if int(timeline_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_by_item["#49"].append("timeline report-grade ready slots")
    if workbook_validation_plan:
        passed_by_item.setdefault("#50", []).append("workbook report-grade validation plan")
        if int(workbook_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_by_item["#50"].append("workbook report-grade ready slots")
    return {
        "batch_id": "commercial-uplift-046-050",
        "item_numbers": [46, 47, 48, 49, 50],
        "implementation_track": "search-analysis-ux-gates",
        "source_refs": [
            f"matches:{len(matches)}",
            f"clusters:{cluster_summary.get('cluster_count', 0)}",
            f"cluster_citation_manifest_sha256:{cluster_citation_manifest.get('manifest_sha256', '')}",
            f"cluster_report_grade_validation_plan_sha256:{cluster_validation_plan.get('validation_plan_sha256', '')}",
            f"entities:{entity_summary.get('entity_count', 0)}",
            f"entity_citation_manifest_sha256:{entity_citation_manifest.get('manifest_sha256', '')}",
            f"entity_report_grade_validation_plan_sha256:{entity_validation_plan.get('validation_plan_sha256', '')}",
            f"graph_edges:{graph_summary.get('edge_count', 0)}",
            f"graph_citation_manifest_sha256:{graph_citation_manifest.get('manifest_sha256', '')}",
            f"graph_report_grade_validation_plan_sha256:{graph_validation_plan.get('validation_plan_sha256', '')}",
            f"timeline_events:{timeline_summary.get('event_count', 0)}",
            f"timeline_citation_manifest_sha256:{timeline_citation_manifest.get('manifest_sha256', '')}",
            f"timeline_report_grade_validation_plan_sha256:{timeline_validation_plan.get('validation_plan_sha256', '')}",
            f"hypotheses:{workbook_summary.get('hypothesis_count', 0)}",
            f"workbook_citation_manifest_sha256:{workbook_citation_manifest.get('manifest_sha256', '')}",
            f"workbook_report_grade_validation_plan_sha256:{workbook_validation_plan.get('validation_plan_sha256', '')}",
        ],
        "reportability_decision": analysis_reportability_decision(
            report_grade=report_grade,
            failed_by_item=failed_by_item,
            cluster_summary=cluster_summary,
            entity_summary=entity_summary,
            graph_summary=graph_summary,
            timeline_summary=timeline_summary,
            workbook_summary=workbook_summary,
            trusted_diffs=trusted_diffs,
            cluster_validation_plan=cluster_validation_plan,
            entity_validation_plan=entity_validation_plan,
            graph_validation_plan=graph_validation_plan,
            timeline_validation_plan=timeline_validation_plan,
            workbook_validation_plan=workbook_validation_plan,
        ),
        "passed_validation_check_ids_by_item": passed_by_item,
        "failed_validation_check_ids_by_item": failed_by_item,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "trusted_diffs": {
            str(number): dict(trusted_diffs.get(number, {}))
            if trusted_diffs.get(number)
            else {
                "status": "missing",
                "blocker_id": ANALYSIS_TRUSTED_DIFF_BLOCKERS[number],
                "required_tools": sorted(ANALYSIS_TRUSTED_TOOLS),
            }
            for number in range(46, 51)
        },
        "trusted_diff_blockers": trusted_diff_blockers,
        "large_data_controls": {
            "max_clusters": max_clusters,
            "max_entities": max_entities,
            "max_graph_match_nodes": MAX_GRAPH_MATCH_NODES,
            "max_graph_edges": max_graph_edges,
            "max_timeline_events": max_timeline_events,
            "max_cluster_representatives": MAX_CLUSTER_REPRESENTATIVES,
            "max_entity_match_references": MAX_ENTITY_MATCH_REFERENCES,
            "cluster_truncated": bool(cluster_summary.get("truncated")),
            "cluster_review_profile_present": bool(cluster_review_profile),
            "cluster_citation_manifest_present": bool(cluster_citation_manifest),
            "cluster_citation_manifest_hash": str(cluster_citation_manifest.get("manifest_sha256") or ""),
            "cluster_report_grade_validation_plan_present": bool(cluster_validation_plan),
            "cluster_report_grade_validation_plan_hash": str(
                cluster_validation_plan.get("validation_plan_sha256") or ""
            ),
            "cluster_report_grade_ready_slot_count": int(cluster_validation_plan.get("ready_slot_count") or 0),
            "cluster_report_grade_blocking_slot_count": int(cluster_validation_plan.get("blocking_slot_count") or 0),
            "cluster_citation_entry_count": int(cluster_citation_manifest.get("cluster_entry_count") or 0),
            "cluster_representative_citation_count": int(
                cluster_citation_manifest.get("representative_citation_count") or 0
            ),
            "cluster_review_queue_count": int(cluster_review_profile.get("review_queue_count") or 0),
            "high_volume_cluster_count": int(cluster_review_profile.get("high_volume_cluster_count") or 0),
            "representative_first_cluster_review": bool(cluster_review_profile.get("representative_first_review")),
            "entity_truncated": bool(entity_summary.get("truncated")),
            "entity_review_profile_present": bool(entity_review_profile),
            "entity_citation_manifest_present": bool(entity_citation_manifest),
            "entity_citation_manifest_hash": str(entity_citation_manifest.get("manifest_sha256") or ""),
            "entity_report_grade_validation_plan_present": bool(entity_validation_plan),
            "entity_report_grade_validation_plan_hash": str(entity_validation_plan.get("validation_plan_sha256") or ""),
            "entity_report_grade_ready_slot_count": int(entity_validation_plan.get("ready_slot_count") or 0),
            "entity_report_grade_blocking_slot_count": int(entity_validation_plan.get("blocking_slot_count") or 0),
            "entity_citation_entry_count": int(entity_citation_manifest.get("entity_entry_count") or 0),
            "entity_match_citation_count": int(entity_citation_manifest.get("match_citation_count") or 0),
            "entity_review_queue_count": int(entity_review_profile.get("review_queue_count") or 0),
            "merge_split_candidate_count": int(entity_review_profile.get("merge_split_candidate_count") or 0),
            "analyst_verified_entity_resolution": bool(
                entity_review_profile.get("analyst_verified_entity_resolution")
            ),
            "persistent_entity_review_state": bool(entity_review_profile.get("persistent_entity_review_state")),
            "graph_truncated": bool(graph_summary.get("truncated")),
            "graph_interaction_profile_present": bool(graph_interaction_profile),
            "graph_citation_manifest_present": bool(graph_citation_manifest),
            "graph_citation_manifest_hash": str(graph_citation_manifest.get("manifest_sha256") or ""),
            "graph_report_grade_validation_plan_present": bool(graph_validation_plan),
            "graph_report_grade_validation_plan_hash": str(graph_validation_plan.get("validation_plan_sha256") or ""),
            "graph_report_grade_ready_slot_count": int(graph_validation_plan.get("ready_slot_count") or 0),
            "graph_report_grade_blocking_slot_count": int(graph_validation_plan.get("blocking_slot_count") or 0),
            "graph_citation_edge_count": int(graph_citation_manifest.get("edge_citation_count") or 0),
            "graph_source_viewer_locator_count": int(graph_citation_manifest.get("source_viewer_locator_count") or 0),
            "graph_filter_count": len(graph_interaction_profile.get("available_filters") or []),
            "graph_edge_page_count": int(graph_interaction_profile.get("edge_page_count") or 0),
            "graph_saved_layout_supported": bool(graph_interaction_profile.get("saved_layout_supported")),
            "timeline_truncated": bool(timeline_summary.get("truncated")),
            "timeline_correlation_profile_present": bool(timeline_correlation_profile),
            "timeline_citation_manifest_present": bool(timeline_citation_manifest),
            "timeline_citation_manifest_hash": str(timeline_citation_manifest.get("manifest_sha256") or ""),
            "timeline_report_grade_validation_plan_present": bool(timeline_validation_plan),
            "timeline_report_grade_validation_plan_hash": str(
                timeline_validation_plan.get("validation_plan_sha256") or ""
            ),
            "timeline_report_grade_ready_slot_count": int(timeline_validation_plan.get("ready_slot_count") or 0),
            "timeline_report_grade_blocking_slot_count": int(
                timeline_validation_plan.get("blocking_slot_count") or 0
            ),
            "timeline_event_citation_count": int(timeline_citation_manifest.get("event_citation_count") or 0),
            "timeline_source_viewer_locator_count": int(
                timeline_citation_manifest.get("source_viewer_locator_count") or 0
            ),
            "timeline_event_page_count": int(timeline_correlation_profile.get("event_page_count") or 0),
            "timeline_missing_timezone_count": int(timeline_correlation_profile.get("missing_timezone_count") or 0),
            "timeline_clock_skew_overlay_supported": bool(
                timeline_correlation_profile.get("clock_skew_overlay_supported")
            ),
            "workbook_review_profile_present": bool(workbook_review_profile),
            "workbook_citation_manifest_present": bool(workbook_citation_manifest),
            "workbook_citation_manifest_hash": str(workbook_citation_manifest.get("manifest_sha256") or ""),
            "workbook_report_grade_validation_plan_present": bool(workbook_validation_plan),
            "workbook_report_grade_validation_plan_hash": str(
                workbook_validation_plan.get("validation_plan_sha256") or ""
            ),
            "workbook_report_grade_ready_slot_count": int(workbook_validation_plan.get("ready_slot_count") or 0),
            "workbook_report_grade_blocking_slot_count": int(
                workbook_validation_plan.get("blocking_slot_count") or 0
            ),
            "workbook_hypothesis_citation_count": int(
                workbook_citation_manifest.get("hypothesis_citation_count") or 0
            ),
            "workbook_evidence_cluster_ref_count": int(workbook_citation_manifest.get("evidence_cluster_ref_count") or 0),
            "workbook_review_queue_count": int(workbook_review_profile.get("review_queue_count") or 0),
            "workbook_evidence_attachment_count": int(
                workbook_review_profile.get("evidence_attachment_count") or 0
            ),
            "workbook_version_history_supported": bool(workbook_review_profile.get("version_history_supported")),
            "persistent_review_state": False,
            "full_case_reindex": False,
        },
        "reporting_status": "triage-only-validation-required",
    }


def analysis_reportability_decision(
    *,
    report_grade: Mapping[str, object],
    failed_by_item: Mapping[str, Sequence[str]],
    cluster_summary: Mapping[str, object],
    entity_summary: Mapping[str, object],
    graph_summary: Mapping[str, object],
    timeline_summary: Mapping[str, object],
    workbook_summary: Mapping[str, object],
    trusted_diffs: Mapping[int, Mapping[str, object]] | None = None,
    cluster_validation_plan: Mapping[str, object] | None = None,
    entity_validation_plan: Mapping[str, object] | None = None,
    graph_validation_plan: Mapping[str, object] | None = None,
    timeline_validation_plan: Mapping[str, object] | None = None,
    workbook_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers", []) if str(item)}
    for item_id, checks in failed_by_item.items():
        blockers.update(f"{item_id}:{check}" for check in checks)
    if not ANALYSIS_NATIVE_CAPABILITIES["full_case_reindex"]:
        blockers.add("full-case-reindex-not-available")
    if not ANALYSIS_NATIVE_CAPABILITIES["analyst_verified_entity_resolution"]:
        blockers.add("analyst-verified-entity-resolution-not-available")
    trusted_diffs = trusted_diffs or {}
    cluster_validation_plan = cluster_validation_plan or {}
    entity_validation_plan = entity_validation_plan or {}
    graph_validation_plan = graph_validation_plan or {}
    timeline_validation_plan = timeline_validation_plan or {}
    workbook_validation_plan = workbook_validation_plan or {}
    for number, blocker in ANALYSIS_TRUSTED_DIFF_BLOCKERS.items():
        if trusted_diffs.get(number, {}).get("status") != "pass":
            blockers.add(blocker)
    return {
        "profile_version": "search-analysis-reportability-decision-v1",
        "commercial_gap_ids": ["#46", "#47", "#48", "#49", "#50"],
        "decision": "do-not-report-search-analysis-as-reviewed-findings",
        "allowed_use": "bounded-search-analysis-triage-pivot",
        "blockers": sorted(blockers),
        "ready_for_court_report": False,
        "review_output_counts": {
            "clusters": int(cluster_summary.get("cluster_count") or 0),
            "entities": int(entity_summary.get("entity_count") or 0),
            "graph_edges": int(graph_summary.get("edge_count") or 0),
            "timeline_events": int(timeline_summary.get("event_count") or 0),
            "hypotheses": int(workbook_summary.get("hypothesis_count") or 0),
        },
        "cluster_report_grade_validation_plan_present": bool(cluster_validation_plan),
        "cluster_report_grade_validation_plan_hash": str(
            cluster_validation_plan.get("validation_plan_sha256") or ""
        ),
        "cluster_report_grade_ready_slot_count": int(cluster_validation_plan.get("ready_slot_count") or 0),
        "cluster_report_grade_blocking_slot_count": int(cluster_validation_plan.get("blocking_slot_count") or 0),
        "entity_report_grade_validation_plan_present": bool(entity_validation_plan),
        "entity_report_grade_validation_plan_hash": str(entity_validation_plan.get("validation_plan_sha256") or ""),
        "entity_report_grade_ready_slot_count": int(entity_validation_plan.get("ready_slot_count") or 0),
        "entity_report_grade_blocking_slot_count": int(entity_validation_plan.get("blocking_slot_count") or 0),
        "graph_report_grade_validation_plan_present": bool(graph_validation_plan),
        "graph_report_grade_validation_plan_hash": str(graph_validation_plan.get("validation_plan_sha256") or ""),
        "graph_report_grade_ready_slot_count": int(graph_validation_plan.get("ready_slot_count") or 0),
        "graph_report_grade_blocking_slot_count": int(graph_validation_plan.get("blocking_slot_count") or 0),
        "timeline_report_grade_validation_plan_present": bool(timeline_validation_plan),
        "timeline_report_grade_validation_plan_hash": str(
            timeline_validation_plan.get("validation_plan_sha256") or ""
        ),
        "timeline_report_grade_ready_slot_count": int(timeline_validation_plan.get("ready_slot_count") or 0),
        "timeline_report_grade_blocking_slot_count": int(timeline_validation_plan.get("blocking_slot_count") or 0),
        "workbook_report_grade_validation_plan_present": bool(workbook_validation_plan),
        "workbook_report_grade_validation_plan_hash": str(
            workbook_validation_plan.get("validation_plan_sha256") or ""
        ),
        "workbook_report_grade_ready_slot_count": int(workbook_validation_plan.get("ready_slot_count") or 0),
        "workbook_report_grade_blocking_slot_count": int(workbook_validation_plan.get("blocking_slot_count") or 0),
        "required_before_report": [
            "persist analyst review state for clusters, entity merge/split decisions, graph layouts, and workbook hypotheses",
            "validate graph and timeline joins against full-case indexed source rows with timezone and parser-confidence evidence",
            "attach report citations to verified source rows before promoting any draft hypothesis to a finding",
            "attach passing trusted review diffs for clusters, entities, graph citations, timeline order, and workbook hypotheses",
        ],
    }


def analysis_core_accuracy_gates(
    *,
    matches: Sequence[Mapping[str, object]],
    clusters: Mapping[str, object],
    entities: Mapping[str, object],
    graph: Mapping[str, object],
    timeline: Mapping[str, object],
    workbook: Mapping[str, object],
    deduplication: Mapping[str, object],
    trusted_diffs: Mapping[int, Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    evidence_refs = [
        f"match_count:{len(matches)}",
        f"cluster_count:{clusters.get('summary', {}).get('cluster_count', 0) if isinstance(clusters.get('summary'), Mapping) else 0}",
        f"entity_count:{entities.get('summary', {}).get('entity_count', 0) if isinstance(entities.get('summary'), Mapping) else 0}",
        f"graph_nodes:{graph.get('summary', {}).get('node_count', 0) if isinstance(graph.get('summary'), Mapping) else 0}",
        f"timeline_events:{timeline.get('summary', {}).get('event_count', 0) if isinstance(timeline.get('summary'), Mapping) else 0}",
        f"workbook_hypotheses:{workbook.get('summary', {}).get('hypothesis_count', 0) if isinstance(workbook.get('summary'), Mapping) else 0}",
        f"duplicate_groups:{deduplication.get('summary', {}).get('duplicate_group_count', 0) if isinstance(deduplication.get('summary'), Mapping) else 0}",
    ]
    cluster_summary = clusters.get("summary") if isinstance(clusters.get("summary"), Mapping) else {}
    cluster_review_profile = (
        clusters.get("cluster_review_profile")
        if isinstance(clusters.get("cluster_review_profile"), Mapping)
        else {}
    )
    cluster_citation_manifest = (
        clusters.get("cluster_citation_manifest")
        if isinstance(clusters.get("cluster_citation_manifest"), Mapping)
        else {}
    )
    cluster_validation_plan = (
        clusters.get("cluster_report_grade_validation_plan")
        if isinstance(clusters.get("cluster_report_grade_validation_plan"), Mapping)
        else {}
    )
    entity_summary = entities.get("summary") if isinstance(entities.get("summary"), Mapping) else {}
    entity_review_profile = (
        entities.get("entity_review_profile")
        if isinstance(entities.get("entity_review_profile"), Mapping)
        else {}
    )
    entity_citation_manifest = (
        entities.get("entity_citation_manifest")
        if isinstance(entities.get("entity_citation_manifest"), Mapping)
        else {}
    )
    entity_validation_plan = (
        entities.get("entity_report_grade_validation_plan")
        if isinstance(entities.get("entity_report_grade_validation_plan"), Mapping)
        else {}
    )
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), Mapping) else {}
    graph_interaction_profile = (
        graph.get("graph_interaction_profile")
        if isinstance(graph.get("graph_interaction_profile"), Mapping)
        else {}
    )
    graph_citation_manifest = (
        graph.get("graph_citation_manifest")
        if isinstance(graph.get("graph_citation_manifest"), Mapping)
        else {}
    )
    graph_validation_plan = (
        graph.get("graph_report_grade_validation_plan")
        if isinstance(graph.get("graph_report_grade_validation_plan"), Mapping)
        else {}
    )
    timeline_summary = timeline.get("summary") if isinstance(timeline.get("summary"), Mapping) else {}
    timeline_correlation_profile = (
        timeline.get("timeline_correlation_profile")
        if isinstance(timeline.get("timeline_correlation_profile"), Mapping)
        else {}
    )
    timeline_citation_manifest = (
        timeline.get("timeline_citation_manifest")
        if isinstance(timeline.get("timeline_citation_manifest"), Mapping)
        else {}
    )
    timeline_validation_plan = (
        timeline.get("timeline_report_grade_validation_plan")
        if isinstance(timeline.get("timeline_report_grade_validation_plan"), Mapping)
        else {}
    )
    workbook_summary = workbook.get("summary") if isinstance(workbook.get("summary"), Mapping) else {}
    workbook_review_profile = (
        workbook.get("workbook_review_profile")
        if isinstance(workbook.get("workbook_review_profile"), Mapping)
        else {}
    )
    workbook_citation_manifest = (
        workbook.get("workbook_citation_manifest")
        if isinstance(workbook.get("workbook_citation_manifest"), Mapping)
        else {}
    )
    workbook_validation_plan = (
        workbook.get("workbook_report_grade_validation_plan")
        if isinstance(workbook.get("workbook_report_grade_validation_plan"), Mapping)
        else {}
    )
    cluster_rows = clusters.get("clusters") if isinstance(clusters.get("clusters"), list) else []
    entity_rows = entities.get("entities") if isinstance(entities.get("entities"), list) else []
    graph_nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    graph_edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    timeline_events = timeline.get("events") if isinstance(timeline.get("events"), list) else []
    hypotheses = workbook.get("hypotheses") if isinstance(workbook.get("hypotheses"), list) else []
    dedup_summary = deduplication.get("summary") if isinstance(deduplication.get("summary"), Mapping) else {}
    duplicate_groups = deduplication.get("groups") if isinstance(deduplication.get("groups"), list) else []
    dedup_review_profile = (
        deduplication.get("dedup_review_profile")
        if isinstance(deduplication.get("dedup_review_profile"), Mapping)
        else {}
    )
    dedup_manifest = (
        deduplication.get("search_dedup_manifest")
        if isinstance(deduplication.get("search_dedup_manifest"), Mapping)
        else {}
    )
    dedup_validation_plan = (
        deduplication.get("search_dedup_report_grade_validation_plan")
        if isinstance(deduplication.get("search_dedup_report_grade_validation_plan"), Mapping)
        else {}
    )
    trusted_diffs = trusted_diffs or {}
    for number, diff in trusted_diffs.items():
        if isinstance(diff, Mapping):
            evidence_refs.append(f"trusted_diff_{number}_status:{diff.get('status', '')}")
            evidence_refs.append(f"trusted_diff_{number}_tool:{diff.get('trusted_tool', '')}")

    item46: list[str] = []
    if cluster_summary.get("cluster_count") is not None:
        item46.append("bounded cluster generation")
    if any(isinstance(row, Mapping) and row.get("match_indices") for row in cluster_rows):
        item46.append("representative match links")
    if any(isinstance(row, Mapping) and row.get("sources") for row in cluster_rows):
        item46.append("source and keyword grouping")
    if cluster_review_profile:
        item46.append("cluster review profile")
        evidence_refs.append(f"cluster_review_queue_count:{cluster_review_profile.get('review_queue_count', 0)}")
        evidence_refs.append(f"high_volume_cluster_count:{cluster_review_profile.get('high_volume_cluster_count', 0)}")
    if cluster_review_profile.get("representative_first_review"):
        item46.append("representative-first review queue")
    if cluster_citation_manifest:
        item46.append("cluster citation manifest")
        evidence_refs.append(f"cluster_citation_manifest_sha256:{cluster_citation_manifest.get('manifest_sha256', '')}")
        if int(cluster_citation_manifest.get("representative_citation_count") or 0) > 0:
            item46.append("representative source viewer locators")
    if cluster_validation_plan:
        item46.append("cluster report-grade validation plan")
        evidence_refs.append(
            f"cluster_report_grade_validation_plan_sha256:{cluster_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(cluster_validation_plan.get("ready_slot_count") or 0) >= 6:
            item46.append("cluster report-grade ready slots")
    if "truncated" in cluster_summary:
        item46.append("truncation disclosure")
    if not ANALYSIS_NATIVE_CAPABILITIES["ml_semantic_clustering"]:
        item46.append("review-state limitation warning")
    if trusted_diffs.get(46, {}).get("status") == "pass":
        item46.append("trusted cluster review diff pass")

    item47: list[str] = []
    if entity_summary.get("type_counts"):
        item47.append("entity extraction across supported types")
    if any(isinstance(row, Mapping) and (row.get("sources") or row.get("paths")) for row in entity_rows):
        item47.append("source and path references")
    if any(isinstance(row, Mapping) and row.get("match_indices") for row in entity_rows):
        item47.append("match reference links")
    if any(isinstance(row, Mapping) and row.get("risk_flags") for row in entity_rows):
        item47.append("risk flag assignment")
    if entity_review_profile:
        item47.append("entity review profile")
        evidence_refs.append(f"entity_review_queue_count:{entity_review_profile.get('review_queue_count', 0)}")
        evidence_refs.append(f"merge_split_candidate_count:{entity_review_profile.get('merge_split_candidate_count', 0)}")
    if entity_citation_manifest:
        item47.append("entity citation manifest")
        evidence_refs.append(f"entity_citation_manifest_sha256:{entity_citation_manifest.get('manifest_sha256', '')}")
        if int(entity_citation_manifest.get("match_citation_count") or 0) > 0:
            item47.append("entity source viewer locators")
        if entity_citation_manifest.get("raw_entity_values_serialized") is False:
            item47.append("hash-only entity citation values")
    if entity_validation_plan:
        item47.append("entity report-grade validation plan")
        evidence_refs.append(
            f"entity_report_grade_validation_plan_sha256:{entity_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(entity_validation_plan.get("ready_slot_count") or 0) >= 6:
            item47.append("entity report-grade ready slots")
    if int(entity_review_profile.get("merge_split_candidate_count") or 0) > 0:
        item47.append("merge/split review queue")
    if not ANALYSIS_NATIVE_CAPABILITIES["analyst_verified_entity_resolution"]:
        item47.append("merge/split limitation warning")
    if trusted_diffs.get(47, {}).get("status") == "pass":
        item47.append("trusted entity review diff pass")

    item48: list[str] = []
    node_types = {str(row.get("type")) for row in graph_nodes if isinstance(row, Mapping)}
    if node_types & {"match", "path", "keyword", "email", "url", "domain", "ipv4", "hash", "phone", "account", "person"}:
        item48.append("match/path/keyword/entity nodes")
    if graph_edges:
        item48.append("relationship edges built")
    if matches:
        item48.append("source citation references")
    if any(isinstance(row, Mapping) and row.get("source_citation") for row in graph_edges):
        item48.append("edge source citations")
    if graph_interaction_profile:
        item48.append("graph interaction profile")
        evidence_refs.append(f"graph_filter_count:{len(graph_interaction_profile.get('available_filters') or [])}")
        evidence_refs.append(f"graph_edge_page_count:{graph_interaction_profile.get('edge_page_count', 0)}")
    if graph_interaction_profile.get("available_filters"):
        item48.append("filter metadata")
    if graph_citation_manifest:
        item48.append("graph citation manifest")
        evidence_refs.append(f"graph_citation_manifest_sha256:{graph_citation_manifest.get('manifest_sha256', '')}")
        if int(graph_citation_manifest.get("edge_citation_count") or 0) > 0:
            item48.append("edge source viewer locators")
        if int(graph_citation_manifest.get("source_viewer_locator_count") or 0) > 0:
            item48.append("graph source locator coverage")
    if graph_validation_plan:
        item48.append("graph report-grade validation plan")
        evidence_refs.append(
            f"graph_report_grade_validation_plan_sha256:{graph_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(graph_validation_plan.get("ready_slot_count") or 0) >= 6:
            item48.append("graph report-grade ready slots")
    if "truncated" in graph_summary:
        item48.append("graph paging/truncation disclosure")
    if not ANALYSIS_NATIVE_CAPABILITIES["court_ready_graph_layout"]:
        item48.append("causal-proof limitation warning")
    if trusted_diffs.get(48, {}).get("status") == "pass":
        item48.append("trusted graph source-citation diff pass")

    item49: list[str] = []
    if timeline_events:
        item49.append("timestamp extraction")
    if all("+" in str(event.get("timestamp", "")) for event in timeline_events if isinstance(event, Mapping)):
        item49.append("UTC normalization")
    if any(isinstance(event, Mapping) and "match_index" in event for event in timeline_events):
        item49.append("source match anchors")
    if timeline.get("date_buckets") is not None:
        item49.append("date bucket generation")
    if timeline_correlation_profile:
        item49.append("timeline correlation profile")
        evidence_refs.append(f"timeline_event_page_count:{timeline_correlation_profile.get('event_page_count', 0)}")
        evidence_refs.append(
            f"timeline_missing_timezone_count:{timeline_correlation_profile.get('missing_timezone_count', 0)}"
        )
    if timeline_correlation_profile.get("event_page_count") is not None:
        item49.append("cursor page metadata")
    if timeline_correlation_profile.get("timezone_counts") is not None:
        item49.append("timezone distribution")
    if timeline_citation_manifest:
        item49.append("timeline citation manifest")
        evidence_refs.append(
            f"timeline_citation_manifest_sha256:{timeline_citation_manifest.get('manifest_sha256', '')}"
        )
        if int(timeline_citation_manifest.get("event_citation_count") or 0) > 0:
            item49.append("timeline event source viewer locators")
        if timeline_citation_manifest.get("clock_skew_overlay_supported") is False:
            item49.append("clock-skew blocker recorded")
    if timeline_validation_plan:
        item49.append("timeline report-grade validation plan")
        evidence_refs.append(
            f"timeline_report_grade_validation_plan_sha256:{timeline_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(timeline_validation_plan.get("ready_slot_count") or 0) >= 6:
            item49.append("timeline report-grade ready slots")
    item49.append("timezone/skew limitation warning")
    if trusted_diffs.get(49, {}).get("status") == "pass":
        item49.append("trusted timeline known-answer diff pass")

    item50: list[str] = []
    if hypotheses:
        item50.append("draft hypotheses generated")
    if any(isinstance(row, Mapping) and row.get("evidence_cluster_ids") is not None for row in hypotheses):
        item50.append("evidence cluster links")
    if workbook.get("review_questions") and workbook.get("next_actions"):
        item50.append("review tasks and questions")
    if any(isinstance(row, Mapping) and row.get("ready_for_report") is False for row in hypotheses):
        item50.append("report-readiness flag")
    if workbook_review_profile:
        item50.append("workbook review profile")
        evidence_refs.append(f"workbook_review_queue_count:{workbook_review_profile.get('review_queue_count', 0)}")
        evidence_refs.append(
            f"workbook_evidence_attachment_count:{workbook_review_profile.get('evidence_attachment_count', 0)}"
        )
    if int(workbook_review_profile.get("review_queue_count") or 0) > 0:
        item50.append("hypothesis review queue")
    if workbook_citation_manifest:
        item50.append("workbook citation manifest")
        evidence_refs.append(
            f"workbook_citation_manifest_sha256:{workbook_citation_manifest.get('manifest_sha256', '')}"
        )
        if int(workbook_citation_manifest.get("hypothesis_citation_count") or 0) > 0:
            item50.append("hypothesis citation source locators")
        if workbook_citation_manifest.get("version_history_supported") is False:
            item50.append("workbook version-history blocker")
    if workbook_validation_plan:
        item50.append("workbook report-grade validation plan")
        evidence_refs.append(
            f"workbook_report_grade_validation_plan_sha256:{workbook_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(workbook_validation_plan.get("ready_slot_count") or 0) >= 6:
            item50.append("workbook report-grade ready slots")
    if not ANALYSIS_NATIVE_CAPABILITIES["full_case_reindex"]:
        item50.append("persistence/versioning limitation warning")
    if trusted_diffs.get(50, {}).get("status") == "pass":
        item50.append("trusted workbook rubric diff pass")

    item60: list[str] = []
    if dedup_summary.get("unique_fingerprint_count") is not None:
        item60.append("duplicate fingerprint generation")
    if dedup_summary.get("duplicate_group_count") is not None:
        item60.append("duplicate group counts")
    if any(isinstance(row, Mapping) and row.get("match_indices") for row in duplicate_groups):
        item60.append("representative hit links")
    if any(isinstance(row, Mapping) and (row.get("sources") or row.get("paths")) for row in duplicate_groups):
        item60.append("source/path references")
    if dedup_review_profile.get("collapse_preview_supported"):
        item60.append("collapse preview profile")
        evidence_refs.append(f"dedup_review_group_count:{dedup_review_profile.get('duplicate_group_count', 0)}")
    if dedup_manifest.get("manifest_sha256"):
        item60.append("dedup citation manifest")
        evidence_refs.append(f"dedup_manifest_sha256:{dedup_manifest.get('manifest_sha256', '')}")
    if int(dedup_manifest.get("member_row_hash_count") or 0) > 0:
        item60.append("duplicate member row hashes")
    if isinstance(dedup_manifest.get("source_viewer_locator"), Mapping):
        item60.append("dedup source viewer locators")
    if dedup_validation_plan:
        item60.append("dedup report-grade validation plan")
        evidence_refs.append(
            f"dedup_report_grade_validation_plan_sha256:{dedup_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(dedup_validation_plan.get("ready_slot_count") or 0) >= 6:
            item60.append("dedup report-grade ready slots")
    item60.append("near-duplicate limitation warning")

    return [
        build_accuracy_gate(46, satisfied_checks=item46, evidence_refs=evidence_refs),
        build_accuracy_gate(47, satisfied_checks=item47, evidence_refs=evidence_refs),
        build_accuracy_gate(48, satisfied_checks=item48, evidence_refs=evidence_refs),
        build_accuracy_gate(49, satisfied_checks=item49, evidence_refs=evidence_refs),
        build_accuracy_gate(50, satisfied_checks=item50, evidence_refs=evidence_refs),
        build_accuracy_gate(60, satisfied_checks=item60, evidence_refs=evidence_refs),
    ]


def build_result_clusters(
    matches: Sequence[Mapping[str, object]],
    *,
    max_clusters: int,
) -> dict[str, object]:
    buckets: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, match in enumerate(matches):
        for key in cluster_keys(match):
            buckets[key].append(index)

    clusters: list[dict[str, object]] = []
    for (family, value), indices in sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(indices) < 2 and family not in {"source", "keyword"}:
            continue
        sample_matches = [matches[index] for index in indices[:MAX_CLUSTER_REPRESENTATIVES]]
        clusters.append(
            {
                "cluster_id": stable_id("cluster", family, value),
                "family": family,
                "label": cluster_label(family, value),
                "value": value,
                "match_count": len(indices),
                "match_indices": indices[:MAX_CLUSTER_REPRESENTATIVES],
                "truncated_match_indices": len(indices) > MAX_CLUSTER_REPRESENTATIVES,
                "sources": sorted({str(item.get("source") or "unknown") for item in sample_matches}),
                "keywords": sorted(
                    {
                        str(keyword)
                        for item in sample_matches
                        for keyword in item.get("matched_keywords", [])
                    }
                ),
                "representative_titles": [str(item.get("title") or item.get("path") or "") for item in sample_matches[:5]],
                "top_paths": most_common_paths(sample_matches),
                "review_hint": cluster_review_hint(family, value, len(indices)),
            }
        )
        if len(clusters) >= max_clusters:
            break
    review_profile = build_cluster_review_profile(clusters, candidate_bucket_count=len(buckets), max_clusters=max_clusters)
    citation_manifest = build_cluster_citation_manifest(clusters, matches)
    validation_plan = build_cluster_report_grade_validation_plan(
        clusters=clusters,
        matches=matches,
        cluster_review_profile=review_profile,
        cluster_citation_manifest=citation_manifest,
    )
    return {
        "summary": {
            "cluster_count": len(clusters),
            "candidate_bucket_count": len(buckets),
            "max_clusters": max_clusters,
            "truncated": len(clusters) >= max_clusters and len(buckets) > max_clusters,
            "review_queue_count": int(review_profile.get("review_queue_count") or 0),
            "high_volume_cluster_count": int(review_profile.get("high_volume_cluster_count") or 0),
            "cluster_citation_entry_count": int(citation_manifest.get("cluster_entry_count") or 0),
            "representative_citation_count": int(citation_manifest.get("representative_citation_count") or 0),
            "commercial_gap_ids": ["#46"],
            "commercial_grade_ready": False,
        },
        "cluster_review_profile": review_profile,
        "cluster_citation_manifest": citation_manifest,
        "cluster_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "cluster_report_grade_validation_plan": validation_plan,
        "cluster_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "clusters": clusters,
        "report_grade_assessment": component_report_grade_assessment("#46", "large-result-clustering"),
    }


def build_cluster_review_profile(
    clusters: Sequence[Mapping[str, object]],
    *,
    candidate_bucket_count: int,
    max_clusters: int,
) -> dict[str, object]:
    family_counts = Counter(str(cluster.get("family") or "unknown") for cluster in clusters)
    review_queue: list[dict[str, object]] = []
    high_volume_count = 0
    for cluster in clusters:
        match_count = int(cluster.get("match_count") or 0)
        if match_count >= 3:
            high_volume_count += 1
        family = str(cluster.get("family") or "unknown")
        review_priority = "high" if match_count >= 3 or family in {"keyword", "folder"} else "normal"
        review_queue.append(
            {
                "cluster_id": str(cluster.get("cluster_id") or ""),
                "family": family,
                "value": str(cluster.get("value") or ""),
                "label": str(cluster.get("label") or ""),
                "match_count": match_count,
                "representative_match_indices": list(cluster.get("match_indices") or [])[:MAX_CLUSTER_REPRESENTATIVES],
                "top_paths": list(cluster.get("top_paths") or [])[:5],
                "review_priority": review_priority,
                "review_status": "unreviewed",
                "review_decision": "pending",
                "report_candidate": False,
                "noise_candidate": family in {"source", "extension"} and match_count >= 5,
                "review_hint": str(cluster.get("review_hint") or ""),
            }
        )
    review_queue.sort(
        key=lambda item: (
            item["review_priority"] != "high",
            -int(item["match_count"]),
            str(item["family"]),
            str(item["value"]),
        )
    )
    return {
        "profile_version": "large-result-cluster-review-v1",
        "selected_track": "bounded-representative-first-cluster-review",
        "cluster_count": len(clusters),
        "candidate_bucket_count": candidate_bucket_count,
        "max_clusters": max_clusters,
        "family_counts": dict(sorted(family_counts.items())),
        "high_volume_cluster_count": high_volume_count,
        "review_queue": review_queue,
        "review_queue_count": len(review_queue),
        "persistent_review_state": False,
        "near_duplicate_text_media_clustering": False,
        "representative_first_review": True,
        "commercial_release_blocked": True,
        "reporting_status": "cluster-review-validation-required",
        "required_before_report": [
            "persist analyst review decisions before suppressing, promoting, or reporting cluster output",
            "validate high-volume clusters against hand-labeled review sets for false positive/noise rates",
            "add near-duplicate text/media clustering validation before claiming semantic clustering coverage",
        ],
    }


def build_cluster_citation_manifest(
    clusters: Sequence[Mapping[str, object]],
    matches: Sequence[Mapping[str, object]],
    *,
    cluster_limit: int = 200,
    representative_limit: int = MAX_CLUSTER_REPRESENTATIVES,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    representative_citation_count = 0
    for index, cluster in enumerate(clusters[:cluster_limit], start=1):
        representative_indices = [
            int(item)
            for item in list(cluster.get("match_indices") or [])[:representative_limit]
            if isinstance(item, int) and 0 <= item < len(matches)
        ]
        representative_citations = []
        for match_index in representative_indices:
            match = matches[match_index]
            source = str(match.get("source") or "unknown")
            path = str(match.get("path") or "")
            title = str(match.get("title") or path or f"match-{match_index}")
            representative_citations.append(
                {
                    "match_index": match_index,
                    "source": source,
                    "path": path,
                    "title": title,
                    "kind": str(match.get("kind") or ""),
                    "keyword_refs": [str(item) for item in list(match.get("matched_keywords") or [])[:10]],
                    "source_viewer_locator": {
                        "viewer": "search-result-source",
                        "match_index": match_index,
                        "source": source,
                        "path": path,
                    },
                    "match_sha256": stable_analysis_sha256(
                        {
                            "match_index": match_index,
                            "source": source,
                            "path": path,
                            "title": title,
                            "kind": str(match.get("kind") or ""),
                        }
                    ),
                }
            )
        representative_citation_count += len(representative_citations)
        entry_payload = {
            "entry_index": index,
            "cluster_id": str(cluster.get("cluster_id") or ""),
            "family": str(cluster.get("family") or ""),
            "value": str(cluster.get("value") or ""),
            "label": str(cluster.get("label") or ""),
            "match_count": int(cluster.get("match_count") or 0),
            "representative_citation_count": len(representative_citations),
            "review_hint": str(cluster.get("review_hint") or ""),
        }
        entries.append(
            {
                **entry_payload,
                "entry_hash": stable_analysis_sha256(entry_payload),
                "representative_citations": representative_citations,
                "representative_citations_truncated": bool(cluster.get("truncated_match_indices")),
                "source_viewer_locator": {
                    "viewer": "search-cluster-review",
                    "cluster_id": entry_payload["cluster_id"],
                    "family": entry_payload["family"],
                    "value": entry_payload["value"],
                    "open_representative_first": True,
                },
                "validation_status": "candidate-cluster-citation",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "search-cluster-citation-manifest-v1",
        "item_number": 46,
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-cluster-representative-source-citations",
        "cluster_entry_count": len(entries),
        "cluster_entry_cap": cluster_limit,
        "cluster_entries_truncated": len(clusters) > cluster_limit,
        "representative_citation_count": representative_citation_count,
        "representative_citation_cap_per_cluster": representative_limit,
        "cluster_entries": entries,
        "persistent_review_state": False,
        "near_duplicate_text_media_clustering": False,
        "passed_validation_check_ids": [
            "search-cluster-citation-manifest-emitted",
            "cluster-source-viewer-locators-built",
            "representative-source-citations-built",
        ],
        "failed_validation_check_ids": [
            "persistent-cluster-review-state",
            "near-duplicate-text-media-clustering",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[46],
        ],
        "commercial_blockers": [
            "persistent-cluster-review-state",
            "near-duplicate-text-media-clustering",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[46],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_analysis_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_cluster_report_grade_validation_plan(
    *,
    clusters: Sequence[Mapping[str, object]],
    matches: Sequence[Mapping[str, object]],
    cluster_review_profile: Mapping[str, object],
    cluster_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    review_profile_hash = stable_analysis_sha256(cluster_review_profile)
    citation_manifest_hash = str(cluster_citation_manifest.get("manifest_sha256") or "")
    representative_citation_count = int(cluster_citation_manifest.get("representative_citation_count") or 0)
    cluster_entry_count = int(cluster_citation_manifest.get("cluster_entry_count") or 0)

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "search-cluster-bounded-generation",
            ready=bool(clusters),
            evidence=f"cluster_count={len(clusters)} match_count={len(matches)}",
            blocker_id="search-cluster-generation-required",
            operator_action="Run search analysis on the result set so bounded clusters are emitted.",
        ),
        slot(
            "search-cluster-review-profile-emitted",
            ready=cluster_review_profile.get("profile_version") == "large-result-cluster-review-v1",
            evidence=f"cluster_review_profile_sha256={review_profile_hash}",
            blocker_id="search-cluster-review-profile-required",
            operator_action="Regenerate analysis so the cluster review profile is available to the reviewer.",
        ),
        slot(
            "search-cluster-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"cluster_citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="search-cluster-citation-manifest-required",
            operator_action="Generate the citation manifest before using cluster output in a report.",
        ),
        slot(
            "search-cluster-representative-source-viewer-locators",
            ready=representative_citation_count > 0,
            evidence=f"representative_citation_count={representative_citation_count}",
            blocker_id="search-cluster-source-viewer-locators-required",
            operator_action="Attach representative source viewer locators for every report candidate cluster.",
        ),
        slot(
            "search-cluster-truncation-controls",
            ready="max_clusters" in cluster_review_profile and "review_queue_count" in cluster_review_profile,
            evidence=(
                f"max_clusters={cluster_review_profile.get('max_clusters', '')} "
                f"review_queue_count={cluster_review_profile.get('review_queue_count', '')}"
            ),
            blocker_id="search-cluster-truncation-controls-required",
            operator_action="Record max-cluster and review-queue caps before large-case use.",
        ),
        slot(
            "search-cluster-representative-first-review",
            ready=bool(cluster_review_profile.get("representative_first_review")),
            evidence=f"representative_first_review={bool(cluster_review_profile.get('representative_first_review'))}",
            blocker_id="search-cluster-representative-first-review-required",
            operator_action="Enable representative-first review before using clusters as a triage queue.",
        ),
        slot(
            "search-cluster-persistent-review-state",
            ready=False,
            evidence="persistent_review_state=false",
            blocker_id="persistent-cluster-review-state-required",
            operator_action="Persist analyst cluster review decisions, promoted/noise state, notes, and timestamps.",
        ),
        slot(
            "search-cluster-near-duplicate-text-media",
            ready=False,
            evidence="near_duplicate_text_media_clustering=false",
            blocker_id="near-duplicate-text-media-clustering-required",
            operator_action="Validate near-duplicate text/media clustering before semantic clustering claims.",
        ),
        slot(
            "search-cluster-trusted-review-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=ANALYSIS_TRUSTED_DIFF_BLOCKERS[46],
            operator_action="Attach a passing hand-labeled cluster review diff.",
        ),
        slot(
            "search-cluster-false-positive-corpus",
            ready=False,
            evidence="false_positive_noise_corpus_attached=false",
            blocker_id="cluster-false-positive-corpus-required",
            operator_action="Measure high-volume/noise cluster false-positive rates with a known-answer corpus.",
        ),
        slot(
            "search-cluster-large-case-performance-validation",
            ready=False,
            evidence="large_case_cluster_performance_validation=false",
            blocker_id="large-case-cluster-performance-validation-required",
            operator_action="Validate cluster generation latency and memory on large result sets.",
        ),
        slot(
            "search-cluster-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="cluster-independent-review-required",
            operator_action="Attach independent reviewer signoff before reviewed-cluster wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": CLUSTER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 46,
        "gap_id": "#46",
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-representative-first-cluster-report-validation",
        "match_count": len(matches),
        "cluster_count": len(clusters),
        "cluster_entry_count": cluster_entry_count,
        "representative_citation_count": representative_citation_count,
        "cluster_review_profile_sha256": review_profile_hash,
        "cluster_citation_manifest_sha256": citation_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(CLUSTER_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage search <case-db-or-output> --keyword <keyword> --output search-results.json",
            "rapidtriage cross-tool-validate --rapid-output search-results.json --reference-output <hand-labeled-cluster-review> --backlog-item 46 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 46 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-large-result-cluster-review-pivot",
            "forbidden_claims": [
                "cluster decisions are analyst-reviewed",
                "near-duplicate text/media clustering is validated",
                "high-volume clusters have measured false-positive rates",
                "cluster output is commercial-grade for large cases",
            ],
            "required_disclaimer": (
                "Clusters are representative-first triage pivots. Do not report cluster conclusions until persistent "
                "review state, near-duplicate validation, trusted review diff, false-positive corpus, large-case "
                "performance evidence, and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_analysis_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def build_analysis_trusted_diff(
    number: int,
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    blocker = ANALYSIS_TRUSTED_DIFF_BLOCKERS.get(number, "analysis-trusted-diff-required")
    rapid_index = index_analysis_trusted_rows(number, rapid_rows)
    trusted_index = index_analysis_trusted_rows(number, trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in ANALYSIS_TRUSTED_TOOLS
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
                        "analysis_row_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "search-analysis-trusted-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-search-analysis-output-as-reviewed-finding",
            "blockers": [] if status == "pass" else [blocker],
        },
    }


def index_analysis_trusted_rows(number: int, rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexers = {
        46: index_cluster_rows,
        47: index_entity_rows,
        48: index_graph_rows,
        49: index_timeline_rows,
        50: index_workbook_rows,
        60: index_dedup_rows,
    }
    return indexers.get(number, index_workbook_rows)(rows)


def index_cluster_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        family = diff_value(row.get("family"))
        value = diff_value(row.get("value") or row.get("label"))
        cluster_id = diff_value(row.get("cluster_id"))
        key = cluster_id or stable_diff_key("cluster", family, value)
        if not key:
            continue
        indexed[key] = {
            "family": family,
            "value": value,
            "match_count": diff_value(row.get("match_count")),
            "review_status": diff_value(row.get("review_status") or row.get("validation_status")),
        }
    return indexed


def index_entity_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        entity_type = diff_value(row.get("type") or row.get("entity_type"))
        value = diff_value(row.get("value") or row.get("entity"))
        key = stable_diff_key("entity", entity_type, value)
        if not value:
            continue
        indexed[key] = {
            "type": entity_type,
            "value": value,
            "source_count": diff_value(row.get("source_count")),
            "review_status": diff_value(row.get("review_status") or row.get("merge_status")),
        }
    return indexed


def index_graph_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        source = diff_value(row.get("source") or row.get("from") or row.get("from_node"))
        target = diff_value(row.get("target") or row.get("to") or row.get("to_node"))
        edge_type = diff_value(row.get("type") or row.get("edge_type"))
        key = diff_value(row.get("edge_id")) or stable_diff_key("edge", source, target, edge_type)
        if not source and not target:
            continue
        indexed[key] = {
            "source": source,
            "target": target,
            "type": edge_type,
            "citation_count": diff_value(row.get("citation_count") or len(row.get("match_indices") or [])),
        }
    return indexed


def index_timeline_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        timestamp = diff_value(row.get("timestamp"))
        source = diff_value(row.get("source"))
        match_index = diff_value(row.get("match_index"))
        title = diff_value(row.get("title") or row.get("summary"))
        key = diff_value(row.get("event_id")) or stable_diff_key("timeline", timestamp, source, match_index, title)
        if not timestamp:
            continue
        indexed[key] = {
            "timestamp": timestamp,
            "source": source,
            "match_index": match_index,
            "title": title,
        }
    return indexed


def index_workbook_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        key_value = diff_value(row.get("key") or row.get("hypothesis_id") or row.get("title"))
        key = stable_diff_key("workbook", key_value)
        if not key_value:
            continue
        indexed[key] = {
            "key": key_value,
            "ready_for_report": diff_value(row.get("ready_for_report")),
            "evidence_count": diff_value(row.get("evidence_count") or len(row.get("evidence_cluster_ids") or [])),
            "review_status": diff_value(row.get("review_status") or row.get("status")),
        }
    return indexed


def index_dedup_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        group_id = diff_value(row.get("group_id"))
        fingerprint = diff_value(row.get("fingerprint"))
        key = group_id or stable_diff_key("dedup", fingerprint)
        if not key:
            continue
        indexed[key] = {
            "fingerprint": fingerprint,
            "match_count": diff_value(row.get("match_count")),
            "duplicate_resolution_status": diff_value(row.get("duplicate_resolution_status")),
            "review_action": diff_value(row.get("review_action")),
        }
    return indexed


def stable_diff_key(*parts: object) -> str:
    text = "|".join(diff_value(part) for part in parts if diff_value(part))
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def stable_analysis_sha256(value: object) -> str:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8", errors="replace")).hexdigest()


def diff_value(value: object) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(diff_value(item) for item in value if diff_value(item)))
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def build_search_hit_deduplication(
    matches: Sequence[Mapping[str, object]],
    *,
    max_groups: int = 25,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    buckets: dict[str, list[int]] = defaultdict(list)
    for index, match in enumerate(matches):
        buckets[dedupe_fingerprint(match)].append(index)
    groups = []
    duplicate_match_count = 0
    for fingerprint, indices in sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(indices) < 2:
            continue
        duplicate_match_count += len(indices)
        sample = [matches[index] for index in indices[:8]]
        groups.append(
            {
                "group_id": stable_id("duplicate", fingerprint),
                "fingerprint": fingerprint,
                "match_count": len(indices),
                "match_indices": indices[:20],
                "representative_index": indices[0],
                "hidden_duplicate_count": max(0, len(indices) - 1),
                "truncated_match_indices": len(indices) > 20,
                "sources": sorted({str(item.get("source") or "unknown") for item in sample}),
                "paths": sorted({str(item.get("path") or "") for item in sample if item.get("path")})[:8],
                "representative_preview": str(sample[0].get("preview") or "")[:240] if sample else "",
                "collapse_hint": "show-representative-with-duplicates-collapsed",
                "review_action": "review-representative-hit-first",
                "report_suppression_status": "not-suppressed",
                "duplicate_resolution_status": "candidate",
                "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
            }
        )
        if len(groups) >= max_groups:
            break
    summary = {
        "duplicate_group_count": len(groups),
        "duplicate_match_count": duplicate_match_count,
        "unique_fingerprint_count": len(buckets),
        "max_groups": max_groups,
    }
    dedup_manifest = build_search_dedup_manifest(matches=matches, groups=groups, summary=summary)
    dedup_review_profile = build_dedup_review_profile(groups=groups, summary=summary)
    validation_plan = build_search_dedup_report_grade_validation_plan(
        groups=groups,
        summary=summary,
        dedup_manifest=dedup_manifest,
        dedup_review_profile=dedup_review_profile,
        trusted_diff=trusted_diff,
    )
    core_accuracy_gates = search_deduplication_core_accuracy_gates(
        groups=groups,
        summary=summary,
        dedup_manifest=dedup_manifest,
        validation_plan=validation_plan,
        trusted_diff=trusted_diff,
    )
    return {
        "summary": {
            "duplicate_group_count": len(groups),
            "duplicate_match_count": duplicate_match_count,
            "unique_fingerprint_count": len(buckets),
            "max_groups": max_groups,
            "truncated": len([indices for indices in buckets.values() if len(indices) > 1]) > len(groups),
            "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
            "commercial_grade_ready": False,
        },
        "groups": groups,
        "search_dedup_manifest": dedup_manifest,
        "search_dedup_manifest_hash": dedup_manifest["manifest_sha256"],
        "dedup_review_profile": dedup_review_profile,
        "search_dedup_report_grade_validation_plan": validation_plan,
        "search_dedup_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "deduplication_assessment": search_deduplication_assessment(),
        "trusted_duplicate_manifest_diff": dict(trusted_diff) if isinstance(trusted_diff, Mapping) else {
            "status": "missing",
            "blocker_id": ANALYSIS_TRUSTED_DIFF_BLOCKERS[60],
            "required_tools": sorted(ANALYSIS_TRUSTED_TOOLS),
        },
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": search_deduplication_commercial_uplift_evidence(
            groups=groups,
            summary=summary,
            dedup_manifest=dedup_manifest,
            validation_plan=validation_plan,
            core_accuracy_gates=core_accuracy_gates,
            trusted_diff=trusted_diff,
        ),
    }


def build_search_dedup_manifest(
    *,
    matches: Sequence[Mapping[str, object]],
    groups: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
) -> dict[str, object]:
    group_entries = []
    member_hash_count = 0
    for group_index, group in enumerate(groups, start=1):
        member_entries = []
        for member_index in list(group.get("match_indices") or [])[:20]:
            if not isinstance(member_index, int) or member_index < 0 or member_index >= len(matches):
                continue
            match = matches[member_index]
            member_core = {
                "match_index": member_index,
                "source": str(match.get("source") or ""),
                "kind": str(match.get("kind") or ""),
                "path": str(match.get("path") or ""),
                "title": str(match.get("title") or ""),
                "pointer": str(match.get("pointer") or ""),
                "preview_sha256": stable_analysis_sha256(str(match.get("preview") or "")),
                "matched_keywords": [str(item) for item in list(match.get("matched_keywords") or [])[:10]],
            }
            member_entries.append(
                {
                    **member_core,
                    "member_row_hash": stable_analysis_sha256(member_core),
                    "source_viewer_locator": {
                        "viewer": "search-dedup-member-source",
                        "match_index": member_index,
                        "path": member_core["path"],
                        "source": member_core["source"],
                    },
                }
            )
            member_hash_count += 1
        representative_index = int(group.get("representative_index") or -1)
        group_core = {
            "group_index": group_index,
            "group_id": str(group.get("group_id") or ""),
            "fingerprint": str(group.get("fingerprint") or ""),
            "match_count": int(group.get("match_count") or 0),
            "representative_index": representative_index,
            "hidden_duplicate_count": int(group.get("hidden_duplicate_count") or 0),
            "report_suppression_status": str(group.get("report_suppression_status") or ""),
            "duplicate_resolution_status": str(group.get("duplicate_resolution_status") or ""),
            "member_row_count": len(member_entries),
        }
        group_entries.append(
            {
                **group_core,
                "group_row_hash": stable_analysis_sha256(group_core),
                "representative_source_viewer_locator": {
                    "viewer": "search-dedup-representative-source",
                    "match_index": representative_index,
                    "open_action": "open-representative-hit-first",
                },
                "member_entries": member_entries,
                "member_entries_truncated": bool(group.get("truncated_match_indices")),
                "review_status": "unreviewed",
                "suppression_decision": "not-suppressed",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "search-dedup-citation-manifest-v1",
        "item_number": 60,
        "batch_id": "commercial-uplift-056-060",
        "selected_track": "bounded-search-hit-duplicate-review",
        "duplicate_group_count": int(summary.get("duplicate_group_count") or 0),
        "duplicate_match_count": int(summary.get("duplicate_match_count") or 0),
        "unique_fingerprint_count": int(summary.get("unique_fingerprint_count") or 0),
        "group_entry_count": len(group_entries),
        "member_row_hash_count": member_hash_count,
        "group_entries": group_entries,
        "source_viewer_locator": {
            "viewer": "search-dedup-review",
            "open_action": "open-dedup-review-board",
            "representative_first": True,
        },
        "case_db_suppression_state": False,
        "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
        "passed_validation_check_ids": [
            "search-dedup-citation-manifest-emitted",
            "dedup-member-row-hashes",
            "dedup-source-viewer-locators",
        ],
        "failed_validation_check_ids": [
            "persistent-dedup-suppression-workflow",
            "fuzzy-near-duplicate-text-grouping",
            "perceptual-media-duplicate-grouping",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[60],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_analysis_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_search_dedup_report_grade_validation_plan(
    *,
    groups: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
    dedup_manifest: Mapping[str, object],
    dedup_review_profile: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    group_count = int(summary.get("duplicate_group_count") or 0)
    duplicate_match_count = int(summary.get("duplicate_match_count") or 0)
    unique_fingerprint_count = int(summary.get("unique_fingerprint_count") or 0)
    member_row_hash_count = int(dedup_manifest.get("member_row_hash_count") or 0)
    manifest_hash = str(dedup_manifest.get("manifest_sha256") or "")
    review_group_count = int(dedup_review_profile.get("duplicate_group_count") or 0)
    validation_slots = [
        slot(
            "search-dedup-fingerprint-generation",
            ready=unique_fingerprint_count >= 0,
            evidence=f"unique_fingerprint_count={unique_fingerprint_count}",
            blocker_id="search-dedup-fingerprint-generation-required",
            operator_action="Generate stable fingerprints for every returned search hit.",
        ),
        slot(
            "search-dedup-group-counts",
            ready=group_count >= 0 and duplicate_match_count >= 0,
            evidence=f"duplicate_group_count={group_count} duplicate_match_count={duplicate_match_count}",
            blocker_id="search-dedup-group-counts-required",
            operator_action="Emit duplicate group and duplicate match counts.",
        ),
        slot(
            "search-dedup-representative-hit-links",
            ready=group_count == 0 or any(isinstance(group, Mapping) and group.get("match_indices") for group in groups),
            evidence=f"group_count={group_count} representative_links={sum(1 for group in groups if isinstance(group, Mapping) and group.get('match_indices'))}",
            blocker_id="search-dedup-representative-hit-links-required",
            operator_action="Preserve representative match indices for duplicate review.",
        ),
        slot(
            "search-dedup-citation-manifest-emitted",
            ready=bool(manifest_hash),
            evidence=f"search_dedup_manifest_sha256={manifest_hash}",
            blocker_id="search-dedup-citation-manifest-required",
            operator_action="Attach a bounded citation manifest before using duplicate groups in report review.",
        ),
        slot(
            "search-dedup-member-row-hashes-and-locators",
            ready=member_row_hash_count >= max(0, min(duplicate_match_count, 1))
            and isinstance(dedup_manifest.get("source_viewer_locator"), Mapping),
            evidence=f"member_row_hash_count={member_row_hash_count} source_viewer_locator={bool(dedup_manifest.get('source_viewer_locator'))}",
            blocker_id="search-dedup-member-row-hashes-required",
            operator_action="Emit member row hashes and source-viewer locators for representative and duplicate members.",
        ),
        slot(
            "search-dedup-collapse-review-profile",
            ready=bool(dedup_review_profile.get("collapse_preview_supported")),
            evidence=f"review_group_count={review_group_count} collapse_preview_supported={dedup_review_profile.get('collapse_preview_supported', False)}",
            blocker_id="search-dedup-collapse-review-profile-required",
            operator_action="Expose collapse preview as analyst review aid, not automatic suppression.",
        ),
        slot(
            "search-dedup-case-db-suppression-state",
            ready=False,
            evidence=f"case_db_suppression_state={dedup_review_profile.get('case_db_suppression_state', False)}",
            blocker_id="case-db-duplicate-suppression-state-required",
            operator_action="Persist analyst duplicate suppression decisions in the Case DB with immutable audit history.",
        ),
        slot(
            "search-dedup-fuzzy-near-duplicate-text-corpus",
            ready=False,
            evidence="fuzzy_near_duplicate_text_corpus=false",
            blocker_id="fuzzy-near-duplicate-text-corpus-required",
            operator_action="Validate normalized/fuzzy text duplicate groups against a known-answer corpus.",
        ),
        slot(
            "search-dedup-perceptual-media-duplicate-corpus",
            ready=False,
            evidence="perceptual_media_duplicate_corpus=false",
            blocker_id="perceptual-media-duplicate-corpus-required",
            operator_action="Validate image/video duplicate grouping against a perceptual media corpus.",
        ),
        slot(
            "search-dedup-ocr-duplicate-corpus",
            ready=False,
            evidence="ocr_duplicate_corpus=false",
            blocker_id="ocr-duplicate-corpus-required",
            operator_action="Validate OCR-derived duplicate groups against engine/version-specific OCR corpora.",
        ),
        slot(
            "search-dedup-trusted-duplicate-manifest-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=ANALYSIS_TRUSTED_DIFF_BLOCKERS[60],
            operator_action="Attach a passing trusted duplicate-manifest diff before making suppression-ready claims.",
        ),
        slot(
            "search-dedup-large-case-performance-validation",
            ready=False,
            evidence="large_case_dedup_performance_validation=false",
            blocker_id="large-case-dedup-performance-validation-required",
            operator_action="Run large search-result dedup benchmarks and preserve p95 latency/memory evidence.",
        ),
    ]
    blockers = sorted(
        {
            str(slot_row["blocker_id"])
            for slot_row in validation_slots
            if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": SEARCH_DEDUP_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 60,
        "gap_id": SEARCH_DEDUP_GAP_ID,
        "batch_id": "commercial-uplift-056-060",
        "selected_track": "bounded-search-hit-duplicate-review",
        "duplicate_group_count": group_count,
        "duplicate_match_count": duplicate_match_count,
        "unique_fingerprint_count": unique_fingerprint_count,
        "search_dedup_manifest_sha256": manifest_hash,
        "dedup_review_profile_version": str(dedup_review_profile.get("profile_version") or ""),
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete"),
        "blocking_slot_count": sum(1 for slot_row in validation_slots if slot_row.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(SEARCH_DEDUP_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage search <case-db-or-output> --keyword <keyword> --output search-results.json",
            "rapidtriage cross-tool-validate --rapid-output search-results.json --reference-output <trusted-duplicate-manifest> --backlog-item 60 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 60 --json",
        ],
        "report_guidance": {
            "allowed_use": "duplicate-hit-triage-pivot",
            "forbidden_claims": [
                "duplicates are safely suppressed",
                "preview-based duplicate groups are content-complete",
                "fuzzy/OCR/media duplicates are validated",
                "deduplication is commercial-grade on large cases",
            ],
            "required_disclaimer": (
                "Search deduplication collapses repeated hits for review routing only. Do not hide, suppress, or report "
                "duplicate conclusions until Case DB suppression state, fuzzy/text/OCR/media corpora, trusted manifest "
                "diffs, and large-case performance evidence are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_analysis_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def search_deduplication_core_accuracy_gates(
    *,
    groups: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
    dedup_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = []
    if summary.get("unique_fingerprint_count") is not None:
        satisfied.append("duplicate fingerprint generation")
    if summary.get("duplicate_group_count") is not None:
        satisfied.append("duplicate group counts")
    if any(group.get("match_indices") for group in groups):
        satisfied.append("representative hit links")
    if any(group.get("sources") or group.get("paths") for group in groups):
        satisfied.append("source/path references")
    if any(group.get("collapse_hint") for group in groups):
        satisfied.append("collapse preview profile")
    dedup_manifest = dedup_manifest if isinstance(dedup_manifest, Mapping) else {}
    if dedup_manifest.get("manifest_sha256"):
        satisfied.append("dedup citation manifest")
    if dedup_manifest.get("member_row_hash_count"):
        satisfied.append("duplicate member row hashes")
    if isinstance(dedup_manifest.get("source_viewer_locator"), Mapping):
        satisfied.append("dedup source viewer locators")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("dedup report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("dedup report-grade ready slots")
    satisfied.append("near-duplicate limitation warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append(ANALYSIS_TRUSTED_DIFF_CHECKS[60])
    return [
        build_accuracy_gate(
            60,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"duplicate_group_count:{summary.get('duplicate_group_count', 0)}",
                f"duplicate_match_count:{summary.get('duplicate_match_count', 0)}",
                f"unique_fingerprint_count:{summary.get('unique_fingerprint_count', 0)}",
                f"dedup_manifest_hash:{dedup_manifest.get('manifest_sha256', '')}",
                f"dedup_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def search_deduplication_commercial_uplift_evidence(
    *,
    groups: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
    dedup_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
    core_accuracy_gates: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == SEARCH_DEDUP_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    assessment = search_deduplication_assessment()
    dedup_manifest = dedup_manifest if isinstance(dedup_manifest, Mapping) else {}
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    return {
        "batch_id": "commercial-uplift-056-060",
        "item_numbers": [60],
        "implementation_track": "search-hit-deduplication-gate",
        "source_refs": [
            f"duplicate_group_count:{summary.get('duplicate_group_count', 0)}",
            f"duplicate_match_count:{summary.get('duplicate_match_count', 0)}",
            f"unique_fingerprint_count:{summary.get('unique_fingerprint_count', 0)}",
            f"search_dedup_manifest_sha256:{dedup_manifest.get('manifest_sha256', '')}",
            f"search_dedup_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
        ],
        "reportability_decision": search_deduplication_reportability_decision(
            failed_validation_check_ids=[
                "persistent-dedup-suppression-workflow",
                "fuzzy-near-duplicate-text-grouping",
                "perceptual-media-duplicate-grouping",
                "case-db-duplicate-suppression-state",
                *([] if isinstance(trusted_diff, Mapping) and trusted_diff.get("status") == "pass" else [ANALYSIS_TRUSTED_DIFF_BLOCKERS[60]]),
            ],
            assessment_blockers=list(assessment["blockers"]),
            summary=summary,
            validation_plan=validation_plan,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "persistent-dedup-suppression-workflow",
            "fuzzy-near-duplicate-text-grouping",
            "perceptual-media-duplicate-grouping",
            "case-db-duplicate-suppression-state",
            *([] if isinstance(trusted_diff, Mapping) and trusted_diff.get("status") == "pass" else [ANALYSIS_TRUSTED_DIFF_BLOCKERS[60]]),
        ],
        "trusted_diff": dict(trusted_diff) if isinstance(trusted_diff, Mapping) else {
            "status": "missing",
            "blocker_id": ANALYSIS_TRUSTED_DIFF_BLOCKERS[60],
            "required_tools": sorted(ANALYSIS_TRUSTED_TOOLS),
        },
        "commercial_blockers": list(assessment["blockers"]),
        "large_data_controls": {
            "max_groups": int(summary.get("max_groups") or 0),
            "group_count": len(groups),
            "duplicate_match_count": int(summary.get("duplicate_match_count") or 0),
            "representative_first_review": True,
            "hash_or_preview_fingerprint": True,
            "collapse_preview_supported": True,
            "dedup_manifest_hash": str(dedup_manifest.get("manifest_sha256") or ""),
            "dedup_member_row_hash_count": int(dedup_manifest.get("member_row_hash_count") or 0),
            "dedup_source_viewer_locator": bool(dedup_manifest.get("source_viewer_locator")),
            "dedup_report_grade_validation_plan_present": bool(validation_plan),
            "dedup_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or ""),
            "dedup_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "dedup_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "media_perceptual_duplicate_grouping": False,
            "case_db_suppression_state": False,
        },
        "reporting_status": "implemented-baseline-validation-required",
    }


def search_deduplication_reportability_decision(
    *,
    failed_validation_check_ids: Sequence[str],
    assessment_blockers: Sequence[str],
    summary: Mapping[str, object],
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in assessment_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    blockers.update(str(item) for item in validation_plan.get("blockers", []) if str(item))
    return {
        "profile_version": "search-deduplication-reportability-decision-v1",
        "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
        "decision": "do-not-report-duplicate-groups-as-suppressed-or-content-complete",
        "allowed_use": "duplicate-hit-triage-pivot",
        "blockers": sorted(blockers),
        "duplicate_group_count": int(summary.get("duplicate_group_count") or 0),
        "duplicate_match_count": int(summary.get("duplicate_match_count") or 0),
        "dedup_report_grade_validation_plan_present": bool(validation_plan),
        "dedup_report_grade_validation_plan_hash": str(validation_plan.get("validation_plan_sha256") or ""),
        "dedup_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
        "dedup_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate exact, fuzzy text, perceptual image/video, and OCR duplicate groups against a large known-answer corpus",
            "persist analyst suppression decisions in Case DB before hiding or excluding duplicates",
            "verify representative source rows and hashes before using duplicates in reports",
        ],
    }


def build_dedup_review_profile(*, groups: Sequence[Mapping[str, object]], summary: Mapping[str, object]) -> dict[str, object]:
    review_groups = []
    for group in groups[:10]:
        review_groups.append(
            {
                "group_id": group.get("group_id"),
                "representative_index": group.get("representative_index"),
                "hidden_duplicate_count": group.get("hidden_duplicate_count"),
                "match_count": group.get("match_count"),
                "review_status": "unreviewed",
                "review_decision": "pending",
                "report_suppression_status": group.get("report_suppression_status", "not-suppressed"),
                "suggested_action": "open representative hit, verify source hash, then review duplicate members before suppressing",
                "collapse_hint": group.get("collapse_hint", "show-representative-with-duplicates-collapsed"),
            }
        )
    return {
        "profile_version": "search-dedup-review-profile-v1",
        "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
        "duplicate_group_count": int(summary.get("duplicate_group_count") or 0),
        "duplicate_match_count": int(summary.get("duplicate_match_count") or 0),
        "representative_first_review": True,
        "collapse_preview_supported": True,
        "review_group_limit": 10,
        "review_groups": review_groups,
        "case_db_suppression_state": False,
        "suppression_requires_analyst_override": True,
        "commercial_release_blocked": True,
        "blockers": [
            "case-db-duplicate-suppression-state",
            "trusted-duplicate-manifest-diff",
            "fuzzy-text-and-perceptual-media-duplicate-validation",
        ],
    }


def dedupe_fingerprint(match: Mapping[str, object]) -> str:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    hashes = []
    for key in ("sha256", "sha1", "md5", "hash"):
        value = metadata.get(key) or match.get(key)
        if isinstance(value, str) and value:
            hashes.append(value.lower())
    if hashes:
        return f"hash:{hashes[0]}"
    source = str(match.get("source") or "").lower()
    path = normalize_dedupe_text(str(match.get("path") or ""))
    title = normalize_dedupe_text(str(match.get("title") or ""))
    preview = normalize_dedupe_text(str(match.get("preview") or ""))[:300]
    return stable_id("preview", source, path, title, preview)


def search_deduplication_assessment() -> dict[str, object]:
    return {
        "component": "search-hit-deduplication",
        "status": "implemented-baseline-validation-required",
        "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
        "ready_for_court_report": False,
        "blockers": [
            "deduplication-is-hash-or-normalized-preview-based-not-full-content-clustering",
            "ocr-and-export-duplicate-hits-need-source-level-review-before-suppression",
            "near-duplicate-semantic-clustering-not-implemented",
        ],
        "recommended_validation": [
            "Use duplicate groups to reduce review load, but verify representative source rows before hiding or rejecting duplicates.",
            "Prefer hash-based duplicate groups for report decisions; preview-based groups are triage hints.",
        ],
    }


def normalize_dedupe_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def cluster_keys(match: Mapping[str, object]) -> Iterable[tuple[str, str]]:
    source = str(match.get("source") or "unknown").strip().lower()
    if source:
        yield ("source", source)
    kind = str(match.get("kind") or "").strip().lower()
    if kind:
        yield ("kind", kind)
    path = str(match.get("path") or "")
    suffix = Path(path).suffix.lower()
    if suffix:
        yield ("extension", suffix)
    parent = str(Path(path).parent) if path else ""
    if parent and parent != ".":
        yield ("folder", parent)
    for keyword in match.get("matched_keywords", []):
        text = str(keyword).strip().lower()
        if text:
            yield ("keyword", text)


def cluster_label(family: str, value: str) -> str:
    labels = {
        "source": "Source",
        "kind": "Artifact kind",
        "extension": "Extension",
        "folder": "Folder",
        "keyword": "Keyword",
    }
    return f"{labels.get(family, family.title())}: {value}"


def cluster_review_hint(family: str, value: str, count: int) -> str:
    if family == "folder":
        return f"Review this folder as a set; {count} hits may share custody, owner, or app context."
    if family == "keyword":
        return f"Use this keyword cluster to separate repeated hits from unique evidence before reporting."
    if family == "kind":
        return f"Open representative rows first, then verify parser limitations for {value}."
    return "Use representative hits to decide whether this cluster is report-worthy or noise."


def most_common_paths(matches: Sequence[Mapping[str, object]]) -> list[str]:
    counter = Counter(str(item.get("path") or "") for item in matches if item.get("path"))
    return [path for path, _count in counter.most_common(5)]


def build_entity_view(
    matches: Sequence[Mapping[str, object]],
    *,
    max_entities: int,
) -> dict[str, object]:
    buckets: dict[tuple[str, str], dict[str, object]] = {}
    for index, match in enumerate(matches):
        text = entity_haystack(match)
        for entity_type, value in [*iter_entities(text), *iter_structured_entities(match)]:
            key = (entity_type, value)
            bucket = buckets.setdefault(
                key,
                {
                    "entity_id": stable_id("entity", entity_type, value),
                    "type": entity_type,
                    "value": value,
                    "count": 0,
                    "sources": set(),
                    "kinds": set(),
                    "paths": set(),
                    "match_indices": [],
                    "risk_flags": set(),
                },
            )
            bucket["count"] = int(bucket["count"]) + 1
            bucket["sources"].add(str(match.get("source") or "unknown"))
            if match.get("kind"):
                bucket["kinds"].add(str(match.get("kind")))
            if match.get("path"):
                bucket["paths"].add(str(match.get("path")))
            if len(bucket["match_indices"]) < MAX_ENTITY_MATCH_REFERENCES:
                bucket["match_indices"].append(index)
            for flag in entity_risk_flags(entity_type, value):
                bucket["risk_flags"].add(flag)

    entities = []
    for bucket in sorted(buckets.values(), key=lambda item: (-int(item["count"]), str(item["type"]), str(item["value"]))):
        entities.append(
            {
                "entity_id": bucket["entity_id"],
                "type": bucket["type"],
                "value": bucket["value"],
                "count": bucket["count"],
                "sources": sorted(bucket["sources"]),
                "kinds": sorted(bucket["kinds"]),
                "paths": sorted(bucket["paths"])[:10],
                "match_indices": bucket["match_indices"],
                "truncated_match_indices": int(bucket["count"]) > len(bucket["match_indices"]),
                "risk_flags": sorted(bucket["risk_flags"]),
                "confidence": "pattern-match",
            }
        )
        if len(entities) >= max_entities:
            break

    type_counts = Counter(str(item["type"]) for item in entities)
    review_profile = build_entity_review_profile(entities, total_candidate_count=len(buckets), max_entities=max_entities)
    citation_manifest = build_entity_citation_manifest(entities, matches)
    validation_plan = build_entity_report_grade_validation_plan(
        entities=entities,
        matches=matches,
        entity_review_profile=review_profile,
        entity_citation_manifest=citation_manifest,
    )
    return {
        "summary": {
            "entity_count": len(entities),
            "type_counts": dict(sorted(type_counts.items())),
            "max_entities": max_entities,
            "truncated": len(buckets) > len(entities),
            "review_queue_count": int(review_profile.get("review_queue_count") or 0),
            "merge_split_candidate_count": int(review_profile.get("merge_split_candidate_count") or 0),
            "entity_citation_entry_count": int(citation_manifest.get("entity_entry_count") or 0),
            "match_citation_count": int(citation_manifest.get("match_citation_count") or 0),
            "entity_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "entity_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "commercial_gap_ids": ["#47"],
            "commercial_grade_ready": False,
        },
        "entity_review_profile": review_profile,
        "entity_citation_manifest": citation_manifest,
        "entity_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "entity_report_grade_validation_plan": validation_plan,
        "entity_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "entities": entities,
        "report_grade_assessment": component_report_grade_assessment("#47", "entity-view"),
    }


def build_entity_review_profile(
    entities: Sequence[Mapping[str, object]],
    *,
    total_candidate_count: int,
    max_entities: int,
) -> dict[str, object]:
    type_counts = Counter(str(entity.get("type") or "unknown") for entity in entities)
    review_queue: list[dict[str, object]] = []
    merge_split_candidate_count = 0
    for entity in entities:
        entity_type = str(entity.get("type") or "unknown")
        count = int(entity.get("count") or 0)
        sources = list(entity.get("sources") or [])
        paths = list(entity.get("paths") or [])
        risk_flags = list(entity.get("risk_flags") or [])
        merge_split_required = entity_type in {"person", "account", "phone", "email"} or len(sources) > 1
        if merge_split_required:
            merge_split_candidate_count += 1
        review_queue.append(
            {
                "entity_id": str(entity.get("entity_id") or ""),
                "type": entity_type,
                "value": str(entity.get("value") or ""),
                "count": count,
                "source_count": len(sources),
                "path_count": len(paths),
                "risk_flags": risk_flags[:10],
                "match_indices": list(entity.get("match_indices") or [])[:MAX_ENTITY_MATCH_REFERENCES],
                "review_priority": entity_review_priority(entity_type, count, risk_flags, len(sources)),
                "review_status": "unreviewed",
                "review_decision": "pending",
                "merge_split_review_required": merge_split_required,
                "report_candidate": False,
                "validation_status": "candidate",
            }
        )
    review_queue.sort(
        key=lambda item: (
            item["review_priority"] != "high",
            -int(item["count"]),
            str(item["type"]),
            str(item["value"]),
        )
    )
    return {
        "profile_version": "entity-review-profile-v1",
        "selected_track": "bounded-pattern-and-structured-entity-review",
        "entity_count": len(entities),
        "total_candidate_count": total_candidate_count,
        "max_entities": max_entities,
        "type_counts": dict(sorted(type_counts.items())),
        "review_queue": review_queue,
        "review_queue_count": len(review_queue),
        "merge_split_candidate_count": merge_split_candidate_count,
        "persistent_entity_review_state": False,
        "analyst_verified_entity_resolution": False,
        "automatic_merge_performed": False,
        "commercial_release_blocked": True,
        "reporting_status": "entity-review-validation-required",
        "required_before_report": [
            "persist analyst merge/split decisions before using entities as people/account conclusions",
            "validate entity extraction against a hand-labeled fixture for false positives and missed aliases",
            "attach source-row citations and confidence notes before promoting entity pivots to report findings",
        ],
    }


def build_entity_citation_manifest(
    entities: Sequence[Mapping[str, object]],
    matches: Sequence[Mapping[str, object]],
    *,
    entity_limit: int = 200,
    match_limit: int = MAX_ENTITY_MATCH_REFERENCES,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    match_citation_count = 0
    for index, entity in enumerate(entities[:entity_limit], start=1):
        match_indices = [
            int(item)
            for item in list(entity.get("match_indices") or [])[:match_limit]
            if isinstance(item, int) and 0 <= item < len(matches)
        ]
        match_citations = []
        for match_index in match_indices:
            match = matches[match_index]
            source = str(match.get("source") or "unknown")
            path = str(match.get("path") or "")
            title = str(match.get("title") or path or f"match-{match_index}")
            match_citations.append(
                {
                    "match_index": match_index,
                    "source": source,
                    "path": path,
                    "title": title,
                    "kind": str(match.get("kind") or ""),
                    "source_viewer_locator": {
                        "viewer": "search-entity-source",
                        "entity_id": str(entity.get("entity_id") or ""),
                        "match_index": match_index,
                        "source": source,
                        "path": path,
                    },
                    "match_sha256": stable_analysis_sha256(
                        {
                            "entity_id": str(entity.get("entity_id") or ""),
                            "match_index": match_index,
                            "source": source,
                            "path": path,
                            "title": title,
                        }
                    ),
                }
            )
        match_citation_count += len(match_citations)
        value = str(entity.get("value") or "")
        entry_payload = {
            "entry_index": index,
            "entity_id": str(entity.get("entity_id") or ""),
            "type": str(entity.get("type") or ""),
            "value_sha256": stable_analysis_sha256(value),
            "value_shape": entity_value_shape(str(entity.get("type") or ""), value),
            "count": int(entity.get("count") or 0),
            "source_count": len(entity.get("sources") or []),
            "path_count": len(entity.get("paths") or []),
            "risk_flags": [str(item) for item in list(entity.get("risk_flags") or [])[:10]],
            "match_citation_count": len(match_citations),
            "merge_split_review_required": str(entity.get("type") or "") in {"person", "account", "phone", "email"}
            or len(entity.get("sources") or []) > 1,
        }
        entries.append(
            {
                **entry_payload,
                "entry_hash": stable_analysis_sha256(entry_payload),
                "match_citations": match_citations,
                "match_citations_truncated": bool(entity.get("truncated_match_indices")),
                "source_viewer_locator": {
                    "viewer": "search-entity-review",
                    "entity_id": entry_payload["entity_id"],
                    "type": entry_payload["type"],
                    "open_requires_merge_split_review": entry_payload["merge_split_review_required"],
                },
                "validation_status": "candidate-entity-citation",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "search-entity-citation-manifest-v1",
        "item_number": 47,
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-entity-source-citations",
        "entity_entry_count": len(entries),
        "entity_entry_cap": entity_limit,
        "entity_entries_truncated": len(entities) > entity_limit,
        "match_citation_count": match_citation_count,
        "match_citation_cap_per_entity": match_limit,
        "entity_entries": entries,
        "raw_entity_values_serialized": False,
        "persistent_entity_review_state": False,
        "analyst_verified_entity_resolution": False,
        "passed_validation_check_ids": [
            "search-entity-citation-manifest-emitted",
            "entity-source-viewer-locators-built",
            "entity-values-hashed-in-manifest",
        ],
        "failed_validation_check_ids": [
            "analyst-verified-entity-resolution",
            "entity-merge-split-workflow",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[47],
        ],
        "commercial_blockers": [
            "analyst-verified-entity-resolution",
            "entity-merge-split-workflow",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[47],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_analysis_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_entity_report_grade_validation_plan(
    *,
    entities: Sequence[Mapping[str, object]],
    matches: Sequence[Mapping[str, object]],
    entity_review_profile: Mapping[str, object],
    entity_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    review_profile_hash = stable_analysis_sha256(entity_review_profile)
    citation_manifest_hash = str(entity_citation_manifest.get("manifest_sha256") or "")
    match_citation_count = int(entity_citation_manifest.get("match_citation_count") or 0)
    entity_entry_count = int(entity_citation_manifest.get("entity_entry_count") or 0)
    merge_split_candidate_count = int(entity_review_profile.get("merge_split_candidate_count") or 0)

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "search-entity-pattern-and-structured-extraction",
            ready=bool(entities),
            evidence=f"entity_count={len(entities)} match_count={len(matches)}",
            blocker_id="search-entity-extraction-required",
            operator_action="Run search analysis so pattern and structured entity candidates are emitted.",
        ),
        slot(
            "search-entity-review-profile-emitted",
            ready=entity_review_profile.get("profile_version") == "entity-review-profile-v1",
            evidence=f"entity_review_profile_sha256={review_profile_hash}",
            blocker_id="search-entity-review-profile-required",
            operator_action="Regenerate analysis so the entity review profile is available to the reviewer.",
        ),
        slot(
            "search-entity-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"entity_citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="search-entity-citation-manifest-required",
            operator_action="Generate the entity citation manifest before using entity output in a report.",
        ),
        slot(
            "search-entity-source-viewer-locators",
            ready=match_citation_count > 0,
            evidence=f"match_citation_count={match_citation_count}",
            blocker_id="search-entity-source-viewer-locators-required",
            operator_action="Attach source viewer locators for entity match citations.",
        ),
        slot(
            "search-entity-hash-only-citations",
            ready=entity_citation_manifest.get("raw_entity_values_serialized") is False,
            evidence=f"raw_entity_values_serialized={entity_citation_manifest.get('raw_entity_values_serialized')}",
            blocker_id="search-entity-hash-only-citations-required",
            operator_action="Keep entity citation manifests hash-only unless a lawful report export explicitly reveals values.",
        ),
        slot(
            "search-entity-merge-split-review-queue",
            ready=merge_split_candidate_count > 0,
            evidence=f"merge_split_candidate_count={merge_split_candidate_count}",
            blocker_id="search-entity-merge-split-review-queue-required",
            operator_action="Create a merge/split review queue for people, accounts, phones, and emails.",
        ),
        slot(
            "search-entity-persistent-review-state",
            ready=False,
            evidence="persistent_entity_review_state=false",
            blocker_id="persistent-entity-review-state-required",
            operator_action="Persist analyst merge/split decisions, notes, timestamps, and reviewer identity.",
        ),
        slot(
            "search-entity-analyst-verified-resolution",
            ready=False,
            evidence="analyst_verified_entity_resolution=false",
            blocker_id="analyst-verified-entity-resolution-required",
            operator_action="Require analyst verification before reporting person/account/entity resolution claims.",
        ),
        slot(
            "search-entity-merge-split-workflow",
            ready=False,
            evidence="entity_merge_split_workflow=false",
            blocker_id="entity-merge-split-workflow-required",
            operator_action="Add GUI/workflow support for merge, split, undo, and audit of entity decisions.",
        ),
        slot(
            "search-entity-trusted-review-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=ANALYSIS_TRUSTED_DIFF_BLOCKERS[47],
            operator_action="Attach a passing analyst entity review diff.",
        ),
        slot(
            "search-entity-false-positive-corpus",
            ready=False,
            evidence="entity_false_positive_corpus_attached=false",
            blocker_id="entity-false-positive-corpus-required",
            operator_action="Measure false positives, missed aliases, and normalization drift with known-answer fixtures.",
        ),
        slot(
            "search-entity-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="entity-independent-review-required",
            operator_action="Attach independent reviewer signoff before entity resolution wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": ENTITY_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 47,
        "gap_id": "#47",
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-hash-only-entity-report-validation",
        "match_count": len(matches),
        "entity_count": len(entities),
        "entity_entry_count": entity_entry_count,
        "match_citation_count": match_citation_count,
        "merge_split_candidate_count": merge_split_candidate_count,
        "entity_review_profile_sha256": review_profile_hash,
        "entity_citation_manifest_sha256": citation_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(ENTITY_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage search <case-db-or-output> --keyword <keyword> --output search-results.json",
            "rapidtriage cross-tool-validate --rapid-output search-results.json --reference-output <analyst-entity-review> --backlog-item 47 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 47 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-entity-review-pivot",
            "forbidden_claims": [
                "entities are analyst-resolved people or accounts",
                "aliases have been merged or split by a reviewer",
                "entity extraction false-positive rates are validated",
                "entity view is commercial-grade for full-case identity resolution",
            ],
            "required_disclaimer": (
                "Entities are pattern/field-based review pivots. Do not report identity-resolution conclusions until "
                "persistent review state, analyst merge/split workflow, trusted entity diff, false-positive corpus, "
                "and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_analysis_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def entity_value_shape(entity_type: str, value: str) -> str:
    if not value:
        return "empty"
    if entity_type == "email" and "@" in value:
        local, domain = value.split("@", 1)
        return f"email:{len(local)}@{domain}"
    if entity_type in {"phone", "hash"}:
        return f"{entity_type}:len-{len(value)}"
    if entity_type in {"url", "domain", "ipv4"}:
        return f"{entity_type}:{value[:32]}"
    return f"{entity_type}:len-{len(value)}"


def entity_review_priority(entity_type: str, count: int, risk_flags: Sequence[object], source_count: int) -> str:
    if risk_flags or entity_type in {"email", "url", "domain", "ipv4", "hash"} or count >= 2 or source_count >= 2:
        return "high"
    return "normal"


def entity_haystack(match: Mapping[str, object]) -> str:
    return json.dumps(
        {
            "path": match.get("path"),
            "title": match.get("title"),
            "preview": match.get("preview"),
            "metadata": match.get("metadata"),
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )


def iter_entities(text: str) -> Iterable[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    for entity_type, pattern in ENTITY_PATTERNS:
        for match in pattern.finditer(text):
            value = normalize_entity_value(entity_type, match.group(0))
            if not value:
                continue
            key = (entity_type, value)
            if key in seen:
                continue
            seen.add(key)
            yield key
            if entity_type == "url":
                domain = normalize_domain(urlparse(value).hostname or "")
                if domain:
                    domain_key = ("domain", domain)
                    if domain_key not in seen:
                        seen.add(domain_key)
                        yield domain_key


def iter_structured_entities(match: Mapping[str, object]) -> Iterable[tuple[str, str]]:
    payload = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    candidates = collect_structured_entity_candidates(payload)
    candidates.extend(collect_structured_entity_candidates(match))
    seen: set[tuple[str, str]] = set()
    for entity_type, value in candidates:
        normalized = normalize_entity_value(entity_type, value)
        if not normalized:
            continue
        key = (entity_type, normalized)
        if key in seen:
            continue
        seen.add(key)
        yield key


def collect_structured_entity_candidates(value: object, *, depth: int = 0) -> list[tuple[str, str]]:
    if depth > 4:
        return []
    rows: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            if isinstance(item, str):
                text = item.strip()
                if text:
                    if key_text in {"user", "username", "account", "account_name", "accountname", "account_identifier", "accountidentifier"}:
                        rows.append(("account", text))
                    elif key_text in {"person", "name", "contact_name", "contactname", "display_name", "displayname", "fullname", "owner"}:
                        rows.append(("person", text))
                    elif key_text in {"sender", "recipient", "from", "to", "author"}:
                        rows.append(("account", text))
            elif isinstance(item, (Mapping, list)):
                rows.extend(collect_structured_entity_candidates(item, depth=depth + 1))
    elif isinstance(value, list):
        for item in value[:50]:
            rows.extend(collect_structured_entity_candidates(item, depth=depth + 1))
    return rows


def normalize_entity_value(entity_type: str, value: str) -> str:
    stripped = value.strip().strip(".,;:)]}\"'")
    if entity_type in {"email", "url", "hash"}:
        stripped = stripped.lower()
    if entity_type == "phone":
        digits = re.sub(r"\D", "", stripped)
        return stripped if len(digits) >= 8 else ""
    if entity_type == "person":
        if "://" in stripped or "@" in stripped or len(stripped) > 120:
            return ""
    if entity_type == "account":
        if len(stripped) > 160:
            return ""
    if entity_type == "ipv4" and is_private_or_noise_ip(stripped):
        return ""
    return stripped


def normalize_domain(value: str) -> str:
    domain = value.lower().strip(".")
    if not domain or "." not in domain:
        return ""
    return domain


def is_private_or_noise_ip(value: str) -> bool:
    if value in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
        return True
    parts = [int(part) for part in value.split(".") if part.isdigit()]
    if len(parts) != 4:
        return True
    return parts[0] == 10 or (parts[0] == 192 and parts[1] == 168) or (parts[0] == 172 and 16 <= parts[1] <= 31)


def entity_risk_flags(entity_type: str, value: str) -> list[str]:
    flags = []
    if entity_type in {"url", "domain", "ipv4"}:
        flags.append("network-pivot")
    if entity_type == "email":
        flags.append("account-pivot")
    if entity_type == "hash":
        flags.append("hash-pivot")
    if entity_type == "phone":
        flags.append("person-pivot")
    if entity_type == "person":
        flags.append("person-pivot")
    if entity_type == "account":
        flags.append("account-pivot")
    if value.endswith((".ru", ".cn", ".top", ".xyz")):
        flags.append("review-tld")
    return flags


def build_relationship_graph(
    matches: Sequence[Mapping[str, object]],
    *,
    entities: Sequence[Mapping[str, object]],
    max_edges: int,
) -> dict[str, object]:
    nodes: dict[str, dict[str, object]] = {}
    edges: list[dict[str, object]] = []
    entity_by_match: dict[int, list[Mapping[str, object]]] = defaultdict(list)
    for entity in entities:
        for index in entity.get("match_indices", []):
            if isinstance(index, int):
                entity_by_match[index].append(entity)

    for index, match in enumerate(matches[:MAX_GRAPH_MATCH_NODES]):
        match_id = stable_id("match", index, match.get("source"), match.get("path"), match.get("pointer"))
        nodes[match_id] = {
            "id": match_id,
            "type": "match",
            "label": str(match.get("title") or match.get("path") or f"match {index}"),
            "source": match.get("source"),
            "match_index": index,
        }
        path = str(match.get("path") or "")
        if path:
            path_id = stable_id("path", path)
            nodes.setdefault(path_id, {"id": path_id, "type": "path", "label": Path(path).name or path, "path": path})
            edges.append(graph_edge(match_id, path_id, "located-at", match=match, match_index=index))
        for keyword in match.get("matched_keywords", []):
            keyword_id = stable_id("keyword", keyword)
            nodes.setdefault(keyword_id, {"id": keyword_id, "type": "keyword", "label": str(keyword)})
            edges.append(graph_edge(match_id, keyword_id, "matched-keyword", match=match, match_index=index))
        for entity in entity_by_match.get(index, [])[:8]:
            entity_id = str(entity.get("entity_id"))
            nodes.setdefault(
                entity_id,
                {
                    "id": entity_id,
                    "type": str(entity.get("type") or "entity"),
                    "label": str(entity.get("value") or ""),
                    "count": entity.get("count"),
                },
            )
            edges.append(graph_edge(match_id, entity_id, "mentions", match=match, match_index=index))
        if len(edges) >= max_edges:
            edges = edges[:max_edges]
            break

    interaction_profile = build_graph_interaction_profile(
        nodes=list(nodes.values()),
        edges=edges,
        match_count=len(matches),
        max_edges=max_edges,
    )
    citation_manifest = build_graph_citation_manifest(nodes=list(nodes.values()), edges=edges)
    validation_plan = build_graph_report_grade_validation_plan(
        nodes=list(nodes.values()),
        edges=edges,
        graph_interaction_profile=interaction_profile,
        graph_citation_manifest=citation_manifest,
    )
    return {
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "max_match_nodes": MAX_GRAPH_MATCH_NODES,
            "max_edges": max_edges,
            "truncated": len(matches) > MAX_GRAPH_MATCH_NODES or len(edges) >= max_edges,
            "source_citation_edge_count": int(interaction_profile.get("source_citation_edge_count") or 0),
            "graph_citation_edge_count": int(citation_manifest.get("edge_citation_count") or 0),
            "source_viewer_locator_count": int(citation_manifest.get("source_viewer_locator_count") or 0),
            "available_filter_count": len(interaction_profile.get("available_filters") or []),
            "edge_page_count": int(interaction_profile.get("edge_page_count") or 0),
            "graph_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "graph_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "commercial_gap_ids": ["#48"],
            "commercial_grade_ready": False,
        },
        "nodes": list(nodes.values()),
        "edges": edges,
        "graph_interaction_profile": interaction_profile,
        "graph_citation_manifest": citation_manifest,
        "graph_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "graph_report_grade_validation_plan": validation_plan,
        "graph_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_assessment": component_report_grade_assessment("#48", "relationship-graph"),
    }


def graph_edge(
    source_id: str,
    target_id: str,
    edge_type: str,
    *,
    match: Mapping[str, object],
    match_index: int,
) -> dict[str, object]:
    return {
        "edge_id": stable_id("edge", source_id, target_id, edge_type, match_index),
        "source": source_id,
        "target": target_id,
        "type": edge_type,
        "match_indices": [match_index],
        "citation_count": 1,
        "source_citation": {
            "match_index": match_index,
            "source": str(match.get("source") or "unknown"),
            "kind": str(match.get("kind") or ""),
            "path": str(match.get("path") or ""),
            "pointer": str(match.get("pointer") or ""),
            "title": str(match.get("title") or ""),
        },
        "validation_status": "candidate",
        "causal_proof": False,
    }


def build_graph_interaction_profile(
    *,
    nodes: Sequence[Mapping[str, object]],
    edges: Sequence[Mapping[str, object]],
    match_count: int,
    max_edges: int,
) -> dict[str, object]:
    node_type_counts = Counter(str(node.get("type") or "unknown") for node in nodes)
    edge_type_counts = Counter(str(edge.get("type") or "unknown") for edge in edges)
    available_filters = [
        {
            "filter_id": f"node-type:{node_type}",
            "label": f"Node type: {node_type}",
            "count": count,
            "field": "node.type",
            "value": node_type,
        }
        for node_type, count in sorted(node_type_counts.items())
    ]
    available_filters.extend(
        {
            "filter_id": f"edge-type:{edge_type}",
            "label": f"Edge type: {edge_type}",
            "count": count,
            "field": "edge.type",
            "value": edge_type,
        }
        for edge_type, count in sorted(edge_type_counts.items())
    )
    edge_page_size = max(1, min(max_edges, 100))
    edge_page_count = (len(edges) + edge_page_size - 1) // edge_page_size if edges else 0
    return {
        "profile_version": "relationship-graph-interaction-v1",
        "selected_track": "bounded-cited-graph-review",
        "match_count": match_count,
        "node_type_counts": dict(sorted(node_type_counts.items())),
        "edge_type_counts": dict(sorted(edge_type_counts.items())),
        "available_filters": available_filters,
        "edge_page_size": edge_page_size,
        "edge_page_count": edge_page_count,
        "current_edge_page": 1 if edges else 0,
        "source_citation_edge_count": sum(1 for edge in edges if edge.get("source_citation")),
        "saved_layout_supported": False,
        "server_side_paging_supported": False,
        "interactive_canvas_supported": False,
        "commercial_release_blocked": True,
        "reporting_status": "graph-source-citation-validation-required",
        "required_before_report": [
            "persist graph filters and analyst layout before treating graph state as reviewed evidence",
            "add server-side graph paging before opening very large case-wide relationship graphs",
            "validate every reported edge against source citations and trusted graph review diffs",
        ],
    }


def build_graph_citation_manifest(
    *,
    nodes: Sequence[Mapping[str, object]],
    edges: Sequence[Mapping[str, object]],
    edge_limit: int = 500,
) -> dict[str, object]:
    node_index = {str(node.get("id") or ""): node for node in nodes if node.get("id")}
    edge_entries: list[dict[str, object]] = []
    source_viewer_locator_count = 0
    for index, edge in enumerate(edges[:edge_limit], start=1):
        citation = edge.get("source_citation") if isinstance(edge.get("source_citation"), Mapping) else {}
        source_id = str(edge.get("source") or "")
        target_id = str(edge.get("target") or "")
        source_node = node_index.get(source_id, {})
        target_node = node_index.get(target_id, {})
        source_locator = {
            "viewer": "search-graph-edge-source",
            "edge_id": str(edge.get("edge_id") or ""),
            "match_index": citation.get("match_index"),
            "source": str(citation.get("source") or "unknown"),
            "path": str(citation.get("path") or ""),
            "pointer": str(citation.get("pointer") or ""),
        }
        if citation:
            source_viewer_locator_count += 1
        entry_payload = {
            "entry_index": index,
            "edge_id": str(edge.get("edge_id") or ""),
            "source_node_id": source_id,
            "target_node_id": target_id,
            "edge_type": str(edge.get("type") or ""),
            "source_node_type": str(source_node.get("type") or ""),
            "target_node_type": str(target_node.get("type") or ""),
            "citation_count": int(edge.get("citation_count") or 0),
            "causal_proof": bool(edge.get("causal_proof")),
        }
        edge_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_analysis_sha256(entry_payload),
                "source_citation": {
                    "match_index": citation.get("match_index"),
                    "source": str(citation.get("source") or "unknown"),
                    "kind": str(citation.get("kind") or ""),
                    "path": str(citation.get("path") or ""),
                    "pointer": str(citation.get("pointer") or ""),
                    "title": str(citation.get("title") or ""),
                },
                "source_viewer_locator": source_locator,
                "validation_status": "candidate-graph-edge-citation",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "search-graph-citation-manifest-v1",
        "item_number": 48,
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-graph-edge-source-citations",
        "node_count": len(nodes),
        "edge_citation_count": len(edge_entries),
        "edge_citation_cap": edge_limit,
        "edge_citations_truncated": len(edges) > edge_limit,
        "source_viewer_locator_count": source_viewer_locator_count,
        "edge_entries": edge_entries,
        "server_side_paging_supported": False,
        "saved_layout_supported": False,
        "causal_proof_supported": False,
        "passed_validation_check_ids": [
            "search-graph-citation-manifest-emitted",
            "graph-edge-source-viewer-locators-built",
            "graph-edge-source-citations-built",
        ],
        "failed_validation_check_ids": [
            "server-side-graph-paging",
            "saved-graph-layouts",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[48],
        ],
        "commercial_blockers": [
            "server-side-graph-paging",
            "saved-graph-layouts",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[48],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_analysis_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_graph_report_grade_validation_plan(
    *,
    nodes: Sequence[Mapping[str, object]],
    edges: Sequence[Mapping[str, object]],
    graph_interaction_profile: Mapping[str, object],
    graph_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    interaction_profile_hash = stable_analysis_sha256(graph_interaction_profile)
    citation_manifest_hash = str(graph_citation_manifest.get("manifest_sha256") or "")
    edge_citation_count = int(graph_citation_manifest.get("edge_citation_count") or 0)
    source_viewer_locator_count = int(graph_citation_manifest.get("source_viewer_locator_count") or 0)
    available_filter_count = len(graph_interaction_profile.get("available_filters") or [])
    edge_page_count = int(graph_interaction_profile.get("edge_page_count") or 0)

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "search-graph-nodes-and-edges-built",
            ready=bool(nodes) and bool(edges),
            evidence=f"node_count={len(nodes)} edge_count={len(edges)}",
            blocker_id="search-graph-nodes-and-edges-required",
            operator_action="Run search analysis with enough matches/entities to emit relationship graph nodes and edges.",
        ),
        slot(
            "search-graph-interaction-profile-emitted",
            ready=graph_interaction_profile.get("profile_version") == "relationship-graph-interaction-v1",
            evidence=f"graph_interaction_profile_sha256={interaction_profile_hash}",
            blocker_id="search-graph-interaction-profile-required",
            operator_action="Regenerate analysis so graph filter/page metadata is available to the reviewer.",
        ),
        slot(
            "search-graph-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"graph_citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="search-graph-citation-manifest-required",
            operator_action="Generate the graph citation manifest before using graph output in a report.",
        ),
        slot(
            "search-graph-edge-source-viewer-locators",
            ready=edge_citation_count > 0 and source_viewer_locator_count > 0,
            evidence=f"edge_citation_count={edge_citation_count} source_viewer_locator_count={source_viewer_locator_count}",
            blocker_id="search-graph-edge-source-viewer-locators-required",
            operator_action="Attach source viewer locators for graph edge citations.",
        ),
        slot(
            "search-graph-filter-and-page-metadata",
            ready=available_filter_count > 0 and edge_page_count >= 1,
            evidence=f"available_filter_count={available_filter_count} edge_page_count={edge_page_count}",
            blocker_id="search-graph-filter-page-metadata-required",
            operator_action="Emit filter metadata and bounded edge page metadata for graph review.",
        ),
        slot(
            "search-graph-causal-proof-warning",
            ready=graph_citation_manifest.get("causal_proof_supported") is False,
            evidence=f"causal_proof_supported={graph_citation_manifest.get('causal_proof_supported')}",
            blocker_id="search-graph-causal-proof-warning-required",
            operator_action="Record that graph edges are candidate pivots, not causal proof.",
        ),
        slot(
            "search-graph-interactive-canvas",
            ready=False,
            evidence="interactive_canvas_supported=false",
            blocker_id="interactive-graph-canvas-required",
            operator_action="Add an interactive graph canvas with keyboard navigation and source-row opening.",
        ),
        slot(
            "search-graph-server-side-paging",
            ready=False,
            evidence="server_side_paging_supported=false",
            blocker_id="server-side-graph-paging-required",
            operator_action="Add server-side graph paging before opening large case-wide relationship graphs.",
        ),
        slot(
            "search-graph-saved-layouts",
            ready=False,
            evidence="saved_layout_supported=false",
            blocker_id="saved-graph-layouts-required",
            operator_action="Persist analyst graph layouts, filters, notes, and reviewer identity.",
        ),
        slot(
            "search-graph-trusted-source-citation-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=ANALYSIS_TRUSTED_DIFF_BLOCKERS[48],
            operator_action="Attach a passing graph source-citation review diff.",
        ),
        slot(
            "search-graph-large-case-performance-validation",
            ready=False,
            evidence="large_case_graph_performance_validation=false",
            blocker_id="large-case-graph-performance-validation-required",
            operator_action="Validate graph latency, memory, and paging behavior on large result sets.",
        ),
        slot(
            "search-graph-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="graph-independent-review-required",
            operator_action="Attach independent reviewer signoff before relationship-graph wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": GRAPH_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 48,
        "gap_id": "#48",
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-source-cited-graph-report-validation",
        "node_count": len(nodes),
        "edge_count": len(edges),
        "edge_citation_count": edge_citation_count,
        "source_viewer_locator_count": source_viewer_locator_count,
        "available_filter_count": available_filter_count,
        "edge_page_count": edge_page_count,
        "graph_interaction_profile_sha256": interaction_profile_hash,
        "graph_citation_manifest_sha256": citation_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(GRAPH_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage search <case-db-or-output> --keyword <keyword> --output search-results.json",
            "rapidtriage cross-tool-validate --rapid-output search-results.json --reference-output <graph-source-citation-review> --backlog-item 48 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 48 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-source-cited-relationship-graph-pivot",
            "forbidden_claims": [
                "graph edges prove causality",
                "graph layout has been analyst-reviewed and persisted",
                "graph can scale to full-case relationship data without paging validation",
                "graph view is commercial-grade for large cases",
            ],
            "required_disclaimer": (
                "Graph edges are candidate source-cited pivots. Do not report graph relationships as reviewed "
                "findings until interactive review, server-side paging, saved layouts, trusted source-citation diff, "
                "large-case validation, and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_analysis_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def build_correlated_timeline(
    matches: Sequence[Mapping[str, object]],
    *,
    max_events: int,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        for timestamp_key, timestamp in iter_timestamps(match):
            events.append(
                {
                    "event_id": stable_id("analysis-event", index, timestamp_key, timestamp),
                    "timestamp": timestamp,
                    "timestamp_key": timestamp_key,
                    "match_index": index,
                    "source": str(match.get("source") or "unknown"),
                    "kind": str(match.get("kind") or ""),
                    "path": str(match.get("path") or ""),
                    "title": str(match.get("title") or match.get("path") or ""),
                    "summary": str(match.get("preview") or "")[:240],
                }
            )
    events.sort(key=lambda item: (timestamp_to_epoch(str(item["timestamp"])), str(item["source"]), str(item["path"])))
    original_event_count = len(events)
    truncated = len(events) > max_events
    events = events[:max_events]
    buckets = Counter(str(event["timestamp"])[:10] for event in events if str(event.get("timestamp")))
    correlation_profile = build_timeline_correlation_profile(
        events=events,
        original_event_count=original_event_count,
        max_events=max_events,
        truncated=truncated,
    )
    citation_manifest = build_timeline_citation_manifest(events=events, original_event_count=original_event_count)
    validation_plan = build_timeline_report_grade_validation_plan(
        events=events,
        timeline_correlation_profile=correlation_profile,
        timeline_citation_manifest=citation_manifest,
    )
    return {
        "summary": {
            "event_count": len(events),
            "date_bucket_count": len(buckets),
            "earliest_event_at": events[0]["timestamp"] if events else None,
            "latest_event_at": events[-1]["timestamp"] if events else None,
            "truncated": truncated,
            "event_page_count": int(correlation_profile.get("event_page_count") or 0),
            "missing_timezone_count": int(correlation_profile.get("missing_timezone_count") or 0),
            "event_citation_count": int(citation_manifest.get("event_citation_count") or 0),
            "source_viewer_locator_count": int(citation_manifest.get("source_viewer_locator_count") or 0),
            "timeline_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "timeline_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "commercial_gap_ids": ["#49"],
            "commercial_grade_ready": False,
        },
        "date_buckets": [{"date": date, "count": count} for date, count in sorted(buckets.items())],
        "events": events,
        "timeline_correlation_profile": correlation_profile,
        "timeline_citation_manifest": citation_manifest,
        "timeline_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "timeline_report_grade_validation_plan": validation_plan,
        "timeline_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_assessment": component_report_grade_assessment("#49", "correlated-timeline"),
    }


def build_timeline_correlation_profile(
    *,
    events: Sequence[Mapping[str, object]],
    original_event_count: int,
    max_events: int,
    truncated: bool,
) -> dict[str, object]:
    source_counts = Counter(str(event.get("source") or "unknown") for event in events)
    kind_counts = Counter(str(event.get("kind") or "unknown") for event in events)
    timezone_counts = Counter(timestamp_timezone_label(str(event.get("timestamp") or "")) for event in events)
    missing_timezone_count = int(timezone_counts.get("missing", 0))
    event_page_size = max(1, min(max_events, 250))
    event_page_count = (len(events) + event_page_size - 1) // event_page_size if events else 0
    return {
        "profile_version": "timeline-correlation-review-v1",
        "selected_track": "bounded-source-anchored-timeline-review",
        "original_event_count": original_event_count,
        "retained_event_count": len(events),
        "max_events": max_events,
        "truncated": truncated,
        "event_page_size": event_page_size,
        "event_page_count": event_page_count,
        "current_event_page": 1 if events else 0,
        "source_counts": dict(sorted(source_counts.items())),
        "kind_counts": dict(sorted(kind_counts.items())),
        "timezone_counts": dict(sorted(timezone_counts.items())),
        "missing_timezone_count": missing_timezone_count,
        "timezone_normalization_status": "utc-normalized-source-preserved",
        "source_anchor_required": True,
        "full_case_join_supported": False,
        "clock_skew_overlay_supported": False,
        "review_annotation_overlay_supported": False,
        "cursor_api_supported": False,
        "commercial_release_blocked": True,
        "reporting_status": "timeline-correlation-validation-required",
        "required_before_report": [
            "join timeline rows from the full Case DB instead of bounded search matches",
            "validate source timezone assumptions and clock skew against known-answer evidence",
            "persist analyst annotations and cursor state before using the timeline as reviewed case chronology",
        ],
    }


def build_timeline_citation_manifest(
    *,
    events: Sequence[Mapping[str, object]],
    original_event_count: int,
    event_limit: int = 500,
) -> dict[str, object]:
    event_entries: list[dict[str, object]] = []
    source_viewer_locator_count = 0
    missing_timezone_count = 0
    for index, event in enumerate(events[:event_limit], start=1):
        timestamp = str(event.get("timestamp") or "")
        timezone_label = timestamp_timezone_label(timestamp)
        if timezone_label == "missing":
            missing_timezone_count += 1
        locator = {
            "viewer": "search-timeline-event-source",
            "event_id": str(event.get("event_id") or ""),
            "match_index": event.get("match_index"),
            "source": str(event.get("source") or "unknown"),
            "path": str(event.get("path") or ""),
            "timestamp_key": str(event.get("timestamp_key") or ""),
        }
        source_viewer_locator_count += 1
        entry_payload = {
            "entry_index": index,
            "event_id": str(event.get("event_id") or ""),
            "timestamp": timestamp,
            "timestamp_key": str(event.get("timestamp_key") or ""),
            "timezone_label": timezone_label,
            "match_index": int(event.get("match_index") or 0),
            "source": str(event.get("source") or "unknown"),
            "kind": str(event.get("kind") or ""),
            "path_sha256": stable_analysis_sha256(str(event.get("path") or "")),
        }
        event_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_analysis_sha256(entry_payload),
                "source_viewer_locator": locator,
                "validation_status": "candidate-timeline-event-citation",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "search-timeline-citation-manifest-v1",
        "item_number": 49,
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-timeline-event-source-citations",
        "original_event_count": original_event_count,
        "event_citation_count": len(event_entries),
        "event_citation_cap": event_limit,
        "event_citations_truncated": len(events) > event_limit,
        "source_viewer_locator_count": source_viewer_locator_count,
        "missing_timezone_count": missing_timezone_count,
        "event_entries": event_entries,
        "full_case_join_supported": False,
        "cursor_api_supported": False,
        "clock_skew_overlay_supported": False,
        "review_annotation_overlay_supported": False,
        "passed_validation_check_ids": [
            "search-timeline-citation-manifest-emitted",
            "timeline-event-source-viewer-locators-built",
            "timeline-event-source-citations-built",
        ],
        "failed_validation_check_ids": [
            "full-case-timeline-join",
            "timezone-skew-validation",
            "cursor-paged-timeline",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[49],
        ],
        "commercial_blockers": [
            "full-case-timeline-join",
            "timezone-skew-validation",
            "cursor-paged-timeline",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[49],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_analysis_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_timeline_report_grade_validation_plan(
    *,
    events: Sequence[Mapping[str, object]],
    timeline_correlation_profile: Mapping[str, object],
    timeline_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    correlation_profile_hash = stable_analysis_sha256(timeline_correlation_profile)
    citation_manifest_hash = str(timeline_citation_manifest.get("manifest_sha256") or "")
    event_citation_count = int(timeline_citation_manifest.get("event_citation_count") or 0)
    source_viewer_locator_count = int(timeline_citation_manifest.get("source_viewer_locator_count") or 0)
    event_page_count = int(timeline_correlation_profile.get("event_page_count") or 0)
    missing_timezone_count = int(timeline_correlation_profile.get("missing_timezone_count") or 0)
    timezone_counts = (
        timeline_correlation_profile.get("timezone_counts")
        if isinstance(timeline_correlation_profile.get("timezone_counts"), Mapping)
        else {}
    )

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    utc_normalized = bool(events) and all(
        "+" in str(event.get("timestamp", "")) or str(event.get("timestamp", "")).endswith("Z")
        for event in events
        if isinstance(event, Mapping)
    )
    validation_slots = [
        slot(
            "search-timeline-timestamp-extraction",
            ready=bool(events),
            evidence=f"event_count={len(events)}",
            blocker_id="search-timeline-events-required",
            operator_action="Run search analysis on timestamp-bearing results so timeline events are emitted.",
        ),
        slot(
            "search-timeline-utc-normalization",
            ready=utc_normalized,
            evidence=f"utc_normalized={utc_normalized} missing_timezone_count={missing_timezone_count}",
            blocker_id="search-timeline-utc-normalization-required",
            operator_action="Normalize source timestamps while preserving the original source timezone assumption.",
        ),
        slot(
            "search-timeline-correlation-profile-emitted",
            ready=timeline_correlation_profile.get("profile_version") == "timeline-correlation-review-v1",
            evidence=f"timeline_correlation_profile_sha256={correlation_profile_hash}",
            blocker_id="search-timeline-correlation-profile-required",
            operator_action="Regenerate analysis so timeline page/timezone metadata is available to reviewers.",
        ),
        slot(
            "search-timeline-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"timeline_citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="search-timeline-citation-manifest-required",
            operator_action="Generate the timeline citation manifest before using timeline output in a report.",
        ),
        slot(
            "search-timeline-event-source-viewer-locators",
            ready=event_citation_count > 0 and source_viewer_locator_count > 0,
            evidence=f"event_citation_count={event_citation_count} source_viewer_locator_count={source_viewer_locator_count}",
            blocker_id="search-timeline-event-source-viewer-locators-required",
            operator_action="Attach source viewer locators for every report candidate timeline event.",
        ),
        slot(
            "search-timeline-timezone-and-cursor-metadata",
            ready=event_page_count >= 1 and bool(timezone_counts),
            evidence=f"event_page_count={event_page_count} timezone_count_keys={len(timezone_counts)}",
            blocker_id="search-timeline-timezone-cursor-metadata-required",
            operator_action="Emit bounded cursor/page metadata and timezone distribution for timeline review.",
        ),
        slot(
            "search-timeline-full-case-join",
            ready=False,
            evidence="full_case_join_supported=false",
            blocker_id="full-case-timeline-join-required",
            operator_action="Join all Case DB artifact families before calling this case chronology.",
        ),
        slot(
            "search-timeline-timezone-skew-validation",
            ready=False,
            evidence="clock_skew_overlay_supported=false",
            blocker_id="timezone-skew-validation-required",
            operator_action="Validate timezone assumptions and device clock skew against known-answer evidence.",
        ),
        slot(
            "search-timeline-cursor-paged-api",
            ready=False,
            evidence="cursor_api_supported=false",
            blocker_id="cursor-paged-timeline-required",
            operator_action="Expose cursor-paged timeline APIs before opening large case-wide timelines.",
        ),
        slot(
            "search-timeline-review-annotation-overlay",
            ready=False,
            evidence="review_annotation_overlay_supported=false",
            blocker_id="timeline-review-annotation-overlay-required",
            operator_action="Persist analyst annotations, reviewed state, and source-row decisions on timeline events.",
        ),
        slot(
            "search-timeline-known-answer-trusted-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=ANALYSIS_TRUSTED_DIFF_BLOCKERS[49],
            operator_action="Attach a passing trusted timeline-order/source-citation diff before report use.",
        ),
        slot(
            "search-timeline-large-case-validation",
            ready=False,
            evidence="large_case_timeline_validation=false",
            blocker_id="large-case-timeline-validation-required",
            operator_action="Run large-case timeline validation and capture p95 latency, memory, and failure thresholds.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan: dict[str, object] = {
        "profile_version": TIMELINE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 49,
        "gap_id": "#49",
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-source-anchored-timeline-report-validation",
        "event_count": len(events),
        "event_citation_count": event_citation_count,
        "source_viewer_locator_count": source_viewer_locator_count,
        "event_page_count": event_page_count,
        "missing_timezone_count": missing_timezone_count,
        "timeline_correlation_profile_sha256": correlation_profile_hash,
        "timeline_citation_manifest_sha256": citation_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(TIMELINE_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage search <case> --query <keyword> --json",
            "rapidtriage cross-tool-validate --rapid-output search-results.json --reference-output <timeline-known-answer> --backlog-item 49 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 49 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-search-result-timeline-triage-pivot",
            "forbidden_claim": "complete case chronology or validated device clock-skew finding",
            "required_disclaimer": (
                "Timeline rows are bounded to retained search hits and require full-case joins, timezone/skew "
                "validation, cursor-paged review, annotation state, trusted diffs, and large-case validation "
                "before report-grade chronology claims."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_analysis_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def timestamp_timezone_label(timestamp: str) -> str:
    if not timestamp:
        return "missing"
    if timestamp.endswith("Z"):
        return "UTC"
    if len(timestamp) >= 6 and timestamp[-6] in {"+", "-"} and timestamp[-3] == ":":
        return timestamp[-6:]
    return "missing"


def iter_timestamps(value: object, *, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            next_prefix = f"{prefix}.{key_text}" if prefix else key_text
            if key_text in TIMESTAMP_KEYS and isinstance(item, str):
                timestamp = normalize_timestamp(item)
                if timestamp:
                    yield next_prefix, timestamp
            if isinstance(item, (Mapping, list)):
                yield from iter_timestamps(item, prefix=next_prefix)
    elif isinstance(value, list):
        for index, item in enumerate(value[:100]):
            yield from iter_timestamps(item, prefix=f"{prefix}[{index}]")


def normalize_timestamp(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat()


def timestamp_to_epoch(value: str) -> float:
    try:
        return dt.datetime.fromisoformat(value).timestamp()
    except ValueError:
        return float("-inf")


def build_hypothesis_workbook(
    matches: Sequence[Mapping[str, object]],
    *,
    keywords: Sequence[str],
    clusters: Sequence[Mapping[str, object]],
    entities: Sequence[Mapping[str, object]],
    timeline_events: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    source_counts = Counter(str(match.get("source") or "unknown") for match in matches)
    entity_type_counts = Counter(str(entity.get("type") or "entity") for entity in entities)
    hypotheses: list[dict[str, object]] = []
    add_hypothesis(
        hypotheses,
        key="credential-exposure",
        condition=keyword_seen(keywords, {"password", "credential", "token", "secret"}) or entity_type_counts.get("email", 0) >= 2,
        title="Credential or account exposure",
        rationale="Credential-like keywords or account entities appear in the result set.",
        evidence_cluster_ids=cluster_ids_for(clusters, {"keyword:password", "keyword:credential", "keyword:token"}),
    )
    add_hypothesis(
        hypotheses,
        key="web-ai-activity",
        condition=source_counts.get("web", 0) > 0 or any("ai" in str(match.get("preview", "")).lower() for match in matches),
        title="Browser or AI-service activity is relevant",
        rationale="Web/AI artifacts appear in search results and may explain user intent or research steps.",
        evidence_cluster_ids=cluster_ids_for(clusters, {"source:web", "kind:browser"}),
    )
    add_hypothesis(
        hypotheses,
        key="execution-or-persistence",
        condition=any(
            token in str(match.get("kind", "")).lower() or token in str(match.get("preview", "")).lower()
            for match in matches
            for token in ("prefetch", "powershell", "task", "service", "execution", "evtx")
        ),
        title="Execution, persistence, or log activity needs review",
        rationale="Execution/log artifacts appear in the result set; verify event IDs, parser confidence, and source hashes.",
        evidence_cluster_ids=cluster_ids_for(clusters, {"kind:windows-execution", "kind:eventlog", "source:timeline"}),
    )
    add_hypothesis(
        hypotheses,
        key="network-or-cloud",
        condition=entity_type_counts.get("domain", 0) > 0 or entity_type_counts.get("url", 0) > 0 or source_counts.get("indicators", 0) > 0,
        title="Network, cloud, or external-service pivot",
        rationale="URL/domain/IP entities or indicator rows are available for enrichment and timeline correlation.",
        evidence_cluster_ids=cluster_ids_for(clusters, {"source:indicators", "kind:cloud"}),
    )
    if not hypotheses:
        add_hypothesis(
            hypotheses,
            key="general-review",
            condition=True,
            title="General evidence review",
            rationale="No strong automated hypothesis was identified; start with largest clusters and earliest/latest timeline events.",
            evidence_cluster_ids=[str(cluster.get("cluster_id")) for cluster in clusters[:3]],
        )

    review_profile = build_workbook_review_profile(
        hypotheses=hypotheses,
        review_questions=[
            "Which cluster contains unique report-worthy evidence rather than repeated noise?",
            "Which entities connect multiple sources, users, or time ranges?",
            "Do timeline events support the analyst hypothesis in chronological order?",
            "Have source hashes and parser limitations been verified before report inclusion?",
        ],
    )
    citation_manifest = build_workbook_citation_manifest(hypotheses=hypotheses, clusters=clusters)
    validation_plan = build_workbook_report_grade_validation_plan(
        hypotheses=hypotheses,
        workbook_review_profile=review_profile,
        workbook_citation_manifest=citation_manifest,
    )
    return {
        "summary": {
            "hypothesis_count": len(hypotheses),
            "keyword_count": len([keyword for keyword in keywords if str(keyword).strip()]),
            "source_counts": dict(sorted(source_counts.items())),
            "review_queue_count": int(review_profile.get("review_queue_count") or 0),
            "evidence_attachment_count": int(review_profile.get("evidence_attachment_count") or 0),
            "hypothesis_citation_count": int(citation_manifest.get("hypothesis_citation_count") or 0),
            "evidence_cluster_ref_count": int(citation_manifest.get("evidence_cluster_ref_count") or 0),
            "workbook_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
            "workbook_report_grade_blocking_slot_count": int(validation_plan.get("blocking_slot_count") or 0),
            "commercial_gap_ids": ["#50"],
            "commercial_grade_ready": False,
        },
        "hypotheses": hypotheses,
        "workbook_review_profile": review_profile,
        "workbook_citation_manifest": citation_manifest,
        "workbook_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "workbook_report_grade_validation_plan": validation_plan,
        "workbook_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "report_grade_assessment": component_report_grade_assessment("#50", "hypothesis-workbook"),
        "review_questions": list(review_profile["review_questions"]),
        "next_actions": [
            "Open representative hits from the top clusters.",
            "Bookmark only verified source rows and mark review status.",
            "Use the entity list to pivot across files, web artifacts, logs, and cloud/mobile rows.",
            "Export report candidates only after source preview/hash verification.",
        ],
        "timeline_anchor_indices": [int(event["match_index"]) for event in timeline_events[:10] if isinstance(event.get("match_index"), int)],
    }


def build_workbook_review_profile(
    *,
    hypotheses: Sequence[Mapping[str, object]],
    review_questions: Sequence[str],
) -> dict[str, object]:
    review_queue = []
    evidence_attachment_count = 0
    for index, hypothesis in enumerate(hypotheses):
        evidence_ids = list(hypothesis.get("evidence_cluster_ids") or [])
        evidence_attachment_count += len(evidence_ids)
        review_queue.append(
            {
                "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
                "key": str(hypothesis.get("key") or ""),
                "title": str(hypothesis.get("title") or ""),
                "queue_position": index + 1,
                "review_status": str(hypothesis.get("status") or "draft"),
                "report_decision": "pending",
                "ready_for_report": bool(hypothesis.get("ready_for_report")),
                "evidence_cluster_ids": evidence_ids[:8],
                "evidence_count": len(evidence_ids),
                "required_actions": list(hypothesis.get("tasks") or [])[:8],
            }
        )
    return {
        "profile_version": "hypothesis-workbook-review-v1",
        "selected_track": "bounded-draft-hypothesis-review",
        "review_queue": review_queue,
        "review_queue_count": len(review_queue),
        "review_questions": list(review_questions),
        "review_question_count": len(review_questions),
        "evidence_attachment_count": evidence_attachment_count,
        "editable_workbook_supported": False,
        "persistent_workbook_supported": False,
        "version_history_supported": False,
        "report_section_export_supported": False,
        "commercial_release_blocked": True,
        "reporting_status": "workbook-validation-required",
        "required_before_report": [
            "persist analyst edits, notes, and hypothesis status in the Case DB",
            "attach verified source-row citations instead of only cluster IDs before report export",
            "preserve workbook version history and reviewer decisions for reproducibility",
        ],
    }


def build_workbook_citation_manifest(
    *,
    hypotheses: Sequence[Mapping[str, object]],
    clusters: Sequence[Mapping[str, object]],
    hypothesis_limit: int = 100,
) -> dict[str, object]:
    cluster_index = {str(cluster.get("cluster_id") or ""): cluster for cluster in clusters}
    hypothesis_entries: list[dict[str, object]] = []
    evidence_cluster_ref_count = 0
    for index, hypothesis in enumerate(hypotheses[:hypothesis_limit], start=1):
        cluster_refs = []
        for cluster_id in list(hypothesis.get("evidence_cluster_ids") or [])[:8]:
            cluster = cluster_index.get(str(cluster_id), {})
            cluster_refs.append(
                {
                    "cluster_id": str(cluster_id),
                    "family": str(cluster.get("family") or ""),
                    "value": str(cluster.get("value") or ""),
                    "match_count": int(cluster.get("match_count") or 0),
                    "source_viewer_locator": {
                        "viewer": "search-workbook-cluster-evidence",
                        "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
                        "cluster_id": str(cluster_id),
                    },
                }
            )
        evidence_cluster_ref_count += len(cluster_refs)
        entry_payload = {
            "entry_index": index,
            "hypothesis_id": str(hypothesis.get("hypothesis_id") or ""),
            "key": str(hypothesis.get("key") or ""),
            "title": str(hypothesis.get("title") or ""),
            "status": str(hypothesis.get("status") or "draft"),
            "ready_for_report": bool(hypothesis.get("ready_for_report")),
            "evidence_cluster_ref_count": len(cluster_refs),
        }
        hypothesis_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_analysis_sha256(entry_payload),
                "evidence_cluster_refs": cluster_refs,
                "source_viewer_locator": {
                    "viewer": "search-workbook-hypothesis-review",
                    "hypothesis_id": entry_payload["hypothesis_id"],
                    "open_requires_source_verification": True,
                },
                "required_report_actions": list(hypothesis.get("tasks") or [])[:8],
                "validation_status": "draft-hypothesis-validation-required",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "search-workbook-citation-manifest-v1",
        "item_number": 50,
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-hypothesis-evidence-citations",
        "hypothesis_citation_count": len(hypothesis_entries),
        "hypothesis_citation_cap": hypothesis_limit,
        "hypothesis_citations_truncated": len(hypotheses) > hypothesis_limit,
        "evidence_cluster_ref_count": evidence_cluster_ref_count,
        "hypothesis_entries": hypothesis_entries,
        "editable_workbook_supported": False,
        "persistent_workbook_supported": False,
        "version_history_supported": False,
        "report_section_export_supported": False,
        "passed_validation_check_ids": [
            "search-workbook-citation-manifest-emitted",
            "hypothesis-source-viewer-locators-built",
            "hypothesis-evidence-cluster-refs-built",
        ],
        "failed_validation_check_ids": [
            "editable-persistent-workbook",
            "evidence-attachment-workflow",
            "workbook-version-history",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[50],
        ],
        "commercial_blockers": [
            "editable-persistent-workbook",
            "evidence-attachment-workflow",
            "workbook-version-history",
            ANALYSIS_TRUSTED_DIFF_BLOCKERS[50],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_analysis_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_workbook_report_grade_validation_plan(
    *,
    hypotheses: Sequence[Mapping[str, object]],
    workbook_review_profile: Mapping[str, object],
    workbook_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    review_profile_hash = stable_analysis_sha256(workbook_review_profile)
    citation_manifest_hash = str(workbook_citation_manifest.get("manifest_sha256") or "")
    hypothesis_citation_count = int(workbook_citation_manifest.get("hypothesis_citation_count") or 0)
    evidence_cluster_ref_count = int(workbook_citation_manifest.get("evidence_cluster_ref_count") or 0)
    review_queue_count = int(workbook_review_profile.get("review_queue_count") or 0)
    review_question_count = int(workbook_review_profile.get("review_question_count") or 0)
    evidence_attachment_count = int(workbook_review_profile.get("evidence_attachment_count") or 0)

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "search-workbook-draft-hypotheses-generated",
            ready=bool(hypotheses),
            evidence=f"hypothesis_count={len(hypotheses)}",
            blocker_id="search-workbook-draft-hypotheses-required",
            operator_action="Run search analysis so draft hypotheses are generated from search pivots.",
        ),
        slot(
            "search-workbook-review-profile-emitted",
            ready=workbook_review_profile.get("profile_version") == "hypothesis-workbook-review-v1",
            evidence=f"workbook_review_profile_sha256={review_profile_hash}",
            blocker_id="search-workbook-review-profile-required",
            operator_action="Regenerate analysis so review queue and required actions are available.",
        ),
        slot(
            "search-workbook-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"workbook_citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="search-workbook-citation-manifest-required",
            operator_action="Generate the workbook citation manifest before using workbook output in a report.",
        ),
        slot(
            "search-workbook-hypothesis-source-viewer-locators",
            ready=hypothesis_citation_count > 0,
            evidence=f"hypothesis_citation_count={hypothesis_citation_count}",
            blocker_id="search-workbook-hypothesis-source-viewer-locators-required",
            operator_action="Attach source viewer locators for workbook hypothesis review.",
        ),
        slot(
            "search-workbook-evidence-cluster-refs",
            ready=evidence_cluster_ref_count > 0,
            evidence=f"evidence_cluster_ref_count={evidence_cluster_ref_count}",
            blocker_id="search-workbook-evidence-cluster-refs-required",
            operator_action="Attach evidence cluster references to draft hypotheses.",
        ),
        slot(
            "search-workbook-review-queue-and-questions",
            ready=review_queue_count > 0 and review_question_count > 0,
            evidence=(
                f"review_queue_count={review_queue_count} review_question_count={review_question_count} "
                f"evidence_attachment_count={evidence_attachment_count}"
            ),
            blocker_id="search-workbook-review-queue-required",
            operator_action="Emit review queue, analyst questions, and evidence counts for each hypothesis.",
        ),
        slot(
            "search-workbook-editable-persistent-workbook",
            ready=False,
            evidence="editable_workbook_supported=false persistent_workbook_supported=false",
            blocker_id="editable-persistent-workbook-required",
            operator_action="Persist analyst edits, status, notes, and workbook state in the Case DB.",
        ),
        slot(
            "search-workbook-source-row-evidence-attachment",
            ready=False,
            evidence="source_row_evidence_attachment_workflow=false",
            blocker_id="source-row-evidence-attachment-workflow-required",
            operator_action="Attach verified source-row citations instead of cluster references before report export.",
        ),
        slot(
            "search-workbook-reviewer-assignment-workflow",
            ready=False,
            evidence="reviewer_assignment_workflow=false",
            blocker_id="reviewer-assignment-workflow-required",
            operator_action="Persist reviewer assignments, decision state, and conflict-aware handoffs.",
        ),
        slot(
            "search-workbook-report-section-export",
            ready=False,
            evidence="report_section_export_supported=false",
            blocker_id="report-section-export-required",
            operator_action="Export reviewed workbook sections with source citations and limitation wording.",
        ),
        slot(
            "search-workbook-version-history",
            ready=False,
            evidence="version_history_supported=false",
            blocker_id="workbook-version-history-required",
            operator_action="Record version history and immutable reviewer decision changes.",
        ),
        slot(
            "search-workbook-trusted-rubric-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=ANALYSIS_TRUSTED_DIFF_BLOCKERS[50],
            operator_action="Attach a passing trusted workbook rubric diff before report use.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan: dict[str, object] = {
        "profile_version": WORKBOOK_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 50,
        "gap_id": "#50",
        "batch_id": "commercial-uplift-046-050",
        "selected_track": "bounded-draft-hypothesis-workbook-report-validation",
        "hypothesis_count": len(hypotheses),
        "review_queue_count": review_queue_count,
        "review_question_count": review_question_count,
        "evidence_attachment_count": evidence_attachment_count,
        "hypothesis_citation_count": hypothesis_citation_count,
        "evidence_cluster_ref_count": evidence_cluster_ref_count,
        "workbook_review_profile_sha256": review_profile_hash,
        "workbook_citation_manifest_sha256": citation_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(WORKBOOK_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage search <case> --query <keyword> --json",
            "rapidtriage cross-tool-validate --rapid-output search-results.json --reference-output <workbook-rubric-known-answer> --backlog-item 50 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 50 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-draft-hypothesis-review-workbook",
            "forbidden_claim": "analyst-reviewed finding or final report section",
            "required_disclaimer": (
                "Workbook hypotheses are draft review aids and require editable Case DB persistence, verified "
                "source-row evidence attachments, reviewer assignment state, report-section export, version "
                "history, and trusted rubric validation before report-grade finding claims."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_analysis_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def add_hypothesis(
    rows: list[dict[str, object]],
    *,
    key: str,
    condition: bool,
    title: str,
    rationale: str,
    evidence_cluster_ids: Sequence[str],
) -> None:
    if not condition:
        return
    rows.append(
        {
            "hypothesis_id": stable_id("hypothesis", key),
            "key": key,
            "title": title,
            "status": "draft",
            "rationale": rationale,
            "evidence_cluster_ids": list(evidence_cluster_ids)[:8],
            "tasks": [
                "Open representative source rows.",
                "Verify source hashes and parser warnings.",
                "Bookmark relevant rows with notes.",
                "Decide whether to include in the report.",
            ],
            "commercial_gap_ids": ["#50"],
            "ready_for_report": False,
        }
    )


def keyword_seen(keywords: Sequence[str], needles: set[str]) -> bool:
    return any(str(keyword).strip().lower() in needles for keyword in keywords)


def cluster_ids_for(clusters: Sequence[Mapping[str, object]], keys: set[str]) -> list[str]:
    rows = []
    for cluster in clusters:
        marker = f"{cluster.get('family')}:{cluster.get('value')}"
        if marker in keys:
            rows.append(str(cluster.get("cluster_id")))
    return rows


def stable_id(*parts: object) -> str:
    serialized = json.dumps([str(part) for part in parts], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def analysis_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "triage-only-validation-required",
        "commercial_gap_ids": ANALYSIS_GAP_IDS,
        "ready_for_court_report": False,
        "blockers": list(ANALYSIS_REPORT_GRADE_BLOCKERS),
        "recommended_validation": [
            "Validate clusters, entities, graph edges, and timeline anchors against source rows before report inclusion.",
            "Document analyst review decisions in the case workbook/bookmark workflow before treating hypotheses as findings.",
        ],
    }


def analysis_analyst_review_profile(
    *,
    matches: Sequence[Mapping[str, object]],
    clusters: Mapping[str, object],
    entities: Mapping[str, object],
    graph: Mapping[str, object],
    timeline: Mapping[str, object],
    workbook: Mapping[str, object],
    deduplication: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    cluster_summary = clusters.get("summary") if isinstance(clusters.get("summary"), Mapping) else {}
    entity_summary = entities.get("summary") if isinstance(entities.get("summary"), Mapping) else {}
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), Mapping) else {}
    timeline_summary = timeline.get("summary") if isinstance(timeline.get("summary"), Mapping) else {}
    workbook_summary = workbook.get("summary") if isinstance(workbook.get("summary"), Mapping) else {}
    dedup_summary = deduplication.get("summary") if isinstance(deduplication.get("summary"), Mapping) else {}
    dedup_validation_plan = (
        deduplication.get("search_dedup_report_grade_validation_plan")
        if isinstance(deduplication.get("search_dedup_report_grade_validation_plan"), Mapping)
        else {}
    )
    source_counts = Counter(str(match.get("source") or "unknown") for match in matches)
    top_sources = [
        {"source": source, "match_count": count}
        for source, count in source_counts.most_common(10)
    ]
    return {
        "profile_version": "analysis-analyst-review-profile-v1",
        "gap_ids": ANALYSIS_GAP_IDS,
        "artifact_type": "search-analysis-workbench",
        "severity": "high" if matches else "medium",
        "summary": (
            f"matches={len(matches)} clusters={cluster_summary.get('cluster_count', 0)} "
            f"entities={entity_summary.get('entity_count', 0)} "
            f"graph_edges={graph_summary.get('edge_count', 0)} "
            f"timeline_events={timeline_summary.get('event_count', 0)}"
        ),
        "evidence_interpretation": "Bounded search-derived clustering/entity/graph/timeline/workbook review routing",
        "not_proof_of": [
            "full-case reindex",
            "analyst-verified identity resolution",
            "causal relationship proof",
            "timezone or clock-skew validated timeline",
            "final investigative findings",
        ],
        "analyst_questions": [
            "Which clusters have enough representative hits to review first?",
            "Which entities need merge/split decisions before reporting?",
            "Which graph edges need source-row citation review?",
            "Which timeline anchors need timezone/skew and parser-confidence validation?",
            "Which workbook hypotheses should be converted to reviewed evidence items?",
        ],
        "primary_pivots": [
            f"top_source:{item['source']}={item['match_count']}"
            for item in top_sources[:5]
        ],
        "source_field_values": {
            "match_count": len(matches),
            "cluster_count": int(cluster_summary.get("cluster_count") or 0),
            "entity_count": int(entity_summary.get("entity_count") or 0),
            "graph_node_count": int(graph_summary.get("node_count") or 0),
            "graph_edge_count": int(graph_summary.get("edge_count") or 0),
            "timeline_event_count": int(timeline_summary.get("event_count") or 0),
            "workbook_hypothesis_count": int(workbook_summary.get("hypothesis_count") or 0),
            "duplicate_group_count": int(dedup_summary.get("duplicate_group_count") or 0),
            "dedup_report_grade_validation_plan_hash": str(
                dedup_validation_plan.get("validation_plan_sha256") or ""
            ),
            "dedup_report_grade_ready_slot_count": int(dedup_validation_plan.get("ready_slot_count") or 0),
            "dedup_report_grade_blocking_slot_count": int(dedup_validation_plan.get("blocking_slot_count") or 0),
            "top_sources": top_sources,
        },
        "review_entrypoints": [
            {"view": "clusters", "json_pointer": "/analysis/clusters/cluster_review_profile"},
            {"view": "entities", "json_pointer": "/analysis/entities/entity_review_profile"},
            {"view": "graph", "json_pointer": "/analysis/graph/graph_interaction_profile"},
            {"view": "timeline", "json_pointer": "/analysis/timeline/timeline_correlation_profile"},
            {"view": "workbook", "json_pointer": "/analysis/workbook/workbook_review_profile"},
            {"view": "deduplication", "json_pointer": "/analysis/deduplication/dedup_review_profile"},
        ],
        "correlation_targets": [
            "source viewer row verification",
            "case review marks and evidence tray",
            "entity merge/split workflow",
            "timeline timezone/clock-skew validation",
            "trusted analysis rubric diff",
        ],
        "risk_tags": ["analysis-validation-required", "bounded-search-result-derived"],
        "validation_required": True,
        "report_grade_ready": False,
        "commercial_blockers": list(report_grade.get("blockers", ANALYSIS_REPORT_GRADE_BLOCKERS)),
        "report_guidance": "Treat analysis output as a review-routing layer; report only source-verified rows with saved review decisions and citations.",
    }


def component_report_grade_assessment(gap_id: str, component: str) -> dict[str, object]:
    return {
        "component": component,
        "status": "triage-only-validation-required",
        "commercial_gap_ids": [gap_id],
        "ready_for_court_report": False,
        "blockers": list(ANALYSIS_REPORT_GRADE_BLOCKERS),
    }
