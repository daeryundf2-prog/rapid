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
}
ANALYSIS_TRUSTED_DIFF_CHECKS = {
    46: "trusted cluster review diff pass",
    47: "trusted entity review diff pass",
    48: "trusted graph source-citation diff pass",
    49: "trusted timeline known-answer diff pass",
    50: "trusted workbook rubric diff pass",
}
ANALYSIS_TRUSTED_TOOLS = {
    "hand-labeled-cluster-review",
    "analyst-entity-review",
    "graph-source-citation-review",
    "timeline-known-answer",
    "workbook-rubric-review",
    "case-db-review-export",
    "independent-review-export",
}
SEARCH_DEDUP_GAP_ID = "#60"


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
    deduplication = build_search_hit_deduplication(normalized_matches)
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
    entity_summary = entities.get("summary") if isinstance(entities.get("summary"), Mapping) else {}
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), Mapping) else {}
    timeline_summary = timeline.get("summary") if isinstance(timeline.get("summary"), Mapping) else {}
    workbook_summary = workbook.get("summary") if isinstance(workbook.get("summary"), Mapping) else {}
    trusted_diffs = trusted_diffs or {}
    trusted_diff_blockers = [
        blocker
        for number, blocker in ANALYSIS_TRUSTED_DIFF_BLOCKERS.items()
        if trusted_diffs.get(number, {}).get("status") != "pass"
    ]
    return {
        "batch_id": "commercial-uplift-046-050",
        "item_numbers": [46, 47, 48, 49, 50],
        "implementation_track": "search-analysis-ux-gates",
        "source_refs": [
            f"matches:{len(matches)}",
            f"clusters:{cluster_summary.get('cluster_count', 0)}",
            f"entities:{entity_summary.get('entity_count', 0)}",
            f"graph_edges:{graph_summary.get('edge_count', 0)}",
            f"timeline_events:{timeline_summary.get('event_count', 0)}",
            f"hypotheses:{workbook_summary.get('hypothesis_count', 0)}",
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
            "entity_truncated": bool(entity_summary.get("truncated")),
            "graph_truncated": bool(graph_summary.get("truncated")),
            "timeline_truncated": bool(timeline_summary.get("truncated")),
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
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers", []) if str(item)}
    for item_id, checks in failed_by_item.items():
        blockers.update(f"{item_id}:{check}" for check in checks)
    if not ANALYSIS_NATIVE_CAPABILITIES["full_case_reindex"]:
        blockers.add("full-case-reindex-not-available")
    if not ANALYSIS_NATIVE_CAPABILITIES["analyst_verified_entity_resolution"]:
        blockers.add("analyst-verified-entity-resolution-not-available")
    trusted_diffs = trusted_diffs or {}
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
    entity_summary = entities.get("summary") if isinstance(entities.get("summary"), Mapping) else {}
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), Mapping) else {}
    timeline_summary = timeline.get("summary") if isinstance(timeline.get("summary"), Mapping) else {}
    workbook_summary = workbook.get("summary") if isinstance(workbook.get("summary"), Mapping) else {}
    cluster_rows = clusters.get("clusters") if isinstance(clusters.get("clusters"), list) else []
    entity_rows = entities.get("entities") if isinstance(entities.get("entities"), list) else []
    graph_nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    graph_edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    timeline_events = timeline.get("events") if isinstance(timeline.get("events"), list) else []
    hypotheses = workbook.get("hypotheses") if isinstance(workbook.get("hypotheses"), list) else []
    dedup_summary = deduplication.get("summary") if isinstance(deduplication.get("summary"), Mapping) else {}
    duplicate_groups = deduplication.get("groups") if isinstance(deduplication.get("groups"), list) else []
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
    return {
        "summary": {
            "cluster_count": len(clusters),
            "candidate_bucket_count": len(buckets),
            "max_clusters": max_clusters,
            "truncated": len(clusters) >= max_clusters and len(buckets) > max_clusters,
            "commercial_gap_ids": ["#46"],
            "commercial_grade_ready": False,
        },
        "clusters": clusters,
        "report_grade_assessment": component_report_grade_assessment("#46", "large-result-clustering"),
    }


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


def stable_diff_key(*parts: object) -> str:
    text = "|".join(diff_value(part) for part in parts if diff_value(part))
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def diff_value(value: object) -> str:
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(diff_value(item) for item in value if diff_value(item)))
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def build_search_hit_deduplication(matches: Sequence[Mapping[str, object]], *, max_groups: int = 25) -> dict[str, object]:
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
                "truncated_match_indices": len(indices) > 20,
                "sources": sorted({str(item.get("source") or "unknown") for item in sample}),
                "paths": sorted({str(item.get("path") or "") for item in sample if item.get("path")})[:8],
                "representative_preview": str(sample[0].get("preview") or "")[:240] if sample else "",
                "review_action": "review-representative-hit-first",
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
    core_accuracy_gates = search_deduplication_core_accuracy_gates(groups=groups, summary=summary)
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
        "deduplication_assessment": search_deduplication_assessment(),
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": search_deduplication_commercial_uplift_evidence(
            groups=groups,
            summary=summary,
            core_accuracy_gates=core_accuracy_gates,
        ),
    }


def search_deduplication_core_accuracy_gates(
    *,
    groups: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
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
    satisfied.append("near-duplicate limitation warning")
    return [
        build_accuracy_gate(
            60,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"duplicate_group_count:{summary.get('duplicate_group_count', 0)}",
                f"duplicate_match_count:{summary.get('duplicate_match_count', 0)}",
                f"unique_fingerprint_count:{summary.get('unique_fingerprint_count', 0)}",
            ],
        )
    ]


def search_deduplication_commercial_uplift_evidence(
    *,
    groups: Sequence[Mapping[str, object]],
    summary: Mapping[str, object],
    core_accuracy_gates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    passed = []
    for gate in core_accuracy_gates:
        if gate.get("gap_id") == SEARCH_DEDUP_GAP_ID:
            passed.extend(str(item) for item in gate.get("satisfied_checks") or [])
    assessment = search_deduplication_assessment()
    return {
        "batch_id": "commercial-uplift-056-060",
        "item_numbers": [60],
        "implementation_track": "search-hit-deduplication-gate",
        "source_refs": [
            f"duplicate_group_count:{summary.get('duplicate_group_count', 0)}",
            f"duplicate_match_count:{summary.get('duplicate_match_count', 0)}",
            f"unique_fingerprint_count:{summary.get('unique_fingerprint_count', 0)}",
        ],
        "reportability_decision": search_deduplication_reportability_decision(
            failed_validation_check_ids=[
                "ui-collapse-suppression-workflow",
                "fuzzy-near-duplicate-text-grouping",
                "perceptual-media-duplicate-grouping",
                "case-db-duplicate-suppression-state",
            ],
            assessment_blockers=list(assessment["blockers"]),
            summary=summary,
        ),
        "passed_validation_check_ids": sorted(set(passed)),
        "failed_validation_check_ids": [
            "ui-collapse-suppression-workflow",
            "fuzzy-near-duplicate-text-grouping",
            "perceptual-media-duplicate-grouping",
            "case-db-duplicate-suppression-state",
        ],
        "commercial_blockers": list(assessment["blockers"]),
        "large_data_controls": {
            "max_groups": int(summary.get("max_groups") or 0),
            "group_count": len(groups),
            "duplicate_match_count": int(summary.get("duplicate_match_count") or 0),
            "representative_first_review": True,
            "hash_or_preview_fingerprint": True,
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
) -> dict[str, object]:
    blockers = {str(item) for item in assessment_blockers if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    return {
        "profile_version": "search-deduplication-reportability-decision-v1",
        "commercial_gap_ids": [SEARCH_DEDUP_GAP_ID],
        "decision": "do-not-report-duplicate-groups-as-suppressed-or-content-complete",
        "allowed_use": "duplicate-hit-triage-pivot",
        "blockers": sorted(blockers),
        "duplicate_group_count": int(summary.get("duplicate_group_count") or 0),
        "duplicate_match_count": int(summary.get("duplicate_match_count") or 0),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate exact, fuzzy text, perceptual image/video, and OCR duplicate groups against a large known-answer corpus",
            "persist analyst suppression decisions in Case DB before hiding or excluding duplicates",
            "verify representative source rows and hashes before using duplicates in reports",
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
    return {
        "summary": {
            "entity_count": len(entities),
            "type_counts": dict(sorted(type_counts.items())),
            "max_entities": max_entities,
            "truncated": len(buckets) > len(entities),
            "commercial_gap_ids": ["#47"],
            "commercial_grade_ready": False,
        },
        "entities": entities,
        "report_grade_assessment": component_report_grade_assessment("#47", "entity-view"),
    }


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
            edges.append({"source": match_id, "target": path_id, "type": "located-at"})
        for keyword in match.get("matched_keywords", []):
            keyword_id = stable_id("keyword", keyword)
            nodes.setdefault(keyword_id, {"id": keyword_id, "type": "keyword", "label": str(keyword)})
            edges.append({"source": match_id, "target": keyword_id, "type": "matched-keyword"})
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
            edges.append({"source": match_id, "target": entity_id, "type": "mentions"})
        if len(edges) >= max_edges:
            edges = edges[:max_edges]
            break

    return {
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "max_match_nodes": MAX_GRAPH_MATCH_NODES,
            "max_edges": max_edges,
            "truncated": len(matches) > MAX_GRAPH_MATCH_NODES or len(edges) >= max_edges,
            "commercial_gap_ids": ["#48"],
            "commercial_grade_ready": False,
        },
        "nodes": list(nodes.values()),
        "edges": edges,
        "report_grade_assessment": component_report_grade_assessment("#48", "relationship-graph"),
    }


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
    truncated = len(events) > max_events
    events = events[:max_events]
    buckets = Counter(str(event["timestamp"])[:10] for event in events if str(event.get("timestamp")))
    return {
        "summary": {
            "event_count": len(events),
            "date_bucket_count": len(buckets),
            "earliest_event_at": events[0]["timestamp"] if events else None,
            "latest_event_at": events[-1]["timestamp"] if events else None,
            "truncated": truncated,
            "commercial_gap_ids": ["#49"],
            "commercial_grade_ready": False,
        },
        "date_buckets": [{"date": date, "count": count} for date, count in sorted(buckets.items())],
        "events": events,
        "report_grade_assessment": component_report_grade_assessment("#49", "correlated-timeline"),
    }


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

    return {
        "summary": {
            "hypothesis_count": len(hypotheses),
            "keyword_count": len([keyword for keyword in keywords if str(keyword).strip()]),
            "source_counts": dict(sorted(source_counts.items())),
            "commercial_gap_ids": ["#50"],
            "commercial_grade_ready": False,
        },
        "hypotheses": hypotheses,
        "report_grade_assessment": component_report_grade_assessment("#50", "hypothesis-workbook"),
        "review_questions": [
            "Which cluster contains unique report-worthy evidence rather than repeated noise?",
            "Which entities connect multiple sources, users, or time ranges?",
            "Do timeline events support the analyst hypothesis in chronological order?",
            "Have source hashes and parser limitations been verified before report inclusion?",
        ],
        "next_actions": [
            "Open representative hits from the top clusters.",
            "Bookmark only verified source rows and mark review status.",
            "Use the entity list to pivot across files, web artifacts, logs, and cloud/mobile rows.",
            "Export report candidates only after source preview/hash verification.",
        ],
        "timeline_anchor_indices": [int(event["match_index"]) for event in timeline_events[:10] if isinstance(event.get("match_index"), int)],
    }


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


def component_report_grade_assessment(gap_id: str, component: str) -> dict[str, object]:
    return {
        "component": component,
        "status": "triage-only-validation-required",
        "commercial_gap_ids": [gap_id],
        "ready_for_court_report": False,
        "blockers": list(ANALYSIS_REPORT_GRADE_BLOCKERS),
    }
