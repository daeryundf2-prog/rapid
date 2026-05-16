from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from rapidtriage.core.analysis import build_analysis_trusted_diff, build_search_analysis
from rapidtriage.core.keyword_packs import resolve_keyword_packs
from rapidtriage.core.search import build_advanced_search_trusted_diff, filter_matches, run_unified_search, search_core_accuracy_gates, search_docs
from rapidtriage.core.search_backend import (
    build_external_search_adapter_contract,
    build_search_backend_contract,
    build_synthetic_benchmark_generator_manifest,
    build_ui_virtualization_contract,
    build_uniform_cursor_pagination_contract,
)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class RapidTriageSearchAnalysisTests(unittest.TestCase):
    def make_matches(self) -> list[dict[str, object]]:
        return [
            {
                "source": "documents",
                "kind": "txt",
                "path": "/cases/CASE-1/notes/passwords.txt",
                "title": "passwords.txt",
                "matched_keywords": ["password"],
                "preview": "alice@example.com reset password at https://example.com/reset",
                "pointer": "/results/0",
                "metadata": {
                    "modified_at": "2026-04-25T01:02:03+00:00",
                    "details": {"user": "alice", "contact_name": "Alice Example"},
                },
            },
            {
                "source": "web",
                "kind": "browser",
                "path": "/cases/CASE-1/Chrome/History",
                "title": "Chrome visit",
                "matched_keywords": ["password"],
                "preview": "Visited https://example.com/reset from 203.0.113.10",
                "pointer": "/artifacts/0",
                "metadata": {"details": {"visited_at": "2026-04-25T01:05:00+00:00"}},
            },
            {
                "source": "web",
                "kind": "browser",
                "path": "/cases/CASE-1/Chrome/History",
                "title": "Chrome visit",
                "matched_keywords": ["password"],
                "preview": "Visited https://example.com/reset from 203.0.113.10",
                "pointer": "/artifacts/1",
                "metadata": {"details": {"visited_at": "2026-04-25T01:05:00+00:00"}},
            },
            {
                "source": "timeline",
                "kind": "eventlog-security",
                "path": "/cases/CASE-1/Security.evtx",
                "title": "PowerShell command",
                "matched_keywords": ["powershell"],
                "preview": "PowerShell contacted https://evil.example.xyz/a",
                "pointer": "/events/0",
                "metadata": {"timestamp": "2026-04-25T01:10:00+00:00"},
            },
        ]

    def test_search_docs_surfaces_document_extraction_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_path = root / "rapidtriage-docs.json"
            evidence_path = root / "broken.pdf"
            write_json(
                docs_path,
                {
                    "candidates": [{"path": str(evidence_path), "kind": "pdf"}],
                    "results": [{"path": str(evidence_path)}],
                },
            )

            with patch("rapidtriage.core.search.extract_text", side_effect=OSError("cannot read pdf")):
                matches, errors = search_docs({"docs": str(docs_path)}, ["secret"], limit=10)

            self.assertEqual(matches, [])
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["path"], str(evidence_path))
            self.assertEqual(errors[0]["kind"], "pdf")
            self.assertIn("OSError: cannot read pdf", errors[0]["error"])

    def test_search_docs_uses_recorded_extraction_errors_as_partial_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_path = root / "rapidtriage-docs.json"
            skipped_path = root / "huge.mbox"
            searchable_path = root / "notes.txt"
            searchable_path.write_text("secret remains searchable after skipped mailbox", encoding="utf-8")
            write_json(
                docs_path,
                {
                    "candidates": [
                        {"path": str(skipped_path), "kind": "mbox"},
                        {"path": str(searchable_path), "kind": "txt"},
                    ],
                    "results": [{"path": str(searchable_path)}],
                    "extraction_errors": [
                        {
                            "path": str(skipped_path),
                            "kind": "mbox",
                            "size": 9000000000,
                            "reason": "input-too-large",
                            "error_type": "TextExtractionTooLarge",
                            "message": "document extraction input is capped",
                            "recoverable": True,
                            "effect": "document-skipped-search-continues",
                        }
                    ],
                },
            )

            matches, errors = search_docs({"docs": str(docs_path)}, ["secret"], limit=10)

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["path"], str(searchable_path))
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["path"], str(skipped_path))
            self.assertEqual(errors[0]["reason"], "input-too-large")
            self.assertEqual(errors[0]["effect"], "document-skipped-search-continues")

    def test_filter_matches_fast_path_preserves_copy_semantics(self) -> None:
        matches = self.make_matches()

        filtered = filter_matches(matches, sources=set(), extensions=set(), path_fragment="")

        self.assertEqual(filtered, matches)
        self.assertIsNot(filtered[0], matches[0])

    def test_filter_matches_combines_source_extension_and_path_filters(self) -> None:
        matches = self.make_matches()

        filtered = filter_matches(matches, sources={"documents"}, extensions={".txt"}, path_fragment="notes")

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["source"], "documents")
        self.assertEqual(filtered[0]["path"], "/cases/CASE-1/notes/passwords.txt")

    def test_filter_matches_path_fragment_is_case_insensitive(self) -> None:
        matches = self.make_matches()

        filtered = filter_matches(matches, sources=set(), extensions=set(), path_fragment="security.evtx")

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["source"], "timeline")

    def test_run_unified_search_reports_document_error_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_path = root / "rapidtriage-docs.json"
            summary_path = root / "summary.json"
            evidence_path = root / "broken.docx"
            write_json(
                docs_path,
                {
                    "candidates": [{"path": str(evidence_path), "kind": "docx"}],
                    "results": [{"path": str(evidence_path)}],
                },
            )
            write_json(summary_path, {"outputs": {"summary": str(summary_path), "docs": str(docs_path)}})

            with patch("rapidtriage.core.search.extract_text", side_effect=ValueError("corrupt document")):
                payload = run_unified_search(summary_path, ["secret"], include_analysis=False)

            self.assertEqual(payload["summary"]["document_error_count"], 1)
            self.assertEqual(payload["documents"]["errors"][0]["kind"], "docx")
            self.assertIn("ValueError: corrupt document", payload["documents"]["errors"][0]["error"])

    def test_run_unified_search_reports_recorded_document_extraction_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_path = root / "rapidtriage-docs.json"
            summary_path = root / "summary.json"
            skipped_path = root / "huge.pdf"
            write_json(
                docs_path,
                {
                    "candidates": [{"path": str(skipped_path), "kind": "pdf"}],
                    "results": [],
                    "extraction_errors": [
                        {
                            "path": str(skipped_path),
                            "kind": "pdf",
                            "size": 7000000000,
                            "reason": "input-too-large",
                            "error_type": "TextExtractionTooLarge",
                            "message": "document extraction input is capped",
                            "recoverable": True,
                            "effect": "document-skipped-search-continues",
                        }
                    ],
                },
            )
            write_json(summary_path, {"outputs": {"summary": str(summary_path), "docs": str(docs_path)}})

            payload = run_unified_search(summary_path, ["secret"], include_analysis=False)

            self.assertEqual(payload["summary"]["match_count"], 0)
            self.assertEqual(payload["summary"]["document_error_count"], 1)
            self.assertEqual(payload["documents"]["errors"][0]["reason"], "input-too-large")
            self.assertEqual(payload["documents"]["errors"][0]["effect"], "document-skipped-search-continues")

    def test_build_search_analysis_adds_clusters_entities_graph_timeline_and_workbook(self) -> None:
        analysis = build_search_analysis(self.make_matches(), ["password", "powershell"])

        self.assertGreaterEqual(analysis["summary"]["cluster_count"], 1)
        self.assertGreaterEqual(analysis["summary"]["entity_count"], 3)
        self.assertGreaterEqual(analysis["summary"]["graph_node_count"], 1)
        self.assertEqual(analysis["summary"]["timeline_event_count"], 4)
        self.assertGreaterEqual(analysis["summary"]["workbook_hypothesis_count"], 2)
        self.assertEqual(analysis["summary"]["duplicate_group_count"], 1)
        self.assertEqual(analysis["summary"]["commercial_gap_ids"], ["#46", "#47", "#48", "#49", "#50", "#60"])
        self.assertFalse(analysis["analysis_native_capabilities"]["full_case_reindex"])
        self.assertTrue(analysis["analysis_native_capabilities"]["search_hit_deduplication"])
        self.assertIn("#46", analysis["analysis_report_grade_assessment"]["commercial_gap_ids"])
        analysis_review = analysis["analysis_analyst_review_profile"]
        self.assertEqual(analysis_review["profile_version"], "analysis-analyst-review-profile-v1")
        self.assertEqual(analysis_review["gap_ids"], ["#46", "#47", "#48", "#49", "#50", "#60"])
        self.assertEqual(analysis_review["artifact_type"], "search-analysis-workbench")
        self.assertIn("source viewer row verification", analysis_review["correlation_targets"])
        self.assertIn("full-case reindex", analysis_review["not_proof_of"])
        self.assertFalse(analysis_review["report_grade_ready"])
        analysis_gates = {gate["gap_id"]: gate for gate in analysis["core_accuracy_gates"]}
        self.assertIn("bounded cluster generation", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("representative match links", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("cluster review profile", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("representative-first review queue", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("cluster citation manifest", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("representative source viewer locators", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("cluster report-grade validation plan", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("cluster report-grade ready slots", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("entity extraction across supported types", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("match reference links", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("entity review profile", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("entity citation manifest", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("entity source viewer locators", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("hash-only entity citation values", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("entity report-grade validation plan", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("entity report-grade ready slots", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("merge/split review queue", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("relationship edges built", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("causal-proof limitation warning", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("edge source citations", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("graph interaction profile", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("filter metadata", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("graph citation manifest", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("edge source viewer locators", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("graph source locator coverage", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("graph report-grade validation plan", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("graph report-grade ready slots", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("timestamp extraction", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("UTC normalization", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("timeline correlation profile", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("cursor page metadata", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("timezone distribution", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("timeline citation manifest", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("timeline event source viewer locators", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("clock-skew blocker recorded", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("draft hypotheses generated", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("workbook review profile", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("hypothesis review queue", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("workbook citation manifest", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("hypothesis citation source locators", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("workbook version-history blocker", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("persistence/versioning limitation warning", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("duplicate fingerprint generation", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("duplicate group counts", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("collapse preview profile", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("dedup citation manifest", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("duplicate member row hashes", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("dedup source viewer locators", analysis_gates["#60"]["satisfied_checks"])
        analysis_uplift = analysis["commercial_uplift_evidence"]
        self.assertEqual(analysis_uplift["batch_id"], "commercial-uplift-046-050")
        self.assertEqual(analysis_uplift["item_numbers"], [46, 47, 48, 49, 50])
        self.assertIn("bounded cluster generation", analysis_uplift["passed_validation_check_ids_by_item"]["#46"])
        self.assertIn("cluster review profile", analysis_uplift["passed_validation_check_ids_by_item"]["#46"])
        self.assertIn("cluster report-grade validation plan", analysis_uplift["passed_validation_check_ids_by_item"]["#46"])
        self.assertIn("cluster report-grade ready slots", analysis_uplift["passed_validation_check_ids_by_item"]["#46"])
        self.assertIn("entity extraction across supported types", analysis_uplift["passed_validation_check_ids_by_item"]["#47"])
        self.assertIn("entity review profile", analysis_uplift["passed_validation_check_ids_by_item"]["#47"])
        self.assertIn("entity report-grade validation plan", analysis_uplift["passed_validation_check_ids_by_item"]["#47"])
        self.assertIn("entity report-grade ready slots", analysis_uplift["passed_validation_check_ids_by_item"]["#47"])
        self.assertIn("relationship edges built", analysis_uplift["passed_validation_check_ids_by_item"]["#48"])
        self.assertIn("edge source citations", analysis_uplift["passed_validation_check_ids_by_item"]["#48"])
        self.assertIn("graph report-grade validation plan", analysis_uplift["passed_validation_check_ids_by_item"]["#48"])
        self.assertIn("graph report-grade ready slots", analysis_uplift["passed_validation_check_ids_by_item"]["#48"])
        self.assertIn("timestamp extraction", analysis_uplift["passed_validation_check_ids_by_item"]["#49"])
        self.assertIn("timeline correlation profile", analysis_uplift["passed_validation_check_ids_by_item"]["#49"])
        self.assertIn("draft hypotheses generated", analysis_uplift["passed_validation_check_ids_by_item"]["#50"])
        self.assertIn("workbook review profile", analysis_uplift["passed_validation_check_ids_by_item"]["#50"])
        self.assertIn("persistent-cluster-review-state", analysis_uplift["failed_validation_check_ids_by_item"]["#46"])
        self.assertEqual(
            analysis_uplift["reportability_decision"]["decision"],
            "do-not-report-search-analysis-as-reviewed-findings",
        )
        self.assertEqual(
            analysis_uplift["reportability_decision"]["allowed_use"],
            "bounded-search-analysis-triage-pivot",
        )
        self.assertIn(
            "#48:server-side-graph-paging",
            analysis_uplift["reportability_decision"]["blockers"],
        )
        self.assertIn(
            "full-case-reindex-not-available",
            analysis_uplift["reportability_decision"]["blockers"],
        )
        self.assertEqual(analysis_uplift["reportability_decision"]["review_output_counts"]["hypotheses"], 4)
        self.assertTrue(analysis_uplift["reportability_decision"]["cluster_report_grade_validation_plan_present"])
        self.assertTrue(analysis_uplift["reportability_decision"]["entity_report_grade_validation_plan_present"])
        self.assertTrue(analysis_uplift["reportability_decision"]["graph_report_grade_validation_plan_present"])
        self.assertFalse(analysis_uplift["large_data_controls"]["persistent_review_state"])
        self.assertFalse(analysis_uplift["large_data_controls"]["full_case_reindex"])
        self.assertTrue(analysis_uplift["large_data_controls"]["cluster_review_profile_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["cluster_citation_manifest_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["cluster_report_grade_validation_plan_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["cluster_citation_entry_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["cluster_representative_citation_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["cluster_review_queue_count"], 1)
        self.assertTrue(analysis_uplift["large_data_controls"]["representative_first_cluster_review"])
        self.assertTrue(analysis_uplift["large_data_controls"]["entity_review_profile_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["entity_citation_manifest_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["entity_report_grade_validation_plan_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["entity_citation_entry_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["entity_match_citation_count"], 1)
        self.assertEqual(analysis_uplift["large_data_controls"]["entity_report_grade_ready_slot_count"], 6)
        self.assertEqual(analysis_uplift["large_data_controls"]["entity_report_grade_blocking_slot_count"], 6)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["entity_review_queue_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["merge_split_candidate_count"], 1)
        self.assertFalse(analysis_uplift["large_data_controls"]["analyst_verified_entity_resolution"])
        self.assertFalse(analysis_uplift["large_data_controls"]["persistent_entity_review_state"])
        self.assertTrue(analysis_uplift["large_data_controls"]["graph_interaction_profile_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["graph_citation_manifest_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["graph_report_grade_validation_plan_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["graph_citation_edge_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["graph_source_viewer_locator_count"], 1)
        self.assertEqual(analysis_uplift["large_data_controls"]["graph_report_grade_ready_slot_count"], 6)
        self.assertEqual(analysis_uplift["large_data_controls"]["graph_report_grade_blocking_slot_count"], 6)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["graph_filter_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["graph_edge_page_count"], 1)
        self.assertFalse(analysis_uplift["large_data_controls"]["graph_saved_layout_supported"])
        self.assertTrue(analysis_uplift["large_data_controls"]["timeline_correlation_profile_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["timeline_citation_manifest_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["timeline_event_citation_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["timeline_source_viewer_locator_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["timeline_event_page_count"], 1)
        self.assertEqual(analysis_uplift["large_data_controls"]["timeline_missing_timezone_count"], 0)
        self.assertFalse(analysis_uplift["large_data_controls"]["timeline_clock_skew_overlay_supported"])
        self.assertTrue(analysis_uplift["large_data_controls"]["workbook_review_profile_present"])
        self.assertTrue(analysis_uplift["large_data_controls"]["workbook_citation_manifest_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["workbook_hypothesis_citation_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["workbook_evidence_cluster_ref_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["workbook_review_queue_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["workbook_evidence_attachment_count"], 1)
        self.assertFalse(analysis_uplift["large_data_controls"]["workbook_version_history_supported"])
        self.assertIn(
            "cluster-review-trusted-diff-required",
            analysis_uplift["reportability_decision"]["blockers"],
        )

        clusters = analysis["clusters"]["clusters"]
        self.assertTrue(any(cluster["family"] == "keyword" and cluster["value"] == "password" for cluster in clusters))
        self.assertIn("#46", analysis["clusters"]["summary"]["commercial_gap_ids"])
        cluster_review = analysis["clusters"]["cluster_review_profile"]
        self.assertEqual(cluster_review["profile_version"], "large-result-cluster-review-v1")
        self.assertGreaterEqual(cluster_review["review_queue_count"], 1)
        self.assertTrue(cluster_review["representative_first_review"])
        self.assertFalse(cluster_review["persistent_review_state"])
        self.assertFalse(cluster_review["near_duplicate_text_media_clustering"])
        self.assertTrue(cluster_review["commercial_release_blocked"])
        self.assertEqual(cluster_review["review_queue"][0]["review_status"], "unreviewed")
        self.assertEqual(cluster_review["review_queue"][0]["review_decision"], "pending")
        cluster_manifest = analysis["clusters"]["cluster_citation_manifest"]
        self.assertEqual(cluster_manifest["manifest_version"], "search-cluster-citation-manifest-v1")
        self.assertEqual(cluster_manifest["item_number"], 46)
        self.assertEqual(analysis["clusters"]["cluster_citation_manifest_hash"], cluster_manifest["manifest_sha256"])
        self.assertGreaterEqual(cluster_manifest["cluster_entry_count"], 1)
        self.assertGreaterEqual(cluster_manifest["representative_citation_count"], 1)
        self.assertIn(
            "search-cluster-citation-manifest-emitted",
            cluster_manifest["passed_validation_check_ids"],
        )
        self.assertEqual(
            cluster_manifest["cluster_entries"][0]["source_viewer_locator"]["viewer"],
            "search-cluster-review",
        )
        self.assertEqual(
            cluster_manifest["cluster_entries"][0]["representative_citations"][0]["source_viewer_locator"]["viewer"],
            "search-result-source",
        )
        cluster_plan = analysis["clusters"]["cluster_report_grade_validation_plan"]
        self.assertEqual(cluster_plan["profile_version"], "search-cluster-report-grade-validation-plan-v1")
        self.assertEqual(cluster_plan["item_number"], 46)
        self.assertEqual(cluster_plan["gap_id"], "#46")
        self.assertEqual(
            analysis["clusters"]["cluster_report_grade_validation_plan_hash"],
            cluster_plan["validation_plan_sha256"],
        )
        self.assertEqual(cluster_plan["cluster_citation_manifest_sha256"], cluster_manifest["manifest_sha256"])
        self.assertGreaterEqual(cluster_plan["cluster_count"], 1)
        self.assertGreaterEqual(cluster_plan["representative_citation_count"], 1)
        self.assertEqual(cluster_plan["ready_slot_count"], 6)
        self.assertEqual(cluster_plan["blocking_slot_count"], 6)
        self.assertEqual(cluster_plan["validation_status"], "report-validation-blocked")
        self.assertFalse(cluster_plan["commercial_grade"])
        cluster_slots = {slot["slot_id"]: slot for slot in cluster_plan["validation_slots"]}
        self.assertEqual(cluster_slots["search-cluster-bounded-generation"]["status"], "complete")
        self.assertEqual(cluster_slots["search-cluster-review-profile-emitted"]["status"], "complete")
        self.assertEqual(cluster_slots["search-cluster-citation-manifest-emitted"]["status"], "complete")
        self.assertEqual(cluster_slots["search-cluster-representative-source-viewer-locators"]["status"], "complete")
        self.assertEqual(cluster_slots["search-cluster-truncation-controls"]["status"], "complete")
        self.assertEqual(cluster_slots["search-cluster-representative-first-review"]["status"], "complete")
        self.assertEqual(cluster_slots["search-cluster-persistent-review-state"]["status"], "external-required")
        self.assertEqual(cluster_slots["search-cluster-trusted-review-diff"]["status"], "external-required")
        self.assertIn("persistent-cluster-review-state-required", cluster_plan["blockers"])
        self.assertIn("cluster-review-trusted-diff-required", cluster_plan["blockers"])
        self.assertEqual(
            analysis_uplift["large_data_controls"]["cluster_report_grade_validation_plan_hash"],
            cluster_plan["validation_plan_sha256"],
        )
        self.assertEqual(analysis_uplift["large_data_controls"]["cluster_report_grade_ready_slot_count"], 6)
        self.assertEqual(analysis_uplift["large_data_controls"]["cluster_report_grade_blocking_slot_count"], 6)
        self.assertEqual(
            analysis_uplift["reportability_decision"]["cluster_report_grade_validation_plan_hash"],
            cluster_plan["validation_plan_sha256"],
        )

        entities = analysis["entities"]["entities"]
        entity_values = {entity["value"] for entity in entities}
        self.assertIn("alice@example.com", entity_values)
        self.assertIn("alice", entity_values)
        self.assertIn("Alice Example", entity_values)
        self.assertIn("example.com", entity_values)
        self.assertIn("evil.example.xyz", entity_values)
        entity_types = {entity["type"] for entity in entities}
        self.assertIn("account", entity_types)
        self.assertIn("person", entity_types)
        self.assertIn("#47", analysis["entities"]["summary"]["commercial_gap_ids"])
        entity_review = analysis["entities"]["entity_review_profile"]
        self.assertEqual(entity_review["profile_version"], "entity-review-profile-v1")
        self.assertGreaterEqual(entity_review["review_queue_count"], 1)
        self.assertGreaterEqual(entity_review["merge_split_candidate_count"], 1)
        self.assertFalse(entity_review["analyst_verified_entity_resolution"])
        self.assertFalse(entity_review["persistent_entity_review_state"])
        self.assertTrue(entity_review["commercial_release_blocked"])
        self.assertEqual(entity_review["review_queue"][0]["review_status"], "unreviewed")
        self.assertEqual(entity_review["review_queue"][0]["review_decision"], "pending")
        entity_manifest = analysis["entities"]["entity_citation_manifest"]
        self.assertEqual(entity_manifest["manifest_version"], "search-entity-citation-manifest-v1")
        self.assertEqual(entity_manifest["item_number"], 47)
        self.assertEqual(analysis["entities"]["entity_citation_manifest_hash"], entity_manifest["manifest_sha256"])
        self.assertGreaterEqual(entity_manifest["entity_entry_count"], 1)
        self.assertGreaterEqual(entity_manifest["match_citation_count"], 1)
        self.assertFalse(entity_manifest["raw_entity_values_serialized"])
        self.assertIn(
            "search-entity-citation-manifest-emitted",
            entity_manifest["passed_validation_check_ids"],
        )
        self.assertEqual(
            entity_manifest["entity_entries"][0]["source_viewer_locator"]["viewer"],
            "search-entity-review",
        )
        self.assertEqual(
            entity_manifest["entity_entries"][0]["match_citations"][0]["source_viewer_locator"]["viewer"],
            "search-entity-source",
        )
        entity_plan = analysis["entities"]["entity_report_grade_validation_plan"]
        self.assertEqual(entity_plan["profile_version"], "search-entity-report-grade-validation-plan-v1")
        self.assertEqual(entity_plan["item_number"], 47)
        self.assertEqual(entity_plan["gap_id"], "#47")
        self.assertEqual(
            analysis["entities"]["entity_report_grade_validation_plan_hash"],
            entity_plan["validation_plan_sha256"],
        )
        self.assertEqual(entity_plan["entity_citation_manifest_sha256"], entity_manifest["manifest_sha256"])
        self.assertGreaterEqual(entity_plan["entity_count"], 1)
        self.assertGreaterEqual(entity_plan["match_citation_count"], 1)
        self.assertEqual(entity_plan["ready_slot_count"], 6)
        self.assertEqual(entity_plan["blocking_slot_count"], 6)
        self.assertEqual(entity_plan["validation_status"], "report-validation-blocked")
        self.assertFalse(entity_plan["commercial_grade"])
        entity_slots = {slot["slot_id"]: slot for slot in entity_plan["validation_slots"]}
        self.assertEqual(entity_slots["search-entity-pattern-and-structured-extraction"]["status"], "complete")
        self.assertEqual(entity_slots["search-entity-review-profile-emitted"]["status"], "complete")
        self.assertEqual(entity_slots["search-entity-citation-manifest-emitted"]["status"], "complete")
        self.assertEqual(entity_slots["search-entity-source-viewer-locators"]["status"], "complete")
        self.assertEqual(entity_slots["search-entity-hash-only-citations"]["status"], "complete")
        self.assertEqual(entity_slots["search-entity-merge-split-review-queue"]["status"], "complete")
        self.assertEqual(entity_slots["search-entity-persistent-review-state"]["status"], "external-required")
        self.assertEqual(entity_slots["search-entity-merge-split-workflow"]["status"], "external-required")
        self.assertIn("persistent-entity-review-state-required", entity_plan["blockers"])
        self.assertIn("entity-review-trusted-diff-required", entity_plan["blockers"])
        self.assertEqual(
            analysis_uplift["large_data_controls"]["entity_report_grade_validation_plan_hash"],
            entity_plan["validation_plan_sha256"],
        )
        self.assertEqual(
            analysis_uplift["reportability_decision"]["entity_report_grade_validation_plan_hash"],
            entity_plan["validation_plan_sha256"],
        )

        graph = analysis["graph"]
        self.assertTrue(any(edge["type"] == "mentions" for edge in graph["edges"]))
        self.assertTrue(all(edge.get("source_citation") for edge in graph["edges"]))
        self.assertFalse(graph["summary"]["truncated"])
        self.assertGreaterEqual(graph["summary"]["source_citation_edge_count"], 1)
        self.assertGreaterEqual(graph["summary"]["available_filter_count"], 1)
        self.assertIn("#48", graph["summary"]["commercial_gap_ids"])
        graph_profile = graph["graph_interaction_profile"]
        self.assertEqual(graph_profile["profile_version"], "relationship-graph-interaction-v1")
        self.assertGreaterEqual(graph_profile["source_citation_edge_count"], 1)
        self.assertGreaterEqual(len(graph_profile["available_filters"]), 1)
        self.assertFalse(graph_profile["saved_layout_supported"])
        self.assertFalse(graph_profile["server_side_paging_supported"])
        self.assertTrue(graph_profile["commercial_release_blocked"])
        graph_manifest = graph["graph_citation_manifest"]
        self.assertEqual(graph_manifest["manifest_version"], "search-graph-citation-manifest-v1")
        self.assertEqual(graph_manifest["item_number"], 48)
        self.assertEqual(graph["graph_citation_manifest_hash"], graph_manifest["manifest_sha256"])
        self.assertGreaterEqual(graph_manifest["edge_citation_count"], 1)
        self.assertGreaterEqual(graph_manifest["source_viewer_locator_count"], 1)
        self.assertEqual(
            graph_manifest["edge_entries"][0]["source_viewer_locator"]["viewer"],
            "search-graph-edge-source",
        )
        self.assertIn(
            "search-graph-citation-manifest-emitted",
            graph_manifest["passed_validation_check_ids"],
        )
        graph_plan = graph["graph_report_grade_validation_plan"]
        self.assertEqual(graph_plan["profile_version"], "search-graph-report-grade-validation-plan-v1")
        self.assertEqual(graph_plan["item_number"], 48)
        self.assertEqual(graph_plan["gap_id"], "#48")
        self.assertEqual(graph["graph_report_grade_validation_plan_hash"], graph_plan["validation_plan_sha256"])
        self.assertEqual(graph_plan["graph_citation_manifest_sha256"], graph_manifest["manifest_sha256"])
        self.assertGreaterEqual(graph_plan["edge_count"], 1)
        self.assertGreaterEqual(graph_plan["edge_citation_count"], 1)
        self.assertEqual(graph_plan["ready_slot_count"], 6)
        self.assertEqual(graph_plan["blocking_slot_count"], 6)
        self.assertEqual(graph_plan["validation_status"], "report-validation-blocked")
        self.assertFalse(graph_plan["commercial_grade"])
        graph_slots = {slot["slot_id"]: slot for slot in graph_plan["validation_slots"]}
        self.assertEqual(graph_slots["search-graph-nodes-and-edges-built"]["status"], "complete")
        self.assertEqual(graph_slots["search-graph-interaction-profile-emitted"]["status"], "complete")
        self.assertEqual(graph_slots["search-graph-citation-manifest-emitted"]["status"], "complete")
        self.assertEqual(graph_slots["search-graph-edge-source-viewer-locators"]["status"], "complete")
        self.assertEqual(graph_slots["search-graph-filter-and-page-metadata"]["status"], "complete")
        self.assertEqual(graph_slots["search-graph-causal-proof-warning"]["status"], "complete")
        self.assertEqual(graph_slots["search-graph-server-side-paging"]["status"], "external-required")
        self.assertEqual(graph_slots["search-graph-saved-layouts"]["status"], "external-required")
        self.assertIn("server-side-graph-paging-required", graph_plan["blockers"])
        self.assertIn("graph-source-citation-trusted-diff-required", graph_plan["blockers"])
        self.assertEqual(
            analysis_uplift["large_data_controls"]["graph_report_grade_validation_plan_hash"],
            graph_plan["validation_plan_sha256"],
        )
        self.assertEqual(
            analysis_uplift["reportability_decision"]["graph_report_grade_validation_plan_hash"],
            graph_plan["validation_plan_sha256"],
        )
        self.assertFalse(graph["report_grade_assessment"]["ready_for_court_report"])
        self.assertIn("#49", analysis["timeline"]["summary"]["commercial_gap_ids"])
        self.assertIn("event_id", analysis["timeline"]["events"][0])
        timeline_profile = analysis["timeline"]["timeline_correlation_profile"]
        self.assertEqual(timeline_profile["profile_version"], "timeline-correlation-review-v1")
        self.assertGreaterEqual(timeline_profile["event_page_count"], 1)
        self.assertEqual(timeline_profile["missing_timezone_count"], 0)
        self.assertIn("+00:00", timeline_profile["timezone_counts"])
        self.assertFalse(timeline_profile["full_case_join_supported"])
        self.assertFalse(timeline_profile["cursor_api_supported"])
        self.assertTrue(timeline_profile["commercial_release_blocked"])
        timeline_manifest = analysis["timeline"]["timeline_citation_manifest"]
        self.assertEqual(timeline_manifest["manifest_version"], "search-timeline-citation-manifest-v1")
        self.assertEqual(timeline_manifest["item_number"], 49)
        self.assertEqual(analysis["timeline"]["timeline_citation_manifest_hash"], timeline_manifest["manifest_sha256"])
        self.assertGreaterEqual(timeline_manifest["event_citation_count"], 1)
        self.assertGreaterEqual(timeline_manifest["source_viewer_locator_count"], 1)
        self.assertFalse(timeline_manifest["clock_skew_overlay_supported"])
        self.assertEqual(
            timeline_manifest["event_entries"][0]["source_viewer_locator"]["viewer"],
            "search-timeline-event-source",
        )
        self.assertIn(
            "search-timeline-citation-manifest-emitted",
            timeline_manifest["passed_validation_check_ids"],
        )
        self.assertEqual(analysis["deduplication"]["groups"][0]["match_count"], 2)
        self.assertEqual(analysis["deduplication"]["groups"][0]["representative_index"], 1)
        self.assertEqual(analysis["deduplication"]["groups"][0]["hidden_duplicate_count"], 1)
        self.assertEqual(analysis["deduplication"]["groups"][0]["collapse_hint"], "show-representative-with-duplicates-collapsed")
        self.assertEqual(analysis["deduplication"]["groups"][0]["report_suppression_status"], "not-suppressed")
        self.assertEqual(analysis["deduplication"]["groups"][0]["duplicate_resolution_status"], "candidate")
        self.assertIn("#60", analysis["deduplication"]["groups"][0]["commercial_gap_ids"])
        self.assertIn("#60", analysis["deduplication"]["summary"]["commercial_gap_ids"])
        self.assertIn("#60", analysis["deduplication"]["deduplication_assessment"]["commercial_gap_ids"])
        self.assertEqual(analysis["deduplication"]["core_accuracy_gates"][0]["gap_id"], "#60")
        dedup_manifest = analysis["deduplication"]["search_dedup_manifest"]
        self.assertEqual(dedup_manifest["manifest_version"], "search-dedup-citation-manifest-v1")
        self.assertEqual(analysis["deduplication"]["search_dedup_manifest_hash"], dedup_manifest["manifest_sha256"])
        self.assertEqual(dedup_manifest["source_viewer_locator"]["viewer"], "search-dedup-review")
        self.assertGreaterEqual(dedup_manifest["member_row_hash_count"], 2)
        self.assertEqual(
            dedup_manifest["group_entries"][0]["representative_source_viewer_locator"]["viewer"],
            "search-dedup-representative-source",
        )
        self.assertEqual(
            dedup_manifest["group_entries"][0]["member_entries"][0]["source_viewer_locator"]["viewer"],
            "search-dedup-member-source",
        )
        dedup_profile = analysis["deduplication"]["dedup_review_profile"]
        self.assertEqual(dedup_profile["profile_version"], "search-dedup-review-profile-v1")
        self.assertTrue(dedup_profile["representative_first_review"])
        self.assertTrue(dedup_profile["collapse_preview_supported"])
        self.assertFalse(dedup_profile["case_db_suppression_state"])
        self.assertEqual(dedup_profile["review_groups"][0]["review_status"], "unreviewed")
        self.assertEqual(dedup_profile["review_groups"][0]["report_suppression_status"], "not-suppressed")
        dedup_uplift = analysis["deduplication"]["commercial_uplift_evidence"]
        self.assertEqual(dedup_uplift["batch_id"], "commercial-uplift-056-060")
        self.assertEqual(dedup_uplift["item_numbers"], [60])
        self.assertIn("duplicate fingerprint generation", dedup_uplift["passed_validation_check_ids"])
        self.assertIn("collapse preview profile", dedup_uplift["passed_validation_check_ids"])
        self.assertIn("persistent-dedup-suppression-workflow", dedup_uplift["failed_validation_check_ids"])
        self.assertTrue(dedup_uplift["large_data_controls"]["collapse_preview_supported"])
        self.assertEqual(dedup_uplift["large_data_controls"]["dedup_manifest_hash"], dedup_manifest["manifest_sha256"])
        self.assertGreaterEqual(dedup_uplift["large_data_controls"]["dedup_member_row_hash_count"], 2)
        self.assertTrue(dedup_uplift["large_data_controls"]["dedup_source_viewer_locator"])
        self.assertFalse(dedup_uplift["large_data_controls"]["case_db_suppression_state"])
        self.assertEqual(
            dedup_uplift["reportability_decision"]["decision"],
            "do-not-report-duplicate-groups-as-suppressed-or-content-complete",
        )
        self.assertEqual(dedup_uplift["reportability_decision"]["allowed_use"], "duplicate-hit-triage-pivot")
        self.assertIn(
            "check:case-db-duplicate-suppression-state",
            dedup_uplift["reportability_decision"]["blockers"],
        )
        self.assertEqual(analysis["deduplication"]["trusted_duplicate_manifest_diff"]["status"], "missing")
        self.assertIn(
            "check:search-dedup-trusted-duplicate-manifest-required",
            dedup_uplift["reportability_decision"]["blockers"],
        )
        self.assertFalse(analysis["deduplication"]["deduplication_assessment"]["ready_for_court_report"])

        workbook = analysis["workbook"]
        hypothesis_keys = {item["key"] for item in workbook["hypotheses"]}
        self.assertIn("credential-exposure", hypothesis_keys)
        self.assertIn("web-ai-activity", hypothesis_keys)
        self.assertIn("execution-or-persistence", hypothesis_keys)
        self.assertIn("#50", workbook["summary"]["commercial_gap_ids"])
        self.assertFalse(workbook["hypotheses"][0]["ready_for_report"])
        workbook_profile = workbook["workbook_review_profile"]
        self.assertEqual(workbook_profile["profile_version"], "hypothesis-workbook-review-v1")
        self.assertGreaterEqual(workbook_profile["review_queue_count"], 1)
        self.assertGreaterEqual(workbook_profile["evidence_attachment_count"], 1)
        self.assertFalse(workbook_profile["editable_workbook_supported"])
        self.assertFalse(workbook_profile["version_history_supported"])
        self.assertTrue(workbook_profile["commercial_release_blocked"])
        self.assertEqual(workbook_profile["review_queue"][0]["report_decision"], "pending")
        workbook_manifest = workbook["workbook_citation_manifest"]
        self.assertEqual(workbook_manifest["manifest_version"], "search-workbook-citation-manifest-v1")
        self.assertEqual(workbook_manifest["item_number"], 50)
        self.assertEqual(workbook["workbook_citation_manifest_hash"], workbook_manifest["manifest_sha256"])
        self.assertGreaterEqual(workbook_manifest["hypothesis_citation_count"], 1)
        self.assertGreaterEqual(workbook_manifest["evidence_cluster_ref_count"], 1)
        self.assertFalse(workbook_manifest["version_history_supported"])
        self.assertEqual(
            workbook_manifest["hypothesis_entries"][0]["source_viewer_locator"]["viewer"],
            "search-workbook-hypothesis-review",
        )
        self.assertIn(
            "search-workbook-citation-manifest-emitted",
            workbook_manifest["passed_validation_check_ids"],
        )

    def test_analysis_trusted_diffs_control_reviewed_finding_gates(self) -> None:
        baseline = build_search_analysis(self.make_matches(), ["password", "powershell"])
        trusted_diffs = {
            46: build_analysis_trusted_diff(
                46,
                baseline["clusters"]["clusters"],
                [dict(row) for row in baseline["clusters"]["clusters"]],
                trusted_tool="hand-labeled-cluster-review",
            ),
            47: build_analysis_trusted_diff(
                47,
                baseline["entities"]["entities"],
                [dict(row) for row in baseline["entities"]["entities"]],
                trusted_tool="analyst-entity-review",
            ),
            48: build_analysis_trusted_diff(
                48,
                baseline["graph"]["edges"],
                [dict(row) for row in baseline["graph"]["edges"]],
                trusted_tool="graph-source-citation-review",
            ),
            49: build_analysis_trusted_diff(
                49,
                baseline["timeline"]["events"],
                [dict(row) for row in baseline["timeline"]["events"]],
                trusted_tool="timeline-known-answer",
            ),
            50: build_analysis_trusted_diff(
                50,
                baseline["workbook"]["hypotheses"],
                [dict(row) for row in baseline["workbook"]["hypotheses"]],
                trusted_tool="workbook-rubric-review",
            ),
        }
        self.assertTrue(all(diff["status"] == "pass" for diff in trusted_diffs.values()))

        analysis = build_search_analysis(self.make_matches(), ["password", "powershell"], trusted_diffs=trusted_diffs)
        gates = {gate["gap_id"]: gate for gate in analysis["core_accuracy_gates"]}

        self.assertIn("trusted cluster review diff pass", gates["#46"]["satisfied_checks"])
        self.assertIn("trusted entity review diff pass", gates["#47"]["satisfied_checks"])
        self.assertIn("trusted graph source-citation diff pass", gates["#48"]["satisfied_checks"])
        self.assertIn("trusted timeline known-answer diff pass", gates["#49"]["satisfied_checks"])
        self.assertIn("trusted workbook rubric diff pass", gates["#50"]["satisfied_checks"])

        dedup_diff = build_analysis_trusted_diff(
            60,
            baseline["deduplication"]["groups"],
            [dict(row) for row in baseline["deduplication"]["groups"]],
            trusted_tool="duplicate-manifest-review",
        )
        self.assertEqual(dedup_diff["status"], "pass")
        analysis_with_dedup = build_search_analysis(
            self.make_matches(),
            ["password", "powershell"],
            trusted_diffs={60: dedup_diff},
        )
        dedup_gate = analysis_with_dedup["deduplication"]["core_accuracy_gates"][0]
        self.assertIn("trusted duplicate manifest diff pass", dedup_gate["satisfied_checks"])

        mismatch = build_analysis_trusted_diff(
            49,
            baseline["timeline"]["events"],
            [{**dict(row), "timestamp": "2026-04-25T09:09:09+00:00"} for row in baseline["timeline"]["events"]],
            trusted_tool="timeline-known-answer",
        )
        self.assertEqual(mismatch["status"], "diffs-present")
        self.assertIn("timeline-known-answer-trusted-diff-required", mismatch["reportability_decision"]["blockers"])

    def test_unified_search_payload_includes_analysis_by_default_and_can_skip_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_path = root / "rapidtriage-docs.json"
            summary_path = root / "rapidtriage-run-summary.json"
            evidence_path = root / "passwords.txt"
            evidence_path.write_text("alice@example.com password reset https://example.com/reset", encoding="utf-8")
            write_json(
                docs_path,
                {
                    "command": "docs",
                    "generated_at": "2026-04-25T00:00:00+00:00",
                    "root": str(root),
                    "keywords": ["password"],
                    "summary": {"candidate_count": 1, "match_count": 1},
                    "manifest": {},
                    "candidates": [
                        {
                            "path": str(evidence_path),
                            "kind": "txt",
                            "size": evidence_path.stat().st_size,
                            "modified_at": "2026-04-25T00:00:00+00:00",
                        }
                    ],
                    "results": [
                        {
                            "path": str(evidence_path),
                            "kind": "txt",
                            "matched_keywords": ["password"],
                            "preview": "password reset",
                        }
                    ],
                },
            )
            write_json(
                summary_path,
                {
                    "command": "run",
                    "outputs": {
                        "summary": str(summary_path),
                        "docs": str(docs_path),
                    },
                },
            )

            payload = run_unified_search(summary_path, ["password"], include_ocr=False)

            self.assertIn("analysis", payload)
            self.assertGreaterEqual(payload["analysis"]["summary"]["cluster_count"], 1)
            self.assertGreaterEqual(payload["analysis"]["summary"]["entity_count"], 1)

            no_analysis = run_unified_search(summary_path, ["password"], include_ocr=False, include_analysis=False)

            self.assertNotIn("analysis", no_analysis)

    def test_unified_search_uses_ocr_sidecars_without_requiring_ocr_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "screen.png"
            sidecar_path = root / "screen.png.ocr.txt"
            files_path = root / "rapidtriage-files.json"
            summary_path = root / "rapidtriage-run-summary.json"
            image_path.write_bytes(b"\x89PNG\r\n\x1a\n")
            sidecar_path.write_text("invoice password visible in screenshot", encoding="utf-8")
            write_json(
                files_path,
                {
                    "command": "files",
                    "generated_at": "2026-04-25T00:00:00+00:00",
                    "root": str(root),
                    "filters": {},
                    "summary": {"candidate_count": 1},
                    "candidates": [
                        {
                            "path": str(image_path),
                            "name": image_path.name,
                            "extension": ".png",
                            "size": image_path.stat().st_size,
                            "modified_at": "2026-04-25T00:00:00+00:00",
                            "modified_epoch": 1777075200,
                            "categories": ["images"],
                            "reasons": {"categories": ["images"]},
                        }
                    ],
                },
            )
            write_json(
                summary_path,
                {
                    "command": "run",
                    "outputs": {
                        "summary": str(summary_path),
                        "files": str(files_path),
                    },
                },
            )

            payload = run_unified_search(summary_path, ["password"], include_ocr=True, include_analysis=False)

            self.assertEqual(payload["summary"]["match_count"], 1)
            self.assertEqual(payload["matches"][0]["source"], "ocr")
            self.assertEqual(payload["matches"][0]["metadata"]["ocr_source"], "sidecar")
            self.assertEqual(payload["matches"][0]["metadata"]["ocr_sidecar_path"], str(sidecar_path))

    def test_unified_search_supports_fuzzy_regex_proximity_and_keyword_packs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_path = root / "rapidtriage-docs.json"
            summary_path = root / "rapidtriage-run-summary.json"
            evidence_path = root / "notes.txt"
            evidence_path.write_text("The passwrod note also says password near a token during PowerShell execution.", encoding="utf-8")
            write_json(
                docs_path,
                {
                    "command": "docs",
                    "generated_at": "2026-04-25T00:00:00+00:00",
                    "root": str(root),
                    "keywords": ["password"],
                    "summary": {"candidate_count": 1, "match_count": 1},
                    "manifest": {},
                    "candidates": [
                        {
                            "path": str(evidence_path),
                            "kind": "txt",
                            "size": evidence_path.stat().st_size,
                            "modified_at": "2026-04-25T00:00:00+00:00",
                        }
                    ],
                    "results": [],
                },
            )
            write_json(
                summary_path,
                {
                    "command": "run",
                    "outputs": {
                        "summary": str(summary_path),
                        "docs": str(docs_path),
                    },
                },
            )

            fuzzy = run_unified_search(
                summary_path,
                ["password", "token"],
                include_ocr=False,
                search_mode="fuzzy",
                fuzzy_distance=2,
                proximity_window=5,
            )
            regex = run_unified_search(summary_path, [r"PowerShell\s+execution"], include_ocr=False, search_mode="regex")
            packed = resolve_keyword_packs([], pack_names=["credentials"])

            self.assertEqual(fuzzy["summary"]["match_count"], 1)
            self.assertIn("#61", fuzzy["summary"]["commercial_gap_ids"])
            self.assertIn("#61", fuzzy["search_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(fuzzy["advanced_search_profile"]["profile_version"], "advanced-search-profile-v1")
            self.assertEqual(fuzzy["advanced_search_profile"]["active_mode"], "fuzzy")
            self.assertEqual(fuzzy["advanced_search_profile"]["controls"]["fuzzy_distance"], 2)
            self.assertEqual(fuzzy["advanced_search_profile"]["controls"]["proximity_window"], 5)
            self.assertEqual(fuzzy["advanced_search_profile"]["proximity_matched_count"], 1)
            self.assertEqual(fuzzy["advanced_search_profile"]["hit_row_hash_count"], 1)
            self.assertEqual(fuzzy["advanced_search_profile"]["source_locator_count"], 1)
            self.assertEqual(
                fuzzy["advanced_search_profile"]["query_hit_manifest_hash"],
                fuzzy["advanced_search_query_hit_manifest_hash"],
            )
            self.assertTrue(fuzzy["advanced_search_profile"]["source_verification_required"])
            self.assertIn("fuzzy-results-are-typo-tolerant-triage-not-exact-proof", fuzzy["advanced_search_profile"]["review_warnings"])
            self.assertEqual(fuzzy["advanced_search_profile"]["query_validation"][0]["query"], "password")
            self.assertEqual(fuzzy["core_accuracy_gates"][0]["gap_id"], "#61")
            self.assertIn("query mode and options recorded", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("proximity metadata preserved", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("advanced search query-hit manifest", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("search hit row hashes", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("advanced search source locators", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            query_manifest = fuzzy["advanced_search_query_hit_manifest"]
            self.assertEqual(query_manifest["manifest_version"], "advanced-search-query-hit-manifest-v1")
            self.assertEqual(query_manifest["manifest_hash"], fuzzy["advanced_search_query_hit_manifest_hash"])
            self.assertEqual(query_manifest["match_count"], 1)
            self.assertEqual(query_manifest["hit_row_hash_count"], 1)
            self.assertEqual(query_manifest["source_locator_count"], 1)
            backend_contract = fuzzy["search_backend_contract"]
            self.assertEqual(backend_contract["profile_version"], "search-backend-contract-v1")
            self.assertEqual(backend_contract["qc_prep_item_numbers"], [48, 49, 50, 51, 52, 53, 54, 55])
            self.assertEqual(backend_contract["selected_backend_id"], "sqlite-fts-local")
            self.assertTrue(backend_contract["ui_cli_contract"]["query_plan_metadata"])
            self.assertEqual(backend_contract["sqlite_fts_default_plan"]["qc_prep_item_number"], 49)
            self.assertEqual(
                backend_contract["local_inverted_candidate_evaluation"]["qc_prep_item_number"],
                50,
            )
            self.assertEqual(backend_contract["external_search_adapter_contract"]["qc_prep_item_number"], 51)
            self.assertFalse(backend_contract["external_search_adapter_contract"]["mandatory_for_single_case_desktop"])
            self.assertEqual(backend_contract["normalized_index_schema_contract"]["qc_prep_item_number"], 52)
            self.assertIn("evtx", backend_contract["normalized_index_schema_contract"]["artifact_families"])
            self.assertEqual(backend_contract["synthetic_benchmark_generator_manifest"]["qc_prep_item_number"], 53)
            self.assertEqual(backend_contract["uniform_cursor_pagination_contract"]["qc_prep_item_number"], 54)
            self.assertEqual(backend_contract["ui_virtualization_contract"]["qc_prep_item_number"], 55)
            self.assertEqual(fuzzy["search_backend_contract_hash"], backend_contract["contract_hash"])
            self.assertEqual(query_manifest["hits"][0]["search_result_id"], "search-hit-000001")
            self.assertTrue(query_manifest["hits"][0]["hit_row_hash"])
            self.assertEqual(
                query_manifest["hits"][0]["source_viewer_locator"]["viewer"],
                "advanced-search-hit-source",
            )
            search_uplift = fuzzy["commercial_uplift_evidence"]
            self.assertEqual(search_uplift["batch_id"], "commercial-uplift-061-065")
            self.assertEqual(search_uplift["item_numbers"], [61])
            self.assertIn("query mode and options recorded", search_uplift["passed_validation_check_ids"])
            self.assertFalse(search_uplift["large_data_controls"]["full_linguistic_stemming"])
            self.assertEqual(
                search_uplift["large_data_controls"]["advanced_search_manifest_hash"],
                fuzzy["advanced_search_query_hit_manifest_hash"],
            )
            self.assertEqual(search_uplift["large_data_controls"]["hit_row_hash_count"], 1)
            self.assertEqual(search_uplift["large_data_controls"]["source_locator_count"], 1)
            self.assertEqual(
                search_uplift["reportability_decision"]["decision"],
                "do-not-report-advanced-search-hit-as-source-proof",
            )
            self.assertEqual(search_uplift["reportability_decision"]["allowed_use"], "advanced-search-triage-pivot")
            self.assertIn("check:query-builder-ux-validation", search_uplift["reportability_decision"]["blockers"])
            self.assertIn("trusted-advanced-search-query-hit-diff-missing", search_uplift["failed_validation_check_ids"])
            self.assertTrue(fuzzy["search_native_capabilities"]["regex_search"])
            self.assertEqual(fuzzy["matches"][0]["search_match"]["mode"], "fuzzy")
            self.assertIn("#61", fuzzy["matches"][0]["search_match"]["commercial_gap_ids"])
            self.assertTrue(fuzzy["matches"][0]["search_match"]["proximity"]["matched"])
            self.assertEqual(fuzzy["matches"][0]["search_result_id"], "search-hit-000001")
            self.assertEqual(
                fuzzy["matches"][0]["source_verification_profile"]["profile_version"],
                "unified-search-source-verification-v1",
            )
            self.assertEqual(
                fuzzy["matches"][0]["advanced_search_hit_manifest"]["manifest_version"],
                "advanced-search-hit-manifest-v1",
            )
            self.assertEqual(
                fuzzy["matches"][0]["advanced_search_hit_manifest_hash"],
                fuzzy["matches"][0]["advanced_search_hit_manifest"]["manifest_hash"],
            )
            self.assertTrue(fuzzy["matches"][0]["advanced_search_hit_manifest"]["hit_row_hash"])
            self.assertEqual(
                fuzzy["matches"][0]["advanced_search_hit_manifest"]["source_viewer_locator"]["viewer"],
                "advanced-search-hit-source",
            )
            self.assertTrue(fuzzy["matches"][0]["source_verification_profile"]["viewer_supported"])
            self.assertFalse(fuzzy["matches"][0]["source_verification_profile"]["source_pointer_available"])
            self.assertIn(
                "source-pointer-required",
                fuzzy["matches"][0]["source_verification_profile"]["blockers"],
            )
            self.assertIn(
                "source-hash-recommended-before-report",
                fuzzy["matches"][0]["source_verification_profile"]["blockers"],
            )
            self.assertEqual(
                fuzzy["workbench_search_profile"]["source_verification_summary"]["source_pointer_count"],
                0,
            )
            self.assertEqual(
                fuzzy["workbench_search_profile"]["source_verification_summary"]["ready_for_report_selection_count"],
                0,
            )
            self.assertEqual(regex["summary"]["match_count"], 1)
            self.assertEqual(regex["advanced_search_profile"]["active_mode"], "regex")
            self.assertEqual(regex["advanced_search_profile"]["query_validation"][0]["valid"], True)
            invalid_regex = run_unified_search(summary_path, [r"PowerShell("], include_ocr=False, search_mode="regex")
            self.assertEqual(invalid_regex["summary"]["match_count"], 0)
            self.assertEqual(invalid_regex["advanced_search_profile"]["query_validation"][0]["valid"], False)
            self.assertIn("invalid-regex-pattern-will-match-nothing", invalid_regex["advanced_search_profile"]["query_validation"][0]["warnings"])
            self.assertIn("password", packed)

            trusted_diff = build_advanced_search_trusted_diff(fuzzy["matches"], fuzzy["matches"])
            gates = search_core_accuracy_gates(
                matches=fuzzy["matches"],
                options=fuzzy["options"],
                trusted_diff=trusted_diff,
            )

            self.assertEqual(trusted_diff["status"], "pass")
            self.assertIn("trusted advanced-search query-hit diff pass", gates[0]["satisfied_checks"])

    def test_search_backend_contract_exposes_default_and_candidate_engines(self) -> None:
        contract = build_search_backend_contract(
            keywords=["password"],
            limit=9000,
            corpus_estimate={"document_rows": 100_000, "artifact_rows": 250_000, "target_rows": 1_000_000},
        )

        self.assertEqual(contract["selected_backend_id"], "sqlite-fts-local")
        self.assertEqual(contract["qc_prep_item_numbers"], [48, 49, 50, 51, 52, 53, 54, 55])
        self.assertEqual(contract["sqlite_fts_default_plan"]["effective_interactive_limit"], 5000)
        self.assertTrue(contract["sqlite_fts_default_plan"]["cursor_pagination_required"])
        self.assertEqual(contract["local_inverted_candidate_evaluation"]["target_rows"], 1_000_000)
        self.assertFalse(contract["local_inverted_candidate_evaluation"]["prototype_dependency_added"])
        self.assertTrue(contract["local_inverted_candidate_evaluation"]["prototype_runtime_available"])
        self.assertEqual(
            contract["local_inverted_candidate_evaluation"]["sidecar_query_command"],
            "rapidtriage docs-index-search <docs-index.json> -k <keyword>",
        )
        self.assertEqual(
            contract["local_inverted_candidate_evaluation"]["enablement_scope"],
            "processed-document-text-sidecar-only",
        )
        self.assertEqual(contract["external_search_adapter_contract"]["backend_id"], "elasticsearch-opensearch-optional")
        self.assertFalse(contract["external_search_adapter_contract"]["privacy_controls"]["export_evidence_text_to_external_service_by_default"])
        self.assertIn("messenger", contract["normalized_index_schema_contract"]["artifact_families"])
        self.assertEqual(contract["synthetic_benchmark_generator_manifest"]["targets"], [100_000, 1_000_000, 10_000_000])
        self.assertTrue(contract["uniform_cursor_pagination_contract"]["collection_contracts"]["search"]["cursor_required"])
        self.assertTrue(contract["ui_virtualization_contract"]["required_behaviors"]["selection_state_survives_virtual_unmount"])
        self.assertIn("sqlite-fts-parity-diff-required", contract["commercial_blockers"])

    def test_search_large_case_qc_contracts_cover_items_51_to_55(self) -> None:
        external = build_external_search_adapter_contract(corpus_estimate={"target_rows": 10_000_000})
        benchmark = build_synthetic_benchmark_generator_manifest()
        cursor = build_uniform_cursor_pagination_contract()
        virtualization = build_ui_virtualization_contract()

        self.assertEqual(external["qc_prep_item_number"], 51)
        self.assertEqual(external["target_rows"], 10_000_000)
        self.assertIn("OpenSearch", external["supported_service_families"])
        self.assertIn("local SQLite fallback if external service is unavailable", external["required_connection_controls"])
        self.assertEqual(benchmark["qc_prep_item_number"], 53)
        self.assertEqual([item["target_rows"] for item in benchmark["generators"]], [100_000, 1_000_000, 10_000_000])
        self.assertTrue(benchmark["reproducibility_controls"]["deterministic_row_order_required"])
        self.assertEqual(cursor["qc_prep_item_number"], 54)
        self.assertTrue(cursor["collection_contracts"]["review_queue"]["resume_token_required"])
        self.assertTrue(cursor["collection_contracts"]["report_candidates"]["source_locator_required"])
        self.assertEqual(virtualization["qc_prep_item_number"], 55)
        self.assertTrue(virtualization["required_behaviors"]["viewport_restore_required"])
        self.assertTrue(virtualization["persistence_contract"]["focused_row_id"])


if __name__ == "__main__":
    unittest.main()
