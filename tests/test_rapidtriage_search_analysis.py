from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from rapidtriage.core.analysis import build_analysis_trusted_diff, build_search_analysis
from rapidtriage.core.keyword_packs import resolve_keyword_packs
from rapidtriage.core.search import build_advanced_search_trusted_diff, run_unified_search, search_core_accuracy_gates


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
        analysis_gates = {gate["gap_id"]: gate for gate in analysis["core_accuracy_gates"]}
        self.assertIn("bounded cluster generation", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("representative match links", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("cluster review profile", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("representative-first review queue", analysis_gates["#46"]["satisfied_checks"])
        self.assertIn("entity extraction across supported types", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("match reference links", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("entity review profile", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("merge/split review queue", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("relationship edges built", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("causal-proof limitation warning", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("edge source citations", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("graph interaction profile", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("filter metadata", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("timestamp extraction", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("UTC normalization", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("timeline correlation profile", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("cursor page metadata", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("timezone distribution", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("draft hypotheses generated", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("workbook review profile", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("hypothesis review queue", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("persistence/versioning limitation warning", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("duplicate fingerprint generation", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("duplicate group counts", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("collapse preview profile", analysis_gates["#60"]["satisfied_checks"])
        analysis_uplift = analysis["commercial_uplift_evidence"]
        self.assertEqual(analysis_uplift["batch_id"], "commercial-uplift-046-050")
        self.assertEqual(analysis_uplift["item_numbers"], [46, 47, 48, 49, 50])
        self.assertIn("bounded cluster generation", analysis_uplift["passed_validation_check_ids_by_item"]["#46"])
        self.assertIn("cluster review profile", analysis_uplift["passed_validation_check_ids_by_item"]["#46"])
        self.assertIn("entity extraction across supported types", analysis_uplift["passed_validation_check_ids_by_item"]["#47"])
        self.assertIn("entity review profile", analysis_uplift["passed_validation_check_ids_by_item"]["#47"])
        self.assertIn("relationship edges built", analysis_uplift["passed_validation_check_ids_by_item"]["#48"])
        self.assertIn("edge source citations", analysis_uplift["passed_validation_check_ids_by_item"]["#48"])
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
        self.assertFalse(analysis_uplift["large_data_controls"]["persistent_review_state"])
        self.assertFalse(analysis_uplift["large_data_controls"]["full_case_reindex"])
        self.assertTrue(analysis_uplift["large_data_controls"]["cluster_review_profile_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["cluster_review_queue_count"], 1)
        self.assertTrue(analysis_uplift["large_data_controls"]["representative_first_cluster_review"])
        self.assertTrue(analysis_uplift["large_data_controls"]["entity_review_profile_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["entity_review_queue_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["merge_split_candidate_count"], 1)
        self.assertFalse(analysis_uplift["large_data_controls"]["analyst_verified_entity_resolution"])
        self.assertFalse(analysis_uplift["large_data_controls"]["persistent_entity_review_state"])
        self.assertTrue(analysis_uplift["large_data_controls"]["graph_interaction_profile_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["graph_filter_count"], 1)
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["graph_edge_page_count"], 1)
        self.assertFalse(analysis_uplift["large_data_controls"]["graph_saved_layout_supported"])
        self.assertTrue(analysis_uplift["large_data_controls"]["timeline_correlation_profile_present"])
        self.assertGreaterEqual(analysis_uplift["large_data_controls"]["timeline_event_page_count"], 1)
        self.assertEqual(analysis_uplift["large_data_controls"]["timeline_missing_timezone_count"], 0)
        self.assertFalse(analysis_uplift["large_data_controls"]["timeline_clock_skew_overlay_supported"])
        self.assertTrue(analysis_uplift["large_data_controls"]["workbook_review_profile_present"])
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
            self.assertTrue(fuzzy["advanced_search_profile"]["source_verification_required"])
            self.assertIn("fuzzy-results-are-typo-tolerant-triage-not-exact-proof", fuzzy["advanced_search_profile"]["review_warnings"])
            self.assertEqual(fuzzy["advanced_search_profile"]["query_validation"][0]["query"], "password")
            self.assertEqual(fuzzy["core_accuracy_gates"][0]["gap_id"], "#61")
            self.assertIn("query mode and options recorded", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("proximity metadata preserved", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            search_uplift = fuzzy["commercial_uplift_evidence"]
            self.assertEqual(search_uplift["batch_id"], "commercial-uplift-061-065")
            self.assertEqual(search_uplift["item_numbers"], [61])
            self.assertIn("query mode and options recorded", search_uplift["passed_validation_check_ids"])
            self.assertFalse(search_uplift["large_data_controls"]["full_linguistic_stemming"])
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


if __name__ == "__main__":
    unittest.main()
