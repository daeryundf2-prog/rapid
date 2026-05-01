from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from rapidtriage.core.analysis import build_search_analysis
from rapidtriage.core.keyword_packs import resolve_keyword_packs
from rapidtriage.core.search import run_unified_search


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
        self.assertIn("entity extraction across supported types", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("match reference links", analysis_gates["#47"]["satisfied_checks"])
        self.assertIn("relationship edges built", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("causal-proof limitation warning", analysis_gates["#48"]["satisfied_checks"])
        self.assertIn("timestamp extraction", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("UTC normalization", analysis_gates["#49"]["satisfied_checks"])
        self.assertIn("draft hypotheses generated", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("persistence/versioning limitation warning", analysis_gates["#50"]["satisfied_checks"])
        self.assertIn("duplicate fingerprint generation", analysis_gates["#60"]["satisfied_checks"])
        self.assertIn("duplicate group counts", analysis_gates["#60"]["satisfied_checks"])

        clusters = analysis["clusters"]["clusters"]
        self.assertTrue(any(cluster["family"] == "keyword" and cluster["value"] == "password" for cluster in clusters))
        self.assertIn("#46", analysis["clusters"]["summary"]["commercial_gap_ids"])

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

        graph = analysis["graph"]
        self.assertTrue(any(edge["type"] == "mentions" for edge in graph["edges"]))
        self.assertFalse(graph["summary"]["truncated"])
        self.assertIn("#48", graph["summary"]["commercial_gap_ids"])
        self.assertFalse(graph["report_grade_assessment"]["ready_for_court_report"])
        self.assertIn("#49", analysis["timeline"]["summary"]["commercial_gap_ids"])
        self.assertIn("event_id", analysis["timeline"]["events"][0])
        self.assertEqual(analysis["deduplication"]["groups"][0]["match_count"], 2)
        self.assertEqual(analysis["deduplication"]["groups"][0]["duplicate_resolution_status"], "candidate")
        self.assertIn("#60", analysis["deduplication"]["groups"][0]["commercial_gap_ids"])
        self.assertIn("#60", analysis["deduplication"]["summary"]["commercial_gap_ids"])
        self.assertIn("#60", analysis["deduplication"]["deduplication_assessment"]["commercial_gap_ids"])
        self.assertEqual(analysis["deduplication"]["core_accuracy_gates"][0]["gap_id"], "#60")
        self.assertFalse(analysis["deduplication"]["deduplication_assessment"]["ready_for_court_report"])

        workbook = analysis["workbook"]
        hypothesis_keys = {item["key"] for item in workbook["hypotheses"]}
        self.assertIn("credential-exposure", hypothesis_keys)
        self.assertIn("web-ai-activity", hypothesis_keys)
        self.assertIn("execution-or-persistence", hypothesis_keys)
        self.assertIn("#50", workbook["summary"]["commercial_gap_ids"])
        self.assertFalse(workbook["hypotheses"][0]["ready_for_report"])

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
            self.assertEqual(fuzzy["core_accuracy_gates"][0]["gap_id"], "#61")
            self.assertIn("query mode and options recorded", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("proximity metadata preserved", fuzzy["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertTrue(fuzzy["search_native_capabilities"]["regex_search"])
            self.assertEqual(fuzzy["matches"][0]["search_match"]["mode"], "fuzzy")
            self.assertIn("#61", fuzzy["matches"][0]["search_match"]["commercial_gap_ids"])
            self.assertTrue(fuzzy["matches"][0]["search_match"]["proximity"]["matched"])
            self.assertEqual(regex["summary"]["match_count"], 1)
            self.assertIn("password", packed)


if __name__ == "__main__":
    unittest.main()
