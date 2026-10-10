"""P23: run persist step builds the case DB index; unified search uses it
(FTS backend) or a bounded scan (budget / early stop / sources first)."""

from __future__ import annotations

import json
import os
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.cli import build_parser
from rapidtriage.core.artifact_profiles import iter_artifact_output_rows
from rapidtriage.core.jobs import RunRequest, persist_step_message
from rapidtriage.core.json_stream import iter_array_items
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.run.persist import CASE_DB_FILE_NAME, DOCS_TEXT_SPOOL_NAME
from rapidtriage.core.run.progress import read_run_progress
from rapidtriage.core.search import run_unified_search
from rapidtriage.core.search_budget import (
    DEFAULT_SCAN_BUDGET_SECONDS,
    SCAN_BUDGET_ENV,
    resolve_scan_budget_seconds,
)
from rapidtriage.core.search_fts import (
    build_candidate_query,
    keyword_candidate_term,
    regex_leading_literal,
)
from tests.test_rapidtriage_run import build_run_fixture

KOREAN_NAME = "진정서(배○현)_2024-005727.pdf"


def resolve_pointer(summary: dict, match: dict) -> str | None:
    """Path of the run-output row a search match's pointer names."""
    outputs = summary["outputs"]
    pointer = str(match.get("pointer") or "")
    source = match["source"]
    index = int(pointer.rsplit("/", 1)[1]) if pointer else -1
    if source == "files" and pointer.startswith("/candidates/"):
        rows = list(iter_array_items(Path(outputs["files"]), "candidates"))
    elif source in {"artifacts", "web"} and pointer.startswith("/artifacts/"):
        rows = list(iter_artifact_output_rows(Path(outputs[f"artifacts_{match['kind']}"])))
    elif source == "timeline" and pointer.startswith("/events/"):
        rows = list(iter_array_items(Path(outputs["timeline"]), "events"))
    elif source == "documents" and pointer.startswith("/results/"):
        rows = list(iter_array_items(Path(outputs["docs"]), "results"))
    elif source == "indicators" and pointer.startswith("/indicators/"):
        rows = list(iter_array_items(Path(outputs["indicators"]), "indicators"))
        sources = rows[index].get("sources") or [{}]
        return str(sources[0].get("path") or sources[0].get("source_path") or "")
    else:
        return None
    return str(rows[index].get("path", ""))


class SearchIndexRunTests(unittest.TestCase):
    """One fraud-mode run with the persist step on, shared by the tests."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        cls.root = tmp / "case-root"
        cls.root.mkdir()
        build_run_fixture(cls.root)
        downloads = cls.root / "Users" / "alice" / "Downloads"
        # NFD file name (macOS-style decomposed Hangul) must be found by an
        # NFC query and vice versa (P22 normalization on index and query).
        (downloads / unicodedata.normalize("NFD", KOREAN_NAME)).write_bytes(b"%PDF-1.4\n%%EOF\n")
        cls.output_dir = tmp / "run-out"
        cls.summary = run_triage_mode(cls.root, mode="fraud", output_dir=cls.output_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def search(self, keywords, **kwargs):
        kwargs.setdefault("include_ocr", False)
        kwargs.setdefault("include_analysis", False)
        return run_unified_search(self.summary, keywords, **kwargs)

    def test_persist_step_builds_case_db_and_records_progress(self) -> None:
        db_path = self.output_dir.resolve() / CASE_DB_FILE_NAME
        self.assertTrue(db_path.is_file())
        self.assertEqual(self.summary["search_backend"], "fts")
        self.assertEqual(Path(self.summary["outputs"]["case_db"]), db_path)
        record = self.summary["case_db"]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["document_text_source"], "docs-stage-spool")
        self.assertGreater(record["counts"]["file_record_count"], 0)
        self.assertGreater(record["counts"]["artifact_count"], 0)
        self.assertFalse((self.output_dir / DOCS_TEXT_SPOOL_NAME).exists())
        progress = read_run_progress(self.output_dir)
        persist = [entry for entry in progress["completed_stages"] if entry["stage"] == "persist"]
        self.assertEqual(len(persist), 1)
        self.assertEqual(persist[0]["status"], "completed")
        self.assertIn("started_at", persist[0])
        self.assertEqual(persist[0]["counts"], record["counts"])
        self.assertIn("search index built", persist_step_message(self.summary))

    def test_fts_matches_use_scan_schema_and_pointers_resolve(self) -> None:
        indexed = self.search(["powershell"], limit=200)
        scanned = self.search(["powershell"], limit=200, use_case_db=False, scan_budget_seconds=0)
        self.assertEqual(indexed["backend"], "fts")
        self.assertEqual(scanned["backend"], "scan")
        self.assertFalse(indexed["truncated"])
        self.assertIsInstance(indexed["elapsed_ms"], float)
        self.assertTrue(indexed["matches"])
        sources = {match["source"] for match in indexed["matches"]}
        self.assertIn("documents", sources)
        self.assertIn("files", sources)
        for match in indexed["matches"]:
            for key in ("source", "kind", "path", "title", "matched_keywords", "preview", "pointer", "metadata", "search_match"):
                self.assertIn(key, match)
            self.assertEqual(match["matched_keywords"], ["powershell"])
            resolved = resolve_pointer(self.summary, match)
            if resolved is not None:
                self.assertEqual(resolved, match["path"], match["pointer"])
        # Index hits are scan hits (the index only narrows candidates).
        scan_keys = {(m["source"], m["pointer"]) for m in scanned["matches"]}
        for match in indexed["matches"]:
            if match["source"] in {"files", "timeline", "indicators"}:
                self.assertIn((match["source"], match["pointer"]), scan_keys)

    def test_nfc_and_nfd_queries_find_nfd_named_file(self) -> None:
        for form in ("NFC", "NFD"):
            payload = self.search([unicodedata.normalize(form, "진정서")], sources=["files"])
            self.assertEqual(payload["backend"], "fts")
            names = [unicodedata.normalize("NFC", Path(m["path"]).name) for m in payload["matches"]]
            self.assertIn(KOREAN_NAME, names, form)

    def test_filters_and_limit_are_applied_in_the_index(self) -> None:
        payload = self.search(["persistence"], sources=["files"], extensions=[".bat"], path_contains="desktop")
        self.assertEqual(payload["backend"], "fts")
        self.assertTrue(payload["matches"])
        for match in payload["matches"]:
            self.assertEqual(match["source"], "files")
            self.assertTrue(match["path"].lower().endswith(".bat"))
            self.assertIn("desktop", match["path"].lower())
        self.assertEqual(set(payload["scanned"]), {"files"})
        limited = self.search(["powershell"], limit=1)
        self.assertEqual(len(limited["matches"]), 1)
        self.assertEqual(limited["scanned"]["timeline"]["stopped"], "limit")

    def test_fuzzy_and_regex_are_reverified_with_scan_matchers(self) -> None:
        regex = self.search([r"power[s]hell\b"], search_mode="regex", sources=["files"])
        fuzzy = self.search(["powershel"], search_mode="fuzzy", fuzzy_distance=1, sources=["files"])
        for payload in (regex, fuzzy):
            self.assertEqual(payload["backend"], "fts")
            self.assertTrue(payload["matches"])
        no_hit = self.search(["powershellx"], search_mode="exact", sources=["files"])
        self.assertEqual(no_hit["matches"], [])

    def test_missing_index_falls_back_to_scan(self) -> None:
        payload = self.search(["powershell"], case_db_path=self.output_dir / "missing.db", sources=["files"])
        self.assertEqual(payload["backend"], "scan")


class PersistFailureTests(unittest.TestCase):
    def test_index_failure_keeps_run_completed_with_scan_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir()
            build_run_fixture(root)
            output_dir = Path(tmp_dir) / "run-out"
            with mock.patch(
                "rapidtriage.core.run.persist.CaseDatabase.import_run_output",
                side_effect=RuntimeError("disk full"),
            ):
                summary = run_triage_mode(root, mode="fraud", output_dir=output_dir)
            self.assertEqual(summary["search_backend"], "scan")
            self.assertEqual(summary["case_db"]["status"], "failed")
            self.assertIn("disk full", summary["case_db"]["error"])
            self.assertNotIn("case_db", summary["outputs"])
            self.assertFalse((output_dir / CASE_DB_FILE_NAME).exists())
            self.assertFalse((output_dir / DOCS_TEXT_SPOOL_NAME).exists())
            progress = read_run_progress(output_dir)
            self.assertEqual(progress["status"], "completed")
            persist = [entry for entry in progress["completed_stages"] if entry["stage"] == "persist"][0]
            self.assertEqual(persist["status"], "failed")
            self.assertIn("disk full", persist["error"])
            self.assertIn("search uses scan", persist_step_message(summary))
            self.assertEqual(run_unified_search(summary, ["powershell"], include_ocr=False)["backend"], "scan")

    def test_no_case_db_flag_and_run_request_round_trip(self) -> None:
        args = build_parser().parse_args(["run", "root", "--mode", "fraud", "--no-case-db"])
        self.assertFalse(args.case_db)
        self.assertTrue(build_parser().parse_args(["run", "root", "--mode", "fraud"]).case_db)
        request = RunRequest(root="r", mode="fraud", case_db=False)
        self.assertFalse(RunRequest.from_dict(request.to_dict()).case_db)
        self.assertTrue(RunRequest.from_dict({"root": "r", "mode": "fraud"}).case_db)


def write_synthetic_run(root: Path, *, events: int, needle_every: int) -> dict:
    timeline = {
        "command": "timeline",
        "summary": {"event_count": events},
        "events": [
            {
                "timestamp": f"2026-01-01T00:00:{index % 60:02d}+00:00",
                "event_type": "file-modified",
                "source": "files",
                "path": f"C:/evidence/file-{index}.txt",
                "summary": "needle event" if index % needle_every == needle_every - 1 else "plain event",
            }
            for index in range(events)
        ],
    }
    files = {"command": "files", "summary": {}, "candidates": [{"path": "C:/evidence/needle.txt", "name": "needle.txt"}]}
    (root / "timeline.json").write_text(json.dumps(timeline), encoding="utf-8")
    (root / "files.json").write_text(json.dumps(files), encoding="utf-8")
    return {"outputs": {"timeline": str(root / "timeline.json"), "files": str(root / "files.json")}}


class ScanBudgetTests(unittest.TestCase):
    def test_sources_apply_before_scanning_and_scan_stops_at_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary = write_synthetic_run(Path(tmp_dir), events=5000, needle_every=10)
            payload = run_unified_search(
                summary, ["needle"], limit=2, sources=["timeline"], include_ocr=False, include_analysis=False
            )
            self.assertEqual(payload["backend"], "scan")
            self.assertEqual(set(payload["scanned"]), {"timeline"})
            timeline = payload["scanned"]["timeline"]
            self.assertEqual(timeline["rows"], 20)
            self.assertEqual(timeline["stopped"], "limit")
            self.assertFalse(payload["truncated"])
            self.assertEqual([m["pointer"] for m in payload["matches"]], ["/events/9", "/events/19"])

    def test_limit_left_after_earlier_sources_carries_over(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary = write_synthetic_run(Path(tmp_dir), events=200, needle_every=10)
            payload = run_unified_search(summary, ["needle"], limit=3, include_ocr=False, include_analysis=False)
            self.assertEqual([m["source"] for m in payload["matches"]], ["files", "timeline", "timeline"])
            self.assertEqual(payload["scanned"]["timeline"]["rows"], 20)

    def test_wall_clock_budget_returns_partial_results_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary = write_synthetic_run(Path(tmp_dir), events=3000, needle_every=10)
            payload = run_unified_search(
                summary,
                ["needle"],
                limit=1000,
                sources=["timeline"],
                include_ocr=False,
                include_analysis=False,
                scan_budget_seconds=1e-9,
            )
            self.assertTrue(payload["truncated"])
            self.assertEqual(payload["scanned"]["timeline"]["stopped"], "budget")
            self.assertFalse(payload["scanned"]["timeline"]["complete"])
            self.assertLess(payload["scanned"]["timeline"]["rows"], 3000)
            unbounded = run_unified_search(
                summary,
                ["needle"],
                limit=1000,
                sources=["timeline"],
                include_ocr=False,
                include_analysis=False,
                scan_budget_seconds=0,
            )
            self.assertFalse(unbounded["truncated"])
            self.assertEqual(len(unbounded["matches"]), 300)

    def test_budget_seconds_come_from_environment(self) -> None:
        with mock.patch.dict(os.environ, {SCAN_BUDGET_ENV: "3.5"}):
            self.assertEqual(resolve_scan_budget_seconds(), 3.5)
        with mock.patch.dict(os.environ, {SCAN_BUDGET_ENV: "not-a-number"}):
            self.assertEqual(resolve_scan_budget_seconds(), DEFAULT_SCAN_BUDGET_SECONDS)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(SCAN_BUDGET_ENV, None)
            self.assertEqual(resolve_scan_budget_seconds(), DEFAULT_SCAN_BUDGET_SECONDS)
        self.assertEqual(resolve_scan_budget_seconds(7), 7.0)


class CandidateQueryTests(unittest.TestCase):
    def test_exact_terms_are_token_prefix_phrases_on_the_shortest_stem(self) -> None:
        self.assertEqual(keyword_candidate_term("powershell", mode="exact", fuzzy_distance=0), '"powershell"*')
        self.assertEqual(keyword_candidate_term("files", mode="exact", fuzzy_distance=0), '"file"*')
        self.assertEqual(
            keyword_candidate_term("c:\\windows\\system32", mode="exact", fuzzy_distance=0),
            '"c windows system32"*',
        )
        self.assertIsNone(keyword_candidate_term("***", mode="exact", fuzzy_distance=0))

    def test_fuzzy_terms_keep_the_first_half_of_the_word(self) -> None:
        self.assertEqual(keyword_candidate_term("powershel", mode="fuzzy", fuzzy_distance=1), '"power"*')

    def test_hangul_query_is_nfc(self) -> None:
        nfd = unicodedata.normalize("NFD", "진정서")
        self.assertEqual(keyword_candidate_term(nfd, mode="exact", fuzzy_distance=0), '"진정서"*')

    def test_regex_leading_literal(self) -> None:
        self.assertEqual(regex_leading_literal(r"\bpowershell\.exe"), "powershell")
        self.assertEqual(regex_leading_literal(r"^(?i)mimikatz"), "mimikatz")
        self.assertEqual(regex_leading_literal(r"powers?hell"), "power")
        self.assertIsNone(regex_leading_literal(r"[a-z]+\.exe"))
        self.assertIsNone(regex_leading_literal(r"cmd|powershell"))
        self.assertIsNone(build_candidate_query(["powershell", r"\d+"], mode="regex", fuzzy_distance=0))
        self.assertEqual(
            build_candidate_query(["powershell", "cmd"], mode="exact", fuzzy_distance=0),
            '"powershell"* OR "cmd"*',
        )


if __name__ == "__main__":
    unittest.main()
