from __future__ import annotations

import contextlib
import json
import sqlite3
import tempfile
import unicodedata
import unittest
from pathlib import Path

from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.case_db.helpers import build_fts_query, matched_keywords
from rapidtriage.core.docs import (
    build_preview,
    normalize_index_query_terms,
    query_docs_index,
    run_docs_search,
    search_docs_index_payload,
    tokenize_index_terms,
)
from rapidtriage.core.files import (
    normalize_text_filters,
    normalized_name_mismatch,
    normalized_path_mismatch,
    run_files_scan,
)
from rapidtriage.core.rules import _RuleEvaluator as RuleEvaluator
from rapidtriage.core.rules import build_context, load_rule_set, match_substrings
from rapidtriage.core.search import (
    build_keyword_match_plan,
    match_keywords,
    normalize_keywords,
)
from rapidtriage.core.textnorm import (
    locate_normalized,
    normalize_nfc,
    normalize_search_text,
)

KEYWORD = "진정서"
NFC_NAME = "진정서(배○현)_2024-005727.txt"
NFD_NAME = unicodedata.normalize("NFD", NFC_NAME)
NFC_BODY = "사건 진정서(배○현)_2024-005727 접수. 진정서 원본 첨부."
NFD_BODY = unicodedata.normalize("NFD", NFC_BODY)


def nfd(value: str) -> str:
    return unicodedata.normalize("NFD", value)


class NormalizeSearchTextTests(unittest.TestCase):
    def test_fixture_really_is_decomposed(self) -> None:
        self.assertNotEqual(NFD_NAME, NFC_NAME)
        self.assertGreater(len(NFD_NAME), len(NFC_NAME))
        self.assertNotIn(KEYWORD, NFD_BODY)
        self.assertNotIn(KEYWORD, NFD_BODY.lower())

    def test_nfd_and_nfc_korean_normalize_identically(self) -> None:
        self.assertEqual(normalize_search_text(nfd(KEYWORD)), KEYWORD)
        self.assertEqual(normalize_search_text(NFD_BODY), normalize_search_text(NFC_BODY))
        self.assertIn(normalize_search_text(KEYWORD), normalize_search_text(NFD_BODY))
        self.assertEqual(normalize_nfc(NFD_NAME), NFC_NAME)

    def test_full_casefold(self) -> None:
        self.assertEqual(normalize_search_text("Straße"), normalize_search_text("STRASSE"))
        self.assertIn(normalize_search_text("strasse"), normalize_search_text("Hauptstraße 5"))
        # Turkish dotted capital I: decomposed "I" + U+0307 composes to U+0130 under
        # NFC, and both fold to "i" + combining dot above.
        self.assertEqual(normalize_search_text("İstanbul"), normalize_search_text("İSTANBUL"))
        self.assertIn(normalize_search_text("İSTANBUL"), normalize_search_text("Flight to İstanbul"))
        self.assertEqual(normalize_search_text("ΣΊΣΥΦΟΣ"), normalize_search_text("σίσυφος"))

    def test_ascii_parity_with_lower(self) -> None:
        for value in ("", "Hello World", "C:\\Users\\Admin\\NTUSER.DAT", "MiXeD_123-./:@", "\t\nTAB"):
            self.assertEqual(normalize_search_text(value), value.lower())
            self.assertIs(normalize_nfc(value), value)

    def test_surrogate_escaped_names_do_not_raise(self) -> None:
        value = "name\udcff.txt"
        self.assertEqual(normalize_search_text(value), value)

    def test_locate_normalized_maps_length_changing_folds(self) -> None:
        text = "ß" * 100 + "TARGET" + "x" * 100
        display, start, end = locate_normalized(text, "target")
        self.assertEqual(display, text)
        self.assertEqual(display[start:end], "TARGET")
        located = locate_normalized(NFD_BODY, KEYWORD)
        assert located is not None
        display, start, end = located
        self.assertEqual(display, NFC_BODY)
        self.assertEqual(display[start:end], KEYWORD)
        self.assertIsNone(locate_normalized(NFD_BODY, "absent"))


class PreviewTests(unittest.TestCase):
    def test_korean_nfd_document_preview_is_centered_on_the_hit(self) -> None:
        prefix = nfd("서울특별시 강남구 " * 20)
        text = prefix + NFD_BODY + nfd(" 끝 " * 20)
        preview = build_preview(text, KEYWORD, radius=10)
        display = unicodedata.normalize("NFC", text)
        index = display.find(KEYWORD)
        self.assertEqual(preview, display[index - 10 : index + len(KEYWORD) + 10].strip())
        self.assertIn(KEYWORD, preview)
        # The raw NFD slice at NFC offsets would cut mid-syllable and miss the hit.
        self.assertNotIn(KEYWORD, normalize_nfc(text[index - 10 : index + len(KEYWORD) + 10]))

    def test_casefold_expansion_does_not_shift_preview(self) -> None:
        text = "ß" * 50 + " Evidence " + "y" * 50
        self.assertEqual(build_preview(text, "EVIDENCE", radius=3), "ßß Evidence yy")

    def test_ascii_preview_unchanged(self) -> None:
        text = "alpha beta Gamma delta"
        self.assertEqual(build_preview(text, "gamma", radius=5), "beta Gamma delt")
        self.assertEqual(build_preview(text, "missing", radius=3), "alpha")


class DocsSearchTests(unittest.TestCase):
    def test_docs_search_and_index_find_nfd_document_with_nfc_keyword(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            root.mkdir()
            nfd_file = root / NFD_NAME
            nfd_file.write_text(NFD_BODY, encoding="utf-8")
            (root / "other.txt").write_text("unrelated", encoding="utf-8")
            index_path = Path(tmp_dir) / "docs-index.json"

            payload = run_docs_search(root, [KEYWORD], index_output=index_path, manifest={})

            results = payload["results"]
            self.assertEqual(len(results), 1)
            self.assertEqual(Path(results[0]["path"]).name, NFD_NAME)  # original name kept
            self.assertEqual(results[0]["matched_keywords"], [KEYWORD])
            self.assertIn(KEYWORD, results[0]["preview"])

            index_payload = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(index_payload["version"], 2)
            self.assertEqual(index_payload["analyzer"]["unicode_normalization"], "NFC")
            self.assertIn(KEYWORD, index_payload["terms"])
            for keyword in (KEYWORD, nfd(KEYWORD)):
                query = query_docs_index(index_path, [keyword])
                self.assertEqual(query["query"]["terms"], [KEYWORD])
                self.assertEqual([Path(item["path"]).name for item in query["results"]], [NFD_NAME])

    def test_index_and_query_tokenizers_agree(self) -> None:
        self.assertEqual(tokenize_index_terms(NFD_BODY), tokenize_index_terms(NFC_BODY))
        self.assertIn(KEYWORD, tokenize_index_terms(NFD_BODY))
        self.assertEqual(normalize_index_query_terms([nfd(KEYWORD)]), [KEYWORD])
        self.assertEqual(normalize_index_query_terms(["STRASSE"]), normalize_index_query_terms(["straße"]))
        self.assertEqual(tokenize_index_terms("Incident ALPHA https://Example.test/x"), ["incident", "alpha", "https://example.test/x"])

    def test_version_one_index_still_loads_and_queries_normalize(self) -> None:
        legacy = {
            "command": "docs-index",
            "version": 1,
            "strategy": "processed-text-inverted-index",
            "documents": [{"id": 0, "path": "/e/a.txt", "kind": "txt"}],
            "terms": {KEYWORD: [{"document_id": 0, "count": 1}]},
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            index_path = Path(tmp_dir) / "legacy.json"
            index_path.write_text(json.dumps(legacy, ensure_ascii=False), encoding="utf-8")
            result = query_docs_index(index_path, [nfd(KEYWORD)])
        self.assertEqual(result["index_version"], 1)
        self.assertEqual(result["summary"]["matched_document_count"], 1)
        self.assertEqual(search_docs_index_payload(legacy, [KEYWORD])["summary"]["matched_document_count"], 1)


class UnifiedSearchMatchingTests(unittest.TestCase):
    def test_exact_fuzzy_and_regex_modes_match_nfd_text(self) -> None:
        for mode in ("exact", "fuzzy", "regex"):
            keywords = normalize_keywords([KEYWORD], search_mode=mode)
            plan = build_keyword_match_plan(keywords, search_options={"search_mode": mode})
            self.assertEqual(match_keywords(NFD_BODY, keywords, plan=plan), [KEYWORD], mode)

    def test_regex_keeps_escapes_and_matches_normalized_haystack(self) -> None:
        keywords = normalize_keywords([r"\d{4}-\d{6}", r"진정서\(배"], search_mode="regex")
        self.assertEqual(keywords, [r"\d{4}-\d{6}", r"진정서\(배"])
        plan = build_keyword_match_plan(keywords, search_options={"search_mode": "regex"})
        self.assertEqual(match_keywords(NFD_BODY, keywords, plan=plan), keywords)

    def test_casefold_and_ascii_parity(self) -> None:
        keywords = normalize_keywords(["STRASSE", "Alpha"], search_mode="exact")
        self.assertEqual(keywords, ["strasse", "alpha"])
        plan = build_keyword_match_plan(keywords, search_options={"search_mode": "exact"})
        self.assertEqual(match_keywords("Hauptstraße ALPHA", keywords, plan=plan), ["strasse", "alpha"])


class RuleMatchingTests(unittest.TestCase):
    def _rule_set(self, tmp_dir: str, name: str, body: str):
        path = Path(tmp_dir) / name
        path.write_text(body, encoding="utf-8")
        return load_rule_set(path)

    def test_json_rule_keyword_and_path_terms_match_nfd_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            rule_set = self._rule_set(
                tmp_dir,
                "rules.json",
                json.dumps(
                    {"rules": [{"id": "petition", "keywords": [KEYWORD], "path_contains": [KEYWORD]}]},
                    ensure_ascii=False,
                ),
            )
        context = build_context(path=f"/Users/a/{NFD_NAME}", extension=".txt", text_values=[NFD_BODY])
        matched_rules, hits = RuleEvaluator(rule_set).evaluate_context(context)
        self.assertEqual(matched_rules, ["petition"])
        self.assertEqual(hits, [{"rule_id": "petition", "type": "keyword", "value": KEYWORD}])

    def test_yara_lite_strings_match_nfd_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            rule_set = self._rule_set(
                tmp_dir,
                "rules.yar",
                'rule Petition {\n  strings:\n    $a = "진정서"\n    $b = "STRASSE"\n  condition:\n    any of them\n}\n',
            )
        evaluator = RuleEvaluator(rule_set)
        korean = evaluator.evaluate_context(build_context(path="/x.txt", extension=".txt", text_values=[NFD_BODY]))
        german = evaluator.evaluate_context(build_context(path="/y.txt", extension=".txt", text_values=["Straße"]))
        self.assertEqual(korean[0], ["Petition"])
        self.assertEqual(german[0], ["Petition"])

    def test_match_substrings_reports_original_needle(self) -> None:
        haystacks = [normalize_search_text(NFD_BODY)]
        self.assertEqual(match_substrings([nfd(KEYWORD), "absent"], haystacks), [nfd(KEYWORD)])


class FileFilterTests(unittest.TestCase):
    def test_name_and_path_filters_match_nfd_names(self) -> None:
        filters = normalize_text_filters([KEYWORD, ""])
        self.assertEqual(filters, [KEYWORD])
        self.assertFalse(normalized_name_mismatch(NFD_NAME, filters))
        self.assertFalse(normalized_path_mismatch(f"/Users/a/{NFD_NAME}", normalize_text_filters([nfd(KEYWORD)])))
        self.assertTrue(normalized_name_mismatch("other.txt", filters))
        self.assertFalse(normalized_name_mismatch("REPORT.TXT", normalize_text_filters(["Report"])))

    def test_files_scan_name_filter_finds_nfd_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / NFD_NAME).write_text("x", encoding="utf-8")
            (root / "notes.txt").write_text("y", encoding="utf-8")
            payload = run_files_scan(root, categories=["documents"], name_contains=[KEYWORD])
        names = [Path(str(item["path"])).name for item in payload["candidates"]]
        self.assertEqual(names, [NFD_NAME])


class CaseDbFtsTests(unittest.TestCase):
    def test_fts_insert_and_query_round_trip_with_nfd_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            evidence = tmp / "evidence"
            evidence.mkdir()
            doc_path = evidence / NFD_NAME
            doc_path.write_text(NFD_BODY, encoding="utf-8")
            outputs = {
                "docs": tmp / "docs.json",
                "files": tmp / "files.json",
                "timeline": tmp / "timeline.json",
            }
            outputs["docs"].write_text(
                json.dumps({"candidates": [{"path": str(doc_path), "kind": "txt"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            outputs["files"].write_text(
                json.dumps({"candidates": [{"path": str(doc_path), "extension": ".txt"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            outputs["timeline"].write_text(
                json.dumps(
                    {
                        "events": [
                            {
                                "timestamp": "2024-05-01T00:00:00+00:00",
                                "event_type": "file-modified",
                                "path": str(doc_path),
                                "summary": NFD_BODY,
                                "source": "files",
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            db_path = tmp / "case.db"
            database = open_case_database(db_path)
            database.create_case(case_id="CASE-NFD")
            source_id = database._insert_evidence_source("CASE-NFD", {"root": str(evidence)})
            self.assertEqual(database._import_docs("CASE-NFD", source_id, outputs), 1)
            self.assertEqual(database._import_files("CASE-NFD", source_id, outputs), 1)
            self.assertEqual(database._import_timeline("CASE-NFD", source_id, outputs), 1)

            query = build_fts_query([nfd(KEYWORD)])
            self.assertEqual(query, f'"{KEYWORD}"')

            def fts_hits(connection: sqlite3.Connection) -> dict[str, int]:
                return {
                    table: connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {table} MATCH ?", (query,)
                    ).fetchone()[0]
                    for table in ("indexed_document_fts", "file_record_fts", "event_fts")
                }

            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                self.assertEqual(
                    fts_hits(connection),
                    {"indexed_document_fts": 1, "file_record_fts": 1, "event_fts": 1},
                )
                # Evidence-derived source rows keep their original (NFD) values.
                stored_path = connection.execute("SELECT path FROM file_record").fetchone()[0]
                stored_target = connection.execute("SELECT target FROM event").fetchone()[0]
                self.assertEqual(stored_path, str(doc_path))
                self.assertEqual(stored_target, str(doc_path))
                # indexed_document is the FTS content table: stored NFC.
                title = connection.execute("SELECT title FROM indexed_document").fetchone()[0]
                self.assertEqual(title, NFC_NAME)

            payload = database.search_case(case_id="CASE-NFD", keywords=[KEYWORD])
            sources = sorted({str(item["source"]) for item in payload["matches"]})
            self.assertEqual(sources, ["documents", "files", "timeline"])
            for item in payload["matches"]:
                self.assertEqual(item["matched_keywords"], [KEYWORD], item["source"])
            documents = [item for item in payload["matches"] if item["source"] == "documents"]
            self.assertIn(f"[{KEYWORD}]", documents[0]["preview"])

            database.rebuild_search_indexes("CASE-NFD")
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                self.assertEqual(
                    fts_hits(connection),
                    {"indexed_document_fts": 1, "file_record_fts": 1, "event_fts": 1},
                )

    def test_matched_keywords_normalizes_both_sides(self) -> None:
        self.assertEqual(matched_keywords(NFD_BODY, [KEYWORD, "Absent"]), [KEYWORD])
        self.assertEqual(matched_keywords("Hauptstraße", ["STRASSE"]), ["STRASSE"])
        self.assertEqual(matched_keywords("Password=1", ["PASSWORD"]), ["PASSWORD"])


if __name__ == "__main__":
    unittest.main()
