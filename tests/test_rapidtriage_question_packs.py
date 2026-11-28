"""질문 팩 카탈로그 계약 (core/question_packs.py)."""

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.keyword_packs import BUILTIN_KEYWORD_PACKS
from rapidtriage.core.question_packs import (
    QuestionPackError,
    load_question_packs,
    normalize_question_pack,
    question_pack_catalog,
    question_packs_from_payload,
    read_question_pack_file,
)


class QuestionPackCatalogTest(unittest.TestCase):
    def test_builtin_catalog_is_consistent(self) -> None:
        catalog = question_pack_catalog()
        packs = catalog["packs"]
        ids = [pack["id"] for pack in packs]
        self.assertEqual(len(ids), len(set(ids)), "질문 id 는 유일해야 한다")
        self.assertEqual(catalog["pack_count"], len(packs))
        self.assertTrue(catalog["categories"])
        self.assertEqual(catalog["custom_count"], 0)
        for pack in packs:
            self.assertTrue(pack["question"].strip(), pack["id"])
            self.assertTrue(pack["collections"], pack["id"])
            for name in pack["keyword_packs"]:
                self.assertIn(name, BUILTIN_KEYWORD_PACKS, pack["id"])

    def test_keyword_packs_expand_into_the_search_terms(self) -> None:
        pack = normalize_question_pack(
            {
                "id": "q-expand",
                "question": "유출 기록 있나?",
                "keyword_packs": ["exfiltration"],
                "keywords": ["대외비", "MEGA.NZ"],
                "event_ids": [4624],
            },
            source_ref="test",
        )
        expanded = pack["expanded_keywords"]
        self.assertIn("mega.nz", expanded)
        self.assertIn("대외비", expanded)
        self.assertIn("4624", expanded)
        # mega.nz came from the pack; the case-different repeat is not added twice.
        self.assertEqual(sum(1 for value in expanded if value.casefold() == "mega.nz"), 1)
        self.assertEqual(pack["keyword_count"], len(expanded))

    def test_unknown_keyword_pack_or_collection_is_refused(self) -> None:
        with self.assertRaises(QuestionPackError):
            normalize_question_pack(
                {"id": "q", "question": "?", "keyword_packs": ["없는팩"]}, source_ref="test"
            )
        with self.assertRaises(QuestionPackError):
            normalize_question_pack(
                {"id": "q", "question": "?", "collections": ["없는화면"]}, source_ref="test"
            )
        with self.assertRaises(QuestionPackError):
            normalize_question_pack({"question": "id 없음"}, source_ref="test")

    def test_user_file_adds_and_overrides_by_id(self) -> None:
        builtin = {pack["id"]: pack for pack in load_question_packs()}
        target = next(iter(builtin))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case-packs.json"
            path.write_text(
                json.dumps(
                    {
                        "packs": [
                            {"id": target, "question": "사건용으로 바꾼 질문", "keywords": ["교체"]},
                            {"id": "case-only", "question": "이 사건 전용 질문", "keywords": ["전용"]},
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            packs = {pack["id"]: pack for pack in load_question_packs([path])}
        self.assertEqual(packs[target]["question"], "사건용으로 바꾼 질문")
        self.assertEqual(packs[target]["source_ref"], str(path))
        self.assertIn("case-only", packs)
        self.assertEqual(len(packs), len(builtin) + 1)

    def test_other_tools_keyword_list_export_becomes_questions(self) -> None:
        rows = question_packs_from_payload({"유출 의심 단어": ["mega.nz", "대외비"]}, origin="autopsy")
        self.assertEqual(len(rows), 1)
        pack = normalize_question_pack(rows[0], source_ref="autopsy.json")
        self.assertEqual(pack["question"], "유출 의심 단어")
        self.assertEqual(pack["category"], "가져온 목록")
        self.assertIn("mega.nz", pack["expanded_keywords"])
        self.assertIn("imported:autopsy", pack["references"])

    def test_broken_file_names_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(QuestionPackError) as caught:
                read_question_pack_file(path)
            self.assertIn(str(path), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
