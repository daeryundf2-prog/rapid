"""R7 lane B: entity patterns (known-answer set, masks, normalization, ReDoS guard, cut safety)."""

from __future__ import annotations

import importlib.util
import json
import re
import time
import unittest
from pathlib import Path

from rapidtriage.core.search_index import patterns
from rapidtriage.core.search_index.build import cut_text
from rapidtriage.core.search_index.patterns import (
    ENTITY_RULE,
    entity_sha256,
    find_entities,
    mask_sensitive,
    mask_text,
    parse_entity_value,
    whole_entity,
)
from rapidtriage.core.search_index.regex_guard import analyze_regex

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "entity_known_answer"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_known_answer", FIXTURE_DIR / "generate_known_answer.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def kinds_of(text: str) -> list[tuple[str, bool]]:
    return [(entity.kind, entity.verified) for entity in find_entities(text)]


class KnownAnswerTests(unittest.TestCase):
    """300 synthetic values: true >= 99 % verified as their kind, false positives <= 1 %."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.generator = load_generator()
        cls.items = json.loads((FIXTURE_DIR / "known_answer.json").read_text(encoding="utf-8"))["items"]

    def test_fixture_is_synthetic_and_reproducible(self) -> None:
        self.assertEqual((FIXTURE_DIR / "known_answer.json").read_text(encoding="utf-8"), self.generator.render())
        self.assertEqual(len(self.items), 300)
        sets = {name: [item for item in self.items if item["set"] == name] for name in ("true", "check-fail", "look-alike")}
        self.assertEqual({name: len(values) for name, values in sets.items()}, {"true": 100, "check-fail": 100, "look-alike": 100})
        payload = json.loads((FIXTURE_DIR / "known_answer.json").read_text(encoding="utf-8"))
        self.assertTrue(payload["synthetic"])

    def test_true_values_verified(self) -> None:
        hits = 0
        for item in self.items:
            if item["set"] != "true":
                continue
            found = [entity for entity in find_entities(f"값: {item['value']} 끝") if entity.verified and entity.kind == item["kind"]]
            hits += bool(found)
        self.assertGreaterEqual(hits / 100, 0.99, hits)

    def test_false_positives(self) -> None:
        verified = 0
        extracted_look_alikes = 0
        for item in self.items:
            if item["set"] == "true":
                continue
            found = find_entities(f"값: {item['value']} 끝")
            verified += any(entity.verified for entity in found)
            if item["set"] == "look-alike":
                extracted_look_alikes += bool(found)
        self.assertLessEqual(verified / 200, 0.01, verified)
        self.assertLessEqual(extracted_look_alikes / 100, 0.01, extracted_look_alikes)

    def test_check_failures_are_candidates_never_verified(self) -> None:
        for item in self.items:
            if item["set"] != "check-fail":
                continue
            found = find_entities(item["value"])
            self.assertFalse(any(entity.verified for entity in found), item)
            if item["kind"] in {"card", "corpno"}:
                self.assertEqual(found, [], item)  # Luhn / 법인 check failures are not entities at all


class PatternTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gen = load_generator()
        import random

        self.rng = random.Random(99)

    def test_masks(self) -> None:
        rrn = self.gen.rrn(self.rng, valid=True)
        card = self.gen.card(self.rng, valid=True)
        found = find_entities(f"주민 {rrn} / 카드 {card} / 010-2345-6789 / 02-345-6789 / kim.gil@naver.com")
        masks = {entity.kind: entity.masked for entity in found}
        self.assertRegex(masks["rrn"], r"^\d{6}-[1-8]\*{6}$")
        self.assertEqual(masks["rrn"][:8], rrn[:8])
        self.assertRegex(masks["card"], r"^\*{4} \*{4} \*{4} \d{4}$")
        self.assertEqual(masks["email"], "k***@naver.com")
        phones = [entity.masked for entity in found if entity.kind == "phone"]
        self.assertEqual(phones, ["010-****-6789", "02-****-6789"])
        masked = mask_text(f"주민 {rrn} 끝", find_entities(f"주민 {rrn} 끝"))
        self.assertNotIn(rrn, masked)
        self.assertNotIn(rrn[7:], masked)

    def test_phone_forms_normalize_to_e164(self) -> None:
        for text in ("010-2345-6789", "01023456789", "010 2345 6789", "+82 10-2345-6789", "+82-10-2345-6789", "+821023456789"):
            found = [entity for entity in find_entities(f"tel {text} end") if entity.kind == "phone"]
            self.assertEqual(len(found), 1, text)
            self.assertEqual(found[0].normalized, "+821023456789", text)
        self.assertEqual(parse_entity_value("phone", "010-2345-6789"), "+821023456789")
        self.assertEqual(parse_entity_value("phone", "+82 10 2345 6789"), "+821023456789")
        landline = [entity for entity in find_entities("tel 031-123-4567 / 070-1234-5678") if entity.kind == "phone"]
        self.assertEqual([entity.normalized for entity in landline], ["+82311234567", "+827012345678"])
        self.assertEqual(kinds_of("0311234567"), [])  # a landline needs separators
        self.assertEqual(kinds_of("012-345-6789"), [])

    def test_accounts_are_low_confidence(self) -> None:
        for text in ("123456-78-901234", "110-123-456789", "1002-123-456789", "3333-01-1234567", "352-1234-5678-91"):
            found = find_entities(f"계좌 {text}")
            self.assertEqual([(entity.kind, entity.verified) for entity in found], [("account", False)], text)
        self.assertEqual(kinds_of("1234-01-1234567"), [])  # 4-2-7 only with a 카카오뱅크 prefix
        self.assertEqual(find_entities("계좌 110-123-456789")[0].masked, "***-***-**6789")

    def test_bizno_requires_hyphens(self) -> None:
        value = self.gen.bizno(self.rng, valid=True)
        self.assertEqual(kinds_of(value), [("bizno", True)])
        self.assertEqual(kinds_of(value.replace("-", "")), [])  # bare 10 digits: mostly Unix times
        self.assertEqual(find_entities(value)[0].masked, value[:7] + "*****")

    def test_corpno_vs_rrn(self) -> None:
        corp = self.gen.corpno(self.rng, valid=True)
        self.assertEqual(kinds_of(corp), [("corpno", True)])
        self.assertTrue(find_entities(corp)[0].masked.endswith("-*******"))
        rrn = self.gen.rrn(self.rng, valid=True)
        self.assertEqual(kinds_of(rrn.replace("-", "")), [("rrn", True)])

    def test_passport_email_ip_host(self) -> None:
        found = find_entities("여권 M12345678, 신여권 M123A4567, 메일 a.b+c@sub.example.co.kr")
        self.assertEqual([(entity.kind, entity.masked) for entity in found], [("passport", "M****5678"), ("passport", "M****4567"), ("email", "a***@sub.example.co.kr")])
        found = find_entities("접속 10.1.2.3, 192.168.0.0/16, fe80::1%eth0, https://user@files.example.com:8443/x, www.naver.com.")
        self.assertEqual(
            [(entity.kind, entity.normalized) for entity in found],
            [("ip", "10.1.2.3"), ("ip", "192.168.0.0/16"), ("ip", "fe80::1"), ("host", "files.example.com"), ("host", "www.naver.com")],
        )
        self.assertTrue(found[0].net.startswith("4:"))
        for text in ("10.0.19041.1", "999.1.1.1", "C:\\Windows\\setup.com", "report.docx", "v1.2.3"):
            self.assertEqual(kinds_of(text), [], text)

    def test_ip_and_host_are_not_masked(self) -> None:
        text = "from 10.1.2.3 via www.example.com to kim@naver.com"
        self.assertEqual(mask_sensitive(text), "from 10.1.2.3 via www.example.com to k***@naver.com")

    def test_whole_entity_and_hash(self) -> None:
        rrn = self.gen.rrn(self.rng, valid=True)
        entity = whole_entity(rrn)
        assert entity is not None
        self.assertEqual(entity.kind, "rrn")
        self.assertIsNone(whole_entity(f"{rrn} 외"))
        self.assertEqual(len(entity_sha256("rrn", entity.normalized)), 32)
        self.assertNotEqual(entity_sha256("rrn", entity.normalized), entity_sha256("corpno", entity.normalized))
        self.assertEqual(ENTITY_RULE, "entities-v1")

    def test_boundaries(self) -> None:
        card = self.gen.card(self.rng, valid=True).replace(" ", "").replace("-", "")
        self.assertEqual(kinds_of(f"a{card}"), [])  # inside a word / hex hash
        self.assertEqual(kinds_of(f"{card}0"), [])  # inside a longer number
        self.assertEqual(kinds_of(f"1.{card}"), [])  # a decimal
        rrn = self.gen.rrn(self.rng, valid=True)
        self.assertEqual(kinds_of(f"주민번호:{rrn}"), [("rrn", True)])
        self.assertEqual(kinds_of(f"주민번호({rrn})"), [("rrn", True)])
        self.assertEqual(kinds_of(f"1234567 {rrn}"), [("rrn", True)])  # space-joined pieces


class GuardTests(unittest.TestCase):
    def test_patterns_pass_the_regex_guard(self) -> None:
        for name, pattern in patterns.ALL_PATTERNS.items():
            with self.subTest(name=name):
                analyze_regex(pattern.pattern, ignorecase=bool(pattern.flags & re.IGNORECASE))

    def test_adversarial_rows_are_linear(self) -> None:
        rows = [
            "1-" * 200_000,
            "1 " * 200_000,
            "9" * 400_000,
            "a" * 400_000 + "@",
            "a." * 200_000 + "com",
            ":" * 400_000,
            "0:" * 200_000,
            "1." * 200_000,
            ("010-1234-5678 " * 30_000),
        ]
        for row in rows:
            started = time.perf_counter()
            find_entities(row)
            mask_sensitive(row)
            self.assertLess(time.perf_counter() - started, 3.0, row[:20])

    def test_scan_cap_bounds_a_row(self) -> None:
        row = "010-1234-5678 " * 50_000
        self.assertLessEqual(len(find_entities(row)), patterns.SCAN_CAP)


class CutTests(unittest.TestCase):
    def test_cut_drops_the_split_token(self) -> None:
        text = "주민 901010-1234567 끝"
        cut = cut_text(text, len("주민 901010-12"))
        self.assertEqual(cut, "주민 ")
        card = "4111 1111 1111 1111"
        self.assertEqual(cut_text(f"카드 {card} 끝", len("카드 4111 1111 11")), "카드 ")
        self.assertEqual(cut_text("abc def", 5), "abc ")
        self.assertEqual(cut_text("abc def", 4), "abc ")
        self.assertEqual(cut_text("short", 10), "short")
        self.assertEqual(cut_text("메일 kim@naver.com 끝", len("메일 kim@na")), "메일 ")


if __name__ == "__main__":
    unittest.main()
