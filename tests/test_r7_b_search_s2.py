"""R7 lane B: entity search fields, masking, reveal + audit, lists, languages, ordered proximity,
hash-set categories (QA Q-B1–Q-B7 on a synthetic run; no real number anywhere)."""

from __future__ import annotations

import importlib.util
import json
import os
import random
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.analyses import ANALYSIS_RUNNER
    from rapidtriage.api.app.search_index_service import SEARCH_HISTORY

    HAS_FASTAPI = True
except (ImportError, RuntimeError):  # pragma: no cover
    # starlette.testclient raises RuntimeError (not ImportError) when httpx is missing. The E2E
    # entity-search spec imports build_entity_run from here in a `.[web]`-only environment.
    HAS_FASTAPI = False

from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.search_index.build import build_search_index, stale_reasons
from rapidtriage.core.search_index.engine import Budget, QueryRequest, run_query
from rapidtriage.core.search_index.hashsets import DATA_DIR_ENV
from rapidtriage.core.search_index.patterns import ROW_CAP
from rapidtriage.core.search_index.query import QueryError
from rapidtriage.core.search_index.schema import INDEX_FILE_NAME, INDEX_VERSION
from tests.search_index_fixture import build_fixture_run, write_analysis, write_kind

TOKEN = "r7-b-token"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "entity_known_answer"


def _generator():
    spec = importlib.util.spec_from_file_location("generate_known_answer", FIXTURE_DIR / "generate_known_answer.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_values() -> dict[str, str]:
    """Made-up values with valid check digits (seeded; never a real number)."""
    gen = _generator()
    rng = random.Random(4242)
    return {
        "rrn": gen.rrn(rng, valid=True),
        "rrn_candidate": gen.rrn(rng, valid=False),
        "card": gen.card(rng, valid=True),
        "card_mail": gen.card(rng, valid=True),
        "bizno": gen.bizno(rng, valid=True),
        "phone": f"010-{rng.randint(2000, 9999)}-{rng.randint(1000, 9999)}",
        "phone_mail": f"010-{rng.randint(2000, 9999)}-{rng.randint(1000, 9999)}",
        "account": f"110-{rng.randint(100, 999)}-{rng.randint(100000, 999999)}",
        "passport": f"M{rng.randint(10_000_000, 99_999_999)}",
        "email": f"gil{rng.randint(1000, 9999)}@naver.com",
    }


def raw_forms(values: dict[str, str]) -> list[str]:
    """Every raw value and its digits-only form (the email local part too)."""
    forms: set[str] = set()
    for key, value in values.items():
        forms.add(value)
        digits = "".join(char for char in value if char.isdigit())
        if key != "email" and len(digits) >= 8:
            forms.add(digits)
        if key == "email":
            forms.add(value.split("@")[0])
    return sorted(forms)


def build_entity_run(base: Path) -> dict[str, object]:
    fixture = build_fixture_run(base)
    run_dir = Path(fixture["run_dir"])
    evidence = Path(fixture["evidence"])
    values = synthetic_values()
    texts = {
        "개인정보목록.txt": (
            f"직원 연락처 목록입니다. 홍길동 주민등록번호 {values['rrn']} 휴대폰 {values['phone']} 메일 {values['email']} "
            f"사업자 {values['bizno']} 계좌 {values['account']} 여권 {values['passport']}. 회사는 계약을 즉시 해지한다고 통보했다."
        ),
        "신규등록.txt": f"신규 등록 대상자 번호 {values['rrn_candidate']} 입니다. 해지 후 계약을 다시 맺는다.",
        "japanese.txt": f"契約の解除についてお知らせします。カード番号 {values['card']} をご確認ください。よろしくお願いします。",
        "english.txt": "Please review the termination notice and the attached contract before Friday. Regards, the legal team.",
    }
    docs_path = Path(fixture["summary"]["outputs"]["docs"])
    docs = json.loads(docs_path.read_text(encoding="utf-8"))
    for name, text in texts.items():
        path = evidence / "Users" / "bsh" / "Desktop" / name
        path.write_text(text, encoding="utf-8")
        docs["candidates"].append({"path": str(path), "kind": "txt", "size": len(text.encode()), "text_status": "ok", "matched": False})
    docs_path.write_text(json.dumps(docs, ensure_ascii=False), encoding="utf-8")
    mails = [
        {
            "provider": "email", "artifact_type": "email-message", "path": str(evidence / "mail.pst"),
            "details": {"from": "sender.kim@naver.com", "to": "billing@company.example.com", "subject": "결제 안내",
                        "body": f"고객님 카드번호 {values['card_mail']} 결제 내역을 보내드립니다. 문의 {values['phone_mail']} 로 연락 주세요."},
        },
        {
            "provider": "email", "artifact_type": "email-message", "path": str(evidence / "mail.pst"),
            "details": {"from": "news@gmail.com", "to": "team@company.example.com", "subject": "주간 소식",
                        "body": "이번 주 소식을 전해 드립니다. 접속 기록 192.168.10.20 에서 https://evil.example.com/login 으로 연결되었습니다."},
        },
    ]
    summary = dict(fixture["summary"])
    outputs = dict(summary["outputs"])
    outputs["artifacts_email"] = str(write_kind(run_dir, "email", mails))
    summary["outputs"] = outputs
    Path(fixture["summary_path"]).write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
    fixture["summary"] = summary
    fixture["values"] = values
    return fixture


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for search API tests")
class EntitySearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        cls.env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data")})
        cls.env.start()
        cls.fixture = build_entity_run(base)
        cls.run_dir = Path(cls.fixture["run_dir"])
        cls.values = cls.fixture["values"]
        cls.raw = raw_forms(cls.values)
        cls.build = build_search_index(cls.run_dir, cls.fixture["summary"], run_id="r7b")
        cls.store = RunJobStore()
        cls.run_id = cls.store.import_completed_run(cls.run_dir).run_id
        cls.app = create_app(cls.store, auth_token=TOKEN)
        cls.client = TestClient(cls.app, headers={"X-RapidTriage-Token": TOKEN})

    @classmethod
    def tearDownClass(cls) -> None:
        SEARCH_HISTORY.flush()
        ANALYSIS_RUNNER.shutdown(owner=cls.app.state.analysis_owner)
        cls.env.stop()
        cls.temp.cleanup()

    # -- helpers ------------------------------------------------------------

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def assert_no_raw(self, text: str) -> None:
        for raw in self.raw:
            self.assertNotIn(raw, text, "a raw synthetic value leaked")

    def post(self, suffix: str, body: dict[str, object], status: int = 200) -> dict:
        response = self.client.post(self.url(suffix), json=body)
        self.assertEqual(response.status_code, status, response.text)
        self.assert_no_raw(response.text)
        return response.json()

    def query(self, q: str, **body: object) -> dict:
        return self.post("/search/query", {"q": q, **body})

    def titles(self, result: dict) -> list[str]:
        return sorted(str(row["title"]) for row in result["rows"])

    def ensure_case_db(self) -> Path:
        database = self.run_dir / "rapidtriage-case.db"
        if not database.exists():
            open_case_database(database).create_case(case_id=f"run-{self.run_id}", name="r7 b")
        return database

    # -- index ----------------------------------------------------------------

    def test_index_is_v5_and_holds_no_raw_value(self) -> None:
        index = self.run_dir / INDEX_FILE_NAME
        blob = index.read_bytes()
        for raw in self.raw:
            self.assertNotIn(raw.encode("utf-8"), blob, raw[:3])
        connection = sqlite3.connect(index)
        try:
            meta = dict(connection.execute("SELECT key, value FROM search_meta"))
            self.assertEqual(meta["index_version"], INDEX_VERSION)
            self.assertEqual(meta["entities"], "entities-v1")
            kinds = dict(connection.execute("SELECT kind, COUNT(*) FROM search_entity_value GROUP BY kind"))
            for kind in ("rrn", "card", "bizno", "phone", "account", "passport", "email", "ip", "host"):
                self.assertGreater(kinds.get(kind, 0), 0, kind)
            for (sha,) in connection.execute("SELECT value_sha256 FROM search_entity_value"):
                self.assertEqual(len(sha), 32)
            text = "\n".join(row[0] for row in connection.execute("SELECT text FROM search_doc WHERE text IS NOT NULL"))
            self.assertIn(self.values["rrn"][:8] + "******", text)  # the mask stands in the text
            pii = connection.execute("SELECT MAX(pii_count) FROM search_doc").fetchone()[0]
            self.assertGreaterEqual(pii, 6)
        finally:
            connection.close()
        self.assertEqual(self.build["entities"]["rule"], "entities-v1")
        self.assertIn("ko", self.build["entities"]["languages"])

    # -- Q-B1 .. Q-B7 ---------------------------------------------------------

    def test_qb1_rrn_verified_in_docs(self) -> None:
        verified = self.query("rrn:verified in:docs")
        self.assertEqual(self.titles(verified), ["개인정보목록.txt"])
        row = verified["rows"][0]
        self.assertEqual(row["pii"]["rrn"], 1)
        self.assertIn(self.values["rrn"][:8] + "******", row["masked_preview"])
        kinds = {item["kind"] for item in row["entities"]}
        self.assertTrue({"rrn", "phone", "email", "bizno", "account", "passport"} <= kinds)
        self.assertEqual(self.titles(self.query("rrn:* in:docs")), ["개인정보목록.txt", "신규등록.txt"])
        self.assertEqual(self.titles(self.query("rrn:candidate")), ["신규등록.txt"])
        prefix = self.values["rrn"][:6]
        self.assertIn("개인정보목록.txt", self.titles(self.query(f"rrn:{prefix}")))
        self.assertIn("개인정보목록.txt", self.titles(self.query(f"rrn:{prefix}*")))

    def test_qb2_card_and_email_domain(self) -> None:
        both = self.query("card:* email:@naver.com")
        self.assertEqual([row["artifact_type"] for row in both["rows"]], ["email-message"])
        cards = self.query("card:*")
        naver = self.query("email:@naver.com")
        self.assertEqual(cards["page"]["total"], 2)
        facet = {item["key"]: item["count"] for item in naver["facets"]["entities"]}
        self.assertEqual(facet["card"], 1)
        self.assertEqual(facet["email"], naver["page"]["total"])
        self.assertEqual(self.query("card:verified")["page"]["total"], 2)
        last4 = "".join(char for char in self.values["card"] if char.isdigit())[-4:]
        self.assertEqual(self.titles(self.query(f"card:{last4}")), ["japanese.txt"])

    def test_exact_values_and_keyword_rewrite(self) -> None:
        phone = self.values["phone"]
        for q in (f"phone:{phone}", f'"{phone}"', phone, f"phone:{phone.replace('-', '')}"):
            result = self.query(q)
            self.assertEqual(self.titles(result), ["개인정보목록.txt"], q)
            self.assertNotIn(phone, result["query"]["raw"])
        result = self.query(f"bizno:{self.values['bizno']}")
        self.assertEqual(self.titles(result), ["개인정보목록.txt"])
        self.assertEqual(result["query"]["parsed"]["clauses"][0]["display"], "bizno:" + self.values["bizno"][:7] + "*****")
        self.assertEqual(self.titles(self.query(f"email:{self.values['email']}")), ["개인정보목록.txt"])
        self.assertEqual(self.query("ip:10.0.0.0/8")["page"]["total"], 1)
        self.assertEqual(self.query("ip:192.168.0.0/16")["page"]["total"], 1)
        # evil.example.com (company.example.com is only the domain of e-mail addresses)
        self.assertEqual(self.query("host:example.com")["page"]["total"], 1)
        response = self.client.post(self.url("/search/query"), json={"q": "rrn:12"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("주민등록번호", response.json()["detail"])

    def test_console_field_tokens_and_keyword_echo(self) -> None:
        result = self.post("/search/query", {"keywords": ["rrn:verified"], "aggregates": False, "facets": False})
        self.assertEqual([hit["title"] for hit in result["matches"]], ["개인정보목록.txt"])
        result = self.post("/search/query", {"keywords": [self.values["phone"]], "aggregates": False, "facets": False})
        self.assertEqual(len(result["matches"]), 1)
        self.assertNotIn(self.values["phone"], json.dumps(result["keywords"], ensure_ascii=False))
        result = self.post("/search/query", {"keywords": ["계약", "lang:ko"], "aggregates": False, "facets": False})
        self.assertTrue(result["matches"])

    def test_qb3_reveal_audit_and_switch(self) -> None:
        row = self.query("rrn:verified in:docs")["rows"][0]
        entity = next(item for item in row["entities"] if item["kind"] == "rrn")
        body = {"collection": row["collection"], "kind": row["kind"], "locator": row["locator"], "value_sha256": entity["value_sha256"], "reason": "수사 협조"}
        database = self.run_dir / "rapidtriage-case.db"
        if database.exists():
            database.unlink()
        response = self.client.post(self.url("/search/entities/reveal"), json=body)
        self.assertEqual(response.status_code, 409)
        self.assertIn("케이스 DB", response.json()["detail"])
        self.ensure_case_db()
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_PII_REVEAL": "off"}):
            response = self.client.post(self.url("/search/entities/reveal"), json=body)
        self.assertEqual(response.status_code, 403)
        self.assertIn("꺼져 있습니다", response.json()["detail"])
        before = self.audit_rows()
        response = self.client.post(self.url("/search/entities/reveal"), json=body)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get("cache-control"), "no-store")
        payload = response.json()
        self.assertEqual(payload["value"], self.values["rrn"])
        self.assertEqual(response.text.count(self.values["rrn"]), 1)  # the value once
        after = self.audit_rows()
        self.assertEqual(len(after), len(before) + 1)
        audit = after[-1]
        self.assertEqual(audit["action"], "search.entity.reveal")
        self.assertEqual(audit["citation_id"], payload["audit_id"])
        self.assertNotIn(self.values["rrn"], json.dumps(audit, ensure_ascii=False))
        self.assertNotIn(self.values["rrn"][7:], audit["params_json"])
        self.assertEqual(json.loads(audit["params_json"])["masked"], entity["masked"])
        missing = dict(body, value_sha256="0" * 64)
        self.assertEqual(self.client.post(self.url("/search/entities/reveal"), json=missing).status_code, 404)
        ip_row = self.query("ip:192.168.10.20")["rows"][0]
        ip_entity = next(item for item in ip_row["entities"] if item["kind"] == "ip")
        response = self.client.post(
            self.url("/search/entities/reveal"),
            json={"collection": ip_row["collection"], "kind": ip_row["kind"], "locator": ip_row["locator"], "value_sha256": ip_entity["value_sha256"]},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.audit_rows()), len(after))
        # the mail body (an artifact row) reveals too
        mail = self.query("card:* email:@naver.com")["rows"][0]
        card = next(item for item in mail["entities"] if item["kind"] == "card")
        response = self.client.post(
            self.url("/search/entities/reveal"),
            json={"collection": mail["collection"], "kind": mail["kind"], "locator": mail["locator"], "value_sha256": card["value_sha256"]},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["value"], self.values["card_mail"])

    def audit_rows(self) -> list[dict[str, object]]:
        connection = sqlite3.connect(self.run_dir / "rapidtriage-case.db")
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute("SELECT * FROM audit_event WHERE action = 'search.entity.reveal' ORDER BY id")]
        finally:
            connection.close()

    def test_qb4_list_counts(self) -> None:
        text = "\n".join(
            [
                "# IOC",
                "10.1.2.3",
                "10.0.0.0/8",
                "192.168.10.20",
                "192.168.0.0/16",
                "evil.example.com",
                "sender.kim@naver.com",
                self.fixture["exe_hashes"]["sha256"],
                "AnyDesk",
                "/Any[Dd]esk\\.exe/",
                "1.2.3.4",
            ]
        )
        created = self.post("/search/lists", {"name": "IOC 시험", "kind": "ioc", "text": text, "id": "ioc-test"}, status=201)
        self.assertEqual(created["item_count"], 10)
        self.assertEqual(created["by_type"]["ip"], 5)
        started = time.monotonic()
        result = self.query("list:ioc-test")
        self.assertLess(time.monotonic() - started, 5.0)
        counts = {item["item"]: item["count"] for item in result["lists"][0]["items"]}
        self.assertEqual(counts["10.1.2.3"], 1)
        self.assertGreaterEqual(counts["10.0.0.0/8"], counts["10.1.2.3"])
        self.assertGreaterEqual(counts["192.168.0.0/16"], counts["192.168.10.20"])
        self.assertEqual(counts["1.2.3.4"], 0)
        self.assertEqual(counts["evil.example.com"], 1)
        self.assertGreaterEqual(counts["AnyDesk"], 1)
        self.assertGreaterEqual(result["page"]["total"], max(counts.values()))
        self.assertEqual(self.query("list:execution")["lists"][0]["id"], "execution")  # built-in pack
        response = self.client.post(self.url("/search/query"), json={"q": "list:nope"})
        self.assertEqual(response.status_code, 404)
        bad = self.post("/search/lists", {"name": "bad", "text": "/(a+)+b/\nok"}, status=201)
        self.assertEqual(bad["rejected_count"], 1)
        listed = self.client.get(self.url("/search/lists")).json()["lists"]
        self.assertIn("ioc-test", [item["id"] for item in listed])

    def test_qb5_languages(self) -> None:
        korean = self.titles(self.query("lang:ko in:docs"))
        self.assertIn("개인정보목록.txt", korean)
        self.assertNotIn("japanese.txt", korean)
        self.assertEqual(self.titles(self.query("lang:ja")), ["japanese.txt"])
        self.assertEqual(self.titles(self.query("lang:en in:docs")), ["english.txt"])
        excluded = self.titles(self.query("in:docs -lang:ja"))
        self.assertNotIn("japanese.txt", excluded)
        both = self.query("lang:(ko, ja) in:docs")
        facet = {item["key"]: item["count"] for item in both["facets"]["lang"]}
        self.assertEqual(facet["ja"], 1)
        mails = self.query("lang:ko type:email-message")
        self.assertEqual(mails["page"]["total"], 2)
        response = self.client.post(self.url("/search/query"), json={"q": "lang:xx"})
        self.assertEqual(response.status_code, 400)

    def test_qb6_hashset_category(self) -> None:
        exe = self.fixture["exe_hashes"]
        lines = ['"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"']
        lines.append(f'"{exe["sha1"].upper()}","{exe["md5"].upper()}","0000ABCD","AnyDesk.exe",68,1,"WIN",""')
        lines.append(f'"{"1" * 40}","{"2" * 32}","00000000","other.bin",1,1,"WIN",""')
        response = self.client.post("/api/hash-sets", content="\n".join(lines).encode("utf-8"), params={"name": "NSRL 시험", "filename": "NSRLFile.txt"}, headers={"content-type": "text/csv"})
        self.assertEqual(response.status_code, 201, response.text)
        created = response.json()
        self.assertEqual(created["category"], "known-good")  # NSRL without a category
        hits = self.query("in:files hashset:known-good")["page"]["total"]
        everything = self.query("in:files")["page"]["total"]
        hidden = self.query("in:files -hashset:known-good")["page"]["total"]
        self.assertGreaterEqual(hits, 1)
        self.assertEqual(everything - hidden, hits)
        options = self.query("in:files", options={"hide_hashsets": ["known-good"]})["page"]["total"]
        self.assertEqual(options, hidden)
        empty = self.query("in:files hashset:known-bad")
        self.assertEqual(empty["page"]["total"], 0)
        self.assertTrue(any("알려진 악성" in warning for warning in empty["query"]["parsed"]["warnings"]))
        custom = self.client.post("/api/hash-sets", json={"name": "c", "category": "known-bad", "lines": exe["sha256"]})
        self.assertEqual(custom.status_code, 201, custom.text)
        self.assertEqual(custom.json()["category"], "known-bad")
        self.assertGreaterEqual(self.query("hashset:known-bad")["page"]["total"], 1)
        self.client.delete(f"/api/hash-sets/{custom.json()['id']}")
        self.client.delete(f"/api/hash-sets/{created['id']}")

    def test_qb7_ordered_proximity(self) -> None:
        self.assertEqual(self.titles(self.query("pre:(계약 해지)/3")), ["개인정보목록.txt"])
        self.assertEqual(self.titles(self.query("pre:(해지 계약)/3")), ["신규등록.txt"])
        self.assertEqual(self.titles(self.query('pre:"계약 즉시 해지"/1')), ["개인정보목록.txt"])
        self.assertEqual(self.query("pre:(계약 해지)/0")["page"]["total"], 0)
        for bad in ("pre:(계약)/3", "pre:(계약 해지)", "pre:계약/3", "pre:(계약 해지)/101"):
            response = self.client.post(self.url("/search/query"), json={"q": bad})
            self.assertEqual(response.status_code, 400, bad)

    def test_entity_summary_endpoint(self) -> None:
        summary = self.post("/search/entities", {})
        kinds = {item["kind"]: item for item in summary["kinds"]}
        self.assertEqual(kinds["rrn"]["values"], 2)
        self.assertEqual(kinds["rrn"]["verified_values"], 1)
        self.assertTrue(kinds["rrn"]["sensitive"])
        self.assertFalse(kinds["ip"]["sensitive"])
        rrn = next(item for item in summary["values"] if item["kind"] == "rrn" and item["verified"])
        detail = self.post("/search/entities", {"value_sha256": rrn["value_sha256"]})
        self.assertEqual([row["title"] for row in detail["rows"]], ["개인정보목록.txt"])
        scoped = self.post("/search/entities", {"q": "lang:ja"})
        self.assertEqual([item["kind"] for item in scoped["kinds"]], ["card"])
        self.assertEqual({item["key"] for item in summary["languages"]} >= {"ko", "ja", "en"}, True)

    def test_history_keeps_masks_only(self) -> None:
        self.query(f"phone:{self.values['phone']}")
        SEARCH_HISTORY.flush()
        history = self.client.get(self.url("/search/history")).json()["history"]
        self.assertTrue(history)
        self.assert_no_raw(json.dumps(history, ensure_ascii=False))
        blob = (self.run_dir / "search" / "history.sqlite").read_bytes()
        self.assertNotIn(self.values["phone"].encode(), blob)

    def test_count_echo_is_masked(self) -> None:
        result = self.post("/search/count", {"terms": [{"label": self.values["phone"], "q": f'"{self.values["phone"]}"'}]})
        self.assertEqual(result["items"][0]["count"], 1)


class EntityBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_row_cap_and_incremental(self) -> None:
        fixture = build_fixture_run(self.base)
        run_dir = Path(fixture["run_dir"])
        rng = random.Random(5)
        phones = [f"010-{rng.randint(2000, 9999)}-{rng.randint(1000, 9999)}" for _ in range(100)]
        write_analysis(run_dir, "20261027T000000-bbbbbbbb", "carve", [
            {"artifact_type": "carve-row", "path": "x.bin", "details": {"text": " ".join(phones)}},
        ])
        summary = build_search_index(run_dir, fixture["summary"])
        self.assertEqual(summary["skipped"].get("entity-row-capped"), 100 - ROW_CAP)
        index = run_dir / INDEX_FILE_NAME
        blob = index.read_bytes()
        for phone in phones:
            self.assertNotIn(phone.encode(), blob)  # past the cap still masked
        connection = sqlite3.connect(index)
        postings = connection.execute("SELECT COUNT(*) FROM search_entity").fetchone()[0]
        connection.close()
        write_analysis(run_dir, "20261027T000001-cccccccc", "carve", [
            {"artifact_type": "carve-row", "path": "y.bin", "details": {"text": f"연락처 {phones[0]}"}},
        ])
        incremental = build_search_index(run_dir, fixture["summary"], mode="incremental", analysis_ids=["20261027T000001-cccccccc"])
        self.assertEqual(incremental["entities"]["postings"], postings + 1)
        meta = json.loads(json.dumps(incremental))
        self.assertEqual(meta["mode"], "incremental")
        result = run_query(index, _meta(index), QueryRequest(q=f"phone:{phones[0]}"), budget=Budget(15))
        self.assertEqual(result["page"]["total"], 2)
        incremental = build_search_index(run_dir, fixture["summary"], mode="incremental", analysis_ids=["20261027T000001-cccccccc"])
        self.assertEqual(incremental["entities"]["postings"], postings + 1)  # replaced, not doubled

    def test_v4_index_is_stale_and_entity_fields_409(self) -> None:
        fixture = build_fixture_run(self.base)
        run_dir = Path(fixture["run_dir"])
        build_search_index(run_dir, fixture["summary"])
        index = run_dir / INDEX_FILE_NAME
        old = run_dir / "old.db"
        shutil.copy(index, old)
        connection = sqlite3.connect(old)
        connection.execute("UPDATE search_meta SET value = 'search-index-v4' WHERE key = 'index_version'")
        connection.execute("DELETE FROM search_meta WHERE key = 'entities'")
        connection.commit()
        connection.close()
        meta = _meta(old)
        reasons = stale_reasons(meta, fixture["summary"], run_dir)
        self.assertTrue(any("개체 추출 이전 형식" in reason for reason in reasons))
        with self.assertRaises(QueryError) as caught:
            run_query(old, meta, QueryRequest(q="rrn:*"), budget=Budget(15))
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("다시 만드세요", caught.exception.message)
        result = run_query(old, meta, QueryRequest(q="급여대장"), budget=Budget(15))
        self.assertGreater(result["page"]["total"], 0)
        self.assertIsNone(result["rows"][0]["entities"])


def _meta(index: Path) -> dict[str, object]:
    from rapidtriage.core.search_index.build import index_meta

    meta = index_meta(index)
    assert meta is not None
    return meta


if __name__ == "__main__":
    unittest.main()
