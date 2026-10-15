"""Search index API (plan search-2026-10-13 §3.2/§3.3): every S1 endpoint."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.analyses import (
        ANALYSIS_RUNNER,
        TERMINAL_STATUSES,
        run_scope,
    )
    from rapidtriage.api.app.search_index_service import (
        AUTO_INDEX_ENV,
        QUERY_LIMITER,
        SEARCH_HISTORY,
        auto_incremental_after_analysis,
    )

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover
    HAS_FASTAPI = False

from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.search_index.hashsets import DATA_DIR_ENV
from rapidtriage.core.search_index.schema import INDEX_FILE_NAME
from tests.search_index_fixture import EXPECTED_DOCS, build_fixture_run, write_analysis

TOKEN = "search-api-token"


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for search API tests")
class SearchApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(SEARCH_HISTORY.flush)  # history is written off the event loop
        base = Path(self.temp.name)
        env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data"), AUTO_INDEX_ENV: "1"})
        env.start()
        self.addCleanup(env.stop)
        self.fixture = build_fixture_run(base)
        self.run_dir = self.fixture["run_dir"]
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.app = create_app(self.store, auth_token=TOKEN)
        self.client = TestClient(self.app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))

    # -- helpers ------------------------------------------------------------

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def wait(self, analysis_id: str, timeout: float = 300.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.client.get(self.url(f"/analyses/{analysis_id}")).json()
            if state["status"] in TERMINAL_STATUSES:
                return state
            time.sleep(0.1)
        self.fail(f"analysis {analysis_id} did not finish")

    def build_index(self) -> dict:
        response = self.client.post(self.url("/search/index/build"), json={"mode": "full"})
        self.assertEqual(response.status_code, 202, response.text)
        state = response.json()
        self.assertEqual(state["kind"], "search-index")
        finished = self.wait(state["analysis_id"])
        self.assertEqual(finished["status"], "completed", finished)
        return finished

    def query(self, q: str, **body: object) -> dict:
        response = self.client.post(self.url("/search/query"), json={"q": q, **body})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def make_case_db(self) -> None:
        database = open_case_database(self.run_dir / "rapidtriage-case.db")
        database.create_case(case_id=f"run-{self.run_id}", name="search api test")

    # -- tests --------------------------------------------------------------

    def test_requires_auth_token(self) -> None:
        anonymous = TestClient(self.app)
        self.assertEqual(anonymous.get(self.url("/search/index")).status_code, 401)
        self.assertEqual(anonymous.post(self.url("/search/query"), json={"q": "x"}).status_code, 401)
        self.assertEqual(anonymous.get("/api/hash-sets").status_code, 401)

    def test_no_index_and_build_lifecycle(self) -> None:
        status = self.client.get(self.url("/search/index")).json()
        self.assertEqual(status["status"], "none")
        response = self.client.post(self.url("/search/query"), json={"q": "급여대장"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "검색 색인이 없습니다. 처리 단계에서 색인을 만드세요")
        self.assertEqual(self.client.post(self.url("/search/count"), json={"terms": [{"q": "x"}]}).status_code, 404)
        self.assertEqual(self.client.post(self.url("/search/hashes"), json={"hashes": ["a" * 32]}).status_code, 404)
        self.assertFalse(self.client.get("/api/runs").json()["runs"][0]["search_index_available"])

        finished = self.build_index()
        summary = finished["summary"]
        self.assertEqual(summary["doc_count"], EXPECTED_DOCS)
        for key in ("by_domain", "text_bytes", "db_bytes", "elapsed_s", "skipped", "tokenizer"):
            self.assertIn(key, summary)
        self.assertEqual(finished["progress"]["unit"], "출력 파일")
        self.assertEqual(finished["progress"]["percent"], 100.0)
        status = self.client.get(self.url("/search/index")).json()
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["doc_count"], EXPECTED_DOCS)
        self.assertEqual(status["tz"], "+09:00")
        self.assertIsNone(status["building"])
        self.assertEqual(status["last_build"]["analysis_id"], finished["analysis_id"])
        self.assertEqual(status["analyses_indexed"][0]["analysis_id"], "20251013T000000-aaaaaaaa")
        runs = self.client.get("/api/runs").json()["runs"]
        self.assertTrue(runs[0]["search_index_available"])
        self.assertTrue(self.client.get(self.url("")).json()["search_index_available"])

        # Stale after an output changes: queries still answer, with a warning.
        files_output = Path(self.fixture["summary"]["outputs"]["files"])
        later = time.time() + 10
        os.utime(files_output, (later, later))
        status = self.client.get(self.url("/search/index")).json()
        self.assertEqual(status["status"], "stale")
        self.assertIn("바뀐 출력 파일", status["stale_reason"])
        result = self.query("급여대장")
        self.assertTrue(result["index"]["stale"])
        self.assertTrue(any("오래되었습니다" in warning for warning in result["query"]["parsed"]["warnings"]))

    def test_build_validation_and_conflicts(self) -> None:
        response = self.client.post(self.url("/search/index/build"), json={"mode": "weird"})
        self.assertEqual(response.status_code, 422)
        response = self.client.post(self.url("/search/index/build"), json={"mode": "incremental", "analysis_ids": ["../x"]})
        self.assertEqual(response.status_code, 422)
        missing = self.client.post("/api/runs/nope/search/index/build", json={})
        self.assertEqual(missing.status_code, 404)
        # A live build owned by another server process (heartbeat fresh): 409.
        busy = self.run_dir / "analyses" / "20991231T000000-busybusy"
        busy.mkdir(parents=True)
        (busy / "analysis.json").write_text(
            json.dumps(
                {
                    "analysis_id": busy.name,
                    "kind": "search-index",
                    "status": "running",
                    "created_at": "2099-12-31T00:00:00+00:00",
                    "_owner": {"pid": os.getppid(), "boot_id": int(time.time() - time.monotonic()), "heartbeat_at": time.time()},
                }
            ),
            encoding="utf-8",
        )
        response = self.client.post(self.url("/search/index/build"), json={})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"], "이미 색인을 만드는 중입니다")
        self.assertEqual(self.client.get(self.url("/search/index")).json()["status"], "building")

    def test_query_count_and_errors(self) -> None:
        self.build_index()
        result = self.query("급여대장", histogram={"bucket": "auto"}, page={"limit": 2})
        self.assertEqual(result["page"]["total"], 4)
        self.assertEqual(result["page"]["returned"], 2)
        self.assertIsNotNone(result["page"]["next_cursor"])
        self.assertEqual({item["key"] for item in result["facets"]["collection"]}, {"docs", "files", "artifacts"})
        self.assertEqual(result["query"]["parsed"]["clauses"][0]["display"], "kw:급여대장")
        page2 = self.query("급여대장", page={"limit": 2, "cursor": result["page"]["next_cursor"]})
        self.assertEqual(len({row["doc_id"] for row in result["rows"] + page2["rows"]}), 4)
        bad_cursor = self.client.post(self.url("/search/query"), json={"q": "SanDisk", "page": {"cursor": result["page"]["next_cursor"]}})
        self.assertEqual(bad_cursor.status_code, 400)
        self.assertEqual(bad_cursor.json()["detail"], "커서가 이 질의에 맞지 않습니다")

        response = self.client.post(self.url("/search/query"), json={"q": "(급여"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "질의 1번째 글자: 닫는 괄호가 없습니다")
        self.assertEqual(response.json()["position"], 1)
        response = self.client.post(self.url("/search/query"), json={"q": "a" * 4001})
        self.assertEqual(response.status_code, 400)
        self.assertIn("최대 4,000자", response.json()["detail"])
        response = self.client.post(self.url("/search/query"), json={"q": "re:/(a+)+/"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("정규식이 너무 복잡합니다", response.json()["detail"])
        for locator in ("artifacts:eventlog/artifacts/../x", "/artifacts/12/../../etc", "events/abc", "/artifacts/-1"):
            response = self.client.post(self.url("/search/query"), json={"q": f"around:({locator}, 5m)"})
            self.assertEqual(response.status_code, 400, locator)
        response = self.client.post(self.url("/search/query"), json={"q": "hashset:hs-0123456789ab"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.query("'; DROP TABLE search_doc; --")["page"]["total"], 0)
        self.assertEqual(self.query("SanDisk")["page"]["total"], 1)
        result = self.query("time:[2025-05-28T19:00+09:00 .. 2025-05-28T21:00+09:00]", collapse=False, view="timeline", histogram={"bucket": "auto"})
        self.assertEqual(result["page"]["total"], sum(bucket["count"] for bucket in result["histogram"]["buckets"]))

        counts = self.client.post(
            self.url("/search/count"), json={"terms": [{"label": "a", "q": "급여대장"}, {"label": "b", "q": "SanDisk"}, {"label": "c", "q": "(x"}]}
        )
        self.assertEqual(counts.status_code, 200, counts.text)
        payload = counts.json()
        self.assertEqual([item["count"] for item in payload["items"]], [4, 1, None])
        self.assertEqual(payload["done"], 3)
        resumed = self.client.post(self.url("/search/count"), json={"terms": [{"q": "급여대장"}, {"q": "SanDisk"}], "offset": 1}).json()
        self.assertEqual([item["count"] for item in resumed["items"]], [1])
        too_far = self.client.post(self.url("/search/count"), json={"terms": [{"q": "x"}], "offset": 5})
        self.assertEqual(too_far.status_code, 400)

    def test_concurrency_limit_is_429(self) -> None:
        self.build_index()
        slots = [QUERY_LIMITER.slot(self.run_id) for _ in range(4)]
        for slot in slots:
            slot.__enter__()
        try:
            response = self.client.post(self.url("/search/query"), json={"q": "SanDisk"})
            self.assertEqual(response.status_code, 429)
            self.assertEqual(response.json()["detail"], "검색이 너무 많이 실행 중입니다")
        finally:
            for slot in slots:
                slot.__exit__(None, None, None)
        self.assertEqual(self.client.post(self.url("/search/query"), json={"q": "SanDisk"}).status_code, 200)

    def test_hashes_endpoint_and_hash_sets(self) -> None:
        self.build_index()
        exe = self.fixture["exe_hashes"]
        response = self.client.post(self.url("/search/hashes"), json={"hashes": [exe["sha256"], "zz", exe["md5"].upper(), "", "a" * 64]})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["matched_count"], 2)
        self.assertEqual(payload["unmatched_count"], 1)
        self.assertEqual(payload["invalid"], [{"line": 2, "value": "zz", "reason": "해시 형식이 아닙니다(MD5 32자·SHA-1 40자·SHA-256 64자 16진수)"}])
        only_md5 = self.client.post(self.url("/search/hashes"), json={"hashes": [exe["sha256"], exe["md5"]], "algorithms": ["md5"]}).json()
        self.assertEqual(only_md5["matched_count"], 1)
        self.assertEqual(only_md5["invalid_count"], 1)
        too_many = self.client.post(self.url("/search/hashes"), json={"hashes": ["a" * 32] * 100_001})
        self.assertEqual(too_many.status_code, 413)
        self.assertEqual(too_many.json()["detail"], "해시 목록이 너무 큽니다(최대 100,000개)")
        both = self.client.post(self.url("/search/hashes"), json={"hashes": [], "hashset_id": "hs-0123456789ab"})
        self.assertEqual(both.status_code, 400)

        created = self.client.post("/api/hash-sets", json={"name": "수사기관 목록", "label": "known-bad", "lines": exe["sha256"] + "\nbad line\n"})
        self.assertEqual(created.status_code, 201, created.text)
        hash_set = created.json()
        self.assertEqual(hash_set["count_by_algorithm"], {"sha256": 1})
        self.assertEqual(hash_set["rejected_lines"][0]["line"], 2)
        listed = self.client.get("/api/hash-sets").json()["hash_sets"]
        self.assertEqual([item["id"] for item in listed], [hash_set["id"]])
        self.assertEqual(self.client.get(f"/api/hash-sets/{hash_set['id']}").json()["name"], "수사기관 목록")
        by_set = self.client.post(self.url("/search/hashes"), json={"hashset_id": hash_set["id"]}).json()
        self.assertEqual(by_set["matched_count"], 1)
        self.assertEqual(self.query(f"hashset:{hash_set['id']}")["page"]["total"], 2)
        # The set matches the AnyDesk file and the sha256 indicator; only the file row mentions AnyDesk.
        self.assertEqual(self.query(f"AnyDesk -hashset:{hash_set['id']}")["page"]["total"], self.query("AnyDesk")["page"]["total"] - 1)

        boundary = uuid.uuid4().hex
        csv_text = f'"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"\r\n"{exe["sha1"]}","{exe["md5"]}","0","AnyDesk.exe",1,1,"WIN",""\r\n'
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nNSRL\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\nknown-good\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"NSRLFile.txt\"\r\nContent-Type: text/plain\r\n\r\n{csv_text}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        uploaded = self.client.post("/api/hash-sets", content=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        self.assertEqual(uploaded.json()["label"], "known-good")
        self.assertEqual(uploaded.json()["count_by_algorithm"], {"md5": 1, "sha1": 1})
        raw = self.client.post("/api/hash-sets?name=raw&label=custom&filename=list.txt", content=exe["md5"].encode(), headers={"Content-Type": "text/plain"})
        self.assertEqual(raw.status_code, 201, raw.text)
        hidden = self.query("AnyDesk", options={"hide_hashsets": [uploaded.json()["id"]]})
        self.assertEqual(hidden["page"]["total"], self.query("AnyDesk")["page"]["total"] - 1)  # the file row
        big = self.client.post("/api/hash-sets?name=big", content=b"0" * (50 * 1024 * 1024 + 70 * 1024), headers={"Content-Type": "text/plain"})
        self.assertEqual(big.status_code, 413)
        self.assertEqual(self.client.post("/api/hash-sets", json={"name": "x", "label": "custom", "lines": "nothing"}).status_code, 400)
        self.assertEqual(self.client.delete(f"/api/hash-sets/{hash_set['id']}").status_code, 204)
        self.assertEqual(self.client.get(f"/api/hash-sets/{hash_set['id']}").status_code, 404)
        self.assertEqual(self.client.delete("/api/hash-sets/..%2Fx").status_code, 404)

    def test_saved_searches_history_and_tree(self) -> None:
        self.build_index()
        self.assertEqual(self.client.get(self.url("/search/saved")).json()["saved"], [])
        self.assertEqual(self.client.get(self.url("/search/history")).json()["history"], [])
        response = self.client.post(self.url("/search/saved"), json={"name": "급여", "q": "급여대장"})
        self.assertEqual(response.status_code, 409)
        self.assertIn("케이스 DB가 없습니다", response.json()["detail"])

        self.make_case_db()
        response = self.client.post(self.url("/search/saved"), json={"name": "급여", "q": "급여대장", "sort": "ts", "options": {"tz": "+09:00"}})
        self.assertEqual(response.status_code, 201, response.text)
        saved = response.json()
        self.assertEqual((saved["name"], saved["q"], saved["sort"], saved["view"]), ("급여", "급여대장", "ts", "rows"))
        duplicate = self.client.post(self.url("/search/saved"), json={"name": "급여", "q": "x"})
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.json()["detail"], "같은 이름의 저장 검색이 있습니다")
        updated = self.client.put(self.url(f"/search/saved/{saved['id']}"), json={"name": "급여대장 전부"}).json()
        self.assertEqual((updated["name"], updated["q"]), ("급여대장 전부", "급여대장"))
        first = self.query("급여대장", saved_id=saved["id"], page={"limit": 2})
        # A follow-up page is not a new search: no extra history entry.
        self.query("급여대장", page={"limit": 2, "cursor": first["page"]["next_cursor"]})
        self.query("SanDisk")
        listed = self.client.get(self.url("/search/saved")).json()["saved"]
        self.assertEqual(listed[0]["last_count"], 4)
        self.assertEqual(self.client.get(self.url(f"/search/saved/{saved['id']}")).json()["last_count"], 4)

        history = self.client.get(self.url("/search/history?limit=50")).json()["history"]
        self.assertEqual([item["q"] for item in history], ["SanDisk", "급여대장"])
        self.assertEqual(history[0]["total"], 1)
        self.assertEqual(self.client.get(self.url("/search/history?limit=1")).json()["history"][0]["q"], "SanDisk")
        self.assertEqual(self.client.get(self.url("/search/history?limit=0")).status_code, 422)

        tree = self.client.get(self.url("/tree")).json()
        node = next(item for item in tree["nodes"] if item["id"] == "search")
        self.assertEqual(node["index_status"]["status"], "ready")
        self.assertEqual(node["saved_searches"], [{"id": saved["id"], "name": "급여대장 전부", "q": "급여대장", "last_count": 4}])

        self.assertEqual(self.client.delete(self.url(f"/search/saved/{saved['id']}")).status_code, 204)
        self.assertEqual(self.client.get(self.url(f"/search/saved/{saved['id']}")).status_code, 404)
        self.assertEqual(self.client.delete(self.url(f"/search/saved/{saved['id']}")).status_code, 404)

    def test_review_filter_without_case_db_warns(self) -> None:
        self.build_index()
        result = self.query("review:relevant")
        self.assertEqual(result["page"]["total"], 0)
        self.assertIn("케이스 DB가 없어 리뷰 조건과 일치하는 행이 없습니다", result["query"]["parsed"]["warnings"])

    def test_legacy_search_is_deprecated(self) -> None:
        response = self.client.get(self.url("/search"), params={"keyword": "AnyDesk", "ocr": "false"})
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertTrue(payload["deprecated"])
        self.assertEqual(payload["successor"], f"/api/runs/{self.run_id}/search/query")

    def test_auto_builds(self) -> None:
        job = self.store.get(self.run_id)
        # Apps only auto-build when asked (the served module-level app is).
        self.store._run_completion_hooks(job)
        self.assertIsNone(ANALYSIS_RUNNER.latest(self.run_dir, ["search-index"]))
        auto_app = create_app(self.store, auth_token=TOKEN, auto_search_index=True)
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=auto_app.state.analysis_owner))
        self.addCleanup(lambda: self.store.set_completion_hook("search-index", None))
        with mock.patch.dict(os.environ, {AUTO_INDEX_ENV: "0"}):
            self.store._run_completion_hooks(job)
        self.assertEqual(self.client.get(self.url("/search/index")).json()["status"], "none")
        self.store._run_completion_hooks(job)
        latest = ANALYSIS_RUNNER.latest(self.run_dir, ["search-index"])
        self.assertIsNotNone(latest)
        self.wait(str(latest["analysis_id"]))
        self.assertEqual(self.client.get(self.url("/search/index")).json()["status"], "ready")
        self.assertTrue((self.run_dir / INDEX_FILE_NAME).is_file())

        # Another analysis completes: an incremental search-index analysis indexes its rows.
        write_analysis(self.run_dir, "20251015T000000-cccccccc", "carve", [{"artifact_type": "carve-row", "path": "C:\\x\\y.bin", "details": {"signature_kind": "zip"}}])
        scope = run_scope(self.store, self.run_id)
        context = SimpleNamespace(
            scope=scope,
            spec=SimpleNamespace(kind="carve"),
            state={"analysis_id": "20251015T000000-cccccccc"},
            owner=auto_app.state.analysis_owner,
        )
        auto_incremental_after_analysis(context)
        latest = ANALYSIS_RUNNER.latest(self.run_dir, ["search-index"])
        self.assertEqual(latest["options"], {"mode": "incremental", "analysis_ids": ["20251015T000000-cccccccc"]})
        finished = self.wait(str(latest["analysis_id"]))
        self.assertEqual(finished["summary"]["mode"], "incremental")
        self.assertEqual(self.query("analysis:20251015T000000-cccccccc")["page"]["total"], 1)
        status = self.client.get(self.url("/search/index")).json()
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["doc_count"], EXPECTED_DOCS + 1)


if __name__ == "__main__":
    unittest.main()
