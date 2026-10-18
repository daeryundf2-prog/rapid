"""통합 보기 API (plan axiom-adoption §3.2): pages, cursor, filters, 422s, original rows, tree, analysis kind."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import analyses, create_app, derived

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.derived.stage import run_derived_stage
from rapidtriage.core.jobs import RunJobStore

TOKEN = "derived-test-token"
SECRET = "Bearer-eyJhbGciOiJIUzI1NiJ9.secret-token-value"


def event(event_id: str, timestamp: str, **details: object) -> dict[str, object]:
    return {
        "artifact_type": "eventlog-event",
        "path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
        "details": {"event_id": event_id, "channel": "Security", "timestamp": timestamp, **details},
    }


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for derived API tests")
class DerivedApiTests(unittest.TestCase):
    def setUp(self) -> None:
        derived.clear_derived_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        events = [
            *[event("4624", f"2024-05-{day:02d}T10:00:00Z", target_user_name=f"user{day}", source_ip="10.0.0.5") for day in range(1, 8)],
            *[event("4672", "2024-04-01T00:00:00Z", subject_user_name="user1") for _ in range(3)],
        ]
        records = self.run_dir / "eventlog.jsonl"
        records.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
        accounts = [{"artifact_type": "windows-sam-account", "details": {"user_name": "USER1", "last_logon_at": "2023-01-01T00:00:00Z"}}]
        kakao = [{"artifact_type": "kakaotalk-windows-crypto-material-candidate", "details": {"candidate_value": SECRET}}]
        outputs = {
            "artifacts_eventlog": {
                "records_path": str(records),
                "record_count": len(events),
                "artifacts": [],
                "summary": {"artifact_count": len(events), "artifact_type_counts": {"eventlog-event": len(events)}},
            },
            "artifacts_windows-os-account": {
                "artifacts": accounts,
                "record_count": 1,
                "summary": {"artifact_count": 1, "artifact_type_counts": {"windows-sam-account": 1}},
            },
            "artifacts_kakaotalk-windows": {
                "artifacts": kakao,
                "record_count": 1,
                "summary": {"artifact_count": 1, "artifact_type_counts": {"kakaotalk-windows-crypto-material-candidate": 1}},
            },
            "files": {"candidates": [{"path": r"C:\Users\user1\x.docx", "name": "x.docx"}], "inventory": [{"path": r"C:\Users\user1\x.docx"}]},
        }
        self.artifact_paths: dict[str, Path] = {}
        summary_outputs: dict[str, str] = {}
        for name, payload in outputs.items():
            path = self.run_dir / f"{name}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            summary_outputs[name] = str(path)
            if name.startswith("artifacts_"):
                self.artifact_paths[name.removeprefix("artifacts_")] = path
        summary_path = self.run_dir / "rapidtriage-run-summary.json"
        summary_outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(self.run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": summary_outputs,
                    "summary": {"counts": {"artifacts": len(events) + 2, "files": 1}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def build(self) -> dict[str, object]:
        step = run_derived_stage(self.run_dir, artifact_outputs=self.artifact_paths, files_path=self.run_dir / "files.json")
        self.assertEqual(step["status"], "completed", step)
        return step

    def get(self, path: str, expect: int = 200, **params) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}{path}", params=params)
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def test_no_set_is_409_and_meta_says_why(self) -> None:
        self.assertIn("통합 보기 결과가 없습니다", self.get("/derived/people", expect=409)["detail"])
        meta = self.get("/derived")
        self.assertIsNone(meta["source"])
        self.assertTrue(meta["reason"])
        self.assertNotIn("derived", {node["id"] for node in self.get("/tree")["nodes"]})

    def test_meta_tree_and_first_page(self) -> None:
        self.build()
        meta = self.get("/derived")
        self.assertEqual([table["table"] for table in meta["tables"]], ["people", "devices", "paths", "attachments", "credentials", "urls"])
        people_meta = meta["tables"][0]
        self.assertEqual((people_meta["label"], people_meta["rows"]), ("사람 식별자", 7))
        node = next(node for node in self.get("/tree")["nodes"] if node["id"] == "derived")
        self.assertEqual(node["label"], "통합 보기")
        self.assertEqual([child["id"] for child in node["children"]], [f"derived:{t}" for t in ("people", "devices", "paths", "attachments", "credentials", "urls")])
        self.assertEqual(node["children"][0]["count"], 7)
        page = self.get("/derived/people")
        self.assertEqual((page["total"], page["matched"], page["sort"], page["next_cursor"]), (7, 7, "count", None))
        first = page["rows"][0]
        self.assertEqual((first["normalized"], first["count"], first["kinds"]), ("user1", 5, {"eventlog": 4, "windows-os-account": 1}))
        self.assertNotIn("samples", first)
        self.assertEqual(first["sample_count"], 5)

    def test_keyset_paging_has_no_gaps_or_repeats(self) -> None:
        self.build()
        for sort in ("count", "first_seen", "last_seen"):
            seen: list[str] = []
            cursor = None
            for _ in range(10):
                params = {"limit": 3, "sort": sort, **({"after": cursor} if cursor else {})}
                page = self.get("/derived/people", **params)
                seen.extend(row["normalized"] for row in page["rows"])
                cursor = page["next_cursor"]
                if cursor is None:
                    break
            self.assertEqual(len(seen), 7, sort)
            self.assertEqual(len(set(seen)), 7, sort)
        newest = self.get("/derived/people", sort="last_seen", limit=1)["rows"][0]
        self.assertEqual(newest["normalized"], "user7")
        oldest = self.get("/derived/people", sort="first_seen", limit=1)["rows"][0]
        self.assertEqual(oldest["normalized"], "user1")

    def test_filters(self) -> None:
        self.build()
        page = self.get("/derived/people", q="USER1")
        self.assertEqual([row["normalized"] for row in page["rows"]], ["user1"])
        page = self.get("/derived/people", kind="windows-os-account")
        self.assertEqual((page["matched"], page["rows"][0]["normalized"]), (1, "user1"))
        self.assertEqual(self.get("/derived/people", kind="browser")["matched"], 0)
        paths = self.get("/derived/paths")
        self.assertEqual(paths["rows"][0]["kinds"], {"files:candidates": 1, "files:inventory": 1})

    def test_bad_parameters_are_korean_422_and_no_path_escape(self) -> None:
        self.build()
        for params in (
            {"sort": "value"},
            {"limit": "0"},
            {"limit": "501"},
            {"limit": "abc"},
            {"after": "!!"},
            {"after": "eyJ4IjoxfQ"},
            {"kind": "../people"},
            {"q": "x" * 201},
        ):
            detail = self.get("/derived/people", expect=422, **params)["detail"]
            self.assertRegex(str(detail), r"[가-힣]", params)
        cursor = self.get("/derived/people", limit=2)["next_cursor"]
        self.assertIn("정렬", self.get("/derived/people", expect=422, sort="last_seen", after=cursor)["detail"])
        for table in ("summary", "people.jsonl", "%2E%2E", "%2E%2E%2Fsummary", "analysis", "people%00"):
            response = self.client.get(f"/api/runs/{self.run_id}/derived/{table}")
            self.assertIn(response.status_code, (404, 422), table)
            self.assertNotIn("catalog_version", response.text)
        self.get("/derived/people/rows", expect=422, value="")
        self.get("/derived/people/rows", expect=404, value="nobody")

    def test_cursor_of_an_older_generation_is_refused(self) -> None:
        self.build()
        cursor = self.get("/derived/people", limit=2)["next_cursor"]
        time.sleep(0.01)
        self.build()
        self.assertIn("첫 페이지", self.get("/derived/people", expect=422, limit=2, after=cursor)["detail"])

    def test_missing_or_bad_paging_index_falls_back_to_the_table(self) -> None:
        step = self.build()
        directory = self.run_dir / "analyses" / str(step["analysis_id"])
        expected = self.get("/derived/people", limit=3)["rows"]
        good = json.loads((directory / "people.index.json").read_text(encoding="utf-8"))
        past_end = {**good, "offsets": [999_999] * good["rows"]}
        short = {**good, "count": good["count"][:-1]}
        for broken in (None, json.dumps(past_end), json.dumps(short), "not json"):
            derived.clear_derived_cache()
            sidecar = directory / "people.index.json"
            if broken is None:
                sidecar.unlink()
            else:
                sidecar.write_text(broken, encoding="utf-8")
            page = self.get("/derived/people", limit=3)
            self.assertEqual(page["rows"], expected, broken)
            self.assertEqual(page["total"], 7)
            self.assertEqual(self.get("/derived/people/rows", value="user1")["count"], 5)

    def test_index_cache_is_bounded_by_rows_and_search_text_by_length(self) -> None:
        """Adversarial review of E2 item 11: cache by total rows, search text ≤ SEARCH_TEXT_CHARS."""
        step = self.build()
        directory = self.run_dir / "analyses" / str(step["analysis_id"])
        sidecar = directory / "people.index.json"
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        payload["search"] = [text + "x" * 5000 for text in payload["search"]]  # an older, uncut sidecar
        sidecar.write_text(json.dumps(payload), encoding="utf-8")
        cache = derived.TableIndexCache(max_tables=8, max_rows=8)
        people = cache.get("run", str(step["analysis_id"]), "people", directory / "people.jsonl")
        self.assertEqual(len(people), 7)
        self.assertTrue(all(len(text) <= derived.SEARCH_TEXT_CHARS for text in people.search))
        devices = cache.get("run", str(step["analysis_id"]), "devices", directory / "devices.jsonl")
        # 7 + 1 rows fit; the next table pushes the oldest (people) out although only 3 tables are cached.
        self.assertEqual(len(cache._cache), 2)
        cache.get("run", str(step["analysis_id"]), "paths", directory / "paths.jsonl")
        self.assertNotIn(("run", "people"), cache._cache)
        self.assertIn(("run", "paths"), cache._cache)
        self.assertLessEqual(sum(len(item) for item in cache._cache.values()), 8)
        # A single table larger than the row budget is still served (the newest is always kept).
        tiny = derived.TableIndexCache(max_rows=1)
        self.assertEqual(len(tiny.get("run", str(step["analysis_id"]), "people", directory / "people.jsonl")), 7)
        self.assertEqual(len(devices), 1)

    def test_value_rows_give_grid_locators(self) -> None:
        self.build()
        rows = self.get("/derived/people/rows", value="user1")
        kinds = {sample["kind"] for sample in rows["samples"]}
        self.assertEqual(kinds, {"eventlog", "windows-os-account"})
        sam = next(sample for sample in rows["samples"] if sample["kind"] == "windows-os-account")
        self.assertEqual((sam["collection"], sam["kind"], sam["locator"], sam["family"]), ("artifacts", "windows-os-account", "/artifacts/0", "sam-account"))
        files = self.get("/derived/paths/rows", value=r"c:\users\user1\x.docx")
        locators = sorted((sample["collection"], sample["scope"], sample["locator"]) for sample in files["samples"])
        self.assertEqual(locators, [("files", "candidates", "/candidates/0"), ("files", "inventory", "/inventory/0")])

    def test_graph_two_hops_from_a_people_value(self) -> None:
        """연결 그래프 라이트 (r4 §2.3): value → original rows (by family) → the rows' other values."""
        self.build()
        graph = self.get("/derived/people/graph", value="user1")
        nodes = {node["id"]: node for node in graph["nodes"]}
        center = nodes[graph["center"]]
        self.assertTrue(center["center"])
        self.assertEqual((center["table"], center["normalized"]), ("people", "user1"))
        rows = [node for node in graph["nodes"] if node["type"] == "row"]
        self.assertEqual({row["kind"] for row in rows}, {"eventlog", "windows-os-account"})
        sam = next(row for row in rows if row["kind"] == "windows-os-account")
        self.assertEqual((sam["collection"], sam["locator"]), ("artifacts", "/artifacts/0"))
        self.assertEqual(graph["rows_read"], len(rows))
        # Second hop: the 4624 row of user1 carries source_ip 10.0.0.5 (장치 식별자).
        device = nodes.get("v:devices:10.0.0.5")
        self.assertIsNotNone(device, sorted(nodes))
        self.assertTrue(device["in_table"])
        self.assertGreaterEqual(device["count"], 7)
        edges = {(edge["source"], edge["target"]) for edge in graph["edges"]}
        self.assertTrue(all((graph["center"], row["id"]) in edges for row in rows))
        self.assertTrue(any(target == "v:devices:10.0.0.5" for _source, target in edges))
        # The centre value never reappears as its own neighbour.
        self.assertEqual(sum(1 for node in graph["nodes"] if node.get("normalized") == "user1" and node["table"] == "people"), 1)
        self.assertLessEqual(len(graph["nodes"]), 200)
        self.assertFalse(graph["truncated"])

    def test_graph_is_bounded_and_validates(self) -> None:
        self.build()
        graph = self.get("/derived/devices/graph", value="10.0.0.5", max_nodes=10)
        self.assertLessEqual(len(graph["nodes"]), 10)
        self.assertEqual(graph["max_nodes"], 10)
        self.assertIn("max_nodes", self.get("/derived/people/graph", expect=422, value="user1", max_nodes=500)["detail"])
        self.assertIn("value", self.get("/derived/people/graph", expect=422, value="")["detail"])
        self.assertIn("없는 값", self.get("/derived/people/graph", expect=404, value="nobody")["detail"])
        self.assertEqual(self.client.get(f"/api/runs/{self.run_id}/derived/secrets/graph", params={"value": "x"}).status_code, 404)

    def test_graph_keeps_credentials_masked(self) -> None:
        self.build()
        row = self.get("/derived/credentials")["rows"][0]
        response = self.client.get(f"/api/runs/{self.run_id}/derived/credentials/graph", params={"value": row["normalized"]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn(SECRET[2:-1], response.text)

    def test_credentials_are_masked_in_every_response(self) -> None:
        self.build()
        page = self.client.get(f"/api/runs/{self.run_id}/derived/credentials")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(SECRET, page.text)
        self.assertNotIn(SECRET[2:-1], page.text)
        row = page.json()["rows"][0]
        self.assertEqual(row["length"], len(SECRET))
        self.assertTrue(row["normalized"].startswith("sha256:"))
        detail = self.client.get(f"/api/runs/{self.run_id}/derived/credentials/rows", params={"value": row["normalized"]})
        self.assertNotIn(SECRET[2:-1], detail.text)
        self.assertNotIn(SECRET[2:-1], self.client.get(f"/api/runs/{self.run_id}/derived/credentials", params={"q": "Bearer"}).text)

    def test_analysis_kind_builds_a_set(self) -> None:
        response = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "derived", "options": {}})
        self.assertEqual(response.status_code, 202, response.text)
        analysis_id = response.json()["analysis_id"]
        deadline = time.monotonic() + 30
        while True:
            state = self.get(f"/analyses/{analysis_id}")
            if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                break
            self.assertLess(time.monotonic(), deadline, state)
            time.sleep(0.02)
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["tables"]["people"]["rows"], 7)
        self.assertTrue(Path(state["output_dir"]).resolve().is_relative_to(self.run_dir.resolve()))
        page = self.get("/derived/people")
        self.assertEqual(page["source"]["analysis_id"], analysis_id)
        self.assertEqual(page["source"]["source"], "analysis")
        bad = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "derived", "options": {"x": 1}})
        self.assertEqual(bad.status_code, 422)


if __name__ == "__main__":
    unittest.main()
