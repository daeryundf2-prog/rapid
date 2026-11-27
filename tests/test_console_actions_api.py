"""Action API v1 (docs/ai-action-api.md): the selection a console user and an agent share.

Select resolves a timeline window, an anchor's related rows and explicit locators to the same
targets the grid shows, and profiles them without writing. Mark previews by default; applied,
it goes through the run's case DB review batch and records an agent as ``agent:<name>``.
The timeline histogram's ``from``/``to`` window (the console's zoomed time overview) is here too.
"""

from __future__ import annotations

import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient  # noqa: F401

    from rapidtriage.api.app import routes_actions
    from rapidtriage.core.case_db.run_locator import parse_ordinal
    from rapidtriage.core.jobs import RunJobStore
    from tests.test_rapidtriage_api import api_test_client
    from tests.test_rapidtriage_run import build_run_fixture

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False


def _instant(value: object) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ActionApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        root = base / "case-root"
        root.mkdir()
        build_run_fixture(root)
        cls.client = api_test_client(RunJobStore(), case_db_roots=[cls.temp.name])
        response = cls.client.post(
            "/api/runs",
            json={"root": str(root), "mode": "fraud", "output_dir": str(base / "run-out"), "read_only": True, "wait": True},
        )
        assert response.status_code == 202, response.text
        cls.run_id = response.json()["run_id"]
        events = cls.client.get(f"/api/runs/{cls.run_id}/timeline?limit=1000").json()["events"]
        cls.events = events
        cls.timed = [(i, _instant(e.get("timestamp"))) for i, e in enumerate(events) if _instant(e.get("timestamp"))]
        assert len(cls.timed) >= 2, "fixture timeline needs timed events"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()
        cls.temp.cleanup()

    def _select(self, selection: dict, **body):
        return self.client.post(f"/api/runs/{self.run_id}/actions/select", json={"selection": selection, **body})

    def _mark(self, selection: dict, mark: dict, **body):
        return self.client.post(f"/api/runs/{self.run_id}/actions/mark", json={"selection": selection, "mark": mark, **body})

    def test_catalog_names_the_shared_actions(self) -> None:
        catalog = self.client.get("/api/actions")
        self.assertEqual(catalog.status_code, 200, catalog.text)
        body = catalog.json()
        self.assertEqual(body["version"], "1")
        self.assertEqual({action["id"] for action in body["actions"]} >= {"select", "mark"}, True)
        self.assertEqual(set(body["selection_forms"]), {"rows", "timeline", "related"})

    def test_time_window_around_an_anchor_matches_the_timeline_rows(self) -> None:
        anchor, at = self.timed[0]
        window = dt.timedelta(minutes=30)
        expected = {f"/events/{i}" for i, t in self.timed if abs(t - at) <= window}
        selected = self._select(
            {"related": {"relation": "time_window", "anchor": {"collection": "timeline", "locator": f"/events/{anchor}"}, "window_s": 1800}},
            sample=50,
        )
        self.assertEqual(selected.status_code, 200, selected.text)
        body = selected.json()
        self.assertEqual(body["total"], len(expected))
        self.assertEqual({row["locator"] for row in body["sample"]}, expected)
        self.assertEqual(sum(body["by_source"].values()), body["timeline_rows"])
        self.assertLessEqual(_instant(body["time_range"]["first"]), _instant(body["time_range"]["last"]))

    def test_same_path_and_explicit_rows(self) -> None:
        anchor = next(i for i, event in enumerate(self.events) if event.get("path"))
        path = str(self.events[anchor]["path"]).casefold()
        expected = sum(1 for event in self.events if str(event.get("path") or "").casefold() == path)
        related = self._select({"related": {"relation": "same_path", "anchor": {"collection": "timeline", "locator": f"/events/{anchor}"}}})
        self.assertEqual(related.json()["total"], expected)
        rows = self._select({"rows": [{"collection": "timeline", "locator": f"/events/{anchor}"}, {"collection": "files", "locator": "/candidates/0"}]})
        self.assertEqual(rows.status_code, 200, rows.text)
        self.assertEqual(rows.json()["by_collection"], {"timeline": 1, "files": 1})
        self.assertEqual(rows.json()["timeline_rows"], 1)

    def test_bad_selections_are_korean_422s(self) -> None:
        cases = [
            ({}, "하나만"),
            ({"timeline": {}, "related": {"relation": "same_name", "path": "a.txt"}}, "하나만"),
            ({"related": {"relation": "time_window", "anchor": {"collection": "files", "locator": "/candidates/0"}}}, "타임라인 행"),
            ({"related": {"relation": "time_window", "at": "어제"}}, "기준 시각"),
            ({"timeline": {"from": "2025-13-99"}}, None),
        ]
        for selection, needle in cases:
            with self.subTest(selection=selection):
                response = self._select(selection)
                self.assertEqual(response.status_code, 422, response.text)
                if needle:
                    self.assertIn(needle, response.json()["detail"])
        missing = self._select({"related": {"relation": "same_path", "anchor": {"collection": "timeline", "locator": "/events/999999"}}})
        self.assertEqual(missing.status_code, 404)

    def test_row_numbers_are_ascii_decimal_and_bounded(self) -> None:
        self.assertEqual(parse_ordinal("007"), 7)
        self.assertEqual(parse_ordinal("9" * 12), int("9" * 12))
        for text in ("", "²", "٣", "1²", "-1", "+1", " 1", "9" * 13):
            with self.subTest(text=text):
                self.assertIsNone(parse_ordinal(text))

    def test_non_ascii_or_huge_row_numbers_are_refused_not_crashes(self) -> None:
        # isdigit() accepted these: '²' and 5000 digits made int() raise (a 500), '٣' read as row 3.
        for tail in ("²", "٣", "9" * 13, "9" * 5000):
            row = {"collection": "timeline", "locator": f"/events/{tail}"}
            calls = {
                "select rows": lambda: self._select({"rows": [row]}),
                "select anchor": lambda: self._select({"related": {"relation": "same_path", "anchor": row}}),
                "mark preview": lambda: self._mark({"rows": [row]}, {"status": "relevant"}),
                "mark apply": lambda: self._mark({"rows": [row]}, {"status": "relevant"}, dry_run=False),
            }
            for name, call in calls.items():
                with self.subTest(tail=tail[:20], call=name):
                    response = call()
                    self.assertIn(response.status_code, (400, 422), response.text)
        applied = self._mark({"rows": [{"collection": "files", "locator": "/candidates/²"}]}, {"status": "relevant"}, dry_run=False)
        self.assertEqual(applied.status_code, 400, applied.text)

    def test_mark_previews_then_applies_as_the_agent(self) -> None:
        index, _ = self.timed[-1]
        selection = {"rows": [{"collection": "timeline", "locator": f"/events/{index}"}]}
        history_url = f"/api/runs/{self.run_id}/review-history?collection=timeline&locator=/events/{index}"
        preview = self._mark(selection, {"status": "needs-review"}, actor={"kind": "agent", "name": "triage-bot"})
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertTrue(preview.json()["dry_run"])
        self.assertEqual(preview.json()["actor"]["reviewer"], "agent:triage-bot")
        before = self.client.get(history_url)
        self.assertEqual(before.json().get("entries", []), [], "a dry run writes nothing")

        applied = self._mark(selection, {"status": "needs-review"}, dry_run=False, actor={"kind": "agent", "name": "triage-bot"})
        self.assertEqual(applied.status_code, 200, applied.text)
        self.assertEqual(applied.json()["updated_count"], 1)
        entries = self.client.get(history_url).json()["entries"]
        self.assertEqual([entry["author"] for entry in entries], ["agent:triage-bot"])

    def test_unnamed_actor_is_recorded_never_the_previous_reviewer(self) -> None:
        index, _ = self.timed[-2]
        selection = {"rows": [{"collection": "timeline", "locator": f"/events/{index}"}]}
        history_url = f"/api/runs/{self.run_id}/review-history?collection=timeline&locator=/events/{index}"
        steps = [
            ({"kind": "agent", "name": "bot"}, "relevant", {}, "agent:bot"),
            # No actor after an agent's mark: the author was the agent's ("agent:bot") before.
            (None, "excluded", {}, "local-user"),
            ({"kind": "human", "name": "김분석"}, "needs-review", {}, "김분석"),
            ({"kind": "human"}, "relevant", {"RAPIDTRIAGE_REVIEWER": "서버 검토자"}, "서버 검토자"),
            ({"kind": "agent", "name": "   "}, "unreviewed", {}, "agent:unnamed"),
        ]
        for actor, status, env, author in steps:
            with self.subTest(actor=actor, status=status), mock.patch.dict(os.environ, env):
                if not env:
                    os.environ.pop("RAPIDTRIAGE_REVIEWER", None)
                body = {"actor": actor} if actor is not None else {}
                applied = self._mark(selection, {"status": status}, dry_run=False, **body)
                self.assertEqual(applied.status_code, 200, applied.text)
                self.assertEqual(applied.json()["actor"]["reviewer"], author)
                self.assertEqual(self.client.get(history_url).json()["entries"][0]["author"], author)

    def test_a_human_cannot_claim_an_agent_name(self) -> None:
        index, _ = self.timed[-3]
        selection = {"rows": [{"collection": "timeline", "locator": f"/events/{index}"}]}
        history_url = f"/api/runs/{self.run_id}/review-history?collection=timeline&locator=/events/{index}"
        for name in ("agent:bot", "  Agent:bot", "AGENT:"):
            for dry_run in (True, False):
                with self.subTest(name=name, dry_run=dry_run):
                    spoof = self._mark(selection, {"status": "relevant"}, dry_run=dry_run, actor={"kind": "human", "name": name})
                    self.assertEqual(spoof.status_code, 422, spoof.text)
                    self.assertIn("agent:", spoof.json()["detail"])
        self.assertEqual(self.client.get(history_url).json().get("entries", []), [])

    def test_histogram_window_counts_only_its_range(self) -> None:
        _, at = self.timed[0]
        half = dt.timedelta(minutes=30)
        window = {"from": (at - half).isoformat(), "to": (at + half).isoformat()}
        expected = sum(1 for _, t in self.timed if abs(t - at) <= half)
        zoomed = self.client.get(f"/api/runs/{self.run_id}/timeline-histogram", params=window)
        self.assertEqual(zoomed.status_code, 200, zoomed.text)
        self.assertEqual(zoomed.json()["parsed_events"], expected)
        self.assertLessEqual(zoomed.json()["bucket_seconds"], 300)
        whole = self.client.get(f"/api/runs/{self.run_id}/timeline-histogram").json()
        self.assertEqual(whole["parsed_events"], len(self.timed))
        bad = self.client.get(f"/api/runs/{self.run_id}/timeline-histogram", params={"from": "어제"})
        self.assertEqual(bad.status_code, 422)
        self.assertIn("범위 시각", bad.json()["detail"])

    def test_mark_refusals(self) -> None:
        selection = {"timeline": {}}
        empty = self._mark(selection, {})
        self.assertEqual(empty.status_code, 422)
        self.assertIn("mark", empty.json()["detail"])
        nothing = self._mark({"timeline": {"contains": "이런 문구는 없다"}}, {"status": "relevant"})
        self.assertEqual(nothing.status_code, 422)
        self.assertIn("선택한 행이 없습니다", nothing.json()["detail"])
        with mock.patch.object(routes_actions, "MAX_TARGETS", 1), mock.patch("rapidtriage.api.app.actions.MAX_TARGETS", 1):
            over = self._mark(selection, {"status": "relevant"}, dry_run=False)
        self.assertEqual(over.status_code, 422)
        self.assertIn("범위를 좁히세요", over.json()["detail"])


if __name__ == "__main__":
    unittest.main()
