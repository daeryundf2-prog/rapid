"""r2 console fix M2/M4: ``browser=`` / ``service=`` filters of ``GET /artifacts`` and the
``field_type_counts`` / ``inventory_notes`` the ``/tree`` kind nodes carry."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import artifact_sort, create_app, tree

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore

TOKEN = "field-filter-test-token"


def browser_row(artifact_type: str, browser: str, n: int) -> dict[str, object]:
    return {
        "artifact_type": artifact_type,
        "path": rf"C:\Users\a\AppData\{browser}\History",
        "details": {"browser": browser, "url": f"https://example.test/{n}", "timestamp": f"2024-05-0{n % 9 + 1}T10:00:00Z"},
    }


def chat_row(artifact_type: str, service: str, n: int) -> dict[str, object]:
    return {
        "artifact_type": artifact_type,
        "path": rf"C:\Users\a\AppData\Roaming\{service}\store.ldb",
        "details": {"service": service, "app": service, "body": f"m{n}", "direction": "outgoing"},
    }


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FieldFilterApiTests(unittest.TestCase):
    def setUp(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        tree._FACET_CACHE.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        run_dir = base / "run"
        run_dir.mkdir()
        browser_rows = [
            browser_row("browser-history", "chrome", 1),
            browser_row("browser-history", "ie-edge-legacy", 2),
            browser_row("browser-cache-entry", "ie-edge-legacy", 3),
            browser_row("browser-cookie", "edge", 4),
            browser_row("browser-download", "ie-edge-legacy", 5),
            browser_row("webcachev01-ese-file", "ie-edge-legacy", 6),
        ]
        records = run_dir / "browser.jsonl"
        records.write_text("".join(json.dumps(row) + "\n" for row in browser_rows), encoding="utf-8")
        chat_rows = [
            chat_row("chat-message", "Slack", 1),
            chat_row("chat-message", "Slack", 2),
            chat_row("chat-message", "Microsoft Teams (new)", 3),
            chat_row("chat-contact", "Slack", 4),
            chat_row("chat-app-inventory", "WeChat", 5),
        ]
        email_rows = [
            {
                "artifact_type": "email-container-inventory",
                "path": r"C:\Users\a\Documents\Outlook.pst",
                "details": {"status": "disabled", "status_label": "외부 도구 꺼짐", "reason": "외부 도구 실행 꺼짐(기본값) — RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1"},
            },
            {
                "artifact_type": "email-container-inventory",
                "path": r"C:\Users\a\Documents\Archive.pst",
                "details": {"status": "disabled", "status_label": "외부 도구 꺼짐", "reason": "외부 도구 실행 꺼짐(기본값) — RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1"},
            },
            {"artifact_type": "email-mailbox", "path": r"C:\Users\a\Documents\Outlook.pst", "details": {}},
        ]
        kakao_rows = [
            {
                "artifact_type": "kakaotalk-app-inventory",
                "path": r"C:\Users\a\AppData\Local\Kakao\KakaoTalk\users\x\chatLogs_1.edb",
                "details": {"decryption_status": "no-key-material", "status_label": "복호 키 없음", "reason": "복호 키 없음 — 키 재료 후보로 키를 만들 수 없음"},
            },
        ]
        outputs: dict[str, dict[str, object]] = {
            "artifacts_browser": {
                "records_path": str(records),
                "record_count": len(browser_rows),
                "artifacts": [],
                "summary": {"artifact_count": len(browser_rows), "artifact_type_counts": counts(browser_rows)},
            },
            "artifacts_windows-messenger": {
                "artifacts": chat_rows,
                "record_count": len(chat_rows),
                "summary": {"artifact_count": len(chat_rows), "artifact_type_counts": counts(chat_rows)},
            },
            "artifacts_email": {
                "artifacts": email_rows,
                "record_count": len(email_rows),
                "summary": {"artifact_count": len(email_rows), "artifact_type_counts": counts(email_rows)},
            },
            "artifacts_kakaotalk-windows": {
                "artifacts": kakao_rows,
                "record_count": len(kakao_rows),
                "summary": {"artifact_count": len(kakao_rows), "artifact_type_counts": counts(kakao_rows)},
            },
        }
        summary_outputs: dict[str, str] = {}
        for name, payload in outputs.items():
            path = run_dir / f"{name}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            summary_outputs[name] = str(path)
        summary_path = run_dir / "rapidtriage-run-summary.json"
        summary_outputs["summary"] = str(summary_path)
        total = sum(len(payload.get("artifacts") or []) for payload in outputs.values()) + len(browser_rows)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": summary_outputs,
                    "summary": {"counts": {"artifacts": total}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, query: str) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/artifacts?{query}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_browser_filter_pages_only_legacy_rows(self) -> None:
        payload = self.get(
            "kind=browser&limit=50&browser=ie-edge-legacy"
            "&artifact_type=browser-history&artifact_type=browser-cache-entry"
            "&artifact_type=browser-cookie&artifact_type=browser-download"
        )
        page = payload["artifacts"]["browser"]
        types = [row["artifact_type"] for row in page["artifacts"]]
        self.assertEqual(types, ["browser-history", "browser-cache-entry", "browser-download"])
        self.assertTrue(all(row["details"]["browser"] == "ie-edge-legacy" for row in page["artifacts"]))
        self.assertEqual(page["matched"], 3)
        self.assertEqual(page["pagination"]["fields"], {"browser": ["ie-edge-legacy"]})

    def test_service_filter_is_exact_and_repeatable(self) -> None:
        page = self.get("kind=windows-messenger&limit=50&service=Slack&artifact_type=chat-message")["artifacts"]["windows-messenger"]
        self.assertEqual([row["details"]["body"] for row in page["artifacts"]], ["m1", "m2"])
        # Exact match: a substring / other casing matches nothing.
        page = self.get("kind=windows-messenger&limit=50&service=slack")["artifacts"]["windows-messenger"]
        self.assertEqual(page["artifacts"], [])
        page = self.get("kind=windows-messenger&limit=50&service=Slack&service=WeChat")["artifacts"]["windows-messenger"]
        self.assertEqual(page["matched"], 4)

    def test_field_filter_across_kinds(self) -> None:
        payload = self.get("limit=50&browser=ie-edge-legacy")
        self.assertEqual(payload["cross_kind"]["matched"], 4)
        self.assertEqual(payload["cross_kind"]["fields"], {"browser": ["ie-edge-legacy"]})

    def test_field_filter_with_sort_narrows_sorted_pages(self) -> None:
        page: dict[str, object] = {}
        for _attempt in range(100):
            page = self.get("kind=browser&limit=50&browser=ie-edge-legacy&sort=timestamp:desc")["artifacts"]["browser"]
            if page["sort"]["status"] != "building":
                break
            time.sleep(0.05)
        self.assertEqual(page["sort"]["status"], "ready")
        rows = page["artifacts"]
        self.assertEqual([row["details"]["url"] for row in rows], [f"https://example.test/{n}" for n in (6, 5, 3, 2)])

    def test_field_filters_compose_with_channel_filters(self) -> None:
        """R3 integration: ``browser=`` / ``service=`` AND ``channel=`` / ``channel_group=`` (O2)."""
        page = self.get("kind=windows-messenger&limit=50&service=Slack&channel_group=none")["artifacts"]["windows-messenger"]
        self.assertEqual(page["matched"], 3)  # Slack rows have no event-log channel
        self.assertEqual(page["pagination"]["fields"], {"service": ["Slack"]})
        self.assertEqual(page["pagination"]["channel_groups"], ["none"])
        page = self.get("kind=windows-messenger&limit=50&service=Slack&channel=Security")["artifacts"]["windows-messenger"]
        self.assertEqual((page["matched"], page["artifacts"]), (0, []))
        # Across kinds.
        payload = self.get("limit=50&browser=ie-edge-legacy&channel_group=none")
        self.assertEqual(payload["cross_kind"]["matched"], 4)
        self.assertEqual(payload["cross_kind"]["fields"], {"browser": ["ie-edge-legacy"]})
        self.assertEqual(payload["cross_kind"]["channel_groups"], ["none"])
        self.assertEqual(self.get("limit=50&browser=ie-edge-legacy&channel=Security")["cross_kind"]["matched"], 0)
        # Sorted pages and the 특이사항 sort.
        for channel, expected in (("channel_group=none", 4), ("channel=Security", 0)):
            sorted_page: dict[str, object] = {}
            for _attempt in range(100):
                sorted_page = self.get(f"kind=browser&limit=50&browser=ie-edge-legacy&{channel}&sort=timestamp:desc")["artifacts"]["browser"]
                if sorted_page["sort"]["status"] != "building":
                    break
                time.sleep(0.05)
            self.assertEqual(sorted_page["sort"]["status"], "ready")
            self.assertEqual(len(sorted_page["artifacts"]), expected, channel)
            flag_page = self.get(f"kind=browser&limit=50&browser=ie-edge-legacy&{channel}&sort=flags")["artifacts"]["browser"]
            self.assertEqual(len(flag_page["artifacts"]), expected, channel)
        # A bad channel group is still a Korean 422 next to a valid field filter.
        response = self.client.get(f"/api/runs/{self.run_id}/artifacts?kind=browser&limit=10&browser=chrome&channel_group=bogus")
        self.assertEqual(response.status_code, 422)
        self.assertRegex(response.json()["detail"], "[가-힣]")

    def test_invalid_field_values_are_korean_422(self) -> None:
        for query in ("kind=browser&limit=10&browser=", "kind=browser&limit=10&service=%20", "kind=browser&limit=10&browser=a%01b"):
            response = self.client.get(f"/api/runs/{self.run_id}/artifacts?{query}")
            self.assertEqual(response.status_code, 422, query)
            detail = response.json()["detail"]
            self.assertRegex(detail, "[가-힣]")
        response = self.client.get(f"/api/runs/{self.run_id}/artifacts?kind=browser&limit=10&browser={'x' * 300}")
        self.assertEqual(response.status_code, 422)
        # Like every filter, it needs limit > 0.
        response = self.client.get(f"/api/runs/{self.run_id}/artifacts?kind=browser&browser=chrome")
        self.assertEqual(response.status_code, 400)

    def test_tree_carries_field_counts_and_inventory_notes(self) -> None:
        payload = self.client.get(f"/api/runs/{self.run_id}/tree").json()
        kinds = {node["id"]: node for node in walk(payload["nodes"]) if node.get("collection") == "artifacts" and node.get("kind") and not node.get("artifact_type")}
        browser = kinds["artifacts:browser"]
        self.assertEqual(
            browser["field_type_counts"]["browser"]["ie-edge-legacy"],
            {"browser-cache-entry": 1, "browser-download": 1, "browser-history": 1, "webcachev01-ese-file": 1},
        )
        self.assertEqual(browser["field_type_counts"]["browser"]["chrome"], {"browser-history": 1})
        messenger = kinds["artifacts:windows-messenger"]
        self.assertEqual(messenger["field_type_counts"]["service"]["Slack"], {"chat-contact": 1, "chat-message": 2})
        email = kinds["artifacts:email"]
        self.assertEqual(len(email["inventory_notes"]), 1)
        note = email["inventory_notes"][0]
        self.assertEqual((note["status"], note["count"], note["status_label"]), ("disabled", 2, "외부 도구 꺼짐"))
        self.assertIn("RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1", note["reason"])
        kakao = kinds["artifacts:kakaotalk-windows"]
        self.assertEqual(kakao["inventory_notes"][0]["status"], "no-key-material")
        self.assertTrue(kakao["inventory_notes"][0]["reason"].startswith("복호 키 없음"))
        # Second request: served from the facet cache (same values).
        again = self.client.get(f"/api/runs/{self.run_id}/tree").json()
        again_kinds = {node["id"]: node for node in walk(again["nodes"])}
        self.assertEqual(again_kinds["artifacts:browser"]["field_type_counts"], browser["field_type_counts"])


def counts(rows: list[dict[str, object]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[str(row["artifact_type"])] = out.get(str(row["artifact_type"]), 0) + 1
    return out


def walk(nodes: list[dict[str, object]]):
    for node in nodes:
        yield node
        yield from walk(node.get("children") or [])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
