"""특이사항 API (plan viewer-families §3.1): join, filters, sort, tree, meta, citations, analysis kind."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import analyses, artifact_sort, create_app, triage_flags

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.triage_rules import engine as triage_engine
from rapidtriage.core.triage_rules import load_catalog

TOKEN = "triage-flags-test-token"
CLEARED = "eventlog.log_cleared"
SERVICE = "eventlog.new_service"


def event(event_id: str, channel: str, provider: str, **details: object) -> dict[str, object]:
    return {
        "artifact_type": "eventlog-event",
        "path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
        "details": {"event_id": event_id, "channel": channel, "provider_name": provider, "timestamp": "2024-05-01T10:00:00Z", **details},
    }


def flag(rule_id: str, grade: str, **evidence: object) -> dict[str, object]:
    return {"id": rule_id, "grade": grade, "label": rule_id, "evidence": evidence}


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for triage flag API tests")
class TriageFlagsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        artifact_sort.SORT_INDEX_CACHE.clear()
        triage_flags.clear_flags_index_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        events = [
            event("4624", "Security", "Microsoft-Windows-Security-Auditing", logon_type="5"),
            event(
                "1102",
                "Security",
                "Microsoft-Windows-Eventlog",
                subject_user_name="alice",
                evtx_record_state="recovered-slack",
                parser="windows-eventlog-evtx-native",
                parser_version="eventlog-normalized-v21",
            ),
            event("104", "Microsoft-Windows-Kernel-Cache/Operational", "Microsoft-Windows-Kernel-Cache"),
            event("4688", "Security", "Microsoft-Windows-Security-Auditing"),
        ]
        records = self.run_dir / "eventlog.jsonl"
        records.write_text("".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")
        shell_rows = [
            {"artifact_type": "shellbag-entry", "path": r"C:\Users\a\NTUSER.DAT", "details": {"n": 1}},
            {"artifact_type": "shellbag-entry", "path": r"C:\Users\a\NTUSER.DAT", "details": {"n": 2}},
        ]
        files = {
            "candidates": [
                {"path": r"C:\Users\a\x.docx", "name": "x.docx", "categories": ["documents"]},
                {"path": r"C:\Users\a\y.zip", "name": "y.zip", "categories": ["archives"]},
                {"path": r"C:\Users\a\z.docx", "name": "z.docx", "categories": ["documents"]},
            ]
        }
        outputs = {
            "artifacts_eventlog": {
                "records_path": str(records),
                "record_count": len(events),
                "artifacts": [],
                "summary": {"artifact_count": len(events), "artifact_type_counts": {"eventlog-event": len(events)}},
            },
            "artifacts_windows-shellbags": {
                "artifacts": shell_rows,
                "record_count": 2,
                "summary": {"artifact_count": 2, "artifact_type_counts": {"shellbag-entry": 2}},
            },
            "files": files,
        }
        summary_outputs: dict[str, str] = {}
        for name, payload in outputs.items():
            path = self.run_dir / f"{name}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            summary_outputs[name] = str(path)
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
                    "summary": {"counts": {"artifacts": 6, "files": 3}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    # -- helpers -------------------------------------------------------------------

    def write_flag_set(self, analysis_id: str, lines: list[dict[str, object]], *, finished_at: str = "2024-06-01T00:00:00+00:00") -> Path:
        """A completed ``triage-flags`` analysis written directly (deterministic flags)."""
        directory = self.run_dir / "analyses" / analysis_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "flags.jsonl").write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
        by_rule: dict[str, int] = {}
        for line in lines:
            for item in line["flags"]:
                by_rule[item["id"]] = by_rule.get(item["id"], 0) + 1
        (directory / "summary.json").write_text(
            json.dumps(
                {
                    "status": "completed",
                    "generated_at": finished_at,
                    "catalog_version": "test",
                    "rule_versions": {CLEARED: 3},
                    "flagged_rows": len(lines),
                    "rows_by_best_grade": {"A": 1, "B": 1, "C": 0},
                    "by_rule": by_rule,
                    "by_kind": {"eventlog": {"rows": 2, "flags": 2, "A": 1, "B": 1, "C": 0}},
                    "by_kind_type": {"eventlog": {"eventlog-event": {"A": 1, "B": 1, "C": 0}}},
                    "policy_sources": [{"id": "sysmon", "label": "Sysmon", "count": 0, "note": "설치 필요"}],
                }
            ),
            encoding="utf-8",
        )
        (directory / "rows.jsonl").write_text("", encoding="utf-8")
        (directory / "analysis.json").write_text(
            json.dumps(
                {
                    "analysis_id": analysis_id,
                    "kind": "triage-flags",
                    "status": "completed",
                    "created_at": finished_at,
                    "finished_at": finished_at,
                    "row_count": 0,
                    "options": {},
                }
            ),
            encoding="utf-8",
        )
        return directory

    def standard_flags(self) -> None:
        self.write_flag_set(
            "flags-1",
            [
                {"kind": "eventlog", "record_index": 1, "flags": [flag(CLEARED, "A", event_id="1102")]},
                {"kind": "eventlog", "record_index": 3, "flags": [flag(SERVICE, "B", service="x")]},
                {"kind": "files:candidates", "record_index": 2, "flags": [flag("documents.macro_or_ole", "B")]},
            ],
        )

    def get(self, path: str, expect: int = 200, **params) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}{path}", params=params)
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def wait(self, analysis_id: str, timeout: float = 30.0) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        while True:
            state = self.get(f"/analyses/{analysis_id}")
            if state["status"] in analyses.TERMINAL_STATUSES and state.get("finished_at"):
                return state
            if time.monotonic() > deadline:
                self.fail(f"analysis did not finish: {state}")
            time.sleep(0.02)

    # -- join ------------------------------------------------------------------------

    def test_rows_carry_flags_with_citation_and_join_info(self) -> None:
        self.standard_flags()
        page = self.get("/artifacts", kind="eventlog", limit=10)
        self.assertEqual(page["flags_join"]["status"], "joined")
        self.assertEqual(page["flags_join"]["analysis_id"], "flags-1")
        rows = page["artifacts"]["eventlog"]["artifacts"]
        self.assertEqual([len(row["flags"]) for row in rows], [0, 1, 0, 1])
        cleared = rows[1]["flags"][0]
        self.assertEqual(cleared["id"], CLEARED)
        self.assertEqual(cleared["version"], 3)  # the version the set was computed with
        self.assertEqual(cleared["citation"], f"{CLEARED}@3")
        self.assertEqual(cleared["status"], load_catalog().specs[CLEARED].status)
        self.assertEqual(
            {key: cleared["provenance"][key] for key in ("kind", "record_index", "recovery_method", "parser_version")},
            {"kind": "eventlog", "record_index": 1, "recovery_method": "carved", "parser_version": "eventlog-normalized-v21"},
        )
        shell = self.get("/artifacts", kind="windows-shellbags", limit=10)["artifacts"]["windows-shellbags"]["artifacts"]
        self.assertEqual([row["flags"] for row in shell], [[], []])

    def test_no_flag_set_rows_get_empty_flags_and_filter_is_409(self) -> None:
        page = self.get("/artifacts", kind="eventlog", limit=10)
        self.assertEqual(page["flags_join"]["status"], "no_source")
        self.assertIn("특이사항", page["flags_join"]["reason"])
        self.assertTrue(all(row["flags"] == [] for row in page["artifacts"]["eventlog"]["artifacts"]))
        response = self.client.get(f"/api/runs/{self.run_id}/artifacts", params={"kind": "eventlog", "limit": 10, "flag_grade": "A"})
        self.assertEqual(response.status_code, 409)
        self.assertIn("특이사항", response.json()["detail"])
        self.assertNotIn("flags", self.get("/tree"))

    def test_newest_completed_set_wins_and_running_or_crafted_ids_are_ignored(self) -> None:
        self.standard_flags()
        self.write_flag_set("flags-0", [{"kind": "eventlog", "record_index": 0, "flags": [flag(CLEARED, "A")]}], finished_at="2023-01-01T00:00:00+00:00")
        evil = self.write_flag_set("flags-9", [{"kind": "eventlog", "record_index": 0, "flags": [flag(CLEARED, "A")]}], finished_at="2030-01-01T00:00:00+00:00")
        state = json.loads((evil / "analysis.json").read_text(encoding="utf-8"))
        state["analysis_id"] = "../flags-1"  # a state file never chooses the directory read
        (evil / "analysis.json").write_text(json.dumps(state), encoding="utf-8")
        page = self.get("/artifacts", kind="eventlog", limit=10)
        self.assertEqual(page["flags_join"]["analysis_id"], "flags-1")
        self.assertEqual(page["artifacts"]["eventlog"]["artifacts"][1]["flags"][0]["id"], CLEARED)

    def test_index_is_built_once_and_rebuilt_when_the_set_changes(self) -> None:
        self.standard_flags()
        before = triage_flags.FLAGS_INDEX_CACHE.builds
        threads = [threading.Thread(target=lambda: self.client.get(f"/api/runs/{self.run_id}/artifacts", params={"kind": "eventlog", "limit": 5})) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(triage_flags.FLAGS_INDEX_CACHE.builds, before + 1)
        time.sleep(0.01)
        self.write_flag_set("flags-1", [{"kind": "eventlog", "record_index": 0, "flags": [flag(CLEARED, "A")]}])
        rows = self.get("/artifacts", kind="eventlog", limit=10)["artifacts"]["eventlog"]["artifacts"]
        self.assertEqual([bool(row["flags"]) for row in rows], [True, False, False, False])

    # -- filters / sort --------------------------------------------------------------

    def test_flag_grade_and_rule_filters(self) -> None:
        self.standard_flags()
        page = self.get("/artifacts", kind="eventlog", limit=10, flag_grade="A")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1])
        self.assertEqual(page["matched"], 1)
        self.assertEqual(page["pagination"]["flags"], {"flag": None, "flag_grade": "A"})
        page = self.get("/artifacts", kind="eventlog", limit=10, flag_grade="b")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1, 3])
        page = self.get("/artifacts", kind="eventlog", limit=10, flag=SERVICE)["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [3])
        page = self.get("/artifacts", kind="eventlog", limit=1, offset=1, flag=[SERVICE, CLEARED])["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [3])
        page = self.get("/artifacts", kind="eventlog", limit=10, flag=SERVICE, path_contains="nomatch")["artifacts"]["eventlog"]
        self.assertEqual(page["artifacts"], [])

    def test_flag_filter_across_kinds(self) -> None:
        self.standard_flags()
        page = self.get("/artifacts", limit=10, flag_grade="B")
        self.assertEqual(page["cross_kind"]["order"], [["eventlog", 1], ["eventlog", 3]])
        self.assertEqual(page["cross_kind"]["flags"], {"flag": None, "flag_grade": "B"})
        self.assertEqual(page["artifacts"]["windows-shellbags"]["artifacts"], [])
        self.assertTrue(all(row["flags"] for row in page["artifacts"]["eventlog"]["artifacts"]))

    def test_sort_flags_orders_grades_then_unflagged(self) -> None:
        self.standard_flags()
        page = self.get("/artifacts", kind="eventlog", limit=10, sort="flags")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1, 3, 0, 2])
        self.assertEqual(page["sort"]["key"], "flags")
        # A reordering, not a filter: filtered false, total = every record even when has_more.
        page = self.get("/artifacts", kind="eventlog", limit=1, sort="flags")["artifacts"]["eventlog"]
        self.assertTrue(page["pagination"]["has_more"])
        self.assertFalse(page["pagination"]["filtered"])
        self.assertEqual(page["pagination"]["total"], 4)
        self.assertEqual(page["matched"], 4)
        page = self.get("/artifacts", kind="eventlog", limit=2, offset=1, sort="flags")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [3, 0])
        page = self.get("/artifacts", kind="eventlog", limit=10, sort="flags", flag_grade="B")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1, 3])

    def test_flag_filter_with_field_sort(self) -> None:
        self.standard_flags()
        deadline = time.monotonic() + 20
        while True:
            page = self.get("/artifacts", kind="eventlog", limit=10, sort="details.event_id:desc", flag_grade="B")["artifacts"]["eventlog"]
            if page["sort"]["status"] == "ready" or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        self.assertEqual(page["sort"]["status"], "ready")
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [3, 1])  # 4688 > 1102
        self.assertEqual(page["pagination"]["flags"], {"flag": None, "flag_grade": "B"})

    def test_bad_flag_params(self) -> None:
        self.standard_flags()
        for params, status in (
            ({"kind": "eventlog", "limit": 10, "flag_grade": "Z"}, 422),
            ({"kind": "eventlog", "limit": 10, "flag": "no.such_rule"}, 422),
            ({"kind": "eventlog", "limit": 0, "flag_grade": "A"}, 400),
            ({"limit": 10, "sort": "flags"}, 400),
        ):
            response = self.client.get(f"/api/runs/{self.run_id}/artifacts", params=params)
            self.assertEqual(response.status_code, status, (params, response.text))
            self.assertRegex(json.dumps(response.json(), ensure_ascii=False), "[가-힣]|sort requires")
        # /files keeps ignoring sorts it does not have (only sort=flags exists there).
        response = self.client.get(f"/api/runs/{self.run_id}/files", params={"limit": 10, "sort": "name"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([row["record_index"] for row in response.json()["candidates"]], [0, 1, 2])
        for record_index in ("-5", "abc", "", "1.5"):
            response = self.client.get(f"/api/runs/{self.run_id}/flags/row", params={"kind": "eventlog", "record_index": record_index})
            self.assertEqual(response.status_code, 422, record_index)
            self.assertIn("record_index는 0 이상의 정수", response.json()["detail"])

    def test_files_join_filter_and_sort(self) -> None:
        self.standard_flags()
        page = self.get("/files", limit=10)
        self.assertEqual([bool(row["flags"]) for row in page["candidates"]], [False, False, True])
        self.assertEqual(page["flags_join"]["status"], "joined")
        page = self.get("/files", limit=10, flag_grade="B")
        self.assertEqual([row["record_index"] for row in page["candidates"]], [2])
        self.assertEqual(page["matched"], 1)
        page = self.get("/files", limit=10, flag_grade="B", category="archives")
        self.assertEqual(page["candidates"], [])
        page = self.get("/files", limit=10, sort="flags")
        self.assertEqual([row["record_index"] for row in page["candidates"]], [2, 0, 1])
        self.assertIn("ntfs_join", page)

    def test_analysis_rows_join_and_filter(self) -> None:
        directory = self.run_dir / "analyses" / "carve-1"
        directory.mkdir(parents=True)
        (directory / "rows.jsonl").write_text(
            "".join(json.dumps({"artifact_type": "carve-row", "details": {"n": index}}) + "\n" for index in range(3)), encoding="utf-8"
        )
        (directory / "analysis.json").write_text(
            json.dumps({"analysis_id": "carve-1", "kind": "carve", "status": "completed", "row_count": 3, "created_at": "2024-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )
        self.write_flag_set("flags-1", [{"kind": "analysis:carve-1", "record_index": 2, "flags": [flag(CLEARED, "A")]}])
        page = self.get("/analyses/carve-1/rows", limit=10)
        self.assertEqual([bool(row["flags"]) for row in page["rows"]], [False, False, True])
        page = self.get("/analyses/carve-1/rows", limit=10, flag_grade="A")
        self.assertEqual([row["record_index"] for row in page["rows"]], [2])
        page = self.get("/analyses/carve-1/rows", limit=10, sort="flags")
        self.assertEqual([row["record_index"] for row in page["rows"]], [2, 0, 1])

    # -- tree / meta / citations --------------------------------------------------------

    def test_tree_flags_section_and_counts(self) -> None:
        self.standard_flags()
        tree = self.get("/tree")
        section = tree["flags"]
        self.assertEqual(section["total"], 3)
        self.assertEqual(section["by_grade"], {"A": 1, "B": 1, "C": 0})
        self.assertEqual(section["by_rule"][0]["id"], CLEARED)  # A rules first
        self.assertEqual(section["policy"][0]["id"], "sysmon")
        self.assertEqual(section["source"]["analysis_id"], "flags-1")
        nodes = {node["id"]: node for node in tree["nodes"]}

        def walk(items):
            for node in items:
                yield node
                yield from walk(node.get("children") or [])

        everything = {node["id"]: node for node in walk(tree["nodes"])}
        self.assertEqual(everything["artifacts:eventlog"]["flag_counts"], {"A": 1, "B": 1, "C": 0})
        group = next(node for node in walk(nodes["artifacts"]["children"]) if node["id"].startswith("artifacts-group:") and any(child["id"] == "artifacts:eventlog" for child in node["children"]))
        self.assertEqual(group["flag_counts"]["A"], 1)
        self.assertIn("analysis:triage-flags", everything)
        self.assertEqual(everything["analysis:triage-flags"]["latest_completed"]["analysis_id"], "flags-1")

    def test_meta_families_matches_catalog(self) -> None:
        response = self.client.get("/api/meta/families")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        catalog = load_catalog()
        self.assertEqual(payload["version"], catalog.version)
        self.assertEqual(len(payload["rules"]), len(catalog.specs))
        family = next(item for item in payload["families"] if item["id"] == "eventlog-event")
        self.assertTrue(family["core_columns"])
        self.assertIn(CLEARED, family["rules"])
        rule = next(item for item in payload["rules"] if item["id"] == CLEARED)
        self.assertEqual(rule["grade"], "A")
        self.assertTrue(all(url.startswith("https://") for url in rule["sources"]))

    def test_row_citations_and_no_path_escape(self) -> None:
        self.standard_flags()
        payload = self.get("/flags/row", kind="eventlog", record_index=1)
        citation = payload["citations"][0]
        self.assertEqual(citation["citation"], f"{CLEARED}@3")
        self.assertEqual(
            citation["text"], f"{CLEARED}@3 (event_id=1102) [carved, windows-eventlog-evtx-native@eventlog-normalized-v21, #1]"
        )
        self.assertEqual(citation["provenance"]["recovery_method"], "carved")
        self.assertEqual(citation["provenance"]["record_index"], 1)
        files_citation = self.get("/flags/row", kind="files:candidates", record_index=2)["citations"][0]
        self.assertEqual(files_citation["provenance"]["recovery_method"], "parsed")
        self.assertEqual(self.get("/flags/row", kind="eventlog", record_index=0)["citations"], [])
        for kind in ("../../x", "../../etc/passwd", "..\\analyses\\flags-1", "files:../x", "analysis:../flags-1", "nope", ""):
            response = self.client.get(f"/api/runs/{self.run_id}/flags/row", params={"kind": kind, "record_index": 1})
            self.assertEqual(response.status_code, 422, kind)
            self.assertIn("이 런에 없는 행 종류", response.json()["detail"])
            self.assertNotIn("..", response.json()["detail"])  # the request value is not echoed
        self.assertEqual(self.get("/flags/row", kind="analysis:flags-1", record_index=0)["citations"], [])
        summary = self.get("/flags")
        self.assertEqual(summary["flags"]["total"], 3)

    # -- the triage-flags analysis kind ----------------------------------------------------

    def test_analysis_kind_runs_engine_and_joins(self) -> None:
        response = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "triage-flags", "options": {}})
        self.assertEqual(response.status_code, 202, response.text)
        state = self.wait(response.json()["analysis_id"])
        self.assertEqual(state["status"], "completed", state)
        self.assertEqual(state["summary"]["by_rule"].get(CLEARED), 1)
        self.assertGreaterEqual(state["progress"]["total"], 3)
        directory = Path(state["output_dir"])
        self.assertTrue((directory / "flags.jsonl").is_file())
        self.assertTrue(directory.resolve().is_relative_to(self.run_dir.resolve()))
        page = self.get("/artifacts", kind="eventlog", limit=10, flag_grade="A")["artifacts"]["eventlog"]
        self.assertEqual([row["record_index"] for row in page["artifacts"]], [1])  # Kernel-Cache 104 is not a log clear

    def test_analysis_kind_bad_options_are_korean_422(self) -> None:
        response = self.client.post(
            f"/api/runs/{self.run_id}/analyses", json={"kind": "triage-flags", "options": {"incident_start": "어제"}}
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("ISO-8601", json.dumps(response.json(), ensure_ascii=False))

    def test_analysis_kind_cancel_and_single_flight(self) -> None:
        release = threading.Event()
        entered = threading.Event()

        def slow(inputs, out_dir, *, progress, **_kwargs):
            entered.set()
            while not release.wait(0.01):
                progress.check_cancel()
            raise AssertionError("not cancelled")

        with patch.object(triage_engine, "run_triage_flags", slow):
            first = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "triage-flags", "options": {}})
            self.assertEqual(first.status_code, 202)
            analysis_id = first.json()["analysis_id"]
            self.assertTrue(entered.wait(10))
            second = self.client.post(f"/api/runs/{self.run_id}/analyses", json={"kind": "triage-flags", "options": {}})
            self.assertEqual(second.status_code, 409)
            self.assertEqual(second.json()["detail"], analyses.ALREADY_RUNNING_MESSAGE)
            self.client.post(f"/api/runs/{self.run_id}/analyses/{analysis_id}/cancel")
            state = self.wait(analysis_id)
            release.set()
        self.assertEqual(state["status"], "cancelled")
        self.assertFalse((self.run_dir / "analyses" / analysis_id / "flags.jsonl").exists())
        self.assertEqual(self.get("/artifacts", kind="eventlog", limit=5)["flags_join"]["status"], "no_source")

    # -- review follow-ups -----------------------------------------------------------------

    def test_cross_kind_after_cursor_with_flag_grade(self) -> None:
        self.write_flag_set(
            "flags-1",
            [
                {"kind": "eventlog", "record_index": 1, "flags": [flag(CLEARED, "A")]},
                {"kind": "eventlog", "record_index": 3, "flags": [flag(SERVICE, "B")]},
                {"kind": "windows-shellbags", "record_index": 1, "flags": [flag(SERVICE, "B")]},
            ],
        )
        seen: list[list[object]] = []
        after = None
        for _ in range(5):
            params = {"limit": 1, "flag_grade": "B", **({"after": after} if after else {})}
            page = self.get("/artifacts", **params)["cross_kind"]
            seen.extend(page["order"])
            after = page["next_after"]
            if not page["has_more"]:
                break
        self.assertEqual(seen, [["eventlog", 1], ["eventlog", 3], ["windows-shellbags", 1]])
        page = self.get("/artifacts", limit=10, flag_grade="A")["cross_kind"]
        self.assertEqual(page["order"], [["eventlog", 1]])
        self.assertEqual(page["matched"], 1)

    def test_too_large_flag_set_is_not_joined(self) -> None:
        self.standard_flags()
        with patch.object(triage_flags, "INDEX_MAX_BYTES", 10):
            page = self.get("/artifacts", kind="eventlog", limit=10)
            self.assertEqual(page["flags_join"]["status"], "too_large")
            self.assertIn("색인 한도", page["flags_join"]["reason"])
            self.assertTrue(all(row["flags"] == [] for row in page["artifacts"]["eventlog"]["artifacts"]))
            response = self.client.get(f"/api/runs/{self.run_id}/artifacts", params={"kind": "eventlog", "limit": 10, "flag_grade": "A"})
            self.assertEqual(response.status_code, 409)
            self.assertIn("색인 한도", response.json()["detail"])
            self.assertEqual(self.get("/tree")["flags"]["total"], 3)  # the tree only needs the summary

    def test_analysis_rows_field_sort_with_flag_filter(self) -> None:
        directory = self.run_dir / "analyses" / "carve-1"
        directory.mkdir(parents=True)
        (directory / "rows.jsonl").write_text(
            "".join(json.dumps({"artifact_type": "carve-row", "details": {"n": index}}) + "\n" for index in range(4)), encoding="utf-8"
        )
        (directory / "analysis.json").write_text(
            json.dumps({"analysis_id": "carve-1", "kind": "carve", "status": "completed", "row_count": 4, "created_at": "2024-01-01T00:00:00+00:00"}),
            encoding="utf-8",
        )
        self.write_flag_set(
            "flags-1",
            [
                {"kind": "analysis:carve-1", "record_index": 0, "flags": [flag(CLEARED, "A")]},
                {"kind": "analysis:carve-1", "record_index": 2, "flags": [flag(CLEARED, "A")]},
                {"kind": "analysis:carve-1", "record_index": 3, "flags": [flag(SERVICE, "B")]},
            ],
        )
        deadline = time.monotonic() + 20
        while True:
            page = self.get("/analyses/carve-1/rows", limit=10, sort="details.n:desc", flag_grade="A")
            if page["sort"]["status"] == "ready" or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        self.assertEqual(page["sort"]["status"], "ready")
        self.assertEqual([row["record_index"] for row in page["rows"]], [2, 0])
        self.assertEqual(page["pagination"]["flags"], {"flag": None, "flag_grade": "A"})
        self.assertTrue(all(row["flags"] for row in page["rows"]))

    def test_partial_flag_set_is_joined_with_a_reason(self) -> None:
        directory = self.write_flag_set("flags-1", [{"kind": "eventlog", "record_index": 1, "flags": [flag(CLEARED, "A")]}])
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        summary.update({"status": "partial", "coverage": {"complete": False, "incomplete": ["eventlog"], "sources": {}}})
        (directory / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        page = self.get("/artifacts", kind="eventlog", limit=10)
        info = page["flags_join"]
        self.assertEqual((info["status"], info["coverage"], info["incomplete_sources"]), ("joined", "partial", ["eventlog"]))
        self.assertIn("일부만 계산", info["reason"])
        self.assertTrue(page["artifacts"]["eventlog"]["artifacts"][1]["flags"])
        source = self.get("/tree")["flags"]["source"]
        self.assertEqual((source["coverage"], source["incomplete_sources"]), ("partial", ["eventlog"]))
        self.standard_flags()  # a complete set (rewritten) reports coverage complete
        triage_flags.invalidate_flag_sources()
        self.assertEqual(self.get("/artifacts", kind="eventlog", limit=1)["flags_join"]["coverage"], "complete")

    def test_unknown_grades_are_skipped_and_counted(self) -> None:
        self.write_flag_set(
            "flags-1",
            [
                {"kind": "eventlog", "record_index": 0, "flags": [flag(CLEARED, "Z")]},
                {"kind": "eventlog", "record_index": 1, "flags": [flag(CLEARED, "A"), flag(SERVICE, "")]},
            ],
        )
        page = self.get("/artifacts", kind="eventlog", limit=10)
        rows = page["artifacts"]["eventlog"]["artifacts"]
        self.assertEqual(rows[0]["flags"], [])
        self.assertEqual([item["id"] for item in rows[1]["flags"]], [CLEARED])
        self.assertEqual(page["flags_join"]["skipped_flags"], 2)
        self.assertEqual(self.get("/artifacts", kind="eventlog", limit=10, flag_grade="C")["artifacts"]["eventlog"]["matched"], 1)

    def test_source_list_is_cached_briefly(self) -> None:
        self.standard_flags()
        triage_flags.invalidate_flag_sources()
        calls = []
        original = analyses.ANALYSIS_RUNNER.list_states

        def counting(output_dir):
            calls.append(output_dir)
            return original(output_dir)

        with patch.object(analyses.ANALYSIS_RUNNER, "list_states", counting):
            for _ in range(3):
                self.get("/artifacts", kind="eventlog", limit=5)
            self.assertEqual(len(calls), 1)
            triage_flags.invalidate_flag_sources(self.run_dir)
            self.get("/artifacts", kind="eventlog", limit=5)
            self.assertEqual(len(calls), 2)

    def test_incident_window_order_is_validated(self) -> None:
        response = self.client.post(
            f"/api/runs/{self.run_id}/analyses",
            json={"kind": "triage-flags", "options": {"incident_start": "2024-05-02T00:00:00Z", "incident_end": "2024-05-01T00:00:00Z"}},
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("사건 시작 시각이 종료 시각보다 늦습니다", json.dumps(response.json(), ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
