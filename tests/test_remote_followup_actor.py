"""Remote-use follow-up (audit GAP-5, PR #92 P3 leftovers): who did what, and token-file upkeep.

Per-user tokens name the server's actor; the writes that used to record nobody (bookmarks,
case report, reviewer bundle, original export, search history, saved-search edits, hash sets,
analyses, case-DB imports) now record that name, edits keep an append-only trail and
regenerated reports keep the previous version. The tokens file is re-read when it changes,
``GET /api/whoami`` tells the console whose name it records, and run removals go to an
append-only log beside ``runs.json``. All data is synthetic (temporary folders only).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.analyses import ANALYSIS_RUNNER, TERMINAL_STATUSES
from rapidtriage.api.app.helpers import REQUEST_TOKEN_ACTOR
from rapidtriage.api.app.search_index_service import AUTO_INDEX_ENV, SEARCH_HISTORY
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.schema_validation import load_schema, validate
from rapidtriage.core.search_index.hashsets import DATA_DIR_ENV
from rapidtriage.core.user_tokens import TOKENS_FILE_ENV, load_user_tokens
from tests.search_index_fixture import build_fixture_run

ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
KIM = "tok-kim-0123456789abcdefghij"
LEE = "tok-lee-0123456789abcdefghij"
PARK = "tok-park-0123456789abcdefghi"
CLEARED_ENV = ("RAPIDTRIAGE_TOKEN", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_DISABLE_AUTH", "RAPIDTRIAGE_REVIEWER", TOKENS_FILE_ENV, "RAPIDTRIAGE_CASE_DB_UNRESTRICTED")


def write_tokens(path: Path, **tokens: str) -> Path:
    path.write_text("".join(f"{name}={token}\n" for name, token in tokens.items()), encoding="utf-8")
    path.chmod(0o600)
    return path


def json_file(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class _Sandbox(unittest.TestCase):
    """evidence/ (input root), out/ (output root), home/; per-user tokens kim and lee."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.base = base
        self.evidence = base / "evidence"
        self.case_dir = self.evidence / "case1"
        (self.case_dir / "docs").mkdir(parents=True)
        (self.case_dir / "docs" / "note.txt").write_text("synthetic evidence\n", encoding="utf-8")
        self.output_root = base / "out"
        self.output_root.mkdir()
        (base / "home").mkdir()
        env = mock.patch.dict(
            os.environ,
            {
                ROOTS_ENV: str(self.evidence),
                OUTPUT_ROOTS_ENV: str(self.output_root),
                "HOME": str(base / "home"),
                "USERPROFILE": str(base / "home"),
                "RAPIDTRIAGE_NO_BROWSER": "1",
                DATA_DIR_ENV: str(base / "data"),
            },
        )
        env.start()
        self.addCleanup(env.stop)
        for key in CLEARED_ENV:
            os.environ.pop(key, None)
        self.store = RunJobStore(state_path=base / "state" / "runs.json")
        self.tokens = write_tokens(base / "tokens", kim=KIM, lee=LEE)
        self.app = create_app(self.store, tokens_file=self.tokens)
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))
        self.kim = TestClient(self.app, headers={"X-RapidTriage-Token": KIM})
        self.lee = TestClient(self.app, headers={"X-RapidTriage-Token": LEE})

    def own_run(self, name: str) -> tuple[str, Path]:
        run = self.kim.post(
            "/api/runs",
            json={"root": str(self.case_dir), "mode": "fraud", "output_dir": str(self.output_root / name),
                  "read_only": True, "wait": True},
        )
        self.assertEqual(run.status_code, 202, run.text)
        return run.json()["run_id"], Path(run.json()["summary"]["output_dir"])

    def bookmark(self, client: TestClient, run_id: str, **body: object) -> dict:
        response = client.post(f"/api/runs/{run_id}/bookmarks", json={"source": "files", "pointer": "/candidates/0", **body})
        self.assertIn(response.status_code, (200, 201), response.text)
        return response.json()


class BookmarkAttributionTests(_Sandbox):
    """GAP-5 (ported audit repro): report bookmarks record no author."""

    def test_bookmark_and_its_history_name_the_token_owner(self) -> None:
        run_id, output_dir = self.own_run("bm")
        self.bookmark(self.kim, run_id, include_in_report=True)
        self.bookmark(self.lee, run_id, note="not relevant", include_in_report=False)
        case = json_file(output_dir / "rapidtriage-case.json")
        text = json.dumps(case, ensure_ascii=False)
        self.assertIn('"kim"', text, "bookmark creation is not attributed")
        self.assertIn('"lee"', text, "bookmark edit (report exclusion) is not attributed")

    def test_created_by_updated_by_and_an_append_only_trail(self) -> None:
        run_id, output_dir = self.own_run("bm2")
        self.bookmark(self.kim, run_id, include_in_report=True)
        self.bookmark(self.lee, run_id, note="not relevant", include_in_report=False)
        # A client-sent name is no author: lee's token decides.
        self.bookmark(self.lee, run_id, tags=["x"], reviewer="kim")
        case = json_file(output_dir / "rapidtriage-case.json")
        validate(case, load_schema("case.schema.json"))
        (bookmark,) = case["bookmarks"]
        self.assertEqual((bookmark["created_by"], bookmark["updated_by"]), ("kim", "lee"))
        trail = [(entry["action"], entry["actor"], entry["changed_fields"]) for entry in bookmark["review_history"]]
        self.assertEqual(
            trail,
            [
                ("created", "kim", ["bookmark", "review", "tags", "note"]),
                ("updated", "lee", ["review.include_in_report", "note"]),
                ("updated", "lee", ["tags"]),
            ],
        )
        audit = json_file(output_dir / "rapidtriage-case.audit.json")
        self.assertEqual(audit["provenance"]["options"]["actor"], "lee")

    def test_without_a_server_actor_the_fallback_is_local_user(self) -> None:
        app = create_app(self.store, auth_token="single-token-0123456789abcdef")
        client = TestClient(app, headers={"X-RapidTriage-Token": "single-token-0123456789abcdef"})
        run_id, output_dir = self.own_run("bm3")
        response = client.post(f"/api/runs/{run_id}/bookmarks", json={"source": "files", "pointer": "/candidates/0"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["case"]["bookmarks"][0]["created_by"], "local-user")
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "park"}):
            client.post(f"/api/runs/{run_id}/bookmarks", json={"source": "files", "pointer": "/candidates/0", "note": "n"})
        bookmark = json_file(output_dir / "rapidtriage-case.json")["bookmarks"][0]
        self.assertEqual([entry["actor"] for entry in bookmark["review_history"]], ["local-user", "park"])


class ReportAttributionTests(_Sandbox):
    """GAP-5: case report / reviewer bundle name who generated them and keep earlier versions."""

    def test_case_report_records_generated_by_and_keeps_the_previous_version(self) -> None:
        run_id, output_dir = self.own_run("rep")
        self.bookmark(self.kim, run_id, include_in_report=True)
        first = self.kim.post(f"/api/runs/{run_id}/case-report", json={"investigator": "client-says-lee"})
        self.assertEqual(first.status_code, 200, first.text)
        self.assertIsNone(first.json()["previous_version"])
        audit = json_file(output_dir / "rapidtriage-case-report.audit.md")
        self.assertEqual(audit["provenance"]["options"]["generated_by"], "kim")
        # The client's investigator stays a display field next to the server's actor.
        self.assertEqual(audit["provenance"]["options"]["investigator"], "client-says-lee")
        self.assertEqual(json_file(output_dir / "rapidtriage-case-report.exports.json")["generated_by"], "kim")

        second = self.lee.post(f"/api/runs/{run_id}/case-report", json={"title": "second"})
        self.assertEqual(second.status_code, 200, second.text)
        previous = Path(second.json()["previous_version"])
        self.assertEqual(previous.parent, output_dir / "rapidtriage-case-report-history")
        self.assertEqual(json_file(previous / "rapidtriage-case-report.audit.md")["provenance"]["options"]["generated_by"], "kim")
        self.assertEqual(json_file(previous / "rapidtriage-case-report.exports.json")["generated_by"], "kim")
        for name in ("rapidtriage-case-report.md", "rapidtriage-case-report.html", "rapidtriage-case-report.docx", "rapidtriage-case-report.pdf"):
            self.assertTrue((previous / name).is_file(), name)
        self.assertEqual(json_file(output_dir / "rapidtriage-case-report.audit.md")["provenance"]["options"]["generated_by"], "lee")

    def test_reviewer_bundle_records_generated_by_and_keeps_the_previous_version(self) -> None:
        run_id, output_dir = self.own_run("bun")
        self.bookmark(self.kim, run_id, include_in_report=True)
        first = self.kim.post(f"/api/runs/{run_id}/reviewer-bundle", json={})
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["generated_by"], "kim")
        bundle_dir = output_dir / "rapidtriage-reviewer-bundle"
        self.assertEqual(json_file(bundle_dir / "rapidtriage-bundle-audit.json")["generated_by"], "kim")
        self.assertEqual(json_file(bundle_dir / "rapidtriage-case-report.exports.json")["generated_by"], "kim")

        second = self.lee.post(f"/api/runs/{run_id}/reviewer-bundle", json={})
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(json_file(bundle_dir / "rapidtriage-bundle-manifest.json")["generated_by"], "lee")
        (previous,) = (output_dir / "rapidtriage-reviewer-bundle-history").iterdir()
        self.assertEqual(json_file(previous / "rapidtriage-reviewer-bundle" / "rapidtriage-bundle-audit.json")["generated_by"], "kim")
        self.assertTrue((previous / "rapidtriage-reviewer-bundle.zip").is_file())

        # Downloading serves the bundle the last POST built: no rebuild, no new history version.
        bundle_hash = hashlib.sha256((output_dir / "rapidtriage-reviewer-bundle.zip").read_bytes()).hexdigest()
        download = self.kim.get(f"/api/runs/{run_id}/reviewer-bundle/file")
        self.assertEqual(download.status_code, 200, download.text)
        self.assertEqual(hashlib.sha256(download.content).hexdigest(), bundle_hash)
        self.assertEqual(len(list((output_dir / "rapidtriage-reviewer-bundle-history").iterdir())), 1)


class ExtractAttributionTests(_Sandbox):
    """GAP-5: the original export names who asked for it."""

    def test_extract_manifest_records_the_requester(self) -> None:
        run_id, output_dir = self.own_run("ex")
        response = self.lee.post(f"/api/runs/{run_id}/extract", json={"rows": [{"path": str(self.case_dir / "docs" / "note.txt")}]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["requested_by"], "lee")
        manifest = json_file(output_dir / "extract" / response.json()["name"] / "rapidtriage-extract-manifest.json")
        self.assertEqual(manifest["requested_by"], "lee")
        validate(manifest, load_schema("extract.schema.json"))


class AnalysisAndHashSetAttributionTests(_Sandbox):
    """GAP-5 (cheap extras): analyses and hash sets name their requester / uploader."""

    def test_analysis_requester_and_canceller(self) -> None:
        run_id, _output_dir = self.own_run("an")
        real_execute = ANALYSIS_RUNNER._execute

        def held(key, context):  # the analysis waits for the cancel request, then runs (and stops)
            context.cancel_event.wait(30)
            real_execute(key, context)

        with mock.patch.object(ANALYSIS_RUNNER, "_execute", held):
            created = self.kim.post(f"/api/runs/{run_id}/analyses", json={"kind": "search-index", "options": {}})
            self.assertEqual(created.status_code, 202, created.text)
            self.assertEqual(created.json()["analysis"]["requested_by"], "kim")
            analysis_id = created.json()["analysis_id"]
            cancelled = self.lee.post(f"/api/runs/{run_id}/analyses/{analysis_id}/cancel")
            self.assertEqual(cancelled.status_code, 200, cancelled.text)
            self.assertEqual(cancelled.json()["cancel_requested_by"], "lee")
            deadline = time.monotonic() + 60
            while (state := self.kim.get(f"/api/runs/{run_id}/analyses/{analysis_id}").json())["status"] not in TERMINAL_STATUSES:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.05)
        self.assertEqual((state["status"], state["requested_by"], state["cancel_requested_by"]), ("cancelled", "kim", "lee"))

    def test_hash_set_uploader_and_deletion_log(self) -> None:
        uploaded = self.kim.post("/api/hash-sets", json={"name": "bad", "label": "known-bad", "lines": "d41d8cd98f00b204e9800998ecf8427e\n"})
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        self.assertEqual(uploaded.json()["uploaded_by"], "kim")
        hash_set_id = uploaded.json()["id"]
        self.assertEqual(self.lee.delete(f"/api/hash-sets/{hash_set_id}").status_code, 204)
        lines = (self.base / "data" / "hash-sets" / "hash-sets-deleted.jsonl").read_text(encoding="utf-8").splitlines()
        (record,) = [json.loads(line) for line in lines]
        self.assertEqual((record["id"], record["name"], record["uploaded_by"], record["deleted_by"]), (hash_set_id, "bad", "kim", "lee"))


class CaseDbImportAttributionTests(_Sandbox):
    """GAP-5 (cheap extra): case-DB run import audit names the server actor, not local-user."""

    def test_ensure_run_case_db_audit_actor(self) -> None:
        run_id, output_dir = self.own_run("db")
        # A fresh case DB in the run's own folder (the run's canonical DB is imported by the pipeline).
        response = self.lee.post(f"/api/runs/{run_id}/case-db/ensure", json={"database": str(output_dir / "review.db")})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["imported"])
        with sqlite3.connect(response.json()["database"]) as connection:
            actors = connection.execute("SELECT actor FROM audit_event WHERE action = 'run.imported'").fetchall()
        self.assertEqual(actors, [("lee",)])


class SearchAttributionTests(unittest.TestCase):
    """GAP-5: search history and saved-search edits/deletes name the server actor."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(SEARCH_HISTORY.flush)
        base = Path(temp.name)
        env = mock.patch.dict(os.environ, {DATA_DIR_ENV: str(base / "data"), AUTO_INDEX_ENV: "1"})
        env.start()
        self.addCleanup(env.stop)
        for key in CLEARED_ENV:
            os.environ.pop(key, None)
        self.run_dir = build_fixture_run(base)["run_dir"]
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.app = create_app(self.store, tokens_file=write_tokens(base / "tokens", kim=KIM, lee=LEE))
        self.addCleanup(lambda: ANALYSIS_RUNNER.shutdown(owner=self.app.state.analysis_owner))
        self.kim = TestClient(self.app, headers={"X-RapidTriage-Token": KIM})
        self.lee = TestClient(self.app, headers={"X-RapidTriage-Token": LEE})

    def url(self, suffix: str) -> str:
        return f"/api/runs/{self.run_id}{suffix}"

    def test_search_history_records_the_server_actor(self) -> None:
        build = self.kim.post(self.url("/search/index/build"), json={"mode": "full"})
        self.assertEqual(build.status_code, 202, build.text)
        deadline = time.monotonic() + 300
        while self.kim.get(self.url(f"/analyses/{build.json()['analysis_id']}")).json()["status"] not in TERMINAL_STATUSES:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.1)
        self.assertEqual(self.lee.post(self.url("/search/query"), json={"q": "급여대장"}).status_code, 200)
        history = self.kim.get(self.url("/search/history")).json()["history"]
        self.assertEqual([entry["actor"] for entry in history], ["lee"])

    def test_search_history_fallback_without_an_actor(self) -> None:
        output_dir = Path(tempfile.mkdtemp(dir=self.run_dir))
        reset = REQUEST_TOKEN_ACTOR.set(None)
        try:
            SEARCH_HISTORY.record(output_dir, {"q": "x"}, truncated=False)
        finally:
            REQUEST_TOKEN_ACTOR.reset(reset)
        SEARCH_HISTORY.flush()
        self.assertEqual([entry["actor"] for entry in SEARCH_HISTORY.read(output_dir, 5)], ["local-user"])

    def test_saved_search_update_and_delete_are_audited(self) -> None:
        open_case_database(self.run_dir / "rapidtriage-case.db").create_case(case_id=f"run-{self.run_id}", name="t")
        saved = self.kim.post(self.url("/search/saved"), json={"name": "급여", "q": "급여대장"})
        self.assertEqual(saved.status_code, 201, saved.text)
        saved_id = saved.json()["id"]
        self.assertEqual(self.lee.put(self.url(f"/search/saved/{saved_id}"), json={"name": "급여 전부"}).status_code, 200)
        self.assertEqual(self.lee.delete(self.url(f"/search/saved/{saved_id}")).status_code, 204)
        with open_case_database(self.run_dir / "rapidtriage-case.db").connect() as connection:
            rows = connection.execute(
                "SELECT action, actor, params_json FROM audit_event WHERE action LIKE 'search.saved.%' ORDER BY id"
            ).fetchall()
        self.assertEqual([(row[0], row[1]) for row in rows],
                         [("search.saved.create", "kim"), ("search.saved.update", "lee"), ("search.saved.delete", "lee")])
        deleted = json.loads(rows[2][2])
        # The hard delete keeps what was removed in the audit trail.
        self.assertEqual((deleted["name"], deleted["created_by"]), ("급여 전부", "kim"))

    def test_case_db_saved_search_upsert_keeps_the_original_author(self) -> None:
        database = open_case_database(self.run_dir / "upsert.db")
        database.create_case(case_id="c1", name="t")
        database.save_search(case_id="c1", name="s", keywords=["a"], created_by="kim")
        database.save_search(case_id="c1", name="s", keywords=["b"], created_by="lee")
        saved = database.get_saved_search("c1", name="s")
        self.assertEqual(saved["created_by"], "kim")
        with database.connect() as connection:
            audit = connection.execute("SELECT actor FROM audit_event WHERE action = 'search.saved.update'").fetchall()
        self.assertEqual([tuple(row) for row in audit], [("lee",)])


class TokenFileReloadTests(unittest.TestCase):
    """#92 P3: the tokens file is picked up when it changes; a bad edit keeps the last good set."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for key in CLEARED_ENV:
            os.environ.pop(key, None)
        self.path = write_tokens(Path(temp.name) / "tokens", kim=KIM, lee=LEE)
        self.app = create_app(RunJobStore(), tokens_file=self.path)

    def edit(self, text: str) -> None:
        previous = self.path.stat().st_mtime_ns
        self.path.write_text(text, encoding="utf-8")
        # A coarse-mtime file system: make the change visible.
        if self.path.stat().st_mtime_ns == previous:
            os.utime(self.path, ns=(previous + 1_000_000, previous + 1_000_000))

    def status(self, token: str) -> int:
        return TestClient(self.app, headers={"X-RapidTriage-Token": token}).get("/api/whoami").status_code

    def test_add_revoke_and_invalid_edit(self) -> None:
        self.assertEqual((self.status(KIM), self.status(LEE), self.status(PARK)), (200, 200, 401))
        self.edit(f"kim={KIM}\npark={PARK}\n")
        self.assertEqual((self.status(KIM), self.status(LEE), self.status(PARK)), (200, 401, 200))
        with self.assertLogs("rapidtriage.core.user_tokens", level="WARNING") as logs:
            self.edit(f"kim={KIM}\nkim={LEE}\n")  # repeated name: refused
            self.assertEqual((self.status(KIM), self.status(LEE), self.status(PARK)), (200, 401, 200))
        output = "\n".join(logs.output)
        self.assertIn("keeping the previous tokens", output)
        for token in (KIM, LEE, PARK):
            self.assertNotIn(token, output)
        self.edit(f"lee={LEE}\n")
        self.assertEqual((self.status(KIM), self.status(LEE), self.status(PARK)), (401, 200, 401))

    def test_deleted_file_keeps_the_last_good_set(self) -> None:
        self.path.unlink()
        with self.assertLogs("rapidtriage.core.user_tokens", level="WARNING"):
            self.assertEqual(self.status(KIM), 200)


class TokenCommentWarningTests(unittest.TestCase):
    """#92 P3: a '#' after a token is part of it; the loader warns (line number only)."""

    def test_trailing_comment_is_warned_without_the_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = write_tokens(Path(temp) / "tokens", kim=f"{KIM} # kim's laptop", lee=LEE)
            users = load_user_tokens(path)
        self.assertEqual(users.actor_for(f"{KIM} # kim's laptop"), "kim")
        (warning,) = [item for item in users.warnings if "#" in item]
        self.assertIn("line(s) 1", warning)
        self.assertNotIn(KIM, warning)
        self.assertNotIn("laptop", warning)


class WhoamiTests(unittest.TestCase):
    """#92 P3: ``GET /api/whoami`` names the actor the server records (never the token)."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for key in CLEARED_ENV:
            os.environ.pop(key, None)

    def test_per_user_token(self) -> None:
        app = create_app(RunJobStore(), tokens_file=write_tokens(self.base / "tokens", kim=KIM))
        response = TestClient(app, headers={"X-RapidTriage-Token": KIM}).get("/api/whoami")
        self.assertEqual(response.json(), {"actor": "kim", "source": "token", "per_user_tokens": True})
        self.assertNotIn(KIM, response.text)
        self.assertEqual(TestClient(app).get("/api/whoami").status_code, 401)

    def test_single_token_with_and_without_reviewer(self) -> None:
        app = create_app(RunJobStore(), auth_token="single-token-0123456789abcdef")
        client = TestClient(app, headers={"X-RapidTriage-Token": "single-token-0123456789abcdef"})
        self.assertEqual(client.get("/api/whoami").json(), {"actor": None, "source": None, "per_user_tokens": False})
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "park"}):
            self.assertEqual(client.get("/api/whoami").json(), {"actor": "park", "source": "env", "per_user_tokens": False})
        self.assertEqual(TestClient(app).get("/api/whoami").status_code, 401)


class RemovedRunsLogTests(unittest.TestCase):
    """#92 P3: removal records go to an append-only ``runs-removed.jsonl``, not into ``runs.json``."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.output = self.root / "out"
        self.output.mkdir()
        summary = {"command": "run", "output_dir": str(self.output), "outputs": {}}
        (self.output / "rapidtriage-run-summary.json").write_text(json.dumps(summary), encoding="utf-8")

    def test_removal_is_logged_beside_runs_json_and_survives_a_restart(self) -> None:
        state = self.root / "runs.json"
        store = RunJobStore(state_path=state)
        run_id = store.import_completed_run(self.output).run_id
        store.remove(run_id, actor="lee")
        self.assertNotIn("removed_runs", json_file(state))
        lines = (self.root / "runs-removed.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual([(json.loads(line)["run_id"], json.loads(line)["removed_by"]) for line in lines], [(run_id, "lee")])
        restarted = RunJobStore(state_path=state)
        self.assertEqual([record["removed_by"] for record in restarted.removed_runs()], ["lee"])

    def test_legacy_removed_runs_move_to_the_log(self) -> None:
        state = self.root / "runs.json"
        legacy = {"run_id": "old", "status": "completed", "owner": "kim", "root": "/x", "output_dir": None,
                  "removed_at": "2026-11-01T00:00:00+00:00", "removed_by": "kim"}
        state.write_text(json.dumps({"version": 1, "runs": [], "removed_runs": [legacy]}), encoding="utf-8")
        store = RunJobStore(state_path=state)
        self.assertEqual(store.removed_runs(), [legacy])
        self.assertNotIn("removed_runs", json_file(state))
        self.assertEqual(RunJobStore(state_path=state).removed_runs(), [legacy])

    def test_in_memory_store_keeps_records(self) -> None:
        store = RunJobStore()
        run_id = store.import_completed_run(self.output).run_id
        store.remove(run_id, actor="kim")
        self.assertEqual([record["removed_by"] for record in store.removed_runs()], ["kim"])


if __name__ == "__main__":
    unittest.main()
