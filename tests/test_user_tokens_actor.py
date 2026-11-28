"""Per-user tokens and the server-decided actor (remote-use review R5, R12).

With ``RAPIDTRIAGE_TOKENS_FILE`` each person has a token and the server records who acted from
it: review marks, tags, notes and run create/cancel/delete. The ``reviewer``/``actor`` names a
client sends do not count then. In single-token mode ``RAPIDTRIAGE_REVIEWER`` is the server's
actor. All data is synthetic.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.cli import run_web_server
from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.run.plan import CONTROL_FILE_NAME, build_run_plan
from rapidtriage.core.run.progress import RunProgress
from rapidtriage.core.user_tokens import (
    TOKENS_FILE_ENV,
    UserTokenFileError,
    load_user_tokens,
)

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from fastapi import HTTPException

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.helpers import REQUEST_TOKEN_ACTOR
    from rapidtriage.api.app.routes_actions import ActionActor, actor_reviewer

CASE_ID = "CASE-R5"
TOKENS = {"kim": "tok-kim-0123456789", "lee": "tok-lee-0123456789", "agent:triage-bot": "tok-bot-0123456789"}
ENV_KEYS = ("RAPIDTRIAGE_TOKEN", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_DISABLE_AUTH", "RAPIDTRIAGE_REVIEWER", TOKENS_FILE_ENV)


@contextlib.contextmanager
def clean_env(**overrides: str):
    with mock.patch.dict(os.environ):
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        os.environ.update(overrides)
        yield


def write_tokens(path: Path, tokens: dict[str, str] = TOKENS) -> Path:
    lines = ["# synthetic per-user tokens", ""] + [f"{name} = {token}" for name, token in tokens.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class UserTokenFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "tokens"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_each_token_names_its_user(self) -> None:
        users = load_user_tokens(write_tokens(self.path))
        for name, token in TOKENS.items():
            self.assertEqual(users.actor_for(token), name)
        for wrong in ("", "tok-kim", "tok-kim-0123456789 ", "tok-kim-01234567890", "토큰"):
            self.assertIsNone(users.actor_for(wrong), wrong)

    def test_bad_files_are_refused_without_echoing_a_token(self) -> None:
        cases = {
            "no separator": "kim tok-secret-aaaa\n",
            "empty token": "kim=\n",
            "empty name": "=tok-secret-aaaa\n",
            "repeated name": "kim=tok-secret-aaaa\nKIM=tok-secret-bbbb\n",
            "repeated token": "kim=tok-secret-aaaa\nlee=tok-secret-aaaa\n",
            "agent without a name": "agent:=tok-secret-aaaa\n",
            # agent:<name>@<person> would no longer name one person (PR #92 review P3).
            "@ in a name": "kim@lee=tok-secret-aaaa\n",
            "no entry": "# only a comment\n\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                self.path.write_text(text, encoding="utf-8")
                with self.assertRaises(UserTokenFileError) as raised:
                    load_user_tokens(self.path)
                self.assertNotIn("tok-secret", str(raised.exception))
        with self.assertRaises(UserTokenFileError):
            load_user_tokens(Path(self.temp.name) / "missing")

    def test_notepad_bom_short_tokens_and_open_mode(self) -> None:
        # PR #92 review P3: a UTF-8 BOM made the first name "\ufeffkim" and refused the file.
        long_token = "tok-kim-0123456789abcdef0123"
        self.path.write_text(f"\ufeffkim={long_token}\nlee=short-token\n", encoding="utf-8")
        self.path.chmod(0o600)
        users = load_user_tokens(self.path)
        self.assertEqual(users.actor_for(long_token), "kim")
        self.assertEqual(len(users.warnings), 1)
        self.assertIn("line(s) 2: tokens shorter than 24", users.warnings[0])
        if os.name == "posix":
            self.path.chmod(0o644)
            warnings = load_user_tokens(self.path).warnings
            self.assertTrue(any("chmod 600" in warning for warning in warnings), warnings)
        for warning in load_user_tokens(self.path).warnings:
            self.assertNotIn("short-token", warning)
            self.assertNotIn("lee", warning)

    def test_web_server_prints_no_token_and_refuses_a_shared_token_beside_it(self) -> None:
        write_tokens(self.path)
        captured: dict[str, object] = {}
        fake_uvicorn = types.SimpleNamespace(run=lambda *args, **kwargs: captured.update(kwargs))
        out, err = io.StringIO(), io.StringIO()
        with clean_env(**{TOKENS_FILE_ENV: str(self.path), "RAPIDTRIAGE_NO_BROWSER": "1"}):
            with mock.patch.dict(sys.modules, {"uvicorn": fake_uvicorn}):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(run_web_server("0.0.0.0", 8899, remote=True), 0)
            # No single token was generated or exported next to the per-user tokens.
            self.assertNotIn("RAPIDTRIAGE_AUTH_TOKEN", os.environ)
            with self.assertRaisesRegex(RuntimeError, "replaces the single API token"):
                run_web_server("127.0.0.1", 8899, auth_token="shared-token")
            with self.assertRaisesRegex(RuntimeError, "needs API authentication"):
                run_web_server("127.0.0.1", 8899, allow_remote_without_auth=True)
        self.assertEqual(captured["host"], "0.0.0.0")
        printed = out.getvalue() + err.getvalue()
        self.assertIn("per-user tokens for 3 users", printed)
        self.assertIn("WARNING: RAPIDTRIAGE_TOKENS_FILE line(s) 3, 4, 5: tokens shorter than 24", err.getvalue())
        for token in TOKENS.values():
            self.assertNotIn(token, printed)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class PerUserTokenApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "case.db"
        database = CaseDatabase(self.database)
        database.initialize()
        database.create_case(case_id=CASE_ID, examiner="검사관 A")
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO file_record (citation_id, case_id, path, normalized_path, created_at) "
                "VALUES ('F-1', ?, 'C:/synthetic/1.txt', 'c:/synthetic/1.txt', '2026-11-28T00:00:00+00:00')",
                (CASE_ID,),
            )
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "note.txt").write_text("synthetic", encoding="utf-8")
        self.store = RunJobStore(state_path=self.root / "runs.json")
        # Runs stay queued: nothing executes in these tests.
        self.store._execute = lambda run_id: {}  # type: ignore[method-assign]
        self.env = clean_env()
        self.env.__enter__()
        self.app = create_app(
            self.store,
            tokens_file=write_tokens(self.root / "tokens"),
            case_db_roots=[self.root],
            cases_db_path=self.root / "workspace" / "rapidtriage-cases.db",
        )

    def tearDown(self) -> None:
        self.env.__exit__(None, None, None)
        self.temp.cleanup()

    def client(self, name: str | None) -> TestClient:
        headers = {"X-RapidTriage-Token": TOKENS[name]} if name else {}
        return TestClient(self.app, headers=headers)

    def history_actors(self) -> list[str]:
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            rows = connection.execute(
                "SELECT actor FROM review_mark_history WHERE case_id = ? AND target_id = '1' ORDER BY version", (CASE_ID,)
            ).fetchall()
        return [row[0] for row in rows]

    def test_only_a_listed_token_gets_in(self) -> None:
        self.assertEqual(self.client(None).get("/api/runs").status_code, 401)
        for token in ("tok-kim", "shared-token", TOKENS["kim"] + "x"):
            with self.subTest(token=token):
                response = TestClient(self.app, headers={"X-RapidTriage-Token": token}).get("/api/runs")
                self.assertEqual(response.status_code, 401)
                self.assertNotIn(TOKENS["kim"], response.text)
        self.assertEqual(self.client("lee").get("/api/runs").status_code, 200)
        with self.assertRaisesRegex(RuntimeError, TOKENS_FILE_ENV):
            create_app(RunJobStore(), auth_token="shared-token", tokens_file=self.root / "tokens")

    def test_marks_and_tags_record_the_token_owner_not_the_client_reviewer(self) -> None:
        # R5: the console sends whatever name the browser stored; kim claims to be lee and back.
        for name, fake in (("kim", "lee"), ("lee", "kim"), ("agent:triage-bot", "kim")):
            response = self.client(name).post(
                "/api/case-db/review-batch",
                json={
                    "database": str(self.database),
                    "case_id": CASE_ID,
                    "targets": [{"target_type": "file_record", "target_id": "1"}],
                    "status": "relevant",
                    "add_tags": [f"tag-{fake}"],
                    "note": f"{name} wrote this",
                    "reviewer": fake,
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["marks"][0]["reviewer"], name)
        self.assertEqual(self.history_actors(), ["kim", "lee", "agent:triage-bot"])

        tag = self.client("lee").post(
            f"/api/cases/{CASE_ID}/tags", params={"database": str(self.database)}, json={"name": "송금 정황", "created_by": "kim"}
        )
        self.assertEqual(tag.status_code, 201, tag.text)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            created_by = connection.execute("SELECT created_by FROM case_tag WHERE name = '송금 정황'").fetchone()[0]
        self.assertEqual(created_by, "lee")

    def test_case_notes_record_the_token_owner(self) -> None:
        case = self.client("kim").post("/api/cases", json={"case_number": "2026-R5-001", "examiner": "lee"})
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["case"]["case_id"]
        note = self.client("lee").post(f"/api/cases/{case_id}/notes", json={"text": "합성 메모", "author": "kim"})
        self.assertEqual(note.status_code, 201, note.text)
        self.assertEqual(note.json()["note"]["author"], "lee")

    def test_case_db_saved_search_records_the_token_owner(self) -> None:
        # PR #92 review P2: the console's save button sent created_by and it was stored as sent.
        saved = self.client("kim").post(
            "/api/case-db/saved-searches",
            json={"database": str(self.database), "case_id": CASE_ID, "name": "s1", "keywords": ["invoice"], "created_by": "lee"},
        )
        self.assertEqual(saved.status_code, 200, saved.text)
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            created_by = connection.execute("SELECT created_by FROM saved_search WHERE name = 's1'").fetchone()[0]
        self.assertEqual(created_by, "kim")

    def test_running_cancel_names_the_token_owner_in_the_control_file_and_plan(self) -> None:
        # PR #92 review P2: the control file kept only web/cli, so lee's cancel read as the CLI's.
        output_dir = self.root / "out"
        created = self.client("kim").post("/api/runs", json={"root": str(self.evidence), "mode": "hacking", "output_dir": str(output_dir)})
        self.assertEqual(created.status_code, 202, created.text)
        self.store.get(created.json()["run_id"]).status = "running"  # a live run: the cancel goes to its control file
        self.assertEqual(self.client("lee").post(f"/api/runs/{created.json()['run_id']}/cancel").status_code, 200)
        requests = json.loads((output_dir / CONTROL_FILE_NAME).read_text(encoding="utf-8"))["requests"]
        self.assertEqual([(item["action"], item["actor"], item["by"]) for item in requests], [("cancel_all", "web", "lee")])

        # The run process applies it: the plan and report name lee, and that it came from the web.
        progress = RunProgress(output_dir, heartbeat_interval=0)
        progress.start(stage="artifacts")
        progress.set_plan(build_run_plan(mode="hacking"))
        progress.apply_control(requests[0])
        requested_by = progress.task_record("email")["requested_by"]
        self.assertEqual((requested_by["actor"], requested_by["source"]), ("lee", "web"))

    def test_runs_record_owner_canceller_and_remover(self) -> None:
        # R12: anyone may cancel or remove a run; the server now records who did.
        created = self.client("kim").post("/api/runs", json={"root": str(self.evidence), "mode": "hacking"})
        self.assertEqual(created.status_code, 202, created.text)
        run_id = created.json()["run_id"]
        self.assertEqual(created.json()["owner"], "kim")

        notes = self.client("lee").put(f"/api/runs/{run_id}/case-notes", json={"examiner": "kim", "summary": "합성"})
        self.assertEqual(notes.status_code, 200, notes.text)
        self.assertEqual(notes.json()["updated_by"], "lee")

        cancelled = self.client("lee").post(f"/api/runs/{run_id}/cancel")
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.assertEqual(cancelled.json()["status"], "cancelled")
        requests = [entry for entry in cancelled.json()["transition_log"] if entry["event_type"] == "cancel-requested"]
        self.assertEqual([entry["details"]["actor"] for entry in requests], ["lee"])

        retried = self.client("agent:triage-bot").post(f"/api/runs/{run_id}/retry")
        self.assertEqual(retried.status_code, 202, retried.text)
        self.assertEqual(retried.json()["owner"], "agent:triage-bot")

        self.assertEqual(self.client("lee").delete(f"/api/runs/{run_id}").status_code, 204)
        saved = json.loads((self.root / "runs.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [(record["run_id"], record["owner"], record["removed_by"]) for record in saved["removed_runs"]],
            [(run_id, "kim", "lee")],
        )
        # The removal record survives a restart; the owner persists with the remaining run.
        restarted = RunJobStore(state_path=self.root / "runs.json")
        self.assertEqual(restarted.removed_runs()[0]["removed_by"], "lee")
        self.assertEqual(restarted.get(retried.json()["run_id"]).owner, "agent:triage-bot")
        for token in TOKENS.values():
            self.assertNotIn(token, (self.root / "runs.json").read_text(encoding="utf-8"))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ActionActorTests(unittest.TestCase):
    """Action API ``actor`` (PR #77) under per-user tokens: the token outranks the body."""

    def reviewer(self, token_name: str | None, **actor: str) -> str:
        reset = REQUEST_TOKEN_ACTOR.set(token_name)
        try:
            return actor_reviewer(ActionActor(**actor))
        finally:
            REQUEST_TOKEN_ACTOR.reset(reset)

    def test_token_decides_who_marks(self) -> None:
        with clean_env():
            self.assertEqual(self.reviewer("kim", kind="human", name="lee"), "kim")
            self.assertEqual(self.reviewer("kim", kind="agent", name="triage-bot"), "agent:triage-bot@kim")
            self.assertEqual(self.reviewer("agent:triage-bot", kind="human", name="kim"), "agent:triage-bot")
            self.assertEqual(self.reviewer("agent:triage-bot", kind="agent", name="other"), "agent:triage-bot")
            # Single-token mode keeps PR #77's rules.
            self.assertEqual(self.reviewer(None, kind="agent", name="triage-bot"), "agent:triage-bot")
            self.assertEqual(self.reviewer(None, kind="human", name="김분석"), "김분석")
            with self.assertRaises(HTTPException):
                self.reviewer("kim", kind="human", name="agent:bot")
            # "x@lee" from kim's token would read as lee's agent (PR #92 review P3).
            for token_name in ("kim", None):
                with self.subTest(token_name=token_name), self.assertRaises(HTTPException):
                    self.reviewer(token_name, kind="agent", name="x@lee")
        with clean_env(RAPIDTRIAGE_REVIEWER="서버 검토자"):
            self.assertEqual(self.reviewer(None, kind="human", name="김분석"), "서버 검토자")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class SingleTokenModeTests(unittest.TestCase):
    def test_reviewer_env_owns_web_runs_and_marks(self) -> None:
        with tempfile.TemporaryDirectory() as temp, clean_env(RAPIDTRIAGE_REVIEWER="kim"):
            root = Path(temp)
            store = RunJobStore()
            store._execute = lambda run_id: {}  # type: ignore[method-assign]
            client = TestClient(create_app(store, auth_token="single-token"), headers={"X-RapidTriage-Token": "single-token"})
            created = client.post("/api/runs", json={"root": str(root), "mode": "hacking"})
            self.assertEqual(created.status_code, 202, created.text)
            self.assertEqual(created.json()["owner"], "kim")
            cancelled = client.post(f"/api/runs/{created.json()['run_id']}/cancel")
            requests = [entry for entry in cancelled.json()["transition_log"] if entry["event_type"] == "cancel-requested"]
            self.assertEqual(requests[0]["details"]["actor"], "kim")


if __name__ == "__main__":
    unittest.main()
