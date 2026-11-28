"""Remote-use follow-ups, robustness slice: audit GAP-6/7/8/10, PR #89 review P2/P3, PR #90 review §4.

``RequestSizeTests`` and ``UnauthenticatedSurfaceTests`` are ported from the 2026-11-28
remote-use security audit (shared/rapid-remote-security-audit.md); every test asserts
the fixed behaviour. All data is synthetic (temporary folders only); no sockets are
opened and no real signal is sent.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import signal
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.body_limit import DEFAULT_MAX_BODY_BYTES, RequestBodyLimit
from rapidtriage.api.app.run_wait import chain_stop_signals
from rapidtriage.cli.web import run_web_server
from rapidtriage.core.case_db import CaseDatabase, apply_schema
from rapidtriage.core.case_db.review_tools import list_case_tags
from rapidtriage.core.jobs import RunJobStore

TOKEN = "audit-token-0123456789abcdef"
ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
EXECUTE = "rapidtriage.core.jobs.execute_run_request"


def fake_summary(request, *, run_id=None, **_kwargs) -> dict[str, object]:
    return {"output_dir": str(request.output_dir), "outputs": {}, "run_id": run_id}


class _Sandbox(unittest.TestCase):
    """evidence/ (input root), out/ (output root), home/ (server account home, outside both)."""

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
        self.home = base / "home"
        self.home.mkdir()
        env = mock.patch.dict(
            os.environ,
            {
                ROOTS_ENV: str(self.evidence),
                OUTPUT_ROOTS_ENV: str(self.output_root),
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "RAPIDTRIAGE_NO_BROWSER": "1",
                "RAPIDTRIAGE_CRASH_LOG_DIR": str(base / "crash"),
            },
        )
        env.start()
        self.addCleanup(env.stop)
        for key in (
            "RAPIDTRIAGE_TOKENS_FILE",
            "RAPIDTRIAGE_REVIEWER",
            "RAPIDTRIAGE_DISABLE_AUTH",
            "RAPIDTRIAGE_CASE_DB_UNRESTRICTED",
            "RAPIDTRIAGE_MAX_BODY_BYTES",
            "RAPIDTRIAGE_RUN_WAIT_SECONDS",
        ):
            os.environ.pop(key, None)
        self.store = RunJobStore(state_path=base / "state" / "runs.json")
        self.addCleanup(self.store._executor.shutdown, wait=True)
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def run_body(self, name: str, **extra: object) -> dict[str, object]:
        return {"root": str(self.case_dir), "mode": "fraud", "output_dir": str(self.output_root / name), **extra}

    def crash_reports(self) -> list[Path]:
        crash_dir = self.base / "crash"
        return list(crash_dir.rglob("*.json")) if crash_dir.exists() else []


class RequestSizeTests(_Sandbox):
    """GAP-6 (P2): JSON bodies had no size cap (only the hash-set upload had 50 MB)."""

    def test_oversized_json_body_is_refused_before_parsing(self) -> None:
        body = b'{"database": "x", "case_id": "c", "targets": [], "note": "' + b"A" * (65 * 1024 * 1024) + b'"}'
        response = self.client.post(
            "/api/case-db/review-batch", content=body, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status_code, 413, response.status_code)

    def test_body_without_content_length_is_counted(self) -> None:
        def chunks():
            for _ in range(9):
                yield b"A" * (1024 * 1024)

        response = self.client.post(
            "/api/case-db/review-batch", content=chunks(), headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(self.crash_reports(), [])

    def test_body_under_the_cap_still_reaches_the_route(self) -> None:
        response = self.client.post(
            "/api/case-db/review-batch", content=b"{}", headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status_code, 422, response.text)

    def test_cap_is_configurable(self) -> None:
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_MAX_BODY_BYTES": "4096"}):
            client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        body = json.dumps({"root": "x" * 8192}).encode()
        self.assertEqual(client.post("/api/runs", content=body, headers={"Content-Type": "application/json"}).status_code, 413)
        self.assertEqual(client.post("/api/runs", json={"root": ""}).status_code, 422)

    def test_hash_set_upload_keeps_its_own_cap(self) -> None:
        # Just above the route's 50 MB cap: the route answers (its own message), not the middleware.
        just_over = self.client.post(
            "/api/hash-sets?name=big", content=b"0" * (50 * 1024 * 1024 + 70 * 1024), headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(just_over.status_code, 413)
        self.assertIn("해시 세트", just_over.json()["detail"])
        far_over = self.client.post(
            "/api/hash-sets?name=big", content=b"0" * (52 * 1024 * 1024), headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(far_over.status_code, 413)

    def test_streamed_chunks_are_counted_across_messages(self) -> None:
        seen: list[str] = []

        async def app(scope, receive, send):
            while True:
                message = await receive()
                seen.append(message["type"])
                if message["type"] == "http.disconnect" or not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 400, "headers": []})
            await send({"type": "http.response.body", "body": b"cut off"})

        chunks = [{"type": "http.request", "body": b"x" * 600, "more_body": True} for _ in range(3)]
        chunks.append({"type": "http.request", "body": b"", "more_body": False})
        sent: list[dict] = []

        async def receive():
            return chunks.pop(0)

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "POST", "path": "/api/runs", "headers": []}
        asyncio.run(RequestBodyLimit(app, max_bytes=1000)(scope, receive, send))
        # The second chunk passes the cap: the app sees a disconnect, the client a 413 (not the app's 400).
        self.assertEqual(seen, ["http.request", "http.disconnect"])
        self.assertEqual(len(chunks), 2)
        self.assertEqual(sent[0]["status"], 413)
        self.assertEqual([message["type"] for message in sent], ["http.response.start", "http.response.body"])
        self.assertEqual(DEFAULT_MAX_BODY_BYTES, 8 * 1024 * 1024)


class UnauthenticatedSurfaceTests(_Sandbox):
    """GAP-7 (P2) and GAP-8 (P3): what a LAN device without a token can reach."""

    def test_non_ascii_token_header_is_401_without_a_crash_report(self) -> None:
        anonymous = TestClient(create_app(self.store, auth_token=TOKEN))
        response = anonymous.get("/api/runs", headers={"X-RapidTriage-Token": b"\xe9t\xe9"})
        self.assertEqual(response.status_code, 401, response.text)
        self.assertNotIn(str(self.base), response.text)
        self.assertEqual(self.crash_reports(), [], "unauthenticated request wrote a crash report")

    def test_non_ascii_token_matches_its_own_utf8_bytes(self) -> None:
        token = "토큰-0123456789abcdefghij"
        client = TestClient(create_app(self.store, auth_token=token))
        self.assertEqual(client.get("/api/runs", headers={"X-RapidTriage-Token": token.encode("utf-8")}).status_code, 200)
        self.assertEqual(client.get("/api/runs", headers={"X-RapidTriage-Token": b"\xed\x86"}).status_code, 401)

    def test_api_schema_and_cdn_docs_are_not_public(self) -> None:
        anonymous = TestClient(create_app(self.store, auth_token=TOKEN))
        for path in ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"):
            with self.subTest(path=path):
                self.assertIn(anonymous.get(path).status_code, (401, 403, 404))

    def test_token_holder_and_local_no_auth_still_get_the_schema(self) -> None:
        self.assertEqual(self.client.get("/openapi.json").status_code, 200)
        local = TestClient(create_app(self.store, require_auth=False))
        self.assertEqual(local.get("/openapi.json").status_code, 200)
        self.assertEqual(local.get("/docs").status_code, 200)


class RunWaitShutdownTests(_Sandbox):
    """PR #89 review P2: a stop signal answers waiting ``wait: true`` requests at once;
    queued runs are interrupted instead of run by the executor's exit join."""

    def blocking_execute(self) -> tuple[threading.Event, list[str]]:
        release = threading.Event()
        started: list[str] = []
        self.addCleanup(release.set)

        def execute(request, *, run_id=None, **_kwargs):
            started.append(str(run_id))
            release.wait(timeout=30)
            return fake_summary(request, run_id=run_id)

        patcher = mock.patch(EXECUTE, side_effect=execute)
        patcher.start()
        self.addCleanup(patcher.stop)
        return release, started

    def wait_until(self, condition, message: str) -> None:
        deadline = time.monotonic() + 10
        while not condition():
            if time.monotonic() > deadline:
                self.fail(message)
            time.sleep(0.02)

    def test_released_waits_answer_with_the_run_still_active(self) -> None:
        _release, started = self.blocking_execute()
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_RUN_WAIT_SECONDS": "30"}):
            with ThreadPoolExecutor(max_workers=1) as pool:
                posted = pool.submit(self.client.post, "/api/runs", json=self.run_body("waited", wait=True))
                self.wait_until(lambda: started, "the run never started")
                began = time.monotonic()
                self.client.app.state.run_waits.release_all()
                response = posted.result(timeout=10)
        self.assertLess(time.monotonic() - began, 5)
        self.assertEqual(response.status_code, 202, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "running")
        self.assertTrue(payload["wait_timed_out"])
        self.assertNotIn("summary", payload)
        # Once released, a further wait: true answers without waiting.
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_RUN_WAIT_SECONDS": "30"}):
            later = self.client.post("/api/runs", json=self.run_body("later", wait=True))
        self.assertIn(later.json()["status"], ("queued", "running"))
        self.assertTrue(later.json()["wait_timed_out"])

    def test_lifespan_routes_stop_signals_to_the_waits(self) -> None:
        hooks: list = []
        restored: list[bool] = []

        def chain(on_stop):
            hooks.append(on_stop)
            return lambda: restored.append(True)

        app = create_app(self.store, auth_token=TOKEN)
        with mock.patch("rapidtriage.api.app.factory.chain_stop_signals", side_effect=chain):
            with TestClient(app, headers={"X-RapidTriage-Token": TOKEN}) as client:
                self.assertEqual(len(hooks), 1)
                self.assertFalse(app.state.run_waits.released)
                hooks[0]()  # what the SIGTERM/SIGINT handler does: schedule the release on the loop
                self.assertEqual(client.get("/api/health").status_code, 200)
                self.assertTrue(app.state.run_waits.released)
        self.assertEqual(restored, [True])

    def test_queued_runs_are_interrupted_on_shutdown(self) -> None:
        release, started = self.blocking_execute()
        store = RunJobStore(max_workers=1, state_path=self.base / "state-queued" / "runs.json")
        self.addCleanup(store._executor.shutdown, wait=True)
        app = create_app(store, auth_token=TOKEN)
        with TestClient(app, headers={"X-RapidTriage-Token": TOKEN}) as client:
            run_ids = [client.post("/api/runs", json=self.run_body(f"queued-{index}")).json()["run_id"] for index in range(3)]
            self.wait_until(lambda: started, "the first run never started")
        # Lifespan shutdown: the running run is left alone, the queued ones never start.
        self.assertEqual([store.get(run_id).status for run_id in run_ids], ["running", "interrupted", "interrupted"])
        release.set()
        store._executor.shutdown(wait=True)
        self.assertEqual(started, [run_ids[0]])
        self.assertEqual([store.get(run_id).status for run_id in run_ids], ["completed", "interrupted", "interrupted"])
        queued = store.get(run_ids[1])
        self.assertEqual(queued.transition_log[-1]["event_type"], "job-interrupted-shutdown")
        saved = json.loads((self.base / "state-queued" / "runs.json").read_text(encoding="utf-8"))
        self.assertEqual({run["run_id"]: run["status"] for run in saved["runs"]}[run_ids[2]], "interrupted")

    def test_stop_signal_hook_chains_to_the_server_handler(self) -> None:
        calls: list[object] = []
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        for sig, handler in previous.items():
            self.addCleanup(signal.signal, sig, handler)
        signal.signal(signal.SIGTERM, lambda sig, _frame: calls.append(("server", sig)))
        restore = chain_stop_signals(lambda: calls.append("rapidtriage"))
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertEqual(calls, ["rapidtriage", ("server", signal.SIGTERM)])
        restore()
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertEqual(calls[-1], ("server", signal.SIGTERM))
        self.assertEqual(len(calls), 3)
        self.assertIs(signal.getsignal(signal.SIGINT), previous[signal.SIGINT])

    def test_stop_signal_hook_is_a_no_op_off_the_main_thread(self) -> None:
        before = signal.getsignal(signal.SIGTERM)
        results: list[object] = []
        worker = threading.Thread(target=lambda: results.append(chain_stop_signals(lambda: None)))
        worker.start()
        worker.join(timeout=5)
        self.assertEqual(len(results), 1)
        self.assertIs(signal.getsignal(signal.SIGTERM), before)
        results[0]()  # restoring is harmless too


class WaitCapRaceTests(_Sandbox):
    """PR #89 review P3: a run that ends right after the wait cap is reported completed."""

    def finished_after_the_cap(self, store: RunJobStore):
        """The run completes, but the wait sees its future only after the cap."""
        original = store.completion_future

        def completion_future(run_id: str):
            future = original(run_id)
            if future is not None:
                future.result(timeout=10)
            return Future()

        return mock.patch.object(store, "completion_future", side_effect=completion_future)

    def test_run_route_reports_completion_after_the_cap(self) -> None:
        with mock.patch(EXECUTE, side_effect=fake_summary), self.finished_after_the_cap(self.store):
            with mock.patch.dict(os.environ, {"RAPIDTRIAGE_RUN_WAIT_SECONDS": "0.05"}):
                response = self.client.post("/api/runs", json=self.run_body("raced", wait=True))
        self.assertEqual(response.status_code, 202, response.text)
        payload = response.json()
        self.assertEqual(payload["status"], "completed")
        self.assertFalse(payload["wait_timed_out"])
        self.assertIn("summary", payload)

    def test_case_run_route_reports_completion_after_the_cap(self) -> None:
        client = TestClient(
            create_app(self.store, auth_token=TOKEN, cases_db_path=self.output_root / "workspace" / "cases.db"),
            headers={"X-RapidTriage-Token": TOKEN},
        )
        case = client.post(
            "/api/cases",
            json={"case_number": "2026-테스트-1", "name": "합성", "case_type": "횡령", "examiner": "홍길동",
                  "case_root": str(self.output_root / "case-folder")},
        )
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["case"]["case_id"]
        evidence = client.post(
            f"/api/cases/{case_id}/evidence",
            json={"evidence_number": "E-01", "source_type": "folder", "path": str(self.case_dir)},
        )
        self.assertEqual(evidence.status_code, 201, evidence.text)
        citation = evidence.json()["evidence"]["citation_id"]
        with mock.patch(EXECUTE, side_effect=fake_summary), self.finished_after_the_cap(self.store):
            with mock.patch.dict(os.environ, {"RAPIDTRIAGE_RUN_WAIT_SECONDS": "0.05"}):
                response = client.post(
                    f"/api/cases/{case_id}/runs", json={"evidence_citation_id": citation, "mode": "fraud", "wait": True}
                )
        self.assertEqual(response.status_code, 202, response.text)
        run = response.json()["run"]
        self.assertEqual(run["status"], "completed")
        self.assertFalse(run["wait_timed_out"])
        self.assertIn("summary", run)


class WebServerLimitsTests(unittest.TestCase):
    """GAP-10: open-file limit, connection cap and keep-alive/shutdown timeouts at ``rapidtriage web`` start."""

    def fake_resource(self, soft: int, hard: int, *, fail: bool = False) -> types.SimpleNamespace:
        state = {"limits": (soft, hard), "set": []}

        def setrlimit(_kind, limits):
            if fail:
                raise ValueError("not allowed")
            state["set"].append(limits)
            state["limits"] = limits

        return types.SimpleNamespace(
            RLIMIT_NOFILE=8, RLIM_INFINITY=-1, getrlimit=lambda _kind: state["limits"], setrlimit=setrlimit, state=state
        )

    def start(self, *, resource=None, env: dict[str, str] | None = None) -> tuple[dict[str, object], str]:
        captured: dict[str, object] = {}
        fake_uvicorn = types.SimpleNamespace(run=lambda *args, **kwargs: captured.update(kwargs))
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_NO_BROWSER": "1", **(env or {})}):
            for key in ("RAPIDTRIAGE_TOKENS_FILE", "RAPIDTRIAGE_DISABLE_AUTH", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_TOKEN"):
                os.environ.pop(key, None)
            if env is None or "RAPIDTRIAGE_LIMIT_CONCURRENCY" not in env:
                os.environ.pop("RAPIDTRIAGE_LIMIT_CONCURRENCY", None)
            with mock.patch.dict(sys.modules, {"uvicorn": fake_uvicorn}), mock.patch("rapidtriage.cli.web.resource", resource):
                with redirect_stdout(out), redirect_stderr(io.StringIO()):
                    self.assertEqual(run_web_server("127.0.0.1", 8899, auth_token="local-token"), 0)
        return captured, out.getvalue()

    def test_uvicorn_gets_connection_cap_and_timeouts(self) -> None:
        captured, _out = self.start(resource=self.fake_resource(65536, 65536))
        self.assertEqual(captured["limit_concurrency"], 1000)
        self.assertEqual(captured["timeout_keep_alive"], 5)
        self.assertEqual(captured["timeout_graceful_shutdown"], 10)

    def test_soft_open_file_limit_is_raised_toward_the_hard_limit(self) -> None:
        capped = self.fake_resource(256, 1024)
        captured, out = self.start(resource=capped)
        self.assertEqual(capped.state["set"], [(1024, 1024)])
        self.assertEqual(captured["limit_concurrency"], 512)
        self.assertIn("1024", out)
        unlimited = self.fake_resource(256, -1)
        self.start(resource=unlimited)
        self.assertEqual(unlimited.state["set"], [(8192, -1)])

    def test_refused_raise_is_ignored_and_the_cap_follows_the_soft_limit(self) -> None:
        refused = self.fake_resource(256, 1024, fail=True)
        captured, out = self.start(resource=refused)
        self.assertEqual(captured["limit_concurrency"], 128)
        self.assertIn("ulimit -n", out)

    def test_no_resource_module_and_explicit_cap(self) -> None:
        captured, _out = self.start(resource=None, env={"RAPIDTRIAGE_LIMIT_CONCURRENCY": "64"})
        self.assertEqual(captured["limit_concurrency"], 64)
        captured, _out = self.start(resource=None, env={"RAPIDTRIAGE_LIMIT_CONCURRENCY": "abc"})
        self.assertEqual(captured["limit_concurrency"], 1000)


class SystemTagsUnderConcurrentWriteTests(unittest.TestCase):
    """PR #90 review §4: the first tag list of a case raced a writer into 'database is locked'."""

    CASE_ID = "CASE-TAGS"

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.database = CaseDatabase(Path(tmp.name) / "case.db")
        self.database.initialize()
        self.database.create_case(case_id=self.CASE_ID, examiner="검사관 A")

    def test_first_tag_list_waits_for_a_concurrent_writer(self) -> None:
        writer = sqlite3.connect(self.database.path, timeout=10, isolation_level=None)
        self.addCleanup(writer.close)
        paused = threading.Event()
        writer_holds_lock = threading.Event()
        tag_insert_started = threading.Event()
        outcome: dict[str, object] = {}

        def trace(sql: str) -> None:
            statement = " ".join(sql.split())
            # Pause once where no lock is held yet: before the write transaction (fixed) or
            # before the first read-then-insert of a shortcut tag (deferred transaction). The
            # traced SQL has its parameters expanded.
            if not paused.is_set() and (statement.startswith("BEGIN IMMEDIATE") or "AND shortcut =" in statement):
                paused.set()
                writer_holds_lock.wait(timeout=10)
            if statement.startswith("INSERT INTO case_tag"):
                tag_insert_started.set()

        def list_tags() -> None:
            try:
                with self.database.connect() as connection:  # as GET /api/cases/{id}/tags opens it
                    apply_schema(connection)
                    connection.set_trace_callback(trace)
                    outcome["tags"] = [tag["name"] for tag in list_case_tags(connection, self.CASE_ID)]
            except sqlite3.OperationalError as exc:
                outcome["error"] = str(exc)
            finally:
                tag_insert_started.set()

        reader = threading.Thread(target=list_tags)
        reader.start()
        self.assertTrue(paused.wait(timeout=10), "the tag list never reached its write")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO audit_event (citation_id, case_id, actor, action, target_type, target_id, timestamp, tool_name, tool_version, params_json, result, error) "
            "VALUES ('AUD-SYNTHETIC-1', ?, 'other-examiner', 'synthetic.write', 'case', ?, '2026-11-28T00:00:00+00:00', 'test', '0', '{}', 'ok', '')",
            (self.CASE_ID, self.CASE_ID),
        )
        writer_holds_lock.set()
        # A deferred read-then-insert fails at once; the fixed code waits for the lock.
        tag_insert_started.wait(timeout=0.5)
        writer.execute("COMMIT")
        reader.join(timeout=20)
        self.assertFalse(reader.is_alive())
        self.assertNotIn("error", outcome, outcome)
        self.assertEqual(len(outcome["tags"]), 6)
        with self.database.connect() as connection:
            again = [tag["name"] for tag in list_case_tags(connection, self.CASE_ID)]
        self.assertEqual(again, outcome["tags"])

    def test_concurrent_first_lists_create_each_system_tag_once(self) -> None:
        barrier = threading.Barrier(4)

        def list_tags() -> list[str]:
            barrier.wait(timeout=10)
            with self.database.connect() as connection:
                apply_schema(connection)
                return [tag["name"] for tag in list_case_tags(connection, self.CASE_ID)]

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = [future.result(timeout=30) for future in [pool.submit(list_tags) for _ in range(4)]]
        self.assertEqual(len({tuple(result) for result in results}), 1)
        self.assertEqual(len(results[0]), 6)


if __name__ == "__main__":
    unittest.main()
