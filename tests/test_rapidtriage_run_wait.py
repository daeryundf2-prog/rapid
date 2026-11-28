"""``wait: true`` runs are bounded and never hold request threads (remote-use review R3).

Before the fix every ``wait: true`` request ran its whole run inside a request
thread: 40 concurrent ones exhausted the server's thread pool and ``/api/health``
stopped answering. These tests drive a real uvicorn server on 127.0.0.1 with
synthetic runs that block until released.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

try:
    import uvicorn

    from rapidtriage.api.app import create_app
    from rapidtriage.core.jobs import RunJobStore

    HAS_SERVER = True
except ImportError:  # pragma: no cover - web deps are base requirements
    HAS_SERVER = False

TOKEN = "run-wait-test-token"
CONCURRENT_WAIT_REQUESTS = 40
RUN_WORKERS = 2


@unittest.skipUnless(HAS_SERVER, "fastapi and uvicorn are required")
class WaitTrueRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.temp = Path(self._temp.name)
        self.evidence = self.temp / "evidence"
        self.evidence.mkdir()
        (self.evidence / "a.txt").write_text("synthetic", encoding="utf-8")
        self.release = threading.Event()
        self.running = 0
        self.max_running = 0
        self._count_lock = threading.Lock()
        execute = patch("rapidtriage.core.jobs.execute_run_request", side_effect=self._blocking_execute)
        execute.start()
        self.addCleanup(execute.stop)
        self.store = RunJobStore(max_workers=RUN_WORKERS)
        self.base_url = self._start_server()

    def tearDown(self) -> None:
        self.release.set()
        self.server.should_exit = True
        self.server_thread.join(timeout=15)
        self.store._executor.shutdown(wait=True)
        self._temp.cleanup()

    def _blocking_execute(self, request, *, run_id=None, **_kwargs):
        with self._count_lock:
            self.running += 1
            self.max_running = max(self.max_running, self.running)
        try:
            self.release.wait(timeout=60)
        finally:
            with self._count_lock:
                self.running -= 1
        return {"output_dir": str(request.output_dir), "outputs": {}}

    def _start_server(self) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        app = create_app(self.store, auth_token=TOKEN)
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
        self.server_thread = threading.Thread(target=self.server.run, kwargs={"sockets": [sock]}, daemon=True)
        self.server_thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline:
                self.fail("uvicorn did not start")
            time.sleep(0.02)
        return f"http://127.0.0.1:{port}"

    def _request(self, method: str, path: str, body: dict | None = None, *, timeout: float) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base_url + path,
            method=method,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers={"X-RapidTriage-Token": TOKEN, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def _wait_run(self, index: int, *, timeout: float) -> tuple[int, dict]:
        body = {"root": str(self.evidence), "mode": "fraud", "output_dir": str(self.temp / f"out-{index}"), "wait": True}
        return self._request("POST", "/api/runs", body, timeout=timeout)

    def test_forty_concurrent_wait_runs_leave_health_responsive(self) -> None:
        with patch.dict(os.environ, {"RAPIDTRIAGE_RUN_WAIT_SECONDS": "60"}):
            with ThreadPoolExecutor(max_workers=CONCURRENT_WAIT_REQUESTS) as clients:
                posts = [clients.submit(self._wait_run, index, timeout=90) for index in range(CONCURRENT_WAIT_REQUESTS)]
                deadline = time.monotonic() + 20
                while len(self.store.list()) < CONCURRENT_WAIT_REQUESTS:
                    if time.monotonic() > deadline:
                        self.fail(f"only {len(self.store.list())} of {CONCURRENT_WAIT_REQUESTS} runs were queued")
                    time.sleep(0.05)

                # All 40 requests are still waiting on their runs: the server keeps answering.
                started = time.monotonic()
                status, health = self._request("GET", "/api/health", timeout=5)
                self.assertEqual((status, health), (200, {"status": "ok"}))
                status, listed = self._request("GET", "/api/runs", timeout=5)
                self.assertEqual(status, 200)
                self.assertEqual(len(listed["runs"]), CONCURRENT_WAIT_REQUESTS)
                self.assertLess(time.monotonic() - started, 5)
                self.assertTrue(all(not post.done() for post in posts))

                self.release.set()
                results = [post.result(timeout=60) for post in posts]

        self.assertEqual({status for status, _payload in results}, {202})
        self.assertEqual({payload["status"] for _status, payload in results}, {"completed"})
        self.assertEqual({payload["wait_timed_out"] for _status, payload in results}, {False})
        self.assertTrue(all("summary" in payload for _status, payload in results))
        # Runs went through the worker pool instead of one request thread each.
        self.assertLessEqual(self.max_running, RUN_WORKERS)

    def test_wait_past_the_limit_answers_with_the_run_still_active(self) -> None:
        with patch.dict(os.environ, {"RAPIDTRIAGE_RUN_WAIT_SECONDS": "0.3"}):
            started = time.monotonic()
            status, payload = self._wait_run(0, timeout=10)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(status, 202)
        self.assertIn(payload["status"], {"queued", "running"})
        self.assertTrue(payload["wait_timed_out"])
        self.assertNotIn("summary", payload)

        # The run keeps going after the response; the client polls it.
        self.release.set()
        deadline = time.monotonic() + 10
        while True:
            _status, polled = self._request("GET", f"/api/runs/{payload['run_id']}", timeout=5)
            if polled["status"] == "completed":
                break
            if time.monotonic() > deadline:
                self.fail(f"run stayed {polled['status']}")
            time.sleep(0.05)


if __name__ == "__main__":
    unittest.main()
