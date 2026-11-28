"""Remote-use path confinement (remote review R1, R2, R10; fixes 1 and 2).

Synthetic trees only: an evidence root, an output root, and a fake home with a
fake secret outside both. ``RAPIDTRIAGE_ANALYSIS_ROOTS`` /
``RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS`` are the operator's server roots; ``--remote``
refuses to start without them.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.helpers import allowed_case_db_roots
from rapidtriage.cli import run_web_server
from rapidtriage.core.jobs import RunJobStore

TOKEN = "remote-path-test-token"
ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
SECRET = "synthetic secret: not real\n"


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class RemotePathConfinementTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.evidence = base / "evidence"
        self.case_dir = self.evidence / "case1"
        (self.case_dir / "docs").mkdir(parents=True)
        (self.case_dir / "docs" / "note.txt").write_text("synthetic evidence\n", encoding="utf-8")
        self.output_root = base / "out"
        self.output_root.mkdir()
        self.home = base / "home"
        (self.home / "secrets").mkdir(parents=True)
        self.secret = self.home / "secrets" / "id_fake.txt"
        self.secret.write_text(SECRET, encoding="utf-8")
        self.store = RunJobStore()
        self.client = TestClient(
            create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}
        )
        self.roots = {ROOTS_ENV: str(self.evidence), OUTPUT_ROOTS_ENV: str(self.output_root)}

    def _roots(self):
        return patch.dict(os.environ, self.roots)

    def _no_roots(self):
        saved = {key: os.environ.pop(key) for key in (ROOTS_ENV, OUTPUT_ROOTS_ENV) if key in os.environ}
        self.addCleanup(os.environ.update, saved)
        return contextlib.nullcontext()

    def _run(self, root: Path, output_dir: Path | None, **extra) -> object:
        body = {"root": str(root), "mode": "fraud", "read_only": True, "dry_run": True, "max_file_count": 5, "wait": True}
        if output_dir is not None:
            body["output_dir"] = str(output_dir)
        body.update(extra)
        return self.client.post("/api/runs", json=body)

    # --- fix 1: run inputs / outputs (R1, R10) ------------------------------------

    def test_run_root_outside_analysis_roots_is_422_and_no_run(self) -> None:
        with self._roots():
            response = self._run(self.home, self.output_root / "attack")
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("허용 범위", response.json()["detail"])
        self.assertEqual(self.store.list(), [])
        self.assertFalse((self.output_root / "attack").exists())

    def test_large_folder_outside_roots_is_refused_before_any_scan(self) -> None:
        # R3 repro used a 40k-file tree with wait:true; outside the roots it never reaches the scanner.
        big = self.home / "big"
        for index in range(50):
            folder = big / f"d{index:02d}"
            folder.mkdir(parents=True)
            for name in range(40):
                (folder / f"f{name}.txt").write_text("x", encoding="utf-8")
        with self._roots(), patch("rapidtriage.core.jobs.execute_run_request") as execute:
            started = time.monotonic()
            response = self._run(big, self.output_root / "big", dry_run=False, max_file_count=0)
            elapsed = time.monotonic() - started
        self.assertEqual(response.status_code, 422, response.text)
        execute.assert_not_called()
        self.assertEqual(self.store.list(), [])
        self.assertLess(elapsed, 5.0)

    def test_output_dir_outside_output_roots_is_422(self) -> None:
        with self._roots():
            explicit = self._run(self.case_dir, self.home / "out")
            inside_evidence = self._run(self.case_dir, self.evidence / "out")
            default_next_to_evidence = self._run(self.case_dir, None)
        for response in (explicit, inside_evidence):
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("허용 범위", response.json()["detail"])
        self.assertEqual(default_next_to_evidence.status_code, 422, default_next_to_evidence.text)
        self.assertIn(OUTPUT_ROOTS_ENV, default_next_to_evidence.json()["detail"])
        self.assertEqual(self.store.list(), [])
        self.assertFalse((self.evidence / "out").exists())

    def test_rules_and_known_good_feeds_outside_roots_are_422(self) -> None:
        with self._roots():
            rules = self._run(self.case_dir, self.output_root / "r1", rules=str(self.secret))
            feeds = self._run(self.case_dir, self.output_root / "r2", known_good_hash_feeds=[str(self.secret)])
        for response in (rules, feeds):
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.store.list(), [])

    def test_run_inside_roots_is_accepted_and_serves_its_evidence(self) -> None:
        with self._roots():
            response = self._run(self.case_dir, self.output_root / "run1")
            self.assertEqual(response.status_code, 202, response.text)
            run_id = response.json()["run_id"]
            inside = self.client.get(
                f"/api/runs/{run_id}/source-file", params={"path": str(self.case_dir / "docs" / "note.txt")}
            )
            outside = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.secret)})
        self.assertEqual(inside.status_code, 200, inside.text)
        self.assertEqual(outside.status_code, 403, outside.text)

    def test_run_registered_before_roots_cannot_read_outside_files(self) -> None:
        # R1 repro: root=<fake home> → source-file of the fake secret was 200.
        with self._no_roots():
            legacy = self._run(self.home, self.home.parent / "legacy-out")
            self.assertEqual(legacy.status_code, 202, legacy.text)
            run_id = legacy.json()["run_id"]
            before = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.secret)})
            self.assertEqual(before.status_code, 200)
            self.assertEqual(before.text, SECRET)
        with self._roots():
            after = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.secret)})
            retry = self.client.post(f"/api/runs/{run_id}/retry", json={})
            case_db_roots = allowed_case_db_roots(self.store)
        self.assertEqual(after.status_code, 403, after.text)
        self.assertNotIn(SECRET, after.text)
        self.assertEqual(retry.status_code, 422, retry.text)
        self.assertNotIn((self.home.parent / "legacy-out").resolve(), case_db_roots)

    @unittest.skipUnless(os.name == "posix" and Path("/etc/hosts").is_file(), "POSIX /etc/hosts")
    def test_etc_dry_run_is_refused_and_an_older_etc_run_gets_403(self) -> None:
        # R1 repro: {"root":"/etc","dry_run":true,"max_file_count":5,"wait":true} → source-file /etc/hosts 200.
        with self._roots():
            refused = self._run(Path("/etc"), self.output_root / "etc")
        self.assertEqual(refused.status_code, 422, refused.text)
        with self._no_roots():
            legacy = self._run(Path("/etc"), self.home.parent / "out-etc")
            self.assertEqual(legacy.status_code, 202, legacy.text)
            run_id = legacy.json()["run_id"]
        with self._roots():
            response = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": "/etc/hosts"})
        self.assertEqual(response.status_code, 403, response.text)

    def test_import_outside_roots_is_422(self) -> None:
        with self._no_roots():
            legacy = self._run(self.home, self.home / "run-out")
            self.assertEqual(legacy.status_code, 202, legacy.text)
        with self._roots():
            response = self.client.post("/api/runs/import", json={"output_dir": str(self.home / "run-out")})
        self.assertEqual(response.status_code, 422, response.text)

    def test_identify_collect_plan_and_readiness_paths_outside_roots_are_422(self) -> None:
        with self._roots():
            identify = self.client.post("/api/evidence/identify", json={"path": str(self.secret)})
            plan = self.client.post("/api/collect/plan", json={"root": str(self.home)})
            package = self.client.get("/api/commercial-readiness", params={"validation_package": str(self.home / "p.json")})
            mac = self.client.get("/api/commercial-readiness", params={"mac_first_evidence": str(self.home)})
            inside = self.client.post("/api/evidence/identify", json={"path": str(self.case_dir)})
        for response in (identify, plan, package, mac):
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(inside.status_code, 200, inside.text)

    # --- fix 2: /api/browse (R2) ------------------------------------------------------

    def test_browse_lists_only_server_roots(self) -> None:
        with self._roots():
            top = self.client.get("/api/browse")
            filesystem_root = self.client.get("/api/browse", params={"path": os.path.abspath(os.sep)})
            home = self.client.get("/api/browse", params={"path": str(self.home)})
            inside = self.client.get("/api/browse", params={"path": str(self.evidence)})
        self.assertEqual(top.status_code, 200, top.text)
        listing = top.json()
        self.assertTrue(listing["at_roots"])
        self.assertEqual(listing["home"], "")
        self.assertEqual({entry["path"] for entry in listing["entries"]}, {str(self.evidence), str(self.output_root)})
        self.assertEqual({root["path"] for root in listing["roots"]}, {str(self.evidence), str(self.output_root)})
        self.assertEqual(filesystem_root.status_code, 403, filesystem_root.text)
        self.assertEqual(home.status_code, 403, home.text)
        self.assertEqual(inside.status_code, 200, inside.text)
        self.assertEqual([entry["name"] for entry in inside.json()["entries"]], ["case1"])
        self.assertIsNone(inside.json()["parent"])
        self.assertEqual(inside.json()["home"], "")

    def test_browse_without_roots_is_unchanged_for_local_use(self) -> None:
        with self._no_roots():
            response = self.client.get("/api/browse", params={"path": str(self.home)})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("at_roots", response.json())
        self.assertEqual([entry["name"] for entry in response.json()["entries"]], ["secrets"])


class RemoteModeRequiresRootsTests(unittest.TestCase):
    KEYS = ("RAPIDTRIAGE_TOKEN", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_DISABLE_AUTH", ROOTS_ENV, OUTPUT_ROOTS_ENV)

    def setUp(self) -> None:
        saved = {key: os.environ.pop(key) for key in self.KEYS if key in os.environ}

        def restore() -> None:
            for key in self.KEYS:
                os.environ.pop(key, None)
            os.environ.update(saved)

        self.addCleanup(restore)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()

    def test_remote_without_roots_refuses_to_start(self) -> None:
        with self.assertRaises(RuntimeError) as raised:
            run_web_server("127.0.0.1", 8899, remote=True, auth_token="t" * 32)
        self.assertIn(ROOTS_ENV, str(raised.exception))
        self.assertIn(OUTPUT_ROOTS_ENV, str(raised.exception))

    def test_remote_ignores_invalid_root_entries_when_checking(self) -> None:
        os.environ[ROOTS_ENV] = "relative/evidence"
        os.environ[OUTPUT_ROOTS_ENV] = str(self.base)
        with self.assertRaises(RuntimeError) as raised:
            run_web_server("127.0.0.1", 8899, remote=True, auth_token="t" * 32)
        self.assertIn(ROOTS_ENV, str(raised.exception))
        self.assertNotIn(OUTPUT_ROOTS_ENV, str(raised.exception))

    def test_remote_with_roots_starts(self) -> None:
        os.environ[ROOTS_ENV] = str(self.base / "evidence")
        os.environ[OUTPUT_ROOTS_ENV] = str(self.base / "out")
        captured: dict[str, object] = {}
        fake = types.SimpleNamespace(run=lambda *args, **kwargs: captured.update(kwargs))
        with patch.dict(sys.modules, {"uvicorn": fake}), contextlib.redirect_stderr(io.StringIO()):
            result = run_web_server("127.0.0.1", 8899, remote=True, auth_token="t" * 32)
        self.assertEqual(result, 0)
        self.assertEqual(captured["host"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
