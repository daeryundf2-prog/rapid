from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
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
from rapidtriage.cli import run_web_server
from rapidtriage.core.jobs import RunJobStore
from tests.test_rapidtriage_run import build_run_fixture

TEST_API_TOKEN = "rapidtriage-test-token"


def security_test_client(store: RunJobStore | None = None, case_db_roots=None):
    return TestClient(
        create_app(store or RunJobStore(), auth_token=TEST_API_TOKEN, case_db_roots=case_db_roots),
        headers={"X-RapidTriage-Token": TEST_API_TOKEN},
    )


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class RapidTriageApiSecurityTests(unittest.TestCase):
    def _completed_run(self, client, tmp_dir: str) -> str:
        root = Path(tmp_dir) / "case-root"
        output_dir = Path(tmp_dir) / "run-out"
        root.mkdir(parents=True, exist_ok=True)
        build_run_fixture(root)
        run_response = client.post(
            "/api/runs",
            json={
                "root": str(root),
                "mode": "fraud",
                "output_dir": str(output_dir),
                "read_only": True,
                "wait": True,
            },
        )
        self.assertEqual(run_response.status_code, 202, run_response.text)
        return run_response.json()["run_id"]

    def test_auth_token_accepts_and_rejects_requests(self) -> None:
        client = security_test_client(RunJobStore())
        ok = client.get("/api/health")
        self.assertEqual(ok.status_code, 200)

        denied = TestClient(
            create_app(RunJobStore(), auth_token=TEST_API_TOKEN),
            headers={"X-RapidTriage-Token": "wrong-token"},
        )
        self.assertEqual(denied.get("/api/health").status_code, 401)

        missing = TestClient(create_app(RunJobStore(), auth_token=TEST_API_TOKEN))
        self.assertEqual(missing.get("/api/health").status_code, 401)

    def test_case_db_ensure_uses_run_output_dir_root_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = security_test_client(RunJobStore())
            run_id = self._completed_run(client, tmp_dir)

            response = client.post(f"/api/runs/{run_id}/case-db/ensure", json={})

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            default_db = (Path(tmp_dir) / "run-out" / "rapidtriage-case.db").resolve()
            self.assertEqual(payload["database"], str(default_db))
            self.assertTrue(default_db.is_file())

    def test_case_db_rejects_database_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            outside_dir = Path(tmp_dir) / "outside-roots"
            db_path = outside_dir / "nested" / "escape.db"
            client = security_test_client(RunJobStore())

            response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-OUT-OF-ROOT",
                    "keywords": ["password"],
                },
            )

            self.assertEqual(response.status_code, 403, response.text)
            self.assertIn("outside allowed case-db roots", response.json()["detail"])
            self.assertFalse(db_path.exists())

    def test_case_db_allows_explicit_create_app_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            allowed_root = Path(tmp_dir) / "case-dbs"
            db_path = allowed_root / "case.db"
            client = security_test_client(RunJobStore(), case_db_roots=[allowed_root])

            response = client.post(
                "/api/case-db/saved-searches/list",
                json={"database": str(db_path), "case_id": "CASE-EXPLICIT-ROOT"},
            )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(db_path.is_file())

    def test_case_db_allows_env_var_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_root = Path(tmp_dir) / "env-roots"
            db_path = env_root / "deep" / "case.db"
            client = security_test_client(RunJobStore())

            with patch.dict(os.environ, {"RAPIDTRIAGE_CASE_DB_ROOTS": str(env_root)}):
                response = client.post(
                    "/api/case-db/saved-searches/list",
                    json={"database": str(db_path), "case_id": "CASE-ENV-ROOT"},
                )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(db_path.is_file())

    def test_case_db_unrestricted_env_restores_legacy_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "anywhere" / "case.db"
            client = security_test_client(RunJobStore())

            with patch.dict(os.environ, {"RAPIDTRIAGE_CASE_DB_UNRESTRICTED": "1"}):
                response = client.post(
                    "/api/case-db/saved-searches/list",
                    json={"database": str(db_path), "case_id": "CASE-UNRESTRICTED"},
                )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(db_path.is_file())


class RapidTriageWebServerSecurityTests(unittest.TestCase):
    def test_run_web_server_warns_when_auth_disabled_on_remote_host(self) -> None:
        captured_run: dict[str, object] = {}
        fake_uvicorn = types.SimpleNamespace(
            run=lambda *args, **kwargs: captured_run.update({"args": args, "kwargs": kwargs})
        )
        stderr = io.StringIO()
        previous = os.environ.pop("RAPIDTRIAGE_DISABLE_AUTH", None)
        try:
            with patch.dict(sys.modules, {"uvicorn": fake_uvicorn}):
                with contextlib.redirect_stderr(stderr):
                    result = run_web_server("0.0.0.0", 8877, allow_remote_without_auth=True)
        finally:
            if previous is None:
                os.environ.pop("RAPIDTRIAGE_DISABLE_AUTH", None)
            else:
                os.environ["RAPIDTRIAGE_DISABLE_AUTH"] = previous

        self.assertEqual(result, 0)
        self.assertEqual(captured_run["kwargs"]["host"], "0.0.0.0")
        warning = stderr.getvalue()
        self.assertIn("WARNING", warning)
        self.assertIn("authentication is DISABLED", warning)

    def test_run_web_server_refuses_remote_bind_without_token_or_flag(self) -> None:
        fake_uvicorn = types.SimpleNamespace(run=lambda *args, **kwargs: None)
        with patch.dict(sys.modules, {"uvicorn": fake_uvicorn}):
            with self.assertRaises(RuntimeError) as raised:
                run_web_server("0.0.0.0", 8877)
        self.assertIn("non-localhost", str(raised.exception))

    def test_run_web_server_allows_loopback_without_auth_flag(self) -> None:
        captured: dict[str, object] = {}
        fake_uvicorn = types.SimpleNamespace(
            run=lambda *args, **kwargs: captured.update({"kwargs": kwargs})
        )
        stderr = io.StringIO()
        previous_disable = os.environ.pop("RAPIDTRIAGE_DISABLE_AUTH", None)
        previous_token = os.environ.get("RAPIDTRIAGE_AUTH_TOKEN")
        try:
            with patch.dict(sys.modules, {"uvicorn": fake_uvicorn}):
                with contextlib.redirect_stderr(stderr):
                    result = run_web_server("127.0.0.1", 8877, auth_token="fixed-token")
        finally:
            if previous_disable is None:
                os.environ.pop("RAPIDTRIAGE_DISABLE_AUTH", None)
            else:
                os.environ["RAPIDTRIAGE_DISABLE_AUTH"] = previous_disable
            if previous_token is None:
                os.environ.pop("RAPIDTRIAGE_AUTH_TOKEN", None)
            else:
                os.environ["RAPIDTRIAGE_AUTH_TOKEN"] = previous_token

        self.assertEqual(result, 0)
        self.assertNotIn("DISABLED", stderr.getvalue())
        self.assertNotIn("RAPIDTRIAGE_DISABLE_AUTH", os.environ)


if __name__ == "__main__":
    unittest.main()
