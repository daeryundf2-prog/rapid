"""Path-confinement tests for the /api/case-catalog* endpoints.

Mirrors the case-database confinement tests in
tests/test_rapidtriage_api_security.py: catalog paths are confined to the
same allowed roots (run output directories, server working directory,
~/.rapidtriage, and RAPIDTRIAGE_CASE_DB_ROOTS entries).
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HAS_FASTAPI = importlib.util.find_spec("fastapi") is not None

from rapidtriage.core.jobs import RunJobStore
from tests.test_rapidtriage_api_security import security_test_client
from tests.test_rapidtriage_run import build_run_fixture


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class RapidTriageCaseCatalogSecurityTests(unittest.TestCase):
    def _completed_run_output(self, client, tmp_dir: str) -> Path:
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
        return output_dir

    def test_case_catalog_default_path_is_allowed(self) -> None:
        client = security_test_client(RunJobStore())

        response = client.get("/api/case-catalog")

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIn("catalog", payload)
        self.assertIn("cases", payload)

    def test_case_catalog_rejects_path_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            catalog_path = Path(tmp_dir) / "outside-roots" / "nested" / "escape.json"
            client = security_test_client(RunJobStore())

            response = client.get("/api/case-catalog", params={"catalog": str(catalog_path)})

            self.assertEqual(response.status_code, 403, response.text)
            self.assertIn("outside allowed case-db roots", response.json()["detail"])
            self.assertFalse(catalog_path.exists())

    def test_case_catalog_add_run_rejects_path_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            catalog_path = Path(tmp_dir) / "outside-roots" / "escape.json"
            client = security_test_client(RunJobStore())

            response = client.post(
                "/api/case-catalog/add-run",
                json={
                    "catalog": str(catalog_path),
                    "run_output": str(Path(tmp_dir) / "run-out"),
                    "case_id": "CASE-OUT-OF-ROOT",
                },
            )

            self.assertEqual(response.status_code, 403, response.text)
            self.assertIn("outside allowed case-db roots", response.json()["detail"])
            self.assertFalse(catalog_path.exists())

    def test_case_catalog_add_run_allows_run_output_dir_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = security_test_client(RunJobStore())
            run_output = self._completed_run_output(client, tmp_dir)
            catalog_path = run_output / "case-catalog.json"

            response = client.post(
                "/api/case-catalog/add-run",
                json={
                    "catalog": str(catalog_path),
                    "run_output": str(run_output),
                    "case_id": "CASE-IN-ROOT",
                },
            )

            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(catalog_path.is_file())

    def test_case_catalog_allows_explicit_create_app_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            allowed_root = Path(tmp_dir) / "catalogs"
            catalog_path = allowed_root / "case-catalog.json"
            client = security_test_client(RunJobStore(), case_db_roots=[allowed_root])

            response = client.get("/api/case-catalog", params={"catalog": str(catalog_path)})

            self.assertEqual(response.status_code, 200, response.text)

    def test_case_catalog_allows_env_var_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_root = Path(tmp_dir) / "env-roots"
            catalog_path = env_root / "deep" / "case-catalog.json"
            client = security_test_client(RunJobStore())

            with patch.dict(os.environ, {"RAPIDTRIAGE_CASE_DB_ROOTS": str(env_root)}):
                response = client.get("/api/case-catalog", params={"catalog": str(catalog_path)})

            self.assertEqual(response.status_code, 200, response.text)

    def test_case_catalog_unrestricted_env_restores_legacy_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            catalog_path = Path(tmp_dir) / "anywhere" / "case-catalog.json"
            client = security_test_client(RunJobStore())

            with patch.dict(os.environ, {"RAPIDTRIAGE_CASE_DB_UNRESTRICTED": "1"}):
                response = client.get("/api/case-catalog", params={"catalog": str(catalog_path)})

            self.assertEqual(response.status_code, 200, response.text)


if __name__ == "__main__":
    unittest.main()
