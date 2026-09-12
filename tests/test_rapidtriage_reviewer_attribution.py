from __future__ import annotations

import contextlib
import getpass
import io
import json
import os
import tempfile
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
from rapidtriage.cli import main
from rapidtriage.cli.helpers import resolve_reviewer_identity
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.jobs import RunJobStore

TEST_API_TOKEN = "rapidtriage-reviewer-test-token"


def _prepare_case_db(tmp_dir: str, case_id: str = "CASE-REVIEWER") -> tuple[Path, str]:
    db_path = Path(tmp_dir) / "case.db"
    database = open_case_database(db_path)
    database.create_case(case_id=case_id)
    with database.connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO artifact (
                citation_id, case_id, artifact_type, parser_name, title, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"{case_id}-ART-000001",
                case_id,
                "browser-history-visit",
                "rapidtriage-browser",
                "visit example.com",
                "2026-05-16T00:00:00+00:00",
            ),
        )
        return db_path, str(cursor.lastrowid)


def _cli_review(db_path: Path, case_id: str, target_id: str, *extra: str) -> dict[str, object]:
    stdout = io.StringIO()
    argv = [
        "case-review",
        str(db_path),
        "--case-id",
        case_id,
        "--target-type",
        "artifact",
        "--target-id",
        target_id,
        "--status",
        "relevant",
        "--json",
        *extra,
    ]
    with contextlib.redirect_stdout(stdout):
        exit_code = main(argv)
    assert exit_code == 0
    return json.loads(stdout.getvalue())


class ReviewerIdentityResolutionTests(unittest.TestCase):
    def test_explicit_reviewer_wins(self) -> None:
        with patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "env-reviewer"}):
            self.assertEqual(resolve_reviewer_identity(" flag-reviewer "), "flag-reviewer")

    def test_env_reviewer_used_when_flag_absent(self) -> None:
        with patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "env-reviewer"}):
            self.assertEqual(resolve_reviewer_identity(None), "env-reviewer")
            self.assertEqual(resolve_reviewer_identity("  "), "env-reviewer")

    def test_system_user_is_default(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "RAPIDTRIAGE_REVIEWER"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(resolve_reviewer_identity(None), getpass.getuser())


class CliReviewerAttributionTests(unittest.TestCase):
    def test_cli_mark_carries_flag_reviewer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            payload = _cli_review(db_path, "CASE-REVIEWER", target_id, "--reviewer", "examiner-1")
        self.assertEqual(payload["reviewer"], "examiner-1")

    def test_cli_mark_carries_env_reviewer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            with patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "examiner-env"}):
                payload = _cli_review(db_path, "CASE-REVIEWER", target_id)
        self.assertEqual(payload["reviewer"], "examiner-env")

    def test_cli_mark_defaults_to_system_user(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "RAPIDTRIAGE_REVIEWER"}
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            with patch.dict(os.environ, env, clear=True):
                payload = _cli_review(db_path, "CASE-REVIEWER", target_id)
        self.assertEqual(payload["reviewer"], getpass.getuser())


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class ApiReviewerAttributionTests(unittest.TestCase):
    def _client(self, tmp_dir: str):
        return TestClient(
            create_app(RunJobStore(), auth_token=TEST_API_TOKEN, case_db_roots=[Path(tmp_dir)]),
            headers={"X-RapidTriage-Token": TEST_API_TOKEN},
        )

    def _post_review(self, client, db_path: Path, target_id: str, **extra) -> dict[str, object]:
        response = client.post(
            "/api/case-db/review",
            json={
                "database": str(db_path),
                "case_id": "CASE-REVIEWER",
                "target_type": "artifact",
                "target_id": target_id,
                "status": "relevant",
                **extra,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    def test_api_mark_carries_explicit_reviewer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            payload = self._post_review(self._client(tmp_dir), db_path, target_id, reviewer="api-reviewer")
        self.assertEqual(payload["reviewer"], "api-reviewer")

    def test_api_mark_uses_env_reviewer_when_field_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            with patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "server-examiner"}):
                payload = self._post_review(self._client(tmp_dir), db_path, target_id)
        self.assertEqual(payload["reviewer"], "server-examiner")

    def test_api_explicit_reviewer_beats_env_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            with patch.dict(os.environ, {"RAPIDTRIAGE_REVIEWER": "server-examiner"}):
                payload = self._post_review(
                    self._client(tmp_dir), db_path, target_id, reviewer="explicit-reviewer"
                )
        self.assertEqual(payload["reviewer"], "explicit-reviewer")

    def test_api_mark_without_reviewer_keeps_existing_behavior(self) -> None:
        env = {key: value for key, value in os.environ.items() if key != "RAPIDTRIAGE_REVIEWER"}
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path, target_id = _prepare_case_db(tmp_dir)
            with patch.dict(os.environ, env, clear=True):
                client = self._client(tmp_dir)
                created = self._post_review(client, db_path, target_id)
                updated = self._post_review(client, db_path, target_id, reviewer="second-pass")
                kept = self._post_review(client, db_path, target_id)
        self.assertEqual(created["reviewer"], "")
        self.assertEqual(updated["reviewer"], "second-pass")
        self.assertEqual(kept["reviewer"], "second-pass")


if __name__ == "__main__":
    unittest.main()
