from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.benchmark_fts import run_sqlite_fts_benchmark
from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.large_case_readiness import (
    LARGE_CASE_READINESS_ITEM_NUMBERS,
    build_large_case_readiness_report,
)


class RapidTriageLargeCaseReadinessTests(unittest.TestCase):
    def test_large_case_readiness_combines_benchmark_and_case_db_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            benchmark = run_sqlite_fts_benchmark(
                output_dir=root / "bench",
                record_count=100_000,
                keyword="needle",
                query_iterations=1,
                hit_every=10,
            )
            case_db = CaseDatabase(root / "case.db")
            case_db.initialize()
            case_db.create_case(case_id="CASE-LARGE", examiner="Analyst A")
            with case_db.connect() as connection:
                for index in range(2):
                    document_id = connection.execute(
                        """
                        INSERT INTO indexed_document (
                            citation_id, case_id, source_type, field_name, title, body, indexed_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"IDX-LARGE-{index}",
                            "CASE-LARGE",
                            "document",
                            "txt",
                            f"Needle document {index}",
                            f"needle pagination proof body {index}",
                            "2026-05-16T00:00:00+00:00",
                        ),
                    ).lastrowid
                    connection.execute(
                        "INSERT INTO indexed_document_fts(rowid, title, body) VALUES (?, ?, ?)",
                        (
                            document_id,
                            f"Needle document {index}",
                            f"needle pagination proof body {index}",
                        ),
                    )

            payload = build_large_case_readiness_report(
                case_db_path=root / "case.db",
                benchmark_paths=[Path(benchmark["outputs"]["json"])],
                keyword="needle",
                max_query_p95_ms=10_000,
                output=root / "readiness.json",
            )

            self.assertTrue((root / "readiness.json").is_file())
            self.assertEqual(payload["profile_version"], "large-case-readiness-v1")
            self.assertEqual(payload["item_numbers"], LARGE_CASE_READINESS_ITEM_NUMBERS)
            self.assertEqual(payload["summary"]["benchmark_count"], 1)
            self.assertEqual(payload["summary"]["largest_benchmark_record_count"], 100_000)
            self.assertTrue(payload["case_db_profile"]["attached"])
            self.assertIn("artifact_fts", payload["case_db_profile"]["fts_tables"])
            self.assertTrue(payload["summary"]["case_db_search_diagnostics_ready"])
            self.assertTrue(payload["summary"]["case_db_search_index_healthy"])
            self.assertEqual(payload["summary"]["case_db_search_index_missing_rows"], 0)
            self.assertTrue(payload["summary"]["case_db_cursor_diagnostics_ready"])
            self.assertGreaterEqual(payload["summary"]["case_db_cursor_pagination_proven_tables"], 1)
            self.assertRegex(payload["summary"]["case_db_cursor_diagnostics_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                payload["case_db_profile"]["search_diagnostics"]["profile_version"],
                "case-db-search-diagnostics-v1",
            )
            self.assertEqual(
                payload["case_db_profile"]["search_diagnostics"]["cursor_diagnostics"]["profile_version"],
                "case-db-cursor-diagnostics-v1",
            )
            self.assertEqual(
                payload["case_db_profile"]["search_index_health"]["profile_version"],
                "case-db-search-index-health-summary-v1",
            )
            self.assertEqual(payload["case_db_profile"]["search_index_health"]["status"], "healthy")
            self.assertEqual(payload["case_db_profile"]["search_diagnostics"]["keyword"], "needle")
            self.assertRegex(payload["case_db_profile"]["search_diagnostics"]["profile_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(payload["case_db_profile"]["search_index_health"]["profile_hash"], r"^[0-9a-f]{64}$")
            self.assertTrue(
                all(
                    item["query_plan_available"]
                    for item in payload["case_db_profile"]["search_diagnostics"]["fts_tables"]
                )
            )
            cursor_profiles = {
                item["table"]: item
                for item in payload["case_db_profile"]["search_diagnostics"]["cursor_diagnostics"]["tables"]
            }
            self.assertTrue(cursor_profiles["indexed_document_fts"]["pagination_proven"])
            self.assertRegex(cursor_profiles["indexed_document_fts"]["page_one_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(cursor_profiles["indexed_document_fts"]["page_two_hash"], r"^[0-9a-f]{64}$")
            self.assertNotEqual(
                cursor_profiles["indexed_document_fts"]["page_one_rowids"],
                cursor_profiles["indexed_document_fts"]["page_two_rowids"],
            )
            self.assertRegex(payload["manifest_hash"], r"^[0-9a-f]{64}$")
            self.assertTrue(
                any(check["id"] == "sqlite-fts-100k-or-higher" and check["passed"] for check in payload["checks"])
            )
            self.assertTrue(
                any(check["id"] == "sqlite-fts-1m-or-higher" and not check["passed"] for check in payload["checks"])
            )
            self.assertTrue(
                any(check["id"] == "case-db-cursor-diagnostics-ready" and check["passed"] for check in payload["checks"])
            )
            self.assertFalse(payload["commercial_grade_ready"])
            self.assertIn("attach-10m-record-sqlite-fts-benchmark-json", payload["commercial_grade_blockers"])

    def test_large_case_readiness_cli_emits_json_and_nonzero_when_evidence_is_incomplete(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        self.assertIn("large-case-readiness", commands)
        self.assertIn("--benchmark", commands["large-case-readiness"].format_help())

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            benchmark = run_sqlite_fts_benchmark(
                output_dir=root / "bench",
                record_count=250,
                keyword="needle",
                query_iterations=1,
                hit_every=5,
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "large-case-readiness",
                        "--benchmark",
                        str(benchmark["outputs"]["json"]),
                        "--max-query-p95-ms",
                        "10000",
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["command"], "large-case-readiness")
        self.assertEqual(payload["status"], "needs-large-case-evidence")
        self.assertFalse(payload["summary"]["case_db_attached"])
        self.assertTrue(
            any(check["id"] == "case-db-attached" and not check["passed"] for check in payload["checks"])
        )
        self.assertTrue(
            any(check["id"] == "case-db-search-diagnostics-ready" and not check["passed"] for check in payload["checks"])
        )

    def test_large_case_readiness_blocks_absence_claims_on_stale_case_search_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case_db = CaseDatabase(root / "case.db")
            case_db.initialize()
            case_db.create_case(case_id="CASE-STALE")
            with case_db.connect() as connection:
                file_id = connection.execute(
                    """
                    INSERT INTO file_record (citation_id, case_id, path, normalized_path, extension, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "FILE-STALE-1",
                        "CASE-STALE",
                        "/evidence/needle.txt",
                        "/evidence/needle.txt",
                        ".txt",
                        "2026-01-01T00:00:00+00:00",
                    ),
                ).lastrowid
                connection.execute("DELETE FROM file_record_fts WHERE rowid = ?", (file_id,))

            payload = build_large_case_readiness_report(case_db_path=root / "case.db", keyword="needle")

        self.assertFalse(payload["summary"]["case_db_search_index_healthy"])
        self.assertEqual(payload["summary"]["case_db_search_index_missing_rows"], 1)
        self.assertEqual(payload["case_db_profile"]["search_index_health"]["status"], "needs-rebuild")
        self.assertEqual(
            payload["case_db_profile"]["search_index_health"]["summary"]["unhealthy_case_count"],
            1,
        )
        self.assertTrue(
            any(check["id"] == "case-db-search-index-healthy" and not check["passed"] for check in payload["checks"])
        )
        self.assertIn("do not make no-hit or absence claims", " ".join(payload["case_db_profile"]["search_index_health"]["blockers"]))


if __name__ == "__main__":
    unittest.main()
