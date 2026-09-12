from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.cross_case import (
    CROSS_CASE_DEFAULT_REPORT_NAME,
    CROSS_CASE_REPORT_VERSION,
    CrossCaseError,
    correlate_case_databases,
)

SHARED_SHA256 = "ab" * 32
SHARED_PATH = "/evidence/shared/report.pdf"


def _build_db(db_path: Path, *, case_id: str, shared: bool) -> None:
    database = open_case_database(db_path)
    database.create_case(case_id=case_id, name=f"Case {case_id}")
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO file_record (
                citation_id, case_id, path, normalized_path, extension,
                size_bytes, hash_md5, hash_sha1, hash_sha256
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"{case_id}-FILE-1",
                case_id,
                SHARED_PATH if shared else f"/evidence/{case_id}/only.bin",
                (SHARED_PATH if shared else f"/evidence/{case_id}/only.bin").lower(),
                ".pdf" if shared else ".bin",
                512,
                ("aa" * 16) if shared else (case_id.lower() * 8)[:32],
                ("bb" * 20) if shared else (case_id.lower() * 8)[:40],
                SHARED_SHA256 if shared else case_id.lower().ljust(64, "0")[:64],
            ),
        )
        connection.execute(
            """
            INSERT INTO file_record (
                citation_id, case_id, path, normalized_path, extension, hash_sha256
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"{case_id}-FILE-2",
                case_id,
                f"/evidence/{case_id}/unique.txt",
                f"/evidence/{case_id}/unique.txt",
                ".txt",
                case_id.lower().ljust(64, "f")[:64],
            ),
        )
        connection.execute(
            """
            INSERT INTO artifact (
                citation_id, case_id, artifact_type, parser_name, title,
                summary, data_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"{case_id}-ART-1",
                case_id,
                "browser-history" if shared else f"{case_id.lower()}-artifact",
                "fixture-parser",
                "Visited example.test" if shared else f"{case_id} unique artifact",
                "fixture artifact",
                json.dumps({"url": "https://example.test"}, sort_keys=True),
                "2026-01-01T00:00:00+00:00",
            ),
        )


class RapidTriageCrossCaseTests(unittest.TestCase):
    def test_parser_exposes_cross_case_correlate(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("cross-case-correlate", commands)
        help_text = commands["cross-case-correlate"].format_help()
        self.assertIn("--case-id", help_text)
        self.assertIn("--output", help_text)

    def test_shared_entities_correlate_across_databases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            db_b = Path(tmp_dir) / "case-b.db"
            _build_db(db_a, case_id="CASE-A", shared=True)
            _build_db(db_b, case_id="CASE-B", shared=True)

            report = correlate_case_databases([db_a, db_b])

            self.assertEqual(report["profile_version"], CROSS_CASE_REPORT_VERSION)
            self.assertEqual(report["summary"]["scope_count"], 2)
            self.assertGreaterEqual(report["summary"]["shared_hash_count"], 1)
            self.assertGreaterEqual(report["summary"]["shared_path_count"], 1)
            self.assertEqual(report["summary"]["shared_artifact_identifier_count"], 1)
            self.assertEqual(report["summary"]["correlated_scope_pair_count"], 1)
            self.assertFalse(report["summary"]["truncated"])
            self.assertEqual(len(report["report_hash"]), 64)

            sha_hits = [
                entry
                for entry in report["shared_hashes"]
                if entry["algorithm"] == "sha256" and entry["value"] == SHARED_SHA256
            ]
            self.assertEqual(len(sha_hits), 1)
            self.assertEqual(sha_hits[0]["scope_count"], 2)
            self.assertEqual(
                {occ["case_id"] for occ in sha_hits[0]["occurrences"]},
                {"CASE-A", "CASE-B"},
            )

            path_hit = report["shared_paths"][0]
            self.assertEqual(path_hit["normalized_path"], SHARED_PATH.lower())
            self.assertEqual(path_hit["scope_count"], 2)

            artifact_hit = report["shared_artifact_identifiers"][0]
            self.assertEqual(artifact_hit["artifact_type"], "browser-history")
            self.assertEqual(artifact_hit["title"], "Visited example.test")
            self.assertEqual(artifact_hit["scope_count"], 2)

            pair = report["correlated_scope_pairs"][0]
            self.assertEqual(pair["left_scope"], "case-a.db:CASE-A")
            self.assertEqual(pair["right_scope"], "case-b.db:CASE-B")
            self.assertGreaterEqual(pair["shared_entity_count"], 3)

    def test_disjoint_databases_produce_empty_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            db_b = Path(tmp_dir) / "case-b.db"
            _build_db(db_a, case_id="CASE-A", shared=False)
            _build_db(db_b, case_id="CASE-B", shared=False)

            report = correlate_case_databases([db_a, db_b])

            self.assertEqual(report["shared_hashes"], [])
            self.assertEqual(report["shared_paths"], [])
            self.assertEqual(report["shared_artifact_identifiers"], [])
            self.assertEqual(report["correlated_scope_pairs"], [])
            self.assertEqual(report["summary"]["scope_count"], 2)
            self.assertEqual(report["summary"]["shared_hash_count"], 0)

    def test_case_id_filter_limits_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            db_b = Path(tmp_dir) / "case-b.db"
            _build_db(db_a, case_id="CASE-A", shared=True)
            _build_db(db_b, case_id="CASE-B", shared=True)
            open_case_database(db_a).create_case(case_id="CASE-OTHER")

            report = correlate_case_databases([db_a, db_b], case_ids=["CASE-A", "CASE-B"])

            self.assertEqual(report["summary"]["scope_count"], 2)
            self.assertEqual(report["case_id_filter"], ["CASE-A", "CASE-B"])

    def test_correlation_requires_two_databases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            _build_db(db_a, case_id="CASE-A", shared=True)

            with self.assertRaises(CrossCaseError):
                correlate_case_databases([db_a])

    def test_correlation_rejects_missing_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            _build_db(db_a, case_id="CASE-A", shared=True)

            with self.assertRaises(CrossCaseError):
                correlate_case_databases([db_a, Path(tmp_dir) / "missing.db"])

    def test_cli_writes_default_report_next_to_first_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            db_b = Path(tmp_dir) / "case-b.db"
            _build_db(db_a, case_id="CASE-A", shared=True)
            _build_db(db_b, case_id="CASE-B", shared=True)

            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = main(["cross-case-correlate", str(db_a), str(db_b)])

            self.assertEqual(exit_code, 0)
            self.assertIn("cross-case correlation", output.getvalue())
            report_path = db_a.parent / CROSS_CASE_DEFAULT_REPORT_NAME
            self.assertTrue(report_path.is_file())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["correlated_scope_pair_count"], 1)
            self.assertEqual(
                set(report),
                {
                    "command",
                    "profile_version",
                    "generated_at",
                    "databases",
                    "case_id_filter",
                    "scopes",
                    "summary",
                    "shared_hashes",
                    "shared_paths",
                    "shared_artifact_identifiers",
                    "correlated_scope_pairs",
                    "commercial_claim_allowed",
                    "report_hash",
                },
            )

    def test_cli_json_output_and_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_a = Path(tmp_dir) / "case-a.db"
            db_b = Path(tmp_dir) / "case-b.db"
            report_path = Path(tmp_dir) / "reports" / "correlation.json"
            _build_db(db_a, case_id="CASE-A", shared=True)
            _build_db(db_b, case_id="CASE-B", shared=True)

            with contextlib.redirect_stdout(io.StringIO()) as output:
                exit_code = main(
                    [
                        "cross-case-correlate",
                        str(db_a),
                        str(db_b),
                        "--output",
                        str(report_path),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["command"], "cross-case-correlate")
            self.assertEqual(payload["output"], str(report_path.resolve()))
            self.assertTrue(report_path.is_file())


if __name__ == "__main__":
    unittest.main()
