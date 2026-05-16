from __future__ import annotations

import sqlite3
import tempfile
import unittest
import contextlib
import io
import json
from pathlib import Path
from unittest import mock

from rapidtriage.cli import build_parser, main
from rapidtriage.core import case_db as case_db_module
from rapidtriage.core.case_db import (
    SCHEMA_VERSION,
    CaseDatabase,
    CaseDatabaseError,
    acquisition_hash_core_accuracy_gates,
    acquisition_metadata_core_accuracy_gates,
    build_acquisition_hash_trusted_diff,
    build_acquisition_metadata_trusted_diff,
    build_case_db_fts_trusted_diff,
    build_clock_skew_trusted_diff,
    build_contamination_warning_trusted_diff,
    build_citation_manager_trusted_diff,
    build_custody_workflow_trusted_diff,
    build_evidence_history_trusted_diff,
    build_immutable_audit_trusted_diff,
    build_legal_limitation_trusted_diff,
    build_parser_confidence_trusted_diff,
    build_report_provenance_trusted_diff,
    build_report_reproducibility_trusted_diff,
    build_timezone_validation_trusted_diff,
    build_validation_warning_trusted_diff,
    build_reviewer_workflow_trusted_diff,
    clock_skew_core_accuracy_gates,
    citation_manager_core_accuracy_gates,
    contamination_warning_core_accuracy_gates,
    custody_workflow_core_accuracy_gates,
    evidence_selection_core_accuracy_gates,
    immutable_audit_core_accuracy_gates,
    legal_limitation_core_accuracy_gates,
    list_tables,
    open_case_database,
    parser_confidence_core_accuracy_gates,
    report_item_provenance_core_accuracy_gates,
    report_reproducibility_core_accuracy_gates,
    review_workflow_assessment,
    table_columns,
    timezone_validation_core_accuracy_gates,
    validation_warning_ux_core_accuracy_gates,
)
from rapidtriage.core.sample_case import run_sample_workflow
from tests.test_rapidtriage_macos_artifacts import build_macos_fixture
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


REQUIRED_TABLES = {
    "schema_info",
    "case_record",
    "citation_sequence",
    "evidence_source",
    "file_record",
    "file_record_fts",
    "hash_record",
    "acquisition_metadata",
    "artifact",
    "artifact_fts",
    "event",
    "event_fts",
    "indexed_document",
    "indexed_document_fts",
    "review_mark",
    "review_mark_history",
    "saved_search",
    "audit_event",
    "report_item",
    "job",
    "job_step",
}


class RapidTriageCaseDatabaseTests(unittest.TestCase):
    def test_parser_exposes_case_db_subcommand(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("case-db", commands)
        self.assertIn("--create-case", commands["case-db"].format_help())
        self.assertIn("--import-run", commands["case-db"].format_help())
        self.assertIn("--import-vsc-compare", commands["case-db"].format_help())
        self.assertIn("--import-worker-jsonl", commands["case-db"].format_help())
        self.assertIn("case-search", commands)
        self.assertIn("--case-id", commands["case-search"].format_help())
        self.assertIn("--source", commands["case-search"].format_help())
        self.assertIn("--metadata", commands["case-search"].format_help())
        self.assertIn("--review-status", commands["case-search"].format_help())
        self.assertIn("--verification-status", commands["case-search"].format_help())
        self.assertIn("--save-as", commands["case-search"].format_help())
        self.assertIn("--keyword-pack", commands["case-search"].format_help())
        self.assertIn("--cursor", commands["case-search"].format_help())
        self.assertIn("case-review", commands)
        self.assertIn("--include-in-report", commands["case-review"].format_help())
        self.assertIn("--exclude-from-report", commands["case-review"].format_help())
        self.assertIn("--source-read-json", commands["case-review"].format_help())
        self.assertIn("case-db-report", commands)
        self.assertIn("--include-all", commands["case-db-report"].format_help())
        self.assertIn("evidence", commands)
        self.assertIn("rapidtriage case-db", parser.format_help())
        self.assertIn("rapidtriage case-search", parser.format_help())

    def test_initialize_creates_schema_v1_tables_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            database = CaseDatabase(db_path)

            first = database.initialize()
            second = database.initialize()

            self.assertEqual(first["schema_version"], SCHEMA_VERSION)
            self.assertEqual(second["schema_version"], SCHEMA_VERSION)
            self.assertTrue(REQUIRED_TABLES.issubset(set(second["tables"])))
            self.assertIn("#74", second["large_sqlite_fts_optimization"]["commercial_gap_ids"])
            self.assertEqual(second["large_sqlite_fts_optimization"]["functional_priority_profile"]["item_number"], 32)
            self.assertEqual(
                second["large_sqlite_fts_optimization"]["functional_priority_profile"]["batch_id"],
                "commercial-uplift-031-035",
            )
            self.assertTrue(
                second["large_sqlite_fts_optimization"]["functional_priority_profile"]["controls"]["wal_when_supported"]
            )
            self.assertEqual(second["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["gap_id"], "#74")
            self.assertIn("file_record_fts", second["large_sqlite_fts_optimization"]["fts_tables"])
            self.assertIn("artifact_fts", second["large_sqlite_fts_optimization"]["fts_tables"])
            self.assertIn("event_fts", second["large_sqlite_fts_optimization"]["fts_tables"])
            self.assertEqual(
                second["large_sqlite_fts_optimization"]["query_plan_profile"]["profile_version"],
                "case-db-query-plan-profile-v1",
            )
            self.assertRegex(
                second["large_sqlite_fts_optimization"]["query_plan_profile"]["plan_hash"],
                r"^[0-9a-f]{64}$",
            )
            self.assertIn(
                "case DB query plan profile emitted",
                second["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "trusted-case-db-sqlite-fts-query-plan-diff-missing",
                second["large_sqlite_fts_optimization"]["blockers"],
            )
            fts_diff = build_case_db_fts_trusted_diff(
                second["large_sqlite_fts_optimization"],
                second["large_sqlite_fts_optimization"],
            )
            self.assertEqual(fts_diff["status"], "pass")

            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.row_factory = sqlite3.Row
                self.assertTrue(REQUIRED_TABLES.issubset(set(list_tables(connection))))
                self.assertIn("hash_scope", table_columns(connection, "hash_record"))
                self.assertIn("verification_status", table_columns(connection, "review_mark"))
                self.assertIn("version", table_columns(connection, "review_mark_history"))
                self.assertIn("filters_json", table_columns(connection, "saved_search"))
                self.assertIn("citation_id", table_columns(connection, "audit_event"))
                self.assertIn("write_blocker", table_columns(connection, "acquisition_metadata"))
                indexes = {
                    str(row["name"])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
                    ).fetchall()
                }
                self.assertIn("idx_review_mark_case_target", indexes)

    def test_create_list_and_get_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = open_case_database(Path(tmp_dir) / "case.db")

            created = database.create_case(
                case_id="CASE 2026/001",
                name="RapidTriage Sample",
                description="Synthetic evidence smoke case.",
                examiner="Analyst A",
                organization="Lab",
                case_root=Path(tmp_dir) / "evidence",
            )
            fetched = database.get_case(created.case_id)
            listed = database.list_cases()

            self.assertEqual(created.case_id, "CASE-2026-001")
            self.assertEqual(created.name, "RapidTriage Sample")
            self.assertEqual(created.citation_prefix, "CASE-2026-001")
            self.assertEqual(fetched.to_dict(), created.to_dict())
            self.assertEqual([item.case_id for item in listed], [created.case_id])

    def test_acquisition_metadata_records_required_submission_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = open_case_database(Path(tmp_dir) / "case.db")
            database.create_case(case_id="CASE-ACQ", examiner="Analyst A", organization="Lab")

            record = database.record_acquisition_metadata(
                case_id="CASE-ACQ",
                operator="Analyst A",
                acquisition_started_at="2026-04-28T09:00:00+09:00",
                acquisition_completed_at="2026-04-28T10:00:00+09:00",
                source_identifier="Disk SN ABC123",
                write_blocker="Tableau TX1 SN WB-01 verified read-only",
                acquisition_tool="RapidTriage",
                acquisition_tool_version="dev",
                whole_source_sha256="b" * 64,
                notes="Recorded before processing.",
            )
            records = database.list_acquisition_metadata("CASE-ACQ")
            export = database.export_reviewed_items(case_id="CASE-ACQ")

            self.assertTrue(record["citation_id"].startswith("CASE-ACQ-ACQ-"))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["write_blocker"], "Tableau TX1 SN WB-01 verified read-only")
            self.assertEqual(export["acquisition_metadata"]["status"], "metadata-recorded")
            self.assertEqual(export["summary"]["acquisition_metadata_missing_count"], 0)
            self.assertEqual(
                export["acquisition_metadata"]["acquisition_metadata_handoff_manifest"]["profile_version"],
                "acquisition-metadata-handoff-manifest-v1",
            )
            self.assertEqual(len(export["acquisition_metadata"]["acquisition_metadata_handoff_manifest_hash"]), 64)
            self.assertEqual(
                export["acquisition_metadata"]["acquisition_field_completion_matrix"]["profile_version"],
                "acquisition-field-completion-matrix-v1",
            )
            self.assertEqual(len(export["acquisition_metadata"]["acquisition_field_completion_matrix_hash"]), 64)
            self.assertEqual(
                export["acquisition_metadata"]["acquisition_field_completion_matrix_hash"],
                export["acquisition_metadata"]["acquisition_metadata_handoff_manifest"]["field_completion_matrix_hash"],
            )
            self.assertEqual(
                export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["profile_version"],
                "acquisition-metadata-input-manifest-v1",
            )
            self.assertEqual(export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["item_number"], 41)
            self.assertEqual(export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["gap_id"], "#41")
            self.assertEqual(len(export["acquisition_metadata"]["acquisition_metadata_input_manifest_hash"]), 64)
            self.assertTrue(export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["ready_for_submission"])
            self.assertEqual(
                export["acquisition_metadata"]["functional_priority_profile"]["implemented_controls"]["acquisition_metadata_input_manifest_hash"],
                export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["manifest_hash"],
            )
            self.assertEqual(len(export["acquisition_metadata"]["records"][0]["acquisition_metadata_row_hash"]), 64)

    def test_create_case_rejects_duplicate_case_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = open_case_database(Path(tmp_dir) / "case.db")
            database.create_case(case_id="CASE-1")

            with self.assertRaisesRegex(CaseDatabaseError, "case already exists"):
                database.create_case(case_id="CASE-1")

    def test_citation_ids_are_stable_incrementing_and_per_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = open_case_database(Path(tmp_dir) / "case.db")
            database.create_case(case_id="CASE-001")

            first_file = database.next_citation_id("CASE-001", "file")
            second_file = database.next_citation_id("CASE-001", "file")
            first_artifact = database.next_citation_id("CASE-001", "artifact")

            reopened = open_case_database(Path(tmp_dir) / "case.db")
            third_file = reopened.next_citation_id("CASE-001", "file")

            self.assertEqual(first_file, "CASE-001-FILE-000001")
            self.assertEqual(second_file, "CASE-001-FILE-000002")
            self.assertEqual(first_artifact, "CASE-001-ART-000001")
            self.assertEqual(third_file, "CASE-001-FILE-000003")

    def test_citation_ids_reject_unknown_kind_and_missing_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            database = open_case_database(Path(tmp_dir) / "case.db")
            database.create_case(case_id="CASE-001")

            with self.assertRaisesRegex(CaseDatabaseError, "unsupported citation kind"):
                database.next_citation_id("CASE-001", "unknown")
            with self.assertRaisesRegex(CaseDatabaseError, "case not found"):
                database.next_citation_id("CASE-404", "file")

    def test_add_audit_event_records_citation_and_updates_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            database = open_case_database(db_path)
            case = database.create_case(case_id="CASE-001")

            citation = database.add_audit_event(
                case_id=case.case_id,
                action="case.created",
                target_type="case",
                target_id=case.case_id,
                params_json='{"source":"unit-test"}',
            )

            self.assertEqual(citation, "CASE-001-AUD-000001")
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute("SELECT * FROM audit_event WHERE citation_id = ?", (citation,)).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row["action"], "case.created")
                self.assertEqual(row["params_json"], '{"source":"unit-test"}')

            updated = database.get_case(case.case_id)
            self.assertGreaterEqual(updated.updated_at, case.updated_at)

    def test_cli_case_db_initializes_creates_and_lists_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-db",
                        str(db_path),
                        "--create-case",
                        "CASE-001",
                        "--name",
                        "Case One",
                        "--list",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "case-db")
            self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
            self.assertEqual(payload["created_case"]["case_id"], "CASE-001")
            self.assertEqual(payload["cases"][0]["name"], "Case One")
            self.assertTrue(REQUIRED_TABLES.issubset(set(payload["tables"])))

    def test_import_run_output_populates_case_db_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            db_path = root / "case.db"
            database = open_case_database(db_path)

            import_payload = database.import_run_output(
                Path(sample_payload["run"]["output_dir"]),
                case_id="CASE-IMPORT-001",
                case_name="Imported sample",
            )

            self.assertEqual(import_payload["case_id"], "CASE-IMPORT-001")
            self.assertEqual(import_payload["summary"]["evidence_source_count"], 1)
            self.assertGreaterEqual(import_payload["summary"]["file_record_count"], 1)
            self.assertGreaterEqual(import_payload["summary"]["indexed_document_count"], 1)
            self.assertGreaterEqual(import_payload["summary"]["artifact_count"], 1)
            self.assertGreaterEqual(import_payload["summary"]["event_count"], 1)

            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                counts = {
                    table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("case_record", "evidence_source", "file_record", "indexed_document", "artifact", "event", "audit_event")
                }
                fts_count = connection.execute("SELECT COUNT(*) FROM indexed_document_fts WHERE body MATCH 'password'").fetchone()[0]

            self.assertEqual(counts["case_record"], 1)
            self.assertEqual(counts["evidence_source"], 1)
            self.assertGreaterEqual(counts["file_record"], 1)
            self.assertGreaterEqual(counts["indexed_document"], 1)
            self.assertGreaterEqual(counts["artifact"], 1)
            self.assertGreaterEqual(counts["event"], 1)
            self.assertGreaterEqual(counts["audit_event"], 1)
            self.assertGreaterEqual(fts_count, 1)

    def test_import_run_output_audits_document_extraction_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            docs_output = root / "rapidtriage-docs.json"
            missing_document = root / "missing.pdf"
            docs_output.write_text(
                json.dumps(
                    {
                        "candidates": [{"path": str(missing_document), "kind": "pdf"}],
                        "results": [{"path": str(missing_document)}],
                    }
                ),
                encoding="utf-8",
            )
            summary = {
                "root": str(root),
                "outputs": {
                    "summary": str(root / "summary.json"),
                    "docs": str(docs_output),
                },
            }
            db_path = root / "case.db"
            database = open_case_database(db_path)

            import_payload = database.import_run_output(summary, case_id="CASE-DOC-ERROR")

            self.assertEqual(import_payload["summary"]["indexed_document_count"], 1)
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    "SELECT action, target_type, result, error, params_json FROM audit_event WHERE action = ?",
                    ("document-text-extraction",),
                ).fetchone()

            self.assertIsNotNone(row)
            assert row is not None
            self.assertEqual(row["target_type"], "indexed_document")
            self.assertEqual(row["result"], "failed")
            self.assertIn("FileNotFoundError", row["error"])
            self.assertEqual(json.loads(row["params_json"])["path"], str(missing_document))

            search_payload = database.search_case(
                case_id="CASE-DOC-ERROR",
                keywords=["definitely-not-present"],
                sources=["documents"],
                limit=10,
            )

            self.assertEqual(search_payload["summary"]["match_count"], 0)
            self.assertEqual(search_payload["summary"]["document_error_count"], 1)
            self.assertEqual(search_payload["documents"]["errors"][0]["path"], str(missing_document))
            self.assertEqual(
                search_payload["documents"]["errors"][0]["effect"],
                "case-search-documents-partial-coverage",
            )

    def test_case_search_caps_scan_candidates_before_materializing_large_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            database = open_case_database(db_path)
            database.create_case(case_id="CASE-SCAN-CAP")
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.executemany(
                    """
                    INSERT INTO file_record (citation_id, case_id, path, normalized_path, extension)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            f"CASE-SCAN-CAP-FILE-{index:06d}",
                            "CASE-SCAN-CAP",
                            f"/evidence/ordinary-{index}.txt",
                            f"/evidence/ordinary-{index}.txt",
                            ".txt",
                        )
                        for index in range(10_050)
                    ],
                )
                connection.executemany(
                    """
                    INSERT INTO artifact (citation_id, case_id, artifact_type, parser_name, title, summary, data_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            f"CASE-SCAN-CAP-ARTIFACT-{index:06d}",
                            "CASE-SCAN-CAP",
                            "browser-history",
                            "test-parser",
                            f"ordinary artifact {index}",
                            "ordinary summary",
                            json.dumps({"url": f"https://example.test/{index}"}),
                            "2026-05-11T00:00:00+00:00",
                        )
                        for index in range(10_050)
                    ],
                )
                connection.executemany(
                    """
                    INSERT INTO event (citation_id, case_id, event_type, timestamp, target, description, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            f"CASE-SCAN-CAP-EVENT-{index:06d}",
                            "CASE-SCAN-CAP",
                            "file-observed",
                            f"2026-05-11T00:00:{index % 60:02d}+00:00",
                            f"/evidence/ordinary-{index}.txt",
                            "ordinary event",
                            "test-timeline",
                        )
                        for index in range(10_050)
                    ],
                )
                connection.execute(
                    """
                    INSERT INTO file_record (citation_id, case_id, path, normalized_path, extension)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "CASE-SCAN-CAP-FILE-999999",
                        "CASE-SCAN-CAP",
                        "/evidence/needle-after-cap.txt",
                        "/evidence/needle-after-cap.txt",
                        ".txt",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO artifact (citation_id, case_id, artifact_type, parser_name, title, summary, data_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CASE-SCAN-CAP-ARTIFACT-999999",
                        "CASE-SCAN-CAP",
                        "browser-history",
                        "test-parser",
                        "needle artifact after cap",
                        "needle summary after cap",
                        json.dumps({"url": "https://needle.example.test"}),
                        "2026-05-11T00:00:00+00:00",
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO event (citation_id, case_id, event_type, timestamp, target, description, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CASE-SCAN-CAP-EVENT-999999",
                        "CASE-SCAN-CAP",
                        "file-observed",
                        "9999-12-31T23:59:59+00:00",
                        "/evidence/needle-after-cap.txt",
                        "needle event after cap",
                        "test-timeline",
                    ),
                )
                connection.commit()

            for source in ("files", "artifacts", "timeline"):
                with self.subTest(source=source):
                    payload = database.search_case(case_id="CASE-SCAN-CAP", keywords=["needle"], limit=10, sources=[source])

                    self.assertEqual(payload["options"]["scan_candidate_limit"], 10_000)
                    self.assertEqual(payload["large_case_search_plan"]["profile_version"], "case-search-large-case-plan-v1")
                    source_plan = {
                        item["source"]: item
                        for item in payload["large_case_search_plan"]["sources"]
                    }[source]
                    self.assertEqual(source_plan["requested"], True)
                    if source == "files":
                        self.assertEqual(payload["summary"]["match_count"], 1)
                        self.assertEqual(source_plan["backend"], "sqlite-fts5")
                        self.assertEqual(source_plan["fts_table"], "file_record_fts")
                        self.assertEqual(source_plan["scan_candidate_limit"], None)
                        self.assertEqual(source_plan["partial_coverage_warning"], False)
                        self.assertEqual(payload["matches"][0]["path"], "/evidence/needle-after-cap.txt")
                        self.assertEqual(payload["matches"][0]["metadata"]["search_backend"], "sqlite-fts5")
                    elif source == "timeline":
                        self.assertEqual(payload["summary"]["match_count"], 1)
                        self.assertEqual(source_plan["backend"], "sqlite-fts5")
                        self.assertEqual(source_plan["fts_table"], "event_fts")
                        self.assertEqual(source_plan["scan_candidate_limit"], None)
                        self.assertEqual(source_plan["partial_coverage_warning"], False)
                        self.assertEqual(payload["matches"][0]["path"], "/evidence/needle-after-cap.txt")
                        self.assertEqual(payload["matches"][0]["metadata"]["search_backend"], "sqlite-fts5")
                    else:
                        self.assertEqual(payload["summary"]["match_count"], 0)
                        self.assertEqual(source_plan["backend"], "bounded-scan")
                        self.assertEqual(source_plan["scan_candidate_limit"], 10_000)
                        self.assertEqual(source_plan["partial_coverage_warning"], True)
                    self.assertIn("#74", payload["large_case_search_plan"]["commercial_gap_ids"])

    def test_case_search_source_filter_skips_unrequested_large_backends(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            database = open_case_database(db_path)
            database.create_case(case_id="CASE-SOURCE-SCOPE")

            with mock.patch.object(case_db_module, "search_indexed_documents", side_effect=AssertionError("documents scanned")), mock.patch.object(
                case_db_module,
                "search_artifacts",
                side_effect=AssertionError("artifacts scanned"),
            ), mock.patch.object(case_db_module, "search_events", side_effect=AssertionError("events scanned")):
                payload = database.search_case(case_id="CASE-SOURCE-SCOPE", keywords=["needle"], limit=10, sources=["files"])

            self.assertEqual(payload["summary"]["match_count"], 0)

    def test_cli_case_review_appends_source_read_citation_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            db_path = root / "case.db"
            database = open_case_database(db_path)
            database.create_case(case_id="CASE-SOURCE-NOTE")
            source_read_path = root / "source-read.json"
            source_read_path.write_text(
                json.dumps(
                    {
                        "source_citation_package": {
                            "review_note_template": "Current-file hit: Users/alice/note.txt [text preview length 12]\nSnippet: password",
                            "citation_text": "Users/alice/note.txt [text preview length 12] sha256:abc123",
                            "package_hash": "f" * 64,
                        }
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-review",
                        str(db_path),
                        "--case-id",
                        "CASE-SOURCE-NOTE",
                        "--target-type",
                        "indexed_document",
                        "--target-id",
                        "1",
                        "--status",
                        "relevant",
                        "--verification-status",
                        "source_opened",
                        "--note",
                        "Analyst verified the opened source.",
                        "--source-read-json",
                        str(source_read_path),
                        "--include-in-report",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "relevant")
            self.assertEqual(payload["verification_status"], "source_opened")
            self.assertTrue(payload["include_in_report"])
            self.assertIn("Analyst verified the opened source.", payload["note"])
            self.assertIn("Current-file hit:", payload["note"])
            self.assertIn("Source citation:", payload["note"])
            self.assertIn("Source citation package hash:", payload["note"])

    def test_cli_case_db_import_run_outputs_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            db_path = root / "case.db"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-db",
                        str(db_path),
                        "--import-run",
                        str(sample_payload["run"]["output_dir"]),
                        "--case-id",
                        "CASE-CLI-IMPORT",
                        "--name",
                        "CLI Import",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["imported_run"]["case_id"], "CASE-CLI-IMPORT")
            self.assertGreaterEqual(payload["imported_run"]["summary"]["file_record_count"], 1)
            self.assertGreaterEqual(payload["imported_run"]["summary"]["indexed_document_count"], 1)

    def test_cli_case_db_imports_vsc_compare_as_searchable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            current = root / "current"
            snapshot = root / "snapshot"
            current.mkdir()
            snapshot.mkdir()
            (snapshot / "deleted-secret.txt").write_text("snapshot only", encoding="utf-8")
            (current / "added.txt").write_text("current only", encoding="utf-8")
            vsc_output = root / "vsc.json"
            db_path = root / "case.db"

            self.assertEqual(main(["vsc-compare", str(current), str(snapshot), "--output", str(vsc_output)]), 0)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "case-db",
                            str(db_path),
                            "--import-vsc-compare",
                            str(vsc_output),
                            "--case-id",
                            "CASE-VSC",
                            "--json",
                        ]
                    ),
                    0,
                )
            import_payload = json.loads(stdout.getvalue())
            self.assertEqual(import_payload["imported_vsc_compare"]["summary"]["artifact_count"], 2)

            database = open_case_database(db_path)
            payload = database.search_case(
                case_id="CASE-VSC",
                keywords=["deleted-secret"],
                sources=["artifacts"],
                metadata_filters=["status=deleted"],
            )

            self.assertEqual(payload["summary"]["match_count"], 1)
            match = payload["matches"][0]
            self.assertEqual(match["kind"], "vsc-deleted-file")
            self.assertEqual(match["metadata"]["status"], "deleted")
            self.assertEqual(match["metadata"]["relative_path"], "deleted-secret.txt")
            self.assertEqual(match["metadata"]["snapshot_label"], "snapshot")
            filtered_out = database.search_case(
                case_id="CASE-VSC",
                keywords=["deleted-secret"],
                sources=["artifacts"],
                metadata_filters=["status=added"],
            )
            self.assertEqual(filtered_out["summary"]["match_count"], 0)

    def test_cli_case_db_imports_worker_jsonl_as_searchable_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            db_path = root / "case.db"
            worker_jsonl = root / "worker-artifacts.jsonl"
            worker_record = {
                "schema": "ArtifactRecordV1",
                "artifact_id": "CASE-WORKER:SRC:eventlog:1",
                "artifact_family": "eventlog",
                "artifact_type": "eventlog-event",
                "parser": "rapid-worker",
                "parser_version": "0.1.0",
                "source": {
                    "case_id": "CASE-WORKER",
                    "source_id": "SRC",
                    "source_path": str(root / "Security.evtx"),
                    "offset": 4096,
                    "length": 128,
                    "hashes": {"sha256": "abc123"},
                },
                "confidence": 0.83,
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": ["provider-message-rendering-preview-only"],
                "legal_limitations": ["triage import requires source validation"],
                "fields": {
                    "record_id": 42,
                    "channel": "Security",
                    "computer": "LAB-PC",
                    "message_rendering": {
                        "preview": "PowerShell logon investigation keyword hit",
                    },
                },
            }
            worker_jsonl.write_text(json.dumps(worker_record, ensure_ascii=False) + "\n", encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "case-db",
                            str(db_path),
                            "--import-worker-jsonl",
                            str(worker_jsonl),
                            "--case-id",
                            "CASE-WORKER",
                            "--json",
                        ]
                    ),
                    0,
                )

            import_payload = json.loads(stdout.getvalue())
            self.assertEqual(import_payload["imported_worker_jsonl"]["summary"]["artifact_count"], 1)
            self.assertEqual(import_payload["imported_worker_jsonl"]["summary"]["indexed_document_count"], 1)
            database = open_case_database(db_path)
            payload = database.search_case(case_id="CASE-WORKER", keywords=["PowerShell"], sources=["artifacts"])

            self.assertEqual(payload["summary"]["match_count"], 1)
            match = payload["matches"][0]
            self.assertEqual(match["kind"], "eventlog-event")
            self.assertEqual(match["metadata"]["parser"], "rapid-worker")
            self.assertEqual(match["path"], str(root / "Security.evtx"))

    def test_search_case_finds_documents_files_artifacts_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            database = open_case_database(root / "case.db")
            database.import_run_output(Path(sample_payload["run"]["output_dir"]), case_id="CASE-SEARCH-001")

            payload = database.search_case(
                case_id="CASE-SEARCH-001",
                keywords=["password", "payload-installer", "download"],
                limit=50,
            )

            self.assertEqual(payload["command"], "case-search")
            self.assertGreaterEqual(payload["summary"]["match_count"], 3)
            sources = {match["source"] for match in payload["matches"]}
            self.assertIn("documents", sources)
            self.assertIn("files", sources)
            self.assertIn("artifacts", sources)
            self.assertIn("timeline", sources)
            self.assertTrue(all(str(match["citation_id"]).startswith("CASE-SEARCH-001-") for match in payload["matches"]))
            manifest = payload["case_search_result_window_manifest"]
            self.assertEqual(manifest["profile_version"], "case-search-result-window-manifest-v1")
            self.assertEqual(payload["summary"]["case_search_result_window_manifest_hash"], manifest["manifest_hash"])
            self.assertEqual(len(manifest["manifest_hash"]), 64)
            self.assertEqual(len(manifest["page_window_hash"]), 64)
            self.assertEqual(manifest["counts"]["returned_count"], payload["summary"]["returned_count"])
            self.assertGreaterEqual(manifest["counts"]["backend_counts"]["sqlite-fts5"], 1)
            self.assertGreaterEqual(len(manifest["match_rows"]), 1)
            self.assertEqual(manifest["match_rows"][0]["source_viewer_locator"]["viewer"], "case-review-source")

            first_page = database.search_case(
                case_id="CASE-SEARCH-001",
                keywords=["password", "payload-installer", "download"],
                limit=1,
            )
            self.assertEqual(first_page["summary"]["returned_count"], 1)
            self.assertTrue(first_page["summary"]["has_more"])
            self.assertTrue(first_page["summary"]["next_cursor"])
            self.assertEqual(first_page["summary"]["cursor_api"]["profile_version"], "case-search-cursor-v1")
            self.assertEqual(first_page["options"]["page_offset"], 0)
            first_manifest = first_page["case_search_result_window_manifest"]
            self.assertEqual(first_manifest["cursor"]["offset"], 0)
            self.assertEqual(first_manifest["cursor"]["page_size"], 1)
            self.assertEqual(first_manifest["match_rows"][0]["window_position"], 1)

            second_page = database.search_case(
                case_id="CASE-SEARCH-001",
                keywords=["password", "payload-installer", "download"],
                limit=1,
                cursor=first_page["summary"]["next_cursor"],
            )
            self.assertEqual(second_page["options"]["page_offset"], 1)
            self.assertEqual(second_page["summary"]["returned_count"], 1)
            second_manifest = second_page["case_search_result_window_manifest"]
            self.assertEqual(second_manifest["query_scope_hash"], first_manifest["query_scope_hash"])
            self.assertNotEqual(second_manifest["page_window_hash"], first_manifest["page_window_hash"])
            self.assertEqual(second_manifest["match_rows"][0]["window_position"], 2)
            self.assertNotEqual(first_page["matches"][0]["citation_id"], second_page["matches"][0]["citation_id"])
            with self.assertRaisesRegex(CaseDatabaseError, "cursor does not match"):
                database.search_case(
                    case_id="CASE-SEARCH-001",
                    keywords=["different"],
                    limit=1,
                    cursor=first_page["summary"]["next_cursor"],
                )

    def test_case_search_exposes_windows_artifact_paths_and_metadata_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_root = root / "windows-case"
            output_dir = root / "run-out"
            evidence_root.mkdir()
            build_windows_artifact_fixture(evidence_root)

            self.assertEqual(
                main(["run", str(evidence_root), "--mode", "hacking", "--output-dir", str(output_dir), "--read-only"]),
                0,
            )
            database = open_case_database(root / "case.db")
            database.import_run_output(output_dir, case_id="CASE-WINDOWS-ARTIFACTS")

            payload = database.search_case(
                case_id="CASE-WINDOWS-ARTIFACTS",
                keywords=["powershell", "10.0.0.5", "deleted.txt"],
                sources=["artifacts"],
                limit=50,
            )

            self.assertEqual(payload["command"], "case-search")
            self.assertGreaterEqual(payload["summary"]["match_count"], 3)
            self.assertTrue(all(match["source"] == "artifacts" for match in payload["matches"]))
            self.assertTrue(all(match.get("path") for match in payload["matches"]))

            eventlog_matches = [
                match
                for match in payload["matches"]
                if match["kind"] in {"eventlog-event", "eventlog-detection"}
            ]
            self.assertTrue(eventlog_matches)
            self.assertTrue(any(match["metadata"].get("event_id") == "4104" for match in eventlog_matches))
            self.assertTrue(any(match["metadata"].get("event_family") == "execution" for match in eventlog_matches))
            self.assertTrue(any(match["metadata"].get("channel_family") == "powershell" for match in eventlog_matches))
            self.assertTrue(any(match["metadata"].get("source_ip") == "10.0.0.5" for match in eventlog_matches))
            self.assertTrue(any("powershell -enc" in str(match["metadata"].get("command_line", "")).lower() for match in eventlog_matches))
            high_priority_events = [
                match
                for match in eventlog_matches
                if match["review_priority"]["level"] == "high"
            ]
            self.assertTrue(high_priority_events)
            self.assertTrue(any("high-value Windows artifact" in match["review_priority"]["reasons"] for match in high_priority_events))
            self.assertTrue(all(match["source_reference"].get("source_format") for match in eventlog_matches))
            self.assertTrue(any(match["source_reference"].get("source_hashes", {}).get("sha256") for match in eventlog_matches))

            filesystem_matches = [match for match in payload["matches"] if match["kind"] in {"mft-record", "usn-record"}]
            self.assertTrue(filesystem_matches)
            self.assertTrue(any("deleted.txt" in str(match["metadata"].get("file_path", "")) for match in filesystem_matches))

    def test_case_search_exposes_macos_artifact_metadata_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_root = root / "mac-case"
            output_dir = root / "run-out"
            build_macos_fixture(evidence_root)

            self.assertEqual(
                main(["run", str(evidence_root), "--mode", "hacking", "--output-dir", str(output_dir), "--read-only"]),
                0,
            )
            database = open_case_database(root / "case.db")
            database.import_run_output(output_dir, case_id="CASE-MACOS-ARTIFACTS")

            payload = database.search_case(
                case_id="CASE-MACOS-ARTIFACTS",
                keywords=["example.test", "com.example.persist", "osascript"],
                sources=["artifacts"],
                limit=50,
            )

            self.assertEqual(payload["command"], "case-search")
            self.assertGreaterEqual(payload["summary"]["match_count"], 3)
            self.assertTrue(all(match["source"] == "artifacts" for match in payload["matches"]))

            quarantine_matches = [match for match in payload["matches"] if match["kind"] == "macos-quarantine-event"]
            self.assertTrue(quarantine_matches)
            self.assertTrue(any(match["metadata"].get("agent_name") == "Safari" for match in quarantine_matches))
            self.assertTrue(any(match["metadata"].get("origin_url") == "https://example.test" for match in quarantine_matches))

            launch_agent_matches = [match for match in payload["matches"] if match["kind"] == "macos-launch-agent"]
            self.assertTrue(launch_agent_matches)
            self.assertTrue(any(match["metadata"].get("label") == "com.example.persist" for match in launch_agent_matches))
            self.assertTrue(any("/usr/bin/osascript" in match["metadata"].get("program_arguments", []) for match in launch_agent_matches))

            browser_matches = [match for match in payload["matches"] if match["kind"] == "macos-browser-history-downloads"]
            self.assertTrue(browser_matches)
            self.assertTrue(any(match["metadata"].get("browser") == "safari" for match in browser_matches))
            self.assertTrue(any("example.test" in str(match["metadata"].get("preview_value", "")) for match in browser_matches))

    def test_cli_case_search_outputs_json_and_can_write_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            db_path = root / "case.db"
            output_path = root / "case-search.json"
            database = open_case_database(db_path)
            database.import_run_output(Path(sample_payload["run"]["output_dir"]), case_id="CASE-CLI-SEARCH")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-search",
                        str(db_path),
                        "--case-id",
                        "CASE-CLI-SEARCH",
                        "-k",
                        "password",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            printed = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "case-search")
            self.assertEqual(printed["summary"], payload["summary"])
            self.assertGreaterEqual(payload["summary"]["match_count"], 1)

    def test_review_marks_attach_to_search_results_and_can_filter_by_source_and_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            database = open_case_database(root / "case.db")
            database.import_run_output(Path(sample_payload["run"]["output_dir"]), case_id="CASE-REVIEW-SEARCH")

            unfiltered = database.search_case(
                case_id="CASE-REVIEW-SEARCH",
                keywords=["password"],
                sources=["documents"],
                limit=20,
            )
            self.assertIn("#51", unfiltered["review_workflow_summary"]["commercial_gap_ids"])
            self.assertEqual(
                unfiltered["review_workflow_summary"]["profile_version"],
                "case-search-review-workflow-summary-v1",
            )
            self.assertGreaterEqual(unfiltered["review_workflow_summary"]["review_queue_count"], 1)
            self.assertEqual(
                unfiltered["review_workflow_summary"]["review_assignment_manifest"]["manifest_version"],
                "case-review-assignment-manifest-v1",
            )
            self.assertEqual(
                unfiltered["review_workflow_summary"]["review_assignment_manifest_hash"],
                unfiltered["review_workflow_summary"]["review_assignment_manifest"]["manifest_hash"],
            )
            self.assertGreaterEqual(unfiltered["review_workflow_summary"]["source_viewer_locator_count"], 1)
            self.assertEqual(
                unfiltered["review_workflow_summary"]["review_queue"][0]["source_viewer_locator"]["viewer"],
                "case-review-source",
            )
            self.assertTrue(unfiltered["review_workflow_summary"]["review_queue"][0]["queue_row_hash"])
            self.assertIn(
                "assignment queue metadata emitted",
                unfiltered["review_workflow_summary"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "review source viewer locators emitted",
                unfiltered["review_workflow_summary"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            document_match = unfiltered["matches"][0]

            review = database.mark_review(
                case_id="CASE-REVIEW-SEARCH",
                target_type=str(document_match["target_type"]),
                target_id=str(document_match["target_id"]),
                status="relevant",
                verification_status="source_opened",
                tags=["credential", "credential", "report"],
                note="Confirmed in source preview.",
                reviewer="unit-test",
                include_in_report=True,
            )

            self.assertTrue(review["citation_id"].startswith("CASE-REVIEW-SEARCH-REV-"))
            self.assertEqual(review["tags"], ["credential", "report"])
            self.assertEqual(review["status"], "relevant")
            self.assertEqual(review["verification_status"], "source_opened")
            self.assertEqual(review["include_in_report"], True)
            review_qc = review["review_reporting_qc_contract"]
            self.assertEqual(review_qc["qc_prep_item_numbers"], [61, 62, 63, 64, 65])
            self.assertEqual(review_qc["evidence_tray_state_contract"]["qc_prep_item_number"], 61)
            self.assertEqual(review_qc["review_state_contract"]["qc_prep_item_number"], 62)
            self.assertIn("relevant", review_qc["review_state_contract"]["observed_statuses"])
            self.assertIn("#51", review["review_workflow"]["commercial_gap_ids"])
            review_gate = review["review_workflow"]["core_accuracy_gates"][0]
            self.assertEqual(review_gate["gap_id"], "#51")
            self.assertIn("review status fields persisted", review_gate["satisfied_checks"])
            self.assertIn("verification status captured", review_gate["satisfied_checks"])
            review_uplift = review["review_workflow"]["commercial_uplift_evidence"]
            self.assertEqual(review_uplift["batch_id"], "commercial-uplift-051-055")
            self.assertEqual(review_uplift["item_numbers"], [51])
            self.assertIn("review status fields persisted", review_uplift["passed_validation_check_ids"])
            self.assertEqual(
                review_uplift["reportability_decision"]["decision"],
                "do-not-report-review-workflow-as-role-based-case-management",
            )
            self.assertEqual(
                review_uplift["reportability_decision"]["allowed_use"],
                "single-user-review-status-triage-pivot",
            )
            self.assertFalse(review_uplift["large_data_controls"]["role_based_case_server"])
            self.assertFalse(review["review_workflow"]["ready_for_court_report"])

            filtered = database.search_case(
                case_id="CASE-REVIEW-SEARCH",
                keywords=["password"],
                sources=["documents"],
                verification_status="source_opened",
                limit=20,
            )

            self.assertGreaterEqual(filtered["summary"]["match_count"], 1)
            self.assertEqual(filtered["options"]["sources"], ["documents"])
            self.assertEqual(filtered["options"]["verification_status"], "source_opened")
            self.assertEqual(filtered["review_workflow_summary"]["filters"]["verification_status"], "source_opened")
            self.assertEqual(filtered["review_workflow_summary"]["assigned_count"], 0)
            self.assertGreaterEqual(filtered["review_workflow_summary"]["report_candidate_count"], 1)
            self.assertTrue(
                filtered["review_workflow_summary"]["commercial_uplift_evidence"]["large_data_controls"][
                    "review_assignment_manifest_present"
                ]
            )
            self.assertIn(
                "verification status filter applied",
                filtered["review_workflow_summary"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertTrue(all(match["source"] == "documents" for match in filtered["matches"]))
            self.assertTrue(all(match["review"]["verification_status"] == "source_opened" for match in filtered["matches"]))
            self.assertEqual(filtered["matches"][0]["review"]["status"], "relevant")

    def test_reviewer_workflow_requires_trusted_audit_diff_for_report_grade_gate(self) -> None:
        rapid = [
            {
                "citation_id": "CASE-REV-000001",
                "target_type": "indexed_document",
                "target_id": "doc-1",
                "status": "relevant",
                "verification_status": "source_opened",
                "reviewer": "analyst-a",
                "assignee": "analyst-b",
                "priority": "high",
                "due_at": "2026-05-07",
                "include_in_report": True,
                "tags": ["credential", "report"],
            }
        ]
        trusted = [dict(rapid[0])]

        diff = build_reviewer_workflow_trusted_diff(rapid, trusted, trusted_tool="analyst-review-log")
        self.assertEqual(diff["status"], "pass")
        workflow = review_workflow_assessment(
            assignee="analyst-b",
            priority="high",
            due_at="2026-05-07",
            trusted_diff=diff,
        )
        self.assertIn("trusted reviewer workflow audit diff pass", workflow["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertNotIn("review-workflow-trusted-audit-diff-required", workflow["blockers"])

        mismatch = build_reviewer_workflow_trusted_diff(
            rapid,
            [{**rapid[0], "status": "rejected"}],
            trusted_tool="analyst-review-log",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["mismatched_fields"][0]["field"], "status")

    def test_cli_case_review_marks_result_for_filtered_case_search(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            db_path = root / "case.db"
            database = open_case_database(db_path)
            database.import_run_output(Path(sample_payload["run"]["output_dir"]), case_id="CASE-CLI-REVIEW")
            search_payload = database.search_case(case_id="CASE-CLI-REVIEW", keywords=["password"], sources=["documents"])
            target = search_payload["matches"][0]
            review_stdout = io.StringIO()
            search_stdout = io.StringIO()

            with contextlib.redirect_stdout(review_stdout):
                review_exit_code = main(
                    [
                        "case-review",
                        str(db_path),
                        "--case-id",
                        "CASE-CLI-REVIEW",
                        "--target-type",
                        str(target["target_type"]),
                        "--target-id",
                        str(target["target_id"]),
                        "--status",
                        "relevant",
                        "--verification-status",
                        "source_opened",
                        "--tag",
                        "credential",
                        "--include-in-report",
                        "--json",
                    ]
                )

            with contextlib.redirect_stdout(search_stdout):
                search_exit_code = main(
                    [
                        "case-search",
                        str(db_path),
                        "--case-id",
                        "CASE-CLI-REVIEW",
                        "-k",
                        "password",
                        "--source",
                        "documents",
                        "--verification-status",
                        "source_opened",
                        "--review-status",
                        "relevant",
                        "--save-as",
                        "Reviewed credentials",
                        "--json",
                    ]
                )

            self.assertEqual(review_exit_code, 0)
            self.assertEqual(search_exit_code, 0)
            review_payload = json.loads(review_stdout.getvalue())
            filtered_payload = json.loads(search_stdout.getvalue())
            self.assertEqual(review_payload["status"], "relevant")
            self.assertEqual(filtered_payload["saved_search"]["name"], "Reviewed credentials")
            self.assertGreaterEqual(filtered_payload["summary"]["match_count"], 1)
            self.assertEqual(filtered_payload["matches"][0]["review"]["verification_status"], "source_opened")

    def test_case_review_updates_preserve_report_selection_until_explicitly_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            database = open_case_database(db_path)
            database.create_case(case_id="CASE-PRESERVE")

            created = database.mark_review(
                case_id="CASE-PRESERVE",
                target_type="artifact",
                target_id="1",
                status="relevant",
                verification_status="source_opened",
                tags=["credential"],
                note="Initial review",
                reviewer="analyst-a",
                include_in_report=True,
            )
            updated = database.mark_review(
                case_id="CASE-PRESERVE",
                target_type="artifact",
                target_id="1",
                verification_status="verified",
                include_in_report=None,
                status=None,
                tags=None,
                note=None,
                reviewer=None,
            )

            self.assertTrue(created["include_in_report"])
            self.assertTrue(updated["include_in_report"])
            self.assertEqual(updated["status"], "relevant")
            self.assertEqual(updated["verification_status"], "verified")
            self.assertEqual(updated["tags"], ["credential"])
            self.assertEqual(updated["note"], "Initial review")
            self.assertEqual(updated["reviewer"], "analyst-a")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-review",
                        str(db_path),
                        "--case-id",
                        "CASE-PRESERVE",
                        "--target-type",
                        "artifact",
                        "--target-id",
                        "1",
                        "--exclude-from-report",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            excluded = json.loads(stdout.getvalue())
            self.assertFalse(excluded["include_in_report"])
            self.assertEqual(excluded["status"], "relevant")
            self.assertEqual(excluded["verification_status"], "verified")

    def test_saved_searches_and_batch_review_support_repeated_case_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample_payload = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            database = open_case_database(root / "case.db")
            database.import_run_output(Path(sample_payload["run"]["output_dir"]), case_id="CASE-75")

            search_payload = database.search_case(
                case_id="CASE-75",
                keywords=["password"],
                sources=["documents"],
                limit=10,
            )
            targets = [
                {"target_type": str(match["target_type"]), "target_id": str(match["target_id"])}
                for match in search_payload["matches"][:2]
            ]
            saved = database.save_search(
                case_id="CASE-75",
                name="Credential review",
                keywords=["password"],
                sources=["documents"],
                review_status="unreviewed",
                verification_status="unverified",
                created_by="unit-test",
            )
            batch = database.mark_reviews_batch(
                case_id="CASE-75",
                targets=targets,
                status="relevant",
                verification_status="source_opened",
                tags=["credential", "batch"],
                note="Batch reviewed.",
                include_in_report=True,
                reviewer="unit-test",
                assignee="analyst-a",
                priority="high",
            )
            database.mark_review(
                case_id="CASE-75",
                target_type=targets[0]["target_type"],
                target_id=targets[0]["target_id"],
                status="relevant",
                verification_status="verified",
                tags=["credential", "batch"],
                note="Source was verified.",
                include_in_report=True,
                reviewer="unit-test",
                assignee="analyst-a",
                priority="urgent",
            )
            reviewed = database.search_case(
                case_id="CASE-75",
                keywords=["password"],
                sources=["documents"],
                review_status="relevant",
                verification_status="source_opened",
                limit=10,
            )

            self.assertTrue(saved["citation_id"].startswith("CASE-75-SRCH-"))
            self.assertEqual(database.list_saved_searches("CASE-75")[0]["name"], "Credential review")
            self.assertEqual(batch["updated_count"], len(targets))
            self.assertIn("#51", batch["marks"][0]["review_workflow"]["commercial_gap_ids"])
            self.assertEqual(batch["marks"][0]["review_workflow"]["core_accuracy_gates"][0]["gap_id"], "#51")
            self.assertEqual(batch["marks"][0]["review_workflow"]["commercial_uplift_evidence"]["item_numbers"], [51])
            self.assertIn("#65", batch["marks"][0]["evidence_selection_versioning"]["commercial_gap_ids"])
            self.assertTrue(batch["marks"][0]["review_workflow"]["assignment_present"])
            self.assertGreaterEqual(reviewed["summary"]["match_count"], max(0, len(targets) - 1))
            self.assertTrue(all(match["review"]["status"] == "relevant" for match in reviewed["matches"]))

            export = database.export_reviewed_items(case_id="CASE-75")
            self.assertEqual(export["command"], "case-db-report-export")
            self.assertIn("#51", export["summary"]["review_workflow_gap_ids"])
            self.assertIn("#64", export["summary"]["report_citation_gap_ids"])
            self.assertIn("#65", export["summary"]["evidence_selection_gap_ids"])
            self.assertEqual(export["summary"]["review_reporting_qc_gap_ids"], ["#61", "#62", "#63", "#64", "#65"])
            review_reporting_qc = export["review_reporting_qc_contract"]
            self.assertEqual(review_reporting_qc["qc_prep_item_numbers"], [61, 62, 63, 64, 65])
            self.assertEqual(review_reporting_qc["evidence_tray_state_contract"]["state_counts"]["report_candidates"], len(targets))
            self.assertEqual(review_reporting_qc["review_state_contract"]["review_mark_count"], len(targets))
            self.assertEqual(review_reporting_qc["compare_notes_contract"]["required_compare_slots"], ["A", "B", "C"])
            self.assertEqual(review_reporting_qc["report_citation_manager_contract"]["citation_count"], len(export["citation_index"]))
            self.assertGreaterEqual(
                review_reporting_qc["selected_evidence_history_contract"]["history_row_count"],
                len(targets),
            )
            self.assertEqual(export["summary"]["review_reporting_qc_contract_hash"], review_reporting_qc["contract_hash"])
            self.assertEqual(export["summary"]["submission_qc_gap_ids"], ["#66", "#67", "#68", "#69", "#70"])
            submission_qc = export["submission_qc_contract"]
            self.assertEqual(submission_qc["qc_prep_item_numbers"], [66, 67, 68, 69, 70])
            self.assertEqual(submission_qc["court_exhibit_bundle_contract"]["qc_prep_item_number"], 66)
            self.assertEqual(submission_qc["court_exhibit_bundle_contract"]["exhibit_count"], len(export["items"]))
            self.assertEqual(submission_qc["custody_acquisition_contract"]["qc_prep_item_number"], 67)
            self.assertGreaterEqual(submission_qc["custody_acquisition_contract"]["evidence_source_count"], 1)
            self.assertEqual(submission_qc["tamper_evident_audit_contract"]["qc_prep_item_number"], 68)
            self.assertEqual(submission_qc["run_validation_package_contract"]["qc_prep_item_number"], 69)
            self.assertEqual(submission_qc["run_validation_package_contract"]["selected_item_count"], len(export["items"]))
            self.assertEqual(submission_qc["trusted_tool_import_wizard_contract"]["qc_prep_item_number"], 70)
            self.assertIn("EvtxECmd", submission_qc["trusted_tool_import_wizard_contract"]["supported_tool_families"])
            self.assertEqual(export["summary"]["submission_qc_contract_hash"], submission_qc["contract_hash"])
            self.assertTrue(export["summary"]["review_assignment_enabled"])
            self.assertEqual(export["summary"]["exported_item_count"], len(targets))
            self.assertTrue(all(item["review"]["include_in_report"] for item in export["items"]))
            self.assertTrue(all(item["review_citation_id"].startswith("CASE-75-REV-") for item in export["items"]))
            self.assertTrue(all(item["target_citation_id"].startswith("CASE-75-") for item in export["items"]))
            self.assertTrue(all("source_reference" in item for item in export["items"]))
            self.assertGreaterEqual(export["summary"]["citation_count"], len(targets) * 2)
            self.assertEqual(export["summary"]["functional_priority_gap_ids"], ["#21", "#22", "#23", "#24"])
            self.assertEqual(export["summary"]["functional_priority_status"], "implemented-usable-validation-required")
            self.assertEqual(export["functional_reporting_profiles"]["batch_id"], "commercial-uplift-021-025")
            self.assertEqual(export["functional_reporting_profiles"]["item_numbers"], [21, 22, 23, 24])
            self.assertFalse(export["functional_reporting_profiles"]["ready_for_commercial_claim"])
            profile_by_number = {
                profile["item_number"]: profile
                for profile in export["functional_reporting_profiles"]["profiles"]
            }
            self.assertEqual(profile_by_number[21]["component"], "citation-manager-user-workflow")
            self.assertGreaterEqual(profile_by_number[21]["controls"]["citation_index_count"], len(targets) * 2)
            self.assertEqual(profile_by_number[22]["component"], "report-generation-user-workflow")
            self.assertTrue(profile_by_number[22]["controls"]["json_case_export"])
            self.assertTrue(profile_by_number[22]["controls"]["case_db_markdown_document"])
            self.assertTrue(profile_by_number[22]["controls"]["case_db_report_manifest"])
            self.assertTrue(profile_by_number[22]["controls"]["case_db_hash_bundle"])
            self.assertEqual(len(profile_by_number[22]["controls"]["report_generation_manifest_hash"]), 64)
            self.assertEqual(profile_by_number[23]["component"], "court-exhibit-package-readiness")
            self.assertTrue(profile_by_number[23]["controls"]["court_exhibit_manifest"])
            self.assertEqual(len(profile_by_number[23]["controls"]["court_exhibit_manifest_hash"]), 64)
            self.assertEqual(len(profile_by_number[23]["controls"]["court_exhibit_package_hash"]), 64)
            self.assertTrue(profile_by_number[23]["controls"]["external_signature_slot"])
            self.assertFalse(profile_by_number[23]["controls"]["external_signature_attached"])
            self.assertEqual(profile_by_number[24]["component"], "validation-warning-user-experience")
            self.assertGreaterEqual(profile_by_number[24]["controls"]["validation_assessment_count"], len(targets))
            self.assertEqual(profile_by_number[24]["controls"]["warning_display_profile_count"], len(export["items"]))
            self.assertGreaterEqual(profile_by_number[24]["controls"]["validation_required_count"], 1)
            self.assertGreaterEqual(profile_by_number[24]["controls"]["external_evidence_needed_count"], 1)
            self.assertGreaterEqual(profile_by_number[24]["controls"]["report_grade_candidate_count"], 1)
            self.assertTrue(all(item["functional_priority_gap_ids"] == ["#21", "#22", "#23", "#24"] for item in export["items"]))
            self.assertTrue(all(item["warning_display_profile"]["item_number"] == 24 for item in export["items"]))
            self.assertTrue(all(len(item["warning_display_profile"]["profile_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all("validation-required" in item["warning_display_profile"]["state_badges"] for item in export["items"]))
            warning_summary = export["summary"]["warning_ux_summary"]
            self.assertEqual(warning_summary["profile_count"], len(export["items"]))
            self.assertGreaterEqual(warning_summary["validation_required_count"], 1)
            self.assertEqual(export["summary"]["warning_ux_profile_count"], len(export["items"]))
            self.assertTrue(all(item["report_citation_profile"]["item_number"] == 21 for item in export["items"]))
            self.assertTrue(all(len(item["report_citation_profile"]["profile_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(item["report_citation_profile"]["citation_pair_available"] for item in export["items"]))
            self.assertTrue(all(item["report_citation_profile"]["source_path"] for item in export["items"]))
            self.assertTrue(all(item["report_citation_profile"]["legal_limitation_status"] == "present" for item in export["items"]))
            self.assertTrue(all("trusted-citation-index-diff-is-required-before-commercial-claim" in item["report_citation_profile"]["blockers"] for item in export["items"]))
            citation_workflow_summary = export["summary"]["report_citation_profile_summary"]
            self.assertEqual(citation_workflow_summary["item_number"], 21)
            self.assertEqual(citation_workflow_summary["profile_count"], len(export["items"]))
            self.assertGreaterEqual(citation_workflow_summary["ready_for_report_export_count"], 1)
            self.assertGreaterEqual(citation_workflow_summary["legal_limitation_count"], len(export["items"]))
            self.assertEqual(export["summary"]["report_citation_ready_count"], citation_workflow_summary["ready_for_report_export_count"])
            self.assertEqual(export["summary"]["report_citation_blocker_count"], citation_workflow_summary["blocker_count"])
            report_package = export["report_generation_package"]
            self.assertEqual(report_package["manifest"]["profile_version"], "case-db-report-generation-manifest-v1")
            self.assertEqual(report_package["manifest"]["item_number"], 22)
            self.assertEqual(len(report_package["manifest"]["manifest_hash"]), 64)
            self.assertEqual(len(report_package["hash_bundle_sha256"]), 64)
            self.assertIn("# RapidForensic Case DB Report Export", report_package["markdown_document"])
            self.assertIn("Report Candidates", report_package["markdown_document"])
            self.assertEqual(report_package["manifest"]["hash_bundle_sha256"], report_package["hash_bundle_sha256"])
            self.assertEqual(export["summary"]["report_generation_manifest_hash"], report_package["manifest"]["manifest_hash"])
            self.assertEqual(export["summary"]["report_generation_hash_bundle_sha256"], report_package["hash_bundle_sha256"])
            self.assertEqual(len(report_package["hash_bundle"]["item_row_hashes"]), len(export["items"]))
            self.assertEqual(len(report_package["hash_bundle"]["citation_row_hashes"]), len(export["citation_index"]))
            exhibit_package = export["court_exhibit_package"]
            self.assertEqual(exhibit_package["manifest"]["profile_version"], "court-exhibit-package-manifest-v1")
            self.assertEqual(exhibit_package["manifest"]["item_number"], 94)
            self.assertEqual(exhibit_package["manifest"]["functional_item_number"], 23)
            self.assertIn("#94", exhibit_package["commercial_gap_ids"])
            self.assertEqual(exhibit_package["manifest"]["exhibit_count"], len(export["items"]))
            self.assertEqual(len(exhibit_package["manifest"]["manifest_hash"]), 64)
            self.assertEqual(len(exhibit_package["manifest"]["exhibit_readiness_matrix_hash"]), 64)
            self.assertEqual(
                exhibit_package["court_exhibit_readiness_matrix_hash"],
                exhibit_package["manifest"]["exhibit_readiness_matrix_hash"],
            )
            self.assertEqual(
                exhibit_package["court_exhibit_readiness_matrix"]["profile_version"],
                "court-exhibit-readiness-matrix-v1",
            )
            self.assertEqual(len(exhibit_package["package_hash"]), 64)
            self.assertEqual(export["summary"]["court_exhibit_manifest_hash"], exhibit_package["manifest"]["manifest_hash"])
            self.assertEqual(export["summary"]["court_exhibit_package_hash"], exhibit_package["package_hash"])
            self.assertEqual(export["summary"]["court_exhibit_count"], len(export["items"]))
            self.assertTrue(exhibit_package["manifest"]["external_signature"]["slot_present"])
            self.assertFalse(exhibit_package["ready_for_court_report"])
            self.assertTrue(all(row["exhibit_id"].startswith("EXH-") for row in exhibit_package["exhibits"]))
            self.assertTrue(all(len(row["exhibit_row_hash"]) == 64 for row in exhibit_package["exhibits"]))
            self.assertTrue(all(row["review_citation_id"] for row in exhibit_package["exhibits"]))
            self.assertTrue(all(row["source_citation_id"] for row in exhibit_package["exhibits"]))
            self.assertEqual(profile_by_number[21]["controls"]["report_candidate_profile_count"], len(export["items"]))
            self.assertEqual(
                profile_by_number[21]["controls"]["ready_for_report_export_count"],
                citation_workflow_summary["ready_for_report_export_count"],
            )
            self.assertGreaterEqual(profile_by_number[21]["controls"]["legal_limitation_count"], len(export["items"]))
            self.assertTrue(export["citation_index"])
            self.assertIn("#64", export["citation_index"][0]["commercial_gap_ids"])
            self.assertTrue(all(item.get("copy_safe_citation") for item in export["citation_index"]))
            self.assertTrue(all(len(item.get("citation_row_hash", "")) == 64 for item in export["citation_index"]))
            self.assertTrue(all(item.get("source_viewer_locator", {}).get("viewer") == "report-citation-source" for item in export["citation_index"]))
            source_citations = [item for item in export["citation_index"] if item["role"] == "source-record"]
            self.assertTrue(source_citations)
            self.assertTrue(all(item["source_hash_status"] in {"present", "missing"} for item in source_citations))
            self.assertTrue(all(item["parser_version_status"] in {"present", "missing"} for item in source_citations))
            self.assertIn("#64", export["report_citation_manager"]["commercial_gap_ids"])
            citation_manifest = export["report_citation_manager"]["citation_index_manifest"]
            self.assertEqual(citation_manifest["manifest_version"], "report-citation-index-manifest-v1")
            self.assertEqual(export["report_citation_manager"]["citation_index_manifest_hash"], citation_manifest["manifest_hash"])
            self.assertEqual(citation_manifest["citation_count"], len(export["citation_index"]))
            self.assertEqual(citation_manifest["citation_row_hash_count"], len(export["citation_index"]))
            self.assertGreaterEqual(citation_manifest["source_viewer_locator_count"], len(export["citation_index"]))
            coverage = export["report_citation_manager"]["coverage_profile"]
            self.assertEqual(coverage["profile_version"], "report-citation-coverage-profile-v1")
            self.assertEqual(coverage["citation_count"], len(export["citation_index"]))
            self.assertGreaterEqual(coverage["copy_safe_citation_count"], len(export["citation_index"]))
            self.assertEqual(coverage["citation_row_hash_count"], len(export["citation_index"]))
            self.assertGreaterEqual(coverage["source_viewer_locator_count"], len(export["citation_index"]))
            self.assertEqual(coverage["source_record_count"], len(source_citations))
            self.assertIn("#64", coverage["commercial_gap_ids"])
            self.assertEqual(export["report_citation_manager"]["core_accuracy_gates"][0]["gap_id"], "#64")
            self.assertIn("citation count summary", export["report_citation_manager"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("citation index manifest", export["report_citation_manager"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("citation row hashes", export["report_citation_manager"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("citation source viewer locators", export["report_citation_manager"]["core_accuracy_gates"][0]["satisfied_checks"])
            citation_uplift = export["report_citation_manager"]["commercial_uplift_evidence"]
            self.assertEqual(citation_uplift["batch_id"], "commercial-uplift-061-065")
            self.assertEqual(citation_uplift["item_numbers"], [64])
            self.assertIn("citation count summary", citation_uplift["passed_validation_check_ids"])
            self.assertEqual(
                citation_uplift["large_data_controls"]["citation_index_manifest_hash"],
                citation_manifest["manifest_hash"],
            )
            self.assertEqual(citation_uplift["large_data_controls"]["citation_row_hash_count"], len(export["citation_index"]))
            self.assertEqual(citation_uplift["large_data_controls"]["source_viewer_locator_count"], len(export["citation_index"]))
            self.assertIn("trusted-citation-index-diff-is-required-before-commercial-claim", citation_uplift["failed_validation_check_ids"])
            self.assertFalse(citation_uplift["large_data_controls"]["exhibit_numbering_ui"])
            self.assertEqual(
                citation_uplift["reportability_decision"]["decision"],
                "do-not-report-citation-index-as-court-exhibit-complete",
            )
            citation_diff = build_citation_manager_trusted_diff(export["citation_index"], export["citation_index"])
            citation_gates = citation_manager_core_accuracy_gates(
                citation_count=len(export["citation_index"]),
                has_source_reference=True,
                trusted_diff=citation_diff,
                citation_index_manifest=citation_manifest,
            )
            self.assertEqual(citation_diff["status"], "pass")
            self.assertIn("citation index manifest", citation_gates[0]["satisfied_checks"])
            self.assertIn("trusted citation index diff pass", citation_gates[0]["satisfied_checks"])
            self.assertGreaterEqual(len(export["items"][0]["review_history"]), 1)
            self.assertIn("#65", export["items"][0]["review_history"][0]["commercial_gap_ids"])
            self.assertEqual(export["items"][0]["review_history"][0]["target_type"], targets[0]["target_type"])
            self.assertEqual(export["items"][0]["review_history"][0]["target_id"], targets[0]["target_id"])
            self.assertEqual(
                export["items"][0]["review_history"][0]["history_viewer_locator"]["viewer"],
                "evidence-selection-history",
            )
            self.assertEqual(len(export["items"][0]["review_history"][0]["row_hash"]), 64)
            self.assertEqual(export["items"][0]["review_history"][0]["core_accuracy_gates"][0]["gap_id"], "#65")
            self.assertIn("#65", export["evidence_selection_version_history"]["commercial_gap_ids"])
            self.assertEqual(export["evidence_selection_version_history"]["core_accuracy_gates"][0]["gap_id"], "#65")
            integrity = export["evidence_selection_version_history"]["integrity_profile"]
            self.assertEqual(integrity["profile_version"], "evidence-selection-history-integrity-profile-v1")
            self.assertGreaterEqual(integrity["history_row_count"], len(targets))
            self.assertGreaterEqual(integrity["row_hash_count"], len(targets))
            self.assertEqual(len(integrity["head_hash"]), 64)
            self.assertGreaterEqual(integrity["include_in_report_change_count"], 1)
            self.assertTrue(integrity["tamper_evident_export_only"])
            self.assertTrue(integrity["database_enforced_append_only"])
            self.assertEqual(integrity["append_only_triggers"], ["review_mark_history_no_update", "review_mark_history_no_delete"])
            history_manifest = export["evidence_selection_version_history"]["history_manifest"]
            self.assertEqual(history_manifest["manifest_version"], "evidence-selection-history-manifest-v1")
            self.assertEqual(export["evidence_selection_version_history"]["history_manifest_hash"], history_manifest["manifest_hash"])
            self.assertEqual(history_manifest["history_row_count"], integrity["history_row_count"])
            self.assertEqual(history_manifest["row_hash_count"], integrity["row_hash_count"])
            self.assertEqual(history_manifest["history_head_hash"], integrity["head_hash"])
            self.assertGreaterEqual(history_manifest["history_viewer_locator_count"], len(targets))
            self.assertTrue(history_manifest["append_only_enforcement"]["database_enforced_append_only"])
            self.assertFalse(history_manifest["append_only_enforcement"]["multi_user_signed_history"])
            self.assertIn(
                "evidence history manifest",
                export["evidence_selection_version_history"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "database append-only guardrails",
                export["evidence_selection_version_history"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            history_uplift = export["evidence_selection_version_history"]["commercial_uplift_evidence"]
            self.assertEqual(history_uplift["item_numbers"], [65])
            self.assertIn("versioned review history rows", history_uplift["passed_validation_check_ids"])
            self.assertGreaterEqual(history_uplift["large_data_controls"]["row_hash_count"], len(targets))
            self.assertEqual(history_uplift["large_data_controls"]["history_head_hash"], integrity["head_hash"])
            self.assertEqual(history_uplift["large_data_controls"]["history_manifest_hash"], history_manifest["manifest_hash"])
            self.assertGreaterEqual(history_uplift["large_data_controls"]["history_viewer_locator_count"], len(targets))
            self.assertTrue(history_uplift["large_data_controls"]["database_enforced_append_only"])
            self.assertEqual(history_uplift["large_data_controls"]["append_only_trigger_count"], 2)
            self.assertIn("trusted-evidence-history-diff-is-required-before-commercial-claim", history_uplift["failed_validation_check_ids"])
            self.assertFalse(history_uplift["large_data_controls"]["multi_user_signed_history"])
            self.assertEqual(
                history_uplift["reportability_decision"]["allowed_use"],
                "evidence-selection-history-triage-pivot",
            )
            history_rows = [
                row
                for item in export["items"]
                for row in item.get("review_history", [])
            ]
            history_diff = build_evidence_history_trusted_diff(history_rows, history_rows)
            history_gates = evidence_selection_core_accuracy_gates(
                history_rows=history_rows,
                trusted_diff=history_diff,
                history_manifest=history_manifest,
            )
            self.assertEqual(history_diff["status"], "pass")
            self.assertIn("evidence history manifest", history_gates[0]["satisfied_checks"])
            self.assertIn("trusted evidence history diff pass", history_gates[0]["satisfied_checks"])
            with database.connect() as connection:
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        "UPDATE review_mark_history SET actor = actor WHERE id = (SELECT id FROM review_mark_history LIMIT 1)"
                    )
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute(
                        "DELETE FROM review_mark_history WHERE id = (SELECT id FROM review_mark_history LIMIT 1)"
                    )
            self.assertIn("#65", export["items"][0]["commercial_gap_ids"])
            self.assertIn("custody_workflow", export)
            self.assertGreaterEqual(export["custody_workflow"]["summary"]["evidence_source_count"], 1)
            self.assertIn("#86", export["custody_workflow"]["commercial_gap_ids"])
            self.assertEqual(export["custody_workflow"]["functional_priority_profile"]["item_number"], 40)
            self.assertEqual(export["custody_workflow"]["custody_event_manifest"]["profile_version"], "custody-event-manifest-v1")
            self.assertEqual(len(export["custody_workflow"]["custody_event_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                export["custody_workflow"]["custody_manifest_hash"],
                export["custody_workflow"]["custody_event_manifest"]["manifest_hash"],
            )
            self.assertEqual(export["custody_workflow"]["custody_chain_manifest"]["profile_version"], "custody-chain-manifest-v1")
            self.assertEqual(export["custody_workflow"]["custody_chain_manifest"]["item_number"], 40)
            self.assertEqual(export["custody_workflow"]["custody_chain_manifest"]["gap_id"], "#40")
            self.assertEqual(len(export["custody_workflow"]["custody_chain_manifest"]["manifest_hash"]), 64)
            self.assertEqual(len(export["custody_workflow"]["custody_chain_manifest"]["hash_chain_head"]), 64)
            self.assertEqual(
                export["custody_workflow"]["custody_completeness_matrix"]["profile_version"],
                "custody-completeness-matrix-v1",
            )
            self.assertEqual(len(export["custody_workflow"]["custody_completeness_matrix_hash"]), 64)
            self.assertEqual(
                export["custody_workflow"]["custody_chain_manifest"]["custody_completeness_matrix_hash"],
                export["custody_workflow"]["custody_completeness_matrix_hash"],
            )
            self.assertEqual(
                export["custody_workflow"]["custody_chain_manifest_hash"],
                export["custody_workflow"]["custody_chain_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                export["custody_workflow"]["functional_priority_profile"]["implemented_controls"]["custody_chain_manifest_hash"],
                export["custody_workflow"]["custody_chain_manifest"]["manifest_hash"],
            )
            self.assertTrue(all(len(item["custody_row_hash"]) == 64 for item in export["custody_workflow"]["evidence_sources"]))
            self.assertTrue(all(len(item["custody_row_hash"]) == 64 for item in export["custody_workflow"]["custody_events"]))
            self.assertIn(
                "trusted-custody-event-manifest-diff-missing",
                export["custody_workflow"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(export["custody_workflow"]["core_accuracy_gates"][0]["gap_id"], "#86")
            self.assertIn("evidence source inventory", export["custody_workflow"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("custody row hashes emitted", export["custody_workflow"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("custody event manifest hash emitted", export["custody_workflow"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("custody chain manifest hash emitted", export["custody_workflow"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("custody completeness matrix hash emitted", export["custody_workflow"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(export["custody_workflow"]["trusted_custody_diff"]["status"], "missing")
            self.assertIn("trusted-custody-event-manifest-diff-missing", export["custody_workflow"]["blockers"])
            custody_diff = build_custody_workflow_trusted_diff(export["custody_workflow"], export["custody_workflow"])
            custody_gates = custody_workflow_core_accuracy_gates(
                evidence_sources=export["custody_workflow"]["evidence_sources"],
                custody_events=export["custody_workflow"]["custody_events"],
                custody_event_manifest=export["custody_workflow"]["custody_event_manifest"],
                trusted_diff=custody_diff,
            )
            self.assertEqual(custody_diff["status"], "pass")
            self.assertIn("manifest_hash", custody_diff["compared_fields"])
            self.assertIn("trusted custody event manifest diff pass", custody_gates[0]["satisfied_checks"])
            self.assertIn("acquisition_hash_workflow", export)
            self.assertIn("#87", export["acquisition_hash_workflow"]["commercial_gap_ids"])
            self.assertEqual(
                export["acquisition_hash_workflow"]["acquisition_hash_manifest"]["profile_version"],
                "acquisition-hash-manifest-v1",
            )
            self.assertEqual(
                len(export["acquisition_hash_workflow"]["acquisition_hash_manifest"]["manifest_hash"]),
                64,
            )
            self.assertTrue(
                all(len(item["acquisition_hash_row_hash"]) == 64 for item in export["acquisition_hash_workflow"]["hashes"])
            )
            self.assertEqual(export["acquisition_hash_workflow"]["functional_priority_profile"]["item_number"], 87)
            self.assertIn(
                "trusted-acquisition-hash-manifest-diff-missing",
                export["acquisition_hash_workflow"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(export["acquisition_hash_workflow"]["core_accuracy_gates"][0]["gap_id"], "#87")
            self.assertIn(
                "acquisition hash row hashes emitted",
                export["acquisition_hash_workflow"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "acquisition hash manifest hash emitted",
                export["acquisition_hash_workflow"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(export["acquisition_hash_workflow"]["trusted_acquisition_hash_diff"]["status"], "missing")
            self.assertIn("trusted-acquisition-hash-manifest-diff-missing", export["acquisition_hash_workflow"]["blockers"])
            hash_diff = build_acquisition_hash_trusted_diff(
                export["acquisition_hash_workflow"],
                export["acquisition_hash_workflow"],
            )
            hash_gates = acquisition_hash_core_accuracy_gates(
                hashes=export["acquisition_hash_workflow"]["hashes"],
                acquisition_hash_manifest=export["acquisition_hash_workflow"]["acquisition_hash_manifest"],
                trusted_diff=hash_diff,
            )
            self.assertEqual(hash_diff["status"], "pass")
            self.assertIn("manifest_hash", hash_diff["compared_fields"])
            self.assertIn("hash_inventory_matrix_hash", hash_diff["compared_fields"])
            self.assertIn("trusted acquisition hash manifest diff pass", hash_gates[0]["satisfied_checks"])
            self.assertEqual(
                export["acquisition_hash_workflow"]["acquisition_hash_manifest"]["hash_inventory_matrix"]["profile_version"],
                "acquisition-hash-inventory-matrix-v1",
            )
            self.assertEqual(len(export["acquisition_hash_workflow"]["acquisition_hash_manifest"]["hash_inventory_matrix_hash"]), 64)
            self.assertIn(
                "acquisition hash inventory matrix emitted",
                export["acquisition_hash_workflow"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("audit_integrity", export)
            self.assertIn("#88", export["audit_integrity"]["commercial_gap_ids"])
            self.assertEqual(
                export["audit_integrity"]["audit_hash_chain_manifest"]["profile_version"],
                "audit-hash-chain-manifest-v1",
            )
            self.assertEqual(len(export["audit_integrity"]["audit_hash_chain_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                export["audit_integrity"]["audit_hash_chain_manifest"]["actor_action_matrix"]["profile_version"],
                "audit-actor-action-matrix-v1",
            )
            self.assertEqual(len(export["audit_integrity"]["audit_hash_chain_manifest"]["actor_action_matrix_hash"]), 64)
            self.assertEqual(
                export["audit_integrity"]["audit_replay_manifest"]["profile_version"],
                "audit-replay-manifest-v1",
            )
            self.assertEqual(export["audit_integrity"]["audit_replay_manifest"]["item_number"], 44)
            self.assertEqual(export["audit_integrity"]["audit_replay_manifest"]["gap_id"], "#44")
            self.assertEqual(len(export["audit_integrity"]["audit_replay_manifest_hash"]), 64)
            self.assertTrue(export["audit_integrity"]["audit_replay_manifest"]["chain_valid"])
            self.assertEqual(len(export["audit_integrity"]["audit_replay_manifest"]["replay_matrix_hash"]), 64)
            self.assertEqual(export["audit_integrity"]["functional_priority_profile"]["item_number"], 44)
            self.assertTrue(export["audit_integrity"]["functional_priority_profile"]["implemented_controls"]["head_hash_present"])
            self.assertEqual(
                len(export["audit_integrity"]["functional_priority_profile"]["implemented_controls"]["audit_chain_manifest_hash"]),
                64,
            )
            self.assertEqual(
                export["audit_integrity"]["functional_priority_profile"]["implemented_controls"]["audit_replay_manifest_hash"],
                export["audit_integrity"]["audit_replay_manifest"]["manifest_hash"],
            )
            self.assertIn(
                "trusted-audit-hash-chain-manifest-diff-missing",
                export["audit_integrity"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(export["audit_integrity"]["core_accuracy_gates"][0]["gap_id"], "#88")
            self.assertIn(
                "audit hash-chain manifest hash emitted",
                export["audit_integrity"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertGreaterEqual(export["audit_integrity"]["summary"]["event_count"], 1)
            self.assertTrue(export["audit_integrity"]["summary"]["head_hash"])
            self.assertEqual(
                export["audit_integrity"]["summary"]["audit_chain_manifest_hash"],
                export["audit_integrity"]["audit_hash_chain_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                export["audit_integrity"]["summary"]["audit_replay_manifest_hash"],
                export["audit_integrity"]["audit_replay_manifest"]["manifest_hash"],
            )
            self.assertEqual(export["audit_integrity"]["trusted_audit_integrity_diff"]["status"], "missing")
            self.assertIn("trusted-audit-hash-chain-manifest-diff-missing", export["audit_integrity"]["blockers"])
            audit_diff = build_immutable_audit_trusted_diff(export["audit_integrity"], export["audit_integrity"])
            audit_gates = immutable_audit_core_accuracy_gates(
                events=export["audit_integrity"]["events"],
                head_hash=export["audit_integrity"]["summary"]["head_hash"],
                audit_hash_chain_manifest=export["audit_integrity"]["audit_hash_chain_manifest"],
                audit_replay_manifest=export["audit_integrity"]["audit_replay_manifest"],
                trusted_diff=audit_diff,
            )
            self.assertEqual(audit_diff["status"], "pass")
            self.assertIn("manifest_hash", audit_diff["compared_fields"])
            self.assertIn("actor_action_matrix_hash", audit_diff["compared_fields"])
            self.assertIn("audit_replay_manifest_hash", audit_diff["compared_fields"])
            self.assertIn("replay_matrix_hash", audit_diff["compared_fields"])
            self.assertIn("audit actor/action matrix hash emitted", audit_gates[0]["satisfied_checks"])
            self.assertIn("audit replay manifest hash emitted", audit_gates[0]["satisfied_checks"])
            self.assertIn("audit replay matrix hash emitted", audit_gates[0]["satisfied_checks"])
            self.assertIn("audit replay chain validation pass", audit_gates[0]["satisfied_checks"])
            self.assertIn("trusted audit hash-chain manifest diff pass", audit_gates[0]["satisfied_checks"])
            self.assertIn("reproducibility", export)
            self.assertIn("#89", export["reproducibility"]["commercial_gap_ids"])
            self.assertEqual(export["reproducibility"]["core_accuracy_gates"][0]["gap_id"], "#89")
            self.assertTrue(export["reproducibility"]["stable_payload_sha256"])
            self.assertEqual(
                export["reproducibility"]["report_replay_manifest"]["profile_version"],
                "report-replay-manifest-v1",
            )
            self.assertEqual(len(export["reproducibility"]["report_replay_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                export["reproducibility"]["report_replay_manifest_hash"],
                export["reproducibility"]["report_replay_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                len(export["reproducibility"]["report_replay_manifest"]["item_row_hashes"]),
                export["reproducibility"]["stable_item_count"],
            )
            self.assertEqual(
                len(export["reproducibility"]["report_replay_manifest"]["citation_row_hashes"]),
                export["reproducibility"]["citation_count"],
            )
            self.assertEqual(len(export["reproducibility"]["report_replay_manifest"]["row_hash_set_hash"]), 64)
            self.assertEqual(len(export["reproducibility"]["report_replay_manifest"]["replay_contract_hash"]), 64)
            self.assertIn(
                "report replay manifest hash emitted",
                export["reproducibility"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "item/citation row hashes emitted",
                export["reproducibility"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(export["reproducibility"]["trusted_reproducibility_diff"]["status"], "missing")
            self.assertIn("trusted-report-replay-manifest-diff-missing", export["reproducibility"]["blockers"])
            reproducibility_diff = build_report_reproducibility_trusted_diff(
                export["reproducibility"],
                export["reproducibility"],
            )
            reproducibility_gates = report_reproducibility_core_accuracy_gates(
                stable_hash=export["reproducibility"]["stable_payload_sha256"],
                item_count=export["reproducibility"]["stable_item_count"],
                citation_count=export["reproducibility"]["citation_count"],
                report_replay_manifest=export["reproducibility"]["report_replay_manifest"],
                trusted_diff=reproducibility_diff,
            )
            self.assertEqual(reproducibility_diff["status"], "pass")
            self.assertIn("manifest_hash", reproducibility_diff["compared_fields"])
            self.assertIn("row_hash_set_hash", reproducibility_diff["compared_fields"])
            self.assertIn("replay_contract_hash", reproducibility_diff["compared_fields"])
            self.assertIn("row hash set hash emitted", reproducibility_gates[0]["satisfied_checks"])
            self.assertIn("replay contract hash emitted", reproducibility_gates[0]["satisfied_checks"])
            self.assertIn("trusted report replay manifest diff pass", reproducibility_gates[0]["satisfied_checks"])
            self.assertTrue(all("provenance" in item for item in export["items"]))
            self.assertTrue(all("#90" in item["provenance"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all(item["provenance"]["core_accuracy_gates"][0]["gap_id"] == "#90" for item in export["items"]))
            self.assertTrue(all(len(item["provenance"]["provenance_row_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(item["provenance"]["provenance_manifest"]["profile_version"] == "report-provenance-row-manifest-v1" for item in export["items"]))
            self.assertTrue(all(len(item["provenance"]["provenance_manifest_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(len(item["provenance"]["provenance_manifest"]["field_presence_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(item["provenance"]["provenance_manifest"]["completeness_score"] > 0 for item in export["items"]))
            self.assertTrue(all("provenance row hash emitted" in item["provenance"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("provenance manifest hash emitted" in item["provenance"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("provenance field-presence hash emitted" in item["provenance"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all(item["provenance"]["trusted_provenance_diff"]["status"] == "missing" for item in export["items"]))
            self.assertTrue(all("trusted-report-provenance-manifest-diff-missing" in item["provenance"]["blockers"] for item in export["items"]))
            self.assertIn("#90", export["summary"]["forensic_integrity_gap_ids"])
            self.assertTrue(all(item["provenance"]["review_citation_id"].startswith("CASE-75-REV-") for item in export["items"]))
            provenance_rows = [item["provenance"] for item in export["items"]]
            provenance_diff = build_report_provenance_trusted_diff(provenance_rows, provenance_rows)
            provenance_gate = report_item_provenance_core_accuracy_gates(
                source_path=provenance_rows[0]["source_path"],
                hashes=provenance_rows[0]["hashes"],
                record_hashes=provenance_rows[0]["record_hashes"],
                parser=provenance_rows[0]["parser"],
                parser_version=provenance_rows[0]["parser_version"],
                parser_confidence=provenance_rows[0]["parser_confidence"],
                record_offset=provenance_rows[0]["record_offset"],
                source_index=provenance_rows[0]["source_index"],
                review_status=provenance_rows[0]["review_status"],
                reportability=provenance_rows[0]["reportability"],
                provenance_manifest=provenance_rows[0]["provenance_manifest"],
                trusted_diff=provenance_diff,
            )
            self.assertEqual(provenance_diff["status"], "pass")
            self.assertIn("manifest_hash", provenance_diff["compared_fields"])
            self.assertIn("field_presence_hash", provenance_diff["compared_fields"])
            self.assertIn("completeness_score", provenance_diff["compared_fields"])
            self.assertIn("trusted report provenance manifest diff pass", provenance_gate[0]["satisfied_checks"])
            self.assertEqual(export["forensic_integrity_matrix"]["profile_version"], "forensic-integrity-matrix-v1")
            self.assertEqual(export["forensic_integrity_matrix"]["item_numbers"], [86, 87, 88, 89, 90])
            self.assertEqual(len(export["forensic_integrity_matrix"]["matrix_hash"]), 64)
            self.assertEqual(
                export["summary"]["forensic_integrity_matrix_hash"],
                export["forensic_integrity_matrix"]["matrix_hash"],
            )
            self.assertTrue(export["forensic_integrity_matrix"]["all_primary_hashes_present"])
            self.assertTrue(all("validation_assessment" in item for item in export["items"]))
            self.assertTrue(all("#91" in item["validation_assessment"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all("#92" in item["validation_assessment"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["core_accuracy_gates"][0]["gap_id"] == "#91" for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["core_accuracy_gates"][1]["gap_id"] == "#92" for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["parser_confidence_calibration_manifest"]["profile_version"] == "parser-confidence-calibration-manifest-v1" for item in export["items"]))
            self.assertTrue(all(len(item["validation_assessment"]["parser_confidence_manifest_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(len(item["validation_assessment"]["calibration_field_presence_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["confidence_band"] for item in export["items"]))
            self.assertTrue(all(isinstance(item["validation_assessment"]["reportability_score"], int) for item in export["items"]))
            self.assertTrue(all("confidence band assigned" in item["validation_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("reportability score emitted" in item["validation_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("parser confidence calibration manifest hash emitted" in item["validation_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("parser confidence field-presence hash emitted" in item["validation_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["trusted_parser_confidence_diff"]["status"] == "missing" for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["trusted_validation_warning_diff"]["status"] == "missing" for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["validation_warning_checklist_manifest"]["profile_version"] == "validation-warning-checklist-manifest-v1" for item in export["items"]))
            self.assertTrue(all(len(item["validation_assessment"]["validation_warning_manifest_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(len(item["validation_assessment"]["warning_action_matrix_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(isinstance(item["validation_assessment"]["warning_details"], list) for item in export["items"]))
            self.assertTrue(all(isinstance(item["validation_assessment"]["warning_severity_counts"], dict) for item in export["items"]))
            self.assertTrue(all(isinstance(item["validation_assessment"]["warning_ux_badges"], list) for item in export["items"]))
            self.assertTrue(all("warning detail metadata emitted" in item["validation_assessment"]["core_accuracy_gates"][1]["satisfied_checks"] for item in export["items"] if item["validation_assessment"]["warnings"]))
            self.assertTrue(all("warning UX badges emitted" in item["validation_assessment"]["core_accuracy_gates"][1]["satisfied_checks"] for item in export["items"] if item["validation_assessment"]["warnings"]))
            self.assertTrue(all("validation warning checklist manifest hash emitted" in item["validation_assessment"]["core_accuracy_gates"][1]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("warning action matrix hash emitted" in item["validation_assessment"]["core_accuracy_gates"][1]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("trusted-parser-confidence-calibration-diff-missing" in item["validation_assessment"]["blockers"] for item in export["items"]))
            self.assertTrue(all("trusted-validation-warning-checklist-diff-missing" in item["validation_assessment"]["blockers"] for item in export["items"]))
            validation_assessment = export["items"][0]["validation_assessment"]
            confidence_diff = build_parser_confidence_trusted_diff(validation_assessment, validation_assessment)
            warning_diff = build_validation_warning_trusted_diff(validation_assessment, validation_assessment)
            confidence_gate = parser_confidence_core_accuracy_gates(
                parser_confidence=validation_assessment["parser_confidence"],
                reportability=validation_assessment["reportability"],
                coverage_status=validation_assessment["coverage_status"],
                warnings=validation_assessment["warnings"],
                evidence_strength=export["items"][0]["provenance"]["evidence_strength"],
                confidence_manifest=validation_assessment["parser_confidence_calibration_manifest"],
                trusted_diff=confidence_diff,
            )
            warning_gate = validation_warning_ux_core_accuracy_gates(
                warnings=validation_assessment["warnings"],
                warning_manifest=validation_assessment["validation_warning_checklist_manifest"],
                trusted_diff=warning_diff,
            )
            self.assertEqual(confidence_diff["status"], "pass")
            self.assertIn("parser_confidence_manifest_hash", confidence_diff["compared_fields"])
            self.assertIn("calibration_field_presence_hash", confidence_diff["compared_fields"])
            self.assertIn("trusted parser confidence calibration diff pass", confidence_gate[0]["satisfied_checks"])
            self.assertEqual(warning_diff["status"], "pass")
            self.assertIn("validation_warning_manifest_hash", warning_diff["compared_fields"])
            self.assertIn("warning_action_matrix_hash", warning_diff["compared_fields"])
            self.assertIn("trusted validation warning checklist diff pass", warning_gate[0]["satisfied_checks"])
            self.assertGreaterEqual(export["summary"]["validation_warning_count"], 0)
            self.assertTrue(all(item["legal_limitations"] for item in export["items"]))
            self.assertTrue(all("#93" in item["legal_limitations_assessment"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all(item["legal_limitations_assessment"]["core_accuracy_gates"][0]["gap_id"] == "#93" for item in export["items"]))
            self.assertTrue(all(item["legal_limitations_assessment"]["legal_limitation_manifest"]["profile_version"] == "legal-limitation-wording-manifest-v1" for item in export["items"]))
            self.assertTrue(all(len(item["legal_limitations_assessment"]["legal_limitation_manifest_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(len(item["legal_limitations_assessment"]["limitation_wording_matrix_hash"]) == 64 for item in export["items"]))
            self.assertTrue(all(isinstance(item["legal_limitations_assessment"]["limitation_details"], list) for item in export["items"]))
            self.assertTrue(all(isinstance(item["legal_limitations_assessment"]["limitation_category_counts"], dict) for item in export["items"]))
            self.assertTrue(all("legal limitation detail metadata emitted" in item["legal_limitations_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("legal limitation wording manifest hash emitted" in item["legal_limitations_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all("limitation wording matrix hash emitted" in item["legal_limitations_assessment"]["core_accuracy_gates"][0]["satisfied_checks"] for item in export["items"]))
            self.assertTrue(all(item["legal_limitations_assessment"]["trusted_legal_limitation_diff"]["status"] == "missing" for item in export["items"]))
            self.assertTrue(all("trusted-legal-limitation-wording-diff-missing" in item["legal_limitations_assessment"]["blockers"] for item in export["items"]))
            legal_assessment = export["items"][0]["legal_limitations_assessment"]
            legal_diff = build_legal_limitation_trusted_diff(legal_assessment, legal_assessment)
            legal_gate = legal_limitation_core_accuracy_gates(
                limitations=export["items"][0]["legal_limitations"],
                limitation_manifest=legal_assessment["legal_limitation_manifest"],
                trusted_diff=legal_diff,
            )
            self.assertEqual(legal_diff["status"], "pass")
            self.assertIn("legal_limitation_manifest_hash", legal_diff["compared_fields"])
            self.assertIn("limitation_wording_matrix_hash", legal_diff["compared_fields"])
            self.assertIn("trusted legal limitation wording diff pass", legal_gate[0]["satisfied_checks"])
            self.assertIn("#91", export["summary"]["parser_confidence_gap_ids"])
            self.assertIn("#92", export["summary"]["validation_warning_ux_gap_ids"])
            self.assertIn("#93", export["summary"]["legal_limitation_gap_ids"])
            self.assertIn("#94", export["summary"]["report_quality_gap_ids"])
            self.assertEqual(export["report_quality_matrix"]["profile_version"], "report-quality-matrix-v1")
            self.assertEqual(export["report_quality_matrix"]["item_numbers"], [91, 92, 93, 94])
            self.assertEqual(len(export["report_quality_matrix"]["matrix_hash"]), 64)
            self.assertEqual(export["summary"]["report_quality_matrix_hash"], export["report_quality_matrix"]["matrix_hash"])
            self.assertTrue(export["report_quality_matrix"]["all_item_manifests_present"])
            self.assertIn("acquisition_metadata", export)
            self.assertGreaterEqual(export["summary"]["acquisition_metadata_missing_count"], 1)
            self.assertIn("#96", export["summary"]["forensic_integrity_gap_ids"])
            self.assertIn("#96", export["summary"]["acquisition_metadata_gap_ids"])
            self.assertIn("#96", export["acquisition_metadata"]["commercial_gap_ids"])
            self.assertEqual(export["acquisition_metadata"]["functional_priority_profile"]["item_number"], 41)
            self.assertIn(
                "acquisition-required-fields-missing",
                export["acquisition_metadata"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertIn("#96", export["acquisition_metadata"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["acquisition_metadata"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#96")
            self.assertEqual(export["acquisition_metadata"]["trusted_acquisition_metadata_diff"]["status"], "missing")
            self.assertEqual(
                export["acquisition_metadata"]["acquisition_metadata_handoff_manifest"]["profile_version"],
                "acquisition-metadata-handoff-manifest-v1",
            )
            self.assertEqual(len(export["acquisition_metadata"]["acquisition_metadata_handoff_manifest_hash"]), 64)
            self.assertEqual(
                export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["profile_version"],
                "acquisition-metadata-input-manifest-v1",
            )
            self.assertEqual(len(export["acquisition_metadata"]["acquisition_metadata_input_manifest_hash"]), 64)
            self.assertFalse(export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["ready_for_submission"])
            self.assertIn(
                "write_blocker",
                export["acquisition_metadata"]["acquisition_metadata_input_manifest"]["missing_required_fields"],
            )
            self.assertTrue(
                all(
                    len(source["acquisition_evidence_source_row_hash"]) == 64
                    for source in export["acquisition_metadata"]["evidence_sources"]
                )
            )
            self.assertIn("trusted-acquisition-metadata-handoff-diff-missing", export["acquisition_metadata"]["blockers"])
            acquisition_diff = build_acquisition_metadata_trusted_diff(
                export["acquisition_metadata"],
                export["acquisition_metadata"],
            )
            acquisition_gates = acquisition_metadata_core_accuracy_gates(
                records=export["acquisition_metadata"]["records"],
                missing_required_fields=export["acquisition_metadata"]["missing_required_fields"],
                handoff_manifest=export["acquisition_metadata"]["acquisition_metadata_handoff_manifest"],
                input_manifest=export["acquisition_metadata"]["acquisition_metadata_input_manifest"],
                trusted_diff=acquisition_diff,
            )
            self.assertEqual(acquisition_diff["status"], "pass")
            self.assertIn("acquisition_metadata_handoff_manifest_hash", acquisition_diff["compared_fields"])
            self.assertIn("acquisition_field_completion_matrix_hash", acquisition_diff["compared_fields"])
            self.assertIn("acquisition field completion matrix hash emitted", acquisition_gates[0]["satisfied_checks"])
            self.assertIn("acquisition handoff manifest hash emitted", acquisition_gates[0]["satisfied_checks"])
            self.assertIn("acquisition metadata input manifest hash emitted", acquisition_gates[0]["satisfied_checks"])
            self.assertIn("trusted acquisition handoff diff pass", acquisition_gates[0]["satisfied_checks"])
            self.assertIn("timezone_validation", export)
            self.assertIn("#97", export["summary"]["timezone_validation_gap_ids"])
            self.assertIn("#97", export["timezone_validation"]["commercial_gap_ids"])
            self.assertEqual(export["timezone_validation"]["functional_priority_profile"]["item_number"], 42)
            self.assertIn(
                "trusted-timezone-normalization-matrix-diff-missing",
                export["timezone_validation"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertIn("#97", export["timezone_validation"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["timezone_validation"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#97")
            self.assertEqual(export["timezone_validation"]["trusted_timezone_validation_diff"]["status"], "missing")
            self.assertEqual(
                export["timezone_validation"]["timezone_normalization_manifest"]["profile_version"],
                "timezone-normalization-manifest-v1",
            )
            self.assertEqual(len(export["timezone_validation"]["timezone_normalization_manifest_hash"]), 64)
            self.assertEqual(len(export["timezone_validation"]["parser_assumption_matrix_hash"]), 64)
            self.assertEqual(
                export["timezone_validation"]["parser_assumption_matrix_hash"],
                export["timezone_validation"]["timezone_normalization_manifest"]["parser_assumption_matrix_hash"],
            )
            self.assertEqual(
                export["timezone_validation"]["time_semantics_manifest"]["profile_version"],
                "time-semantics-manifest-v1",
            )
            self.assertEqual(export["timezone_validation"]["time_semantics_manifest"]["item_number"], 42)
            self.assertEqual(export["timezone_validation"]["time_semantics_manifest"]["gap_id"], "#42")
            self.assertEqual(len(export["timezone_validation"]["time_semantics_manifest_hash"]), 64)
            self.assertEqual(
                export["timezone_validation"]["functional_priority_profile"]["implemented_controls"]["time_semantics_manifest_hash"],
                export["timezone_validation"]["time_semantics_manifest"]["manifest_hash"],
            )
            self.assertTrue(
                all("normalized_utc" in sample for sample in export["timezone_validation"]["samples"])
            )
            self.assertTrue(
                all(len(sample["timezone_sample_row_hash"]) == 64 for sample in export["timezone_validation"]["samples"])
            )
            self.assertIn("trusted-timezone-normalization-matrix-diff-missing", export["timezone_validation"]["blockers"])
            timezone_diff = build_timezone_validation_trusted_diff(export["timezone_validation"], export["timezone_validation"])
            timezone_gates = timezone_validation_core_accuracy_gates(
                event_count=export["timezone_validation"]["summary"]["event_count"],
                missing_timezone_count=export["timezone_validation"]["summary"]["missing_timezone_count"],
                samples=export["timezone_validation"]["samples"],
                timezone_manifest=export["timezone_validation"]["timezone_normalization_manifest"],
                time_semantics_manifest=export["timezone_validation"]["time_semantics_manifest"],
                trusted_diff=timezone_diff,
            )
            self.assertEqual(timezone_diff["status"], "pass")
            self.assertIn("timezone_normalization_manifest_hash", timezone_diff["compared_fields"])
            self.assertIn("parser_assumption_matrix_hash", timezone_diff["compared_fields"])
            self.assertIn("parser assumption matrix hash emitted", timezone_gates[0]["satisfied_checks"])
            self.assertIn("time_semantics_manifest_hash", timezone_diff["compared_fields"])
            self.assertIn("timezone normalization manifest hash emitted", timezone_gates[0]["satisfied_checks"])
            self.assertIn("time semantics manifest hash emitted", timezone_gates[0]["satisfied_checks"])
            self.assertIn("trusted timezone normalization matrix diff pass", timezone_gates[0]["satisfied_checks"])
            self.assertIn("clock_skew_analysis", export)
            self.assertIn("#98", export["summary"]["clock_skew_gap_ids"])
            self.assertIn("#98", export["clock_skew_analysis"]["commercial_gap_ids"])
            self.assertEqual(export["clock_skew_analysis"]["functional_priority_profile"]["item_number"], 42)
            self.assertIn(
                "trusted-clock-skew-baseline-diff-missing",
                export["clock_skew_analysis"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertIn("#98", export["clock_skew_analysis"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["clock_skew_analysis"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#98")
            self.assertEqual(export["clock_skew_analysis"]["trusted_clock_skew_diff"]["status"], "missing")
            self.assertEqual(
                export["clock_skew_analysis"]["clock_skew_baseline_manifest"]["profile_version"],
                "clock-skew-baseline-manifest-v1",
            )
            self.assertEqual(len(export["clock_skew_analysis"]["clock_skew_baseline_manifest_hash"]), 64)
            self.assertEqual(len(export["clock_skew_analysis"]["clock_skew_range_matrix_hash"]), 64)
            self.assertEqual(
                export["clock_skew_analysis"]["clock_skew_range_matrix_hash"],
                export["clock_skew_analysis"]["clock_skew_baseline_manifest"]["clock_skew_range_matrix_hash"],
            )
            self.assertIn("trusted-clock-skew-baseline-diff-missing", export["clock_skew_analysis"]["blockers"])
            clock_diff = build_clock_skew_trusted_diff(export["clock_skew_analysis"], export["clock_skew_analysis"])
            clock_gates = clock_skew_core_accuracy_gates(
                parsed_timestamp_count=export["clock_skew_analysis"]["summary"]["parsed_timestamp_count"],
                warnings=export["clock_skew_analysis"]["warnings"],
                earliest=export["clock_skew_analysis"]["summary"]["earliest_timestamp"],
                latest=export["clock_skew_analysis"]["summary"]["latest_timestamp"],
                clock_manifest=export["clock_skew_analysis"]["clock_skew_baseline_manifest"],
                trusted_diff=clock_diff,
            )
            self.assertEqual(clock_diff["status"], "pass")
            self.assertIn("clock_skew_baseline_manifest_hash", clock_diff["compared_fields"])
            self.assertIn("clock_skew_range_matrix_hash", clock_diff["compared_fields"])
            self.assertIn("clock skew range matrix hash emitted", clock_gates[0]["satisfied_checks"])
            self.assertIn("clock-skew baseline manifest hash emitted", clock_gates[0]["satisfied_checks"])
            self.assertIn("trusted clock-skew baseline diff pass", clock_gates[0]["satisfied_checks"])
            self.assertIn("contamination_warnings", export)
            self.assertIn("#99", export["summary"]["contamination_warning_gap_ids"])
            self.assertIn("#99", export["contamination_warnings"]["commercial_gap_ids"])
            self.assertEqual(export["contamination_warnings"]["functional_priority_profile"]["item_number"], 43)
            self.assertIn(
                "trusted-contamination-checklist-diff-missing",
                export["contamination_warnings"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertIn("#99", export["contamination_warnings"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["contamination_warnings"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#99")
            self.assertEqual(export["contamination_warnings"]["trusted_contamination_warning_diff"]["status"], "missing")
            self.assertEqual(
                export["contamination_warnings"]["contamination_checklist_manifest"]["profile_version"],
                "contamination-checklist-manifest-v1",
            )
            self.assertEqual(len(export["contamination_warnings"]["contamination_checklist_manifest_hash"]), 64)
            self.assertEqual(len(export["contamination_warnings"]["warning_review_matrix_hash"]), 64)
            self.assertEqual(
                export["contamination_warnings"]["warning_review_matrix_hash"],
                export["contamination_warnings"]["contamination_checklist_manifest"]["warning_review_matrix_hash"],
            )
            self.assertEqual(
                export["contamination_warnings"]["contamination_acquisition_context_manifest"]["profile_version"],
                "contamination-acquisition-context-manifest-v1",
            )
            self.assertEqual(export["contamination_warnings"]["contamination_acquisition_context_manifest"]["item_number"], 43)
            self.assertEqual(export["contamination_warnings"]["contamination_acquisition_context_manifest"]["gap_id"], "#43")
            self.assertEqual(len(export["contamination_warnings"]["contamination_acquisition_context_manifest_hash"]), 64)
            self.assertEqual(
                export["contamination_warnings"]["functional_priority_profile"]["implemented_controls"]["contamination_acquisition_context_manifest_hash"],
                export["contamination_warnings"]["contamination_acquisition_context_manifest"]["manifest_hash"],
            )
            self.assertIn("trusted-contamination-checklist-diff-missing", export["contamination_warnings"]["blockers"])
            contamination_diff = build_contamination_warning_trusted_diff(
                export["contamination_warnings"],
                export["contamination_warnings"],
            )
            contamination_gates = contamination_warning_core_accuracy_gates(
                warnings=export["contamination_warnings"]["warnings"],
                contamination_manifest=export["contamination_warnings"]["contamination_checklist_manifest"],
                acquisition_context_manifest=export["contamination_warnings"]["contamination_acquisition_context_manifest"],
                trusted_diff=contamination_diff,
            )
            self.assertEqual(contamination_diff["status"], "pass")
            self.assertIn("contamination_checklist_manifest_hash", contamination_diff["compared_fields"])
            self.assertIn("warning_review_matrix_hash", contamination_diff["compared_fields"])
            self.assertIn("contamination_acquisition_context_manifest_hash", contamination_diff["compared_fields"])
            self.assertIn("contamination checklist manifest hash emitted", contamination_gates[0]["satisfied_checks"])
            self.assertIn("contamination warning review matrix hash emitted", contamination_gates[0]["satisfied_checks"])
            self.assertIn("contamination acquisition context manifest hash emitted", contamination_gates[0]["satisfied_checks"])
            self.assertIn("trusted contamination checklist diff pass", contamination_gates[0]["satisfied_checks"])

            output_path = root / "case-db-report.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-db-report",
                        str(root / "case.db"),
                        "--case-id",
                        "CASE-75",
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(exit_code, 0)
            output_payload = json.loads(output_path.read_text(encoding="utf-8"))
            printed_payload = json.loads(stdout.getvalue())
            self.assertEqual(output_payload["summary"], printed_payload["summary"])
