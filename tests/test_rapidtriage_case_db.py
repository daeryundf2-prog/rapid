from __future__ import annotations

import sqlite3
import tempfile
import unittest
import contextlib
import io
import json
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.case_db import (
    SCHEMA_VERSION,
    CaseDatabase,
    CaseDatabaseError,
    acquisition_hash_core_accuracy_gates,
    build_acquisition_hash_trusted_diff,
    build_case_db_fts_trusted_diff,
    build_citation_manager_trusted_diff,
    build_custody_workflow_trusted_diff,
    build_evidence_history_trusted_diff,
    build_immutable_audit_trusted_diff,
    build_report_provenance_trusted_diff,
    build_report_reproducibility_trusted_diff,
    build_reviewer_workflow_trusted_diff,
    citation_manager_core_accuracy_gates,
    custody_workflow_core_accuracy_gates,
    evidence_selection_core_accuracy_gates,
    immutable_audit_core_accuracy_gates,
    list_tables,
    open_case_database,
    report_item_provenance_core_accuracy_gates,
    report_reproducibility_core_accuracy_gates,
    review_workflow_assessment,
    table_columns,
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
    "hash_record",
    "acquisition_metadata",
    "artifact",
    "artifact_fts",
    "event",
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
        self.assertIn("case-review", commands)
        self.assertIn("--include-in-report", commands["case-review"].format_help())
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
            self.assertEqual(second["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["gap_id"], "#74")
            self.assertIn("artifact_fts", second["large_sqlite_fts_optimization"]["fts_tables"])
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
            self.assertTrue(export["summary"]["review_assignment_enabled"])
            self.assertEqual(export["summary"]["exported_item_count"], len(targets))
            self.assertTrue(all(item["review"]["include_in_report"] for item in export["items"]))
            self.assertTrue(all(item["review_citation_id"].startswith("CASE-75-REV-") for item in export["items"]))
            self.assertTrue(all(item["target_citation_id"].startswith("CASE-75-") for item in export["items"]))
            self.assertTrue(all("source_reference" in item for item in export["items"]))
            self.assertGreaterEqual(export["summary"]["citation_count"], len(targets) * 2)
            self.assertTrue(export["citation_index"])
            self.assertIn("#64", export["citation_index"][0]["commercial_gap_ids"])
            self.assertIn("#64", export["report_citation_manager"]["commercial_gap_ids"])
            self.assertEqual(export["report_citation_manager"]["core_accuracy_gates"][0]["gap_id"], "#64")
            self.assertIn("citation count summary", export["report_citation_manager"]["core_accuracy_gates"][0]["satisfied_checks"])
            citation_uplift = export["report_citation_manager"]["commercial_uplift_evidence"]
            self.assertEqual(citation_uplift["batch_id"], "commercial-uplift-061-065")
            self.assertEqual(citation_uplift["item_numbers"], [64])
            self.assertIn("citation count summary", citation_uplift["passed_validation_check_ids"])
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
            )
            self.assertEqual(citation_diff["status"], "pass")
            self.assertIn("trusted citation index diff pass", citation_gates[0]["satisfied_checks"])
            self.assertGreaterEqual(len(export["items"][0]["review_history"]), 1)
            self.assertIn("#65", export["items"][0]["review_history"][0]["commercial_gap_ids"])
            self.assertEqual(export["items"][0]["review_history"][0]["core_accuracy_gates"][0]["gap_id"], "#65")
            self.assertIn("#65", export["evidence_selection_version_history"]["commercial_gap_ids"])
            self.assertEqual(export["evidence_selection_version_history"]["core_accuracy_gates"][0]["gap_id"], "#65")
            history_uplift = export["evidence_selection_version_history"]["commercial_uplift_evidence"]
            self.assertEqual(history_uplift["item_numbers"], [65])
            self.assertIn("versioned review history rows", history_uplift["passed_validation_check_ids"])
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
            history_gates = evidence_selection_core_accuracy_gates(history_rows=history_rows, trusted_diff=history_diff)
            self.assertEqual(history_diff["status"], "pass")
            self.assertIn("trusted evidence history diff pass", history_gates[0]["satisfied_checks"])
            self.assertIn("#65", export["items"][0]["commercial_gap_ids"])
            self.assertIn("custody_workflow", export)
            self.assertGreaterEqual(export["custody_workflow"]["summary"]["evidence_source_count"], 1)
            self.assertIn("#86", export["custody_workflow"]["commercial_gap_ids"])
            self.assertEqual(export["custody_workflow"]["core_accuracy_gates"][0]["gap_id"], "#86")
            self.assertIn("evidence source inventory", export["custody_workflow"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(export["custody_workflow"]["trusted_custody_diff"]["status"], "missing")
            self.assertIn("trusted-custody-event-manifest-diff-missing", export["custody_workflow"]["blockers"])
            custody_diff = build_custody_workflow_trusted_diff(export["custody_workflow"], export["custody_workflow"])
            custody_gates = custody_workflow_core_accuracy_gates(
                evidence_sources=export["custody_workflow"]["evidence_sources"],
                custody_events=export["custody_workflow"]["custody_events"],
                trusted_diff=custody_diff,
            )
            self.assertEqual(custody_diff["status"], "pass")
            self.assertIn("trusted custody event manifest diff pass", custody_gates[0]["satisfied_checks"])
            self.assertIn("acquisition_hash_workflow", export)
            self.assertIn("#87", export["acquisition_hash_workflow"]["commercial_gap_ids"])
            self.assertEqual(export["acquisition_hash_workflow"]["core_accuracy_gates"][0]["gap_id"], "#87")
            self.assertEqual(export["acquisition_hash_workflow"]["trusted_acquisition_hash_diff"]["status"], "missing")
            self.assertIn("trusted-acquisition-hash-manifest-diff-missing", export["acquisition_hash_workflow"]["blockers"])
            hash_diff = build_acquisition_hash_trusted_diff(
                export["acquisition_hash_workflow"],
                export["acquisition_hash_workflow"],
            )
            hash_gates = acquisition_hash_core_accuracy_gates(
                hashes=export["acquisition_hash_workflow"]["hashes"],
                trusted_diff=hash_diff,
            )
            self.assertEqual(hash_diff["status"], "pass")
            self.assertIn("trusted acquisition hash manifest diff pass", hash_gates[0]["satisfied_checks"])
            self.assertIn("audit_integrity", export)
            self.assertIn("#88", export["audit_integrity"]["commercial_gap_ids"])
            self.assertEqual(export["audit_integrity"]["core_accuracy_gates"][0]["gap_id"], "#88")
            self.assertGreaterEqual(export["audit_integrity"]["summary"]["event_count"], 1)
            self.assertTrue(export["audit_integrity"]["summary"]["head_hash"])
            self.assertEqual(export["audit_integrity"]["trusted_audit_integrity_diff"]["status"], "missing")
            self.assertIn("trusted-audit-hash-chain-manifest-diff-missing", export["audit_integrity"]["blockers"])
            audit_diff = build_immutable_audit_trusted_diff(export["audit_integrity"], export["audit_integrity"])
            audit_gates = immutable_audit_core_accuracy_gates(
                events=export["audit_integrity"]["events"],
                head_hash=export["audit_integrity"]["summary"]["head_hash"],
                trusted_diff=audit_diff,
            )
            self.assertEqual(audit_diff["status"], "pass")
            self.assertIn("trusted audit hash-chain manifest diff pass", audit_gates[0]["satisfied_checks"])
            self.assertIn("reproducibility", export)
            self.assertIn("#89", export["reproducibility"]["commercial_gap_ids"])
            self.assertEqual(export["reproducibility"]["core_accuracy_gates"][0]["gap_id"], "#89")
            self.assertTrue(export["reproducibility"]["stable_payload_sha256"])
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
                trusted_diff=reproducibility_diff,
            )
            self.assertEqual(reproducibility_diff["status"], "pass")
            self.assertIn("trusted report replay manifest diff pass", reproducibility_gates[0]["satisfied_checks"])
            self.assertTrue(all("provenance" in item for item in export["items"]))
            self.assertTrue(all("#90" in item["provenance"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all(item["provenance"]["core_accuracy_gates"][0]["gap_id"] == "#90" for item in export["items"]))
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
                trusted_diff=provenance_diff,
            )
            self.assertEqual(provenance_diff["status"], "pass")
            self.assertIn("trusted report provenance manifest diff pass", provenance_gate[0]["satisfied_checks"])
            self.assertTrue(all("validation_assessment" in item for item in export["items"]))
            self.assertTrue(all("#91" in item["validation_assessment"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all("#92" in item["validation_assessment"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["core_accuracy_gates"][0]["gap_id"] == "#91" for item in export["items"]))
            self.assertTrue(all(item["validation_assessment"]["core_accuracy_gates"][1]["gap_id"] == "#92" for item in export["items"]))
            self.assertGreaterEqual(export["summary"]["validation_warning_count"], 0)
            self.assertTrue(all(item["legal_limitations"] for item in export["items"]))
            self.assertTrue(all("#93" in item["legal_limitations_assessment"]["commercial_gap_ids"] for item in export["items"]))
            self.assertTrue(all(item["legal_limitations_assessment"]["core_accuracy_gates"][0]["gap_id"] == "#93" for item in export["items"]))
            self.assertIn("#91", export["summary"]["parser_confidence_gap_ids"])
            self.assertIn("#92", export["summary"]["validation_warning_ux_gap_ids"])
            self.assertIn("#93", export["summary"]["legal_limitation_gap_ids"])
            self.assertIn("acquisition_metadata", export)
            self.assertGreaterEqual(export["summary"]["acquisition_metadata_missing_count"], 1)
            self.assertIn("#96", export["summary"]["forensic_integrity_gap_ids"])
            self.assertIn("#96", export["summary"]["acquisition_metadata_gap_ids"])
            self.assertIn("#96", export["acquisition_metadata"]["commercial_gap_ids"])
            self.assertIn("#96", export["acquisition_metadata"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["acquisition_metadata"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#96")
            self.assertIn("timezone_validation", export)
            self.assertIn("#97", export["summary"]["timezone_validation_gap_ids"])
            self.assertIn("#97", export["timezone_validation"]["commercial_gap_ids"])
            self.assertIn("#97", export["timezone_validation"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["timezone_validation"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#97")
            self.assertIn("clock_skew_analysis", export)
            self.assertIn("#98", export["summary"]["clock_skew_gap_ids"])
            self.assertIn("#98", export["clock_skew_analysis"]["commercial_gap_ids"])
            self.assertIn("#98", export["clock_skew_analysis"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["clock_skew_analysis"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#98")
            self.assertIn("contamination_warnings", export)
            self.assertIn("#99", export["summary"]["contamination_warning_gap_ids"])
            self.assertIn("#99", export["contamination_warnings"]["commercial_gap_ids"])
            self.assertIn("#99", export["contamination_warnings"]["validation_assessment"]["commercial_gap_ids"])
            self.assertEqual(export["contamination_warnings"]["validation_assessment"]["core_accuracy_gates"][0]["gap_id"], "#99")

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
