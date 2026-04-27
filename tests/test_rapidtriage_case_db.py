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
    list_tables,
    open_case_database,
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
    "artifact",
    "artifact_fts",
    "event",
    "indexed_document",
    "indexed_document_fts",
    "review_mark",
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
        self.assertIn("case-search", commands)
        self.assertIn("--case-id", commands["case-search"].format_help())
        self.assertIn("--source", commands["case-search"].format_help())
        self.assertIn("--metadata", commands["case-search"].format_help())
        self.assertIn("--review-status", commands["case-search"].format_help())
        self.assertIn("--verification-status", commands["case-search"].format_help())
        self.assertIn("--save-as", commands["case-search"].format_help())
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

            with sqlite3.connect(db_path) as connection:
                connection.row_factory = sqlite3.Row
                self.assertTrue(REQUIRED_TABLES.issubset(set(list_tables(connection))))
                self.assertIn("hash_scope", table_columns(connection, "hash_record"))
                self.assertIn("verification_status", table_columns(connection, "review_mark"))
                self.assertIn("filters_json", table_columns(connection, "saved_search"))
                self.assertIn("citation_id", table_columns(connection, "audit_event"))

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
            with sqlite3.connect(db_path) as connection:
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

            with sqlite3.connect(db_path) as connection:
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
            self.assertGreaterEqual(reviewed["summary"]["match_count"], len(targets))
            self.assertTrue(all(match["review"]["status"] == "relevant" for match in reviewed["matches"]))

            export = database.export_reviewed_items(case_id="CASE-75")
            self.assertEqual(export["command"], "case-db-report-export")
            self.assertEqual(export["summary"]["exported_item_count"], len(targets))
            self.assertTrue(all(item["review"]["include_in_report"] for item in export["items"]))
            self.assertTrue(all(item["review_citation_id"].startswith("CASE-75-REV-") for item in export["items"]))
            self.assertTrue(all(item["target_citation_id"].startswith("CASE-75-") for item in export["items"]))
            self.assertTrue(all("source_reference" in item for item in export["items"]))

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
