from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.cli import build_parser, main, run_web_server
from rapidtriage.core.crash import write_crash_report
from rapidtriage.core.jobs import RunJobStore, RunRequest
from rapidtriage.core.sample_case import run_sample_workflow


class RapidTriageOpsTests(unittest.TestCase):
    def test_parser_exposes_benchmark_and_case_catalog(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("benchmark", commands)
        self.assertIn("--file-count", commands["benchmark"].format_help())
        self.assertIn("--resume", commands["benchmark"].format_help())
        self.assertIn("stress-plan", commands)
        self.assertIn("case-catalog", commands)
        self.assertIn("--add-run", commands["case-catalog"].format_help())
        self.assertIn("validation", commands)
        self.assertIn("--output-dir", commands["validation"].format_help())
        self.assertIn("commercial-readiness", commands)
        self.assertIn("--strict", commands["commercial-readiness"].format_help())
        self.assertIn("cross-tool-validate", commands)
        self.assertIn("--reference-output", commands["cross-tool-validate"].format_help())
        self.assertIn("confidence-dashboard", commands)
        self.assertIn("parser-explainability", commands)
        self.assertIn("reproducibility-kit", commands)
        self.assertIn("enterprise-policy", commands)
        self.assertIn("case-backup", commands)
        self.assertIn("case-restore", commands)
        self.assertIn("case-acquisition", commands)

    def test_enterprise_policy_is_local_only_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            license_path = Path(tmp_dir) / "license.txt"
            license_path.write_text("offline license", encoding="utf-8")
            stdout = io.StringIO()
            with patch.dict(
                "os.environ",
                {"RAPIDTRIAGE_LICENSE_FILE": str(license_path), "RAPIDTRIAGE_USER_ROLE": "viewer"},
                clear=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["enterprise-policy", "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertFalse(payload["telemetry"]["enabled"])
        self.assertFalse(payload["license_activation"]["required"])
        self.assertEqual(payload["license_activation"]["status"], "operator-provided-file")
        self.assertEqual(len(payload["license_activation"]["license_sha256"]), 64)
        self.assertFalse(payload["license_activation"]["network_activation"])
        self.assertEqual(payload["rbac"]["active_role"], "viewer")
        self.assertTrue(payload["rbac"]["active_role_supported"])
        self.assertNotIn("backup_restore", payload["rbac"]["active_permissions"])
        self.assertTrue(payload["multi_user_case_server"]["required_before_enablement"])
        self.assertEqual(payload["collaboration_audit_trail"]["status"], "case-db-audit-events-with-export-hash-chain")
        self.assertEqual(payload["multi_user_case_server"]["status"], "not-enabled")

    def test_benchmark_command_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "bench"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(output_dir),
                        "--file-count",
                        "12",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "benchmark")
            self.assertTrue((output_dir / "rapidtriage-benchmark.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-benchmark.md").is_file())
            self.assertGreaterEqual(payload["metrics"]["ingest_seconds"], 0)
            self.assertIn("search_p50_seconds", payload["metrics"])

    def test_stress_plan_command_writes_large_case_runbook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "stress"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "stress-plan",
                        "--output-dir",
                        str(output_dir),
                        "--size-tb",
                        "1",
                        "--size-tb",
                        "10",
                        "--expected-throughput-mb-s",
                        "100",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "stress-plan")
            self.assertEqual(payload["summary"]["scenario_count"], 2)
            self.assertTrue(payload["summary"]["requires_real_validation"])
            self.assertTrue((output_dir / "rapidtriage-stress-plan.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-stress-plan.md").is_file())
            self.assertEqual(payload["scenarios"][1]["size_tb"], 10)
            self.assertIn("parser_crash_rate_percent", payload["failure_thresholds"])

    def test_validation_command_writes_release_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "validation"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "validation",
                        "--output-dir",
                        str(output_dir),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "validation")
            self.assertEqual(payload["score_target"], 100)
            self.assertTrue((output_dir / "rapidtriage-validation-package.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-validation-report.md").is_file())
            check_ids = {item["id"] for item in payload["checks"]}
            self.assertIn("unit-tests", check_ids)
            self.assertIn("known-limitations", check_ids)
            self.assertIn("windows-code-signing", check_ids)
            self.assertIn("macos-notarization", check_ids)
            release_ids = {item["id"] for item in payload["release_artifact_requirements"]}
            self.assertIn("windows-installer", release_ids)
            self.assertIn("macos-app-or-package", release_ids)
            validation_ids = {item["id"] for item in payload["independent_validation_plan"]}
            self.assertIn("parser-corpus", validation_ids)
            self.assertEqual(payload["support_sla_template"]["status"], "documented-template")
            self.assertEqual(payload["commercial_readiness_gate"]["status"], "commercial-gaps-present")
            self.assertFalse(payload["commercial_readiness_gate"]["commercial_claim_allowed"])
            self.assertGreater(payload["commercial_readiness_gate"]["non_commercial_count"], 0)
            self.assertEqual(payload["support_sla_template"]["document"], "docs/rapidtriage-support-sla.md")
            self.assertEqual(payload["support_sla_template"]["severity_levels"][0]["patch_target"], "emergency hotfix or validated workaround")
            required_docs = {item["path"] for item in payload["required_documents"]}
            self.assertIn("docs/rapidtriage-support-sla.md", required_docs)
            command_names = {item["name"] for item in payload["recommended_commands"]}
            self.assertIn("validation-package", command_names)
            self.assertIn("windows-signature-verify", command_names)
            self.assertIn("windows-smoke-test", command_names)
            self.assertIn("macos-linux-smoke-test", command_names)
            self.assertIn("release-checksums", command_names)
            self.assertIn("verify-release-checksums", command_names)
            self.assertIn("smoke-summary", command_names)
            self.assertIn("release-evidence", command_names)

    def test_commercial_readiness_command_lists_non_commercial_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["commercial-readiness", "--output-dir", tmp_dir, "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "commercial-readiness")
            self.assertEqual(payload["item_count"], 120)
            self.assertEqual(payload["status"], "commercial-gaps-present")
            self.assertFalse(payload["commercial_claim_allowed"])
            self.assertGreater(payload["non_commercial_count"], 0)
            self.assertTrue((Path(tmp_dir) / "rapidtriage-commercial-readiness.json").is_file())
            self.assertTrue((Path(tmp_dir) / "rapidtriage-commercial-readiness.md").is_file())
            critical_numbers = {item["number"] for item in payload["critical_non_commercial_items"]}
            self.assertIn(1, critical_numbers)
            self.assertIn(25, critical_numbers)

    def test_cross_tool_validate_compares_rapid_and_reference_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid.json"
            reference = root / "evtxecmd.csv"
            output = root / "cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {"details": {"event_record_id": 1001}, "path": "Security.evtx"},
                            {"details": {"event_record_id": 1002}, "path": "Security.evtx"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text("EventRecordID,Provider\n1001,Security\n1003,Security\n", encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"evtxecmd={reference}",
                        "--min-overlap",
                        "0.9",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "cross-tool-validate")
            self.assertEqual(payload["status"], "failed")
            self.assertTrue(output.is_file())
            comparison = payload["comparisons"][0]
            self.assertEqual(comparison["reference_name"], "evtxecmd")
            self.assertLess(comparison["overlap_ratio"], 0.9)
            self.assertIn("1003", comparison["missing_in_rapid_sample"])

    def test_confidence_explainability_and_reproducibility_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            artifacts = root / "artifacts.json"
            summary = root / "rapidtriage-run-summary.json"
            dashboard = root / "confidence.json"
            explain_json = root / "explain.json"
            explain_md = root / "explain.md"
            repro_dir = root / "repro"
            artifacts.write_text(
                json.dumps(
                    {
                        "command": "artifacts",
                        "artifacts": [
                            {
                                "provider": "eventlog",
                                "artifact_type": "eventlog-record",
                                "path": "/case/Security.evtx",
                                "details": {
                                    "parser": "eventlog",
                                    "parser_version": "test",
                                    "source_path": "/case/Security.evtx",
                                    "parser_confidence": 0.92,
                                    "reportability": "report-grade",
                                    "validation_required": False,
                                    "commercial_grade_ready": True,
                                    "record_offset": 128,
                                    "hashes": {"sha256": "a" * 64},
                                },
                            },
                            {
                                "provider": "eventlog",
                                "artifact_type": "eventlog-record-candidate",
                                "path": "/case/Security.evtx",
                                "details": {
                                    "parser": "eventlog",
                                    "source_path": "/case/Security.evtx",
                                    "parser_confidence": 0.4,
                                    "validation_required": True,
                                    "commercial_grade_ready": False,
                                },
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            summary.write_text(
                json.dumps(
                    {
                        "command": "run",
                        "generated_at": "2026-04-29T00:00:00+00:00",
                        "outputs": {
                            "summary": str(summary),
                            "artifacts_eventlog": str(artifacts),
                        },
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                dashboard_exit = main(["confidence-dashboard", str(summary), "--output", str(dashboard), "--json"])
            with contextlib.redirect_stdout(io.StringIO()):
                explain_exit = main(
                    [
                        "parser-explainability",
                        str(summary),
                        "--output",
                        str(explain_json),
                        "--markdown-output",
                        str(explain_md),
                    ]
                )
                repro_exit = main(
                    [
                        "reproducibility-kit",
                        "--baseline-run",
                        str(summary),
                        "--candidate-run",
                        str(summary),
                        "--output-dir",
                        str(repro_dir),
                    ]
                )

            self.assertEqual(dashboard_exit, 0)
            self.assertEqual(explain_exit, 0)
            self.assertEqual(repro_exit, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["summary"]["confidence_counts"]["report-grade"], 1)
            self.assertEqual(payload["summary"]["confidence_counts"]["needs-validation"], 1)
            self.assertTrue(dashboard.is_file())
            explain = json.loads(explain_json.read_text(encoding="utf-8"))
            self.assertEqual(explain["summary"]["entry_count"], 2)
            self.assertTrue(explain_md.is_file())
            repro = json.loads((repro_dir / "rapidtriage-reproducibility-kit.json").read_text(encoding="utf-8"))
            self.assertEqual(repro["status"], "reproducible")
            self.assertEqual(repro["summary"]["diff_count"], 0)

    def test_case_catalog_adds_exports_and_imports_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            catalog_path = root / "catalog.json"
            archive_path = root / "CASE-CATALOG.zip"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                add_exit = main(
                    [
                        "case-catalog",
                        "--catalog",
                        str(catalog_path),
                        "--add-run",
                        str(sample["run"]["output_dir"]),
                        "--case-id",
                        "CASE-CATALOG",
                        "--name",
                        "Catalog Case",
                        "--list",
                        "--json",
                    ]
                )
            with contextlib.redirect_stdout(io.StringIO()):
                export_exit = main(
                    [
                        "case-catalog",
                        "--catalog",
                        str(catalog_path),
                        "--export",
                        "CASE-CATALOG",
                        "--archive",
                        str(archive_path),
                    ]
                )
            imported_catalog_path = root / "imported-catalog.json"
            with contextlib.redirect_stdout(io.StringIO()):
                import_exit = main(
                    [
                        "case-catalog",
                        "--catalog",
                        str(imported_catalog_path),
                        "--import",
                        str(archive_path),
                    ]
                )

            self.assertEqual(add_exit, 0)
            self.assertEqual(export_exit, 0)
            self.assertEqual(import_exit, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["cases"][0]["case_id"], "CASE-CATALOG")
            self.assertEqual(payload["cases"][0]["runs"][0]["mode"], "fraud")
            self.assertTrue(archive_path.is_file())
            imported = json.loads(imported_catalog_path.read_text(encoding="utf-8"))
            self.assertEqual(imported["cases"][0]["case_id"], "CASE-CATALOG")

    def test_api_auth_token_protects_api_routes(self) -> None:
        client = TestClient(create_app(RunJobStore(), auth_token="secret"))

        self.assertEqual(client.get("/api/health").status_code, 401)
        self.assertEqual(client.get("/api/health", headers={"X-RapidTriage-Token": "secret"}).status_code, 200)
        self.assertEqual(client.get("/").status_code, 200)

    def test_non_localhost_web_binding_requires_auth_or_explicit_override(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "non-localhost"):
            run_web_server("0.0.0.0", 8765)

    def test_run_jobs_include_step_status_for_recovery_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "missing"
            output_dir = Path(tmp_dir) / "run-out"
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "not-a-mode",
                    "output_dir": str(output_dir),
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 202)
            payload = response.json()
            self.assertEqual(payload["status"], "failed")
            step_statuses = {step["name"]: step["status"] for step in payload["steps"]}
            self.assertEqual(step_statuses["prepare"], "completed")
            self.assertEqual(step_statuses["triage"], "failed")
            self.assertEqual(step_statuses["finalize"], "skipped")

    def test_run_job_store_can_cancel_queued_and_retry_failed_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = RunJobStore(max_workers=1, state_path=Path(tmp_dir) / "runs.json")
            failed = store.run_sync(
                RunRequest(
                    root=str(Path(tmp_dir) / "missing"),
                    mode="not-a-mode",
                    output_dir=str(Path(tmp_dir) / "run-out"),
                )
            )

            retry = store.retry(failed.run_id)
            canceled = store.cancel(retry.run_id)

            self.assertEqual(failed.status, "failed")
            self.assertIn(canceled.status, {"queued", "running", "canceled", "failed"})
            self.assertTrue(canceled.cancellation_requested)
            store._executor.shutdown(wait=True)

    def test_build_release_script_can_assemble_portable_zip_without_building_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "release"
            result = subprocess.run(
                [
                    "python",
                    "scripts/build-release.py",
                    "--output-dir",
                    str(output_dir),
                    "--skip-build",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output_dir / "rapidtriage-portable.zip").is_file())
            self.assertTrue((output_dir / "SHA256SUMS").is_file())
            self.assertTrue((output_dir / "dependency-inventory.txt").is_file())
            self.assertTrue((output_dir / "release-manifest.json").is_file())
            self.assertTrue((output_dir / "update-manifest.json").is_file())
            self.assertTrue((output_dir / "packaging-plan.json").is_file())
            self.assertTrue((output_dir / "packaging-plan.md").is_file())
            self.assertTrue((output_dir / "rapidtriage-commercial-readiness.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-commercial-readiness.md").is_file())
            with zipfile.ZipFile(output_dir / "rapidtriage-portable.zip") as archive:
                names = set(archive.namelist())
            self.assertIn("scripts/start-rapidtriage.sh", names)
            self.assertIn("scripts/smoke-test-rapidtriage.sh", names)
            self.assertIn("scripts/summarize-smoke.py", names)
            self.assertIn("scripts/verify-release-evidence.py", names)
            self.assertIn("scripts/check-dependencies.py", names)
            self.assertIn("scripts/windows/start-rapidtriage.ps1", names)
            self.assertIn("scripts/windows/smoke-test-rapidtriage.ps1", names)
            self.assertIn("scripts/windows/smoke-test-rapidtriage.bat", names)
            self.assertIn("docs/rapidtriage-macos-linux-quickstart.md", names)
            self.assertIn("docs/rapidtriage-fresh-machine-smoke-test.md", names)
            self.assertIn("docs/rapidtriage-support-sla.md", names)
            self.assertIn("docs/rapidtriage-commercial-parity-backlog.md", names)
            checksums = (output_dir / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("rapidtriage-portable.zip", checksums)
            self.assertIn("dependency-inventory.txt", checksums)
            self.assertIn("release-manifest.json", checksums)
            self.assertIn("update-manifest.json", checksums)
            self.assertIn("packaging-plan.json", checksums)
            self.assertIn("rapidtriage-commercial-readiness.json", checksums)
            manifest = json.loads((output_dir / "release-manifest.json").read_text(encoding="utf-8"))
            artifact_names = {item["name"] for item in manifest["artifacts"]}
            self.assertIn("rapidtriage-portable.zip", artifact_names)
            self.assertEqual(manifest["commercial_readiness"]["status"], "commercial-gaps-present")
            self.assertFalse(manifest["commercial_readiness"]["commercial_claim_allowed"])
            self.assertEqual(manifest["package_readiness"]["linux_package"]["status"], "packaging-plan-ready")
            self.assertEqual(manifest["package_readiness"]["auto_update_channel"]["status"], "manifest-generated")
            update_manifest = json.loads((output_dir / "update-manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(update_manifest["auto_update_enabled_by_default"])
            packaging_plan = json.loads((output_dir / "packaging-plan.json").read_text(encoding="utf-8"))
            self.assertEqual(packaging_plan["platform_packages"]["windows"]["current_status"], "external-signing-required")
            self.assertIn("AppImage", packaging_plan["platform_packages"]["linux"]["target_outputs"])

            verify = subprocess.run(
                [
                    "python",
                    "scripts/build-release.py",
                    "--output-dir",
                    str(output_dir),
                    "--verify",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_crash_report_is_local_and_redacts_sensitive_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            report = write_crash_report(
                RuntimeError("boom"),
                context={"path": "/case/source", "auth_token": "secret-value"},
                output_dir=Path(tmp_dir),
            )

            payload = json.loads(Path(report["path"]).read_text(encoding="utf-8"))
            self.assertTrue(payload["local_only"])
            self.assertEqual(payload["context"]["auth_token"], "<redacted>")
            self.assertEqual(payload["exception"]["type"], "RuntimeError")

    def test_case_backup_and_restore_commands_copy_database_with_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            db_path = root / "case.db"
            self.assertEqual(main(["case-db", str(db_path), "--create-case", "CASE-BACKUP", "--json"]), 0)
            backup_dir = root / "backup"
            restored = root / "restored.db"

            backup_stdout = io.StringIO()
            with contextlib.redirect_stdout(backup_stdout):
                backup_exit = main(["case-backup", str(db_path), "--output-dir", str(backup_dir), "--json"])
            self.assertEqual(backup_exit, 0)
            backup_payload = json.loads(backup_stdout.getvalue())
            self.assertEqual(backup_payload["command"], "case-backup")
            self.assertTrue((backup_dir / "rapidtriage-case-backup-manifest.json").is_file())
            self.assertEqual(backup_payload["schema"]["current_schema_version"], 1)
            self.assertEqual(backup_payload["migration_readiness"]["status"], "ready")
            self.assertTrue(backup_payload["migration_readiness"]["restore_rehearsal_required"])

            restore_stdout = io.StringIO()
            with contextlib.redirect_stdout(restore_stdout):
                restore_exit = main(
                    [
                        "case-restore",
                        str(backup_dir / "rapidtriage-case-backup-manifest.json"),
                        "--output",
                        str(restored),
                        "--json",
                    ]
                )
            self.assertEqual(restore_exit, 0)
            restore_payload = json.loads(restore_stdout.getvalue())
            self.assertTrue(restore_payload["hash_verified"])
            self.assertEqual(restore_payload["schema"]["current_schema_version"], 1)
            self.assertEqual(restore_payload["migration_readiness"]["expected_schema_version"], 1)
            self.assertTrue(restored.is_file())

    def test_case_acquisition_command_records_and_lists_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            self.assertEqual(main(["case-db", str(db_path), "--create-case", "CASE-ACQ", "--json"]), 0)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-acquisition",
                        str(db_path),
                        "--case-id",
                        "CASE-ACQ",
                        "--operator",
                        "Analyst One",
                        "--started-at",
                        "2026-04-28T09:00:00+09:00",
                        "--completed-at",
                        "2026-04-28T10:00:00+09:00",
                        "--source-identifier",
                        "Disk SN ABC123",
                        "--write-blocker",
                        "Tableau TX1 SN WB-01 verified read-only",
                        "--tool",
                        "RapidTriage",
                        "--tool-version",
                        "dev",
                        "--whole-source-sha256",
                        "a" * 64,
                        "--notes",
                        "Lab acquisition metadata",
                        "--json",
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["record"]["citation_id"].startswith("CASE-ACQ-ACQ-"))

            list_stdout = io.StringIO()
            with contextlib.redirect_stdout(list_stdout):
                list_exit = main(["case-acquisition", str(db_path), "--case-id", "CASE-ACQ", "--list", "--json"])
            self.assertEqual(list_exit, 0)
            listed = json.loads(list_stdout.getvalue())
            self.assertEqual(listed["record_count"], 1)
            self.assertEqual(listed["records"][0]["source_identifier"], "Disk SN ABC123")

    def test_smoke_summary_script_reports_pass_for_valid_smoke_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            smoke_dir = Path(tmp_dir) / "smoke"
            smoke_dir.mkdir()
            (smoke_dir / "doctor.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
            (smoke_dir / "sample.json").write_text(
                json.dumps({"run": {"output_dir": str(smoke_dir / "sample" / "run-output")}}),
                encoding="utf-8",
            )
            (smoke_dir / "sample-search.json").write_text(json.dumps({"match_count": 1}), encoding="utf-8")
            (smoke_dir / "benchmark.json").write_text(json.dumps({"metrics": {"ingest_seconds": 0.1}}), encoding="utf-8")
            (smoke_dir / "validation.json").write_text(
                json.dumps({"status": "release-validation-package-ready"}),
                encoding="utf-8",
            )
            (smoke_dir / "evidence-vhdx.json").write_text(
                json.dumps({"adapter": "virtual-disk", "message": "mount/export first"}),
                encoding="utf-8",
            )
            (smoke_dir / "web-index.html").write_text("<!doctype html>", encoding="utf-8")

            result = subprocess.run(
                ["python", "scripts/summarize-smoke.py", str(smoke_dir)],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((smoke_dir / "smoke-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["passed"])
            self.assertIn(summary["platform"], {"macos-linux", "windows"})
            self.assertTrue((smoke_dir / "smoke-summary.md").is_file())

    def test_release_evidence_script_reports_pass_for_complete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            smoke_dir = root / "smoke-windows"
            evidence_dir = root / "release-evidence"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)

            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)

            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(json.dumps({"passed": True, "checks": []}), encoding="utf-8")
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["release_gate"], "pass")
            self.assertEqual(report["inputs"]["required_smoke_platforms"], ["windows"])
            self.assertEqual(report["summary"]["fail"], 0)
            check_ids = {item["id"] for item in report["checks"]}
            self.assertIn("smoke-platform-windows", check_ids)
            self.assertTrue((evidence_dir / "release-evidence-report.md").is_file())

    def test_release_evidence_script_reports_missing_required_smoke_platform(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            smoke_dir = root / "smoke-windows"
            evidence_dir = root / "release-evidence"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)

            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)

            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(
                json.dumps({"passed": True, "platform": "windows", "checks": []}),
                encoding="utf-8",
            )
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--require-smoke-platform",
                    "macos-linux",
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            self.assertFalse(report["passed"])
            self.assertEqual(report["release_gate"], "fail")
            failed = {item["id"]: item for item in report["checks"] if item["status"] == "fail"}
            self.assertIn("smoke-platform-macos-linux", failed)
            self.assertTrue(any("macos-linux" in action for action in report["next_actions"]))


if __name__ == "__main__":
    unittest.main()
