from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.cli import build_parser, main, run_web_server
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import run_sample_workflow


class RapidTriageOpsTests(unittest.TestCase):
    def test_parser_exposes_benchmark_and_case_catalog(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("benchmark", commands)
        self.assertIn("--file-count", commands["benchmark"].format_help())
        self.assertIn("case-catalog", commands)
        self.assertIn("--add-run", commands["case-catalog"].format_help())
        self.assertIn("validation", commands)
        self.assertIn("--output-dir", commands["validation"].format_help())

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
            self.assertEqual(payload["support_sla_template"]["status"], "operator-owned-template")
            command_names = {item["name"] for item in payload["recommended_commands"]}
            self.assertIn("validation-package", command_names)
            self.assertIn("windows-signature-verify", command_names)
            self.assertIn("windows-smoke-test", command_names)
            self.assertIn("macos-linux-smoke-test", command_names)
            self.assertIn("release-checksums", command_names)
            self.assertIn("verify-release-checksums", command_names)
            self.assertIn("smoke-summary", command_names)

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
            with zipfile.ZipFile(output_dir / "rapidtriage-portable.zip") as archive:
                names = set(archive.namelist())
            self.assertIn("scripts/start-rapidtriage.sh", names)
            self.assertIn("scripts/smoke-test-rapidtriage.sh", names)
            self.assertIn("scripts/summarize-smoke.py", names)
            self.assertIn("scripts/windows/start-rapidtriage.ps1", names)
            self.assertIn("scripts/windows/smoke-test-rapidtriage.ps1", names)
            self.assertIn("scripts/windows/smoke-test-rapidtriage.bat", names)
            self.assertIn("docs/rapidtriage-macos-linux-quickstart.md", names)
            self.assertIn("docs/rapidtriage-fresh-machine-smoke-test.md", names)
            checksums = (output_dir / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("rapidtriage-portable.zip", checksums)
            self.assertIn("dependency-inventory.txt", checksums)
            self.assertIn("release-manifest.json", checksums)
            manifest = json.loads((output_dir / "release-manifest.json").read_text(encoding="utf-8"))
            artifact_names = {item["name"] for item in manifest["artifacts"]}
            self.assertIn("rapidtriage-portable.zip", artifact_names)

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
            self.assertTrue((smoke_dir / "smoke-summary.md").is_file())


if __name__ == "__main__":
    unittest.main()
