from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

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
from rapidtriage.cli import build_parser, main
from rapidtriage.core.doctor import OK, WARN, format_doctor_text, run_doctor
from rapidtriage.core.jobs import RunJobStore

TEST_API_TOKEN = "rapidtriage-test-token"


def make_static_assets(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text("<html>rapidtriage</html>", encoding="utf-8")
    (root / "app_workbench_config.js").write_text("const WORKBENCH_SMOKE_CHECKPOINTS = [];\n", encoding="utf-8")
    (root / "app_state.js").write_text("function storageAvailable() { return false; }\n", encoding="utf-8")
    (root / "app.js").write_text("console.log('rapidtriage');\n", encoding="utf-8")
    (root / "styles.css").write_text("body {}\n", encoding="utf-8")


class RapidTriageDoctorTests(unittest.TestCase):
    def test_parser_exposes_doctor_subcommand(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("doctor", commands)
        self.assertIn("rapidtriage doctor --json", commands["doctor"].format_help())
        self.assertIn("rapidtriage doctor --json", parser.format_help())

    def test_run_doctor_reports_optional_tool_warnings_without_failing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            static_dir = Path(tmp_dir) / "static"
            app_data_dir = Path(tmp_dir) / "app-data"
            make_static_assets(static_dir)

            payload = run_doctor(
                static_dir=static_dir,
                app_data_dir=app_data_dir,
                tool_resolver=lambda _name: None,
                include_port_check=False,
            )

        checks = {check["name"]: check for check in payload["checks"]}
        self.assertEqual(payload["status"], WARN)
        self.assertEqual(checks["python-version"]["status"], OK)
        self.assertEqual(checks["web-static-assets"]["status"], OK)
        self.assertEqual(checks["app-data-dir"]["status"], OK)
        self.assertEqual(checks["tool:tesseract"]["status"], WARN)
        self.assertEqual(checks["tools:e01"]["status"], WARN)
        self.assertIn("OCR will be disabled", checks["tool:tesseract"]["summary"])
        # r2 M2: PST/OST normalisation needs pffexport or readpst.
        self.assertEqual(checks["tools:email-pst"]["status"], WARN)
        self.assertIn("pffexport", checks["tools:email-pst"]["summary"])

    def test_doctor_reports_email_pst_tool_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            static_dir = Path(tmp_dir) / "static"
            make_static_assets(static_dir)
            payload = run_doctor(
                static_dir=static_dir,
                app_data_dir=Path(tmp_dir) / "app-data",
                tool_resolver=lambda name: "/usr/bin/readpst" if name == "readpst" else None,
                include_port_check=False,
            )

        check = next(check for check in payload["checks"] if check["name"] == "tools:email-pst")
        self.assertEqual(check["status"], OK)
        self.assertEqual(check["details"]["available"], ["readpst"])
        # Runs only use the tool when the opt-in env var is set.
        self.assertIn("RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1", check["summary"])

    def test_doctor_email_pst_warn_remediation_is_korean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            static_dir = Path(tmp_dir) / "static"
            make_static_assets(static_dir)
            payload = run_doctor(
                static_dir=static_dir,
                app_data_dir=Path(tmp_dir) / "app-data",
                tool_resolver=lambda _name: None,
                include_port_check=False,
            )

        check = next(check for check in payload["checks"] if check["name"] == "tools:email-pst")
        self.assertEqual(check["status"], WARN)
        remediation = check["remediation"]
        self.assertTrue(any("가" <= char <= "힣" for char in remediation))
        self.assertIn("pffexport", remediation)
        self.assertIn("readpst", remediation)
        self.assertIn("RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1", remediation)

    def test_doctor_text_output_is_human_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            static_dir = Path(tmp_dir) / "static"
            make_static_assets(static_dir)
            payload = run_doctor(
                static_dir=static_dir,
                app_data_dir=Path(tmp_dir) / "app-data",
                tool_resolver=lambda _name: None,
                include_port_check=False,
            )

        text = format_doctor_text(payload)
        self.assertIn("rapidtriage doctor", text)
        self.assertIn("Status: warn", text)
        self.assertIn("tool:tesseract", text)

    def test_cli_doctor_json_outputs_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["doctor", "--json", "--app-data-dir", str(Path(tmp_dir) / "app-data")])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["command"], "doctor")
        self.assertIn(payload["status"], {OK, WARN})
        self.assertIn("checks", payload)

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage doctor API tests")
    def test_api_exposes_doctor_without_port_self_check(self) -> None:
        client = TestClient(
            create_app(RunJobStore(), auth_token=TEST_API_TOKEN),
            headers={"X-RapidTriage-Token": TEST_API_TOKEN},
        )

        response = client.get("/api/doctor")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "doctor")
        self.assertNotIn("web-port", {check["name"] for check in payload["checks"]})
