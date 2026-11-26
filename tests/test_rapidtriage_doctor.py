from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
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

            with patch("rapidtriage.core.e01_native.pyewf", None), patch("rapidtriage.core.e01_native.NTFS", None):
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

    def _doctor_e01_check(self, *, pyewf: object, ntfs: object, ntfs_version: str | None = "3.16") -> dict:
        from rapidtriage.core import e01_native

        with tempfile.TemporaryDirectory() as tmp_dir, patch.object(e01_native, "pyewf", pyewf), patch.object(
            e01_native, "NTFS", ntfs
        ), patch.object(e01_native, "_distribution_version", return_value=ntfs_version):
            static_dir = Path(tmp_dir) / "static"
            make_static_assets(static_dir)
            payload = run_doctor(
                static_dir=static_dir,
                app_data_dir=Path(tmp_dir) / "app-data",
                tool_resolver=lambda _name: None,
                include_port_check=False,
            )
        return {check["name"]: check for check in payload["checks"]}["tools:e01"]

    def test_doctor_reports_native_e01_decoder_when_external_tools_are_absent(self) -> None:
        working = SimpleNamespace(get_version=lambda: "20240506", handle=object)
        e01 = self._doctor_e01_check(pyewf=working, ntfs=object)
        self.assertEqual(e01["status"], OK)
        self.assertTrue(e01["details"]["native_decoder"])
        self.assertEqual(e01["details"]["native_versions"], {"pyewf": "20240506", "dissect.ntfs": "3.16"})
        self.assertEqual(e01["details"]["native_problems"], [])
        self.assertEqual(e01["details"]["missing"], ["ewfmount", "mmls", "tsk_recover"])
        self.assertIn("pyewf 20240506, dissect.ntfs 3.16", e01["summary"])

        # Frozen/vendored builds may lack dist metadata: importable and working, version unknown.
        unknown = self._doctor_e01_check(pyewf=working, ntfs=object, ntfs_version=None)
        self.assertEqual(unknown["status"], OK)
        self.assertIn("dissect.ntfs unknown", unknown["summary"])

    def test_doctor_does_not_claim_native_e01_decoder_when_the_extra_is_importable_but_broken(self) -> None:
        def broken_handle() -> object:
            raise OSError("libewf binding failed to initialise")

        broken = SimpleNamespace(get_version=lambda: "20240506", handle=broken_handle)
        e01 = self._doctor_e01_check(pyewf=broken, ntfs=object)
        self.assertEqual(e01["status"], WARN)
        self.assertFalse(e01["details"]["native_decoder"])
        self.assertIn("installed but unusable", e01["summary"])
        self.assertIn("libewf binding failed to initialise", e01["details"]["native_problems"][0])

        working = SimpleNamespace(get_version=lambda: "20240506", handle=object)
        too_old = self._doctor_e01_check(pyewf=working, ntfs=object, ntfs_version="3.9.1")
        self.assertEqual(too_old["status"], WARN)
        self.assertEqual(too_old["details"]["native_problems"], ["dissect.ntfs 3.9.1 is older than the required 3.10"])

        half_installed = self._doctor_e01_check(pyewf=working, ntfs=None)
        self.assertEqual(half_installed["status"], WARN)
        self.assertEqual(half_installed["details"]["native_problems"], ["dissect.ntfs is not importable"])

        absent = self._doctor_e01_check(pyewf=None, ntfs=None)
        self.assertEqual(absent["status"], WARN)
        self.assertEqual(absent["summary"], "E01 direct extraction tools are incomplete.")

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
