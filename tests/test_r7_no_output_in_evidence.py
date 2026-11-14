"""R7 forensic integrity: run / tool output is never written inside the evidence.

One guard (``core/output_guard.py``) applied at the core run entry, the web job store, the
API (runs, retry, case runs, evidence, output-check) and the CLI. Every refusal leaves the
evidence folder exactly as it was.
"""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.jobs import (
    RunJob,
    RunJobStore,
    RunRequest,
    check_request_output_outside_evidence,
)
from rapidtriage.core.output_guard import (
    EVIDENCE_INSIDE_OUTPUT,
    OUTPUT_INSIDE_EVIDENCE,
    OutputInsideEvidenceError,
    check_output_outside_evidence,
    output_evidence_conflict,
)
from rapidtriage.core.run import run_triage_mode
from tests.test_rapidtriage_run import build_run_fixture

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app

TOKEN = "rapidtriage-test-token"


def tree(root: Path) -> list[str]:
    """Every path under ``root`` (relative), to prove a refusal wrote nothing."""
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


def make_junction(link: Path, target: Path) -> bool:
    if os.name != "nt":
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            return False
        return True
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True, check=False
    )
    return result.returncode == 0 and link.exists()


def remove_link(link: Path) -> None:
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "rmdir", str(link)], capture_output=True, check=False)
    else:
        link.unlink(missing_ok=True)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        build_run_fixture(self.evidence)
        self.before = tree(self.evidence)

    def assertEvidenceUntouched(self) -> None:
        self.assertEqual(tree(self.evidence), self.before)


class OutputGuardTests(Base):
    def test_equal_and_inside_are_refused(self) -> None:
        self.assertEqual(output_evidence_conflict(self.evidence, self.evidence), OUTPUT_INSIDE_EVIDENCE)
        self.assertEqual(output_evidence_conflict(self.evidence / "out", self.evidence), OUTPUT_INSIDE_EVIDENCE)
        deep = self.evidence / "not" / "yet" / "there"
        self.assertEqual(output_evidence_conflict(deep, self.evidence), OUTPUT_INSIDE_EVIDENCE)
        self.assertEqual(output_evidence_conflict(str(self.evidence) + os.sep, self.evidence), OUTPUT_INSIDE_EVIDENCE)
        dotted = self.base / "x" / ".." / "evidence" / "out"
        self.assertEqual(output_evidence_conflict(dotted, self.evidence), OUTPUT_INSIDE_EVIDENCE)

    def test_evidence_inside_output_is_refused_except_for_a_case_folder(self) -> None:
        self.assertEqual(output_evidence_conflict(self.base, self.evidence), EVIDENCE_INSIDE_OUTPUT)
        with self.assertRaises(OutputInsideEvidenceError) as caught:
            check_output_outside_evidence(self.base, [self.evidence])
        self.assertEqual(caught.exception.code, EVIDENCE_INSIDE_OUTPUT)
        check_output_outside_evidence(self.base, [self.evidence], allow_evidence_inside=True)
        with self.assertRaises(OutputInsideEvidenceError):
            check_output_outside_evidence(self.evidence / "case", [self.evidence], allow_evidence_inside=True)

    def test_siblings_are_allowed(self) -> None:
        self.assertIsNone(output_evidence_conflict(self.base / "out", self.evidence))
        # Same name prefix is not "inside".
        self.assertIsNone(output_evidence_conflict(self.base / "evidence-out", self.evidence))
        self.assertIsNone(output_evidence_conflict(self.base / "evidence2" / "out", self.evidence))
        check_output_outside_evidence(self.base / "out", [self.evidence, None, ""])

    @unittest.skipUnless(os.name == "nt", "case-insensitive paths are a Windows rule")
    def test_case_differences_on_windows(self) -> None:
        upper = Path(str(self.evidence).upper()) / "OUT"
        self.assertEqual(output_evidence_conflict(upper, self.evidence), OUTPUT_INSIDE_EVIDENCE)
        self.assertEqual(output_evidence_conflict(str(self.evidence).replace("\\", "/"), self.evidence),
                         OUTPUT_INSIDE_EVIDENCE)

    def test_junction_or_symlink_into_the_evidence_is_resolved(self) -> None:
        link = self.base / "alias"
        if not make_junction(link, self.evidence):
            self.skipTest("cannot create a junction / symlink here")
        self.addCleanup(remove_link, link)
        self.assertEqual(output_evidence_conflict(link / "out", self.evidence), OUTPUT_INSIDE_EVIDENCE)
        self.assertEqual(output_evidence_conflict(link, self.evidence), OUTPUT_INSIDE_EVIDENCE)
        # The evidence named through the alias, output inside the real folder.
        self.assertEqual(output_evidence_conflict(self.evidence / "out", link), OUTPUT_INSIDE_EVIDENCE)

    def test_file_evidence(self) -> None:
        image = self.base / "disk.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")
        self.assertEqual(output_evidence_conflict(image / "out", image), OUTPUT_INSIDE_EVIDENCE)
        self.assertEqual(output_evidence_conflict(image, image), OUTPUT_INSIDE_EVIDENCE)
        self.assertIsNone(output_evidence_conflict(self.base / "disk-run", image))

    def test_error_detail_is_korean_with_a_stable_code(self) -> None:
        with self.assertRaises(OutputInsideEvidenceError) as caught:
            check_output_outside_evidence(self.evidence / "out", [self.evidence])
        detail = caught.exception.to_detail()
        self.assertEqual(detail["code"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertIn("증거에는 아무것도 쓰지 않습니다", detail["message"])
        self.assertIn("Output must not be", caught.exception.cli_message)


class CoreRunAndJobStoreTests(Base):
    def test_core_run_refuses_before_creating_anything(self) -> None:
        for output in (self.evidence, self.evidence / "run-out", self.base):
            with self.subTest(output=str(output)):
                with self.assertRaises(OutputInsideEvidenceError):
                    run_triage_mode(self.evidence, mode="fraud", output_dir=output, case_db=False)
                self.assertEvidenceUntouched()
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), ["evidence"])

    def test_job_store_has_no_in_evidence_default(self) -> None:
        store = RunJobStore()
        with self.assertRaises(OutputInsideEvidenceError):
            check_request_output_outside_evidence(RunRequest(root=str(self.evidence), mode="fraud"))
        for request in (
            RunRequest(root=str(self.evidence), mode="fraud"),
            RunRequest(root=str(self.evidence), mode="fraud", output_dir=str(self.evidence / "out")),
            RunRequest(root=str(self.evidence), mode="fraud", output_dir=str(self.base)),
        ):
            with self.subTest(output=request.output_dir):
                with self.assertRaises(OutputInsideEvidenceError):
                    store.submit(request)
                with self.assertRaises(OutputInsideEvidenceError):
                    store.run_sync(request)
        self.assertEqual(store.list(), [])
        self.assertEvidenceUntouched()
        # A file evidence's legacy default (a sibling) is outside it.
        image = self.base / "disk.E01"
        image.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")
        check_request_output_outside_evidence(RunRequest(root=str(image), mode="fraud"), run_id="abc")

    def test_retry_of_a_legacy_in_evidence_run_is_refused(self) -> None:
        store = RunJobStore()
        legacy = RunRequest(root=str(self.evidence), mode="fraud", output_dir=str(self.evidence / "old-out"))
        store._jobs["legacy"] = RunJob(run_id="legacy", request=legacy, status="failed")
        for resume in (False, True):
            with self.assertRaises(OutputInsideEvidenceError):
                store.retry("legacy", resume=resume)
        self.assertIsNone(store.get("legacy").retried_by)
        self.assertEvidenceUntouched()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class ApiTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.store = RunJobStore()
        app = create_app(self.store, auth_token=TOKEN, cases_db_path=self.base / "workspace" / "cases.db")
        self.client = TestClient(app, headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)

    def test_quick_run_refusals(self) -> None:
        missing = self.client.post("/api/runs", json={"root": str(self.evidence), "mode": "fraud"})
        self.assertEqual(missing.status_code, 422, missing.text)
        self.assertEqual(missing.json()["detail"]["code"], "OUTPUT_DIR_REQUIRED")
        self.assertIn("폴더 증거 안에는", missing.json()["detail"]["message"])
        cases = {
            str(self.evidence): "OUTPUT_INSIDE_EVIDENCE",
            str(self.evidence / "out"): "OUTPUT_INSIDE_EVIDENCE",
            str(self.base): "EVIDENCE_INSIDE_OUTPUT",
        }
        for output, code in cases.items():
            for wait in (False, True):
                with self.subTest(output=output, wait=wait):
                    response = self.client.post(
                        "/api/runs", json={"root": str(self.evidence), "mode": "fraud", "output_dir": output, "wait": wait}
                    )
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertEqual(response.json()["detail"]["code"], code)
                    self.assertIn("증거", response.json()["detail"]["message"])
        self.assertEqual(self.store.list(), [])
        self.assertEvidenceUntouched()

    def test_retry_refusal_is_422_with_the_code(self) -> None:
        legacy = RunRequest(root=str(self.evidence), mode="fraud")
        self.store._jobs["legacy"] = RunJob(run_id="legacy", request=legacy, status="interrupted")
        response = self.client.post("/api/runs/legacy/retry", json={})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["detail"]["code"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertEvidenceUntouched()

    def test_output_check_reports_it_before_any_case_exists(self) -> None:
        def check(path: Path, kind: str = "output_dir") -> dict:
            response = self.client.post(
                "/api/cases/output-check", json={"path": str(path), "kind": kind, "evidence_paths": [str(self.evidence)]}
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        inside = check(self.evidence / "out")
        self.assertFalse(inside["ok"])
        self.assertEqual(inside["code"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertIn("증거", inside["problem"])
        around = check(self.base)
        self.assertEqual((around["ok"], around["code"]), (False, "EVIDENCE_INSIDE_OUTPUT"))
        self.assertTrue(check(self.base / "out")["ok"])
        # A case folder may hold the evidence, never sit inside it.
        self.assertTrue(check(self.base, "case_root")["ok"])
        self.assertEqual(check(self.evidence / "case", "case_root")["code"], "OUTPUT_INSIDE_EVIDENCE")
        # Without evidence paths the old checks are unchanged.
        plain = self.client.post("/api/cases/output-check", json={"path": str(self.evidence / "out")}).json()
        self.assertTrue(plain["ok"])
        self.assertEqual(self.client.get("/api/cases").json().get("cases", []), [])
        self.assertEvidenceUntouched()

    def _case(self, **extra: object) -> str:
        body = {"case_number": "R7-1", "examiner": "검사관"}
        body.update(extra)
        response = self.client.post("/api/cases", json=body)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["case"]["case_id"]

    def _evidence(self, case_id: str, path: Path, number: str = "E-01"):
        return self.client.post(
            f"/api/cases/{case_id}/evidence",
            json={"evidence_number": number, "source_type": "folder", "path": str(path)},
        )

    def test_case_runs_never_write_inside_any_case_evidence(self) -> None:
        other = self.base / "other-evidence"
        other.mkdir()
        (other / "b.txt").write_text("b", encoding="utf-8")
        case_id = self._case(case_root=str(self.base / "case-folder"))
        first = self._evidence(case_id, self.evidence).json()["evidence"]
        self.assertEqual(self._evidence(case_id, other, "E-02").status_code, 201)
        for output, code in (
            (self.evidence / "out", "OUTPUT_INSIDE_EVIDENCE"),
            (other / "out", "OUTPUT_INSIDE_EVIDENCE"),
            (self.base, "EVIDENCE_INSIDE_OUTPUT"),
        ):
            with self.subTest(output=str(output)):
                response = self.client.post(
                    f"/api/cases/{case_id}/runs",
                    json={"evidence_citation_id": first["citation_id"], "mode": "fraud", "output_dir": str(output)},
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(response.json()["detail"]["code"], code)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(tree(other), ["b.txt"])
        self.assertEvidenceUntouched()

    def test_evidence_that_holds_the_case_folder_is_refused(self) -> None:
        case_id = self._case(case_root=str(self.evidence / "case-folder"))
        response = self._evidence(case_id, self.evidence)
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["detail"]["code"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertEvidenceUntouched()


class CliTests(Base):
    def run_cli(self, argv: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            try:
                code = main(argv)
            except SystemExit as exc:
                code = int(exc.code or 0)
        return code, stderr.getvalue()

    def test_run_requires_an_output_folder_outside_the_evidence(self) -> None:
        code, err = self.run_cli(["run", str(self.evidence), "--mode", "fraud"])
        self.assertEqual(code, 2)
        self.assertIn("--output-dir", err)
        self.assertIn("증거 밖", err)
        for output in (self.evidence / "rapidtriage-run-fraud", self.evidence, self.base):
            with self.subTest(output=str(output)):
                code, err = self.run_cli(["run", str(self.evidence), "--mode", "fraud", "--output-dir", str(output)])
                self.assertEqual(code, 2)
                self.assertIn("evidence", err)
        self.assertEvidenceUntouched()
        # --print-plan writes nothing and needs no output folder.
        self.assertEqual(self.run_cli(["run", str(self.evidence), "--mode", "fraud", "--print-plan"])[0], 0)

    def test_run_with_a_sibling_output_folder_works(self) -> None:
        output = self.base / "run-out"
        code, err = self.run_cli(
            ["run", str(self.evidence), "--mode", "fraud", "--output-dir", str(output), "--no-case-db"]
        )
        self.assertEqual(code, 0, err)
        self.assertTrue((output / "rapidtriage-run-summary.json").is_file())
        self.assertEvidenceUntouched()

    def test_tool_commands_with_derived_outputs(self) -> None:
        commands = [
            ["kakaotalk-decrypt", str(self.evidence), "--output", str(self.evidence / "decrypt.json")],
            ["kakaotalk-memory-carve", str(self.evidence), "--output", str(self.evidence / "carve.json")],
            ["carve", str(self.evidence), "--output-dir", str(self.evidence / "carve-out")],
            ["collect-export", str(self.evidence), str(self.evidence / "export")],
        ]
        for argv in commands:
            with self.subTest(command=argv[0]):
                code, err = self.run_cli(argv)
                self.assertEqual(code, 2, err)
                self.assertIn("evidence", err)
        # kakaotalk-decrypt: the JSON outside, the decrypted copies (beside the JSON by default) too.
        code, err = self.run_cli(
            ["kakaotalk-decrypt", str(self.evidence), "--output", str(self.base / "d.json"),
             "--write-decrypted", "--decrypted-dir", str(self.evidence / "plain")]
        )
        self.assertEqual(code, 2, err)
        self.assertEvidenceUntouched()


if __name__ == "__main__":
    unittest.main()
