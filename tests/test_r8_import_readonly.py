"""R8 RI-05 + D37: ``POST /api/runs/import`` does not trust the summary's paths, and a run whose
output folder is inside its evidence (written before the output guard) opens read-only.

* ``output_dir`` is the folder the summary was read from; a forged / moved value is only recorded.
* every ``outputs`` path must resolve inside that folder (Korean 400 with a stable code otherwise).
* ``root`` stays the evidence reference; when the folder overlaps it the run gets
  ``readonly_reason`` and nothing is written into the folder: every GET of the API leaves it
  byte-identical, state-changing requests answer ``409 RUN_READ_ONLY`` (except removing the run
  from the list and search queries), and the process write guard refuses any lazy write.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunImportError, RunJobStore
from rapidtriage.core.readonly_runs import (
    ReadOnlyRunWriteError,
    install_write_guard,
    may_persist,
    readonly_folders,
    register_readonly_folder,
    unregister_readonly_folder,
)
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.sample_case import build_sample_evidence
from tests import quiet_media_checks

setUpModule = quiet_media_checks.setUpModule

TOKEN = "r8-import-token"
SUMMARY = "rapidtriage-run-summary.json"


def snapshot(root: Path) -> dict[str, str]:
    """Relative path -> SHA-256 (``<dir>`` for folders) of everything under ``root``."""
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        key = str(path.relative_to(root))
        result[key] = "<dir>" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class Fixture:
    """One synthetic evidence folder + a finished run output outside it (built once)."""

    _base: tempfile.TemporaryDirectory | None = None

    @classmethod
    def build(cls) -> tuple[Path, Path]:
        if cls._base is None:
            cls._base = tempfile.TemporaryDirectory()
            base = Path(cls._base.name).resolve()
            build_sample_evidence(base / "evidence")
            run_triage_mode(base / "evidence", mode="fraud", output_dir=base / "out", read_only=True)
        # resolve(): on Windows the temp dir may be an 8.3 short path (RUNNER~1) while the run
        # summary records the long, resolved form; compare like with like.
        base = Path(cls._base.name).resolve()
        return base / "evidence", base / "out"


def tearDownModule() -> None:
    quiet_media_checks.tearDownModule()
    if Fixture._base is not None:
        Fixture._base.cleanup()


class Base(unittest.TestCase):
    def setUp(self) -> None:
        source_evidence, source_out = Fixture.build()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.evidence = self.base / "evidence"
        shutil.copytree(source_evidence, self.evidence)
        self.source_out = source_out
        self.store = RunJobStore()
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)
        # Runs after the folder cleanup is queued, so it runs first: never leave a folder registered.
        self.addCleanup(self.store.close)

    def copy_output(self, target: Path, *, edit=None) -> Path:
        shutil.copytree(self.source_out, target)
        summary_path = target / SUMMARY
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["root"] = str(self.evidence)
        if edit is not None:
            edit(summary)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
        return target

    def import_folder(self, folder: Path):
        return self.client.post("/api/runs/import", json={"output_dir": str(folder)})


class ImportValidationTests(Base):
    def test_moved_folder_is_pinned_to_where_it_was_read(self) -> None:
        folder = self.copy_output(self.base / "moved")
        response = self.import_folder(folder)
        self.assertEqual(response.status_code, 201, response.text)
        summary = response.json()["summary"]
        self.assertEqual(Path(summary["output_dir"]), folder.resolve())
        self.assertEqual(Path(summary["imported_output_dir_claimed"]), self.source_out)
        for name, value in summary["outputs"].items():
            self.assertTrue(Path(value).resolve().is_relative_to(folder.resolve()), name)
        self.assertIsNone(response.json()["readonly_reason"])

    def test_forged_output_dir_is_ignored(self) -> None:
        def forge(summary: dict) -> None:
            summary["output_dir"] = str(self.evidence)  # would make the evidence "the output folder"
            summary["outputs"] = {  # relative outputs resolve against the folder actually read
                name: str(Path(value).relative_to(self.source_out)) for name, value in summary["outputs"].items()
            }

        folder = self.copy_output(self.base / "forged", edit=forge)
        before = snapshot(self.evidence)
        response = self.import_folder(folder)
        self.assertEqual(response.status_code, 201, response.text)
        body = response.json()
        self.assertEqual(Path(body["summary"]["output_dir"]), folder.resolve())
        self.assertEqual(Path(body["request"]["output_dir"]), folder.resolve())
        self.assertIsNone(body["readonly_reason"])
        self.assertEqual(snapshot(self.evidence), before)

    def test_outputs_outside_the_folder_are_refused(self) -> None:
        outside = self.evidence / "Users"
        cases = {
            "absolute": lambda summary: summary["outputs"].update(report=str(outside)),
            "dotdot": lambda summary: summary["outputs"].update(report="../evidence/x.json"),
        }
        for label, edit in cases.items():
            with self.subTest(label):
                folder = self.copy_output(self.base / f"bad-{label}", edit=edit)
                response = self.import_folder(folder)
                self.assertEqual(response.status_code, 400, response.text)
                detail = response.json()["detail"]
                self.assertEqual(detail["code"], "IMPORT_OUTPUT_OUTSIDE_FOLDER")
                self.assertIn("결과 폴더 밖", detail["message"])
        self.assertEqual(self.store.list(), [])

    def test_malformed_outputs_are_refused(self) -> None:
        for label, edit in {
            "missing": lambda summary: summary.pop("outputs"),
            "not-a-path": lambda summary: summary["outputs"].update(report=7),
        }.items():
            with self.subTest(label):
                folder = self.copy_output(self.base / f"malformed-{label}", edit=edit)
                response = self.import_folder(folder)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()["detail"]["code"], "IMPORT_SUMMARY_INVALID")
        with self.assertRaises(RunImportError):
            self.store.import_completed_run(self.base / "malformed-missing")


class ReadOnlyRunTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.legacy = self.copy_output(self.evidence / "legacy-out")
        response = self.import_folder(self.legacy)
        self.assertEqual(response.status_code, 201, response.text)
        self.run_id = response.json()["run_id"]
        self.assertEqual(response.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")

    def test_every_get_leaves_the_folder_unchanged(self) -> None:
        before = snapshot(self.evidence)
        schema = self.client.app.openapi()
        statuses: dict[str, int] = {}
        source = str(self.evidence / "Users")
        for path, operations in schema["paths"].items():
            if "get" not in operations or "{run_id}" not in path:
                continue
            if set(re.findall(r"{(\w+)}", path)) != {"run_id"}:
                continue
            url = path.replace("{run_id}", self.run_id)
            response = self.client.get(url, params={"path": source})
            statuses[path] = response.status_code
            self.assertNotEqual(response.status_code, 500, f"{path}: {response.text[:300]}")
        self.assertGreater(len(statuses), 40)
        self.assertEqual(snapshot(self.evidence), before)
        run = self.client.get(f"/api/runs/{self.run_id}").json()
        self.assertEqual(run["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")

    def test_state_changing_requests_are_refused(self) -> None:
        before = snapshot(self.evidence)
        refused = (
            ("put", f"/api/runs/{self.run_id}/case-notes", {"notes": "x"}),
            ("post", f"/api/runs/{self.run_id}/bookmarks", {"source": "files", "pointer": "/candidates/0"}),
            ("post", f"/api/runs/{self.run_id}/case-report", {}),
            ("post", f"/api/runs/{self.run_id}/validation-package", None),
            ("post", f"/api/runs/{self.run_id}/case-db/ensure", {}),
            ("post", f"/api/runs/{self.run_id}/analyses", {"kind": "ocr-batch"}),
            ("post", f"/api/runs/{self.run_id}/extract", {"rows": [{"path": str(self.evidence)}]}),
            (
                "post",
                "/api/case-db/review",
                {
                    "database": str(self.legacy / "rapidtriage-case.db"),
                    "case_id": "legacy-out",
                    "target_type": "document",
                    "target_id": "a",
                    "status": "relevant",
                },
            ),
        )
        for method, url, body in refused:
            with self.subTest(url=url):
                response = getattr(self.client, method)(url, json=body) if body is not None else getattr(self.client, method)(url)
                self.assertEqual(response.status_code, 409, response.text)
                self.assertEqual(response.json()["detail"]["code"], "RUN_READ_ONLY")
                self.assertIn("읽기 전용", response.json()["detail"]["message"])
        self.assertEqual(snapshot(self.evidence), before)
        removed = self.client.delete(f"/api/runs/{self.run_id}")
        self.assertEqual(removed.status_code, 204, removed.text)
        self.assertTrue(may_persist(self.legacy))
        self.assertEqual(snapshot(self.evidence), before)

    def test_restored_state_keeps_the_run_read_only(self) -> None:
        state = self.base / "state.json"
        store = RunJobStore(state_path=state)
        self.addCleanup(store.close)
        job = store.import_completed_run(self.legacy)
        restored = RunJobStore(state_path=state)
        self.addCleanup(restored.close)
        self.assertEqual(restored.get(job.run_id).readonly_reason, "OUTPUT_INSIDE_EVIDENCE")
        self.assertFalse(may_persist(self.legacy / "anything.json"))


class WriteGuardTests(unittest.TestCase):
    def test_writes_under_a_registered_folder_are_refused(self) -> None:
        install_write_guard()
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir) / "run"
            folder.mkdir()
            existing = folder / "kept.json"
            existing.write_text("{}", encoding="utf-8")
            register_readonly_folder(folder, "OUTPUT_INSIDE_EVIDENCE")
            try:
                self.assertIn(str(folder.resolve()).lower(), {key.lower() for key in readonly_folders()})
                for attempt in (
                    lambda: (folder / "new.json").write_text("x", encoding="utf-8"),
                    lambda: open(existing, "a", encoding="utf-8").close(),
                    lambda: (folder / "sub").mkdir(),
                    lambda: existing.rename(folder / "renamed.json"),
                    lambda: shutil.copyfile(existing, folder / "copy.json"),
                ):
                    with self.assertRaises(ReadOnlyRunWriteError):
                        attempt()
                self.assertEqual(existing.read_text(encoding="utf-8"), "{}")
                (Path(tmp_dir) / "beside.txt").write_text("ok", encoding="utf-8")  # outside: allowed
            finally:
                unregister_readonly_folder(folder)
            (folder / "after.json").write_text("x", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
