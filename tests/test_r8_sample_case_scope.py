"""R8 RI-04: ``POST /api/sample-case/run`` never deletes or overwrites a folder that is not a sample.

Before: ``overwrite`` defaulted to ``True`` and ``create_sample_case`` ran ``shutil.rmtree`` on any
non-empty ``output_dir`` the request named. Now the API only writes under the server's sample root,
``overwrite`` defaults to ``False``, and a folder is cleared only when it carries the sample marker
and holds nothing but the sample's own entries.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest
from rapidtriage.core.sample_case import (
    SAMPLE_DIR_HAS_OTHER_FILES,
    SAMPLE_DIR_NOT_EMPTY,
    SAMPLE_DIR_NOT_SAMPLE,
    SAMPLE_MARKER_NAME,
    SampleCaseError,
    create_sample_case,
)

TOKEN = "r8-sample-token"


def tree(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


class SampleCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_folder_without_marker_survives_overwrite(self) -> None:
        target = self.base / "important"
        target.mkdir()
        (target / "keep.txt").write_text("keep", encoding="utf-8")
        for overwrite, code in ((False, SAMPLE_DIR_NOT_EMPTY), (True, SAMPLE_DIR_NOT_SAMPLE)):
            with self.subTest(overwrite=overwrite):
                with self.assertRaises(SampleCaseError) as caught:
                    create_sample_case(target, overwrite=overwrite)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual((target / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_marker_folder_with_foreign_files_survives(self) -> None:
        target = self.base / "sample"
        create_sample_case(target)
        (target / "notes.txt").write_text("mine", encoding="utf-8")
        before = tree(target)
        with self.assertRaises(SampleCaseError) as caught:
            create_sample_case(target, overwrite=True)
        self.assertEqual(caught.exception.code, SAMPLE_DIR_HAS_OTHER_FILES)
        self.assertEqual(tree(target), before)

    def test_previous_sample_is_replaced(self) -> None:
        target = self.base / "sample"
        create_sample_case(target)
        stale = target / "evidence" / "stale.txt"
        stale.write_text("old", encoding="utf-8")
        create_sample_case(target, overwrite=True)
        self.assertFalse(stale.exists())
        self.assertTrue((target / SAMPLE_MARKER_NAME).is_file())


class SampleApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.sample_root = self.base / "rapidtriage-home"
        self.sample_root.mkdir()
        self.enterContext(patch.dict(os.environ, {"RAPIDTRIAGE_SAMPLE_ROOT": str(self.sample_root)}))
        self.store = RunJobStore()
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)

    def post(self, **body: object):
        return self.client.post("/api/sample-case/run", json={"read_only": True, **body})

    def test_folder_outside_the_sample_root_is_refused_untouched(self) -> None:
        outside = self.base / "elsewhere"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        for target in (outside, self.sample_root, self.base):
            with self.subTest(target=str(target)):
                response = self.post(output_dir=str(target), overwrite=True)
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(response.json()["detail"]["code"], "PATH_OUTSIDE_ALLOWED_ROOT")
                self.assertIn("샘플", response.json()["detail"]["message"])
        self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "keep")
        self.assertEqual(self.store.list(), [])

    def test_non_sample_folder_under_the_root_is_never_deleted(self) -> None:
        target = self.sample_root / "mine"
        target.mkdir()
        (target / "keep.txt").write_text("keep", encoding="utf-8")
        default = self.post(output_dir=str(target))
        self.assertEqual(default.status_code, 409, default.text)
        self.assertEqual(default.json()["detail"]["code"], SAMPLE_DIR_NOT_EMPTY)
        forced = self.post(output_dir=str(target), overwrite=True)
        self.assertEqual(forced.status_code, 409, forced.text)
        self.assertEqual(forced.json()["detail"]["code"], SAMPLE_DIR_NOT_SAMPLE)
        self.assertEqual(tree(target), ["keep.txt"])

    def test_folder_overlapping_known_evidence_is_refused(self) -> None:
        evidence = self.sample_root / "evidence-case"
        evidence.mkdir()
        self.store._jobs["ev"] = RunJob(run_id="ev", request=RunRequest(root=str(evidence), mode="fraud"), status="failed")
        response = self.post(output_dir=str(evidence / "sample"))
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["detail"]["code"], "OUTPUT_INSIDE_EVIDENCE")
        self.assertEqual(list(evidence.iterdir()), [])

    def test_default_folder_runs_and_reruns_with_overwrite(self) -> None:
        first = self.post()
        self.assertEqual(first.status_code, 201, first.text)
        target = self.sample_root / "sample-case"
        self.assertTrue((target / SAMPLE_MARKER_NAME).is_file())
        again = self.post()
        self.assertEqual(again.status_code, 409, again.text)
        replaced = self.post(overwrite=True)
        self.assertEqual(replaced.status_code, 201, replaced.text)


if __name__ == "__main__":
    unittest.main()
