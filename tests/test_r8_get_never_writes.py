"""R8 RI-07 (T-030 + reviewer bundle + extract zip): GET handlers never write into the run folder.

Before, eight GETs built and wrote exports on read: ``/submission-manifest`` (+ ``/file``),
``/validation-package`` (+ ``/file``), ``/case-report/file`` (+ ``/{format}``),
``/reviewer-bundle/file`` (rebuilt the whole bundle and its review snapshot) and
``/extract/{name}/file`` (wrote the zip). Now the JSON GETs build in memory, the file GETs return
the saved export (404 ``EXPORT_NOT_WRITTEN`` until the export POST wrote it), and the extract zip
is written by ``POST /extract`` (or ``POST /extract/{name}/zip`` for an older extract folder).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import build_sample_evidence

TOKEN = "r8-get-token"
#: The two in-memory JSON GETs (T-030 route 1-2).
QUERY_GETS = ("submission-manifest", "validation-package")
#: Saved-file GETs: 404 ``EXPORT_NOT_WRITTEN`` until the export POST wrote the file (T-030 route 3-6;
#: ``/saved`` carries the code too since T-030's remaining scope).
FILE_GETS = (
    "submission-manifest/saved",
    "submission-manifest/file",
    "validation-package/saved",
    "validation-package/file",
    "case-report/file",
    "case-report/file/md",
    "case-report/file/pdf",
    "reviewer-bundle/file",
)
#: Route 7, the extract zip download, needs an extract folder name (see ``extract_file_get``).
EXTRACT_NAME = "pick-legacy"


def snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): "<dir>" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
    }


class GetNeverWritesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.evidence = base / "evidence"
        build_sample_evidence(self.evidence)
        self.store = RunJobStore()
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)
        response = self.client.post(
            "/api/runs",
            json={"root": str(self.evidence), "mode": "fraud", "output_dir": str(base / "out"), "read_only": True, "wait": True},
        )
        self.assertEqual(response.status_code, 202, response.text)
        self.run_id = response.json()["run_id"]
        self.output = Path(self.client.get(f"/api/runs/{self.run_id}").json()["summary"]["output_dir"])
        marked = self.client.post(
            f"/api/runs/{self.run_id}/bookmarks",
            json={"source": "files", "pointer": "/candidates/0", "include_in_report": True},
        )
        self.assertEqual(marked.status_code, 200, marked.text)

    def url(self, rest: str) -> str:
        return f"/api/runs/{self.run_id}/{rest}"

    def legacy_extract_folder(self) -> None:
        """An extract folder without its zip (written before the zip POST existed)."""
        folder = self.output / "extract" / EXTRACT_NAME
        (folder / "Users").mkdir(parents=True)
        (folder / "Users" / "memo.txt").write_text("memo", encoding="utf-8")
        (folder / "rapidtriage-extract-manifest.json").write_text(json.dumps({"summary": {"extracted_count": 1}}), encoding="utf-8")

    def test_all_seven_routes_before_any_export_write_nothing(self) -> None:
        self.legacy_extract_folder()
        before = snapshot(self.output)
        for rest in QUERY_GETS:
            response = self.client.get(self.url(rest))
            self.assertEqual(response.status_code, 200, f"{rest}: {response.text[:200]}")
        for rest in (*FILE_GETS, f"extract/{EXTRACT_NAME}/file"):
            response = self.client.get(self.url(rest))
            self.assertEqual(response.status_code, 404, f"{rest}: {response.text[:200]}")
            self.assertEqual(response.json()["detail"]["code"], "EXPORT_NOT_WRITTEN", rest)
            self.assertIn("먼저", response.json()["detail"]["message"], rest)
        self.assertEqual(snapshot(self.output), before)

    def test_all_seven_routes_after_the_posts_write_nothing(self) -> None:
        self.legacy_extract_folder()
        for rest, body in (
            ("submission-manifest", None),
            ("validation-package", None),
            ("case-report", {}),
            ("reviewer-bundle", {}),
            (f"extract/{EXTRACT_NAME}/zip", None),
        ):
            response = self.client.post(self.url(rest), json=body) if body is not None else self.client.post(self.url(rest))
            self.assertEqual(response.status_code, 200, f"{rest}: {response.text[:200]}")
        before = snapshot(self.output)
        for rest in (*QUERY_GETS, *FILE_GETS, f"extract/{EXTRACT_NAME}/file"):
            response = self.client.get(self.url(rest))
            self.assertEqual(response.status_code, 200, f"{rest}: {response.text[:200]}")
        self.assertEqual(snapshot(self.output), before)
        bundle = self.client.get(self.url("reviewer-bundle/file"))
        self.assertEqual(bundle.content, (self.output / "rapidtriage-reviewer-bundle.zip").read_bytes())

    def test_extract_zip_is_written_by_the_post(self) -> None:
        source = self.evidence / "Users" / "alice" / "Documents"
        path = next(item for item in sorted(source.rglob("*")) if item.is_file())
        created = self.client.post(self.url("extract"), json={"rows": [{"path": str(path)}], "output_name": "pick"})
        self.assertEqual(created.status_code, 200, created.text)
        body = created.json()
        self.assertEqual(body["zip"]["status"], "written")
        before = snapshot(self.output)
        download = self.client.get(body["download_url"])
        self.assertEqual(download.status_code, 200, download.text[:200])
        self.assertEqual(snapshot(self.output), before)

    def test_older_extract_folder_needs_the_zip_post(self) -> None:
        folder = self.output / "extract" / "legacy-20250101T000000"
        (folder / "Users").mkdir(parents=True)
        (folder / "Users" / "memo.txt").write_text("memo", encoding="utf-8")
        (folder / "Users" / ".git-credentials").write_text("https://u:FAKE-R8-ZIP@host\n", encoding="utf-8")
        (folder / "rapidtriage-extract-manifest.json").write_text(json.dumps({"summary": {"extracted_count": 1}}), encoding="utf-8")
        before = snapshot(self.output)
        missing = self.client.get(self.url("extract/legacy-20250101T000000/file"))
        self.assertEqual(missing.status_code, 404, missing.text)
        self.assertEqual(missing.json()["detail"]["code"], "EXPORT_NOT_WRITTEN")
        self.assertEqual(snapshot(self.output), before)
        dashboard = self.client.get(self.url("dashboard")).json()
        entry = next(item for item in dashboard["exports"] if item["name"] == "legacy-20250101T000000.zip")
        self.assertEqual(entry["build_url"], self.url("extract/legacy-20250101T000000/zip"))
        built = self.client.post(entry["build_url"])
        self.assertEqual(built.status_code, 200, built.text)
        self.assertEqual(built.json()["skipped_credential_files"], 1)
        download = self.client.get(entry["download_url"])
        self.assertEqual(download.status_code, 200)
        archive = Path(self._tmp.name) / "dl.zip"
        archive.write_bytes(download.content)
        with zipfile.ZipFile(archive) as handle:
            names = handle.namelist()
        self.assertIn("Users/memo.txt", names)
        self.assertNotIn("Users/.git-credentials", names)
        self.assertIsNone(
            next(item for item in self.client.get(self.url("dashboard")).json()["exports"] if item["type"] == "extract")["build_url"]
        )


if __name__ == "__main__":
    unittest.main()
