"""R8 T-350 / GAP-362: an imported run's summary paths are not read roots.

* the source routes (원본 보기 · hex · 다운로드) serve an imported run only from its result folder
  and from the evidence root its own input fingerprint verifies (relative path + size [+ SHA-256]);
* a summary whose ``root`` / ``scan_scope_root`` / ``source.analysis_root`` is forged to an OS
  folder, another case folder or the evidence's parent folder answers 403
  ``IMPORT_SOURCE_ROOT_UNVERIFIED`` with no file bytes;
* a root that contains the home folder / a credential store / the server state is refused even
  when a forged fingerprint matches it;
* runs imported before the marker existed get it back on state restore;
* T-350 follow-up: remote ``/api/browse`` never lists well-known credential stores, even with
  ``show_hidden=true``, and says so in Korean.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.core import import_roots
from rapidtriage.core.credential_stores import is_credential_store_path
from rapidtriage.core.jobs import RunJob, RunJobStore
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.sample_case import build_sample_evidence

TOKEN = "r8-import-roots-token"
SUMMARY = "rapidtriage-run-summary.json"
FINGERPRINT = "rapidtriage-run-fingerprint.json"
CODE = "IMPORT_SOURCE_ROOT_UNVERIFIED"
SECRET = b"T350-SECRET-BYTES-must-never-leave-the-server"


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
        base = Path(cls._base.name).resolve()
        return base / "evidence", base / "out"


def tearDownModule() -> None:
    if Fixture._base is not None:
        Fixture._base.cleanup()


def set_roots(summary: dict, root: Path) -> None:
    summary["root"] = str(root)
    summary["scan_scope_root"] = str(root)
    source = summary.setdefault("source", {})
    source["analysis_root"] = str(root)
    source["source_path"] = str(root)


class Base(unittest.TestCase):
    def setUp(self) -> None:
        source_evidence, self.source_out = Fixture.build()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name).resolve()
        self.evidence = self.base / "case" / "evidence"
        shutil.copytree(source_evidence, self.evidence)
        # A file next to the evidence (parent-folder forgery target) and another case's folder.
        (self.base / "case" / "outside.txt").write_bytes(SECRET)
        self.other_case = self.base / "other-case"
        (self.other_case / "Users").mkdir(parents=True)
        (self.other_case / "Users" / "secret.txt").write_bytes(SECRET)
        self.store = RunJobStore()
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(self.client.close)
        self.addCleanup(self.store.close)
        import_roots.clear_cache()

    def import_copy(self, name: str, root: Path, *, edit=None) -> str:
        target = self.base / name
        shutil.copytree(self.source_out, target)
        summary_path = target / SUMMARY
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        set_roots(summary, root)
        summary["imported_run"] = False  # a file cannot switch the check off
        if edit is not None:
            edit(summary, target)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")
        response = self.client.post("/api/runs/import", json={"output_dir": str(target)})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIs(response.json()["summary"]["imported_run"], True)
        return response.json()["run_id"]

    def assert_refused(self, run_id: str, path: Path) -> None:
        for route, extra in (
            ("source-preview", {}),
            ("source-hex-range", {"offset": 0, "length": 64}),
            ("source-file", {}),
        ):
            with self.subTest(route=route, path=str(path)):
                response = self.client.get(f"/api/runs/{run_id}/{route}", params={"path": str(path), **extra})
                self.assertEqual(response.status_code, 403, response.text[:300])
                detail = response.json()["detail"]
                self.assertEqual(detail["code"], CODE)
                self.assertIn("원본 위치를 확인할 수 없습니다", detail["message"])
                self.assertNotIn(SECRET, response.content)


class ForgedRootTests(Base):
    def test_root_forged_to_an_os_folder(self) -> None:
        os_folder = Path(os.environ.get("SystemRoot") or "/etc").resolve()
        target = next((p for p in (os_folder / "win.ini", os_folder / "hosts") if p.is_file()), os_folder / "win.ini")
        run_id = self.import_copy("forged-os", os_folder)
        self.assert_refused(run_id, target)

    def test_root_forged_to_another_case_folder(self) -> None:
        run_id = self.import_copy("forged-other", self.other_case)
        self.assert_refused(run_id, self.other_case / "Users" / "secret.txt")

    def test_root_forged_to_the_parent_folder(self) -> None:
        run_id = self.import_copy("forged-parent", self.evidence.parent)
        self.assert_refused(run_id, self.evidence.parent / "outside.txt")

    def test_only_root_forged_keeps_the_verified_scan_root(self) -> None:
        def forge(summary: dict, _target: Path) -> None:
            summary["root"] = str(self.evidence.parent)

        run_id = self.import_copy("forged-root-only", self.evidence, edit=forge)
        self.assert_refused(run_id, self.evidence.parent / "outside.txt")
        rel = "Users/alice/Documents/incident-notes.log"
        response = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.evidence / rel)})
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_forged_fingerprint_cannot_open_home_or_credential_stores(self) -> None:
        home = self.base / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "id_rsa").write_bytes(SECRET)
        (home / "notes.txt").write_bytes(SECRET)

        def forge(summary: dict, target: Path) -> None:
            fingerprint = json.loads((target / FINGERPRINT).read_text(encoding="utf-8"))
            fingerprint["files"] = [
                {"relative_path": "notes.txt", "size_bytes": len(SECRET), "sha256": None},
                {"relative_path": ".ssh/id_rsa", "size_bytes": len(SECRET), "sha256": None},
            ]
            (target / FINGERPRINT).write_text(json.dumps(fingerprint), encoding="utf-8")

        with mock.patch.dict(os.environ, {"USERPROFILE": str(home), "HOME": str(home)}):
            self.assertEqual(Path.home().resolve(), home)
            run_id = self.import_copy("forged-home", home, edit=forge)
            self.assert_refused(run_id, home / "notes.txt")
            self.assert_refused(run_id, home / ".ssh" / "id_rsa")
            ssh_only = self.import_copy("forged-ssh", home / ".ssh", edit=forge)
            self.assert_refused(ssh_only, home / ".ssh" / "id_rsa")

    def test_root_containing_the_server_state_is_refused(self) -> None:
        state_parent = self.base / "state-parent"
        (state_parent / "rapidtriage").mkdir(parents=True)
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_STATE_PATH": str(state_parent / "rapidtriage" / "runs.json")}):
            self.assertEqual(
                import_roots.blocked_root_reason(state_parent.resolve()), "contains-server-state"
            )
        self.assertEqual(import_roots.blocked_root_reason(Path(self.base.anchor)), "filesystem-root")


class GenuineImportTests(Base):
    def test_ten_source_views_of_a_genuine_import_answer_200(self) -> None:
        run_id = self.import_copy("genuine", self.evidence)
        fingerprint = json.loads((self.source_out / FINGERPRINT).read_text(encoding="utf-8"))
        files = [row["relative_path"] for row in fingerprint["files"]]
        self.assertGreaterEqual(len(files), 10)
        statuses = []
        for rel in files[:10]:
            response = self.client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(self.evidence / rel)})
            statuses.append(response.status_code)
        self.assertEqual(statuses, [200] * 10)
        allowed = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.evidence / files[0])})
        self.assertEqual(allowed.status_code, 200)

    def test_moved_evidence_with_the_same_files_is_accepted(self) -> None:
        moved = self.base / "moved-evidence"
        shutil.copytree(self.evidence, moved)
        run_id = self.import_copy("genuine-moved", moved)
        response = self.client.get(
            f"/api/runs/{run_id}/source-preview", params={"path": str(moved / "Users/alice/Documents/incident-notes.log")}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])

    def test_native_run_roots_are_unchanged(self) -> None:
        summary = json.loads((self.source_out / SUMMARY).read_text(encoding="utf-8"))
        from rapidtriage.api.app.helpers import allowed_source_roots

        roots = allowed_source_roots(summary)
        self.assertIn(Path(summary["root"]).resolve(), roots)
        self.assertNotIn("imported_run", summary)


class StateRestoreTests(unittest.TestCase):
    def test_imported_runs_get_the_marker_back_and_native_runs_cannot_claim_it(self) -> None:
        record = {"run_id": "abc", "status": "completed", "origin": "imported", "summary": {"root": "x"}}
        self.assertIs(RunJob.from_record(record).summary["imported_run"], True)
        native = {"run_id": "def", "status": "completed", "origin": "web", "summary": {"root": "x", "imported_run": True}}
        self.assertNotIn("imported_run", RunJob.from_record(native).summary)
        sample = {"run_id": "ghi", "status": "completed", "origin": "imported", "summary": {"imported_run": False}}
        self.assertIs(RunJob.from_record(sample).summary["imported_run"], False)

    def test_only_the_api_import_turns_verification_on(self) -> None:
        _evidence, out = Fixture.build()
        job = RunJobStore().import_completed_run(out)
        self.assertIs(job.summary["imported_run"], False)


class RemoteBrowseCredentialStoreTests(unittest.TestCase):
    STORES = (".ssh", ".gnupg", ".aws", ".azure", ".kube")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "browse"
        for name in (*self.STORES, ".config/gcloud", ".config/other", "Documents", ".hidden-normal"):
            (self.root / name).mkdir(parents=True)
        roaming = self.root / "AppData" / "Roaming" / "Microsoft"
        for name in ("Credentials", "Protect", "Windows"):
            (roaming / name).mkdir(parents=True)
        profile = self.root / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
        profile.mkdir(parents=True)
        for name in ("Login Data", "Cookies", "History"):
            (profile / name).write_bytes(b"x")
        self.profile = profile
        self.client = TestClient(
            create_app(RunJobStore(), auth_token=TOKEN, browse_remote=True, browse_roots=[self.root]),
            headers={"X-RapidTriage-Token": TOKEN},
        )
        self.addCleanup(self.client.close)

    def names(self, path: Path, *, show_hidden: bool = True) -> tuple[list[str], dict]:
        response = self.client.get("/api/browse", params={"path": str(path), "show_hidden": "1" if show_hidden else "0"})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        return [entry["name"] for entry in body["entries"]], body

    def test_credential_stores_are_never_listed_even_with_show_hidden(self) -> None:
        names, body = self.names(self.root)
        for store in self.STORES:
            self.assertNotIn(store, names)
        self.assertIn(".hidden-normal", names)
        self.assertIn("Documents", names)
        self.assertEqual(body["credential_hidden_count"], len(self.STORES))
        self.assertIn("자격 증명 저장소", body["credential_note"])
        self.assertNotIn(".ssh", json.dumps(body["entries"]))
        config, _ = self.names(self.root / ".config")
        self.assertEqual(config, ["other"])
        microsoft, _ = self.names(self.root / "AppData" / "Roaming" / "Microsoft")
        self.assertEqual(microsoft, ["Windows"])
        profile, _ = self.names(self.profile)
        self.assertEqual(profile, ["History"])

    def test_opening_a_credential_store_directly_is_refused(self) -> None:
        for path in (self.root / ".ssh", self.root / ".config" / "gcloud", self.root / "AppData/Roaming/Microsoft/Protect"):
            with self.subTest(path=str(path)):
                response = self.client.get("/api/browse", params={"path": str(path), "show_hidden": "1"})
                self.assertEqual(response.status_code, 403, response.text)
                self.assertEqual(response.json()["detail"]["code"], "PATH_OUTSIDE_ALLOWED_ROOT")

    def test_local_browse_is_unchanged(self) -> None:
        client = TestClient(create_app(RunJobStore(), auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.addCleanup(client.close)
        body = client.get("/api/browse", params={"path": str(self.root), "show_hidden": "1"}).json()
        self.assertEqual(body["browse_mode"], "local")
        self.assertIn(".ssh", [entry["name"] for entry in body["entries"]])

    def test_store_matcher(self) -> None:
        for path in ("C:/Users/a/.ssh", "/home/a/.gnupg/x", "/home/a/.config/gcloud", "C:/Windows/System32/config/SAM"):
            self.assertTrue(is_credential_store_path(path), path)
        for path in ("C:/Users/a/Documents", "/home/a/.config/other", "/home/a/sshnotes"):
            self.assertFalse(is_credential_store_path(path), path)


if __name__ == "__main__":
    unittest.main()
