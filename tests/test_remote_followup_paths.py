"""Remote-use path follow-ups after #89-#92 (security audit GAP-1, GAP-2, GAP-3, GAP-9; PR #91 review B2, B4, B5).

Ported from the audit's ``tests/test_audit_remote_gaps.py`` (each test asserts the
secure behaviour) plus tests for the fixes. Synthetic temporary folders only: an
evidence root, an output root and a fake home (the server account's) outside both.
No sockets are opened.
"""

from __future__ import annotations

import contextlib
import io
import ntpath
import os
import sqlite3
import tempfile
import types
import unicodedata
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.api.app.case_workspace import checked_output_path
from rapidtriage.cli.web import require_server_roots
from rapidtriage.core import local_paths
from rapidtriage.core import search as search_module
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.sample_case import (
    SAMPLE_EXPECTED_NAME,
    SampleCaseError,
    create_sample_case,
)

TOKEN = "audit-token-0123456789abcdef"
ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
CASE_DB_ROOTS_ENV = "RAPIDTRIAGE_CASE_DB_ROOTS"
SECRET = "synthetic-audit-secret-7f3a"


def png_bytes() -> bytes:
    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (4, 4), (200, 10, 10)).save(out, format="PNG")
    return out.getvalue()


def files_under(root: Path) -> set[str]:
    return {str(path.relative_to(root)) for path in root.rglob("*")}


@contextlib.contextmanager
def chdir(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def case_insensitive_fs(folder: Path) -> bool:
    probe = folder / "CaseProbe"
    probe.mkdir()
    try:
        return (folder / "caseprobe").exists()
    finally:
        probe.rmdir()


class _Sandbox(unittest.TestCase):
    """evidence/ (input root), out/ (output root), home/ (server account home, outside both)."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.base = base
        self.evidence = base / "evidence"
        self.case_dir = self.evidence / "case1"
        (self.case_dir / "docs").mkdir(parents=True)
        (self.case_dir / "docs" / "note.txt").write_text("synthetic evidence\n", encoding="utf-8")
        self.output_root = base / "out"
        self.output_root.mkdir()
        self.home = base / "home"
        (self.home / "secrets").mkdir(parents=True)
        self.secret = self.home / "secrets" / "id_fake.txt"
        self.secret.write_text(SECRET + "\n", encoding="utf-8")
        env = mock.patch.dict(
            os.environ,
            {
                ROOTS_ENV: str(self.evidence),
                OUTPUT_ROOTS_ENV: str(self.output_root),
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "RAPIDTRIAGE_NO_BROWSER": "1",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        for key in (
            "RAPIDTRIAGE_TOKENS_FILE",
            "RAPIDTRIAGE_REVIEWER",
            "RAPIDTRIAGE_DISABLE_AUTH",
            "RAPIDTRIAGE_CASE_DB_UNRESTRICTED",
            CASE_DB_ROOTS_ENV,
        ):
            os.environ.pop(key, None)
        self.store = RunJobStore(state_path=base / "state" / "runs.json")
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def own_run(self, name: str = "run1") -> tuple[str, Path]:
        """A legitimate run inside the roots; its output folder is the caller's own."""
        response = self.client.post(
            "/api/runs",
            json={
                "root": str(self.case_dir), "mode": "fraud", "output_dir": str(self.output_root / name),
                "read_only": True, "dry_run": True, "max_file_count": 5, "wait": True,
            },
        )
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json()["status"], "completed", response.text)
        return response.json()["run_id"], Path(response.json()["summary"]["output_dir"])

    @contextlib.contextmanager
    def no_roots(self):
        saved = {key: os.environ.pop(key) for key in (ROOTS_ENV, OUTPUT_ROOTS_ENV)}
        try:
            yield
        finally:
            os.environ.update(saved)

    def legacy_run_in_evidence(self) -> tuple[str, Path]:
        """A run made before the roots were set with the old default: output inside the evidence."""
        with self.no_roots():
            legacy = self.client.post(
                "/api/runs",
                json={"root": str(self.case_dir), "mode": "fraud", "read_only": False, "dry_run": True,
                      "max_file_count": 5, "wait": True},
            )
        self.assertEqual(legacy.status_code, 202, legacy.text)
        output_dir = Path(legacy.json()["summary"]["output_dir"])
        self.assertTrue(output_dir.is_relative_to(self.evidence), output_dir)
        return legacy.json()["run_id"], output_dir


# --- ported audit tests ------------------------------------------------------------------


class CaseDbAndCatalogRootsTests(_Sandbox):
    """GAP-1: case-db / catalog roots included the server's cwd."""

    def test_catalog_add_run_cannot_create_a_dotfile_in_the_server_cwd(self) -> None:
        # The server was started from the account's home (default PowerShell / Terminal cwd).
        _, run_output = self.own_run()
        target = self.home / ".zshenv"
        with chdir(self.home):
            response = self.client.post(
                "/api/case-catalog/add-run",
                json={"catalog": str(target), "run_output": str(run_output), "case_id": "c1", "name": "n"},
            )
        self.assertIn(response.status_code, (400, 403, 422), response.text)
        self.assertFalse(target.exists(), "remote token holder created a shell start-up file in the server account's home")

    def test_case_db_paths_cannot_create_files_inside_an_evidence_root(self) -> None:
        # The server was started from the evidence folder's parent.
        before = files_under(self.evidence)
        database = self.case_dir / "planted.db"
        with chdir(self.base):
            listed = self.client.post(
                "/api/case-db/saved-searches/list", json={"database": str(database), "case_id": "c1"}
            )
            tags = self.client.get("/api/cases/c1/tags", params={"database": str(database)})
        for response in (listed, tags):
            self.assertIn(response.status_code, (400, 403, 404, 422), response.text)
        self.assertEqual(files_under(self.evidence), before, "case-db route created files inside the evidence root")

    def test_catalog_cannot_be_written_inside_an_evidence_root(self) -> None:
        _, run_output = self.own_run()
        before = files_under(self.evidence)
        with chdir(self.base):
            response = self.client.post(
                "/api/case-catalog/add-run",
                json={"catalog": str(self.case_dir / "catalog.json"), "run_output": str(run_output), "case_id": "c1"},
            )
        self.assertIn(response.status_code, (400, 403, 422), response.text)
        self.assertEqual(files_under(self.evidence), before)


class ImportRunOutputConfinementTests(_Sandbox):
    """GAP-2: import-run / add-run ``run_output`` was not confined."""

    def _crafted_summary(self, folder: Path) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        docs = folder / "docs.json"
        docs.write_text(f'{{"candidates": [{{"path": "{self.secret.as_posix()}", "kind": "text"}}]}}', encoding="utf-8")
        summary = folder / "rapidtriage-run-summary.json"
        summary.write_text(
            f'{{"command": "run", "root": "{folder.as_posix()}", "outputs": {{"docs": "{docs.as_posix()}"}}}}',
            encoding="utf-8",
        )
        return folder

    def _indexed_bodies(self, database: Path) -> list[str]:
        if not database.exists():
            return []
        with contextlib.closing(sqlite3.connect(database)) as connection:
            return [row[0] or "" for row in connection.execute("SELECT body FROM indexed_document")]

    def test_import_run_does_not_index_files_outside_the_roots(self) -> None:
        # A run summary planted anywhere the server can read (here: the account's home; in
        # practice inside collected evidence) lists a server file as a document candidate.
        _, run_output = self.own_run()
        crafted = self._crafted_summary(self.home / "planted")
        database = run_output / "audit-case.db"
        response = self.client.post(
            "/api/case-db/import-run",
            json={"database": str(database), "run_output": str(crafted), "case_id": "audit"},
        )
        self.assertIn(response.status_code, (403, 422), response.text)
        self.assertFalse(any(SECRET in body for body in self._indexed_bodies(database)), "server file outside the roots was indexed")

    def test_run_output_is_not_a_file_existence_oracle(self) -> None:
        _, run_output = self.own_run()
        database = run_output / "audit-case.db"
        answers = {}
        for label, path in {"missing": self.home / "nope", "present": self.secret}.items():
            response = self.client.post(
                "/api/case-db/import-run", json={"database": str(database), "run_output": str(path), "case_id": "audit"}
            )
            answers[label] = (response.status_code, response.json().get("detail"))
        self.assertEqual(answers["missing"], answers["present"], answers)

    # --- new ---

    def test_summary_planted_in_an_output_root_cannot_pull_outside_files_into_the_index(self) -> None:
        # Inside the output root (e.g. an extracted evidence file named like a summary): the
        # import is allowed, but the document outside the roots is never read or hashed.
        _, run_output = self.own_run()
        crafted = self._crafted_summary(run_output / "extract" / "planted")
        outside_docs = self.home / "docs.json"
        outside_docs.write_text(
            f'{{"candidates": [{{"path": "{(crafted / "x.txt").as_posix()}", "kind": "text"}}], "note": "{SECRET}"}}',
            encoding="utf-8",
        )
        database = run_output / "planted.db"
        response = self.client.post(
            "/api/case-db/import-run",
            json={"database": str(database), "run_output": str(crafted), "case_id": "planted"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["summary"]["indexed_document_count"], 1)
        self.assertFalse(any(SECRET in body for body in self._indexed_bodies(database)))
        search = self.client.post(
            "/api/case-db/search", json={"database": str(database), "case_id": "planted", "keywords": [SECRET]}
        )
        self.assertNotIn(SECRET, search.text.replace(f'"{SECRET}"', ""))  # the echoed keyword aside
        # A summary whose output file lies outside the roots: that output is dropped.
        summary = crafted / "rapidtriage-run-summary.json"
        summary.write_text(
            f'{{"command": "run", "root": "{crafted.as_posix()}", "outputs": {{"docs": "{outside_docs.as_posix()}"}}}}',
            encoding="utf-8",
        )
        response = self.client.post(
            "/api/case-db/import-run",
            json={"database": str(database), "run_output": str(crafted), "case_id": "planted2"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["summary"]["indexed_document_count"], 0)

    def test_add_run_run_output_is_confined_with_one_answer(self) -> None:
        _, run_output = self.own_run()
        catalog = run_output / "case-catalog.json"
        legacy_like = self.base / "legacy-out"
        legacy_like.mkdir()
        (legacy_like / "rapidtriage-run-summary.json").write_text('{"outputs": {}}', encoding="utf-8")
        answers = set()
        for path in (self.home / "nope", self.secret, legacy_like, self.case_dir, self.output_root / "missing"):
            response = self.client.post(
                "/api/case-catalog/add-run", json={"catalog": str(catalog), "run_output": str(path), "case_id": "c"}
            )
            answers.add((response.status_code, response.json().get("detail")))
        self.assertEqual(len(answers), 1, answers)
        self.assertEqual(next(iter(answers))[0], 422)
        self.assertFalse(catalog.exists())
        ok = self.client.post(
            "/api/case-catalog/add-run", json={"catalog": str(catalog), "run_output": str(run_output), "case_id": "c"}
        )
        self.assertEqual(ok.status_code, 200, ok.text)

    def test_load_run_summary_reads_only_bounded_regular_files(self) -> None:
        folder = self.output_root / "summaries"
        folder.mkdir()
        big = folder / "rapidtriage-run-summary.json"
        big.write_text('{"outputs": {}, "pad": "' + "x" * 64 + '"}', encoding="utf-8")
        with mock.patch.object(search_module, "RUN_SUMMARY_MAX_BYTES", 32):
            with self.assertRaises(search_module.SearchError):
                search_module.load_run_summary(folder)
        self.assertEqual(search_module.load_run_summary(folder)["outputs"], {})
        if hasattr(os, "mkfifo"):
            fifo_dir = self.output_root / "fifo"
            fifo_dir.mkdir()
            os.mkfifo(fifo_dir / "rapidtriage-run-summary.json")
            with self.assertRaises(search_module.SearchError):  # never opened (would block)
                search_module.load_run_summary(fifo_dir)
            response = self.client.post(
                "/api/case-db/import-run",
                json={"database": str(self.output_root / "f.db"), "run_output": str(fifo_dir), "case_id": "f"},
            )
            self.assertEqual(response.status_code, 422, response.text)


class ImportLegacyRunTests(_Sandbox):
    """GAP-2b: a pre-roots run's outputs were re-imported past #91's confinement."""

    def test_legacy_run_outside_the_roots_cannot_be_reimported_and_searched(self) -> None:
        (self.home / "docs").mkdir()
        (self.home / "docs" / "memo.txt").write_text(SECRET + " in the owner's own document\n", encoding="utf-8")
        with self.no_roots():
            legacy = self.client.post(  # the owner triaged his own home locally before sharing the server
                "/api/runs",
                json={"root": str(self.home / "docs"), "mode": "fraud", "output_dir": str(self.base / "legacy-out"),
                      "read_only": True, "wait": True},
            )
        self.assertEqual(legacy.status_code, 202, legacy.text)
        legacy_output = legacy.json()["summary"]["output_dir"]  # GET /api/runs lists it to every token holder
        _, run_output = self.own_run()
        database = run_output / "reimport.db"
        imported = self.client.post(
            "/api/case-db/import-run", json={"database": str(database), "run_output": legacy_output, "case_id": "re"}
        )
        search = self.client.post(
            "/api/case-db/search", json={"database": str(database), "case_id": "re", "keywords": [SECRET]}
        )
        self.assertIn(imported.status_code, (403, 422), imported.text)
        self.assertNotIn(SECRET, search.text.replace(f'"{SECRET}"', ""))


class GetRoutesDoNotWriteTests(_Sandbox):
    """GAP-3 (PR #91 re-review B4): GET routes wrote into a legacy run inside evidence."""

    def test_get_report_routes_do_not_write_into_a_run_inside_evidence(self) -> None:
        run_id, _ = self.legacy_run_in_evidence()
        before = files_under(self.evidence)
        for path in ("validation-package", "submission-manifest", "case-report/file"):
            self.client.get(f"/api/runs/{run_id}/{path}")
        self.assertEqual(sorted(files_under(self.evidence) - before), [], "GET wrote into the evidence root")

    # --- new ---

    def test_every_writing_get_route_is_refused_or_kept_in_memory(self) -> None:
        (self.case_dir / "docs" / "pic.png").write_bytes(png_bytes())
        run_id, output_dir = self.legacy_run_in_evidence()
        (output_dir / "extract" / "manual").mkdir(parents=True)
        (output_dir / "extract" / "manual" / "a.txt").write_text("x", encoding="utf-8")
        planted_db = self.case_dir / "existing.db"
        sqlite3.connect(planted_db).close()  # an empty SQLite file already in the evidence
        before = files_under(self.evidence)
        for path in (
            "validation-package", "validation-package/file", "submission-manifest", "submission-manifest/file",
            "case-report/file", "case-report/file/html", "reviewer-bundle/file", "extract/manual/file",
        ):
            with self.subTest(path=path):
                response = self.client.get(f"/api/runs/{run_id}/{path}")
                self.assertEqual(response.status_code, 403, response.text)
        thumbnail = self.client.get(
            f"/api/runs/{run_id}/source-thumbnail", params={"path": str(self.case_dir / "docs" / "pic.png")}
        )
        self.assertEqual(thumbnail.status_code, 200, thumbnail.text)
        self.assertEqual(thumbnail.headers["content-type"], "image/jpeg")
        tags = self.client.get("/api/cases/c1/tags", params={"database": str(planted_db)})
        self.assertEqual(tags.status_code, 403, tags.text)
        histogram = self.client.get(f"/api/runs/{run_id}/histogram", params={"compare": 1})
        self.assertIn(histogram.status_code, (403, 404), histogram.text)
        self.assertEqual(sorted(files_under(self.evidence) - before), [], "GET wrote into the evidence root")

    def test_runs_inside_the_output_roots_still_serve_and_cache(self) -> None:
        (self.case_dir / "docs" / "pic.png").write_bytes(png_bytes())
        run_id, output_dir = self.own_run()
        self.assertEqual(self.client.get(f"/api/runs/{run_id}/validation-package").status_code, 200)
        thumbnail = self.client.get(
            f"/api/runs/{run_id}/source-thumbnail", params={"path": str(self.case_dir / "docs" / "pic.png")}
        )
        self.assertEqual(thumbnail.status_code, 200, thumbnail.text)
        self.assertTrue(any((output_dir / "thumbs").glob("*.jpg")))


class ExtractNameTests(_Sandbox):
    """GAP-9: GET extract/{name}/file accepted '..' and zipped the whole run output."""

    def test_extract_download_name_cannot_be_dot_dot(self) -> None:
        run_id, _output_dir = self.own_run("ex")
        extract = self.client.post(f"/api/runs/{run_id}/extract",
                                   json={"rows": [{"path": str(self.case_dir / "docs" / "note.txt")}]})
        self.assertEqual(extract.status_code, 200, extract.text)
        response = self.client.get(f"/api/runs/{run_id}/extract/%2E%2E/file")
        names = []
        if response.status_code == 200:
            names = zipfile.ZipFile(io.BytesIO(response.content)).namelist()
        self.assertIn(response.status_code, (400, 404, 422), names[:5])

    # --- new ---

    def test_only_a_direct_extract_folder_is_zipped(self) -> None:
        run_id, output_dir = self.own_run("ex2")
        extract = self.client.post(f"/api/runs/{run_id}/extract",
                                   json={"rows": [{"path": str(self.case_dir / "docs" / "note.txt")}]})
        self.assertEqual(extract.status_code, 200, extract.text)
        for name in ("%2E", "%2e%2e", "..", "nope"):
            with self.subTest(name=name):
                response = self.client.get(f"/api/runs/{run_id}/extract/{name}/file")
                self.assertIn(response.status_code, (400, 404), response.text[:200])
        self.assertFalse((output_dir / "extract.zip").exists())
        self.assertFalse((output_dir / "..zip").exists())
        good = self.client.get(extract.json()["download_url"])
        self.assertEqual(good.status_code, 200, good.text[:200])
        names = zipfile.ZipFile(io.BytesIO(good.content)).namelist()
        self.assertTrue(names)
        self.assertFalse(any("analyses" in name or "rapidtriage-run-summary" in name for name in names), names)


class MergeIntegrityTests(_Sandbox):
    """#89 (async wait) + #92 (owner) + #91 (confine before identify) after the merge."""

    def _tokens_app(self) -> TestClient:
        tokens = self.base / "tokens"
        tokens.write_text("kim=tok-kim-0123456789abcdefghij\n", encoding="utf-8")
        tokens.chmod(0o600)
        app = create_app(self.store, tokens_file=tokens, cases_db_path=self.base / "ws" / "cases.db")
        return TestClient(app, headers={"X-RapidTriage-Token": "tok-kim-0123456789abcdefghij"})

    def test_wait_true_run_and_case_run_record_the_token_owner(self) -> None:
        client = self._tokens_app()
        run = client.post(
            "/api/runs",
            json={"root": str(self.case_dir), "mode": "fraud", "output_dir": str(self.output_root / "k1"),
                  "dry_run": True, "max_file_count": 5, "wait": True},
        )
        self.assertEqual(run.status_code, 202, run.text)
        self.assertEqual(run.json()["owner"], "kim")
        case = client.post("/api/cases", json={"case_number": "AUD-1", "examiner": "x"})
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["case"]["case_id"]
        evidence = client.post(
            f"/api/cases/{case_id}/evidence",
            json={"evidence_number": "E1", "source_type": "folder", "path": str(self.case_dir), "verify_hash": False},
        )
        self.assertEqual(evidence.status_code, 201, evidence.text)
        case_run = client.post(
            f"/api/cases/{case_id}/runs",
            json={"evidence_citation_id": evidence.json()["evidence"]["citation_id"], "mode": "fraud",
                  "output_dir": str(self.output_root / "k2"), "dry_run": True, "max_file_count": 5, "wait": True},
        )
        self.assertEqual(case_run.status_code, 202, case_run.text)
        self.assertEqual(case_run.json()["run"]["owner"], "kim")

    def test_run_root_is_confined_before_the_evidence_is_identified(self) -> None:
        from rapidtriage.api.app import helpers

        with mock.patch.object(helpers, "identify_evidence", wraps=helpers.identify_evidence) as identify:
            response = self.client.post(
                "/api/runs", json={"root": str(self.secret), "mode": "fraud", "output_dir": str(self.output_root / "x")}
            )
        self.assertEqual(response.status_code, 422, response.text)
        identify.assert_not_called()


# --- GAP-1: case-db / catalog roots and names ------------------------------------------


class CaseDbRootsAndNamesTests(_Sandbox):
    def _catalog(self, path: Path):
        return self.client.get("/api/case-catalog", params={"catalog": str(path)})

    def _database(self, path: Path):
        return self.client.post("/api/case-db/saved-searches/list", json={"database": str(path), "case_id": "c1"})

    def test_cwd_and_the_rest_of_dot_rapidtriage_are_not_roots(self) -> None:
        plugins = self.home / ".rapidtriage" / "plugins"
        with chdir(self.home):
            for path in (self.home / "case-catalog.json", plugins / "x.json", self.home / ".rapidtriage" / "c.json"):
                with self.subTest(path=path):
                    response = self._catalog(path)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertIn("outside allowed case-db roots", response.json()["detail"])
            for path in (self.home / "case.db", plugins / "x.db"):
                with self.subTest(path=path):
                    self.assertEqual(self._database(path).status_code, 403)
        self.assertFalse(plugins.exists())
        self.assertFalse((self.home / "case.db").exists())

    def test_dedicated_folder_default_catalog_and_run_outputs_are_allowed(self) -> None:
        _, run_output = self.own_run()
        cases = self.home / ".rapidtriage" / "cases"
        self.assertEqual(self._catalog(cases / "office.json").status_code, 200)
        self.assertEqual(self._catalog(self.home / ".rapidtriage" / "case-catalog.json").status_code, 200)
        for name in ("a.db", "b.sqlite", "c.SQLITE3", "rapidtriage-case.db"):
            with self.subTest(name=name):
                self.assertEqual(self._database(cases / name).status_code, 200)
        self.assertEqual(self._database(run_output / "mine.db").status_code, 200)

    def test_file_names_are_restricted(self) -> None:
        cases = self.home / ".rapidtriage" / "cases"
        for name in (".zshenv", ".hidden.json", "catalog.txt", "x.json.bat", "noext"):
            with self.subTest(catalog=name):
                self.assertEqual(self._catalog(cases / name).status_code, 403)
        for name in (".hidden.db", "case.json", "case.db.bat", "x.txt", "noext"):
            with self.subTest(database=name):
                self.assertEqual(self._database(cases / name).status_code, 403)
        self.assertFalse(cases.exists())

    def test_symlinked_name_is_checked_on_its_target_too(self) -> None:
        cases = self.home / ".rapidtriage" / "cases"
        cases.mkdir(parents=True)
        try:
            (cases / "ok.json").symlink_to(cases / ".zshenv")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self.assertEqual(self._catalog(cases / "ok.json").status_code, 403)

    def test_case_db_roots_entry_over_evidence_is_still_refused_per_request(self) -> None:
        before = files_under(self.evidence)
        with mock.patch.dict(os.environ, {CASE_DB_ROOTS_ENV: str(self.evidence)}):
            response = self._database(self.case_dir / "x.db")
            catalog = self._catalog(self.case_dir / "x.json")
        self.assertEqual(response.status_code, 403, response.text)
        self.assertIn("evidence root", response.json()["detail"])
        self.assertEqual(catalog.status_code, 403, catalog.text)
        self.assertEqual(files_under(self.evidence), before)

    def test_ensure_of_a_legacy_run_in_evidence_is_refused(self) -> None:
        run_id, _ = self.legacy_run_in_evidence()
        before = files_under(self.evidence)
        response = self.client.post(f"/api/runs/{run_id}/case-db/ensure", json={})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(files_under(self.evidence), before)

    def test_startup_refuses_case_db_roots_overlapping_evidence(self) -> None:
        for entry in (str(self.evidence), str(self.case_dir / "db"), str(self.base)):
            with self.subTest(entry=entry), mock.patch.dict(os.environ, {CASE_DB_ROOTS_ENV: entry}):
                with self.assertRaises(RuntimeError) as raised:
                    require_server_roots("--remote")
                self.assertIn(CASE_DB_ROOTS_ENV, str(raised.exception))
        with mock.patch.dict(os.environ, {CASE_DB_ROOTS_ENV: str(self.base / "case-dbs")}):
            require_server_roots("--remote")


# --- #91 follow-ups: root aliases, Windows prefixes, sample deletion ----------------------


class RootAliasTests(unittest.TestCase):
    """PR #91 re-review B2: case-insensitive and NFC/NFD aliases of an evidence root."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        if not case_insensitive_fs(self.base):
            self.skipTest("case-sensitive file system: no case aliases")

    def test_case_alias_overlaps(self) -> None:
        (self.base / "evidence").mkdir()
        self.assertTrue(local_paths.overlapping_roots([str(self.base / "evidence")], [str(self.base / "EVIDENCE" / "x")]))
        self.assertTrue(local_paths.overlapping_roots([str(self.base / "EVIDENCE" / "sub")], [str(self.base / "evidence")]))
        self.assertFalse(local_paths.overlapping_roots([str(self.base / "evidence")], [str(self.base / "out")]))

    def test_unicode_normalization_alias_overlaps(self) -> None:
        nfc = unicodedata.normalize("NFC", "증거")
        nfd = unicodedata.normalize("NFD", "증거")
        self.assertNotEqual(nfc, nfd)
        (self.base / nfc).mkdir()
        if not (self.base / nfd).exists():
            self.skipTest("file system does not treat NFC/NFD names as one folder")
        self.assertTrue(local_paths.overlapping_roots([str(self.base / nfc)], [str(self.base / nfd / "x")]))

    def test_request_output_inside_an_aliased_evidence_root_is_refused(self) -> None:
        evidence = self.base / "evidence"
        evidence.mkdir()
        with mock.patch.dict(os.environ, {ROOTS_ENV: str(evidence), OUTPUT_ROOTS_ENV: str(self.base)}):
            with self.assertRaises(HTTPException) as raised:
                checked_output_path(str(self.base / "EVIDENCE" / "run"), label="out")
            self.assertEqual(raised.exception.status_code, 422)
            self.assertEqual(checked_output_path(str(self.base / "out" / "run"), label="out"), str(self.base / "out" / "run"))


class WindowsExtendedPrefixTests(unittest.TestCase):
    """PR #91 delta note: ``\\\\?\\``, ``\\\\?\\UNC\\`` and ``\\\\.\\`` resolved keys name the same folder."""

    def _overlaps(self, evidence: str, output: str, realpaths: dict[str, str]) -> bool:
        def fake_realpath(path, *args, **kwargs):
            return realpaths.get(path, ntpath.abspath(path))

        with mock.patch.object(local_paths, "os", types.SimpleNamespace(name="nt", path=ntpath)), \
                mock.patch.object(ntpath, "realpath", fake_realpath):
            return bool(local_paths.overlapping_roots([evidence], [output]))

    def test_prefixed_resolved_keys_overlap(self) -> None:
        cases = [
            (r"C:\Cases\evidence", r"D:\link", {r"D:\link": r"\\?\C:\Cases\evidence\out"}),
            (r"C:\Cases\evidence", r"D:\link", {r"D:\link": r"\\.\C:\Cases\evidence\out"}),
            (r"C:\Cases\evidence", r"D:\link", {r"D:\link": r"\\?\c:\CASES"}),
            (r"E:\mapped\ev", r"D:\out", {r"E:\mapped\ev": r"\\?\UNC\srv\share\ev", r"D:\out": r"\\srv\share\ev\out"}),
        ]
        for evidence, output, realpaths in cases:
            with self.subTest(realpaths=realpaths):
                self.assertTrue(self._overlaps(evidence, output, realpaths))

    def test_prefixed_keys_on_other_drives_do_not_overlap(self) -> None:
        self.assertFalse(self._overlaps(r"C:\Cases\evidence", r"D:\link", {r"D:\link": r"\\?\D:\out"}))
        self.assertFalse(
            self._overlaps(r"C:\Cases\evidence", r"D:\link", {r"D:\link": r"\\?\UNC\srv\share\evidence"})
        )


class SampleCaseMarkerTests(unittest.TestCase):
    """PR #91 re-review B5: only the marker file makes a folder a replaceable sample."""

    def test_expected_results_file_alone_does_not_allow_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "planted"
            planted.mkdir()
            (planted / SAMPLE_EXPECTED_NAME).write_text(f'{{"sample_root": "{planted.as_posix()}"}}', encoding="utf-8")
            (planted / "keep.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(SampleCaseError):
                create_sample_case(planted, overwrite=True)
            self.assertTrue((planted / "keep.txt").is_file())

    def test_a_marked_sample_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample"
            create_sample_case(sample)
            (sample / "stale.txt").write_text("old", encoding="utf-8")
            create_sample_case(sample, overwrite=True)
            self.assertFalse((sample / "stale.txt").exists())
            self.assertTrue((sample / SAMPLE_EXPECTED_NAME).is_file())


if __name__ == "__main__":
    unittest.main()
