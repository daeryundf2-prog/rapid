"""Remote-use path confinement (remote review R1, R2, R10; fixes 1 and 2; PR #91 review F1-F3, R-A-R-C).

Synthetic trees only: an evidence root, an output root, and a fake home with a
fake secret outside both. ``RAPIDTRIAGE_ANALYSIS_ROOTS`` /
``RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS`` are the operator's server roots; ``--remote``
and every other non-loopback bind refuse to start without them.
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
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
    from rapidtriage.api.app.helpers import allowed_case_db_roots
from rapidtriage.cli import run_web_server
from rapidtriage.core import files as files_module
from rapidtriage.core.docs import scan_document_candidates
from rapidtriage.core.files import iter_evidence_paths
from rapidtriage.core.jobs import RunJobStore

TOKEN = "remote-path-test-token"
ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
SECRET = "synthetic secret: not real\n"


def files_under(root: Path) -> set[str]:
    return {str(path.relative_to(root)) for path in root.rglob("*") if not path.is_symlink()}


def symlink_or_skip(test: unittest.TestCase, link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:
        test.skipTest(f"symlinks unavailable: {exc}")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class RemotePathConfinementTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.evidence = base / "evidence"
        self.case_dir = self.evidence / "case1"
        (self.case_dir / "docs").mkdir(parents=True)
        (self.case_dir / "docs" / "note.txt").write_text("synthetic evidence\n", encoding="utf-8")
        self.output_root = base / "out"
        self.output_root.mkdir()
        self.home = base / "home"
        (self.home / "secrets").mkdir(parents=True)
        self.secret = self.home / "secrets" / "id_fake.txt"
        self.secret.write_text(SECRET, encoding="utf-8")
        self.store = RunJobStore()
        self.client = TestClient(
            create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN}
        )
        self.roots = {ROOTS_ENV: str(self.evidence), OUTPUT_ROOTS_ENV: str(self.output_root)}

    def _roots(self):
        return patch.dict(os.environ, self.roots)

    def _no_roots(self):
        saved = {key: os.environ.pop(key) for key in (ROOTS_ENV, OUTPUT_ROOTS_ENV) if key in os.environ}
        self.addCleanup(os.environ.update, saved)
        return contextlib.nullcontext()

    def _run(self, root: Path, output_dir: Path | None, **extra) -> object:
        body = {"root": str(root), "mode": "fraud", "read_only": True, "dry_run": True, "max_file_count": 5, "wait": True}
        if output_dir is not None:
            body["output_dir"] = str(output_dir)
        body.update(extra)
        return self.client.post("/api/runs", json=body)

    # --- fix 1: run inputs / outputs (R1, R10) ------------------------------------

    def test_run_root_outside_analysis_roots_is_422_and_no_run(self) -> None:
        with self._roots():
            response = self._run(self.home, self.output_root / "attack")
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("허용 범위", response.json()["detail"])
        self.assertEqual(self.store.list(), [])
        self.assertFalse((self.output_root / "attack").exists())

    def test_large_folder_outside_roots_is_refused_before_any_scan(self) -> None:
        # R3 repro used a 40k-file tree with wait:true; outside the roots it never reaches the scanner.
        big = self.home / "big"
        for index in range(50):
            folder = big / f"d{index:02d}"
            folder.mkdir(parents=True)
            for name in range(40):
                (folder / f"f{name}.txt").write_text("x", encoding="utf-8")
        with self._roots(), patch("rapidtriage.core.jobs.execute_run_request") as execute:
            started = time.monotonic()
            response = self._run(big, self.output_root / "big", dry_run=False, max_file_count=0)
            elapsed = time.monotonic() - started
        self.assertEqual(response.status_code, 422, response.text)
        execute.assert_not_called()
        self.assertEqual(self.store.list(), [])
        self.assertLess(elapsed, 5.0)

    def test_output_dir_outside_output_roots_is_422(self) -> None:
        with self._roots():
            explicit = self._run(self.case_dir, self.home / "out")
            inside_evidence = self._run(self.case_dir, self.evidence / "out")
            default_next_to_evidence = self._run(self.case_dir, None)
        for response in (explicit, inside_evidence):
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn("허용 범위", response.json()["detail"])
        self.assertEqual(default_next_to_evidence.status_code, 422, default_next_to_evidence.text)
        self.assertIn(OUTPUT_ROOTS_ENV, default_next_to_evidence.json()["detail"])
        self.assertEqual(self.store.list(), [])
        self.assertFalse((self.evidence / "out").exists())

    def test_rules_and_known_good_feeds_outside_roots_are_422(self) -> None:
        with self._roots():
            rules = self._run(self.case_dir, self.output_root / "r1", rules=str(self.secret))
            feeds = self._run(self.case_dir, self.output_root / "r2", known_good_hash_feeds=[str(self.secret)])
        for response in (rules, feeds):
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.store.list(), [])

    def test_run_inside_roots_is_accepted_and_serves_its_evidence(self) -> None:
        with self._roots():
            response = self._run(self.case_dir, self.output_root / "run1")
            self.assertEqual(response.status_code, 202, response.text)
            run_id = response.json()["run_id"]
            inside = self.client.get(
                f"/api/runs/{run_id}/source-file", params={"path": str(self.case_dir / "docs" / "note.txt")}
            )
            outside = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.secret)})
        self.assertEqual(inside.status_code, 200, inside.text)
        self.assertEqual(outside.status_code, 403, outside.text)

    def test_run_registered_before_roots_cannot_read_outside_files(self) -> None:
        # R1 repro: root=<fake home> → source-file of the fake secret was 200.
        with self._no_roots():
            legacy = self._run(self.home, self.home.parent / "legacy-out")
            self.assertEqual(legacy.status_code, 202, legacy.text)
            run_id = legacy.json()["run_id"]
            before = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.secret)})
            self.assertEqual(before.status_code, 200)
            self.assertEqual(before.text, SECRET)
        with self._roots():
            after = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": str(self.secret)})
            retry = self.client.post(f"/api/runs/{run_id}/retry", json={})
            case_db_roots = allowed_case_db_roots(self.store)
        self.assertEqual(after.status_code, 403, after.text)
        self.assertNotIn(SECRET, after.text)
        self.assertEqual(retry.status_code, 422, retry.text)
        self.assertNotIn((self.home.parent / "legacy-out").resolve(), case_db_roots)

    @unittest.skipUnless(os.name == "posix" and Path("/etc/hosts").is_file(), "POSIX /etc/hosts")
    def test_etc_dry_run_is_refused_and_an_older_etc_run_gets_403(self) -> None:
        # R1 repro: {"root":"/etc","dry_run":true,"max_file_count":5,"wait":true} → source-file /etc/hosts 200.
        with self._roots():
            refused = self._run(Path("/etc"), self.output_root / "etc")
        self.assertEqual(refused.status_code, 422, refused.text)
        with self._no_roots():
            legacy = self._run(Path("/etc"), self.home.parent / "out-etc")
            self.assertEqual(legacy.status_code, 202, legacy.text)
            run_id = legacy.json()["run_id"]
        with self._roots():
            response = self.client.get(f"/api/runs/{run_id}/source-file", params={"path": "/etc/hosts"})
        self.assertEqual(response.status_code, 403, response.text)

    def test_import_outside_roots_is_422(self) -> None:
        with self._no_roots():
            legacy = self._run(self.home, self.home / "run-out")
            self.assertEqual(legacy.status_code, 202, legacy.text)
        with self._roots():
            response = self.client.post("/api/runs/import", json={"output_dir": str(self.home / "run-out")})
        self.assertEqual(response.status_code, 422, response.text)

    def test_identify_collect_plan_and_readiness_paths_outside_roots_are_422(self) -> None:
        with self._roots():
            identify = self.client.post("/api/evidence/identify", json={"path": str(self.secret)})
            plan = self.client.post("/api/collect/plan", json={"root": str(self.home)})
            package = self.client.get("/api/commercial-readiness", params={"validation_package": str(self.home / "p.json")})
            mac = self.client.get("/api/commercial-readiness", params={"mac_first_evidence": str(self.home)})
            inside = self.client.post("/api/evidence/identify", json={"path": str(self.case_dir)})
        for response in (identify, plan, package, mac):
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(inside.status_code, 200, inside.text)

    # --- fix 2: /api/browse (R2) ------------------------------------------------------

    def test_browse_lists_only_server_roots(self) -> None:
        with self._roots():
            top = self.client.get("/api/browse")
            filesystem_root = self.client.get("/api/browse", params={"path": os.path.abspath(os.sep)})
            home = self.client.get("/api/browse", params={"path": str(self.home)})
            inside = self.client.get("/api/browse", params={"path": str(self.evidence)})
        self.assertEqual(top.status_code, 200, top.text)
        listing = top.json()
        self.assertTrue(listing["at_roots"])
        self.assertEqual(listing["home"], "")
        self.assertEqual({entry["path"] for entry in listing["entries"]}, {str(self.evidence), str(self.output_root)})
        self.assertEqual({root["path"] for root in listing["roots"]}, {str(self.evidence), str(self.output_root)})
        self.assertEqual(filesystem_root.status_code, 403, filesystem_root.text)
        self.assertEqual(home.status_code, 403, home.text)
        self.assertEqual(inside.status_code, 200, inside.text)
        self.assertEqual([entry["name"] for entry in inside.json()["entries"]], ["case1"])
        self.assertIsNone(inside.json()["parent"])
        self.assertEqual(inside.json()["home"], "")

    def test_browse_without_roots_is_unchanged_for_local_use(self) -> None:
        with self._no_roots():
            response = self.client.get("/api/browse", params={"path": str(self.home)})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("at_roots", response.json())
        self.assertEqual([entry["name"] for entry in response.json()["entries"]], ["secrets"])

    # --- PR #91 review F2: import and writes into evidence -----------------------------

    def _legacy_run_inside_evidence(self) -> tuple[str, Path]:
        # The old API default (read_only=false, no output_dir) writes the run into the evidence folder.
        with self._no_roots():
            legacy = self._run(self.case_dir, None, read_only=False)
        self.assertEqual(legacy.status_code, 202, legacy.text)
        output_dir = Path(legacy.json()["summary"]["output_dir"]).resolve()
        self.assertTrue(output_dir.is_relative_to(self.evidence.resolve()), output_dir)
        return legacy.json()["run_id"], output_dir

    def test_import_of_a_run_folder_inside_evidence_is_422(self) -> None:
        run_id, output_dir = self._legacy_run_inside_evidence()
        self.store.remove(run_id)
        before = files_under(self.evidence)
        with self._roots():
            response = self.client.post("/api/runs/import", json={"output_dir": str(output_dir)})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn(OUTPUT_ROOTS_ENV, response.json()["detail"])
        self.assertEqual(self.store.list(), [])
        self.assertEqual(files_under(self.evidence), before)

    def test_writes_into_a_legacy_run_inside_evidence_are_403(self) -> None:
        run_id, _output_dir = self._legacy_run_inside_evidence()
        before = files_under(self.evidence)
        note = str(self.case_dir / "docs" / "note.txt")
        with self._roots():
            extract = self.client.post(f"/api/runs/{run_id}/extract", json={"rows": [{"path": note}]})
            notes = self.client.put(f"/api/runs/{run_id}/case-notes", json={"examiner": "x", "summary": "remote"})
            report = self.client.post(f"/api/runs/{run_id}/case-report", json={})
            bookmark = self.client.post(
                f"/api/runs/{run_id}/bookmarks", json={"source": "files", "pointer": "/candidates/0"}
            )
            cancel = self.client.post(f"/api/runs/{run_id}/cancel")
        for response in (extract, notes, report, bookmark):
            self.assertEqual(response.status_code, 403, response.text)
            self.assertIn("런 출력 폴더", response.json()["detail"])
        self.assertNotEqual(cancel.status_code, 403, cancel.text)
        self.assertEqual(files_under(self.evidence), before)

    def test_writes_into_a_run_inside_the_output_roots_still_work(self) -> None:
        with self._roots():
            created = self._run(self.case_dir, self.output_root / "run-ok")
            self.assertEqual(created.status_code, 202, created.text)
            run_id = created.json()["run_id"]
            notes = self.client.put(f"/api/runs/{run_id}/case-notes", json={"examiner": "x", "summary": "ok"})
        self.assertEqual(notes.status_code, 200, notes.text)

    # --- PR #91 review F3: output root overlapping an evidence root --------------------

    def test_output_root_that_contains_the_evidence_root_still_refuses_evidence_output(self) -> None:
        overlap = {ROOTS_ENV: str(self.evidence), OUTPUT_ROOTS_ENV: str(self.evidence.parent)}
        with patch.dict(os.environ, overlap):
            explicit = self._run(self.case_dir, self.case_dir / "overlap-out")
            default_inside_evidence = self._run(self.case_dir, None, read_only=False)
            beside = self._run(self.case_dir, self.evidence.parent / "beside-out")
        for response in (explicit, default_inside_evidence):
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn(ROOTS_ENV, response.json()["detail"])
        self.assertEqual(beside.status_code, 202, beside.text)
        self.assertFalse((self.case_dir / "overlap-out").exists())
        self.assertEqual([path.name for path in self.case_dir.iterdir()], ["docs"])

    # --- PR #91 review R-A: sample case deleting folders -------------------------------

    def _victim(self, parent: Path) -> Path:
        victim = parent / "victim_dir"
        victim.mkdir()
        (victim / "canary.txt").write_text("canary\n", encoding="utf-8")
        return victim

    def test_sample_case_outside_output_roots_is_422_and_deletes_nothing(self) -> None:
        victim = self._victim(self.home)
        evidence_victim = self._victim(self.case_dir)
        with self._roots():
            outside = self.client.post("/api/sample-case/run", json={"output_dir": str(victim)})
            in_evidence = self.client.post("/api/sample-case/run", json={"output_dir": str(evidence_victim)})
        for response in (outside, in_evidence):
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(sorted(path.name for path in victim.iterdir()), ["canary.txt"])
        self.assertEqual(sorted(path.name for path in evidence_victim.iterdir()), ["canary.txt"])

    def test_sample_case_never_deletes_a_folder_that_is_not_a_sample(self) -> None:
        inside_roots = self._victim(self.output_root)
        with self._roots():
            confined = self.client.post("/api/sample-case/run", json={"output_dir": str(inside_roots)})
        local_victim = self._victim(self.home)
        with self._no_roots():
            local = self.client.post("/api/sample-case/run", json={"output_dir": str(local_victim)})
        for response in (confined, local):
            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn("not a sample case", response.json()["detail"])
        self.assertEqual(sorted(path.name for path in inside_roots.iterdir()), ["canary.txt"])
        self.assertEqual(sorted(path.name for path in local_victim.iterdir()), ["canary.txt"])

    def test_sample_case_defaults_into_the_output_root_and_reruns_over_itself(self) -> None:
        with self._roots():
            first = self.client.post("/api/sample-case/run", json={})
            second = self.client.post("/api/sample-case/run", json={})
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(second.status_code, 201, second.text)
        sample_root = Path(second.json()["sample"]["sample_root"])
        self.assertEqual(sample_root, (self.output_root / "rapidtriage-sample").resolve())
        self.assertTrue((sample_root / "run-output" / "rapidtriage-run-summary.json").is_file())

    # --- PR #91 review R-B: ti_feed probing server files --------------------------------

    def test_ti_feed_outside_analysis_roots_is_422_without_file_facts(self) -> None:
        with self._roots():
            created = self._run(self.case_dir, self.output_root / "ti")
            run_id = created.json()["run_id"]
            probe = self.client.get(f"/api/runs/{run_id}/indicators/ti-enrichment", params={"ti_feed": str(self.secret)})
            missing = self.client.get(
                f"/api/runs/{run_id}/indicators/ti-enrichment", params={"ti_feed": str(self.home / "absent.txt")}
            )
        for response in (probe, missing):
            self.assertEqual(response.status_code, 422, response.text)
            self.assertNotIn("sha256", response.text)
            self.assertNotIn("not found", response.text)

    # --- PR #91 review R-C: links in evidence pointing outside --------------------------

    def test_run_does_not_index_server_files_through_an_evidence_symlink(self) -> None:
        marker = "SYNTHETIC-SECRET 10.66.77.88 evil.example.com"
        self.secret.write_text(marker + "\n", encoding="utf-8")
        symlink_or_skip(self, self.case_dir / "docs" / "link_secret.txt", self.secret)
        symlink_or_skip(self, self.case_dir / "link_home", self.home)
        output = self.output_root / "full"
        with self._roots():
            response = self._run(self.case_dir, output, dry_run=False, max_file_count=0, extract=True)
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json()["status"], "completed", response.text)
        leaked = [str(path) for path in output.rglob("*") if path.is_file() and b"SYNTHETIC-SECRET" in path.read_bytes()]
        self.assertEqual(leaked, [])


class EvidenceWalkLinkTests(unittest.TestCase):
    """``iter_evidence_paths`` (cached and uncached) and document candidates stay inside the root."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name).resolve()
        self.root = base / "evidence"
        (self.root / "docs").mkdir(parents=True)
        (self.root / "docs" / "note.txt").write_text("evidence\n", encoding="utf-8")
        outside = base / "home"
        outside.mkdir()
        (outside / "secret.txt").write_text(SECRET, encoding="utf-8")
        symlink_or_skip(self, self.root / "docs" / "out_link.txt", outside / "secret.txt")
        symlink_or_skip(self, self.root / "docs" / "in_link.txt", self.root / "docs" / "note.txt")

    def test_links_leaving_the_root_are_skipped_and_links_inside_are_kept(self) -> None:
        files_module.enable_evidence_path_cache()
        try:
            cached = {path.name for path in iter_evidence_paths(self.root, "*.txt")}
        finally:
            files_module.disable_evidence_path_cache()
        uncached = {path.name for path in iter_evidence_paths(self.root, "*.txt")}
        documents = {Path(candidate.path).name for candidate in scan_document_candidates(self.root)}
        for names in (cached, uncached, documents):
            self.assertEqual(names, {"note.txt", "in_link.txt"})


class RemoteModeRequiresRootsTests(unittest.TestCase):
    KEYS = ("RAPIDTRIAGE_TOKEN", "RAPIDTRIAGE_AUTH_TOKEN", "RAPIDTRIAGE_DISABLE_AUTH", ROOTS_ENV, OUTPUT_ROOTS_ENV)

    def setUp(self) -> None:
        saved = {key: os.environ.pop(key) for key in self.KEYS if key in os.environ}

        def restore() -> None:
            for key in self.KEYS:
                os.environ.pop(key, None)
            os.environ.update(saved)

        self.addCleanup(restore)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()

    def test_remote_without_roots_refuses_to_start(self) -> None:
        with self.assertRaises(RuntimeError) as raised:
            run_web_server("127.0.0.1", 8899, remote=True, auth_token="t" * 32)
        self.assertIn(ROOTS_ENV, str(raised.exception))
        self.assertIn(OUTPUT_ROOTS_ENV, str(raised.exception))

    def test_remote_ignores_invalid_root_entries_when_checking(self) -> None:
        os.environ[ROOTS_ENV] = "relative/evidence"
        os.environ[OUTPUT_ROOTS_ENV] = str(self.base)
        with self.assertRaises(RuntimeError) as raised:
            run_web_server("127.0.0.1", 8899, remote=True, auth_token="t" * 32)
        self.assertIn(ROOTS_ENV, str(raised.exception))
        self.assertNotIn(OUTPUT_ROOTS_ENV, str(raised.exception))

    def test_remote_with_roots_starts(self) -> None:
        os.environ[ROOTS_ENV] = str(self.base / "evidence")
        os.environ[OUTPUT_ROOTS_ENV] = str(self.base / "out")
        self.assertEqual(self._start("127.0.0.1", remote=True, auth_token="t" * 32), "127.0.0.1")

    def _start(self, host: str, **kwargs: object) -> object:
        captured: dict[str, object] = {}
        fake = types.SimpleNamespace(run=lambda *args, **kw: captured.update(kw))
        with (
            patch.dict(sys.modules, {"uvicorn": fake}),
            patch.dict(os.environ, {"RAPIDTRIAGE_NO_BROWSER": "1"}),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(run_web_server(host, 8899, **kwargs), 0)
        return captured["host"]

    def test_every_non_loopback_bind_without_roots_refuses_to_start(self) -> None:
        # PR #91 review F1: the documented `--host 0.0.0.0 --auth-token` started with no roots.
        cases = [
            ("0.0.0.0", {"auth_token": "t" * 32}),
            ("192.168.0.10", {"auth_token": "t" * 32}),
            ("0.0.0.0", {"allow_remote_without_auth": True}),
        ]
        for host, kwargs in cases:
            with self.subTest(host=host, **kwargs), self.assertRaises(RuntimeError) as raised:
                self._start(host, **kwargs)
            self.assertIn(ROOTS_ENV, str(raised.exception))
            self.assertIn(OUTPUT_ROOTS_ENV, str(raised.exception))

    def test_non_loopback_bind_with_roots_starts(self) -> None:
        os.environ[ROOTS_ENV] = str(self.base / "evidence")
        os.environ[OUTPUT_ROOTS_ENV] = str(self.base / "out")
        self.assertEqual(self._start("0.0.0.0", auth_token="t" * 32), "0.0.0.0")

    def test_loopback_without_roots_is_unchanged(self) -> None:
        self.assertEqual(self._start("127.0.0.1"), "127.0.0.1")
        self.assertEqual(self._start("127.0.0.1", auth_token="t" * 32), "127.0.0.1")

    def test_overlapping_roots_refuse_to_start(self) -> None:
        evidence = self.base / "evidence"
        cases = {
            "same folder": str(evidence),
            "output root contains evidence": str(self.base),
            "output root inside evidence": str(evidence / "out"),
            "filesystem root": os.path.abspath(os.sep),
        }
        for label, output in cases.items():
            os.environ[ROOTS_ENV] = str(evidence)
            os.environ[OUTPUT_ROOTS_ENV] = output
            with self.subTest(label), self.assertRaises(RuntimeError) as raised:
                self._start("0.0.0.0", remote=True, auth_token="t" * 32)
            self.assertIn("must not be, contain, or lie inside", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
