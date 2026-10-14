"""Search index build (plan search-2026-10-13 §3.0): documents, domains, times, incremental, stale."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from rapidtriage.core.search_index.build import (
    BuildCancelled,
    BuildHooks,
    build_search_index,
    index_meta,
    stale_reasons,
    ts_family,
)
from rapidtriage.core.search_index.schema import (
    BUILDING_SUFFIX,
    INDEX_FILE_NAME,
    detect_tokenizer,
)
from tests.search_index_fixture import EXPECTED_DOCS, build_fixture_run, write_analysis

REPO_ROOT = Path(__file__).resolve().parent.parent


class SearchIndexBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name)
        cls.fixture = build_fixture_run(cls.base)
        cls.run_dir = cls.fixture["run_dir"]
        cls.summary = cls.fixture["summary"]
        cls.progress: list[str] = []
        cls.totals: list[int] = []
        cls.result = build_search_index(
            cls.run_dir,
            cls.summary,
            run_id="fixture",
            hooks=BuildHooks(set_total=cls.totals.append, advance=cls.progress.append),
        )
        cls.index = cls.run_dir / INDEX_FILE_NAME

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def query(self, sql: str, params: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
        connection = sqlite3.connect(self.index)
        try:
            return connection.execute(sql, params).fetchall()
        finally:
            connection.close()

    def test_doc_counts_and_domains(self) -> None:
        self.assertEqual(self.result["doc_count"], EXPECTED_DOCS)
        self.assertEqual(sum(self.result["by_domain"].values()), EXPECTED_DOCS)
        self.assertEqual(self.result["by_domain"]["eventlog"], 4)
        self.assertEqual(self.result["by_domain"]["devices"], 1)  # USB device routed like the tree
        self.assertEqual(self.result["tokenizer"], detect_tokenizer())
        self.assertGreater(self.result["db_bytes"], 0)
        primaries = self.query("SELECT COUNT(*) FROM search_doc WHERE doc_id = group_id")[0][0]
        self.assertEqual(primaries, EXPECTED_DOCS)
        collections = dict(self.query("SELECT collection, COUNT(*) FROM search_doc WHERE doc_id = group_id GROUP BY 1"))
        self.assertEqual(collections, {"docs": 1, "files": 5, "artifacts": 9, "indicators": 2, "analysis": 2})

    def test_progress_units_and_atomic_replace(self) -> None:
        # timeline + docs + files + 4 kinds + indicators + 1 analysis
        self.assertEqual(self.totals, [9])
        self.assertEqual(len(self.progress), 9)
        self.assertFalse(self.index.with_name(self.index.name + BUILDING_SUFFIX).exists())

    def test_locators_follow_the_review_map(self) -> None:
        rows = set(self.query("SELECT collection, kind, locator FROM search_doc"))
        for expected in (
            ("docs", "", "/candidates/0"),
            ("files", "", "/candidates/1"),
            ("files", "", "/inventory/0"),
            ("artifacts", "eventlog", "/artifacts/2"),
            ("artifacts", "windows-shellbags", "/artifacts/0"),
            ("indicators", "", "/indicators/0"),
            ("analysis", "20251013T000000-aaaaaaaa", "/rows/1"),
        ):
            self.assertIn(expected, rows)

    def test_eventlog_text_has_event_data_pairs_and_fields(self) -> None:
        text = self.query("SELECT text FROM search_doc WHERE kind = 'eventlog' AND locator = '/artifacts/0'")[0][0]
        self.assertIn("LogonType=10", text)
        self.assertIn("IpAddress=10.1.2.3", text)
        self.assertNotIn("WorkstationName=-", text)  # empty values are not indexed
        # The profile-hoisted provider is restored by expand_profile.
        self.assertIn("Microsoft-Windows-Security-Auditing", text)
        fields = dict(self.query("SELECT name, value_fold FROM search_field WHERE doc_id = (SELECT doc_id FROM search_doc WHERE kind='eventlog' AND locator='/artifacts/0')"))
        self.assertEqual(fields["eventid"], "4624")
        self.assertEqual(fields["channel"], "security")

    def test_timestamps_duplicate_rows_with_same_locator(self) -> None:
        rows = self.query(
            "SELECT doc_id, group_id, ts_kind, text IS NULL FROM search_doc WHERE kind = 'windows-shellbags' ORDER BY ts"
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual([row[2] for row in rows], ["item-created", "item-accessed"])
        self.assertEqual(rows[0][1], rows[1][1])  # same group
        self.assertEqual([row[3] for row in rows], [0, 1])  # text only on the primary row
        labels = self.query("SELECT ts_kind, ts_labels, ts_family FROM search_doc WHERE artifact_type = 'windows-usb-device'")[0]
        self.assertEqual(labels, ("last-arrival", "last-written", "other"))
        self.assertEqual(ts_family("last-written"), "last_written")
        self.assertEqual(ts_family("run-3"), "run")

    def test_documents_carry_body_and_metadata(self) -> None:
        text = self.query("SELECT text FROM search_doc WHERE collection = 'docs'")[0][0]
        self.assertIn("공제 내역", text)  # body (re-extracted: no case DB in the fixture)
        self.assertIn("김경리", text)
        names = {row[0] for row in self.query("SELECT name FROM search_field WHERE doc_id = 1")}
        self.assertEqual(names, {"author", "last_saved_by", "template"})

    def test_hashes_from_files_documents_indicators_and_analysis_rows(self) -> None:
        exe = self.fixture["exe_hashes"]
        owners = self.query("SELECT d.collection FROM search_hash h JOIN search_doc d ON d.doc_id = h.doc_id WHERE h.value = ?", (exe["sha256"],))
        self.assertEqual(sorted(row[0] for row in owners), ["files", "indicators"])
        carve = self.query("SELECT d.collection FROM search_hash h JOIN search_doc d ON d.doc_id = h.doc_id WHERE h.value = ?", (self.fixture["carve_hash"],))
        self.assertEqual(carve, [("analysis",)])
        doc_md5 = self.query("SELECT COUNT(*) FROM search_hash WHERE algorithm = 'md5' AND value = ?", (self.fixture["doc_hashes"]["md5"],))
        self.assertEqual(doc_md5[0][0], 2)  # the file and the generic-documents row (its own subject file)
        # Container rows (EVTX events) never carry the container's hash.
        self.assertEqual(self.query("SELECT COUNT(*) FROM search_hash h JOIN search_doc d ON d.doc_id = h.doc_id WHERE d.kind = 'eventlog'")[0][0], 0)

    def test_evidence_paths_and_flags(self) -> None:
        path, fold, ext = self.query("SELECT path, path_fold, ext FROM search_doc WHERE collection='files' AND locator='/candidates/1'")[0]
        self.assertEqual(path, "\\Users\\bsh\\Downloads\\AnyDesk.exe")
        self.assertEqual(fold, "/users/bsh/downloads/anydesk.exe")
        self.assertEqual(ext, "exe")
        flags = {row[0]: (row[1], row[2]) for row in self.query("SELECT locator, deleted, sig_mismatch FROM search_doc WHERE collection='files'")}
        self.assertEqual(flags["/candidates/2"], (1, 0))
        self.assertEqual(flags["/candidates/3"], (0, 1))

    def test_meta_tz_and_status(self) -> None:
        meta = index_meta(self.index)
        assert meta is not None
        self.assertEqual(meta["tz"], "+09:00")
        self.assertEqual(meta["tz_source"], "registry")
        self.assertEqual(meta["run_id"], "fixture")
        self.assertEqual([item["analysis_id"] for item in meta["analyses_indexed"]], ["20251013T000000-aaaaaaaa"])
        self.assertEqual(stale_reasons(meta, self.summary, self.run_dir), [])


class SearchIndexMutationTests(unittest.TestCase):
    """Builds that change the fixture: each test gets its own run."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = build_fixture_run(Path(self.temp.name))
        self.run_dir = self.fixture["run_dir"]
        self.summary = self.fixture["summary"]
        self.index = self.run_dir / INDEX_FILE_NAME

    def count(self, sql: str, params: tuple[object, ...] = ()) -> int:
        connection = sqlite3.connect(self.index)
        try:
            return int(connection.execute(sql, params).fetchone()[0])
        finally:
            connection.close()

    def test_incremental_adds_and_replaces_analysis_rows(self) -> None:
        build_search_index(self.run_dir, self.summary)
        build_id = index_meta(self.index)["build_id"]
        write_analysis(self.run_dir, "20251014T000000-bbbbbbbb", "ntfs-meta", [
            {"artifact_type": "ntfs-meta-row", "path": "C:\\x\\gone.txt", "details": {"path": "\\x\\gone.txt", "in_use": False, "created_at": "2025-05-01T00:00:00+00:00"}},
        ])
        meta = index_meta(self.index)
        self.assertIn("색인에 없는 분석 결과가 있습니다(1개)", stale_reasons(meta, self.summary, self.run_dir))
        result = build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=["20251014T000000-bbbbbbbb"])
        self.assertEqual(result["mode"], "incremental")
        self.assertEqual(result["doc_count"], EXPECTED_DOCS + 1)
        meta = index_meta(self.index)
        self.assertEqual(meta["build_id"], build_id)  # same build, rows appended
        self.assertEqual(stale_reasons(meta, self.summary, self.run_dir), [])
        self.assertEqual(self.count("SELECT COUNT(*) FROM search_doc WHERE analysis_id = ? AND deleted = 1", ("20251014T000000-bbbbbbbb",)), 1)
        # FTS sees the new row; re-running replaces instead of duplicating.
        self.assertEqual(self.count("SELECT COUNT(*) FROM search_text WHERE text LIKE '%gone.txt%'"), 1)
        build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=["20251014T000000-bbbbbbbb"])
        self.assertEqual(self.count("SELECT COUNT(*) FROM search_doc WHERE analysis_id = ?", ("20251014T000000-bbbbbbbb",)), 1)
        self.assertEqual(self.count("SELECT COUNT(*) FROM search_text WHERE text LIKE '%gone.txt%'"), 1)

    def test_incremental_without_index_builds_everything(self) -> None:
        result = build_search_index(self.run_dir, self.summary, mode="incremental", analysis_ids=["x"])
        self.assertEqual(result["mode"], "full")
        self.assertEqual(result["doc_count"], EXPECTED_DOCS)

    def test_stale_when_an_output_changes(self) -> None:
        build_search_index(self.run_dir, self.summary)
        meta = index_meta(self.index)
        target = Path(self.summary["outputs"]["files"])
        stamp = time.time() + 5
        os.utime(target, (stamp, stamp))
        reasons = stale_reasons(meta, self.summary, self.run_dir)
        self.assertEqual(reasons, ["색인한 뒤 바뀐 출력 파일이 있습니다(1개)"])
        changed = {**self.summary, "outputs": {**self.summary["outputs"], "extra": "x"}}
        self.assertIn("런 출력 목록이 바뀌었습니다", stale_reasons(meta, changed, self.run_dir))

    def test_cancel_removes_building_file_and_keeps_old_index(self) -> None:
        build_search_index(self.run_dir, self.summary)
        old_build = index_meta(self.index)["build_id"]
        calls = {"n": 0}

        def cancel() -> None:
            calls["n"] += 1
            if calls["n"] > 3:
                raise BuildCancelled()

        with self.assertRaises(BuildCancelled):
            build_search_index(self.run_dir, self.summary, hooks=BuildHooks(check_cancel=cancel))
        self.assertFalse(self.index.with_name(self.index.name + BUILDING_SUFFIX).exists())
        self.assertEqual(index_meta(self.index)["build_id"], old_build)

    def test_old_index_readable_during_build(self) -> None:
        build_search_index(self.run_dir, self.summary)
        seen: list[int] = []

        def peek(_message: str) -> None:
            connection = sqlite3.connect(f"{self.index.resolve().as_uri()}?mode=ro", uri=True)
            try:
                seen.append(int(connection.execute("SELECT COUNT(*) FROM search_doc").fetchone()[0]))
            finally:
                connection.close()

        build_search_index(self.run_dir, self.summary, hooks=BuildHooks(advance=peek))
        self.assertTrue(seen)
        self.assertTrue(all(count == 20 for count in seen))

    def test_cli_search_index_command(self) -> None:
        output = Path(self.temp.name) / "cli-index.db"
        completed = subprocess.run(
            [sys.executable, "-m", "rapidtriage", "search-index", str(self.run_dir), "--output", str(output), "--json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=600,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["doc_count"], EXPECTED_DOCS)
        self.assertTrue(output.is_file())
        self.assertFalse(self.index.exists())


if __name__ == "__main__":
    unittest.main()
