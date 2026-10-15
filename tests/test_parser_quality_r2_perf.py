"""Parser-quality r2 (performance): case DB bulk persist, compressed artifact
data, windows-search-index early exit, synthetic-media skip/budget."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unicodedata
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts import synthetic_media
from rapidtriage.artifacts.windows import search_index
from rapidtriage.core.case_db import CaseDatabase
from rapidtriage.core.case_db.bulk_import import next_autoincrement_id
from rapidtriage.core.case_db.database import ARTIFACT_SOURCE_LOCATOR_KEY
from rapidtriage.core.case_db.schema import (
    ARTIFACT_DATA_CODEC_ZLIB,
    ARTIFACT_DATA_LOCATOR_KEY,
    artifact_data_select_sql,
    artifact_fts_is_external,
    artifact_row_data_json,
    decode_artifact_data,
    encode_artifact_data,
    register_case_db_functions,
)
from rapidtriage.core.case_db.search import search_artifacts
from rapidtriage.core.run.persist import build_run_case_db
from rapidtriage.core.search_budget import SearchBudget
from rapidtriage.core.search_fts import fts_unified_matches

NFD_NAME = unicodedata.normalize("NFD", "계약서")


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def artifacts_payload(kind: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return {"command": "artifacts", "kind": kind, "artifacts": rows}


def sample_outputs(root: Path, *, artifact_count: int = 40) -> dict[str, str]:
    evidence = root / "evidence"
    evidence.mkdir(exist_ok=True)
    doc = evidence / "a.txt"
    doc.write_text("contract body", encoding="utf-8")
    files = write_json(root / "files.json", {"command": "files", "summary": {}, "candidates": [{
        "path": str(doc), "name": "a.txt", "extension": ".txt", "size": 13, "sha256": "e" * 64,
        "categories": ["documents"], "reasons": {}}]})
    docs = write_json(root / "docs.json", {"command": "docs", "summary": {}, "candidates": [
        {"path": str(doc), "kind": "txt", "size": 13, "modified_at": ""}], "results": []})
    registry_rows = [
        {"artifact_type": "registry-key-tree-node", "provider": "windows-registry", "path": str(doc), "supported": True,
         "details": {"key_path": f"ROOT\\Software\\Vendor{index}", "note": f"needle{index % 7}",
                     "last_written_at": "2025-05-01T00:00:00+00:00"}}
        for index in range(artifact_count)
    ]
    registry_rows.append({"artifact_type": "registry-key-tree-node", "provider": "windows-registry",
                          "path": f"C:/Users/{NFD_NAME}.txt", "supported": True,
                          "details": {"key_path": f"ROOT\\{NFD_NAME}", "note": "korean"}})
    prefetch_rows = [
        {"artifact_type": "prefetch-reference", "provider": "windows-prefetch", "path": str(doc), "supported": True,
         "details": {"referenced_path": f"C:/Windows/System32/lib{index}.dll", "last_run_times": []}}
        for index in range(artifact_count // 2)
    ]
    registry = write_json(root / "registry.json", artifacts_payload("windows-registry", registry_rows))
    prefetch = write_json(root / "prefetch.json", artifacts_payload("windows-prefetch", prefetch_rows))
    events = [
        {"timestamp": "2025-05-01T00:00:00+00:00", "timestamp_kind": "written", "timezone": "UTC", "source": "artifacts",
         "event_type": "artifact-registry-key", "path": str(doc) if index % 2 else f"C:/{NFD_NAME}/x", "summary": f"s{index}",
         "details": {"source_record": {"kind": "windows-registry", "row_index": index, "output": "artifacts_windows-registry"}}}
        for index in range(artifact_count)
    ]
    timeline = write_json(root / "timeline.json", {"command": "timeline", "summary": {}, "events": events})
    return {
        "files": str(files),
        "docs": str(docs),
        "artifacts_windows-registry": str(registry),
        "artifacts_windows-prefetch": str(prefetch),
        "timeline": str(timeline),
    }


def import_outputs(db_path: Path, outputs: dict[str, str], root: Path, *, bulk: bool) -> CaseDatabase:
    database = CaseDatabase(db_path, bulk_load=bulk)
    database.initialize()
    database.import_run_output({"root": str(root / "evidence"), "outputs": outputs}, case_id="run-x", hash_files=False)
    return database


def artifact_rows(database: CaseDatabase) -> list[tuple[object, ...]]:
    with database.connect() as connection:
        rows = connection.execute(
            f"SELECT id, citation_id, artifact_type, parser_name, parser_version, title, summary, file_record_id, "
            f"{artifact_data_select_sql(connection)} FROM artifact ORDER BY id"
        ).fetchall()
    return [(*tuple(row)[:8], artifact_row_data_json(row)) for row in rows]


class CompressedArtifactDataTests(unittest.TestCase):
    def test_round_trip_and_locator_stub(self) -> None:
        locator = {"output_name": "artifacts_windows-registry", "row_index": 7}
        text = json.dumps({"details": {"k": "값"}, ARTIFACT_DATA_LOCATOR_KEY: locator}, ensure_ascii=False, sort_keys=True)
        stub, blob, codec = encode_artifact_data(text, locator=locator)
        self.assertEqual(codec, ARTIFACT_DATA_CODEC_ZLIB)
        self.assertEqual(json.loads(stub), {ARTIFACT_DATA_LOCATOR_KEY: locator})
        self.assertLess(len(blob), len(text.encode("utf-8")) + 16)
        self.assertEqual(decode_artifact_data(stub, blob, codec), text)
        self.assertEqual(decode_artifact_data(text, None, ""), text)
        self.assertEqual(artifact_row_data_json({"data_json": stub, "data_blob": blob, "data_codec": codec}), text)
        self.assertEqual(artifact_row_data_json({"data_json": text}), text)
        self.assertEqual(ARTIFACT_DATA_LOCATOR_KEY, ARTIFACT_SOURCE_LOCATOR_KEY)

    def test_sql_function_and_legacy_select_fallback(self) -> None:
        with closing(sqlite3.connect(":memory:")) as connection:
            register_case_db_functions(connection)
            stub, blob, codec = encode_artifact_data('{"a": 1}')
            value = connection.execute("SELECT rt_artifact_data(?, ?, ?)", (stub, blob, codec)).fetchone()[0]
            self.assertEqual(value, '{"a": 1}')
            self.assertEqual(connection.execute("SELECT rt_nfc(?)", (NFD_NAME,)).fetchone()[0], "계약서")
            connection.execute("CREATE TABLE artifact (id INTEGER PRIMARY KEY, data_json TEXT)")  # pre-r2 DB
            connection.execute("INSERT INTO artifact (data_json) VALUES ('{\"b\": 2}')")
            connection.row_factory = sqlite3.Row
            row = connection.execute(f"SELECT {artifact_data_select_sql(connection)} FROM artifact").fetchone()
            self.assertEqual(artifact_row_data_json(row), '{"b": 2}')


class BulkPersistEquivalenceTests(unittest.TestCase):
    def test_bulk_compressed_import_matches_legacy_rows_ids_and_search(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outputs = sample_outputs(root)
            legacy = import_outputs(root / "legacy.db", outputs, root, bulk=False)
            bulk = import_outputs(root / "bulk.db", outputs, root, bulk=True)
            with legacy.connect() as connection:
                self.assertFalse(artifact_fts_is_external(connection))
                legacy_events = connection.execute("SELECT * FROM event ORDER BY id").fetchall()
            with bulk.connect() as connection:
                self.assertTrue(artifact_fts_is_external(connection))
                codecs = {row[0] for row in connection.execute("SELECT DISTINCT data_codec FROM artifact")}
                bulk_events = connection.execute("SELECT * FROM event ORDER BY id").fetchall()
                trigger = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'artifact_fts_ai'"
                ).fetchone()
                connection.execute("INSERT INTO artifact_fts(artifact_fts, rank) VALUES ('integrity-check', 1)")
            self.assertEqual(codecs, {ARTIFACT_DATA_CODEC_ZLIB})
            self.assertIsNotNone(trigger)  # re-created after the bulk load
            self.assertEqual(artifact_rows(legacy), artifact_rows(bulk))
            self.assertEqual([tuple(row) for row in legacy_events], [tuple(row) for row in bulk_events])
            for keywords in (["needle3"], ["lib4"], ["계약서"], [NFD_NAME], ["vendor12"]):
                with legacy.connect() as left, bulk.connect() as right:
                    expected = search_artifacts(left, "run-x", keywords, 50, 1000)
                    actual = search_artifacts(right, "run-x", keywords, 50, 1000)
                self.assertTrue(expected, keywords)
                self.assertEqual(expected, actual, keywords)

    def test_registry_tree_and_prefetch_reference_rows_stay_in_fts(self) -> None:
        # Not excluded from artifact_fts: case search and the run's unified
        # search select artifact candidates through artifact_fts MATCH only.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = import_outputs(root / "bulk.db", sample_outputs(root, artifact_count=10), root, bulk=True)
            with database.connect() as connection:
                types = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT a.artifact_type FROM artifact_fts f JOIN artifact a ON a.id = f.rowid "
                        "WHERE artifact_fts MATCH ?",
                        ('"vendor3" OR "lib3"',),
                    )
                }
            self.assertEqual(types, {"registry-key-tree-node", "prefetch-reference"})

    def test_readonly_unified_search_reads_compressed_rows_without_functions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outputs = sample_outputs(root, artifact_count=10)
            out_dir = root / "run-perf"
            out_dir.mkdir()
            record = build_run_case_db(out_dir, outputs, root=str(root / "evidence"))
            self.assertEqual(record["status"], "completed", record.get("error"))
            matches, _docs, _ocr = fts_unified_matches(
                out_dir / "rapidtriage-case.db",
                outputs,
                ["needle2"],
                search_options={},
                sources={"artifacts"},
                extensions=set(),
                path_fragment="",
                hide_known_good=False,
                include_ocr=False,
                limit=50,
                budget=SearchBudget(60.0),
            )
            self.assertTrue(matches)
            self.assertTrue(all(match["source"] == "artifacts" for match in matches))
            self.assertTrue(all(match["pointer"].startswith("/artifacts/") for match in matches))
            # SQL json_extract on the locator stub still works (run review API).
            with closing(sqlite3.connect(f"file:{out_dir / 'rapidtriage-case.db'}?mode=ro", uri=True)) as connection:
                row = connection.execute(
                    "SELECT json_extract(data_json, '$.source_locator.row_index') FROM artifact WHERE id = 2"
                ).fetchone()
            self.assertEqual(row[0], 1)

    def test_autoincrement_id_matches_sqlite(self) -> None:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)")
            self.assertEqual(next_autoincrement_id(connection, "t"), 1)
            connection.executemany("INSERT INTO t (v) VALUES (?)", [("a",), ("b",), ("c",)])
            connection.execute("DELETE FROM t WHERE id = 3")
            expected = next_autoincrement_id(connection, "t")
            cursor = connection.execute("INSERT INTO t (v) VALUES ('d')")
            self.assertEqual(cursor.lastrowid, expected)


class BulkPersistThroughputTests(unittest.TestCase):
    ARTIFACTS = 200_000
    BUDGET_SECONDS = 150.0

    def test_200k_artifacts_persist_within_budget_and_read_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [
                {"artifact_type": "eventlog-event", "provider": "eventlog", "path": "C:/Windows/System32/winevt/Logs/Security.evtx",
                 "supported": True, "details": {"event_id": 4624 + index % 5, "record_number": index,
                                                "event_category": "logon", "message": f"session {index} user u{index % 97}"}}
                for index in range(self.ARTIFACTS)
            ]
            artifacts = root / "eventlog.json"
            with artifacts.open("w", encoding="utf-8") as handle:
                json.dump(artifacts_payload("eventlog", rows), handle, ensure_ascii=False)
            out_dir = root / "run-throughput"
            out_dir.mkdir()
            started = time.perf_counter()
            record = build_run_case_db(out_dir, {"artifacts_eventlog": str(artifacts)}, root=str(root))
            elapsed = time.perf_counter() - started
            self.assertEqual(record["status"], "completed", record.get("error"))
            self.assertEqual(record["counts"]["artifact_count"], self.ARTIFACTS)
            self.assertLess(elapsed, self.BUDGET_SECONDS)
            database = CaseDatabase(out_dir / "rapidtriage-case.db")
            with database.connect() as connection:
                for row_id in (1, 777, self.ARTIFACTS):
                    row = connection.execute(
                        f"SELECT {artifact_data_select_sql(connection)} FROM artifact WHERE id = ?", (row_id,)
                    ).fetchone()
                    stored = json.loads(artifact_row_data_json(row))
                    self.assertEqual(stored["details"]["record_number"], row_id - 1)
                    self.assertEqual(stored[ARTIFACT_DATA_LOCATOR_KEY], {"output_name": "artifacts_eventlog", "row_index": row_id - 1})
                hits = connection.execute(
                    "SELECT count(*) FROM artifact_fts WHERE artifact_fts MATCH ?", ('"u13"',)
                ).fetchone()[0]
            self.assertEqual(hits, len([index for index in range(self.ARTIFACTS) if index % 97 == 13]))


class SearchIndexEarlyExitTests(unittest.TestCase):
    def test_no_edb_tree_skips_filesystem_calls_and_exports_still_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(300):
                folder = root / "Windows" / "System32" / f"d{index % 10}"
                folder.mkdir(parents=True, exist_ok=True)
                (folder / f"f{index}.dll").write_bytes(b"x")
            (root / "Windows" / "System32" / "sru").mkdir(parents=True)
            (root / "Windows" / "System32" / "sru" / "SRUDB.jfm").write_bytes(b"x")
            (root / "notes.csv").write_text("a,b\n1,2\n", encoding="utf-8")  # no export hint
            provider = search_index.WindowsSearchIndexProvider()
            original_resolve = Path.resolve
            with mock.patch.object(Path, "resolve", autospec=True, side_effect=original_resolve) as resolve:
                started = time.perf_counter()
                records = list(provider.collect(root))
                elapsed = time.perf_counter() - started
            self.assertEqual(records, [])
            self.assertEqual(resolve.call_count, 0)
            self.assertLess(elapsed, 5.0)
            export = root / "exports" / "windows-search-export.csv"
            export.parent.mkdir()
            export.write_text("System.ItemPathDisplay,System.ItemName\nC:/Users/u/a.txt,a.txt\n", encoding="utf-8")
            records = list(provider.collect(root))
            self.assertIn("windows-search-index-entry", {record.artifact_type for record in records})

    def test_candidate_filter_keeps_named_databases_and_hinted_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = [root / "x" / "Windows.edb", root / "y" / "windows.db", root / "searchindex" / "rows.json"]
            drop = [root / "x" / "WebCacheV01.dat", root / "x" / "other.edb", root / "y" / "rows.json"]
            for path in keep + drop:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"{}")
            found = {path.relative_to(root) for path in search_index.iter_search_index_candidates(root)}
            self.assertEqual(found, {path.relative_to(root) for path in keep})


class SyntheticMediaTimingTests(unittest.TestCase):
    def _tree(self, root: Path, count: int) -> None:
        for index in range(count):
            (root / f"img{index}.jpg").write_bytes(b"\xff\xd8\xff")
            (root / f"other{index}.bin").write_bytes(b"x")

    def test_absent_engine_skips_fast_with_stable_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._tree(root, 200)
            with mock.patch.object(synthetic_media, "deepfake_lens_module", return_value=None):
                started = time.perf_counter()
                records = list(synthetic_media.SyntheticMediaProvider().collect(root))
                elapsed = time.perf_counter() - started
            self.assertLess(elapsed, 1.0)
            self.assertEqual(len(records), 1)
            details = records[0].details
            self.assertEqual(details["skip_reason"], synthetic_media.SYNTHETIC_MEDIA_SKIP_REASON)
            self.assertEqual(details["unscanned_candidate_count"], 200)

    def test_cli_lookup_once_and_cpu_budget_disclosed(self) -> None:
        class FakeLens:
            @staticmethod
            def analyze_file(path, **_kwargs):
                return {"status": "ok", "kind": "image", "result": {"score": 0.1, "band": "low"}}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._tree(root, 5)
            with mock.patch.object(synthetic_media, "deepfake_lens_module", return_value=FakeLens), \
                    mock.patch.object(synthetic_media.shutil, "which", return_value="") as which:
                records = list(synthetic_media.SyntheticMediaProvider().collect(root))
            self.assertEqual(which.call_count, 1)
            self.assertEqual(len(records), 6)
            summary = records[-1].details
            self.assertFalse(summary["scan_capped"])
            self.assertNotIn("scan_cap_reason", summary)
            with mock.patch.object(synthetic_media, "deepfake_lens_module", return_value=FakeLens), \
                    mock.patch.object(synthetic_media, "SYNTHETIC_MEDIA_SCAN_CPU_BUDGET_SECONDS", -1.0):
                records = list(synthetic_media.SyntheticMediaProvider().collect(root))
            summary = records[-1].details
            self.assertEqual(len(records), 1)
            self.assertTrue(summary["scan_capped"])
            self.assertEqual(summary["scan_status"], "partial")
            self.assertEqual(summary["scan_cap_reason"], synthetic_media.SYNTHETIC_MEDIA_SCAN_BUDGET_REASON)
            self.assertEqual(summary["unscanned_candidate_count"], 5)
            self.assertIn("CPU 시간 예산", summary["scan_cap_note"])


if __name__ == "__main__":
    unittest.main()
