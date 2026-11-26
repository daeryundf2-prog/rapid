"""Exercise physical source citations and isolation through public collection APIs."""
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from rapidtriage.artifacts import unified_log
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.schema_validation import load_schema
from rapidtriage.core.timeline import run_timeline
from tests.unified_log_fixture import write_fixture
from tests.unified_trace_fixture import CACHE, MAIN, make_trace


def records(root):
    return list(unified_log.UnifiedLogProvider().collect(root))


class UnifiedLogProviderTests(unittest.TestCase):
    def test_archive_collection_schema_and_streamed_timeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            store = evidence / "export/nested/synthetic.logarchive"
            write_fixture(store, store)
            path = store / "Persist/sample.tracev3"
            payload = run_artifact_collection(evidence, kind="macos-unified-log",
                                              records_path=root / "records.jsonl")
            Draft202012Validator(load_schema("artifacts.schema.json")).validate(payload)
            self.assertEqual(payload["summary"]["artifact_record_contract_valid_count"], 4)
            manifest = root / "artifacts.json"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            timeline = run_timeline(root=evidence, artifacts_inputs=[manifest])
            self.assertEqual(len(timeline["events"]), 4)
            events = records(store)
            self.assertEqual([r.details["message"] for r in events],
                             ["ok / <private>", "started", "begin", "value 123"])
            self.assertNotIn("hidden", (root / "records.jsonl").read_text(encoding="utf-8"))
            self.assertEqual([r.details["timestamp"] for r in events],
                             [f"2020-09-13T12:26:42.{ns:09d}Z" for ns in (41, 83, 125, 166)])
            for row, tag in zip(events, [4, 2, 6, 3], strict=True):
                self.assertEqual(Path(row.path), path.resolve())
                self.assertEqual(path.read_bytes()[row.details["source_offset"]], tag)
                self.assertTrue(Path(row.details["format_source_path"]).is_file())
                self.assertEqual(Path(row.details["timesync_source_path"]).name, "boot.timesync")
                self.assertEqual(row.details["timesync_source_offset"], 48)
            self.assertEqual({e["details"]["source_offset"] for e in timeline["events"]},
                             {r.details["source_offset"] for r in events})

    def test_raw_tree_and_calibration_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            store = evidence.joinpath(*unified_log.RAW_TREE)
            write_fixture(store, store.with_name("uuidtext"))
            archive = evidence / "nested.logarchive"
            archive.mkdir()
            (archive / "second.tracev3").write_bytes(make_trace())
            rows = records(evidence)
            self.assertEqual(len(rows), 8)
            self.assertEqual([r.details["message"] for r in rows[:4]],
                             ["ok / <private>", "started", "begin", "value 123"])
            self.assertTrue(all(r.details["message_status"] == "missing-format"
                                and "timestamp" not in r.details for r in rows[4:]))
            self.assertTrue(all(r.details["message_status"] == "missing-format" for r in records(store)))

    def test_damaged_sidecars_do_not_hide_other_usable_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "broken.logarchive"
            write_fixture(store, store)
            path = store / "timesync/boot.timesync"
            path.write_bytes(path.read_bytes() + b"bad")
            (store / "dsc" / CACHE).write_bytes(b"short")
            rows = records(store)
            diagnostics = [(Path(r.path).name, r.details["source_offset"]) for r in rows if not r.supported]
            self.assertEqual(diagnostics, [("boot.timesync", 80), (CACHE, 0)])
            self.assertEqual(sum(r.supported for r in rows), 4)
            signpost = next(r.details for r in rows if r.details.get("event_type") == "signpost")
            self.assertEqual(signpost["message_status"], "missing-format")
            self.assertIn("timestamp", signpost)

    def test_empty_firehose_preserves_dictionary_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "empty.logarchive"
            write_fixture(store, store)
            path = store / "Persist/sample.tracev3"
            trace = bytearray(path.read_bytes())
            firehose = trace.index(struct.pack("<I", 0x6001))
            struct.pack_into("<H", trace, firehose + 32, 16)
            path.write_bytes(trace)
            dictionary = store / MAIN[:2] / MAIN[2:]
            dictionary.write_bytes(b"short")
            row, = records(store)
            self.assertEqual(Path(row.path), dictionary.resolve())
            self.assertEqual(row.details["reason"], "truncated-string-header")

    def test_symlinked_sources_and_dictionaries_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            external = root / "other.logarchive"
            write_fixture(external, external)
            selected = root / "selected.logarchive"
            selected.mkdir()
            (selected / "Persist").symlink_to(external / "Persist", target_is_directory=True)
            (selected / "timesync").symlink_to(external / "timesync", target_is_directory=True)
            (selected / MAIN[:2]).symlink_to(external / MAIN[:2], target_is_directory=True)
            (selected / "dsc").symlink_to(external / "dsc", target_is_directory=True)
            (selected / "bad.tracev3").symlink_to(external / "Persist/sample.tracev3")
            self.assertEqual(records(selected), [])
            (selected / "valid.tracev3").write_bytes(make_trace())
            rows = records(selected)
            self.assertEqual(len(rows), 4)
            self.assertTrue(all("timestamp" not in r.details and not r.details["process"]
                                and r.details["message_status"] == "missing-format" for r in rows))

    def test_global_and_file_limits_have_citations(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bounded.logarchive"
            archive.mkdir()
            (archive / "first.tracev3").write_bytes(make_trace())
            (archive / "second.tracev3").write_bytes(make_trace())
            for key, cap, reason in [
                ("MAX_ROWS", 4, "row-limit"), ("MAX_FILE_BYTES", 8, "file-size-limit"),
                ("MAX_FILES", 1, "trace-file-limit"), ("MAX_BYTES", 4, "byte-limit"),
                ("MAX_DIRECTORY_ENTRIES", 1, "directory-entry-limit"),
            ]:
                with self.subTest(key=key), patch.object(unified_log, key, cap):
                    rows = records(archive)
                    self.assertIn(reason, [r.details.get("reason") for r in rows])
                    self.assertTrue(all("source_offset" in r.details for r in rows))
                    if key == "MAX_ROWS":
                        self.assertEqual(len(rows), 5)
