"""Exercise platform activity through the same collection and timeline paths as a run."""

import json
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from jsonschema import Draft202012Validator

from rapidtriage.cli import main
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.run.plan import build_run_plan, find_task
from rapidtriage.core.run.profiles import RUN_PROFILES
from rapidtriage.core.schema_validation import load_schema
from rapidtriage.core.timeline import run_timeline
from tests.test_journald import make_journal


class PlatformActivityIntegrationTests(unittest.TestCase):
    def test_kinds_are_selectable_in_every_run_profile(self):
        for mode, profile in RUN_PROFILES.items():
            plan = build_run_plan(mode=mode, skip_tasks=["linux-journald"])
            for kind in ("linux-journald", "macos-knowledgec"):
                self.assertIn(kind, profile.artifacts_kinds)
                task = find_task(plan, kind)
                self.assertEqual(task["group"], "cross-platform")
                self.assertEqual(task["status"], "skipped" if kind == "linux-journald" else "queued")
        self.assertEqual(artifact_type_domain("macos-knowledgec", "macos-knowledgec-event"), "os")
        self.assertEqual(artifact_type_domain("linux-journald", "linux-journald-entry"), "eventlog")

    def test_selected_kinds_preserve_locators_through_streaming_and_timeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            evidence = output / "evidence"
            db = evidence / "private/var/db/CoreDuet/Knowledge/knowledgeC.db"
            db.parent.mkdir(parents=True)
            with closing(sqlite3.connect(db)) as connection:
                connection.executescript("""
                    CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT,
                                          ZSTARTDATE REAL, ZENDDATE REAL, ZVALUESTRING TEXT);
                    INSERT INTO ZOBJECT VALUES (17, '/app/inFocus', 1, 2, 'example.test');
                """)
            journal = evidence / "var/log/journal/synthetic/system.journal"
            journal.parent.mkdir(parents=True)
            data, offsets = make_journal([["MESSAGE=테스트".encode()]])
            entry = offsets["entries"][0]
            struct.pack_into("<Q", data, entry + 24, 978307203000001)
            journal.write_bytes(data)
            journal.with_suffix(".journal~").write_bytes(b"short")

            schema = Draft202012Validator(load_schema("artifacts.schema.json"))
            paths = []
            for kind, count in (("macos-knowledgec", 1), ("linux-journald", 2)):
                inline = output / f"{kind}.json"
                self.assertEqual(main(["artifacts", str(evidence), "--kind", kind, "--output", str(inline)]), 0)
                payload = json.loads(inline.read_text(encoding="utf-8"))
                schema.validate(payload)
                self.assertEqual(payload["summary"]["artifact_count"], count)
                self.assertEqual(payload["summary"]["artifact_record_contract_valid_count"], count)
                streamed = run_artifact_collection(evidence, kind=kind, records_path=output / f"{kind}.jsonl")
                schema.validate(streamed)
                path = output / f"run-{kind}.json"
                path.write_text(json.dumps(streamed), encoding="utf-8")
                paths.append(path)

            timeline = run_timeline(root=evidence, artifacts_inputs=paths)
            by_label = {event["timestamp_kind"]: event for event in timeline["events"]}
            self.assertEqual(len(timeline["events"]), 3)
            self.assertEqual(set(by_label), {"started", "ended", "logged"})
            self.assertEqual(by_label["started"]["timestamp"], "2001-01-01T00:00:01+00:00")
            self.assertEqual(by_label["ended"]["timestamp"], "2001-01-01T00:00:02+00:00")
            self.assertEqual(by_label["logged"]["timestamp"], "2001-01-01T00:00:03.000001+00:00")
            self.assertEqual(by_label["ended"]["details"]["source_row_id"], 17)
            self.assertEqual(by_label["logged"]["details"]["source_offset"], entry)
            self.assertEqual(by_label["logged"]["details"]["source_record"]["output"], "artifacts_linux-journald")
