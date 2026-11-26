"""Ordered timeline and whole-case differential on synthetic run outputs."""

from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from contextlib import ExitStack, closing
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.artifact_profiles import expand_profile, iter_payload_records
from rapidtriage.core.case_db import bulk_import
from rapidtriage.core.case_db.schema import register_case_db_functions
from rapidtriage.core.run.persist import CASE_DB_FILE_NAME, build_run_case_db
from rapidtriage.core.timeline import (
    build_timeline_report,
    run_timeline,
    write_timeline_result,
)

FIXTURE = Path(__file__).parent / "fixtures" / "known_answer" / "tier0-basic" / "manifest.json"
REFERENCE = dt.datetime(2026, 7, 1, tzinfo=dt.timezone.utc)


def make_inputs(root: Path) -> dict[str, Path]:
    outputs = {name: root / f"{name}.json" for name in ("files", "docs", "artifacts_mixed", "timeline")}
    items = json.loads(FIXTURE.read_text(encoding="utf-8"))["expected_items"]
    files = [
        {"path": item["original_path"], "size": item["size_bytes"], "fs_modified_at": item["modified_time_utc"]}
        for item in items
    ]
    paths = [files[0]["path"], unicodedata.normalize("NFD", "자료/한글.bin")]
    files.append({"path": paths[1], "size": 0})
    outputs["files"].write_text(json.dumps({"command": "files", "candidates": files}), encoding="utf-8")
    outputs["docs"].write_text(json.dumps({"command": "docs", "candidates": []}), encoding="utf-8")
    stamps = (
        "2024-03-01T00:00:00.0000001Z",
        "2024-03-01T00:00:00.0000002+00:00",
        "2024-03-01T09:00:00.0000001+09:00",
    )
    with (root / "mixed.jsonl").open("w", encoding="utf-8") as stream:
        for i in range(2011):  # spans a full producer batch and a short tail
            details = {
                "timestamp": stamps[i % len(stamps)], "record_id": i,
                "entry_name": ("한글" * 8192 if i == 0 else "항목") + "\0끝",
            }
            details["state"] = i % 2
            row = {"artifact_type": "usn-record", "path": paths[i % 2], "details": details,
                   "profile_ref": "usn-record" if i else "absent", "context_ref": True}
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    profile = {
        "contexts": {path: {"details": {"origin": {"path": path}}} for path in paths},
        "codes": {"state": ["live", "saved"]},
        "details": {"origin": {"scope": "fixture"}, "parser": "fixture"},
    }
    head = {"command": "artifacts", "kind": "mixed", "records_file": "mixed.jsonl",
            "artifact_type_profiles": {"usn-record": profile}}
    outputs["artifacts_mixed"].write_text(json.dumps(head), encoding="utf-8")
    return outputs


def write_timeline(root: Path, outputs: dict[str, Path]) -> dict:
    result = run_timeline(
        root=root, files_inputs=[outputs["files"]], docs_inputs=[outputs["docs"]],
        artifacts_inputs=[outputs["artifacts_mixed"]], reference_time=REFERENCE,
    )
    result["generated_at"] = REFERENCE.isoformat()
    write_timeline_result(result, outputs["timeline"])
    return result


def persist(root: Path, outputs: dict[str, Path]) -> dict:
    with ExitStack() as stack:
        for module in ("database", "bulk_import", "review_schema"):
            stack.enter_context(patch(f"rapidtriage.core.case_db.{module}.now_iso", new=REFERENCE.isoformat))
        result = build_run_case_db(root, outputs, root=str(root))
    if result["status"] != "completed":
        raise AssertionError(result)
    return result["counts"]


def ordered_rows(db: sqlite3.Connection, table: str):
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return db.execute(f"SELECT * FROM {quoted} ORDER BY rowid")
    except sqlite3.OperationalError as exc:
        if str(exc) != "no such column: rowid":
            raise
        # FTS5 has WITHOUT ROWID shadow tables. Their declared PK orders the dump.
        pk = sorted((col[5], col[0] + 1) for col in db.execute(f"PRAGMA table_info({quoted})") if col[5])
        order = ", ".join(str(position) for _, position in pk)
        return db.execute(f"SELECT * FROM {quoted} ORDER BY {order}")


def compare_databases(old: Path, new: Path) -> dict[str, int]:
    counts = {}
    with closing(sqlite3.connect(old)) as before, closing(sqlite3.connect(new)) as after:
        for db in (before, after):
            register_case_db_functions(db)
        schema = "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid"
        if before.execute(schema).fetchall() != after.execute(schema).fetchall():
            raise AssertionError("schema differs")
        for (table,) in before.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            count = 0
            for a, b in itertools.zip_longest(ordered_rows(before, table), ordered_rows(after, table)):
                if a != b:
                    raise AssertionError(f"{table} differs at ordered row {count + 1}")
                count += 1
            counts[table] = count
    return counts


class TimelinePersistenceParityTests(unittest.TestCase):
    def test_interrupted_bulk_write_has_no_import_receipt_and_can_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            outputs = make_inputs(root)
            write_timeline(root, outputs)
            # Exit during the event transaction, after the artifact transaction
            # has committed and before the import can publish its receipt.
            child = """
import json
import os
import sys
from pathlib import Path
from rapidtriage.core.case_db import database
from rapidtriage.core.run.persist import build_run_case_db

insert = database.bulk_import_run_events
def interrupt(*args, **kwargs):
    insert(*args, **kwargs)
    os._exit(73)

database.bulk_import_run_events = interrupt
build_run_case_db(Path(sys.argv[1]), json.loads(sys.argv[2]), root=sys.argv[1])
"""
            paths = {key: str(value) for key, value in outputs.items()}
            stopped = subprocess.run(
                [sys.executable, "-c", child, str(root), json.dumps(paths)],
                cwd=Path(__file__).resolve().parents[1], check=False, timeout=60,
            )
            self.assertEqual(stopped.returncode, 73)
            receipt = "SELECT count(*) FROM audit_event WHERE action = 'run.imported'"
            with closing(sqlite3.connect(root / CASE_DB_FILE_NAME)) as db:
                self.assertEqual(db.execute(receipt).fetchone(), (0,))
            self.assertEqual(persist(root, outputs)["artifact_count"], 2011)
            with closing(sqlite3.connect(root / CASE_DB_FILE_NAME)) as db:
                self.assertEqual(db.execute(receipt).fetchone(), (1,))

    def test_ordered_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            outputs = make_inputs(root)
            result = write_timeline(root, outputs)
            # Replace only the machine-dependent input paths before checking the
            # baseline golden. Array order, key order, numbers and all text matter.
            result["root"] = "."
            for key, paths in result["inputs"].items():
                result["inputs"][key] = [Path(path).name for path in paths]
            for event in result["events"]:
                if "input_file" in event:
                    event["input_file"] = Path(event["input_file"]).name
            golden_file = root / "relative-timeline.json"
            write_timeline_result(result, golden_file)
            data = golden_file.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), "ee26735f6525eccfef40d9e254ff6f948eb9e777d946bba910b80dea38652a74")
            # The report gained #40's unmapped-row/unconfirmed-timezone lines and
            # the activity-count section; event rows are unchanged (JSON above).
            report = build_timeline_report(result).encode("utf-8")
            self.assertEqual(hashlib.sha256(report).hexdigest(), "f94083e37d3f0ba2c53e1234ab724f6d515cb77348dc764767f6e18c4b1abc33")

            original = root / "reference.db"
            # The original importer expanded each row twice, independently
            # restoring codes and the per-file context in each projection.
            def original_views(path):
                head = json.loads(path.read_text(encoding="utf-8"))
                profiles = head["artifact_type_profiles"]
                for index, row in enumerate(iter_payload_records(head, payload_path=path, expand=False)):
                    full = expand_profile(row, profiles, copy_templates=False)
                    varying = expand_profile(row, profiles, copy_templates=False, include_type_templates=False)
                    yield index, full, varying

            with patch.object(bulk_import, "iter_artifact_output_row_views", new=original_views):
                expected = persist(root, outputs)
            shutil.move(root / CASE_DB_FILE_NAME, original)
            self.assertEqual(persist(root, outputs), expected)
            counts = compare_databases(original, root / CASE_DB_FILE_NAME)
            self.assertEqual(counts["artifact"], 2011)
            self.assertEqual(counts["event"], len(result["events"]))
            with closing(sqlite3.connect(root / CASE_DB_FILE_NAME)) as db:
                hits = db.execute("SELECT count(*) FROM event_fts WHERE event_fts MATCH 'target:한글'").fetchone()
                self.assertEqual(hits, (2011 // 2,))


if __name__ == "__main__":
    unittest.main()
