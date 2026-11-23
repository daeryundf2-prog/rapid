"""D12 run identity, per-stage reuse keys and read-only output placement.

- ``--resume`` into an output directory of another exhibit must not reuse
  its rows, even when relative paths, sizes and mtimes are identical.
- An output-affecting option (``--max-file-count``) is part of the stage
  cache key: lifting the limit on resume gives the fresh-run result.
- A read-only run never writes inside the source folder.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.jobs import default_run_output_dir
from rapidtriage.core.run.incremental_indexing import (
    build_run_evidence_identity,
    build_run_input_fingerprint,
    build_stage_reuse_binding,
    fingerprint_reuse_blockers,
    incremental_fingerprints_equivalent,
    load_or_build_json,
)

RUN_ARGS = ["--mode", "seizure", "--no-case-db", "--skip-group", "messaging", "--skip-group", "mobile"]
FIXED_NS = 1_600_000_000_000_000_000


def run_cli(root: Path, output_dir: Path | None, *extra: str) -> None:
    args = ["run", str(root), *RUN_ARGS, *extra]
    if output_dir is not None:
        args += ["--output-dir", str(output_dir)]
    if main(args) != 0:
        raise AssertionError(f"run failed: {args}")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def eventlog_events(output_dir: Path) -> list[tuple[str, str]]:
    summary_path = output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.json"
    payload = read_json(summary_path)
    records = summary_path.parent / payload["records_file"]
    rows = [json.loads(line) for line in records.read_text(encoding="utf-8").splitlines() if line.strip()]
    return sorted(
        (row["details"]["record_id"], Path(row["details"]["source_path"]).parent.name)
        for row in rows
        if row["artifact_type"] == "eventlog-event"
    )


def write_exhibit(root: Path, record_id: int) -> None:
    root.mkdir(parents=True)
    events = root / "events.xml"
    events.write_text(
        '<Events><Event><System><Provider Name="Sample"/><EventID>42</EventID>'
        f"<EventRecordID>{record_id}</EventRecordID><Channel>System</Channel></System></Event></Events>",
        encoding="utf-8",
    )
    os.utime(events, ns=(FIXED_NS, FIXED_NS))


def tree_snapshot(root: Path) -> dict[str, object]:
    entries: dict[str, object] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            entries[relative] = ("dir", path.stat().st_mtime_ns)
        else:
            entries[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
    entries["."] = ("dir", root.stat().st_mtime_ns)
    return entries


class ResumeEvidenceIdentityTests(unittest.TestCase):
    def test_resume_into_other_exhibit_output_recollects_instead_of_reusing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            exhibit_a, exhibit_b = base / "exhibit-A", base / "exhibit-B"
            write_exhibit(exhibit_a, 11)
            write_exhibit(exhibit_b, 12)
            shared, fresh = base / "shared-out", base / "fresh-out"

            run_cli(exhibit_a, shared)
            run_cli(exhibit_b, shared, "--resume")
            run_cli(exhibit_b, fresh)

            self.assertEqual(eventlog_events(shared), [("12", "exhibit-B")])
            self.assertEqual(eventlog_events(shared), eventlog_events(fresh))
            safety = read_json(shared / "rapidtriage-run-summary.json")["safety"]
            self.assertNotIn("artifacts-eventlog", safety["reused_outputs"])
            self.assertFalse(safety["resume_effective"])
            self.assertIn("evidence identity", safety["resume_disabled_reason"])

    def test_resume_of_same_exhibit_still_reuses_stage_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            exhibit = base / "exhibit"
            write_exhibit(exhibit, 11)
            output = base / "out"
            run_cli(exhibit, output)
            run_cli(exhibit, output, "--resume")
            safety = read_json(output / "rapidtriage-run-summary.json")["safety"]
            self.assertTrue(safety["resume_effective"])
            self.assertIn("artifacts-eventlog", safety["reused_outputs"])
            self.assertIn("files", safety["reused_outputs"])

    def test_metadata_only_or_foreign_fingerprints_cannot_prove_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "exhibit"
            write_exhibit(root, 11)
            identity = build_run_evidence_identity(str(root), input_kind="windows", scan_root=root)
            current = build_run_input_fingerprint(root, evidence_identity=identity)
            self.assertEqual(fingerprint_reuse_blockers(current, current), [])
            self.assertTrue(incremental_fingerprints_equivalent(current, current))

            metadata_only = {
                **current,
                "content_hash_policy": {"hash_contents": False},
                "files": [{**record, "sha256": None, "hash_status": "disabled"} for record in current["files"]],
            }
            no_identity = {key: value for key, value in current.items() if key != "evidence_identity"}
            other = build_run_input_fingerprint(
                root,
                evidence_identity={**identity, "source_path": str(Path(tmp) / "other")},
            )
            above_cap = build_run_input_fingerprint(root, evidence_identity=identity, max_content_hash_bytes=1)
            for previous, reason in (
                (metadata_only, "no content hashes"),
                (no_identity, "no evidence identity"),
                (other, "evidence identity changed"),
                (above_cap, "without a content hash"),
            ):
                with self.subTest(reason=reason):
                    blockers = fingerprint_reuse_blockers(previous, current)
                    self.assertTrue(any(reason in blocker for blocker in blockers), blockers)
                    self.assertFalse(incremental_fingerprints_equivalent(previous, current))

    def test_stage_payload_is_reused_only_with_its_own_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stage.json"
            identity = {"source_path": "exhibit"}
            first = build_stage_reuse_binding(evidence_identity=identity, input_fingerprint="f", options={"limit": 1})
            payload, reused = load_or_build_json(path, resume=True, producer=lambda: {"rows": 1}, reuse_binding=first)
            self.assertFalse(reused)
            path.write_text(json.dumps(payload), encoding="utf-8")

            again, reused = load_or_build_json(path, resume=True, producer=lambda: {"rows": 3}, reuse_binding=first)
            self.assertTrue(reused)
            self.assertEqual(again["rows"], 1)
            for changed in (
                build_stage_reuse_binding(evidence_identity=identity, input_fingerprint="f", options={"limit": 0}),
                build_stage_reuse_binding(evidence_identity=identity, input_fingerprint="g", options={"limit": 1}),
                build_stage_reuse_binding(evidence_identity={"source_path": "x"}, input_fingerprint="f", options={"limit": 1}),
            ):
                rebuilt, reused = load_or_build_json(path, resume=True, producer=lambda: {"rows": 3}, reuse_binding=changed)
                self.assertFalse(reused)
                self.assertEqual(rebuilt["rows"], 3)


class StageOptionCacheKeyTests(unittest.TestCase):
    def test_lifting_max_file_count_on_resume_matches_fresh_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            for index in range(3):
                (source / f"note{index}.txt").write_text("synthetic note", encoding="utf-8")
            cached, fresh = base / "cached", base / "fresh"

            run_cli(source, cached, "--max-file-count", "1")
            run_cli(source, cached, "--max-file-count", "0", "--resume")
            run_cli(source, fresh, "--max-file-count", "0")

            resumed_files = read_json(cached / "rapidtriage-files.json")
            fresh_files = read_json(fresh / "rapidtriage-files.json")
            self.assertEqual(resumed_files["filters"]["limit"], 0)
            self.assertEqual(
                sorted(row["path"] for row in resumed_files["candidates"]),
                sorted(row["path"] for row in fresh_files["candidates"]),
            )
            self.assertEqual(len(resumed_files["candidates"]), 3)
            safety = read_json(cached / "rapidtriage-run-summary.json")["safety"]
            self.assertNotIn("files", safety["reused_outputs"])
            self.assertNotIn("docs", safety["reused_outputs"])


class ReadOnlyOutputPlacementTests(unittest.TestCase):
    def test_read_only_run_leaves_source_tree_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "seized"
            (source / "docs").mkdir(parents=True)
            (source / "docs" / "note.txt").write_text("synthetic note", encoding="utf-8")
            before = tree_snapshot(source)

            run_cli(source, None, "--read-only")

            self.assertEqual(tree_snapshot(source), before)
            output = Path(tmp) / "seized-rapidtriage-run-seizure"
            self.assertTrue((output / "rapidtriage-run-summary.json").is_file())
            self.assertTrue(read_json(output / "rapidtriage-run-summary.json")["safety"]["read_only"])

    def test_read_only_run_rejects_output_inside_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "seized"
            source.mkdir()
            (source / "note.txt").write_text("synthetic note", encoding="utf-8")
            before = tree_snapshot(source)
            with self.assertRaises(SystemExit):
                run_cli(source, source / "out", "--read-only")
            self.assertEqual(tree_snapshot(source), before)

    def test_default_output_dir_is_a_sibling_for_read_only_folders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence-root"
            root.mkdir()
            output = default_run_output_dir(root, "seizure", run_id="abc123", read_only=True)
            self.assertEqual(output.parent, root.parent)
            self.assertEqual(output.name, "evidence-root-rapidtriage-run-seizure-abc123")


if __name__ == "__main__":
    unittest.main()
