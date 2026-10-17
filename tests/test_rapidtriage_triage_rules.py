"""Triage-flag rule library (plan viewer-families §3.1): catalogue, every rule's fixtures, engine, run step."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.triage_rules import RULE_CLASSES, CatalogError, load_catalog
from rapidtriage.core.triage_rules import engine as triage_engine
from rapidtriage.core.triage_rules.catalog import (
    CATALOG_DIR,
    RULE_ID_PATTERN,
    parse_catalog,
)
from rapidtriage.core.triage_rules.engine import (
    FLAGS_FILE_NAME,
    SUMMARY_FILE_NAME,
    Progress,
    TriageInputs,
    run_triage_flags,
)
from rapidtriage.core.triage_rules.stage import (
    RUN_STAGE_ANALYSIS_PREFIX,
    run_triage_stage,
)
from tests.triage_cases import all_cases, run_case

GOOD_RULE = """
families:
- id: fam
  label: 계열
  core_columns:
  - key: a
    label: 가
  rules: [fam.one]
rules:
- id: fam.one
  family: fam
  grade: A
  label_ko: 하나
  rationale_ko: 이유
  false_positive_ko: 오탐
  sources: ["https://example.org/doc"]
  version: 1
  status: verified
"""


def event(event_id: str, channel: str, provider: str, **details: object) -> dict[str, object]:
    return {
        "artifact_type": "eventlog-event",
        "path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
        "details": {"event_id": event_id, "channel": channel, "provider_name": provider, "timestamp": "2024-05-01T10:00:00Z", **details},
    }


def tiny_run(root: Path) -> TriageInputs:
    events = [
        event("4624", "Security", "Microsoft-Windows-Security-Auditing", logon_type="5"),
        event("1102", "Security", "Microsoft-Windows-Eventlog"),
        event("4104", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell"),
    ]
    records = root / "eventlog.jsonl"
    records.write_text("\n" + "".join(json.dumps(row) + "\n" for row in events), encoding="utf-8")  # blank line: no index
    payload = root / "artifacts_eventlog.json"
    payload.write_text(json.dumps({"records_path": str(records), "record_count": 3, "artifacts": []}), encoding="utf-8")
    return TriageInputs(output_dir=root, artifact_payloads={"eventlog": payload})


class CatalogTests(unittest.TestCase):
    def test_every_catalogue_rule_is_implemented_and_listed(self) -> None:
        catalog = load_catalog()
        self.assertEqual(set(catalog.specs), set(RULE_CLASSES))
        self.assertGreaterEqual(len(catalog.specs), 130)
        listed = {rule_id for family in catalog.families for rule_id in family["rules"]}
        self.assertEqual(listed - set(catalog.specs), set())
        for spec in catalog.specs.values():
            self.assertRegex(spec.id, RULE_ID_PATTERN)
            self.assertIn(spec.grade, ("A", "B", "C"))
            self.assertRegex(spec.label_ko + spec.rationale_ko + spec.false_positive_ko, "[가-힣]")
            self.assertTrue(spec.sources and all(url.startswith("https://") for url in spec.sources))
            self.assertEqual(spec.citation, f"{spec.id}@{spec.version}")
        family_ids = {family["id"] for family in catalog.families}
        self.assertEqual({spec.family for spec in catalog.specs.values()} - family_ids, set())

    def test_catalogue_version_is_content_hash(self) -> None:
        files = [(path.name, path.read_bytes()) for path in sorted(CATALOG_DIR.glob("*.yaml"))]
        self.assertEqual(parse_catalog(files).version, load_catalog().version)
        changed = [(name, data + b"\n# x\n" if index == 0 else data) for index, (name, data) in enumerate(files)]
        self.assertNotEqual(parse_catalog(changed).version, load_catalog().version)

    def test_schema_errors_are_korean(self) -> None:
        self.assertEqual(len(parse_catalog([("a.yaml", GOOD_RULE.encode())]).specs), 1)
        broken = {
            "grade": GOOD_RULE.replace("grade: A", "grade: D"),
            "source": GOOD_RULE.replace("https://example.org/doc", "http://example.org/doc"),
            "family": GOOD_RULE.replace("family: fam\n", "family: nope\n"),
            "id": GOOD_RULE.replace("- id: fam.one", "- id: Fam One"),
            "status": GOOD_RULE.replace("status: verified", "status: maybe"),
            "column": GOOD_RULE.replace("    label: 가", "    label: 가\n    colour: red"),
            "top": GOOD_RULE + "extra: 1\n",
            "listed": GOOD_RULE.replace("rules: [fam.one]", "rules: [fam.two]"),
            "yaml": "families: [",
        }
        for name, text in broken.items():
            with self.subTest(name), self.assertRaises(CatalogError) as caught:
                parse_catalog([("a.yaml", text.encode())])
            self.assertRegex(str(caught.exception), "[가-힣]")
        with self.assertRaises(CatalogError):
            parse_catalog([("a.yaml", GOOD_RULE.encode()), ("b.yaml", GOOD_RULE.replace("- id: fam\n", "- id: fam2\n").encode())])


class RuleFixtureTests(unittest.TestCase):
    """Every rule: one positive and one false-positive look-alike fixture (``tests/triage_cases``)."""

    def test_every_rule_has_both_fixtures(self) -> None:
        cases = all_cases()
        self.assertEqual(sorted(set(RULE_CLASSES) - set(cases)), [])
        self.assertEqual(sorted(set(cases) - set(RULE_CLASSES)), [])
        for rule_id, pair in cases.items():
            self.assertEqual(set(pair), {"positive", "negative"}, rule_id)
            self.assertTrue(pair["positive"].get("flagged"), rule_id)
            self.assertFalse(pair["negative"].get("flagged"), rule_id)

    def test_rule_fixtures(self) -> None:
        for rule_id, pair in sorted(all_cases().items()):
            for name, case in sorted(pair.items()):
                with self.subTest(rule=rule_id, case=name):
                    flagged, expected, summary = run_case(case, rule_id)
                    self.assertNotIn(rule_id, summary["rule_errors"])
                    self.assertEqual(flagged, expected)


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_engine_writes_flags_and_summary(self) -> None:
        inputs = tiny_run(self.root)
        out = self.root / "analyses" / "x"
        summary = run_triage_flags(inputs, out, source_label="test")
        lines = [json.loads(line) for line in (out / FLAGS_FILE_NAME).read_text(encoding="utf-8").splitlines()]
        cleared = [line for line in lines if any(item["id"] == "eventlog.log_cleared" for item in line["flags"])]
        self.assertEqual([(line["kind"], line["record_index"]) for line in cleared], [("eventlog", 1)])
        for line in lines:
            grades = [item["grade"] for item in line["flags"]]
            self.assertEqual(grades, sorted(grades))  # A before B before C
        on_disk = json.loads((out / SUMMARY_FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(on_disk["status"], "completed")
        self.assertEqual(on_disk["catalog_version"], load_catalog().version)
        rule_set = on_disk["rule_set"]
        self.assertEqual(rule_set["catalog_version"], load_catalog().version)
        self.assertEqual(
            rule_set["files"],
            {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(CATALOG_DIR.glob("*.yaml"))},
        )
        self.assertEqual(rule_set["rule_versions"], on_disk["rule_versions"])
        self.assertEqual(on_disk["rule_versions"]["eventlog.log_cleared"], load_catalog().specs["eventlog.log_cleared"].version)
        self.assertEqual(summary["rows_scanned"]["eventlog"], 3)
        self.assertEqual(summary["by_kind_type"]["eventlog"]["eventlog-event"]["A"], 1)
        policy = {item["id"]: item["count"] for item in summary["policy_sources"]}
        self.assertEqual(policy["powershell_scriptblock_4104"], 1)
        self.assertEqual(policy["process_creation_4688"], 0)
        self.assertEqual(sorted(path.name for path in out.iterdir()), [FLAGS_FILE_NAME, SUMMARY_FILE_NAME])

    def test_cancel_stops_before_any_output(self) -> None:
        inputs = tiny_run(self.root)
        out = self.root / "out"

        class Stop(Exception):
            pass

        def cancel() -> None:
            raise Stop()

        with self.assertRaises(Stop):
            run_triage_flags(inputs, out, source_label="test", progress=Progress(check_cancel=cancel))
        self.assertFalse(out.exists() and any(out.iterdir()))

    def test_atomic_write_keeps_old_file_on_failure(self) -> None:
        target = self.root / "flags.jsonl"
        target.write_text("old\n", encoding="utf-8")

        def broken(handle) -> None:
            handle.write("partial")
            raise OSError("disk full")

        with self.assertRaises(OSError):
            triage_engine._write_atomic(target, broken)
        self.assertEqual(target.read_text(encoding="utf-8"), "old\n")
        self.assertEqual([path.name for path in self.root.iterdir()], ["flags.jsonl"])

    def test_a_failing_rule_is_isolated(self) -> None:
        inputs = tiny_run(self.root)
        cls = RULE_CLASSES["eventlog.new_service"]
        with patch.object(cls, "apply", side_effect=RuntimeError("boom")):
            summary = run_triage_flags(inputs, self.root / "out", source_label="test")
        self.assertEqual(summary["rule_errors"]["eventlog.new_service"]["count"], 3)
        self.assertEqual(summary["by_rule"].get("eventlog.log_cleared"), 1)

    def test_caps_suppress_instead_of_growing(self) -> None:
        inputs = tiny_run(self.root)
        with patch.object(triage_engine, "MAX_FLAGGED_ROWS", 0):
            summary = run_triage_flags(inputs, self.root / "out", source_label="test")
        self.assertEqual(summary["flagged_rows"], 0)
        self.assertGreaterEqual(summary["suppressed"].get("eventlog.log_cleared", 0), 1)

    def test_run_stage_writes_a_completed_analysis_inside_the_output_dir(self) -> None:
        inputs = tiny_run(self.root)
        step = run_triage_stage(self.root, artifact_outputs=inputs.artifact_payloads)
        self.assertEqual(step["name"], "triage-flags")
        self.assertEqual(step["status"], "completed", step)
        self.assertTrue(str(step["analysis_id"]).startswith(f"{RUN_STAGE_ANALYSIS_PREFIX}-"))
        self.assertEqual(step["coverage"], "complete")
        directory = self.root / "analyses" / str(step["analysis_id"])
        state = json.loads((directory / "analysis.json").read_text(encoding="utf-8"))
        self.assertEqual((state["kind"], state["status"], state["row_count"]), ("triage-flags", "completed", 0))
        self.assertEqual(state["summary"]["by_rule"]["eventlog.log_cleared"], 1)
        self.assertTrue((directory / FLAGS_FILE_NAME).is_file())
        self.assertEqual({path.name for path in self.root.iterdir()}, {"analyses", "eventlog.jsonl", "artifacts_eventlog.json"})

    def test_run_stage_failure_is_isolated(self) -> None:
        inputs = tiny_run(self.root)
        first = run_triage_stage(self.root, artifact_outputs=inputs.artifact_payloads)
        with (
            patch("rapidtriage.core.triage_rules.stage.run_triage_flags", side_effect=RuntimeError("boom")),
            self.assertLogs("rapidtriage.core.triage_rules.stage", "ERROR"),
        ):
            step = run_triage_stage(self.root, artifact_outputs=inputs.artifact_payloads)
        self.assertEqual(step["status"], "failed_isolated")
        self.assertIn("특이사항 단계 실패", step["warning_messages"][0])
        self.assertFalse((self.root / "analyses" / str(step["analysis_id"]) / "analysis.json").exists())
        # The previous generation stays joinable.
        self.assertTrue((self.root / "analyses" / str(first["analysis_id"]) / "analysis.json").is_file())

    def test_run_stage_writes_a_new_generation_while_the_old_one_is_open(self) -> None:
        inputs = tiny_run(self.root)
        first = run_triage_stage(self.root, artifact_outputs=inputs.artifact_payloads)
        old_flags = self.root / "analyses" / str(first["analysis_id"]) / FLAGS_FILE_NAME
        with open(old_flags, "rb"):  # an API reader building its index (no FILE_SHARE_DELETE on Windows)
            second = run_triage_stage(self.root, artifact_outputs=inputs.artifact_payloads)
        self.assertEqual(second["status"], "completed", second)
        self.assertNotEqual(first["analysis_id"], second["analysis_id"])
        self.assertTrue((self.root / "analyses" / str(second["analysis_id"]) / "analysis.json").is_file())
        third = run_triage_stage(self.root, artifact_outputs=inputs.artifact_payloads)
        generations = sorted(path.name for path in (self.root / "analyses").iterdir())
        self.assertEqual(generations, [str(third["analysis_id"])])  # older generations are removed once closed

    def test_replace_with_retry_waits_for_a_reader(self) -> None:
        source = self.root / "new.tmp"
        target = self.root / "target"
        source.write_text("new", encoding="utf-8")
        target.write_text("old", encoding="utf-8")
        calls = []
        real = triage_engine.os.replace

        def flaky(src, dst):
            calls.append(src)
            if len(calls) < 3:
                raise PermissionError("in use")
            return real(src, dst)

        with patch.object(triage_engine.os, "replace", flaky):
            triage_engine.replace_with_retry(source, target)
        self.assertEqual(target.read_text(encoding="utf-8"), "new")
        self.assertEqual(len(calls), 3)

    def test_unreadable_or_short_source_makes_the_set_partial(self) -> None:
        inputs = tiny_run(self.root)
        missing = self.root / "artifacts_browser.json"
        missing.write_text(json.dumps({"records_path": str(self.root / "gone.jsonl"), "record_count": 5, "artifacts": []}), encoding="utf-8")
        short = self.root / "artifacts_media-image.json"
        short.write_text(
            json.dumps({"artifacts": [{"artifact_type": "media-image", "details": {}}], "record_count": 3}), encoding="utf-8"
        )
        broken = self.root / "artifacts_email.json"
        broken.write_text("{not json", encoding="utf-8")
        payloads = {**inputs.artifact_payloads, "browser": missing, "media-image": short, "email": broken}
        summary = run_triage_flags(TriageInputs(output_dir=self.root, artifact_payloads=payloads), self.root / "out", source_label="t")
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(summary["coverage"]["incomplete"], ["browser", "email", "media-image"])
        self.assertIn("source:browser", summary["rule_errors"])
        self.assertIn("source:email", summary["rule_errors"])
        self.assertEqual(summary["coverage"]["sources"]["media-image"], {"expected": 3, "reached": 1, "error": False})
        self.assertEqual(summary["by_rule"].get("eventlog.log_cleared"), 1)  # what was read is still flagged
        step = run_triage_stage(self.root, artifact_outputs=payloads)
        self.assertEqual((step["status"], step["coverage"], step["warning_level"]), ("completed", "partial", "warning"))
        self.assertTrue(any("일부만 계산" in message for message in step["warning_messages"]))

    def test_unreadable_files_output_makes_the_set_partial(self) -> None:
        inputs = tiny_run(self.root)
        broken = self.root / "files.json"
        broken.write_text('{"candidates": [', encoding="utf-8")
        summary = run_triage_flags(
            TriageInputs(output_dir=self.root, artifact_payloads=inputs.artifact_payloads, files_path=broken), self.root / "out", source_label="t"
        )
        self.assertEqual((summary["status"], summary["coverage"]["incomplete"]), ("partial", ["files"]))
        self.assertFalse(summary["file_listing_known"])

    def test_a_malformed_row_in_context_collection_is_isolated(self) -> None:
        inputs = tiny_run(self.root)
        with patch.object(triage_engine, "_collect_context", side_effect=RuntimeError("bad row")):
            summary = run_triage_flags(inputs, self.root / "out", source_label="t")
        self.assertEqual(summary["rule_errors"]["context"]["count"], 3)
        self.assertEqual(summary["by_rule"].get("eventlog.log_cleared"), 1)

    def test_files_listing_is_streamed_and_capped(self) -> None:
        files = {
            "summary": {"x": 1},
            "candidates": [{"path": rf"C:\Users\u\f{index}.docx", "name": f"f{index}.docx", "fs_modified_at": "2024-01-01T00:00:00Z"} for index in range(5)],
            "inventory": [{"path": rf"C:\Users\u\i{index}.bin", "name": f"i{index}.bin"} for index in range(3)],
        }
        files_path = self.root / "files.json"
        files_path.write_text(json.dumps(files), encoding="utf-8")
        inputs = TriageInputs(output_dir=self.root, artifact_payloads={}, files_path=files_path)
        with (
            patch.object(triage_engine, "FILES_LOAD_MAX_BYTES", 0),
            patch.object(triage_engine, "_load_json", side_effect=AssertionError("a large files output must be streamed")),
        ):
            summary = run_triage_flags(inputs, self.root / "out", source_label="t")
        self.assertEqual(
            summary["files_context"],
            {"rows_folded": 8, "max_rows": triage_engine.FILES_CONTEXT_MAX_ROWS, "capped": False, "listing_known": True, "streamed": True},
        )
        self.assertEqual(summary["rows_scanned"], {"files:candidates": 5, "files:inventory": 3})
        self.assertEqual(summary["status"], "completed")
        with patch.object(triage_engine, "FILES_CONTEXT_MAX_ROWS", 4):
            summary = run_triage_flags(inputs, self.root / "out2", source_label="t")
        self.assertEqual(summary["files_context"]["capped"], True)
        self.assertFalse(summary["files_context"]["streamed"])  # small output: parsed once
        self.assertEqual(summary["files_context"]["rows_folded"], 4)
        self.assertFalse(summary["file_listing_known"])  # a partial listing is "unknown", never "missing"

    def test_files_context_keeps_mtimes_only_for_documents(self) -> None:
        from rapidtriage.core.triage_rules.base import FlagContext

        ctx = FlagContext()
        payload = {"candidates": [
            {"path": r"C:\Users\u\a.docx", "name": "a.docx", "fs_modified_at": "2024-01-01T00:00:00Z"},
            {"path": r"C:\Users\u\b.bin", "name": "b.bin", "fs_modified_at": "2024-01-01T00:00:00Z"},
        ]}
        triage_engine._files_context(ctx, triage_engine.FilesOutput(payload, None))
        self.assertEqual(list(ctx.shared["file_mtimes"]), [r"c:\users\u\a.docx"])


class CatalogLabelTests(unittest.TestCase):
    def test_every_label_shown_in_the_ui_is_korean(self) -> None:
        catalog = load_catalog()
        english = []
        for family in catalog.families:
            if not re.search("[가-힣]", family["label"]):
                english.append(family["id"])
            for column in [*(family.get("core_columns") or []), *(family.get("aux_columns") or [])]:
                if not re.search("[가-힣]", column["label"]):
                    english.append(f"{family['id']}.{column['key']}")
        english += [spec.id for spec in catalog.specs.values() if not re.search("[가-힣]", spec.label_ko)]
        self.assertEqual(english, [])


class RunIntegrationTests(unittest.TestCase):
    def test_a_new_run_ends_with_the_triage_flags_step(self) -> None:
        from rapidtriage.artifacts import clear_collect_cache
        from rapidtriage.core.run import run_triage_mode
        from tests.test_rapidtriage_run import build_run_fixture

        clear_collect_cache()
        self.addCleanup(clear_collect_cache)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "case-root"
            output_dir = Path(temp) / "run-out"
            root.mkdir()
            build_run_fixture(root)
            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir)
            step = next(item for item in summary["steps"] if item["name"] == "triage-flags")
            self.assertEqual(step["status"], "completed", step)
            state_path = output_dir / "analyses" / str(step["analysis_id"]) / "analysis.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual((state["kind"], state["status"]), ("triage-flags", "completed"))
            self.assertTrue((state_path.parent / FLAGS_FILE_NAME).is_file())
            progress = json.loads((output_dir / "rapidtriage-run-progress.json").read_text(encoding="utf-8"))
            stages = [item["stage"] for item in progress["completed_stages"]]
            self.assertLess(stages.index("persist"), stages.index("triage-flags"))



class MediaOffsetTests(unittest.TestCase):
    def test_capture_offset_reads_the_parser_exif_profile(self) -> None:
        import datetime as dt

        from rapidtriage.core.triage_rules.base import RowView
        from rapidtriage.core.triage_rules.media import capture_offset, capture_utc

        row = {
            "artifact_type": "media-image",
            "details": {"exif_datetime_original": "2024:03:01 10:00:00", "exif_gps_profile": {"offset_time_original": "-05:00"}},
        }
        view = RowView(kind="media-image", collection="artifacts", source_kind="media-image", index=0, row=row)
        self.assertEqual(capture_offset(view), dt.timedelta(hours=-5))
        self.assertEqual(capture_utc(view, 9.0), (dt.datetime(2024, 3, 1, 15, 0, tzinfo=dt.timezone.utc), True))
        bare = RowView(kind="media-image", collection="artifacts", source_kind="media-image", index=0, row={"details": {"exif_datetime_original": "2024:03:01 10:00:00"}})
        self.assertEqual(capture_utc(bare, 9.0), (dt.datetime(2024, 3, 1, 1, 0, tzinfo=dt.timezone.utc), False))  # +9 assumed


if __name__ == "__main__":
    unittest.main()
