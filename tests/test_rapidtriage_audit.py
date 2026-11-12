from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import rapidtriage
from rapidtriage.cli import main
from rapidtriage.core.audit import (
    CHAIN_FIELD,
    RECORD_HASH_FIELD,
    audit_path_for,
    audit_timestamps,
    export_audit_log_path,
    verify_audit_chain,
    write_audit_record,
)
from rapidtriage.core.run import run_triage_mode
from tests import quiet_media_checks
from tests.test_rapidtriage_run import build_run_fixture

setUpModule = quiet_media_checks.setUpModule
tearDownModule = quiet_media_checks.tearDownModule


class RapidTriageAuditTests(unittest.TestCase):
    def test_audit_input_root_inventory_is_bounded_for_large_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            for index in range(6):
                (root / f"item-{index}.txt").write_text(f"artifact {index}", encoding="utf-8")

            audit_path = Path(tmp_dir) / "bounded-audit.json"
            payload = write_audit_record(
                audit_path,
                command="artifacts",
                input_root=root,
                input_root_inventory_max_files=3,
                input_root_inventory_max_dirs=20,
            )

            input_root = payload["provenance"]["input_root"]
            self.assertEqual(input_root["file_count"], 3)
            self.assertEqual(input_root["inventory_scope"], "bounded")
            self.assertTrue(input_root["inventory_truncated"])
            self.assertEqual(input_root["inventory_limits"]["max_files"], 3)

    def test_standalone_commands_write_audit_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            manifest_path = root / "manifest.json"
            docs_path = root / "docs.json"
            files_path = root / "files.json"
            artifacts_path = root / "artifacts-browser.json"
            extract_dir = root / "extract-out"
            extract_path = extract_dir / "rapidtriage-extract-manifest.json"

            self.assertEqual(main(["manifest", str(root), "--output", str(manifest_path)]), 0)
            self.assertEqual(main(["docs", str(root), "-k", "fraud", "--output", str(docs_path)]), 0)
            self.assertEqual(main(["files", str(root), "--output", str(files_path)]), 0)
            self.assertEqual(main(["artifacts", str(root), "--kind", "browser", "--output", str(artifacts_path)]), 0)
            self.assertEqual(main(["extract", str(files_path), str(extract_dir)]), 0)

            for command, output_path in (
                ("manifest", manifest_path),
                ("docs", docs_path),
                ("files", files_path),
                ("artifacts", artifacts_path),
                ("extract", extract_path),
            ):
                audit_path = audit_path_for(output_path)
                self.assertTrue(audit_path.is_file(), f"missing audit sidecar for {command}")
                audit_payload = json.loads(audit_path.read_text(encoding="utf-8"))
                self.assertEqual(audit_payload["command"], command)
                self.assertIn("provenance", audit_payload)
                self.assertIn("integrity", audit_payload)
                if command != "extract":
                    self.assertEqual(audit_payload["provenance"]["input_root"]["root_path"], str(root.resolve()))
                self.assertGreaterEqual(len(audit_payload["integrity"]["generated_outputs"]), 1)

            extract_audit = json.loads(audit_path_for(extract_path).read_text(encoding="utf-8"))
            extracted_outputs = extract_audit["integrity"]["generated_outputs"]
            self.assertTrue(any(item["label"] == "extract-manifest" for item in extracted_outputs))
            self.assertTrue(any(item["label"].startswith("extracted:") for item in extracted_outputs))
            self.assertEqual(extract_audit["provenance"]["input_files"][0]["label"], "input-json")

    def test_run_writes_audit_manifest_for_generated_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir), "--extract"]), 0)

            audit_path = output_dir / "rapidtriage-run-audit.json"
            self.assertTrue(audit_path.is_file())
            audit_payload = json.loads(audit_path.read_text(encoding="utf-8"))

            self.assertEqual(audit_payload["command"], "run")
            self.assertEqual(audit_payload["provenance"]["options"]["mode"], "fraud")
            self.assertEqual(audit_payload["provenance"]["input_root"]["root_path"], str(root.resolve()))

            output_labels = {item["label"] for item in audit_payload["integrity"]["generated_outputs"]}
            self.assertIn("run-summary", output_labels)
            self.assertIn("run-report", output_labels)
            self.assertIn("manifest", output_labels)
            self.assertTrue(any(label.startswith("docs-extract:") for label in output_labels))
            self.assertTrue(any(label.startswith("files-extract:") for label in output_labels))

    def test_run_summary_json_matches_returned_payload_including_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            payload = run_triage_mode(root, mode="fraud", output_dir=output_dir)

            summary_path = output_dir / "rapidtriage-run-summary.json"
            self.assertTrue(summary_path.is_file())

            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary_payload, payload)
            self.assertEqual(summary_payload["audit"], str((output_dir / "rapidtriage-run-audit.json").resolve()))


class ExportAuditChainTests(unittest.TestCase):
    """T-029: export audit records accumulate, carry zone-aware time and tool version, and chain."""

    def _export(self, folder: Path, name: str = "report.md") -> dict[str, object]:
        output = folder / name
        output.write_text(f"report {name}\n", encoding="utf-8")
        return write_audit_record(audit_path_for(output), command="report", output_files=[("report", output)])

    def test_two_exports_in_a_row_keep_both_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            first = self._export(folder)
            second = self._export(folder)
            log_path = export_audit_log_path(audit_path_for(folder / "report.md"))
            self.assertEqual(log_path.name, "rapidtriage-export-audit.jsonl")
            raw = log_path.read_bytes()
            self.assertNotIn(b"\r", raw)
            lines = raw.decode("utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0]), first)
            self.assertEqual(json.loads(lines[1]), second)
            self.assertEqual(first[CHAIN_FIELD], "")
            self.assertEqual(second[CHAIN_FIELD], hashlib.sha256(lines[0].encode("utf-8")).hexdigest())
            # Sidecar keeps its name and holds the latest record.
            sidecar = audit_path_for(folder / "report.md")
            self.assertEqual(sidecar.name, "report.audit.md")
            self.assertEqual(json.loads(sidecar.read_text(encoding="utf-8")), second)
            report = verify_audit_chain(log_path)
            self.assertTrue(report["ok"])
            self.assertEqual((report["records"], report["chained"], report["pre_chain_lines"]), (2, 2, 0))

    def test_record_carries_zone_aware_time_tool_version_and_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            record = self._export(Path(tmp_dir))
        local = dt.datetime.fromisoformat(str(record["generated_at"]))
        utc = dt.datetime.fromisoformat(str(record["generated_at_utc"]))
        self.assertIsNotNone(local.utcoffset())
        self.assertEqual(utc.utcoffset(), dt.timedelta(0))
        self.assertEqual(local, utc)
        self.assertRegex(str(record["generated_at"]), r"[+-]\d\d:\d\d$")
        self.assertTrue(str(record["generated_at"]).endswith(str(record["utc_offset"])))
        self.assertEqual(record["tool_name"], "rapidtriage")
        self.assertEqual(record["tool_version"], rapidtriage.__version__)
        self.assertTrue(record["tool_version"])
        self.assertEqual(record["pid"], os.getpid())
        self.assertTrue(record["host"])
        self.assertIn("os_user", record)
        self.assertEqual(record["audit_sidecar"], "report.audit.md")

    def test_timestamps_name_one_instant_in_any_zone(self) -> None:
        instant = dt.datetime(2026, 11, 12, 1, 2, 3, tzinfo=dt.timezone.utc)
        stamps = audit_timestamps(instant)
        self.assertEqual(stamps["generated_at_utc"], "2026-11-12T01:02:03+00:00")
        self.assertEqual(dt.datetime.fromisoformat(stamps["generated_at"]), instant)

    def test_editing_middle_line_is_reported_by_number(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            for index in range(4):
                self._export(folder, f"report-{index}.md")
            log_path = folder / "rapidtriage-export-audit.jsonl"
            pristine = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(pristine), 4)
            self.assertTrue(verify_audit_chain(log_path)["ok"])

            # Still valid JSON, one value changed: the line names itself.
            lines = list(pristine)
            lines[1] = lines[1].replace('"command":"report"', '"command":"rep0rt"')
            self.assertNotEqual(lines[1], pristine[1])
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            report = verify_audit_chain(log_path)
            self.assertFalse(report["ok"])
            self.assertEqual(report["first_broken_line"], 2)
            self.assertEqual([item["line"] for item in report["broken_lines"]], [2])

            # One byte changed so the line is no longer JSON.
            lines = list(pristine)
            lines[2] = lines[2][:-1]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            report = verify_audit_chain(log_path)
            self.assertEqual([item["line"] for item in report["broken_lines"]], [3])

            # Hash fields recomputed by hand for the edited line: the next line's chain still names it.
            lines = list(pristine)
            edited = json.loads(lines[1])
            edited["command"] = "forged"
            edited.pop(RECORD_HASH_FIELD)
            canonical = json.dumps(edited, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            edited[RECORD_HASH_FIELD] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            lines[1] = json.dumps(edited, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            report = verify_audit_chain(log_path)
            self.assertEqual(report["first_broken_line"], 2)

            # A removed line is reported at the line before the gap.
            lines = [pristine[0], pristine[1], pristine[3]]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            self.assertEqual(verify_audit_chain(log_path)["first_broken_line"], 2)

    def test_old_records_are_pre_chain_not_broken(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            old_record = {"command": "report", "generated_at": "2026-04-23T10:00:00", "provenance": {}, "integrity": {}}
            sidecar = folder / "old.audit.json"
            sidecar.write_text(json.dumps(old_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            report = verify_audit_chain(sidecar)
            self.assertTrue(report["ok"])
            self.assertEqual((report["records"], report["pre_chain_lines"]), (1, 1))
            self.assertEqual(report["pre_chain_label"], "사슬 이전 1줄")

            log_path = folder / "rapidtriage-export-audit.jsonl"
            log_path.write_text("".join(json.dumps(old_record) + "\n" for _ in range(4)), encoding="utf-8", newline="\n")
            report = verify_audit_chain(log_path)
            self.assertTrue(report["ok"])
            self.assertEqual(report["pre_chain_lines"], 4)
            self.assertEqual(report["pre_chain_label"], "사슬 이전 4줄")

            # New exports chain on from the old lines; the old lines stay untouched and pre-chain.
            before = log_path.read_bytes()
            appended = self._export(folder)
            self.assertTrue(log_path.read_bytes().startswith(before))
            last_old = before.decode("utf-8").splitlines()[-1]
            self.assertEqual(appended[CHAIN_FIELD], hashlib.sha256(last_old.encode("utf-8")).hexdigest())
            report = verify_audit_chain(log_path)
            self.assertTrue(report["ok"])
            self.assertEqual((report["records"], report["pre_chain_lines"], report["chained"]), (5, 4, 1))

            # Stripping the chain field from a line after the chain started is not "pre-chain".
            lines = log_path.read_text(encoding="utf-8").splitlines()
            stripped = json.loads(lines[-1])
            stripped.pop(CHAIN_FIELD)
            lines[-1] = json.dumps(stripped)
            self._export(folder, "again.md")
            lines.append(log_path.read_text(encoding="utf-8").splitlines()[-1])
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            self.assertEqual(verify_audit_chain(log_path)["first_broken_line"], 5)

    def test_upgrade_check_accepts_the_chain(self) -> None:
        import importlib.util

        script = Path(__file__).resolve().parents[1] / "scripts" / "r8-upgrade-check.py"
        spec = importlib.util.spec_from_file_location("r8_upgrade_check_for_audit", script)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir)
            for index in range(3):
                self._export(folder, f"r-{index}.md")
            result = module.check_audit([folder / "rapidtriage-export-audit.jsonl"])
        self.assertEqual(module.CHAIN_FIELD, CHAIN_FIELD)
        self.assertEqual((result["records"], result["chained"], result["broken"]), (3, 3, 0))


if __name__ == "__main__":
    unittest.main()
