from __future__ import annotations

import contextlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any

from rapidtriage.cli import build_parser, main
from rapidtriage.core.artifacts import SUPPORTED_ARTIFACT_KINDS
from rapidtriage.core.input_root import InputRoot
from rapidtriage.core.reporting import build_run_report_context, render_run_markdown_report
from rapidtriage.core.run import (
    RUN_PROFILES,
    build_checkpoint_resume_trusted_diff,
    build_incremental_indexing_trusted_diff,
    build_memory_cap_trusted_diff,
    build_parser_crash_trusted_diff,
    build_parser_scheduler_manifest,
    build_scheduler_trusted_diff,
    checkpoint_resume_core_accuracy_gates,
    incremental_indexing_core_accuracy_gates,
    isolated_parser_error_payload,
    memory_cap_enforcement_assessment,
    memory_cap_policy_profile,
    memory_cap_stage_check_row,
    parallel_parser_scheduler_assessment,
    parser_crash_isolation_assessment,
)
from rapidtriage.core.run_workflow import (
    RUN_WORKFLOW_STAGE_ORDER,
    build_run_workflow_contract,
    output_handoff_for_key,
    stage_for_output_name,
    stage_for_step_name,
)
from rapidtriage.core.silent_failure import build_silent_failure_report
from tests.windows_artifact_fixtures import build_windows_artifact_fixture


def write_minimal_docx(path: Path, text: str) -> None:
    xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "")
        archive.writestr("word/document.xml", xml)


def write_minimal_pdf(path: Path, text: str) -> None:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1")
    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n")
    objects.append(f"4 0 obj << /Length {len(stream)} >> stream\n".encode("latin-1") + stream + b"\nendstream endobj\n")
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for item in objects:
        offsets.append(len(output))
        output.extend(item)
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    output.extend(
        (
            f"trailer << /Root 1 0 R /Size {len(offsets)} >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("latin-1")
    )
    path.write_bytes(bytes(output))


def build_run_fixture(root: Path) -> None:
    build_windows_artifact_fixture(root)
    suspicious_blob = (
        "invoice payment wire transfer payroll login password credential phishing "
        "powershell remote access persistence ransomware browser history shellbags "
        "download recent evidence restore deleted"
    )
    user_root = root / "Users" / "alice"

    docs_dir = user_root / "Documents"
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "wire-transfer-notes.txt").write_text(suspicious_blob, encoding="utf-8")
    write_minimal_docx(docs_dir / "breach-summary.docx", suspicious_blob)
    write_minimal_pdf(docs_dir / "attacker-activity.pdf", suspicious_blob)

    downloads_dir = user_root / "Downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    (downloads_dir / "evidence-bundle.zip").write_bytes(b"PK\x03\x04" + (b"A" * 262144))
    (downloads_dir / "payload-installer.exe").write_bytes(b"MZ\x90\x00")

    desktop_dir = user_root / "Desktop"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    (desktop_dir / "persistence-runner.bat").write_text("@echo off\r\npowershell -enc AAA=", encoding="utf-8")
    (desktop_dir / "screen-capture.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    startup_dir = user_root / "Startup"
    startup_dir.mkdir(parents=True, exist_ok=True)
    (startup_dir / "startup-dropper.ps1").write_text("Write-Host compromised", encoding="utf-8")

    db_dir = user_root / "Databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "browser-cache.sqlite").write_text("SQLite format 3", encoding="utf-8")

    recycle_dir = root / "$Recycle.Bin" / "alice"
    recycle_dir.mkdir(parents=True, exist_ok=True)
    (recycle_dir / "deleted-wallet-note.txt").write_text("deleted recovery note with recent restore hints", encoding="utf-8")
    (recycle_dir / "deleted-bundle.zip").write_bytes(b"PK\x03\x04" + (b"B" * 131072))
    (recycle_dir / "deleted-photo.jpg").write_bytes(b"\xff\xd8\xff" + (b"\x00" * 4096))


class RapidTriageRunTests(unittest.TestCase):
    def test_parser_exposes_run_subcommand_and_examples(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("run", commands)

        root_help = parser.format_help()
        run_help = commands["run"].format_help()

        self.assertIn("rapidtriage run", root_help)
        self.assertIn("--mode", run_help)
        self.assertIn("fraud", run_help)
        self.assertIn("hacking", run_help)
        self.assertIn("--memory-cap-bytes", run_help)
        self.assertIn("--resume", run_help)
        self.assertIn("source-read", commands)
        self.assertIn("--sqlite-table", commands["source-read"].format_help())
        self.assertIn("source-search", commands)
        self.assertIn("archive.zip::entry", commands["source-search"].format_help())

    def test_run_fraud_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("fraud")

    def test_run_hacking_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("hacking")

    def test_run_seizure_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("seizure")

    def test_run_recovery_mode_writes_component_outputs_summary_and_report(self) -> None:
        self.assert_run_mode_outputs("recovery")

    def test_investigative_run_profiles_cover_all_supported_artifact_collectors(self) -> None:
        supported = set(SUPPORTED_ARTIFACT_KINDS)

        for mode in ("seizure", "fraud", "hacking"):
            with self.subTest(mode=mode):
                self.assertEqual(set(RUN_PROFILES[mode].artifacts_kinds), supported)

        self.assertEqual(
            supported - set(RUN_PROFILES["recovery"].artifacts_kinds),
            {"browser", "windows-execution", "windows-system"},
        )

    def test_parser_crash_isolation_payload_and_memory_cap_assessment_are_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = isolated_parser_error_payload(
                "eventlog",
                input_root=InputRoot(source_path=tmp_dir, root_path=Path(tmp_dir), kind="directory"),
                exc=RuntimeError("synthetic parser crash"),
            )
            self.assertEqual(payload["summary"]["parser_error_count"], 1)
            self.assertIn("#71", payload["parser_errors"][0]["commercial_gap_ids"])
            self.assertRegex(payload["parser_errors"][0]["error_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                payload["parser_errors"][0]["crash_context"]["profile_version"],
                "isolated-parser-crash-context-v1",
            )
            self.assertEqual(payload["parser_error_inventory"]["profile_version"], "parser-error-inventory-v1")
            self.assertEqual(payload["parser_error_inventory"]["parser_error_count"], 1)
            self.assertEqual(
                payload["parser_crash_isolation_manifest"]["profile_version"],
                "parser-crash-isolation-manifest-v1",
            )
            self.assertEqual(payload["parser_crash_isolation_manifest"]["item_number"], 28)
            self.assertEqual(len(payload["parser_crash_isolation_manifest"]["manifest_hash"]), 64)
            self.assertTrue(payload["parser_crash_isolation_manifest"]["run_continuation_expected"])
            self.assertTrue(payload["parser_crash_isolation_manifest"]["quarantine_policy"]["safe_to_continue_later_stages"])
            self.assertIn("#71", payload["parser_crash_isolation"]["commercial_gap_ids"])
            self.assertEqual(
                payload["parser_crash_isolation"]["parser_crash_manifest_hash"],
                payload["parser_crash_isolation_manifest"]["manifest_hash"],
            )
            self.assertEqual(payload["parser_crash_isolation"]["core_accuracy_gates"][0]["gap_id"], "#71")
            self.assertIn(
                "per-parser exception capture",
                payload["parser_crash_isolation"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "parser error hash emitted",
                payload["parser_crash_isolation"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "parser crash isolation manifest hash emitted",
                payload["parser_crash_isolation"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            crash_diff = build_parser_crash_trusted_diff(payload, payload)
            crash_gates = parser_crash_isolation_assessment(error_count=1, trusted_diff=crash_diff)
            self.assertEqual(crash_diff["status"], "pass")
            self.assertIn("trusted parser crash-corpus diff pass", crash_gates["core_accuracy_gates"][0]["satisfied_checks"])

        stage_rows = [
            memory_cap_stage_check_row("prepare", 123456, sequence=1, current_rss_bytes=4096),
            memory_cap_stage_check_row("docs", 123456, sequence=2, current_rss_bytes=8192),
        ]
        assessment = memory_cap_enforcement_assessment(memory_cap_bytes=123456, stage_checks=stage_rows)
        self.assertEqual(assessment["memory_cap_bytes"], 123456)
        self.assertEqual(assessment["memory_cap_policy_profile"]["profile_version"], "memory-cap-policy-profile-v1")
        self.assertTrue(assessment["memory_cap_policy_profile"]["cap_configured"])
        self.assertIn("utilization_percent", assessment["memory_cap_policy_profile"])
        telemetry = assessment["memory_cap_stage_telemetry_manifest"]
        self.assertEqual(telemetry["profile_version"], "memory-cap-stage-telemetry-manifest-v1")
        self.assertEqual(telemetry["item_number"], 72)
        self.assertEqual(telemetry["stage_check_count"], 2)
        self.assertEqual(telemetry["first_stage"], "prepare")
        self.assertEqual(telemetry["last_stage"], "docs")
        self.assertRegex(telemetry["row_head_hash"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(telemetry["manifest_hash"]), 64)
        self.assertEqual(
            assessment["memory_cap_enforcement_manifest"]["profile_version"],
            "memory-cap-enforcement-manifest-v1",
        )
        self.assertEqual(assessment["memory_cap_enforcement_manifest"]["item_number"], 29)
        self.assertEqual(assessment["memory_cap_enforcement_manifest"]["gap_id"], "#29")
        self.assertEqual(assessment["memory_cap_enforcement_manifest"]["commercial_gap_ids"], ["#72"])
        self.assertEqual(assessment["memory_cap_enforcement_manifest"]["enforcement_mode"], "python-process-stage-boundary-rss-check")
        self.assertEqual(
            assessment["memory_cap_enforcement_manifest"]["stage_telemetry_manifest_hash"],
            telemetry["manifest_hash"],
        )
        self.assertEqual(assessment["memory_cap_enforcement_manifest"]["stage_check_count"], 2)
        self.assertFalse(assessment["memory_cap_enforcement_manifest"]["hard_os_limit_configured"])
        self.assertEqual(len(assessment["memory_cap_enforcement_manifest"]["manifest_hash"]), 64)
        self.assertEqual(
            assessment["memory_cap_manifest_hash"],
            assessment["memory_cap_enforcement_manifest"]["manifest_hash"],
        )
        self.assertIn("#72", assessment["commercial_gap_ids"])
        self.assertEqual(assessment["core_accuracy_gates"][0]["gap_id"], "#72")
        self.assertIn("memory cap configuration recorded", assessment["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn("memory cap policy profile emitted", assessment["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn("stage telemetry row hashes emitted", assessment["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn("memory cap enforcement manifest hash emitted", assessment["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn("trusted-memory-cap-rss-diff-missing", assessment["blockers"])
        memory_diff = build_memory_cap_trusted_diff(assessment, assessment)
        memory_assessment = memory_cap_enforcement_assessment(memory_cap_bytes=123456, trusted_diff=memory_diff)
        self.assertEqual(memory_diff["status"], "pass")
        self.assertIn("trusted memory cap/RSS diff pass", memory_assessment["core_accuracy_gates"][0]["satisfied_checks"])

        policy = memory_cap_policy_profile(memory_cap_bytes=100, current_rss_bytes=125)
        self.assertTrue(policy["over_cap"])
        self.assertEqual(policy["utilization_percent"], 125.0)
        scheduler_manifest = build_parser_scheduler_manifest(
            kinds=["browser", "windows"],
            max_workers=2,
            events=[],
            pending_count=2,
        )
        scheduler = parallel_parser_scheduler_assessment(["browser", "windows"], scheduler_manifest=scheduler_manifest)
        self.assertIn("trusted-parser-scheduler-manifest-diff-missing", scheduler["blockers"])
        self.assertIn("per-worker duration telemetry emitted", scheduler["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertEqual(scheduler["scheduler_manifest"]["profile"], "parser-scheduler-run-manifest-v1")
        self.assertIn("events_head_hash", scheduler["scheduler_manifest"])
        self.assertIn("scheduler_event_row_head_hash", scheduler["scheduler_manifest"])
        self.assertRegex(scheduler["scheduler_manifest"]["resource_policy_hash"], r"^[0-9a-f]{64}$")
        self.assertTrue(scheduler["scheduler_manifest"]["deterministic_order_verified"])
        scheduler_diff = build_scheduler_trusted_diff(scheduler, scheduler)
        scheduler_trusted = parallel_parser_scheduler_assessment(["browser", "windows"], trusted_diff=scheduler_diff)
        self.assertEqual(scheduler_diff["status"], "pass")
        self.assertIn("trusted scheduler manifest diff pass", scheduler_trusted["core_accuracy_gates"][0]["satisfied_checks"])

    def test_run_supports_read_only_extract_safety(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            exit_code = main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir), "--read-only"])

            self.assertEqual(exit_code, 0)
            summary_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary_payload["safety"]["read_only"], True)
            self.assertEqual(summary_payload["processing"]["profile_label"], "Fast first pass - read-only")
            self.assertGreaterEqual(summary_payload["processing"]["warning_count"], 1)

            docs_extract_step = next(
                step for step in summary_payload["steps"] if step["name"] == "docs-extract"
            )
            files_extract_step = next(
                step for step in summary_payload["steps"] if step["name"] == "files-extract"
            )
            self.assertEqual(docs_extract_step["status"], "skipped")
            self.assertEqual(files_extract_step["status"], "skipped")
            self.assertEqual(docs_extract_step["skip_reasons"]["read-only"], docs_extract_step["skipped_count"])
            self.assertIn("Extraction skipped by read-only profile.", docs_extract_step["warning_messages"])

            docs_extract_payload = json.loads(
                (output_dir / "docs-extract" / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8")
            )
            files_extract_payload = json.loads(
                (output_dir / "files-extract" / "rapidtriage-extract-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(docs_extract_payload["summary"]["extracted_count"], 0)
            self.assertGreaterEqual(docs_extract_payload["summary"]["skipped_count"], 1)
            self.assertEqual(files_extract_payload["summary"]["extracted_count"], 0)
            self.assertGreaterEqual(files_extract_payload["summary"]["skipped_count"], 1)

            report_text = (output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8")
            self.assertIn("Processing decisions / skipped, capped, reused", report_text)
            self.assertIn("Workflow analyst checklist", report_text)
            self.assertIn("Stage verification items", report_text)
            self.assertIn("Checklist status:", report_text)
            self.assertIn("Read-only mode was enabled", report_text)
            self.assertIn("docs-extract` status=`skipped", report_text)

    def test_run_workflow_contract_maps_internal_steps_to_analyst_flow(self) -> None:
        steps = [
            {"name": "manifest", "status": "completed", "output": "/case/manifest.json", "warning_level": "none"},
            {"name": "docs-extract", "status": "completed", "output": "/case/extract.json", "warning_level": "none"},
            {"name": "artifacts-eventlog", "status": "completed", "output": "/case/eventlog.json", "warning_level": "none"},
            {"name": "timeline", "status": "completed", "output": "/case/timeline.json", "warning_level": "none"},
            {
                "name": "silent-failure-detection",
                "status": "completed",
                "output": "inline",
                "warning_level": "notice",
                "warning_messages": ["eventlog target exists but zero rows were collected"],
            },
        ]
        outputs = {
            "fingerprint": Path("/case/fingerprint.json"),
            "docs_extract_manifest": Path("/case/docs-extract.json"),
            "manifest": Path("/case/manifest.json"),
            "artifacts_eventlog": Path("/case/eventlog.json"),
            "timeline": Path("/case/timeline.json"),
            "report": Path("/case/report.md"),
        }

        contract = build_run_workflow_contract(
            steps=steps,
            outputs=outputs,
            safety={"read_only": False, "resume": False},
            source={"type": "e01", "source_path": "/evidence/case.E01", "analysis_root": "/case/root"},
        )

        self.assertEqual(contract["profile_version"], "run-workflow-contract-v1")
        self.assertEqual(contract["stage_order"], list(RUN_WORKFLOW_STAGE_ORDER))
        self.assertEqual(contract["stage_lookup"]["ingest"], "completed")
        self.assertEqual(contract["stage_lookup"]["review"], "warning")
        self.assertEqual(
            contract["analyst_checklist_summary"]["profile_version"],
            "run-workflow-analyst-checklist-summary-v1",
        )
        self.assertGreaterEqual(contract["analyst_checklist_summary"]["item_count"], 8)
        self.assertGreaterEqual(contract["analyst_checklist_summary"]["warning_count"], 1)
        self.assertTrue(contract["analyst_checklist_summary"]["next_actions"])
        self.assertEqual(stage_for_step_name("artifacts-eventlog"), "parse")
        self.assertEqual(stage_for_output_name("artifacts_eventlog"), "parse")
        artifact_handoff = output_handoff_for_key("artifacts_eventlog")
        self.assertEqual(artifact_handoff["recommended_viewer"], "artifact-table-viewer")
        self.assertIn("artifact rows", artifact_handoff["role"])
        self.assertRegex(str(contract["stage_hash"]), r"^[0-9a-f]{64}$")
        parse_stage = next(stage for stage in contract["stages"] if stage["id"] == "parse")
        parse_handoff_names = {handoff["name"] for handoff in parse_stage["handoff_outputs"]}
        self.assertIn("artifacts_eventlog", parse_handoff_names)
        self.assertIn("manifest", parse_handoff_names)
        parse_checklist = {item["id"]: item for item in parse_stage["analyst_checklist"]}
        self.assertEqual(parse_checklist["parse:artifact-rows"]["status"], "ready")
        self.assertIn("artifacts_eventlog", parse_checklist["parse:artifact-rows"]["matched_outputs"])
        review_stage = next(stage for stage in contract["stages"] if stage["id"] == "review")
        self.assertIn("silent-failure-detection", review_stage["step_names"])
        self.assertGreaterEqual(review_stage["warning_count"], 1)
        review_checklist = {item["id"]: item for item in review_stage["analyst_checklist"]}
        self.assertEqual(review_checklist["review:warning-review"]["status"], "warning")
        self.assertIn("Review review warnings", review_checklist["review:warning-review"]["action"])
        report_stage = next(stage for stage in contract["stages"] if stage["id"] == "report")
        self.assertEqual(report_stage["handoff_outputs"][0]["recommended_viewer"], "report-viewer")
        self.assertEqual(report_stage["analyst_checklist"][0]["status"], "ready")

    def test_silent_failure_detector_flags_target_files_without_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            logs = root / "Windows" / "System32" / "winevt" / "Logs"
            logs.mkdir(parents=True)
            (logs / "Security.evtx").write_bytes(b"ElfFile\x00")

            report = build_silent_failure_report(
                root=root,
                docs_payload={"summary": {"candidate_count": 0, "match_count": 0}},
                files_payload={"summary": {"scanned_file_count": 1, "candidate_count": 0}},
                docs_extract_payload={"summary": {"selected_count": 0, "extracted_count": 0, "skipped_count": 0}},
                files_extract_payload={"summary": {"selected_count": 0, "extracted_count": 0, "skipped_count": 0}},
                artifact_payloads={"eventlog": {"summary": {"artifact_count": 0, "parser_error_count": 0}}},
                timeline_payload={"summary": {"event_count": 0}},
                safety={},
            )

            self.assertEqual(report["status"], "warning")
            self.assertTrue(report["silent_failure_risk"])
            self.assertGreaterEqual(report["risk_check_count"], 1)
            self.assertEqual(report["target_inventory"]["target_counts"]["eventlog"], 1)
            warning_ids = {item["id"] for item in report["checks"] if item["level"] == "warning"}
            self.assertIn("artifact-yield-eventlog", warning_ids)

    def test_run_resume_reuses_valid_stage_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir), "--resume"]), 0)

            summary_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary_payload["safety"]["resume"], True)
            self.assertIn("docs", summary_payload["safety"]["reused_outputs"])
            self.assertIn("files", summary_payload["safety"]["reused_outputs"])
            self.assertIn("timeline", summary_payload["safety"]["reused_outputs"])
            self.assertTrue(summary_payload["safety"]["resume_effective"])
            self.assertGreaterEqual(summary_payload["processing"]["reused_output_count"], 5)
            self.assertIn("#68", summary_payload["processing"]["incremental_indexing"]["commercial_gap_ids"])
            self.assertIn("#70", summary_payload["processing"]["checkpoint_resume"]["commercial_gap_ids"])
            incremental_uplift = summary_payload["processing"]["incremental_indexing"]["commercial_uplift_evidence"]
            self.assertEqual(incremental_uplift["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(incremental_uplift["item_numbers"], [68])
            self.assertIn("bounded fingerprint", " ".join(incremental_uplift["large_data_controls"]))
            self.assertEqual(
                incremental_uplift["reportability_decision"]["decision"],
                "do-not-report-incremental-indexing-as-content-hash-complete",
            )
            checkpoint_uplift = summary_payload["processing"]["checkpoint_resume"]["commercial_uplift_evidence"]
            self.assertEqual(checkpoint_uplift["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(checkpoint_uplift["item_numbers"], [70])
            self.assertIn("stage status records", " ".join(checkpoint_uplift["large_data_controls"]))
            self.assertEqual(
                checkpoint_uplift["reportability_decision"]["allowed_use"],
                "stage-checkpoint-resume-triage-pivot",
            )
            self.assertIn("#71", summary_payload["processing"]["parser_crash_isolation"]["commercial_gap_ids"])
            parser_crash_ledger_path = Path(summary_payload["outputs"]["parser_crash_isolation"])
            self.assertTrue(parser_crash_ledger_path.is_file())
            parser_crash_ledger = json.loads(parser_crash_ledger_path.read_text(encoding="utf-8"))
            self.assertEqual(parser_crash_ledger["profile_version"], "parser-crash-isolation-ledger-v1")
            self.assertEqual(parser_crash_ledger["item_number"], 71)
            self.assertEqual(len(parser_crash_ledger["manifest_hash"]), 64)
            continuation_manifest = parser_crash_ledger["parser_crash_continuation_manifest"]
            self.assertEqual(
                continuation_manifest["profile_version"],
                "parser-crash-continuation-manifest-v1",
            )
            self.assertEqual(continuation_manifest["item_number"], 71)
            self.assertEqual(len(continuation_manifest["manifest_hash"]), 64)
            self.assertRegex(continuation_manifest["row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                parser_crash_ledger["parser_crash_continuation_manifest_hash"],
                continuation_manifest["manifest_hash"],
            )
            self.assertEqual(
                summary_payload["processing"]["parser_crash_isolation"][
                    "parser_crash_continuation_manifest_hash"
                ],
                continuation_manifest["manifest_hash"],
            )
            self.assertIn(
                "parser crash continuation manifest hash emitted",
                summary_payload["processing"]["parser_crash_isolation"]["core_accuracy_gates"][0][
                    "satisfied_checks"
                ],
            )
            self.assertTrue(parser_crash_ledger["run_continuation_verified"])
            self.assertTrue(
                parser_crash_ledger["isolation_policy"]["one_parser_error_does_not_abort_case_run"]
            )
            self.assertEqual(
                summary_payload["processing"]["parser_crash_isolation"]["parser_crash_manifest_hash"],
                parser_crash_ledger["manifest_hash"],
            )
            self.assertIn("#72", summary_payload["processing"]["memory_cap_enforcement"]["commercial_gap_ids"])
            memory_cap_ledger_path = Path(summary_payload["outputs"]["memory_cap_enforcement"])
            self.assertTrue(memory_cap_ledger_path.is_file())
            memory_cap_ledger = json.loads(memory_cap_ledger_path.read_text(encoding="utf-8"))
            self.assertEqual(memory_cap_ledger["profile_version"], "memory-cap-enforcement-manifest-v1")
            self.assertEqual(memory_cap_ledger["commercial_gap_ids"], ["#72"])
            self.assertEqual(len(memory_cap_ledger["manifest_hash"]), 64)
            self.assertRegex(memory_cap_ledger["stage_telemetry_manifest_hash"], r"^[0-9a-f]{64}$")
            self.assertGreater(memory_cap_ledger["stage_check_count"], 0)
            self.assertRegex(memory_cap_ledger["stage_row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                summary_payload["processing"]["memory_cap_enforcement"]["memory_cap_manifest_hash"],
                memory_cap_ledger["manifest_hash"],
            )
            memory_cap_telemetry = summary_payload["processing"]["memory_cap_enforcement"][
                "memory_cap_stage_telemetry_manifest"
            ]
            self.assertEqual(
                summary_payload["processing"]["memory_cap_enforcement"][
                    "memory_cap_stage_telemetry_manifest_hash"
                ],
                memory_cap_telemetry["manifest_hash"],
            )
            self.assertEqual(memory_cap_ledger["stage_telemetry_manifest_hash"], memory_cap_telemetry["manifest_hash"])
            self.assertGreaterEqual(memory_cap_telemetry["stage_check_count"], 8)
            self.assertEqual(memory_cap_telemetry["first_stage"], "prepare")
            self.assertEqual(memory_cap_telemetry["last_stage"], "indicators")
            self.assertFalse(memory_cap_ledger["hard_os_limit_configured"])
            preview_policy_path = Path(summary_payload["outputs"]["preview_sandbox_policy"])
            self.assertTrue(preview_policy_path.is_file())
            preview_policy = json.loads(preview_policy_path.read_text(encoding="utf-8"))
            self.assertEqual(preview_policy["profile_version"], "preview-sandbox-run-policy-manifest-v1")
            self.assertEqual(preview_policy["item_number"], 73)
            self.assertFalse(preview_policy["policy"]["executes_content"])
            self.assertFalse(preview_policy["policy"]["external_network_access"])
            self.assertTrue(preview_policy["policy"]["active_content_blocking"])
            self.assertGreater(preview_policy["preview_policy_row_count"], 0)
            self.assertRegex(preview_policy["preview_policy_row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                preview_policy["preview_policy_row_count"],
                len(preview_policy["preview_policy_rows"]),
            )
            self.assertRegex(preview_policy["preview_policy_rows"][0]["row_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                summary_payload["processing"]["preview_sandboxing"]["preview_sandbox_policy_manifest_hash"],
                preview_policy["manifest_hash"],
            )
            self.assertIn(
                "preview policy row hashes emitted",
                summary_payload["processing"]["preview_sandboxing"]["core_accuracy_gates"][0][
                    "satisfied_checks"
                ],
            )
            sqlite_fts_path = Path(summary_payload["outputs"]["sqlite_fts_optimization"])
            self.assertTrue(sqlite_fts_path.is_file())
            sqlite_fts = json.loads(sqlite_fts_path.read_text(encoding="utf-8"))
            self.assertEqual(sqlite_fts["profile_version"], "sqlite-fts-run-optimization-manifest-v1")
            self.assertEqual(sqlite_fts["item_number"], 74)
            self.assertIn("manifest_hash", sqlite_fts)
            self.assertEqual(sqlite_fts["tracked_output_row_count"], len(sqlite_fts["tracked_outputs"]))
            self.assertRegex(sqlite_fts["tracked_output_row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(sqlite_fts["tracked_outputs"][0]["row_hash"], r"^[0-9a-f]{64}$")
            self.assertTrue(sqlite_fts["optimization_policy"]["cursor_pagination_required"])
            self.assertFalse(sqlite_fts["optimization_policy"]["ten_million_row_regression_attached"])
            self.assertEqual(
                summary_payload["processing"]["sqlite_fts_optimization"]["sqlite_fts_optimization_manifest_hash"],
                sqlite_fts["manifest_hash"],
            )
            self.assertIn("#75", summary_payload["processing"]["parallel_parser_scheduler"]["commercial_gap_ids"])
            scheduler_manifest = summary_payload["processing"]["parallel_parser_scheduler"]["scheduler_manifest"]
            self.assertEqual(scheduler_manifest["profile"], "parser-scheduler-run-manifest-v1")
            self.assertIn("manifest_hash", scheduler_manifest)
            self.assertIn("events_head_hash", scheduler_manifest)
            self.assertTrue(scheduler_manifest["deterministic_order_verified"])
            self.assertEqual(scheduler_manifest["resource_policy"]["backpressure_window"], scheduler_manifest["max_workers"])
            self.assertEqual(scheduler_manifest["deterministic_output_order"], list(summary_payload["safety"]["artifact_scheduler"]["manifest"]["deterministic_output_order"]))
            self.assertTrue(scheduler_manifest["resource_policy"]["cpu_worker_limit"] <= 4)
            self.assertTrue(scheduler_manifest["events"])
            self.assertEqual(scheduler_manifest["event_row_count"], len(scheduler_manifest["events"]))
            self.assertRegex(scheduler_manifest["scheduler_event_row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(scheduler_manifest["events"][0]["row_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(scheduler_manifest["resource_policy_hash"], r"^[0-9a-f]{64}$")
            runtime_profiles = summary_payload["processing"]["runtime_defensibility_profiles"]
            self.assertEqual(runtime_profiles["batch_id"], "commercial-uplift-071-075")
            self.assertEqual(runtime_profiles["item_numbers"], [71, 72, 73, 74, 75])
            self.assertFalse(runtime_profiles["ready_for_commercial_claim"])
            self.assertIn("trusted-preview-no-exec-diff-missing", runtime_profiles["blockers"])
            runtime_by_number = {profile["item_number"]: profile for profile in runtime_profiles["profiles"]}
            self.assertEqual(runtime_by_number[71]["component"], "parser-crash-isolation")
            self.assertTrue(runtime_by_number[71]["controls"]["isolated_error_payloads"])
            self.assertRegex(
                runtime_by_number[71]["controls"]["parser_crash_continuation_manifest_hash"],
                r"^[0-9a-f]{64}$",
            )
            self.assertGreater(runtime_by_number[71]["controls"]["parser_crash_continuation_row_count"], 0)
            self.assertEqual(runtime_by_number[72]["component"], "memory-cap-enforcement")
            self.assertTrue(runtime_by_number[72]["controls"]["stage_boundary_checks"])
            self.assertEqual(
                runtime_by_number[72]["controls"]["stage_telemetry_manifest_hash"],
                memory_cap_telemetry["manifest_hash"],
            )
            self.assertEqual(
                runtime_by_number[72]["controls"]["stage_check_count"],
                memory_cap_telemetry["stage_check_count"],
            )
            self.assertRegex(runtime_by_number[72]["controls"]["stage_row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(runtime_by_number[73]["component"], "preview-sandboxing")
            self.assertTrue(runtime_by_number[73]["controls"]["active_content_blocking_declared"])
            self.assertEqual(
                runtime_by_number[73]["controls"]["run_preview_sandbox_policy_manifest_hash"],
                preview_policy["manifest_hash"],
            )
            self.assertEqual(
                runtime_by_number[73]["controls"]["preview_policy_row_count"],
                preview_policy["preview_policy_row_count"],
            )
            self.assertEqual(
                runtime_by_number[73]["controls"]["preview_policy_row_head_hash"],
                preview_policy["preview_policy_row_head_hash"],
            )
            self.assertEqual(runtime_by_number[74]["component"], "large-sqlite-fts-optimization")
            self.assertTrue(runtime_by_number[74]["controls"]["bounded_sqlite_preview_contract"])
            self.assertEqual(
                runtime_by_number[74]["controls"]["run_sqlite_fts_optimization_manifest_hash"],
                sqlite_fts["manifest_hash"],
            )
            self.assertEqual(
                runtime_by_number[74]["controls"]["tracked_output_row_count"],
                sqlite_fts["tracked_output_row_count"],
            )
            self.assertEqual(
                runtime_by_number[74]["controls"]["tracked_output_row_head_hash"],
                sqlite_fts["tracked_output_row_head_hash"],
            )
            self.assertEqual(runtime_by_number[75]["component"], "parallel-parser-scheduler")
            self.assertTrue(runtime_by_number[75]["controls"]["deterministic_output_paths"])
            self.assertTrue(runtime_by_number[75]["controls"]["per_worker_duration_telemetry"])
            self.assertEqual(runtime_by_number[75]["controls"]["scheduler_manifest_profile"], "parser-scheduler-run-manifest-v1")
            self.assertEqual(
                runtime_by_number[75]["controls"]["scheduler_events_head_hash"],
                scheduler_manifest["events_head_hash"],
            )
            self.assertEqual(
                runtime_by_number[75]["controls"]["scheduler_event_row_head_hash"],
                scheduler_manifest["scheduler_event_row_head_hash"],
            )
            self.assertEqual(
                runtime_by_number[75]["controls"]["scheduler_event_row_count"],
                scheduler_manifest["event_row_count"],
            )
            self.assertEqual(
                runtime_by_number[75]["controls"]["resource_policy_hash"],
                scheduler_manifest["resource_policy_hash"],
            )
            self.assertTrue(runtime_by_number[75]["controls"]["deterministic_order_verified"])
            large_data_profiles = summary_payload["processing"]["functional_large_data_profiles"]
            self.assertEqual(large_data_profiles["batch_id"], "commercial-uplift-026-030")
            self.assertEqual(large_data_profiles["item_numbers"], [26, 28, 29, 30])
            self.assertFalse(large_data_profiles["ready_for_commercial_claim"])
            streaming_boundary = summary_payload["processing"]["streaming_parser_boundary"]
            self.assertEqual(streaming_boundary["profile_version"], "streaming-parser-boundary-manifest-v1")
            self.assertEqual(streaming_boundary["item_number"], 26)
            self.assertEqual(len(streaming_boundary["manifest_hash"]), 64)
            self.assertGreaterEqual(streaming_boundary["parser_stage_count"], 1)
            self.assertGreaterEqual(streaming_boundary["bounded_stage_count"], 1)
            self.assertEqual(streaming_boundary["streaming_safe_claim_count"], 0)
            self.assertTrue(streaming_boundary["benchmark_required"])
            self.assertTrue(streaming_boundary["policy"]["full_file_reads_are_reportable_only_when_explicitly_bounded"])
            profile_by_number = {profile["item_number"]: profile for profile in large_data_profiles["profiles"]}
            self.assertEqual(profile_by_number[26]["component"], "streaming-parser-boundary")
            self.assertTrue(profile_by_number[26]["controls"]["stage_outputs_are_bounded_json"])
            self.assertEqual(
                profile_by_number[26]["controls"]["streaming_boundary_manifest_hash"],
                streaming_boundary["manifest_hash"],
            )
            self.assertEqual(
                profile_by_number[26]["controls"]["parser_stage_count"],
                streaming_boundary["parser_stage_count"],
            )
            self.assertEqual(profile_by_number[26]["controls"]["streaming_safe_claim_count"], 0)
            self.assertEqual(profile_by_number[28]["component"], "parser-crash-isolation")
            self.assertTrue(profile_by_number[28]["controls"]["isolated_error_payloads"])
            self.assertTrue(profile_by_number[28]["controls"]["parser_crash_isolation_manifest_available_for_errors"])
            self.assertEqual(profile_by_number[29]["component"], "memory-cap-enforcement")
            self.assertTrue(profile_by_number[29]["controls"]["rss_stage_boundary_checks"])
            memory_cap_manifest = summary_payload["processing"]["memory_cap_enforcement"]["memory_cap_enforcement_manifest"]
            self.assertEqual(memory_cap_manifest["profile_version"], "memory-cap-enforcement-manifest-v1")
            self.assertEqual(memory_cap_manifest["item_number"], 29)
            self.assertEqual(len(memory_cap_manifest["manifest_hash"]), 64)
            self.assertEqual(
                summary_payload["processing"]["memory_cap_enforcement"]["memory_cap_manifest_hash"],
                memory_cap_manifest["manifest_hash"],
            )
            self.assertEqual(
                profile_by_number[29]["controls"]["memory_cap_manifest_hash"],
                memory_cap_manifest["manifest_hash"],
            )
            self.assertEqual(
                profile_by_number[29]["controls"]["memory_cap_stage_telemetry_manifest_hash"],
                memory_cap_telemetry["manifest_hash"],
            )
            self.assertEqual(
                profile_by_number[29]["controls"]["memory_cap_stage_check_count"],
                memory_cap_telemetry["stage_check_count"],
            )
            self.assertEqual(
                profile_by_number[29]["controls"]["memory_cap_manifest_profile"],
                "memory-cap-enforcement-manifest-v1",
            )
            self.assertEqual(profile_by_number[30]["component"], "incremental-indexing")
            self.assertTrue(profile_by_number[30]["controls"]["resume_effective"])
            self.assertGreaterEqual(profile_by_number[30]["controls"]["reused_output_count"], 5)
            incremental_manifest = summary_payload["processing"]["incremental_indexing"]["incremental_indexing_manifest"]
            self.assertEqual(incremental_manifest["profile_version"], "incremental-indexing-manifest-v1")
            self.assertEqual(incremental_manifest["item_number"], 30)
            self.assertEqual(incremental_manifest["gap_id"], "#30")
            self.assertEqual(len(incremental_manifest["manifest_hash"]), 64)
            self.assertEqual(
                summary_payload["processing"]["incremental_indexing"]["incremental_indexing_manifest_hash"],
                incremental_manifest["manifest_hash"],
            )
            self.assertEqual(
                profile_by_number[30]["controls"]["incremental_indexing_manifest_hash"],
                incremental_manifest["manifest_hash"],
            )
            self.assertEqual(
                profile_by_number[30]["controls"]["incremental_indexing_manifest_profile"],
                "incremental-indexing-manifest-v1",
            )
            self.assertEqual(
                profile_by_number[30]["controls"]["incremental_reuse_decision_manifest_hash"],
                summary_payload["processing"]["incremental_indexing"][
                    "incremental_reuse_decision_manifest_hash"
                ],
            )
            self.assertGreater(profile_by_number[30]["controls"]["reuse_decision_row_count"], 0)
            self.assertIn("#75", summary_payload["safety"]["artifact_scheduler"]["commercial_gap_ids"])
            self.assertEqual(summary_payload["processing"]["parser_crash_isolation"]["core_accuracy_gates"][0]["gap_id"], "#71")
            self.assertEqual(summary_payload["processing"]["memory_cap_enforcement"]["core_accuracy_gates"][0]["gap_id"], "#72")
            self.assertEqual(summary_payload["processing"]["parallel_parser_scheduler"]["core_accuracy_gates"][0]["gap_id"], "#75")
            self.assertEqual(summary_payload["resource_caps"]["memory_cap_bytes"], 0)
            self.assertIn("checkpoints", summary_payload["outputs"])
            checkpoints = json.loads((output_dir / "rapidtriage-run-checkpoints.json").read_text(encoding="utf-8"))
            self.assertEqual(checkpoints["command"], "run-checkpoints")
            self.assertTrue(checkpoints["resume"]["effective"])
            self.assertGreaterEqual(checkpoints["summary"]["reused_count"], 5)
            self.assertIn("#70", checkpoints["summary"]["commercial_gap_ids"])
            self.assertIn("#70", checkpoints["checkpoint_resume_assessment"]["commercial_gap_ids"])
            self.assertEqual(checkpoints["checkpoint_integrity_profile"]["profile_version"], "checkpoint-integrity-profile-v1")
            self.assertGreater(checkpoints["checkpoint_integrity_profile"]["checkpoint_count"], 0)
            self.assertEqual(
                checkpoints["checkpoint_integrity_profile"]["row_hash_count"],
                checkpoints["summary"]["checkpoint_count"],
            )
            decision_manifest = checkpoints["checkpoint_resume_decision_manifest"]
            self.assertEqual(decision_manifest["profile_version"], "checkpoint-resume-decision-manifest-v1")
            self.assertEqual(decision_manifest["item_number"], 70)
            self.assertEqual(decision_manifest["gap_id"], "#70")
            self.assertEqual(len(decision_manifest["manifest_hash"]), 64)
            self.assertEqual(
                checkpoints["checkpoint_resume_decision_manifest_hash"],
                decision_manifest["manifest_hash"],
            )
            self.assertEqual(decision_manifest["checkpoint_count"], checkpoints["summary"]["checkpoint_count"])
            self.assertEqual(
                decision_manifest["checkpoint_integrity_head_hash"],
                checkpoints["checkpoint_integrity_profile"]["head_hash"],
            )
            self.assertGreater(len(decision_manifest["decision_rows"]), 0)
            self.assertRegex(decision_manifest["decision_row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(checkpoints["core_accuracy_gates"][0]["gap_id"], "#70")
            self.assertIn("stage checkpoints emitted", checkpoints["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("checkpoint row hash emitted", checkpoints["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "checkpoint resume decision manifest emitted",
                checkpoints["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(checkpoints["commercial_uplift_evidence"]["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(checkpoints["commercial_uplift_evidence"]["item_numbers"], [70])
            self.assertIn(
                "checkpoint resume decision manifest emitted",
                checkpoints["commercial_uplift_evidence"]["passed_validation_check_ids"],
            )
            self.assertIn("#70", checkpoints["checkpoints"][0]["commercial_gap_ids"])
            self.assertRegex(checkpoints["checkpoints"][0]["row_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(checkpoints["checkpoints"][0]["core_accuracy_gates"][0]["gap_id"], "#70")
            self.assertEqual(
                checkpoints["checkpoints"][0]["commercial_uplift_evidence"]["batch_id"],
                "commercial-uplift-066-070",
            )
            fingerprint = json.loads((output_dir / "rapidtriage-run-fingerprint.json").read_text(encoding="utf-8"))
            self.assertIn("#68", fingerprint["summary"]["commercial_gap_ids"])
            self.assertIn("#68", fingerprint["incremental_indexing_assessment"]["commercial_gap_ids"])
            self.assertEqual(fingerprint["core_accuracy_gates"][0]["gap_id"], "#68")
            self.assertIn("input fingerprint emitted", fingerprint["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("bounded per-file content hashes captured", fingerprint["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(fingerprint["content_hash_policy"]["profile_version"], "incremental-content-hash-policy-v1")
            self.assertEqual(fingerprint["incremental_indexing_manifest"]["profile_version"], "incremental-indexing-manifest-v1")
            self.assertEqual(fingerprint["incremental_indexing_manifest"]["item_number"], 30)
            self.assertEqual(fingerprint["incremental_indexing_manifest"]["gap_id"], "#30")
            self.assertEqual(len(fingerprint["incremental_indexing_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                fingerprint["incremental_reuse_decision_manifest"]["profile_version"],
                "incremental-reuse-decision-manifest-v1",
            )
            self.assertEqual(fingerprint["incremental_reuse_decision_manifest"]["item_number"], 68)
            self.assertEqual(fingerprint["incremental_reuse_decision_manifest"]["gap_id"], "#68")
            self.assertEqual(len(fingerprint["incremental_reuse_decision_manifest"]["manifest_hash"]), 64)
            self.assertGreater(fingerprint["incremental_reuse_decision_manifest"]["decision_row_count"], 0)
            self.assertEqual(
                fingerprint["incremental_indexing_assessment"]["incremental_reuse_decision_manifest_hash"],
                fingerprint["incremental_reuse_decision_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                fingerprint["incremental_indexing_assessment"]["incremental_indexing_manifest_hash"],
                fingerprint["incremental_indexing_manifest"]["manifest_hash"],
            )
            self.assertIn(
                "incremental indexing manifest hash emitted",
                fingerprint["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("reuse decision manifest emitted", fingerprint["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertGreater(fingerprint["summary"]["content_hashed_file_count"], 0)
            self.assertGreater(len(fingerprint["files"]), 0)
            self.assertTrue(any(item.get("sha256") for item in fingerprint["files"]))
            self.assertEqual(fingerprint["incremental_reuse_plan"]["profile_version"], "incremental-reuse-plan-v1")
            self.assertEqual(fingerprint["incremental_reuse_plan"]["reindex_recommendation"], "safe-to-reuse-stage-outputs")
            self.assertEqual(fingerprint["commercial_uplift_evidence"]["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(fingerprint["commercial_uplift_evidence"]["item_numbers"], [68])
            self.assertIn(
                "trusted-incremental-reuse-manifest-diff-missing",
                fingerprint["commercial_uplift_evidence"]["remaining_external_validation"],
            )
            fingerprint_diff = build_incremental_indexing_trusted_diff(fingerprint, fingerprint)
            fingerprint_gates = incremental_indexing_core_accuracy_gates(
                scanned_files=fingerprint["summary"]["scanned_file_count"],
                max_files=fingerprint["summary"]["max_files"],
                truncated=fingerprint["summary"]["truncated"],
                fingerprint=fingerprint["fingerprint"],
                reuse_disabled=False,
                trusted_diff=fingerprint_diff,
            )
            self.assertEqual(fingerprint_diff["status"], "pass")
            self.assertIn("trusted incremental reuse diff pass", fingerprint_gates[0]["satisfied_checks"])
            self.assertIn(
                "trusted-checkpoint-resume-manifest-diff-missing",
                checkpoints["commercial_uplift_evidence"]["remaining_external_validation"],
            )
            checkpoint_diff = build_checkpoint_resume_trusted_diff(checkpoints["checkpoints"], checkpoints["checkpoints"])
            checkpoint_gates = checkpoint_resume_core_accuracy_gates(
                checkpoints=checkpoints["checkpoints"],
                resume_requested=checkpoints["resume"]["requested"],
                resume_effective=checkpoints["resume"]["effective"],
                decision_manifest_hash=checkpoints["checkpoint_resume_decision_manifest_hash"],
                trusted_diff=checkpoint_diff,
            )
            self.assertEqual(checkpoint_diff["status"], "pass")
            self.assertIn("trusted checkpoint/resume manifest diff pass", checkpoint_gates[0]["satisfied_checks"])

            step_statuses = {step["name"]: step["status"] for step in summary_payload["steps"]}
            self.assertEqual(step_statuses["docs"], "reused")
            self.assertEqual(step_statuses["files"], "reused")
            self.assertEqual(step_statuses["timeline"], "reused")

            report_text = (output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8")
            self.assertIn("Resume/reuse outputs: True", report_text)
            self.assertIn("Reused outputs:", report_text)

    def test_run_resume_changed_source_records_incremental_reuse_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            changed_file = root / "Users" / "alice" / "Documents" / "wire-transfer-notes.txt"
            changed_file.write_text("changed password evidence for incremental reuse plan", encoding="utf-8")
            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir), "--resume"]), 0)

            summary_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            self.assertFalse(summary_payload["safety"]["resume_effective"])
            self.assertEqual(
                summary_payload["safety"]["resume_disabled_reason"],
                "input fingerprint changed; rebuilding stage outputs",
            )
            fingerprint = json.loads((output_dir / "rapidtriage-run-fingerprint.json").read_text(encoding="utf-8"))
            plan = fingerprint["incremental_reuse_plan"]
            self.assertEqual(plan["profile_version"], "incremental-reuse-plan-v1")
            self.assertEqual(plan["reindex_recommendation"], "rebuild-affected-stages")
            self.assertGreaterEqual(plan["counts"]["changed"], 1)
            self.assertIn("Users/alice/Documents/wire-transfer-notes.txt", plan["changed"])
            self.assertEqual(fingerprint["incremental_indexing_manifest"]["profile_version"], "incremental-indexing-manifest-v1")
            self.assertEqual(fingerprint["incremental_indexing_manifest"]["reindex_recommendation"], "rebuild-affected-stages")
            self.assertEqual(len(fingerprint["incremental_indexing_manifest"]["reuse_plan_hash"]), 64)
            decision_manifest = fingerprint["incremental_reuse_decision_manifest"]
            self.assertEqual(decision_manifest["profile_version"], "incremental-reuse-decision-manifest-v1")
            self.assertTrue(decision_manifest["reuse_disabled"])
            self.assertEqual(decision_manifest["decision_policy"]["changed_source_disables_stage_reuse"], True)
            changed_rows = [row for row in decision_manifest["decision_rows"] if row["change_type"] == "changed"]
            self.assertTrue(
                any(row["relative_path"] == "Users/alice/Documents/wire-transfer-notes.txt" for row in changed_rows)
            )
            self.assertEqual(len(decision_manifest["manifest_hash"]), 64)
            self.assertIn("changed-source reuse disabled", fingerprint["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("reuse decision manifest emitted", fingerprint["core_accuracy_gates"][0]["satisfied_checks"])

    def test_search_command_finds_keyword_across_completed_run_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            search_output = Path(tmp_dir) / "search.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                main(["search", str(output_dir), "-k", "password", "--no-ocr", "--output", str(search_output)]),
                0,
            )

            payload = json.loads(search_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "search")
            self.assertGreaterEqual(payload["summary"]["match_count"], 1)
            sources = {match["source"] for match in payload["matches"]}
            self.assertIn("documents", sources)
            self.assertIn("password", payload["summary"]["keyword_counts"])

    def test_source_read_command_previews_and_hashes_analyzed_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            source_output = Path(tmp_dir) / "source-read.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                main(
                    [
                        "source-read",
                        str(output_dir),
                        "--path",
                        "Users/alice/Documents/wire-transfer-notes.txt",
                        "--hash",
                        "--output",
                        str(source_output),
                    ]
                ),
                0,
            )

            payload = json.loads(source_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "source-read")
            self.assertEqual(payload["profile_version"], "source-read-v1")
            self.assertEqual(payload["relative_path"], "Users/alice/Documents/wire-transfer-notes.txt")
            self.assertEqual(payload["preview"]["preview_type"], "text")
            self.assertIn("wire transfer", payload["preview"]["text"])
            self.assertEqual(set(payload["hashes"]), {"md5", "sha1", "sha256"})
            self.assertTrue(payload["forensic_read_profile"]["path_inside_analysis_root"])
            self.assertFalse(payload["reportability_decision"]["decision"].startswith("ready"))
            citation = payload["source_citation_package"]
            self.assertEqual(citation["profile_version"], "source-read-citation-package-v1")
            self.assertEqual(citation["source_hash_status"], "present")
            self.assertIn("Users/alice/Documents/wire-transfer-notes.txt", citation["citation_text"])
            self.assertIn("sha256:", citation["citation_text"])
            self.assertIn("Current-file hit:", citation["review_note_template"])
            self.assertIn("Snippet:", citation["review_note_template"])
            self.assertEqual(len(citation["package_hash"]), 64)

    def test_source_read_command_previews_zip_entry_with_archive_locator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            source_output = Path(tmp_dir) / "source-read-zip.json"
            export_path = root / "Users" / "alice" / "Documents" / "ChatGPT-export.zip"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(export_path, "w") as archive:
                archive.writestr(
                    "conversations.json",
                    json.dumps(
                        [
                            {
                                "title": "Incident notes",
                                "mapping": {
                                    "1": {"message": {"author": {"role": "user"}, "content": {"parts": ["find evtx"]}}},
                                    "2": {"message": {"author": {"role": "assistant"}, "content": {"parts": ["check 4624"]}}},
                                },
                            }
                        ],
                        ensure_ascii=False,
                    ),
                )

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                main(
                    [
                        "source-read",
                        str(output_dir),
                        "--path",
                        "Users/alice/Documents/ChatGPT-export.zip::conversations.json",
                        "--hash",
                        "--output",
                        str(source_output),
                        "--json",
                    ]
                ),
                0,
            )

            payload = json.loads(source_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["relative_path"], "Users/alice/Documents/ChatGPT-export.zip::conversations.json")
            self.assertEqual(payload["path"], str(export_path.resolve()))
            self.assertEqual(payload["container_relative_path"], "Users/alice/Documents/ChatGPT-export.zip")
            self.assertEqual(payload["extension"], ".json")
            self.assertEqual(payload["archive_entry"]["container_type"], "zip")
            self.assertEqual(payload["archive_entry"]["archive_entry_name"], "conversations.json")
            self.assertEqual(len(payload["archive_entry"]["entry_hashes"]["sha256"]), 64)
            self.assertEqual(payload["preview"]["preview_type"], "text")
            self.assertEqual(payload["preview"]["strategy"], "bounded-zip-entry-text")
            self.assertIn("find evtx", payload["preview"]["text"])
            self.assertEqual(payload["source_locator"]["locator_type"], "zip-entry-text-preview")
            self.assertEqual(payload["source_locator"]["archive_entry_name"], "conversations.json")
            self.assertEqual(payload["forensic_read_profile"]["container_type"], "zip")
            citation = payload["source_citation_package"]
            self.assertIn("ChatGPT-export.zip::conversations.json", citation["citation_text"])
            self.assertIn("zip entry conversations.json", citation["citation_text"])
            self.assertEqual(citation["source_locator"]["locator_type"], "zip-entry-text-preview")
            self.assertIn("archive completeness", " ".join(citation["core_accuracy_gates"]["remaining_blockers"]))

    def test_source_search_command_finds_zip_entry_hit_with_archive_locator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            source_output = Path(tmp_dir) / "source-search-zip.json"
            export_path = root / "Users" / "alice" / "Documents" / "ChatGPT-export.zip"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            export_path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(export_path, "w") as archive:
                archive.writestr("conversations.json", '{"message":"find evtx then check 4624"}\n')

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                main(
                    [
                        "source-search",
                        str(output_dir),
                        "--path",
                        "Users/alice/Documents/ChatGPT-export.zip::conversations.json",
                        "-k",
                        "evtx",
                        "--output",
                        str(source_output),
                        "--json",
                    ]
                ),
                0,
            )

            payload = json.loads(source_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "source-search")
            self.assertEqual(payload["profile_version"], "source-search-cli-v1")
            self.assertEqual(payload["relative_path"], "Users/alice/Documents/ChatGPT-export.zip::conversations.json")
            self.assertTrue(payload["summary"]["zip_entry_search"])
            self.assertEqual(payload["summary"]["match_count"], 1)
            self.assertEqual(payload["matches"][0]["keyword"], "evtx")
            self.assertIn("ChatGPT-export.zip::conversations.json", payload["matches"][0]["citation"])
            self.assertEqual(payload["reportability_decision"]["decision"], "source-search-hit-is-review-lead-not-standalone-proof")

    def test_source_search_command_scans_sqlite_text_columns_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            source_output = Path(tmp_dir) / "source-search-sqlite.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            db_path = root / "Users" / "alice" / "Databases" / "chat.sqlite"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                with connection:
                    connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
                    connection.executemany(
                        "INSERT INTO messages(sender, body) VALUES (?, ?)",
                        [
                            ("alice", "normal hello"),
                            ("bob", "wire transfer password appears here"),
                            ("carol", "later message"),
                        ],
                    )

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                main(
                    [
                        "source-search",
                        str(output_dir),
                        "--path",
                        "Users/alice/Databases/chat.sqlite",
                        "-k",
                        "password",
                        "--output",
                        str(source_output),
                    ]
                ),
                0,
            )

            payload = json.loads(source_output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "source-search")
            self.assertEqual(payload["summary"]["search_mode"], "bounded-sqlite-table-scan")
            self.assertTrue(payload["summary"]["sqlite_search"])
            self.assertEqual(payload["summary"]["sqlite_status"], "searched")
            self.assertGreaterEqual(payload["summary"]["sqlite_scanned_tables"], 1)
            self.assertGreaterEqual(payload["summary"]["match_count"], 1)
            match = payload["matches"][0]
            self.assertEqual(match["table"], "messages")
            self.assertEqual(match["column"], "body")
            self.assertIn("table messages", match["citation"])
            self.assertIn("password", match["snippet"])

    def test_source_read_command_opens_bounded_sqlite_table_locator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            source_output = Path(tmp_dir) / "source-read-sqlite.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            db_path = root / "Users" / "alice" / "Databases" / "chat.sqlite"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                with connection:
                    connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
                    connection.executemany(
                        "INSERT INTO messages(sender, body) VALUES (?, ?)",
                        [
                            ("alice", "normal hello"),
                            ("bob", "wire transfer password appears here"),
                            ("carol", "later message"),
                        ],
                    )

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            self.assertEqual(
                main(
                    [
                        "source-read",
                        str(output_dir),
                        "--path",
                        "Users/alice/Databases/chat.sqlite",
                        "--sqlite-table",
                        "messages",
                        "--sqlite-where-column",
                        "body",
                        "--sqlite-where-contains",
                        "password",
                        "--sqlite-limit",
                        "5",
                        "--hash",
                        "--output",
                        str(source_output),
                        "--json",
                    ]
                ),
                0,
            )

            payload = json.loads(source_output.read_text(encoding="utf-8"))
            preview = payload["preview"]
            self.assertEqual(preview["preview_type"], "sqlite-table")
            self.assertEqual(preview["table"], "messages")
            self.assertEqual(preview["row_count"], 1)
            self.assertEqual(preview["total_matching_rows"], 1)
            self.assertEqual(preview["rows"][0]["values"]["sender"], "bob")
            self.assertIn("password", preview["rows"][0]["values"]["body"])
            self.assertEqual(payload["source_locator"]["locator_type"], "sqlite-table-page")
            self.assertEqual(len(preview["sqlite_table_locator_manifest_hash"]), 64)
            self.assertIn("sha256", payload["hashes"])
            self.assertEqual(payload["forensic_read_profile"]["source_locator_type"], "sqlite-table-page")
            citation = payload["source_citation_package"]
            self.assertIn("sqlite table messages", citation["citation_text"])
            self.assertIn("password", citation["snippet"])
            self.assertEqual(citation["source_locator"]["locator_type"], "sqlite-table-page")
            self.assertTrue(citation["ready_for_review_note"])
            self.assertFalse(citation["ready_for_court_report"])

    def test_source_read_command_rejects_paths_outside_analysis_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            source_output = Path(tmp_dir) / "source-read.json"
            outside = Path(tmp_dir) / "outside.txt"
            root.mkdir(parents=True, exist_ok=True)
            outside.write_text("outside evidence root", encoding="utf-8")
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "fraud", "--output-dir", str(output_dir)]), 0)
            with self.assertRaises(SystemExit):
                main(
                    [
                        "source-read",
                        str(output_dir),
                        "--path",
                        str(outside),
                        "--output",
                        str(source_output),
                    ]
                )

    def test_hacking_run_surfaces_windows_forensic_artifacts_in_search_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            search_output = Path(tmp_dir) / "search.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "hacking", "--output-dir", str(output_dir)]), 0)

            summary_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            for kind in (
                "email",
                "cloud-export",
                "mobile-export",
                "kakaotalk-windows",
                "android-apk",
                "media-image",
                "memory-volatility",
                "eventlog",
                "windows-os-account",
                "windows-execution",
                "windows-registry",
                "windows-shellbags",
                "windows-prefetch",
                "windows-filesystem",
            ):
                self.assertIn(kind, summary_payload["summary"]["artifacts"])
                self.assertIn(f"artifacts_{kind}", summary_payload["outputs"])
                self.assertTrue(Path(summary_payload["outputs"][f"artifacts_{kind}"]).is_file())

            self.assertGreaterEqual(
                summary_payload["summary"]["artifacts"]["eventlog"]["artifact_count"],
                1,
            )
            self.assertGreaterEqual(
                summary_payload["summary"]["artifacts"]["windows-execution"]["artifact_count"],
                1,
            )
            self.assertGreaterEqual(
                summary_payload["summary"]["artifacts"]["windows-prefetch"]["artifact_count"],
                1,
            )
            self.assertGreaterEqual(
                summary_payload["summary"]["artifacts"]["windows-filesystem"]["artifact_count"],
                1,
            )

            timeline_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-timeline.json").read_text(encoding="utf-8")
            )
            timeline_text = json.dumps(timeline_payload, ensure_ascii=False)
            self.assertIn("eventlog-event", timeline_text)
            self.assertIn("powershell-history-command", timeline_text)
            self.assertIn("prefetch-file", timeline_text)
            self.assertIn("mft-record", timeline_text)
            self.assertIn("artifact-shellbag-native-candidate", timeline_text)

            self.assertEqual(
                main(["search", str(output_dir), "-k", "powershell", "--no-ocr", "--output", str(search_output)]),
                0,
            )
            search_payload = json.loads(search_output.read_text(encoding="utf-8"))
            sources = {match["source"] for match in search_payload["matches"]}
            self.assertIn("artifacts", sources)
            self.assertIn("timeline", sources)
            self.assertIn("powershell", search_payload["summary"]["keyword_counts"])

    def test_hacking_run_includes_broad_forensic_artifact_collectors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            search_output = Path(tmp_dir) / "search.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            self.add_broad_artifact_fixture(root)

            self.assertEqual(main(["run", str(root), "--mode", "hacking", "--output-dir", str(output_dir)]), 0)

            summary_payload: dict[str, Any] = json.loads(
                (output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8")
            )
            expected = {
                "email": 1,
                "cloud-export": 1,
                "mobile-export": 1,
                "media-image": 1,
                "memory-volatility": 1,
            }
            for kind, minimum_count in expected.items():
                with self.subTest(kind=kind):
                    self.assertIn(kind, summary_payload["summary"]["artifacts"])
                    self.assertIn(f"artifacts_{kind}", summary_payload["outputs"])
                    self.assertTrue(Path(summary_payload["outputs"][f"artifacts_{kind}"]).is_file())
                    self.assertGreaterEqual(
                        summary_payload["summary"]["artifacts"][kind]["artifact_count"],
                        minimum_count,
                    )
            self.assertIn("kakaotalk-windows", summary_payload["summary"]["artifacts"])
            self.assertIn("android-apk", summary_payload["summary"]["artifacts"])

            self.assertEqual(
                main(
                    [
                        "search",
                        str(output_dir),
                        "-k",
                        "ChatGPT",
                        "-k",
                        "mobile",
                        "-k",
                        "token",
                        "--no-ocr",
                        "--output",
                        str(search_output),
                    ]
                ),
                0,
            )
            search_payload = json.loads(search_output.read_text(encoding="utf-8"))
            self.assertIn("artifacts", {match["source"] for match in search_payload["matches"]})
            self.assertGreaterEqual(search_payload["summary"]["keyword_counts"]["chatgpt"], 1)
            self.assertGreaterEqual(search_payload["summary"]["keyword_counts"]["mobile"], 1)
            self.assertGreaterEqual(search_payload["summary"]["keyword_counts"]["token"], 1)

    def add_broad_artifact_fixture(self, root: Path) -> None:
        mail_dir = root / "Users" / "alice" / "Mail"
        mail_dir.mkdir(parents=True, exist_ok=True)
        (mail_dir / "case-message.eml").write_text(
            "From: alice@example.com\n"
            "To: bob@example.com\n"
            "Subject: cloud invoice\n\n"
            "Please review the invoice and password reset.",
            encoding="utf-8",
        )

        cloud_dir = root / "Users" / "alice" / "Cloud"
        cloud_dir.mkdir(parents=True, exist_ok=True)
        (cloud_dir / "google-activity.json").write_text(
            '[{"title":"Visited ChatGPT","time":"2024-05-01T10:00:00Z","products":["Search"]}]',
            encoding="utf-8",
        )

        mobile_dir = root / "Users" / "alice" / "Mobile"
        mobile_dir.mkdir(parents=True, exist_ok=True)
        (mobile_dir / "messages.csv").write_text(
            "service,chat_id,sender,text,timestamp\n"
            "WhatsApp,room1,Alice,hello from mobile chat,2024-05-01T11:00:00Z\n",
            encoding="utf-8",
        )

        pictures_dir = root / "Users" / "alice" / "Pictures"
        pictures_dir.mkdir(parents=True, exist_ok=True)
        (pictures_dir / "photo.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 128)

        memory_dir = root / "Memory"
        memory_dir.mkdir(parents=True, exist_ok=True)
        (memory_dir / "sample.dmp").write_bytes(b"MEMORY powershell cmd.exe 192.168.1.5 password token")

    def assert_run_mode_outputs(self, mode: str) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            exit_code = main(["run", str(root), "--mode", mode, "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_dir.is_dir())

            manifest_path = output_dir / "rapidtriage-manifest.json"
            docs_path = output_dir / "rapidtriage-docs.json"
            docs_index_path = output_dir / "rapidtriage-docs-index.json"
            files_path = output_dir / "rapidtriage-files.json"
            docs_extract_manifest_path = output_dir / "docs-extract" / "rapidtriage-extract-manifest.json"
            files_extract_manifest_path = output_dir / "files-extract" / "rapidtriage-extract-manifest.json"
            timeline_path = output_dir / "rapidtriage-timeline.json"
            timeline_report_path = output_dir / "rapidtriage-timeline-report.md"
            indicators_path = output_dir / "rapidtriage-indicators.json"
            summary_path = output_dir / "rapidtriage-run-summary.json"
            report_path = output_dir / "rapidtriage-run-report.md"
            artifact_paths = {
                path.name: path
                for path in (output_dir / "artifacts").glob("rapidtriage-artifacts-*.json")
            }

            expected_output_paths = [
                manifest_path,
                docs_path,
                docs_index_path,
                files_path,
                docs_extract_manifest_path,
                files_extract_manifest_path,
                timeline_path,
                timeline_report_path,
                indicators_path,
                summary_path,
                report_path,
            ]
            for path in expected_output_paths:
                self.assertTrue(path.is_file(), f"missing expected output: {path}")

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            provider_names = {provider["name"] for provider in manifest["providers"]}
            self.assertIn("windows-browser-artifacts", provider_names)
            self.assertIn("windows-recent-files", provider_names)

            docs_payload = json.loads(docs_path.read_text(encoding="utf-8"))
            docs_index_payload = json.loads(docs_index_path.read_text(encoding="utf-8"))
            files_payload = json.loads(files_path.read_text(encoding="utf-8"))
            docs_extract_payload = json.loads(docs_extract_manifest_path.read_text(encoding="utf-8"))
            files_extract_payload = json.loads(files_extract_manifest_path.read_text(encoding="utf-8"))
            summary_payload: dict[str, Any] = json.loads(summary_path.read_text(encoding="utf-8"))
            timeline_payload: dict[str, Any] = json.loads(timeline_path.read_text(encoding="utf-8"))
            indicators_payload: dict[str, Any] = json.loads(indicators_path.read_text(encoding="utf-8"))
            artifact_payloads = {
                path.stem.removeprefix("rapidtriage-artifacts-"): json.loads(path.read_text(encoding="utf-8"))
                for path in artifact_paths.values()
            }

            min_file_candidates = {"fraud": 4, "hacking": 3, "seizure": 4, "recovery": 3}[mode]
            min_doc_matches = {"fraud": 1, "hacking": 1, "seizure": 1, "recovery": 1}[mode]

            self.assertGreaterEqual(files_payload["summary"]["candidate_count"], min_file_candidates)
            self.assertGreaterEqual(docs_payload["summary"]["candidate_count"], 1)
            self.assertGreaterEqual(docs_payload["summary"]["match_count"], min_doc_matches)
            self.assertEqual(docs_payload["index"]["command"], "docs-index")
            self.assertEqual(Path(docs_payload["index"]["path"]).resolve(), docs_index_path.resolve())
            self.assertEqual(docs_index_payload["command"], "docs-index")
            self.assertEqual(docs_index_payload["strategy"], "processed-text-inverted-index")
            self.assertGreaterEqual(docs_index_payload["summary"]["indexed_document_count"], 1)

            self.assertGreaterEqual(docs_extract_payload["summary"]["selected_count"], 1)
            self.assertGreaterEqual(docs_extract_payload["summary"]["extracted_count"], 1)
            self.assertGreaterEqual(files_extract_payload["summary"]["selected_count"], 1)
            self.assertGreaterEqual(files_extract_payload["summary"]["extracted_count"], 1)
            for extract_payload in (docs_extract_payload, files_extract_payload):
                for entry in extract_payload["entries"]:
                    self.assertTrue(Path(entry["extracted_path"]).is_file())
                    self.assertTrue(Path(entry["extracted_path"]).is_relative_to(output_dir.resolve()))

            self.assertEqual(summary_payload["mode"], mode)
            self.assertEqual(summary_payload["command"], "run")
            self.assertEqual(Path(summary_payload["outputs"]["manifest"]).resolve(), manifest_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["docs"]).resolve(), docs_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["docs_index"]).resolve(), docs_index_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["files"]).resolve(), files_path.resolve())
            self.assertEqual(
                Path(summary_payload["outputs"]["docs_extract_manifest"]).resolve(),
                docs_extract_manifest_path.resolve(),
            )
            self.assertEqual(
                Path(summary_payload["outputs"]["files_extract_manifest"]).resolve(),
                files_extract_manifest_path.resolve(),
            )
            self.assertEqual(Path(summary_payload["outputs"]["timeline"]).resolve(), timeline_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["timeline_report"]).resolve(), timeline_report_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["indicators"]).resolve(), indicators_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["summary"]).resolve(), summary_path.resolve())
            self.assertEqual(Path(summary_payload["outputs"]["report"]).resolve(), report_path.resolve())
            self.assertGreaterEqual(summary_payload["summary"]["timeline_event_count"], 1)
            self.assertIn("silent_failure_detection", summary_payload)
            self.assertIn("silent_failure_risk", summary_payload["summary"])
            self.assertIn("silent-failure-detector", {step["name"] for step in summary_payload["steps"]})
            self.assertEqual(summary_payload["workflow"]["profile_version"], "run-workflow-contract-v1")
            self.assertEqual(summary_payload["workflow"]["stage_order"], list(RUN_WORKFLOW_STAGE_ORDER))
            self.assertTrue(summary_payload["workflow"]["gui_primary_flow"])
            self.assertEqual(summary_payload["workflow"]["stage_count"], 6)
            self.assertIn("parse", summary_payload["workflow"]["stage_lookup"])
            self.assertIn("report", summary_payload["workflow"]["stage_lookup"])
            self.assertEqual(
                summary_payload["workflow"]["analyst_checklist_summary"]["profile_version"],
                "run-workflow-analyst-checklist-summary-v1",
            )
            self.assertGreaterEqual(summary_payload["workflow"]["analyst_checklist_summary"]["item_count"], 8)
            workflow_stage_ids = {stage["id"] for stage in summary_payload["workflow"]["stages"]}
            self.assertEqual(workflow_stage_ids, set(RUN_WORKFLOW_STAGE_ORDER))
            for workflow_stage in summary_payload["workflow"]["stages"]:
                self.assertIn("handoff_outputs", workflow_stage)
                self.assertIn("analyst_checklist", workflow_stage)
                self.assertTrue(workflow_stage["analyst_checklist"])
                self.assertEqual(
                    [handoff["name"] for handoff in workflow_stage["handoff_outputs"]],
                    workflow_stage["output_keys"],
                )
            self.assertGreaterEqual(timeline_payload["summary"]["event_count"], 1)
            self.assertIn("recent_file_candidates", summary_payload["highlights"])
            self.assertIn("large_file_candidates", summary_payload["highlights"])

            if mode == "recovery":
                self.assertIn("recent-files", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-os-account", summary_payload["summary"]["artifacts"])
                self.assertIn("eventlog", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-registry", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-shellbags", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-prefetch", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-filesystem", summary_payload["summary"]["artifacts"])
                self.assertIn("images", files_payload["summary"]["category_counts"])
            else:
                self.assertIn("browser", summary_payload["summary"]["artifacts"])
                self.assertIn("recent-files", summary_payload["summary"]["artifacts"])
                self.assertIn("email", summary_payload["summary"]["artifacts"])
                self.assertIn("cloud-export", summary_payload["summary"]["artifacts"])
                self.assertIn("mobile-export", summary_payload["summary"]["artifacts"])
                self.assertIn("kakaotalk-windows", summary_payload["summary"]["artifacts"])
                self.assertIn("android-apk", summary_payload["summary"]["artifacts"])
                self.assertIn("media-image", summary_payload["summary"]["artifacts"])
                self.assertIn("memory-volatility", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-os-account", summary_payload["summary"]["artifacts"])
                self.assertIn("eventlog", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-execution", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-registry", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-shellbags", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-prefetch", summary_payload["summary"]["artifacts"])
                self.assertIn("windows-filesystem", summary_payload["summary"]["artifacts"])
            for artifact_path in artifact_paths.values():
                self.assertTrue(artifact_path.is_file())

            report_text = report_path.read_text(encoding="utf-8")
            report_context = build_run_report_context(
                summary_payload,
                docs_payload=docs_payload,
                files_payload=files_payload,
                docs_extract_payload=docs_extract_payload,
                files_extract_payload=files_extract_payload,
                artifact_payloads=artifact_payloads,
                timeline_payload=timeline_payload,
                indicators_payload=indicators_payload,
            )
            self.assertIn("artifact_summary", report_context)
            self.assertIn("timeline", report_context)
            self.assertIn("extracts", report_context)
            self.assertIn("compare_results", report_context)
            self.assertIn("indicator_summary", report_context)
            self.assertIn("workflow", report_context)
            self.assertTrue(report_context["workflow"]["available"])
            self.assertEqual(render_run_markdown_report(report_context), report_text)
            self.assertIn(mode, report_text.lower())
            self.assertIn("case overview", report_text.lower())
            self.assertIn("workflow analyst checklist", report_text.lower())
            self.assertIn("stage verification items", report_text.lower())
            self.assertIn("checklist status:", report_text.lower())
            self.assertIn("parse:artifact-rows", report_text)
            self.assertIn("key hits", report_text.lower())
            self.assertIn("matched rules", report_text.lower())
            self.assertIn("artifact summary", report_text.lower())
            self.assertIn("indicator pivots", report_text.lower())
            self.assertIn("silent failure detector", report_text.lower())
            self.assertIn("timeline", report_text.lower())
            self.assertIn("extract results", report_text.lower())


if __name__ == "__main__":
    unittest.main()
