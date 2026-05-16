from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.archive_image import ArchiveImageExtractionResult, extract_archive_image_to_directory
from rapidtriage.core.disk_image import (
    DiskImageExtractionResult,
    build_raw_split_report_grade_validation_plan,
    build_split_set_profile,
    discover_split_image_parts,
    extract_raw_image_to_directory,
)
from rapidtriage.core.e01 import (
    E01ExtractionError,
    E01ExtractionResult,
    build_e01_report_grade_validation_plan,
    build_e01_segment_set_profile,
    build_windows11_e01_known_answer_manifest,
    build_image_workflow_trusted_diff,
    collect_tool_preflight,
    e01_failure_guidance,
    e01_preflight_summary,
    extract_e01_to_directory,
    image_core_accuracy_gates,
    mmls_first_filesystem,
    parse_mmls_partitions,
    select_mmls_filesystem,
)
from rapidtriage.core.e01_smoke import run_windows11_e01_smoke
from rapidtriage.cli import main
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.virtual_disk import (
    VirtualDiskExtractionResult,
    build_virtual_disk_chain_profile,
    extract_virtual_disk_to_directory,
)
from tests.test_rapidtriage_run import build_run_fixture


class RapidTriageE01Tests(unittest.TestCase):
    def test_windows11_e01_known_answer_manifest_records_source_expected_outputs_and_validation_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            e01_path.write_bytes(b"EVF-known-answer")

            manifest = build_windows11_e01_known_answer_manifest(
                e01_path,
                case_id="CASE-E01-001",
                expected_partition_start_sector=2048,
                expected_artifacts=["Security.evtx has event 4624", "$MFT contains Users/alice/Documents"],
                validation_commands=["rapidtriage evidence case.E01 --json"],
            )

            self.assertEqual(manifest["schema"], "rapidforensic-windows11-e01-known-answer-manifest-v1")
            self.assertEqual(manifest["case_id"], "CASE-E01-001")
            self.assertEqual(manifest["status"], "draft-needs-execution")
            self.assertFalse(manifest["commercial_grade_ready"])
            self.assertEqual(manifest["source_image"]["integrity"]["hash_status"], "computed")
            self.assertEqual(manifest["source_image"]["segment_set_profile"]["segment_count"], 1)
            self.assertEqual(manifest["expected"]["partitions"][0]["start_sector"], 2048)
            self.assertEqual(len(manifest["expected"]["high_value_artifacts"]), 2)
            self.assertEqual(manifest["validation_commands"][0]["status"], "not-run")
            self.assertIn("e01-hash", manifest["validation_commands"][0]["command"])
            validation_plan = manifest["report_grade_validation_plan"]
            self.assertEqual(validation_plan["profile_version"], "e01-ex01-report-grade-validation-plan-v1")
            self.assertEqual(validation_plan["gap_id"], "#22")
            self.assertIn("source-full-hash", {row["id"] for row in validation_plan["validation_commands"]})
            self.assertIn("trusted-workflow-diff", {row["id"] for row in validation_plan["validation_commands"]})
            self.assertIn("partition-and-recovery-diff", validation_plan["blocking_slot_ids"])
            self.assertEqual(len(validation_plan["manifest_sha256"]), 64)
            self.assertEqual(manifest["core_accuracy_gates"][0]["gap_id"], "#22")
            self.assertIn("source hash and segment integrity", manifest["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("partition offset correctness", manifest["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(len(manifest["manifest_sha256"]), 64)

    def test_e01_report_grade_validation_plan_preserves_commands_slots_and_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            e01_path.write_bytes(b"EVF-validation-plan")

            plan = build_e01_report_grade_validation_plan(
                e01_path,
                output_dir=root / "validation",
                case_id="CASE-PLAN",
                expected_partition_start_sector=2048,
                expected_artifacts=["Security.evtx event 4624"],
                source_integrity={"hash_status": "computed", "sha256": "a" * 64},
                segment_set_profile={"segment_count": 1, "warnings": []},
                tool_preflight=[
                    {"tool": "ewfmount", "available": True, "version": "ewfmount 1.0"},
                    {"tool": "mmls", "available": True, "version": "mmls 1.0"},
                    {"tool": "tsk_recover", "available": True, "version": "tsk_recover 1.0"},
                ],
                preflight_summary={"direct_extract_ready": True, "version_unverified_tools": []},
            )

            self.assertEqual(plan["profile_version"], "e01-ex01-report-grade-validation-plan-v1")
            self.assertEqual(plan["status"], "report-validation-blocked")
            command_ids = {row["id"] for row in plan["validation_commands"]}
            self.assertIn("source-full-hash", command_ids)
            self.assertIn("trusted-ewfverify", command_ids)
            self.assertIn("trusted-workflow-diff", command_ids)
            source_hash_command = next(row for row in plan["validation_commands"] if row["id"] == "source-full-hash")
            self.assertEqual(source_hash_command["argv"][1], "e01-hash")
            self.assertIn("e01-streaming-hash.json", source_hash_command["expected_output"])
            slot_status = {slot["id"]: slot["status"] for slot in plan["evidence_slots"]}
            self.assertEqual(slot_status["full-source-hash"], "available-from-preflight")
            self.assertEqual(slot_status["segment-inventory"], "complete")
            self.assertEqual(slot_status["dependency-version-matrix"], "complete")
            self.assertEqual(slot_status["partition-and-recovery-diff"], "pending-image-workflow-validate")
            self.assertIn("partition-and-recovery-diff", plan["blocking_slot_ids"])
            self.assertIn("corrupt-encrypted-corpus", [slot["id"] for slot in plan["evidence_slots"]])
            self.assertEqual(plan["expected_artifacts"][0]["description"], "Security.evtx event 4624")
            self.assertEqual(len(plan["manifest_sha256"]), 64)

    def test_e01_known_answer_cli_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            output = root / "known-answer.json"
            e01_path.write_bytes(b"EVF-cli")

            exit_code = main(
                [
                    "e01-known-answer",
                    str(e01_path),
                    "--case-id",
                    "CASE-CLI",
                    "--expected-partition-start-sector",
                    "2048",
                    "--expected-artifact",
                    "Security.evtx event 4624",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["case_id"], "CASE-CLI")
            self.assertEqual(payload["expected"]["partitions"][0]["start_sector"], 2048)
            self.assertEqual(payload["expected"]["high_value_artifacts"][0]["description"], "Security.evtx event 4624")

    def test_e01_smoke_records_known_answer_preflight_and_blocked_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            output_dir = root / "smoke"
            e01_path.write_bytes(b"EVF-smoke")

            payload = run_windows11_e01_smoke(
                e01_path,
                output_dir=output_dir,
                case_id="CASE-SMOKE",
                expected_partition_start_sector=2048,
                expected_artifacts=["Security.evtx event 4624"],
            )

            self.assertEqual(payload["schema"], "rapidforensic-e01-smoke-report-v1")
            self.assertEqual(payload["case_id"], "CASE-SMOKE")
            self.assertEqual(payload["status"], "blocked")
            self.assertFalse(payload["commercial_grade_ready"])
            self.assertTrue((output_dir / "windows11-e01-known-answer.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-evidence-preflight.json").is_file())
            self.assertTrue((output_dir / "rapidforensic-e01-validation-plan.json").is_file())
            self.assertTrue((output_dir / "rapidforensic-e01-smoke.json").is_file())
            self.assertTrue((output_dir / "rapidforensic-e01-workflow-stage-status.json").is_file())
            stage_status = {stage["id"]: stage["status"] for stage in payload["stages"]}
            self.assertEqual(stage_status["known-answer-manifest"], "complete")
            self.assertEqual(stage_status["evidence-preflight"], "complete")
            self.assertEqual(stage_status["report-grade-validation-plan"], "complete")
            self.assertEqual(stage_status["triage-run"], "blocked")
            self.assertEqual(payload["stage_status"]["schema"], "rapidforensic-e01-workflow-stage-status-v1")
            self.assertEqual(payload["stage_status"]["stage_counts"]["blocked"], 1)
            self.assertEqual(payload["stage_status"]["blocked_stage_ids"], ["triage-run"])
            self.assertEqual(
                payload["stage_status"]["qc_links"]["validation_plan"],
                str((output_dir / "rapidforensic-e01-validation-plan.json").resolve()),
            )
            self.assertEqual(payload["outputs"]["stage_status"]["exists"], True)
            self.assertEqual(payload["outputs"]["validation_plan"]["exists"], True)
            self.assertEqual(payload["report_grade_validation_plan"]["profile_version"], "e01-ex01-report-grade-validation-plan-v1")
            self.assertIn("trusted-workflow-diff", {row["id"] for row in payload["report_grade_validation_plan"]["validation_commands"]})
            self.assertEqual(payload["known_answer_manifest"]["expected"]["partitions"][0]["start_sector"], 2048)
            self.assertIn("failure_guidance", payload["run_error"])
            self.assertIsNone(payload["outputs"]["smoke_report"]["sha256"])
            self.assertIn("Self-referential", payload["outputs"]["smoke_report"]["hash_note"])

    def test_e01_smoke_cli_writes_single_case_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            output_dir = root / "smoke-cli"
            e01_path.write_bytes(b"EVF-smoke-cli")

            exit_code = main(
                [
                    "e01-smoke",
                    str(e01_path),
                    "--output-dir",
                    str(output_dir),
                    "--case-id",
                    "CASE-SMOKE-CLI",
                    "--expected-partition-start-sector",
                    "2048",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads((output_dir / "rapidforensic-e01-smoke.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["case_id"], "CASE-SMOKE-CLI")
            self.assertEqual(payload["status"], "blocked")
            self.assertEqual(payload["outputs"]["known_answer_manifest"]["exists"], True)
            self.assertEqual(payload["outputs"]["evidence_preflight"]["exists"], True)
            self.assertEqual(payload["outputs"]["validation_plan"]["exists"], True)
            self.assertEqual(payload["outputs"]["stage_status"]["exists"], True)
            self.assertEqual(payload["outputs"]["smoke_report"]["exists"], True)

    def test_mmls_partition_selection_prefers_largest_supported_filesystem(self) -> None:
        text = """
DOS Partition Table
000: 0000000000 0000002047 Unallocated
001: 0000002048 0000010000 NTFS / exFAT (0x07)
002: 0000012048 0000001000 Linux (0x83)
003: 0000013048 0000090000 Basic data partition
"""

        self.assertEqual(mmls_first_filesystem(text), 13048)

    def test_mmls_partition_rows_include_browser_metadata(self) -> None:
        text = """
DOS Partition Table
Units are in 512-byte sectors
000: 0000000000 0000002047 Unallocated
001: 0000002048 0000010000 NTFS / exFAT (0x07)
002: 0000012048 0000001000 Linux swap
003: 0000013048 0000090000 Basic data partition
"""

        rows = parse_mmls_partitions(text)

        self.assertEqual(rows[1]["partition_number"], 1)
        self.assertEqual(rows[1]["start_sector"], 2048)
        self.assertEqual(rows[1]["byte_offset"], 2048 * 512)
        self.assertEqual(rows[1]["size_bytes"], 10000 * 512)
        self.assertEqual(rows[1]["filesystem_guess"], "ntfs")
        self.assertTrue(rows[1]["supported_filesystem_hint"])
        self.assertFalse(rows[2]["supported_filesystem_hint"])
        self.assertEqual(rows[2]["filesystem_guess"], "swap")
        self.assertTrue(rows[1]["manual_override_allowed"])

    def test_mmls_partition_selection_accepts_linux_xfs_and_ext(self) -> None:
        text = """
DOS Partition Table
000: 0000000000 0000002047 Unallocated
001: 0000002048 0000010000 Linux filesystem
002: 0000012048 0000090000 XFS
003: 0000102048 0000001000 Linux swap
"""

        self.assertEqual(mmls_first_filesystem(text), 12048)

    def test_mmls_partition_selection_accepts_user_start_sector(self) -> None:
        text = """
DOS Partition Table
000: 0000000000 0000002047 Unallocated
001: 0000002048 0000010000 NTFS / exFAT (0x07)
002: 0000012048 0000001000 Linux swap
003: 0000013048 0000090000 Basic data partition
"""

        self.assertEqual(select_mmls_filesystem(text, preferred_start_sector=2048), 2048)
        self.assertEqual(select_mmls_filesystem(text, preferred_start_sector=13048), 13048)
        with self.assertRaises(E01ExtractionError):
            select_mmls_filesystem(text, preferred_start_sector=12048)
        with self.assertRaises(E01ExtractionError):
            select_mmls_filesystem(text, preferred_start_sector=999999)

    def test_extract_e01_reports_missing_external_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            e01_path = Path(tmp_dir) / "case.E01"
            e01_path.write_bytes(b"EVF")

            with self.assertRaises(E01ExtractionError) as context:
                extract_e01_to_directory(e01_path, Path(tmp_dir) / "stage", tool_resolver=lambda _: None)

            self.assertIn("requires external tools", str(context.exception))

    def test_e01_segment_set_profile_detects_missing_split_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01 = root / "case.E01"
            e03 = root / "case.E03"
            e01.write_bytes(b"segment-1")
            e03.write_bytes(b"segment-3")

            profile = build_e01_segment_set_profile(e01)

            self.assertEqual(profile["segment_count"], 2)
            self.assertEqual(profile["segment_numbers"], [1, 3])
            self.assertFalse(profile["contiguous"])
            self.assertIn("missing segment", profile["warnings"][0])

    def test_e01_failure_guidance_classifies_operator_next_steps(self) -> None:
        missing = e01_failure_guidance("E01 direct input requires external tools: ewfmount")
        encrypted = e01_failure_guidance("tsk_recover failed: BitLocker encrypted volume")
        corrupt = e01_failure_guidance("ewfmount failed: corrupt segment checksum read error")
        unsupported_fs = e01_failure_guidance("requested partition does not look like a supported filesystem")
        partition = e01_failure_guidance("requested partition start sector 999 was not found")
        permission = e01_failure_guidance("ewfmount failed: operation not permitted")
        external = e01_failure_guidance("tsk_recover failed: unknown Sleuth Kit error")

        self.assertEqual(missing["category"], "missing-tool")
        self.assertEqual(encrypted["category"], "encrypted-volume")
        self.assertEqual(corrupt["category"], "corrupt-image")
        self.assertEqual(unsupported_fs["category"], "unsupported-filesystem")
        self.assertEqual(partition["category"], "partition-ambiguity")
        self.assertEqual(permission["category"], "permission")
        self.assertEqual(external["category"], "external-tool-failure")
        self.assertTrue(missing["next_actions"])
        self.assertIn("ewfverify", " ".join(corrupt["next_actions"]))
        self.assertIn("export", " ".join(unsupported_fs["next_actions"]).lower())

    def test_e01_evidence_preflight_writes_operator_runbook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            output = root / "evidence-preflight.json"
            e01_path.write_bytes(b"EVF-preflight")
            tool_rows = [
                {"tool": "ewfmount", "available": True, "path": "/usr/bin/ewfmount", "version": "ewfmount 1.0"},
                {"tool": "mmls", "available": True, "path": "/usr/bin/mmls", "version": "mmls 1.0"},
                {"tool": "tsk_recover", "available": True, "path": "/usr/bin/tsk_recover", "version": "tsk_recover 1.0"},
            ]

            with (
                patch("rapidtriage.core.evidence.missing_e01_tools", return_value=[]),
                patch("rapidtriage.core.evidence.collect_tool_preflight", return_value=tool_rows),
            ):
                exit_code = main(["evidence", str(e01_path), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["adapter"], "ewf")
            self.assertEqual(payload["preflight_summary"]["status"], "ready")
            workflow = payload["ingest_workflow"]
            self.assertEqual(workflow["profile_version"], "windows11-e01-single-case-workflow-v1")
            self.assertTrue(workflow["direct_extract_ready"])
            runbook = workflow["operator_runbook"]
            self.assertEqual(runbook["profile_version"], "windows11-e01-operator-runbook-v1")
            self.assertIn("rapidtriage run", runbook["recommended_commands"]["run"])
            self.assertEqual(runbook["gui_flow"][0]["label"], "Select E01/Ex01")
            self.assertIn("rapidtriage-e01.json", runbook["expected_outputs"])
            recovery = payload["recovery_unlock_profile"]
            self.assertEqual(recovery["profile_version"], "evidence-recovery-unlock-profile-v1")
            self.assertEqual(recovery["snapshot_workflow"]["status"], "post-extraction-handoff")
            self.assertFalse(recovery["snapshot_workflow"]["direct_image_level_mount_supported"])
            self.assertEqual(recovery["fde_unlock_workflow"]["status"], "completed")
            self.assertFalse(recovery["fde_unlock_workflow"]["lawful_unlock_supported"])
            fde_runbook = recovery["fde_unlock_workflow"]["operator_runbook"]
            self.assertEqual(fde_runbook["profile_version"], "fde-operator-runbook-v1")
            self.assertEqual(fde_runbook["rapidtriage_unlock_engine"], "not-implemented")
            self.assertIn("operator-provided decrypted mounted folder", fde_runbook["accepted_inputs"])
            self.assertIn("rapidtriage run", fde_runbook["post_unlock_next_steps"][1])
            self.assertTrue(recovery["unallocated_carving_workflow"]["bounded_signature_carving_available"])
            self.assertIn("rapidtriage carve", recovery["unallocated_carving_workflow"]["recommended_command"])

    def test_evidence_recovery_unlock_profile_surfaces_snapshot_and_fde_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_root = root / "mounted-evidence"
            (evidence_root / "System Volume Information" / "VSS-1").mkdir(parents=True)
            (evidence_root / ".snapshots" / "com.apple.TimeMachine.localsnapshots" / "2024-01-01-010101").mkdir(parents=True)
            folder_output = root / "folder-evidence.json"

            self.assertEqual(main(["evidence", str(evidence_root), "--output", str(folder_output)]), 0)

            folder_payload = json.loads(folder_output.read_text(encoding="utf-8"))
            recovery = folder_payload["recovery_unlock_profile"]
            self.assertEqual(recovery["snapshot_workflow"]["status"], "candidates-found")
            self.assertGreaterEqual(recovery["snapshot_workflow"]["candidate_count"], 2)
            kinds = {candidate["snapshot_kind"] for candidate in recovery["snapshot_workflow"]["candidates"]}
            self.assertIn("windows-system-volume-information", kinds)
            self.assertIn("apfs-or-time-machine-snapshot", kinds)
            signature_kinds = {row["kind"] for row in recovery["unallocated_carving_workflow"]["supported_signatures"]}
            self.assertIn("jpeg", signature_kinds)
            self.assertIn("zip", signature_kinds)

            locked_raw = root / "locked.raw"
            locked_raw.write_bytes(b"\x00" * 1024 + b"-FVE-FS-" + b"\x00" * 1024)
            raw_output = root / "raw-evidence.json"

            self.assertEqual(main(["evidence", str(locked_raw), "--output", str(raw_output)]), 0)

            raw_payload = json.loads(raw_output.read_text(encoding="utf-8"))
            fde = raw_payload["recovery_unlock_profile"]["fde_unlock_workflow"]
            self.assertEqual(fde["status"], "indicator-found")
            self.assertEqual(fde["indicators"][0]["product_hint"], "BitLocker")
            self.assertFalse(fde["on_the_fly_decryption_supported"])
            runbook = fde["operator_runbook"]
            self.assertEqual(runbook["status"], "unlock-material-required")
            self.assertIn("BitLocker", runbook["product_hints"])
            self.assertTrue(runbook["authority_required"])
            self.assertIn("source-hash-recorded", {item["id"] for item in runbook["qc_checklist"]})
            bitlocker_track = next(item for item in runbook["unlock_tracks"] if item["product"] == "BitLocker")
            self.assertIn("manage-bde", bitlocker_track["operator_tool_examples"])

    def test_e01_tool_preflight_records_roles_versions_and_remediation(self) -> None:
        calls: list[list[str]] = []

        def fake_runner(command):
            calls.append(list(command))
            if command[0] == "ewfmount":
                return subprocess.CompletedProcess(command, 0, "ewfmount 20260401\n", "")
            return subprocess.CompletedProcess(command, 1, "", "unknown option")

        rows = collect_tool_preflight(
            ("ewfmount", "mmls"),
            runner=fake_runner,
            tool_resolver=lambda name: f"/usr/bin/{name}" if name == "ewfmount" else None,
        )
        summary = e01_preflight_summary(rows)

        self.assertEqual(rows[0]["tool"], "ewfmount")
        self.assertEqual(rows[0]["version"], "ewfmount 20260401")
        self.assertIn("Expose E01/Ex01", rows[0]["purpose"])
        self.assertEqual(rows[1]["tool"], "mmls")
        self.assertFalse(rows[1]["available"])
        self.assertIn("Sleuth Kit", rows[1]["install_hint"])
        self.assertEqual(summary["status"], "blocked")
        self.assertEqual(summary["missing_tools"], ["mmls"])
        self.assertTrue(summary["remediation_steps"])
        self.assertIn(["ewfmount", "--version"], calls)

    def test_extract_e01_runs_mount_partition_and_recover_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            stage_dir = root / "stage"
            e01_path.write_bytes(b"EVF")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "ewfmount":
                    (Path(command[2]) / "ewf1").write_bytes(b"raw")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("fraud invoice", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_e01_to_directory(
                e01_path,
                stage_dir,
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertEqual(result.partition_start_sector, 2048)
            self.assertTrue((result.extract_dir / "evidence.txt").is_file())
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][0], "ewfmount")
            self.assertEqual(workflow_commands[1][0], "mmls")
            self.assertEqual(workflow_commands[2][0], "tsk_recover")
            metadata = result.to_dict()
            self.assertFalse(metadata["commercial_grade_ready"])
            self.assertIn("#22", metadata["commercial_gap_ids"])
            self.assertFalse(metadata["native_capabilities"]["native_e01_segment_metadata_decode"])
            self.assertEqual(metadata["source_integrity"]["hash_status"], "computed")
            self.assertTrue(metadata["tool_preflight"])
            self.assertEqual(metadata["preflight_summary"]["status"], "ready")
            self.assertFalse(metadata["preflight_summary"]["blocked"])
            self.assertTrue(metadata["partition_table"][0]["selected_for_recovery"])
            self.assertEqual(metadata["command_history"][-1]["purpose"], "read-only-filesystem-recovery")
            self.assertEqual(metadata["recovered_root_manifest"]["profile_version"], "e01-recovered-root-manifest-v1")
            self.assertEqual(metadata["recovered_root_manifest"]["hashed_file_count"], 1)
            self.assertEqual(metadata["recovered_root_manifest"]["files"][0]["relative_path"], "evidence.txt")
            self.assertEqual(metadata["recovered_root_manifest"]["files"][0]["hash_status"], "computed")
            workflow_manifest = metadata["e01_ex01_workflow_manifest"]
            self.assertEqual(workflow_manifest["profile_version"], "e01-ex01-integrated-workflow-manifest-v1")
            self.assertEqual(workflow_manifest["item_number"], 22)
            self.assertEqual(workflow_manifest["gap_id"], "#22")
            self.assertEqual(len(workflow_manifest["manifest_sha256"]), 64)
            provenance = metadata["e01_provenance_profile"]
            self.assertEqual(provenance["profile_version"], "e01-provenance-profile-v1")
            self.assertEqual(provenance["checklist_item"], 7)
            self.assertEqual(provenance["qc_gap_id"], "#7")
            self.assertEqual(provenance["source_image"]["name"], "case.E01")
            self.assertEqual(provenance["selected_partition"]["selected_start_sector"], 2048)
            self.assertEqual(len(provenance["tool_versions"]), 3)
            self.assertEqual(len(provenance["command_history"]), 3)
            self.assertFalse(provenance["read_only_posture"]["source_mutation_allowed"])
            self.assertEqual(len(provenance["manifest_sha256"]), 64)
            self.assertEqual(workflow_manifest["provenance_profile"]["manifest_sha256"], provenance["manifest_sha256"])
            self.assertEqual(workflow_manifest["status_context"], "extraction-result")
            workflow_statuses = {stage["id"]: stage["status"] for stage in workflow_manifest["stages"]}
            self.assertEqual(workflow_statuses["select-e01"], "complete")
            self.assertEqual(workflow_statuses["dependency-preflight"], "complete")
            self.assertEqual(workflow_statuses["partition-selection"], "complete")
            self.assertEqual(workflow_statuses["filesystem-extraction"], "complete")
            self.assertEqual(workflow_statuses["vsc-discovery-extraction"], "ready-after-extraction")
            self.assertEqual(workflow_statuses["artifact-analysis"], "ready-after-extraction")
            self.assertEqual(workflow_statuses["report-export"], "blocked")
            self.assertEqual(workflow_manifest["vsc_workflow_handoff"]["profile_version"], "vsc-image-workflow-handoff-v1")
            self.assertEqual(workflow_manifest["vsc_workflow_handoff"]["qc_prep_item"], 3)
            self.assertIn("vsc-discover", workflow_manifest["vsc_workflow_handoff"]["commands"]["discover"])
            stage_control = workflow_manifest["stage_control_contract"]
            self.assertEqual(stage_control["profile_version"], "image-stage-control-contract-v1")
            self.assertEqual(stage_control["qc_prep_item"], 4)
            self.assertTrue(stage_control["checkpoint"]["supported"])
            self.assertEqual(stage_control["cancel_retry"]["retry_route"], "/api/runs/<run-id>/retry")
            self.assertTrue(workflow_manifest["large_data_controls"]["bounded_recovered_root_manifest"])
            e01_gate = metadata["core_accuracy_gates"][0]
            self.assertEqual(e01_gate["gap_id"], "#22")
            self.assertIn("partition offset correctness", e01_gate["satisfied_checks"])
            self.assertIn("read-only extraction provenance", e01_gate["satisfied_checks"])
            e01_uplift = metadata["commercial_uplift_evidence"]
            self.assertEqual(e01_uplift["item_numbers"], [22])
            self.assertIn("#22-command-history", e01_uplift["passed_validation_matrix_ids"])
            self.assertIn("#22-native-commercial-parser", e01_uplift["failed_validation_matrix_ids"])
            self.assertEqual(
                e01_uplift["reportability_decision"]["decision"],
                "do-not-report-e01-ex01-workflow-as-native-complete",
            )
            self.assertFalse(e01_uplift["reportability_decision"]["ready_for_court_report"])

    def test_extract_e01_records_user_partition_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            stage_dir = root / "stage"
            e01_path.write_bytes(b"EVF")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "ewfmount":
                    (Path(command[2]) / "ewf1").write_bytes(b"raw")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        "\n".join(
                            [
                                "001: 0000002048 0000010000 NTFS / exFAT (0x07)",
                                "002: 0000013048 0000090000 Basic data partition",
                            ]
                        ),
                        "",
                    )
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_e01_to_directory(
                e01_path,
                stage_dir,
                partition_start_sector=2048,
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            recover_command = next(command for command in workflow_commands if command[0] == "tsk_recover")
            self.assertEqual(recover_command[4], "2048")
            metadata = result.to_dict()
            self.assertEqual(metadata["partition_start_sector"], 2048)
            self.assertEqual(metadata["partition_selection"]["selected_start_sector"], 2048)
            self.assertEqual(metadata["partition_selection"]["selected_byte_offset"], 2048 * 512)
            self.assertEqual(metadata["partition_selection"]["selected_filesystem_guess"], "ntfs")
            self.assertEqual(metadata["partition_selection"]["recommended_start_sector"], 13048)
            self.assertEqual(metadata["partition_selection"]["requested_start_sector"], 2048)
            self.assertEqual(metadata["partition_selection"]["selection_source"], "user-request")
            self.assertEqual(metadata["partition_selection"]["manual_override"]["requested_start_sector"], 2048)
            self.assertTrue(metadata["partition_selection"]["manual_override"]["warning_required_when_differs_from_recommendation"])
            self.assertIn("byte_offset", metadata["partition_selection"]["partition_browser_columns"])
            self.assertTrue(metadata["partition_selection"]["partition_browser_rows"][0]["selected_for_recovery"])
            self.assertFalse(metadata["partition_selection"]["partition_browser_rows"][0]["recommended_for_recovery"])
            self.assertTrue(metadata["partition_selection"]["partition_browser_rows"][1]["recommended_for_recovery"])
            self.assertIn("differs", metadata["partition_selection"]["selection_warning"])
            self.assertTrue(metadata["partition_table"][0]["selected_for_recovery"])
            self.assertFalse(metadata["partition_table"][0]["recommended_for_recovery"])
            self.assertFalse(metadata["partition_table"][1]["selected_for_recovery"])
            self.assertTrue(metadata["partition_table"][1]["recommended_for_recovery"])

    def test_extract_e01_resumes_completed_filesystem_recovery_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            stage_dir = root / "stage"
            e01_path.write_bytes(b"EVF")
            commands: list[list[str]] = []

            def first_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "ewfmount":
                    (Path(command[2]) / "ewf1").write_bytes(b"raw")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("recovered once", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            first_result = extract_e01_to_directory(
                e01_path,
                stage_dir,
                runner=first_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )
            checkpoint_path = stage_dir / "rapidtriage-e01-stage-status.json"
            self.assertTrue(checkpoint_path.is_file())
            self.assertFalse(first_result.resume_status["resumed_from_checkpoint"])
            self.assertEqual(first_result.resume_status["reuse_reasons"], [])
            self.assertIn("read-only-filesystem-recovery", first_result.resume_status["completed_stages"])

            def forbidden_runner(command):
                raise AssertionError(f"resume path should not execute external command: {command}")

            resumed_result = extract_e01_to_directory(
                e01_path,
                stage_dir,
                runner=forbidden_runner,
                tool_resolver=lambda _: None,
            )

            self.assertEqual(resumed_result.partition_start_sector, 2048)
            self.assertTrue(resumed_result.resume_status["resumed_from_checkpoint"])
            self.assertTrue(resumed_result.resume_status["resume_ready"])
            self.assertIn("source signature matched", " ".join(resumed_result.resume_status["reuse_reasons"]))
            self.assertIn("verify source signature", resumed_result.resume_status["resume_warning"])
            self.assertIn("read-only-filesystem-recovery", resumed_result.resume_status["completed_stages"])
            self.assertEqual(resumed_result.recovered_root_manifest["hashed_file_count"], 1)
            self.assertEqual((resumed_result.extract_dir / "evidence.txt").read_text(encoding="utf-8"), "recovered once")

    def test_raw_split_image_discovery_sorts_numeric_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for name in ("case.003", "case.001", "case.002", "other.001"):
                (root / name).write_bytes(b"part")

            parts = discover_split_image_parts(root / "case.001")

            self.assertEqual([part.name for part in parts], ["case.001", "case.002", "case.003"])

    def test_raw_split_image_metadata_warns_about_missing_segments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "case.001"
            image_path.write_bytes(b"part1")
            (root / "case.003").write_bytes(b"part3")

            def fake_runner(command):
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_raw_image_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            metadata = result.to_dict()
            self.assertEqual([Path(path).name for path in metadata["image_paths"]], ["case.001", "case.003"])
            self.assertTrue(metadata["split_part_warnings"])
            self.assertIn("missing segment", metadata["split_part_warnings"][0])
            self.assertEqual(metadata["split_set_profile"]["missing_segment_numbers"], [2])
            self.assertFalse(metadata["split_set_profile"]["contiguous"])

    def test_raw_split_report_grade_validation_plan_tracks_slots_and_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            first = root / "case.001"
            second = root / "case.002"
            first.write_bytes(b"raw-a")
            second.write_bytes(b"raw-b")
            split_profile = build_split_set_profile([first, second], selected_path=first)

            plan = build_raw_split_report_grade_validation_plan(
                first,
                image_paths=[first, second],
                output_dir=root / "validation",
                expected_partition_start_sector=2048,
                expected_files=["Windows/System32/config/SAM"],
                source_integrity=[
                    {"path": str(first), "sha256": "a" * 64},
                    {"path": str(second), "sha256": "b" * 64},
                ],
                split_set_profile=split_profile,
                tool_preflight=[
                    {"tool": "mmls", "available": True, "version": "mmls 1.0"},
                    {"tool": "tsk_recover", "available": True, "version": "tsk_recover 1.0"},
                ],
                partition_table=[{"partition_number": 1, "start_sector": 2048, "filesystem_guess": "ntfs"}],
            )

            self.assertEqual(plan["profile_version"], "raw-split-report-grade-validation-plan-v1")
            self.assertEqual(plan["gap_id"], "#23")
            self.assertEqual(plan["status"], "report-validation-blocked")
            command_ids = {row["id"] for row in plan["validation_commands"]}
            self.assertIn("trusted-partition-enumeration", command_ids)
            self.assertIn("trusted-filesystem-stats", command_ids)
            self.assertIn("read-only-recovery", command_ids)
            self.assertIn("trusted-workflow-diff", command_ids)
            slot_status = {slot["id"]: slot["status"] for slot in plan["evidence_slots"]}
            self.assertEqual(slot_status["split-part-inventory"], "complete")
            self.assertEqual(slot_status["per-part-source-hashes"], "complete")
            self.assertEqual(slot_status["gap-order-size-review"], "complete")
            self.assertEqual(slot_status["partition-selection-and-fsstat"], "complete")
            self.assertEqual(slot_status["read-only-recovery-provenance"], "pending-read-only-recovery")
            self.assertIn("trusted-recovery-diff", plan["blocking_slot_ids"])
            self.assertEqual(plan["expected_files"][0]["description"], "Windows/System32/config/SAM")
            self.assertEqual(len(plan["manifest_sha256"]), 64)

    def test_extract_raw_image_runs_mmls_and_tsk_recover(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "case.001"
            (root / "case.001").write_bytes(b"part1")
            (root / "case.002").write_bytes(b"part2")
            stage_dir = root / "stage"
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("raw image invoice", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_raw_image_to_directory(
                image_path,
                stage_dir,
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertEqual(result.partition_start_sector, 2048)
            self.assertEqual(result.recovery_mode, "partition-offset")
            self.assertEqual([path.name for path in result.image_paths], ["case.001", "case.002"])
            self.assertTrue((result.extract_dir / "evidence.txt").is_file())
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][0], "mmls")
            self.assertEqual(workflow_commands[1][0], "tsk_recover")
            self.assertIn("-o", workflow_commands[1])
            metadata = result.to_dict()
            self.assertFalse(metadata["commercial_grade_ready"])
            self.assertIn("#23", metadata["commercial_gap_ids"])
            self.assertFalse(metadata["native_capabilities"]["native_partition_filesystem_parser"])
            self.assertEqual(metadata["source_integrity"][0]["hash_status"], "computed")
            self.assertEqual(metadata["partition_table"][0]["selected_for_recovery"], True)
            raw_gate = metadata["core_accuracy_gates"][0]
            self.assertEqual(raw_gate["gap_id"], "#23")
            self.assertIn("partition table parsing", raw_gate["satisfied_checks"])
            self.assertIn("filesystem extraction audit", raw_gate["satisfied_checks"])
            self.assertIn("deleted-file recovery expectations", raw_gate["satisfied_checks"])
            raw_uplift = metadata["commercial_uplift_evidence"]
            self.assertEqual(raw_uplift["batch_id"], "commercial-uplift-021-025")
            self.assertEqual(raw_uplift["item_numbers"], [23])
            self.assertIn("#23-command-history", raw_uplift["passed_validation_matrix_ids"])
            self.assertEqual(raw_uplift["large_data_controls"]["split_part_count"], 2)
            self.assertEqual(raw_uplift["large_data_controls"]["split_set_contiguous"], True)
            self.assertEqual(metadata["split_set_profile"]["part_count"], 2)
            self.assertTrue(metadata["split_set_profile"]["selected_is_first_segment"])
            validation_plan = metadata["report_grade_validation_plan"]
            self.assertEqual(validation_plan["profile_version"], "raw-split-report-grade-validation-plan-v1")
            self.assertEqual(validation_plan["gap_id"], "#23")
            self.assertIn("trusted-workflow-diff", {row["id"] for row in validation_plan["validation_commands"]})
            self.assertIn("trusted-recovery-diff", validation_plan["blocking_slot_ids"])
            self.assertIn("partition-selection-and-fsstat", validation_plan["ready_slot_ids"])
            self.assertEqual(len(validation_plan["manifest_sha256"]), 64)
            self.assertEqual(metadata["recovered_root_manifest"]["visited_file_count"], 1)
            self.assertEqual(metadata["recovered_root_manifest"]["hashed_file_count"], 1)
            self.assertEqual(metadata["recovered_root_manifest"]["files"][0]["relative_path"], "evidence.txt")
            self.assertEqual(metadata["recovered_root_manifest"]["files"][0]["hash_status"], "computed")
            workflow_manifest = metadata["raw_split_workflow_manifest"]
            self.assertEqual(workflow_manifest["profile_version"], "raw-split-integrated-workflow-manifest-v1")
            self.assertEqual(workflow_manifest["item_number"], 23)
            self.assertEqual(workflow_manifest["gap_id"], "#23")
            self.assertEqual(len(workflow_manifest["manifest_sha256"]), 64)
            self.assertEqual(workflow_manifest["status_context"], "extraction-result")
            workflow_statuses = {stage["id"]: stage["status"] for stage in workflow_manifest["stages"]}
            self.assertEqual(workflow_statuses["select-raw-or-split"], "complete")
            self.assertEqual(workflow_statuses["split-set-validation"], "complete")
            self.assertEqual(workflow_statuses["dependency-preflight"], "complete")
            self.assertEqual(workflow_statuses["partition-selection"], "complete")
            self.assertEqual(workflow_statuses["filesystem-extraction"], "complete")
            self.assertEqual(workflow_statuses["vsc-discovery-extraction"], "ready-after-extraction")
            self.assertEqual(workflow_statuses["artifact-analysis"], "ready-after-extraction")
            self.assertEqual(workflow_manifest["vsc_workflow_handoff"]["source_kind"], "raw-split-image")
            self.assertIn("vsc-extract", workflow_manifest["vsc_workflow_handoff"]["commands"]["extract"])
            self.assertEqual(workflow_manifest["stage_control_contract"]["profile_version"], "image-stage-control-contract-v1")
            self.assertFalse(workflow_manifest["stage_control_contract"]["checkpoint"]["supported"])
            self.assertIn("split-set provenance profile", raw_gate["satisfied_checks"])
            self.assertEqual(
                raw_uplift["reportability_decision"]["allowed_use"],
                "raw-split-extraction-triage-pivot",
            )
            self.assertIn(
                "native-partition-filesystem-parser-not-implemented",
                raw_uplift["reportability_decision"]["blockers"],
            )

    def test_extract_raw_image_falls_back_to_whole_image_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "filesystem.raw"
            image_path.write_bytes(b"single filesystem")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 1, "", "No partition table")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "evidence.txt").write_text("whole image", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_raw_image_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertIsNone(result.partition_start_sector)
            self.assertEqual(result.recovery_mode, "whole-image")
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertNotIn("-o", workflow_commands[1])

    def test_extract_archive_image_uses_available_7zip_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "install.iso"
            image_path.write_bytes(b"iso")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                Path(command[3][2:] if command[3].startswith("-o") else command[-1]).mkdir(parents=True, exist_ok=True)
                if command[0] in {"7z", "7zz"}:
                    out_dir = Path(command[3][2:])
                    (out_dir / "setup.log").write_text("archive image extracted", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_archive_image_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}" if name == "7z" else None,
            )

            self.assertEqual(result.tool, "7z")
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][:3], ["7z", "x", "-y"])
            self.assertTrue((result.extract_dir / "setup.log").is_file())
            self.assertFalse(result.to_dict()["commercial_grade_ready"])

    def test_extract_virtual_disk_converts_to_raw_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "vm.vmdk"
            image_path.write_bytes(b"vmdk")
            commands: list[list[str]] = []

            def fake_runner(command):
                commands.append(list(command))
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
                if command[:3] == ["qemu-img", "info", "--output=json"]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        '{"format":"vmdk","virtual-size":4096,"actual-size":2048}',
                        "",
                    )
                if command[:3] == ["qemu-img", "convert", "-O"]:
                    Path(command[-1]).write_bytes(b"converted raw")
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[0] == "mmls":
                    return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
                if command[0] == "tsk_recover":
                    Path(command[-1]).mkdir(parents=True, exist_ok=True)
                    (Path(command[-1]) / "vm-evidence.txt").write_text("virtual disk evidence", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            result = extract_virtual_disk_to_directory(
                image_path,
                root / "stage",
                runner=fake_runner,
                tool_resolver=lambda name: f"/usr/bin/{name}",
            )

            self.assertEqual(result.conversion_tool, "qemu-img")
            workflow_commands = [command for command in commands if command[1:] != ["--version"]]
            self.assertEqual(workflow_commands[0][:3], ["qemu-img", "info", "--output=json"])
            self.assertEqual(workflow_commands[1][:4], ["qemu-img", "convert", "-O", "raw"])
            self.assertTrue(result.converted_raw_path.is_file())
            self.assertTrue((result.extract_dir / "vm-evidence.txt").is_file())
            self.assertEqual(result.raw_result.partition_start_sector, 2048)
            metadata = result.to_dict()
            self.assertFalse(metadata["commercial_grade_ready"])
            self.assertIn("#24", metadata["commercial_gap_ids"])
            self.assertFalse(metadata["native_capabilities"]["snapshot_chain_validation"])
            self.assertEqual(metadata["source_integrity"]["hash_status"], "computed")
            self.assertEqual(metadata["converted_raw_integrity"]["hash_status"], "computed")
            vm_gate = metadata["core_accuracy_gates"][0]
            self.assertEqual(vm_gate["gap_id"], "#24")
            self.assertIn("converted raw hash/provenance", vm_gate["satisfied_checks"])
            self.assertIn("nested partition extraction", vm_gate["satisfied_checks"])
            self.assertIn("virtual disk chain risk profile", vm_gate["satisfied_checks"])
            self.assertEqual(metadata["virtual_disk_chain_profile"]["detected_format"], "vmdk")
            self.assertEqual(metadata["virtual_disk_chain_profile"]["parent_chain_resolution"], "not-implemented")
            self.assertEqual(metadata["qemu_img_info_profile"]["parse_status"], "json-parsed")
            self.assertEqual(metadata["qemu_img_info_profile"]["format"], "vmdk")
            vm_uplift = metadata["commercial_uplift_evidence"]
            self.assertEqual(vm_uplift["item_numbers"], [24])
            self.assertEqual(vm_uplift["large_data_controls"]["virtual_disk_chain_status"], "review-required")
            self.assertIn("#24-command-history", vm_uplift["passed_validation_matrix_ids"])
            self.assertIn("#24-native-commercial-parser", vm_uplift["failed_validation_matrix_ids"])
            workflow_manifest = metadata["virtual_disk_workflow_manifest"]
            self.assertEqual(workflow_manifest["profile_version"], "virtual-disk-integrated-workflow-manifest-v1")
            self.assertEqual(workflow_manifest["item_number"], 24)
            self.assertEqual(workflow_manifest["gap_id"], "#24")
            self.assertEqual(len(workflow_manifest["manifest_sha256"]), 64)
            self.assertEqual(workflow_manifest["status_context"], "extraction-result")
            workflow_statuses = {stage["id"]: stage["status"] for stage in workflow_manifest["stages"]}
            self.assertEqual(workflow_statuses["select-virtual-disk"], "complete")
            self.assertEqual(workflow_statuses["chain-risk-review"], "review-required")
            self.assertEqual(workflow_statuses["dependency-preflight"], "complete")
            self.assertEqual(workflow_statuses["qemu-img-info"], "complete")
            self.assertEqual(workflow_statuses["raw-conversion"], "complete")
            self.assertEqual(workflow_statuses["nested-raw-recovery"], "complete")
            self.assertEqual(workflow_statuses["artifact-analysis"], "ready-after-extraction")
            self.assertTrue(workflow_manifest["large_data_controls"]["nested_raw_manifest_linked"])
            self.assertEqual(
                vm_uplift["reportability_decision"]["decision"],
                "do-not-report-virtual-disk-workflow-as-chain-complete",
            )
            self.assertFalse(vm_uplift["reportability_decision"]["native_parser_complete"])

    def test_virtual_disk_chain_profile_flags_snapshot_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "case-000001.vmdk"
            source.write_bytes(b"snapshot member")

            profile = build_virtual_disk_chain_profile(source)

            self.assertTrue(profile["suspected_snapshot_or_differencing_member"])
            self.assertEqual(profile["chain_validation_status"], "review-required")
            self.assertIn("snapshot/differencing", profile["warnings"][0])

    def test_image_workflow_trusted_diffs_gate_e01_raw_vm_and_container_claims(self) -> None:
        e01_diff = build_image_workflow_trusted_diff(
            22,
            [
                {
                    "source_path": "case.E01",
                    "source_sha256": "a" * 64,
                    "partition_start_sector": 2048,
                    "recovery_mode": "partition-offset",
                }
            ],
            [
                {
                    "SourcePath": "case.E01",
                    "SHA256": "a" * 64,
                    "StartSector": 2048,
                    "Workflow": "partition-offset",
                }
            ],
            trusted_tool="ewfverify",
        )
        raw_diff = build_image_workflow_trusted_diff(
            23,
            [{"source_path": "case.001", "source_sha256": "b" * 64, "extracted_file_path": "/evidence.txt", "extracted_sha256": "c" * 64}],
            [{"ImagePath": "case.001", "SourceHash": "b" * 64, "Path": "/evidence.txt", "FileSHA256": "c" * 64}],
            trusted_tool="tsk_recover",
        )
        vm_diff = build_image_workflow_trusted_diff(
            24,
            [{"source_path": "vm.vmdk", "converted_raw_sha256": "d" * 64, "partition_start_sector": 2048}],
            [{"Source": "vm.vmdk", "ConvertedSHA256": "d" * 64, "OffsetSector": 2048}],
            trusted_tool="qemu-img",
        )
        container_diff = build_image_workflow_trusted_diff(
            25,
            [{"container_type": "ad1", "source_sha256": "e" * 64, "export_manifest_sha256": "f" * 64}],
            [{"Format": "ad1", "SHA256": "e" * 64, "VendorManifestSHA256": "f" * 64}],
            trusted_tool="vendor export manifest",
        )

        self.assertEqual(e01_diff["status"], "pass")
        self.assertEqual(raw_diff["status"], "pass")
        self.assertEqual(vm_diff["status"], "pass")
        self.assertEqual(container_diff["status"], "pass")
        self.assertIn(
            "trusted E01/Ex01 workflow diff pass",
            image_core_accuracy_gates(22, {"source_integrity": {"sha256": "a" * 64}, "image_trusted_diff": e01_diff})[0][
                "satisfied_checks"
            ],
        )
        self.assertIn(
            "trusted RAW/split image recovery diff pass",
            image_core_accuracy_gates(23, {"source_integrity": [{"sha256": "b" * 64}], "image_trusted_diff": raw_diff})[0][
                "satisfied_checks"
            ],
        )
        self.assertIn(
            "trusted virtual disk conversion diff pass",
            image_core_accuracy_gates(24, {"converted_raw_integrity": {"sha256": "d" * 64}, "image_trusted_diff": vm_diff})[0][
                "satisfied_checks"
            ],
        )
        self.assertIn(
            "verified vendor export manifest diff pass",
            image_core_accuracy_gates(25, {"container_type": "ad1", "image_trusted_diff": container_diff})[0][
                "satisfied_checks"
            ],
        )

    def test_e01_trusted_diff_accepts_nested_result_metadata_and_recovered_manifest(self) -> None:
        diff = build_image_workflow_trusted_diff(
            22,
            [
                {
                    "details": {
                        "source_path": "/cases/case.E01",
                        "source_integrity": {"sha256": "a" * 64, "path": "/cases/case.E01"},
                        "partition_selection": {"selected_start_sector": 2048},
                        "segment_set_profile": {
                            "segment_count": 2,
                            "segment_numbers": [1, 2],
                            "contiguous": True,
                            "selected_is_first_segment": True,
                        },
                        "recovered_root_manifest": {
                            "visited_file_count": 1,
                            "hashed_file_count": 1,
                            "files": [
                                {
                                    "relative_path": "evidence.txt",
                                    "sha256": "b" * 64,
                                }
                            ],
                        },
                    }
                }
            ],
            [
                {
                    "SourcePath": "/cases/case.E01",
                    "SourceSHA256": "a" * 64,
                    "StartSector": "2048",
                    "Workflow": "partition-offset",
                    "SegmentCount": "2",
                    "SegmentNumbers": "1,2",
                    "Contiguous": "true",
                    "SelectedIsFirstSegment": "true",
                    "RecoveredFileCount": "1",
                    "HashedFileCount": "1",
                    "Path": "evidence.txt",
                    "FileSHA256": "b" * 64,
                }
            ],
            trusted_tool="ewfverify",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["mismatch_count"], 0)

    def test_e01_trusted_diff_blocks_nested_recovered_hash_mismatches(self) -> None:
        diff = build_image_workflow_trusted_diff(
            22,
            [
                {
                    "details": {
                        "source_path": "/cases/case.E01",
                        "source_integrity": {"sha256": "a" * 64},
                        "partition_selection": {"selected_start_sector": 2048},
                        "recovered_root_manifest": {
                            "files": [{"relative_path": "evidence.txt", "sha256": "b" * 64}]
                        },
                    }
                }
            ],
            [
                {
                    "SourcePath": "/cases/case.E01",
                    "SourceSHA256": "a" * 64,
                    "StartSector": "2048",
                    "Workflow": "partition-offset",
                    "Path": "evidence.txt",
                    "FileSHA256": "c" * 64,
                }
            ],
            trusted_tool="ewfverify",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "extracted_sha256")

    def test_raw_trusted_diff_accepts_nested_split_profile_and_recovered_manifest(self) -> None:
        diff = build_image_workflow_trusted_diff(
            23,
            [
                {
                    "details": {
                        "source_path": "/cases/case.001",
                        "source_integrity": [
                            {"path": "/cases/case.001", "sha256": "a" * 64},
                            {"path": "/cases/case.002", "sha256": "b" * 64},
                        ],
                        "partition_start_sector": 2048,
                        "recovery_mode": "partition-offset",
                        "split_set_profile": {
                            "part_count": 2,
                            "segment_numbers": [1, 2],
                            "contiguous": True,
                            "selected_is_first_segment": True,
                        },
                        "recovered_root_manifest": {
                            "visited_file_count": 1,
                            "hashed_file_count": 1,
                            "files": [
                                {
                                    "relative_path": "Users/Alice/Desktop/evidence.txt",
                                    "sha256": "c" * 64,
                                }
                            ],
                        },
                    }
                }
            ],
            [
                {
                    "ImagePath": "/cases/case.001",
                    "SourceSHA256": "a" * 64,
                    "StartSector": "2048",
                    "Workflow": "partition-offset",
                    "SplitPartCount": "2",
                    "SplitSegmentNumbers": "1,2",
                    "SplitSetContiguous": "true",
                    "SelectedIsFirstSegment": "true",
                    "RecoveredFileCount": "1",
                    "HashedFileCount": "1",
                    "Path": "Users/Alice/Desktop/evidence.txt",
                    "FileSHA256": "c" * 64,
                }
            ],
            trusted_tool="tsk_recover",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)
        self.assertEqual(diff["mismatch_count"], 0)

    def test_raw_trusted_diff_blocks_nested_split_profile_mismatches(self) -> None:
        diff = build_image_workflow_trusted_diff(
            23,
            [
                {
                    "details": {
                        "source_path": "/cases/case.001",
                        "source_integrity": [{"path": "/cases/case.001", "sha256": "a" * 64}],
                        "partition_start_sector": 2048,
                        "split_set_profile": {
                            "part_count": 2,
                            "segment_numbers": [1, 3],
                            "contiguous": False,
                        },
                        "recovered_root_manifest": {
                            "files": [{"relative_path": "evidence.txt", "sha256": "b" * 64}]
                        },
                    }
                }
            ],
            [
                {
                    "ImagePath": "/cases/case.001",
                    "SourceSHA256": "a" * 64,
                    "StartSector": "2048",
                    "SplitPartCount": "2",
                    "SplitSegmentNumbers": "1,2",
                    "SplitSetContiguous": "true",
                    "Path": "evidence.txt",
                    "FileSHA256": "b" * 64,
                }
            ],
            trusted_tool="tsk_recover",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "split_segment_numbers")

    def test_virtual_disk_trusted_diff_accepts_nested_raw_recovery_and_chain_profile(self) -> None:
        diff = build_image_workflow_trusted_diff(
            24,
            [
                {
                    "details": {
                        "source_path": "/cases/vm.vmdk",
                        "source_integrity": {"path": "/cases/vm.vmdk", "sha256": "a" * 64},
                        "converted_raw_path": "/stage/converted/vm.raw",
                        "converted_raw_integrity": {"path": "/stage/converted/vm.raw", "sha256": "b" * 64},
                        "virtual_disk_chain_profile": {
                            "detected_format": "vmdk",
                            "chain_validation_status": "review-required",
                            "suspected_snapshot_or_differencing_member": True,
                            "parent_chain_resolution": "not-implemented",
                        },
                        "raw_extraction": {
                            "partition_start_sector": 2048,
                            "recovery_mode": "partition-offset",
                            "recovered_root_manifest": {
                                "visited_file_count": 1,
                                "hashed_file_count": 1,
                                "files": [{"relative_path": "evidence.txt", "sha256": "c" * 64}],
                            },
                        },
                    }
                }
            ],
            [
                {
                    "SourcePath": "/cases/vm.vmdk",
                    "SourceSHA256": "a" * 64,
                    "ConvertedSHA256": "b" * 64,
                    "StartSector": "2048",
                    "Workflow": "partition-offset",
                    "VirtualDiskFormat": "vmdk",
                    "VirtualDiskChainStatus": "review-required",
                    "SnapshotMember": "true",
                    "ParentChainResolution": "not-implemented",
                    "Path": "evidence.txt",
                    "FileSHA256": "c" * 64,
                }
            ],
            trusted_tool="qemu-img",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_virtual_disk_trusted_diff_blocks_nested_converted_hash_mismatches(self) -> None:
        diff = build_image_workflow_trusted_diff(
            24,
            [
                {
                    "details": {
                        "source_path": "/cases/vm.vmdk",
                        "source_integrity": {"sha256": "a" * 64},
                        "converted_raw_integrity": {"sha256": "b" * 64},
                        "raw_extraction": {
                            "partition_start_sector": 2048,
                            "recovered_root_manifest": {
                                "files": [{"relative_path": "evidence.txt", "sha256": "c" * 64}]
                            },
                        },
                    }
                }
            ],
            [
                {
                    "SourcePath": "/cases/vm.vmdk",
                    "SourceSHA256": "a" * 64,
                    "ConvertedSHA256": "d" * 64,
                    "StartSector": "2048",
                    "Path": "evidence.txt",
                    "FileSHA256": "c" * 64,
                }
            ],
            trusted_tool="qemu-img",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["commercial_grade_evidence"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["field"], "converted_raw_sha256")

    def test_container_trusted_diff_accepts_nested_verified_export_manifest_profile(self) -> None:
        diff = build_image_workflow_trusted_diff(
            25,
            [
                {
                    "details": {
                        "source_path": "/cases/case.ad1",
                        "source_integrity": {"path": "/cases/case.ad1", "sha256": "a" * 64},
                        "container_type": "ad1",
                        "verified_export_manifest_profile": {
                            "manifest_sha256": "b" * 64,
                            "vendor_tool": "FTK Imager",
                            "validation_status": "manifest-linked",
                        },
                    }
                }
            ],
            [
                {
                    "ContainerPath": "/cases/case.ad1",
                    "SourceSHA256": "a" * 64,
                    "Format": "ad1",
                    "VendorManifestSHA256": "b" * 64,
                }
            ],
            trusted_tool="vendor export manifest",
        )

        self.assertEqual(diff["status"], "pass")
        self.assertTrue(diff["commercial_grade_evidence"])
        self.assertEqual(diff["matched_count"], 1)

    def test_image_workflow_trusted_diff_blocks_unknown_tools_and_mismatches(self) -> None:
        diff = build_image_workflow_trusted_diff(
            23,
            [{"source_path": "case.001", "extracted_file_path": "/a.txt", "extracted_sha256": "a" * 64}],
            [{"SourcePath": "case.001", "Path": "/a.txt", "FileSHA256": "b" * 64}],
            trusted_tool="unknown-tool",
        )

        self.assertEqual(diff["status"], "diffs-present")
        self.assertFalse(diff["trusted_tool_recognized"])
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertIn("raw-split-trusted-recovery-diff-required", diff["reportability_decision"]["blockers"])

    def test_run_triage_accepts_e01_image_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            e01_path = root / "case.E01"
            output_dir = root / "run-out"
            e01_path.write_bytes(b"EVF")

            def fake_extract(
                source_path: Path,
                stage_dir: Path,
                *,
                partition_start_sector: int | None = None,
            ) -> E01ExtractionResult:
                extract_dir = stage_dir / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                return E01ExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    mount_dir=stage_dir / "_ewfmount",
                    raw_image_path=stage_dir / "_ewfmount" / "ewf1",
                    extract_dir=extract_dir,
                    partition_start_sector=partition_start_sector or 2048,
                )

            with patch("rapidtriage.core.run.extract_e01_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(
                    e01_path,
                    mode="fraud",
                    output_dir=output_dir,
                    e01_partition_start_sector=4096,
                )

            self.assertEqual(payload["source"]["type"], "e01")
            self.assertEqual(Path(payload["source"]["source_path"]), e01_path.resolve())
            self.assertEqual(payload["source"]["workflow_status"]["profile_version"], "windows11-e01-run-workflow-v1")
            self.assertEqual(payload["source"]["workflow_status"]["stages"][0]["id"], "select-e01")
            self.assertEqual(payload["source"]["workflow_status"]["stages"][-1]["id"], "search-review-report")
            self.assertEqual(payload["source"]["workflow_status"]["selected_partition_start_sector"], 4096)
            self.assertIn("operator_runbook", payload["source"]["workflow_status"])
            self.assertIn("--e01-partition-start-sector 4096", payload["source"]["workflow_status"]["recommended_commands"]["run"])
            self.assertEqual(payload["source"]["vsc_workflow_handoff"]["profile_version"], "vsc-image-workflow-handoff-v1")
            self.assertIn("vsc-compare", payload["source"]["workflow_status"]["vsc_workflow_handoff"]["commands"]["compare"])
            self.assertEqual(payload["source"]["stage_control_contract"]["qc_prep_item"], 4)
            self.assertTrue(payload["source"]["workflow_status"]["stage_control_contract"]["resume"]["supported"])
            workflow_manifest = payload["source"]["e01_ex01_workflow_manifest"]
            self.assertEqual(workflow_manifest["profile_version"], "e01-ex01-integrated-workflow-manifest-v1")
            self.assertEqual(workflow_manifest["status_context"], "run-summary")
            self.assertEqual(len(workflow_manifest["manifest_sha256"]), 64)
            workflow_statuses = {stage["id"]: stage["status"] for stage in workflow_manifest["stages"]}
            self.assertEqual(workflow_statuses["artifact-analysis"], "complete")
            self.assertEqual(workflow_statuses["vsc-discovery-extraction"], "ready-after-extraction")
            self.assertEqual(workflow_statuses["unified-search-indexing"], "complete")
            self.assertEqual(workflow_statuses["review-workflow"], "ready")
            self.assertEqual(workflow_statuses["report-export"], "complete")
            self.assertIn("summary", workflow_manifest["run_output_status"])
            self.assertFalse(workflow_manifest["commercial_grade_ready"])
            self.assertEqual(Path(payload["root"]), (output_dir / "_e01" / "filesystem").resolve())
            self.assertIn("e01", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-e01.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-e01.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["partition_start_sector"], 4096)
            self.assertEqual(
                metadata["e01_ex01_workflow_manifest"]["profile_version"],
                "e01-ex01-integrated-workflow-manifest-v1",
            )
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)

    def test_run_triage_accepts_raw_image_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "case.001"
            output_dir = root / "run-out"
            image_path.write_bytes(b"raw")

            def fake_extract(source_path: Path, stage_dir: Path) -> DiskImageExtractionResult:
                extract_dir = stage_dir / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                return DiskImageExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    extract_dir=extract_dir,
                    image_paths=(source_path,),
                    partition_start_sector=2048,
                    recovery_mode="partition-offset",
                )

            with patch("rapidtriage.core.run.extract_raw_image_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(image_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "raw-image")
            self.assertEqual(Path(payload["source"]["source_path"]), image_path.resolve())
            raw_manifest = payload["source"]["raw_split_workflow_manifest"]
            self.assertEqual(raw_manifest["profile_version"], "raw-split-integrated-workflow-manifest-v1")
            self.assertEqual(raw_manifest["status_context"], "run-summary")
            self.assertEqual(len(raw_manifest["manifest_sha256"]), 64)
            self.assertEqual(payload["source"]["vsc_workflow_handoff"]["source_kind"], "raw-split-image")
            self.assertEqual(payload["source"]["stage_control_contract"]["profile_version"], "image-stage-control-contract-v1")
            self.assertEqual(raw_manifest["vsc_workflow_handoff"]["qc_prep_item"], 3)
            self.assertEqual(raw_manifest["stage_control_contract"]["qc_prep_item"], 4)
            raw_statuses = {stage["id"]: stage["status"] for stage in raw_manifest["stages"]}
            self.assertEqual(raw_statuses["artifact-analysis"], "complete")
            self.assertEqual(raw_statuses["vsc-discovery-extraction"], "ready-after-extraction")
            self.assertEqual(raw_statuses["unified-search-indexing"], "complete")
            self.assertEqual(raw_statuses["review-report"], "complete")
            self.assertIn("summary", raw_manifest["run_output_status"])
            self.assertFalse(raw_manifest["commercial_grade_ready"])
            self.assertEqual(Path(payload["root"]), (output_dir / "_disk_image" / "filesystem").resolve())
            self.assertIn("disk_image", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-disk-image.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-disk-image.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["partition_start_sector"], 2048)
            self.assertEqual(metadata["recovery_mode"], "partition-offset")
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)

    def test_run_triage_accepts_archive_image_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "install.iso"
            output_dir = root / "run-out"
            image_path.write_bytes(b"iso")

            def fake_extract(source_path: Path, stage_dir: Path) -> ArchiveImageExtractionResult:
                extract_dir = stage_dir / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                return ArchiveImageExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    extract_dir=extract_dir,
                    tool="7z",
                    command=("7z", "x", "-y", f"-o{extract_dir}", str(source_path)),
                )

            with patch("rapidtriage.core.run.extract_archive_image_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(image_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "archive-image")
            self.assertEqual(Path(payload["source"]["source_path"]), image_path.resolve())
            self.assertEqual(Path(payload["root"]), (output_dir / "_archive_image" / "filesystem").resolve())
            self.assertIn("archive_image", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-archive-image.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-archive-image.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["tool"], "7z")
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)

    def test_run_triage_accepts_virtual_disk_and_analyzes_extracted_filesystem(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            image_path = root / "vm.vmdk"
            output_dir = root / "run-out"
            image_path.write_bytes(b"vmdk")

            def fake_extract(source_path: Path, stage_dir: Path) -> VirtualDiskExtractionResult:
                raw_stage = stage_dir / "raw-extract"
                extract_dir = raw_stage / "filesystem"
                extract_dir.mkdir(parents=True, exist_ok=True)
                build_run_fixture(extract_dir)
                raw_result = DiskImageExtractionResult(
                    source_path=stage_dir / "converted" / "vm.raw",
                    stage_dir=raw_stage,
                    extract_dir=extract_dir,
                    image_paths=(stage_dir / "converted" / "vm.raw",),
                    partition_start_sector=2048,
                    recovery_mode="partition-offset",
                )
                return VirtualDiskExtractionResult(
                    source_path=source_path,
                    stage_dir=stage_dir,
                    converted_raw_path=stage_dir / "converted" / "vm.raw",
                    raw_result=raw_result,
                    conversion_tool="qemu-img",
                )

            with patch("rapidtriage.core.run.extract_virtual_disk_to_directory", side_effect=fake_extract):
                payload = run_triage_mode(image_path, mode="fraud", output_dir=output_dir)

            self.assertEqual(payload["source"]["type"], "virtual-disk")
            self.assertEqual(Path(payload["source"]["source_path"]), image_path.resolve())
            vm_manifest = payload["source"]["virtual_disk_workflow_manifest"]
            self.assertEqual(vm_manifest["profile_version"], "virtual-disk-integrated-workflow-manifest-v1")
            self.assertEqual(vm_manifest["status_context"], "run-summary")
            self.assertEqual(len(vm_manifest["manifest_sha256"]), 64)
            vm_statuses = {stage["id"]: stage["status"] for stage in vm_manifest["stages"]}
            self.assertEqual(vm_statuses["artifact-analysis"], "complete")
            self.assertEqual(vm_statuses["review-report"], "complete")
            self.assertIn("summary", vm_manifest["run_output_status"])
            self.assertFalse(vm_manifest["commercial_grade_ready"])
            self.assertIn("virtual_disk", payload["outputs"])
            self.assertTrue((output_dir / "rapidtriage-virtual-disk.json").is_file())
            metadata = json.loads((output_dir / "rapidtriage-virtual-disk.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["conversion_tool"], "qemu-img")
            self.assertEqual(
                metadata["virtual_disk_workflow_manifest"]["profile_version"],
                "virtual-disk-integrated-workflow-manifest-v1",
            )
            self.assertGreaterEqual(payload["summary"]["document_match_count"], 1)


if __name__ == "__main__":
    unittest.main()
