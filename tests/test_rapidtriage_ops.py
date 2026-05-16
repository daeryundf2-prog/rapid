from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from pathlib import Path

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app
from rapidtriage.cli import build_parser, main, run_web_server
from rapidtriage.core.backup import backup_restore_core_accuracy_gates, build_backup_restore_trusted_diff
from rapidtriage.core.crash import build_crash_report_trusted_diff, crash_report_core_accuracy_gates, write_crash_report
from rapidtriage.core.commercial_readiness import calculate_readiness_score
from rapidtriage.core.enterprise import (
    build_enterprise_trusted_diff,
    build_security_operations_trusted_diff,
    collaboration_audit_core_accuracy_gates,
    license_activation_core_accuracy_gates,
    malicious_evidence_sandbox_core_accuracy_gates,
    multi_user_case_server_core_accuracy_gates,
    rbac_core_accuracy_gates,
    security_hardening_core_accuracy_gates,
    telemetry_core_accuracy_gates,
)
from rapidtriage.core.benchmark import (
    benchmark_core_accuracy_gates,
    build_benchmark_trusted_diff,
    build_stress_run_trusted_diff,
    stress_core_accuracy_gates,
)
from rapidtriage.core.jobs import (
    RunJobStore,
    RunRequest,
    build_cancellation_retry_trusted_diff,
    build_job_queue_trusted_diff,
    cancellation_retry_assessment,
    job_queue_core_accuracy_gates,
)
from rapidtriage.core.sample_case import run_sample_workflow
from rapidtriage.core.validation import (
    build_external_tool_version_assessment,
    build_external_tool_version_trusted_diff,
    build_fixture_corpus_trusted_diff,
    build_fp_fn_trusted_diff,
    build_independent_validation_report,
    build_independent_validation_trusted_diff,
    build_known_answer_trusted_diff,
    build_known_answer_validation,
    build_parser_false_positive_false_negative_notes,
    build_parser_fixture_corpus,
    build_validation_artifact_manifest,
    build_validation_package_assessment,
    build_validation_package_trusted_diff,
)


def load_build_release_module():
    module_path = Path(__file__).resolve().parent.parent / "scripts" / "build-release.py"
    spec = importlib.util.spec_from_file_location("rapidtriage_build_release_test", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_check_dependencies_module():
    module_path = Path(__file__).resolve().parent.parent / "scripts" / "check-dependencies.py"
    spec = importlib.util.spec_from_file_location("rapidtriage_check_dependencies_test", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RapidTriageOpsTests(unittest.TestCase):
    def test_parser_exposes_benchmark_and_case_catalog(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("benchmark", commands)
        self.assertIn("--file-count", commands["benchmark"].format_help())
        self.assertIn("--resume", commands["benchmark"].format_help())
        self.assertIn("columnar-benchmark", commands)
        self.assertIn("--record-count", commands["columnar-benchmark"].format_help())
        self.assertIn("columnar-convert", commands)
        self.assertIn("--input-jsonl", commands["columnar-convert"].format_help())
        self.assertIn("stress-plan", commands)
        self.assertIn("case-catalog", commands)
        self.assertIn("--add-run", commands["case-catalog"].format_help())
        self.assertIn("validation", commands)
        self.assertIn("--output-dir", commands["validation"].format_help())
        self.assertIn("validation-diff-runners", commands)
        self.assertIn("--output", commands["validation-diff-runners"].format_help())
        self.assertIn("final-qc-report", commands)
        self.assertIn("--reviewer-signoff", commands["final-qc-report"].format_help())
        self.assertIn("--chain-of-custody", commands["final-qc-report"].format_help())
        self.assertIn("--audit-bundle", commands["final-qc-report"].format_help())
        self.assertIn("--exhibit-bundle", commands["final-qc-report"].format_help())
        self.assertIn("commercial-readiness", commands)
        self.assertIn("--strict", commands["commercial-readiness"].format_help())
        self.assertIn("--write-known-answer-template", commands["commercial-readiness"].format_help())
        self.assertIn("--write-known-answer-template-dir", commands["commercial-readiness"].format_help())
        self.assertIn("--uplift-targets", commands["commercial-readiness"].format_help())
        self.assertIn("--uplift-batch-size", commands["commercial-readiness"].format_help())
        self.assertIn("--mac-first-evidence", commands["commercial-readiness"].format_help())
        self.assertIn("forensic-validation-plan", commands)
        self.assertIn("--items", commands["forensic-validation-plan"].format_help())
        self.assertIn("forensic-validation-pack", commands)
        self.assertIn("--output-dir", commands["forensic-validation-pack"].format_help())
        self.assertIn("forensic-validation-pack-assess", commands)
        self.assertIn("--pack", commands["forensic-validation-pack-assess"].format_help())
        self.assertIn("forensic-validation-batches", commands)
        self.assertIn("--items", commands["forensic-validation-batches"].format_help())
        self.assertIn("forensic-validation-batches-assess", commands)
        self.assertIn("--root-dir", commands["forensic-validation-batches-assess"].format_help())
        self.assertIn("--strict-external", commands["forensic-validation-batches-assess"].format_help())
        self.assertIn("forensic-validation-smoke-populate", commands)
        self.assertIn("--root-dir", commands["forensic-validation-smoke-populate"].format_help())
        self.assertIn("forensic-validation-evidence-import", commands)
        self.assertIn("--manifest", commands["forensic-validation-evidence-import"].format_help())
        self.assertIn("cross-tool-validate", commands)
        self.assertIn("--reference-output", commands["cross-tool-validate"].format_help())
        self.assertIn("image-workflow-validate", commands)
        self.assertIn("--item-number", commands["image-workflow-validate"].format_help())
        self.assertIn("confidence-dashboard", commands)
        self.assertIn("parser-explainability", commands)
        self.assertIn("reproducibility-kit", commands)
        self.assertIn("enterprise-policy", commands)
        self.assertIn("case-backup", commands)
        self.assertIn("case-restore", commands)
        self.assertIn("case-acquisition", commands)

    def test_enterprise_policy_is_local_only_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            license_path = Path(tmp_dir) / "license.txt"
            license_path.write_text("offline license", encoding="utf-8")
            stdout = io.StringIO()
            with patch.dict(
                "os.environ",
                {"RAPIDTRIAGE_LICENSE_FILE": str(license_path), "RAPIDTRIAGE_USER_ROLE": "viewer"},
                clear=False,
            ):
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(["enterprise-policy", "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIn("#105", payload["commercial_gap_ids"])
        self.assertIn("#106", payload["telemetry"]["commercial_gap_ids"])
        self.assertEqual(payload["telemetry"]["core_accuracy_gates"][0]["gap_id"], "#106")
        self.assertEqual(payload["telemetry"]["local_only_evidence_manifest"]["profile_version"], "local-only-enterprise-evidence-manifest-v1")
        self.assertEqual(len(payload["telemetry"]["local_only_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["telemetry"]["local_only_evidence_manifest"]["control_evidence_matrix"]["profile_version"],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertEqual(len(payload["telemetry"]["control_evidence_matrix_hash"]), 64)
        self.assertEqual(
            payload["telemetry"]["control_evidence_matrix_hash"],
            payload["telemetry"]["local_only_evidence_manifest"]["control_evidence_matrix_hash"],
        )
        self.assertIn("network_egress_smoke", payload["telemetry"]["local_only_evidence_slots"])
        self.assertIn("local-only evidence manifest hash emitted", payload["telemetry"]["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn(
            "local-only control evidence matrix hash emitted",
            payload["telemetry"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        local_deployment_manifest = payload["telemetry"]["local_only_deployment_manifest"]
        self.assertEqual(local_deployment_manifest["profile_version"], "local-only-deployment-manifest-v1")
        self.assertEqual(local_deployment_manifest["item_number"], 61)
        self.assertEqual(len(local_deployment_manifest["manifest_hash"]), 64)
        self.assertEqual(
            payload["telemetry"]["local_only_deployment_manifest_hash"],
            local_deployment_manifest["manifest_hash"],
        )
        self.assertEqual(local_deployment_manifest["enabled_upload_surface_count"], 0)
        self.assertEqual(local_deployment_manifest["known_outbound_endpoint_count"], 0)
        self.assertEqual(local_deployment_manifest["network_boundary"]["default_bind"], "127.0.0.1")
        self.assertTrue(local_deployment_manifest["network_boundary"]["remote_requires_auth_token"])
        self.assertIn("telemetry", {surface["surface"] for surface in local_deployment_manifest["upload_surfaces"]})
        self.assertIn(
            "local-only deployment manifest hash emitted",
            payload["telemetry"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "local-only upload surface inventory emitted",
            payload["telemetry"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "local-only report-grade validation plan",
            payload["telemetry"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "local-only report-grade ready slots",
            payload["telemetry"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertEqual(payload["telemetry"]["functional_priority_profile"]["item_number"], 61)
        self.assertEqual(payload["telemetry"]["functional_priority_profile"]["batch_id"], "commercial-uplift-061-065")
        self.assertTrue(payload["telemetry"]["functional_priority_profile"]["implemented_controls"]["telemetry_disabled"])
        self.assertTrue(
            payload["telemetry"]["functional_priority_profile"]["implemented_controls"][
                "upload_surface_inventory_emitted"
            ]
        )
        self.assertEqual(
            payload["telemetry"]["functional_priority_profile"]["implemented_controls"][
                "local_only_deployment_manifest_hash"
            ],
            local_deployment_manifest["manifest_hash"],
        )
        self.assertIn(
            "local-only-deployment-manifest-emitted",
            payload["telemetry"]["functional_priority_profile"]["passed_validation_check_ids"],
        )
        local_only_plan = payload["telemetry"]["local_only_report_grade_validation_plan"]
        self.assertEqual(
            local_only_plan["profile_version"],
            "local-only-enterprise-report-grade-validation-plan-v1",
        )
        self.assertEqual(len(payload["telemetry"]["local_only_report_grade_validation_plan_hash"]), 64)
        self.assertEqual(
            payload["telemetry"]["local_only_report_grade_validation_plan_hash"],
            local_only_plan["validation_plan_hash"],
        )
        self.assertGreaterEqual(payload["telemetry"]["local_only_report_grade_ready_slot_count"], 7)
        self.assertGreaterEqual(payload["telemetry"]["local_only_report_grade_blocking_slot_count"], 6)
        self.assertIn("network-egress-smoke-required", payload["telemetry"]["blockers"])
        self.assertIn(
            "local-only-report-grade-validation-plan-emitted",
            payload["telemetry"]["functional_priority_profile"]["passed_validation_check_ids"],
        )
        self.assertIn(
            "network-egress-test-not-attached",
            payload["telemetry"]["functional_priority_profile"]["failed_validation_check_ids"],
        )
        self.assertFalse(payload["telemetry"]["enabled"])
        self.assertEqual(payload["telemetry"]["trusted_local_only_diff"]["status"], "missing")
        self.assertIn("trusted-local-only-deployment-policy-diff-missing", payload["telemetry"]["blockers"])
        local_diff = build_enterprise_trusted_diff(
            106,
            payload["telemetry"],
            payload["telemetry"],
            trusted_tool="local-only-deployment-policy",
        )
        local_gates = telemetry_core_accuracy_gates(trusted_diff=local_diff)
        self.assertEqual(local_diff["status"], "pass")
        self.assertIn("control_evidence_matrix_hash", local_diff["compared_fields"])
        self.assertIn("local_only_report_grade_validation_plan_hash", local_diff["compared_fields"])
        self.assertIn("trusted local-only deployment policy diff pass", local_gates[0]["satisfied_checks"])
        self.assertIn("#107", payload["license_activation"]["commercial_gap_ids"])
        self.assertEqual(payload["license_activation"]["core_accuracy_gates"][0]["gap_id"], "#107")
        self.assertEqual(payload["license_activation"]["license_evidence_manifest"]["profile_version"], "license-activation-evidence-manifest-v1")
        self.assertEqual(len(payload["license_activation"]["license_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["license_activation"]["license_evidence_manifest"]["control_evidence_matrix"]["profile_version"],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertEqual(len(payload["license_activation"]["control_evidence_matrix_hash"]), 64)
        self.assertIn("offline_activation_smoke", payload["license_activation"]["license_evidence_slots"])
        self.assertIn("license evidence manifest hash emitted", payload["license_activation"]["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn(
            "license control evidence matrix hash emitted",
            payload["license_activation"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertFalse(payload["license_activation"]["required"])
        self.assertEqual(payload["license_activation"]["status"], "operator-provided-file")
        self.assertEqual(len(payload["license_activation"]["license_sha256"]), 64)
        self.assertFalse(payload["license_activation"]["network_activation"])
        self.assertEqual(payload["license_activation"]["trusted_license_diff"]["status"], "missing")
        self.assertIn("trusted-license-authority-diff-missing", payload["license_activation"]["blockers"])
        license_diff = build_enterprise_trusted_diff(
            107,
            payload["license_activation"],
            payload["license_activation"],
            trusted_tool="license-authority-review",
        )
        license_gates = license_activation_core_accuracy_gates(
            payload["license_activation"],
            trusted_diff=license_diff,
        )
        self.assertEqual(license_diff["status"], "pass")
        self.assertIn("control_evidence_matrix_hash", license_diff["compared_fields"])
        self.assertIn("trusted license authority diff pass", license_gates[0]["satisfied_checks"])
        self.assertIn("#108", payload["rbac"]["commercial_gap_ids"])
        self.assertEqual(payload["rbac"]["core_accuracy_gates"][0]["gap_id"], "#108")
        self.assertEqual(payload["rbac"]["rbac_evidence_manifest"]["profile_version"], "rbac-enforcement-evidence-manifest-v1")
        self.assertEqual(len(payload["rbac"]["rbac_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["rbac"]["rbac_evidence_manifest"]["control_evidence_matrix"]["profile_version"],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertEqual(len(payload["rbac"]["control_evidence_matrix_hash"]), 64)
        self.assertIn("per_action_enforcement_test", payload["rbac"]["rbac_evidence_slots"])
        self.assertIn("rbac evidence manifest hash emitted", payload["rbac"]["core_accuracy_gates"][0]["satisfied_checks"])
        self.assertIn(
            "rbac control evidence matrix hash emitted",
            payload["rbac"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertEqual(payload["rbac"]["active_role"], "viewer")
        self.assertTrue(payload["rbac"]["active_role_supported"])
        self.assertNotIn("backup_restore", payload["rbac"]["active_permissions"])
        self.assertEqual(payload["rbac"]["trusted_rbac_diff"]["status"], "missing")
        self.assertIn("trusted-rbac-enforcement-diff-missing", payload["rbac"]["blockers"])
        rbac_diff = build_enterprise_trusted_diff(
            108,
            payload["rbac"],
            payload["rbac"],
            trusted_tool="rbac-enforcement-test",
        )
        rbac_gates = rbac_core_accuracy_gates(
            payload["rbac"]["active_role"],
            payload["rbac"]["active_permissions"],
            trusted_diff=rbac_diff,
        )
        self.assertEqual(rbac_diff["status"], "pass")
        self.assertIn("control_evidence_matrix_hash", rbac_diff["compared_fields"])
        self.assertIn("trusted RBAC enforcement diff pass", rbac_gates[0]["satisfied_checks"])
        self.assertIn("#109", payload["multi_user_case_server"]["commercial_gap_ids"])
        self.assertEqual(payload["multi_user_case_server"]["core_accuracy_gates"][0]["gap_id"], "#109")
        self.assertEqual(
            payload["multi_user_case_server"]["multi_user_evidence_manifest"]["profile_version"],
            "multi-user-server-evidence-manifest-v1",
        )
        self.assertEqual(len(payload["multi_user_case_server"]["multi_user_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["multi_user_case_server"]["multi_user_evidence_manifest"]["control_evidence_matrix"][
                "profile_version"
            ],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertEqual(len(payload["multi_user_case_server"]["control_evidence_matrix_hash"]), 64)
        self.assertIn("locking_conflict_test", payload["multi_user_case_server"]["multi_user_evidence_slots"])
        self.assertIn(
            "multi-user evidence manifest hash emitted",
            payload["multi_user_case_server"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "multi-user control evidence matrix hash emitted",
            payload["multi_user_case_server"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertTrue(payload["multi_user_case_server"]["required_before_enablement"])
        self.assertEqual(payload["multi_user_case_server"]["trusted_multi_user_diff"]["status"], "missing")
        self.assertIn("trusted-multi-user-server-review-diff-missing", payload["multi_user_case_server"]["blockers"])
        multi_user_diff = build_enterprise_trusted_diff(
            109,
            payload["multi_user_case_server"],
            payload["multi_user_case_server"],
            trusted_tool="multi-user-server-security-review",
        )
        multi_user_gates = multi_user_case_server_core_accuracy_gates(trusted_diff=multi_user_diff)
        self.assertEqual(multi_user_diff["status"], "pass")
        self.assertIn("control_evidence_matrix_hash", multi_user_diff["compared_fields"])
        self.assertIn("trusted multi-user server review diff pass", multi_user_gates[0]["satisfied_checks"])
        self.assertIn("#110", payload["collaboration_audit_trail"]["commercial_gap_ids"])
        self.assertEqual(payload["collaboration_audit_trail"]["core_accuracy_gates"][0]["gap_id"], "#110")
        self.assertEqual(
            payload["collaboration_audit_trail"]["collaboration_audit_evidence_manifest"]["profile_version"],
            "collaboration-audit-evidence-manifest-v1",
        )
        self.assertEqual(len(payload["collaboration_audit_trail"]["collaboration_audit_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["collaboration_audit_trail"]["collaboration_audit_evidence_manifest"]["control_evidence_matrix"][
                "profile_version"
            ],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertEqual(len(payload["collaboration_audit_trail"]["control_evidence_matrix_hash"]), 64)
        self.assertIn("audit_append_only_review", payload["collaboration_audit_trail"]["collaboration_audit_evidence_slots"])
        self.assertIn(
            "collaboration audit evidence manifest hash emitted",
            payload["collaboration_audit_trail"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "collaboration audit control evidence matrix hash emitted",
            payload["collaboration_audit_trail"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertEqual(payload["collaboration_audit_trail"]["status"], "case-db-audit-events-with-export-hash-chain")
        self.assertEqual(payload["multi_user_case_server"]["status"], "not-enabled")
        self.assertEqual(payload["collaboration_audit_trail"]["trusted_collaboration_audit_diff"]["status"], "missing")
        self.assertIn("trusted-collaboration-audit-diff-missing", payload["collaboration_audit_trail"]["blockers"])
        collaboration_diff = build_enterprise_trusted_diff(
            110,
            payload["collaboration_audit_trail"],
            payload["collaboration_audit_trail"],
            trusted_tool="collaboration-audit-review",
        )
        collaboration_gates = collaboration_audit_core_accuracy_gates(trusted_diff=collaboration_diff)
        self.assertEqual(collaboration_diff["status"], "pass")
        self.assertIn("control_evidence_matrix_hash", collaboration_diff["compared_fields"])
        self.assertIn("trusted collaboration audit diff pass", collaboration_gates[0]["satisfied_checks"])
        self.assertIn("#118", payload["security_hardening"]["commercial_gap_ids"])
        self.assertIn("#119", payload["security_hardening"]["commercial_gap_ids"])
        self.assertEqual(payload["security_hardening"]["core_accuracy_gates"][0]["gap_id"], "#118")
        self.assertEqual(payload["security_hardening"]["core_accuracy_gates"][1]["gap_id"], "#119")
        self.assertEqual(
            payload["security_hardening"]["security_hardening_evidence_manifest"]["profile_version"],
            "security-hardening-evidence-manifest-v1",
        )
        self.assertEqual(len(payload["security_hardening"]["security_hardening_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["security_hardening"]["security_hardening_evidence_manifest"]["control_evidence_matrix"][
                "profile_version"
            ],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertEqual(len(payload["security_hardening"]["control_evidence_matrix_hash"]), 64)
        baseline_manifest = payload["security_hardening"]["security_hardening_baseline_manifest"]
        self.assertEqual(baseline_manifest["profile_version"], "security-hardening-baseline-manifest-v1")
        self.assertEqual(baseline_manifest["item_number"], 63)
        self.assertEqual(len(baseline_manifest["manifest_hash"]), 64)
        self.assertEqual(
            payload["security_hardening"]["security_hardening_baseline_manifest_hash"],
            baseline_manifest["manifest_hash"],
        )
        self.assertGreaterEqual(baseline_manifest["control_count"], 7)
        self.assertIn("path_traversal_guardrails", {control["control"] for control in baseline_manifest["controls"]})
        self.assertIn("independent_appsec_review", payload["security_hardening"]["security_hardening_evidence_slots"])
        self.assertIn(
            "security hardening evidence manifest hash emitted",
            payload["security_hardening"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "security hardening baseline manifest hash emitted",
            payload["security_hardening"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "security hardening control evidence matrix hash emitted",
            payload["security_hardening"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertEqual(
            payload["security_hardening"]["malicious_sandbox_evidence_manifest"]["profile_version"],
            "malicious-evidence-sandbox-evidence-manifest-v1",
        )
        self.assertEqual(len(payload["security_hardening"]["malicious_sandbox_evidence_manifest_hash"]), 64)
        self.assertEqual(
            payload["security_hardening"]["malicious_sandbox_evidence_manifest"]["control_evidence_matrix"][
                "profile_version"
            ],
            "enterprise-control-evidence-matrix-v1",
        )
        self.assertIn("malicious_corpus_validation", payload["security_hardening"]["malicious_sandbox_evidence_slots"])
        self.assertIn(
            "malicious sandbox evidence manifest hash emitted",
            payload["security_hardening"]["core_accuracy_gates"][1]["satisfied_checks"],
        )
        self.assertIn(
            "malicious sandbox control evidence matrix hash emitted",
            payload["security_hardening"]["core_accuracy_gates"][1]["satisfied_checks"],
        )
        self.assertEqual(payload["security_hardening"]["functional_priority_profile"]["item_number"], 63)
        self.assertTrue(
            payload["security_hardening"]["functional_priority_profile"]["implemented_controls"][
                "security_hardening_baseline_manifest_emitted"
            ]
        )
        self.assertIn(
            "security-hardening-baseline-manifest-emitted",
            payload["security_hardening"]["functional_priority_profile"]["passed_validation_check_ids"],
        )
        self.assertFalse(
            payload["security_hardening"]["functional_priority_profile"]["implemented_controls"]["os_level_parser_sandbox"]
        )
        self.assertIn(
            "independent-appsec-review-not-attached",
            payload["security_hardening"]["functional_priority_profile"]["failed_validation_check_ids"],
        )
        self.assertEqual(payload["security_hardening"]["trusted_security_hardening_diff"]["status"], "missing")
        self.assertEqual(payload["security_hardening"]["trusted_malicious_sandbox_diff"]["status"], "missing")
        self.assertIn("trusted-security-hardening-review-diff-missing", payload["security_hardening"]["blockers"])
        self.assertIn("trusted-malicious-evidence-sandbox-diff-missing", payload["security_hardening"]["blockers"])
        hardening_diff = build_security_operations_trusted_diff(
            118,
            payload["security_hardening"],
            payload["security_hardening"],
            trusted_tool="independent-appsec-review",
        )
        sandbox_diff = build_security_operations_trusted_diff(
            119,
            payload["security_hardening"],
            payload["security_hardening"],
            trusted_tool="malicious-evidence-sandbox-corpus",
        )
        hardening_gate = security_hardening_core_accuracy_gates(trusted_diff=hardening_diff)
        sandbox_gate = malicious_evidence_sandbox_core_accuracy_gates(trusted_diff=sandbox_diff)
        self.assertEqual(hardening_diff["status"], "pass")
        self.assertEqual(sandbox_diff["status"], "pass")
        self.assertIn("control_evidence_matrix_hash", hardening_diff["compared_fields"])
        self.assertIn("control_evidence_matrix_hash", sandbox_diff["compared_fields"])
        self.assertIn("trusted independent AppSec review diff pass", hardening_gate[0]["satisfied_checks"])
        self.assertIn("trusted malicious evidence sandbox corpus diff pass", sandbox_gate[0]["satisfied_checks"])

    def test_benchmark_command_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "bench"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(output_dir),
                        "--file-count",
                        "12",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "benchmark")
            self.assertTrue((output_dir / "rapidtriage-benchmark.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-benchmark.md").is_file())
            self.assertGreaterEqual(payload["metrics"]["ingest_seconds"], 0)
            self.assertIn("search_p50_seconds", payload["metrics"])
            self.assertEqual(len(payload["metrics"]["search_latency_samples_seconds"]), 1)
            self.assertEqual(payload["environment"]["profile_version"], "benchmark-environment-profile-v1")
            self.assertIn("python_version", payload["environment"])
            self.assertEqual(
                payload["release_threshold_profile"]["profile_version"],
                "benchmark-release-threshold-profile-v1",
            )
            self.assertEqual(payload["benchmark_command_manifest"]["profile_version"], "benchmark-command-manifest-v1")
            self.assertEqual(payload["benchmark_command_manifest"]["item_number"], 34)
            self.assertEqual(payload["benchmark_command_manifest"]["gap_id"], "#34")
            self.assertEqual(len(payload["benchmark_command_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["benchmark_command_manifest_hash"],
                payload["benchmark_command_manifest"]["manifest_hash"],
            )
            self.assertIn(payload["release_threshold_profile"]["status"], {"pass", "needs-review"})
            self.assertEqual(len(payload["release_threshold_profile"]["checks"]), 3)
            self.assertFalse(payload["release_threshold_profile"]["trusted_threshold_manifest_attached"])
            self.assertEqual(
                payload["release_threshold_profile"]["trusted_diff_blocker"],
                "trusted-benchmark-hardware-threshold-diff-missing",
            )
            self.assertIn("#66", payload["summary"]["commercial_gap_ids"])
            self.assertIn("#66", payload["benchmark_report_grade_assessment"]["commercial_gap_ids"])
            self.assertEqual(payload["core_accuracy_gates"][0]["gap_id"], "#66")
            self.assertIn("ingest/search metrics captured", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("release threshold profile emitted", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("benchmark command manifest hash emitted", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("benchmark scale proof manifest emitted", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(payload["functional_priority_profile"]["item_number"], 34)
            self.assertEqual(payload["functional_priority_profile"]["batch_id"], "commercial-uplift-031-035")
            self.assertTrue(payload["functional_priority_profile"]["controls"]["synthetic_or_existing_root_supported"])
            self.assertEqual(
                payload["functional_priority_profile"]["controls"]["benchmark_manifest_hash"],
                payload["benchmark_command_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["functional_priority_profile"]["controls"]["benchmark_scale_proof_manifest_hash"],
                payload["benchmark_scale_proof_manifest"]["manifest_hash"],
            )
            self.assertEqual(payload["functional_priority_profile"]["controls"]["covered_target_count"], 0)
            self.assertFalse(payload["functional_priority_profile"]["controls"]["all_scale_targets_covered"])
            self.assertIn(
                payload["functional_priority_profile"]["controls"]["release_threshold_status"],
                {"pass", "needs-review"},
            )
            self.assertIn(
                "published-100k-1m-10m-hardware-and-os-matrix-required",
                payload["functional_priority_profile"]["blockers"],
            )
            self.assertFalse(payload["benchmark_native_capabilities"]["continuous_10m_record_gate"])
            self.assertEqual([row["label"] for row in payload["benchmark_scale_matrix"]], ["100k", "1M", "10M"])
            self.assertEqual(payload["benchmark_scale_proof_manifest"]["profile_version"], "benchmark-scale-proof-manifest-v1")
            self.assertEqual(payload["benchmark_scale_proof_manifest"]["item_number"], 66)
            self.assertEqual(payload["benchmark_scale_proof_manifest"]["executed_record_count"], 12)
            self.assertEqual(payload["benchmark_scale_proof_manifest"]["covered_target_count"], 0)
            self.assertFalse(payload["benchmark_scale_proof_manifest"]["all_scale_targets_covered"])
            self.assertEqual(len(payload["benchmark_scale_proof_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["benchmark_scale_proof_manifest_hash"],
                payload["benchmark_scale_proof_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["benchmark_scale_proof_manifest"]["evidence_paths"]["run_summary"],
                payload["outputs"]["run_summary"],
            )
            validation_plan = payload["benchmark_report_grade_validation_plan"]
            self.assertEqual(
                validation_plan["profile_version"],
                "benchmark-scale-report-grade-validation-plan-v1",
            )
            self.assertEqual(validation_plan["item_number"], 66)
            self.assertEqual(validation_plan["scale_proof_manifest_hash"], payload["benchmark_scale_proof_manifest_hash"])
            self.assertEqual(payload["benchmark_report_grade_validation_plan_hash"], validation_plan["validation_plan_hash"])
            self.assertEqual(payload["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["report_grade_blocking_slot_count"], 6)
            self.assertIn("benchmark-scale-target-matrix", {slot["id"] for slot in validation_plan["ready_slots"]})
            self.assertIn(
                "benchmark-10m-representative-hardware-run",
                {slot["id"] for slot in validation_plan["blocking_slots"]},
            )
            self.assertIn("10m-representative-hardware-run-required", validation_plan["blockers"])
            self.assertIn(
                "benchmark report-grade validation plan emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "benchmark report-grade ready slots emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            uplift = payload["commercial_uplift_evidence"]
            self.assertEqual(uplift["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(uplift["item_numbers"], [66])
            self.assertTrue(uplift["implemented"])
            self.assertTrue(uplift["usable"])
            self.assertTrue(uplift["validated"])
            self.assertFalse(uplift["commercial_grade_ready"])
            self.assertIn("p50/p95 search latency", " ".join(uplift["large_data_controls"]))
            self.assertIn("report-grade validation plan", " ".join(uplift["large_data_controls"]))
            self.assertIn("published 100k/1M/10M hardware and OS benchmark matrix", uplift["remaining_external_validation"])
            self.assertIn("independent reproduction log for each target scale", uplift["remaining_external_validation"])
            self.assertIn("trusted-benchmark-hardware-threshold-diff-missing", uplift["remaining_external_validation"])
            self.assertEqual(
                uplift["reportability_decision"]["decision"],
                "do-not-report-benchmark-as-published-scale-proof",
            )
            self.assertEqual(
                payload["functional_priority_profile"]["controls"]["benchmark_report_grade_validation_plan_hash"],
                validation_plan["validation_plan_hash"],
            )
            self.assertEqual(payload["functional_priority_profile"]["controls"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["functional_priority_profile"]["controls"]["report_grade_blocking_slot_count"], 6)
            self.assertEqual(
                payload["benchmark_report_grade_assessment"]["benchmark_report_grade_validation_plan_hash"],
                validation_plan["validation_plan_hash"],
            )
            trusted_diff = build_benchmark_trusted_diff(payload["metrics"], payload["metrics"])
            trusted_gates = benchmark_core_accuracy_gates(
                file_count=payload["options"]["file_count"],
                metrics={
                    **payload["metrics"],
                    "benchmark_scale_proof_manifest_hash": payload["benchmark_scale_proof_manifest_hash"],
                },
                run_summary_path=Path(payload["outputs"]["run_summary"]),
                validation_plan=validation_plan,
                trusted_diff=trusted_diff,
            )
            self.assertEqual(trusted_diff["status"], "pass")
            self.assertIn("benchmark scale proof manifest emitted", trusted_gates[0]["satisfied_checks"])
            self.assertIn("benchmark report-grade validation plan emitted", trusted_gates[0]["satisfied_checks"])
            self.assertIn("trusted benchmark threshold diff pass", trusted_gates[0]["satisfied_checks"])

    def test_stress_plan_command_writes_large_case_runbook(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "stress"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "stress-plan",
                        "--output-dir",
                        str(output_dir),
                        "--size-tb",
                        "1",
                        "--size-tb",
                        "10",
                        "--expected-throughput-mb-s",
                        "100",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "stress-plan")
            self.assertEqual(payload["summary"]["scenario_count"], 2)
            self.assertTrue(payload["summary"]["requires_real_validation"])
            self.assertTrue((output_dir / "rapidtriage-stress-plan.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-stress-plan.md").is_file())
            self.assertEqual(payload["scenarios"][1]["size_tb"], 10)
            self.assertIn("parser_crash_rate_percent", payload["failure_thresholds"])
            self.assertIn("#67", payload["summary"]["commercial_gap_ids"])
            self.assertIn("#67", payload["stress_test_assessment"]["commercial_gap_ids"])
            self.assertEqual(payload["core_accuracy_gates"][0]["gap_id"], "#67")
            self.assertIn("TB-scale scenarios emitted", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("hardware-scale evidence manifest hash emitted", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("stress execution proof manifest emitted", payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(
                payload["hardware_scale_evidence_manifest"]["profile_version"],
                "hardware-scale-evidence-manifest-v1",
            )
            self.assertEqual(payload["hardware_scale_evidence_manifest"]["item_number"], 35)
            self.assertEqual(payload["hardware_scale_evidence_manifest"]["gap_id"], "#35")
            self.assertEqual(payload["hardware_scale_evidence_manifest"]["largest_size_tb"], 10)
            self.assertEqual(len(payload["hardware_scale_evidence_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["hardware_scale_evidence_manifest_hash"],
                payload["hardware_scale_evidence_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["stress_execution_proof_manifest"]["profile_version"],
                "stress-execution-proof-manifest-v1",
            )
            self.assertEqual(payload["stress_execution_proof_manifest"]["item_number"], 67)
            self.assertEqual(payload["stress_execution_proof_manifest"]["scenario_count"], 2)
            self.assertEqual(payload["stress_execution_proof_manifest"]["largest_size_tb"], 10)
            self.assertEqual(len(payload["stress_execution_proof_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["stress_execution_proof_manifest_hash"],
                payload["stress_execution_proof_manifest"]["manifest_hash"],
            )
            self.assertFalse(payload["stress_execution_proof_manifest"]["actual_hardware_run_attached"])
            self.assertEqual(payload["stress_execution_proof_manifest"]["run_log_rows"][0]["execution_status"], "real-run-not-attached")
            stress_plan = payload["stress_report_grade_validation_plan"]
            self.assertEqual(stress_plan["profile_version"], "stress-test-report-grade-validation-plan-v1")
            self.assertEqual(stress_plan["item_number"], 67)
            self.assertEqual(stress_plan["stress_execution_proof_manifest_hash"], payload["stress_execution_proof_manifest_hash"])
            self.assertEqual(payload["stress_report_grade_validation_plan_hash"], stress_plan["validation_plan_hash"])
            self.assertEqual(payload["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["report_grade_blocking_slot_count"], 6)
            self.assertIn("stress-tb-scale-scenarios", {slot["id"] for slot in stress_plan["ready_slots"]})
            self.assertIn("stress-10tb-hardware-run", {slot["id"] for slot in stress_plan["blocking_slots"]})
            self.assertIn("actual-10tb-hardware-run-required", stress_plan["blockers"])
            self.assertIn(
                "stress report-grade validation plan emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "stress report-grade ready slots emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(payload["functional_priority_profile"]["item_number"], 35)
            self.assertEqual(payload["functional_priority_profile"]["batch_id"], "commercial-uplift-031-035")
            self.assertEqual(payload["functional_priority_profile"]["controls"]["largest_size_tb"], 10)
            self.assertEqual(
                payload["functional_priority_profile"]["controls"]["hardware_scale_manifest_hash"],
                payload["hardware_scale_evidence_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["functional_priority_profile"]["controls"]["stress_execution_proof_manifest_hash"],
                payload["stress_execution_proof_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["functional_priority_profile"]["controls"]["stress_report_grade_validation_plan_hash"],
                stress_plan["validation_plan_hash"],
            )
            self.assertEqual(payload["functional_priority_profile"]["controls"]["stress_run_log_row_count"], 2)
            self.assertEqual(payload["functional_priority_profile"]["controls"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["functional_priority_profile"]["controls"]["report_grade_blocking_slot_count"], 6)
            self.assertFalse(payload["functional_priority_profile"]["controls"]["actual_hardware_run_attached"])
            self.assertEqual(
                payload["stress_test_assessment"]["stress_report_grade_validation_plan_hash"],
                stress_plan["validation_plan_hash"],
            )
            self.assertEqual(
                payload["evidence_capture_profile"]["profile_version"],
                "stress-evidence-capture-profile-v1",
            )
            self.assertEqual(payload["evidence_capture_profile"]["scenario_count"], 2)
            self.assertIn("rapidtriage-run-summary.json", payload["evidence_capture_profile"]["required_artifacts"])
            self.assertIn("rss_bytes", payload["evidence_capture_profile"]["telemetry_fields"])
            self.assertEqual(
                payload["evidence_capture_profile"]["trusted_diff_blocker"],
                "trusted-stress-run-log-diff-missing",
            )
            self.assertFalse(payload["evidence_capture_profile"]["trusted_run_log_manifest_attached"])
            self.assertIn("#67", payload["scenarios"][0]["commercial_gap_ids"])
            self.assertEqual(payload["scenarios"][0]["run_log_template"]["profile_version"], "stress-run-log-template-v1")
            self.assertIn("peak_memory_bytes", payload["scenarios"][0]["run_log_template"]["required_fields"])
            self.assertIn("checkpoint-manifest.json", payload["scenarios"][0]["run_log_template"]["required_artifacts"])
            self.assertFalse(payload["stress_native_capabilities"]["actual_1tb_10tb_execution"])
            uplift = payload["commercial_uplift_evidence"]
            self.assertEqual(uplift["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(uplift["item_numbers"], [67])
            self.assertIn("1TB/5TB/10TB runbook scenarios", " ".join(uplift["large_data_controls"]))
            self.assertIn("report-grade validation plan", " ".join(uplift["large_data_controls"]))
            self.assertIn("actual 1TB-10TB hardware stress runs", uplift["remaining_external_validation"])
            self.assertIn("trusted run-log manifest for each TB scenario", uplift["remaining_external_validation"])
            self.assertIn("trusted-stress-run-log-diff-missing", uplift["remaining_external_validation"])
            self.assertEqual(
                uplift["reportability_decision"]["allowed_use"],
                "stress-runbook-triage-pivot",
            )
            scenario_uplift = payload["scenarios"][0]["commercial_uplift_evidence"]
            self.assertEqual(scenario_uplift["item_numbers"], [67])
            stress_diff = build_stress_run_trusted_diff(payload["scenarios"], payload["scenarios"])
            stress_gates = stress_core_accuracy_gates(
                scenarios=payload["scenarios"],
                validation_plan=stress_plan,
                trusted_diff=stress_diff,
            )
            self.assertEqual(stress_diff["status"], "pass")
            self.assertIn("stress report-grade validation plan emitted", stress_gates[0]["satisfied_checks"])
            self.assertIn("trusted stress run-log diff pass", stress_gates[0]["satisfied_checks"])
            self.assertIn("run-log template emitted", stress_gates[0]["satisfied_checks"])

    def test_validation_command_writes_release_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "validation"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "validation",
                        "--output-dir",
                        str(output_dir),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "validation")
            self.assertEqual(payload["score_target"], 100)
            self.assertTrue((output_dir / "rapidtriage-validation-package.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-validation-report.md").is_file())
            self.assertTrue((output_dir / "rapidtriage-validation-artifacts.json").is_file())
            self.assertIn("#85", payload["validation_package_assessment"]["commercial_gap_ids"])
            self.assertEqual(payload["validation_package_assessment"]["core_accuracy_gates"][0]["gap_id"], "#85")
            assessment_presence = payload["validation_package_assessment"]["validation_package_manifest"][
                "required_output_presence"
            ]
            self.assertTrue(all(assessment_presence.values()))
            artifact_manifest = json.loads(
                (output_dir / "rapidtriage-validation-artifacts.json").read_text(encoding="utf-8")
            )
            artifact_presence = artifact_manifest["validation_package_manifest"]["required_output_presence"]
            self.assertTrue(all(artifact_presence.values()))
            self.assertEqual(artifact_manifest["artifact_count"], 2)
            self.assertEqual(payload["validation_package_assessment"]["trusted_validation_package_diff"]["status"], "missing")
            self.assertIn("trusted-validation-package-manifest-diff-missing", payload["validation_package_assessment"]["blockers"])
            self.assertEqual(
                payload["validation_package_assessment"]["validation_package_report_grade_validation_plan"]["profile_version"],
                "validation-package-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                payload["validation_package_assessment"]["validation_package_report_grade_validation_plan_hash"],
                payload["validation_package_assessment"]["validation_package_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertEqual(payload["validation_package_assessment"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["validation_package_assessment"]["report_grade_blocking_slot_count"], 4)
            self.assertIn("#81", payload["known_answer_validation"]["commercial_gap_ids"])
            self.assertEqual(payload["known_answer_validation"]["functional_priority_profile"]["item_number"], 36)
            self.assertEqual(
                payload["known_answer_validation"]["known_answer_pipeline_manifest"]["profile_version"],
                "known-answer-pipeline-manifest-v1",
            )
            self.assertEqual(payload["known_answer_validation"]["known_answer_pipeline_manifest"]["item_number"], 36)
            self.assertEqual(payload["known_answer_validation"]["known_answer_pipeline_manifest"]["gap_id"], "#36")
            self.assertEqual(len(payload["known_answer_validation"]["known_answer_pipeline_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["known_answer_validation"]["functional_priority_profile"]["implemented_controls"]["pipeline_manifest_hash"],
                payload["known_answer_validation"]["known_answer_pipeline_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["known_answer_validation"]["known_answer_report_grade_validation_plan"]["profile_version"],
                "known-answer-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                payload["known_answer_validation"]["known_answer_report_grade_validation_plan_hash"],
                payload["known_answer_validation"]["known_answer_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertEqual(payload["known_answer_validation"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["known_answer_validation"]["report_grade_blocking_slot_count"], 6)
            self.assertEqual(
                payload["known_answer_validation"]["functional_priority_profile"]["implemented_controls"][
                    "report_grade_validation_plan_hash"
                ],
                payload["known_answer_validation"]["known_answer_report_grade_validation_plan_hash"],
            )
            self.assertIn(
                "known-answer-manifest-not-attached",
                payload["known_answer_validation"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(payload["known_answer_validation"]["core_accuracy_gates"][0]["gap_id"], "#81")
            self.assertIn(
                "known-answer pipeline manifest hash emitted",
                payload["known_answer_validation"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "known-answer report-grade validation plan emitted",
                payload["known_answer_validation"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(payload["known_answer_validation"]["trusted_known_answer_diff"]["status"], "missing")
            self.assertIn("trusted-known-answer-manifest-diff-missing", payload["known_answer_validation"]["blockers"])
            self.assertIn("#82", payload["parser_fixture_corpus"]["commercial_gap_ids"])
            self.assertEqual(payload["parser_fixture_corpus"]["core_accuracy_gates"][0]["gap_id"], "#82")
            self.assertEqual(
                payload["parser_fixture_corpus"]["fixture_corpus_report_grade_validation_plan"]["profile_version"],
                "fixture-corpus-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                payload["parser_fixture_corpus"]["fixture_corpus_report_grade_validation_plan_hash"],
                payload["parser_fixture_corpus"]["fixture_corpus_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertEqual(payload["parser_fixture_corpus"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["parser_fixture_corpus"]["report_grade_blocking_slot_count"], 6)
            self.assertEqual(payload["parser_fixture_corpus"]["trusted_fixture_corpus_diff"]["status"], "missing")
            self.assertIn("trusted-fixture-corpus-manifest-diff-missing", payload["parser_fixture_corpus"]["blockers"])
            self.assertIn("#83", payload["parser_false_positive_false_negative_notes"][0]["commercial_gap_ids"])
            runner_matrix = payload["validation_diff_runner_matrix"]
            self.assertEqual(runner_matrix["profile_version"], "validation-diff-runner-matrix-v1")
            self.assertEqual(runner_matrix["qc_prep_item_numbers"], [76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86])
            self.assertEqual(runner_matrix["summary"]["runner_group_count"], 10)
            self.assertEqual(len(runner_matrix["matrix_hash"]), 64)
            self.assertIn("NIST CFReDS", {row["corpus_name"] for row in runner_matrix["public_corpus_registry"]})
            self.assertIn("EvtxECmd", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("PECmd", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("LECmd", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("Velociraptor", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("AmcacheParser", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("Hindsight", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("qemu-img", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("iLEAPP", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            self.assertIn("apktool/aapt/jadx", {tool["name"] for group in runner_matrix["runner_groups"] for tool in group["trusted_tools"]})
            final_qc = payload["final_qc_execution_report"]
            self.assertEqual(final_qc["profile_version"], "final-qc-execution-report-v1")
            self.assertEqual(final_qc["qc_prep_item_numbers"], [81, 82, 83, 84, 85, 86, 87, 88, 89, 90])
            self.assertEqual(len(final_qc["report_hash"]), 64)
            self.assertEqual(final_qc["legal_submission_qc_contract"]["profile_version"], "legal-submission-qc-contract-v1")
            self.assertIn("validation-package-attached", final_qc["final_qc_checklist"]["failed_check_ids"])
            self.assertEqual(len(payload["parser_false_positive_false_negative_notes"][0]["risk_note_hash"]), 64)
            self.assertEqual(
                payload["parser_false_positive_false_negative_notes"][0]["fp_fn_report_grade_validation_plan"][
                    "profile_version"
                ],
                "parser-fp-fn-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                payload["parser_false_positive_false_negative_notes"][0]["fp_fn_report_grade_validation_plan_hash"],
                payload["parser_false_positive_false_negative_notes"][0]["fp_fn_report_grade_validation_plan"][
                    "validation_plan_hash"
                ],
            )
            self.assertEqual(payload["parser_false_positive_false_negative_notes"][0]["report_grade_ready_slot_count"], 6)
            self.assertEqual(
                payload["parser_false_positive_false_negative_notes"][0]["report_grade_blocking_slot_count"], 6
            )
            self.assertEqual(payload["parser_fp_fn_risk_register_profile"]["profile_version"], "parser-fp-fn-risk-register-v1")
            self.assertEqual(len(payload["parser_fp_fn_risk_register_profile"]["register_digest"]), 64)
            self.assertEqual(
                payload["parser_fp_fn_risk_register_manifest"]["profile_version"],
                "parser-fp-fn-risk-register-manifest-v1",
            )
            self.assertEqual(payload["parser_fp_fn_risk_register_manifest"]["item_number"], 38)
            self.assertEqual(payload["parser_fp_fn_risk_register_manifest"]["gap_id"], "#38")
            self.assertEqual(payload["parser_fp_fn_risk_register_manifest"]["commercial_gap_ids"], ["#83"])
            self.assertEqual(len(payload["parser_fp_fn_risk_register_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["parser_fp_fn_risk_register_profile"]["risk_register_manifest_hash"],
                payload["parser_fp_fn_risk_register_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["parser_fp_fn_risk_register_manifest"]["unquantified_parser_count"],
                payload["parser_fp_fn_risk_register_manifest"]["parser_count"],
            )
            self.assertFalse(payload["parser_fp_fn_risk_register_manifest"]["commercial_claim_allowed"])
            self.assertEqual(
                payload["parser_false_positive_false_negative_notes"][0]["functional_priority_profile"]["item_number"],
                38,
            )
            self.assertIn(
                "trusted-fp-fn-risk-register-diff-missing",
                payload["parser_false_positive_false_negative_notes"][0]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(payload["parser_false_positive_false_negative_notes"][0]["core_accuracy_gates"][0]["gap_id"], "#83")
            self.assertEqual(payload["parser_false_positive_false_negative_notes"][0]["trusted_fp_fn_diff"]["status"], "missing")
            self.assertIn("trusted-fp-fn-risk-register-diff-missing", payload["parser_false_positive_false_negative_notes"][0]["blockers"])
            self.assertIn("#84", payload["independent_validation_report"]["commercial_gap_ids"])
            self.assertEqual(
                payload["independent_validation_report"]["independent_validation_manifest"]["profile_version"],
                "independent-validation-report-manifest-v1",
            )
            self.assertEqual(len(payload["independent_validation_report"]["independent_validation_manifest"]["report_manifest_hash"]), 64)
            self.assertEqual(
                payload["independent_validation_report"]["independent_validation_package_manifest"]["profile_version"],
                "independent-validation-package-manifest-v1",
            )
            self.assertEqual(payload["independent_validation_report"]["independent_validation_package_manifest"]["item_number"], 39)
            self.assertEqual(payload["independent_validation_report"]["independent_validation_package_manifest"]["gap_id"], "#39")
            self.assertEqual(len(payload["independent_validation_report"]["independent_validation_package_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                payload["independent_validation_report"]["independent_validation_package_manifest_hash"],
                payload["independent_validation_report"]["independent_validation_package_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["independent_validation_report"]["independent_validation_report_grade_validation_plan"]["profile_version"],
                "independent-validation-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                payload["independent_validation_report"]["independent_validation_report_grade_validation_plan_hash"],
                payload["independent_validation_report"]["independent_validation_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertEqual(payload["independent_validation_report"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(payload["independent_validation_report"]["report_grade_blocking_slot_count"], 4)
            self.assertEqual(
                payload["independent_validation_report"]["functional_priority_profile"]["implemented_controls"]["package_manifest_hash"],
                payload["independent_validation_report"]["independent_validation_package_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["independent_validation_report"]["functional_priority_profile"]["implemented_controls"]["report_grade_validation_plan_hash"],
                payload["independent_validation_report"]["independent_validation_report_grade_validation_plan_hash"],
            )
            self.assertIn(
                "release-owner",
                payload["independent_validation_report"]["independent_validation_package_manifest"]["missing_signoff_roles"],
            )
            self.assertEqual(payload["independent_validation_report"]["functional_priority_profile"]["item_number"], 39)
            self.assertIn(
                "independent-validation-report-not-attached",
                payload["independent_validation_report"]["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(payload["independent_validation_report"]["core_accuracy_gates"][0]["gap_id"], "#84")
            self.assertEqual(payload["independent_validation_report"]["trusted_independent_validation_diff"]["status"], "missing")
            self.assertIn("trusted-independent-validation-signoff-diff-missing", payload["independent_validation_report"]["blockers"])
            self.assertIn("independent-validation-report-not-attached", payload["independent_validation_report"]["blockers"])
            self.assertIn("#95", payload["external_tool_version_assessment"]["commercial_gap_ids"])
            self.assertEqual(payload["external_tool_version_assessment"]["core_accuracy_gates"][0]["gap_id"], "#95")
            self.assertEqual(payload["external_tool_version_assessment"]["trusted_external_tool_version_diff"]["status"], "missing")
            self.assertIn(
                "trusted-external-tool-version-transcript-diff-missing",
                payload["external_tool_version_assessment"]["blockers"],
            )

            self.assertEqual(
                payload["external_tool_version_assessment"]["external_tool_version_manifest"]["profile_version"],
                "external-tool-version-manifest-v1",
            )
            self.assertEqual(len(payload["external_tool_version_assessment"]["external_tool_version_manifest_hash"]), 64)
            self.assertEqual(
                payload["external_tool_version_assessment"]["external_tool_capture_matrix"]["profile_version"],
                "external-tool-capture-matrix-v1",
            )
            self.assertEqual(len(payload["external_tool_version_assessment"]["external_tool_capture_matrix_hash"]), 64)
            self.assertEqual(
                payload["external_tool_version_assessment"]["external_tool_capture_matrix_hash"],
                payload["external_tool_version_assessment"]["external_tool_version_manifest"]["capture_matrix_hash"],
            )
            self.assertEqual(
                payload["external_tool_version_assessment"]["external_tool_version_report_grade_validation_plan"][
                    "profile_version"
                ],
                "external-tool-version-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                payload["external_tool_version_assessment"]["external_tool_version_report_grade_validation_plan_hash"],
                payload["external_tool_version_assessment"]["external_tool_version_report_grade_validation_plan"][
                    "validation_plan_hash"
                ],
            )
            self.assertGreaterEqual(
                payload["external_tool_version_assessment"]["external_tool_version_report_grade_ready_slot_count"],
                7,
            )
            self.assertGreaterEqual(
                payload["external_tool_version_assessment"]["external_tool_version_report_grade_blocking_slot_count"],
                6,
            )
            self.assertIn(
                "tool-inventory-and-row-hashes",
                {
                    slot["slot_id"]
                    for slot in payload["external_tool_version_assessment"][
                        "external_tool_version_report_grade_validation_plan"
                    ]["ready_slots"]
                },
            )
            self.assertIn(
                "per-run-external-parser-version-capture",
                {
                    slot["slot_id"]
                    for slot in payload["external_tool_version_assessment"][
                        "external_tool_version_report_grade_validation_plan"
                    ]["blocking_slots"]
                },
            )
            self.assertTrue(all(len(item["tool_version_row_hash"]) == 64 for item in payload["external_tool_versions"]))
            self.assertTrue(all(len(item["command_argv_hash"]) == 64 for item in payload["external_tool_versions"]))
            self.assertTrue(all(len(item["capture_state_hash"]) == 64 for item in payload["external_tool_versions"]))
            self.assertTrue(all(item["tool_version_row_manifest"]["profile_version"] == "external-tool-version-row-v1" for item in payload["external_tool_versions"]))
            self.assertTrue(all("#95" in item["commercial_gap_ids"] for item in payload["external_tool_versions"]))
            self.assertTrue(all(item["core_accuracy_gates"][0]["gap_id"] == "#95" for item in payload["external_tool_versions"]))
            tool_diff = build_external_tool_version_trusted_diff(
                payload["external_tool_versions"],
                payload["external_tool_versions"],
            )
            promoted_tools = build_external_tool_version_assessment(trusted_diff=tool_diff)
            self.assertEqual(tool_diff["status"], "pass")
            self.assertIn("tool_version_row_hash", tool_diff["compared_fields"])
            self.assertIn("command_argv_hash", tool_diff["compared_fields"])
            self.assertIn("capture_state_hash", tool_diff["compared_fields"])
            self.assertIn(
                "external tool version manifest hash emitted",
                promoted_tools["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "external tool capture matrix hash emitted",
                promoted_tools["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "external tool version report-grade validation plan",
                promoted_tools["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "trusted external tool transcript diff pass",
                promoted_tools["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("#101", payload["deployment_operations_gap_ids"])
            self.assertIn("#120", payload["deployment_operations_gap_ids"])
            self.assertIn("#101", payload["deployment_operations_assessment"]["commercial_gap_ids"])
            self.assertIn("#120", payload["deployment_operations_assessment"]["commercial_gap_ids"])
            self.assertEqual(
                [gate["gap_id"] for gate in payload["deployment_operations_assessment"]["core_accuracy_gates"]],
                [f"#{number}" for number in range(101, 121)],
            )
            artifact_manifest = json.loads((output_dir / "rapidtriage-validation-artifacts.json").read_text(encoding="utf-8"))
            self.assertIn("#85", artifact_manifest["commercial_gap_ids"])
            self.assertEqual(artifact_manifest["core_accuracy_gates"][0]["gap_id"], "#85")
            self.assertEqual(artifact_manifest["validation_package_manifest"]["profile_version"], "validation-package-manifest-v1")
            self.assertEqual(len(artifact_manifest["validation_package_manifest"]["package_manifest_hash"]), 64)
            self.assertEqual(artifact_manifest["package_manifest_hash"], artifact_manifest["validation_package_manifest"]["package_manifest_hash"])
            self.assertEqual(
                artifact_manifest["validation_package_report_grade_validation_plan"]["profile_version"],
                "validation-package-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                artifact_manifest["validation_package_report_grade_validation_plan_hash"],
                artifact_manifest["validation_package_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertEqual(artifact_manifest["report_grade_ready_slot_count"], 6)
            self.assertEqual(artifact_manifest["report_grade_blocking_slot_count"], 4)
            self.assertGreaterEqual(len(artifact_manifest["validation_package_manifest"]["reproduction_commands"]), 2)
            self.assertEqual(artifact_manifest["trusted_validation_package_diff"]["status"], "missing")
            self.assertIn("trusted-validation-package-manifest-diff-missing", artifact_manifest["blockers"])
            check_ids = {item["id"] for item in payload["checks"]}
            self.assertIn("unit-tests", check_ids)
            self.assertIn("known-limitations", check_ids)
            self.assertIn("windows-code-signing", check_ids)
            self.assertIn("macos-notarization", check_ids)
            release_ids = {item["id"] for item in payload["release_artifact_requirements"]}
            self.assertIn("windows-installer", release_ids)
            self.assertIn("macos-app-or-package", release_ids)
            validation_ids = {item["id"] for item in payload["independent_validation_plan"]}
            self.assertIn("parser-corpus", validation_ids)
            self.assertEqual(payload["support_sla_template"]["status"], "documented-template")
            self.assertEqual(payload["commercial_readiness_gate"]["status"], "commercial-gaps-present")
            self.assertFalse(payload["commercial_readiness_gate"]["commercial_claim_allowed"])
            self.assertGreater(payload["commercial_readiness_gate"]["non_commercial_count"], 0)
            self.assertEqual(payload["support_sla_template"]["document"], "docs/rapidtriage-support-sla.md")
            self.assertEqual(payload["support_sla_template"]["severity_levels"][0]["patch_target"], "emergency hotfix or validated workaround")
            required_docs = {item["path"] for item in payload["required_documents"]}
            self.assertIn("docs/rapidtriage-support-sla.md", required_docs)
            command_names = {item["name"] for item in payload["recommended_commands"]}
            self.assertIn("validation-package", command_names)
            self.assertIn("windows-signature-verify", command_names)
            self.assertIn("windows-smoke-test", command_names)
            self.assertIn("macos-linux-smoke-test", command_names)
            self.assertIn("release-checksums", command_names)
            self.assertIn("verify-release-checksums", command_names)
            self.assertIn("smoke-summary", command_names)
            self.assertIn("release-evidence", command_names)

    def test_validation_diff_runners_command_emits_qc_runner_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "runner-matrix.json"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["validation-diff-runners", "--output", str(output), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["profile_version"], "validation-diff-runner-matrix-v1")
            self.assertEqual(payload["qc_prep_item_numbers"], [76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86])
            self.assertTrue(output.is_file())
            self.assertEqual(len(payload["matrix_hash"]), 64)
            self.assertEqual(payload["summary"]["runner_group_count"], 10)
            self.assertEqual(payload["summary"]["trusted_tool_count"], 40)
            self.assertFalse(payload["summary"]["version_probe_enabled"])
            self.assertEqual(payload["summary"]["version_captured_count"], 0)
            self.assertEqual(payload["output_manifest"]["bytes"], output.stat().st_size)
            groups = {group["item_number"]: group for group in payload["runner_groups"]}
            self.assertIn("evtx", groups[77]["artifact_family"])
            self.assertIn("registry", groups[78]["artifact_family"])
            self.assertIn("ntfs", groups[79]["artifact_family"])
            self.assertIn("ese", groups[80]["artifact_family"])
            self.assertIn("execution-user-activity", groups[81]["artifact_family"])
            self.assertIn("os-account-execution", groups[82]["artifact_family"])
            self.assertIn("browser-ai", groups[84]["artifact_family"])
            self.assertIn("evidence-image-workflow", groups[85]["artifact_family"])
            self.assertIn("mobile-app-export", groups[86]["artifact_family"])
            self.assertIn("iLEAPP", {tool["name"] for tool in groups[86]["trusted_tools"]})
            self.assertIn("apktool/aapt/jadx", {tool["name"] for tool in groups[86]["trusted_tools"]})
            self.assertIn("--tool-version", groups[77]["required_cross_tool_metadata"])
            self.assertEqual(groups[77]["trusted_tools"][0]["version_probe"]["status"], "not-run")

    def test_validation_diff_runners_can_probe_versions_from_extra_search_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tool_dir = Path(tmp_dir)
            evtxecmd = tool_dir / "EvtxECmd"
            evtxecmd.write_text("#!/bin/sh\nprintf 'EvtxECmd 1.2.3\\n'\n", encoding="utf-8")
            evtxecmd.chmod(0o755)
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "validation-diff-runners",
                        "--search-path",
                        str(tool_dir),
                        "--probe-versions",
                        "--version-timeout-seconds",
                        "1",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["summary"]["version_probe_enabled"])
            self.assertGreaterEqual(payload["summary"]["available_tool_count"], 1)
            self.assertGreaterEqual(payload["summary"]["version_captured_count"], 1)
            evtx_group = next(group for group in payload["runner_groups"] if group["artifact_family"] == "evtx")
            evtx_tool = next(tool for tool in evtx_group["trusted_tools"] if tool["name"] == "EvtxECmd")
            self.assertTrue(evtx_tool["available"])
            self.assertEqual(evtx_tool["resolved_path"], str(evtxecmd))
            self.assertEqual(evtx_tool["version_probe"]["status"], "captured")
            self.assertIn("EvtxECmd 1.2.3", evtx_tool["version_probe"]["output_preview"])
            self.assertEqual(len(evtx_tool["version_probe"]["output_sha256"]), 64)

    def test_final_qc_report_command_hashes_attached_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            validation_package = root / "validation.json"
            runner_matrix = root / "runner.json"
            performance = root / "performance.json"
            browser_trace = root / "trace.json"
            custody = root / "custody.json"
            audit = root / "audit.json"
            exhibit = root / "exhibit.zip"
            signoff = root / "signoff.md"
            output = root / "final-qc.json"
            validation_package.write_text('{"status":"pass"}', encoding="utf-8")
            runner_matrix.write_text('{"profile_version":"validation-diff-runner-matrix-v1"}', encoding="utf-8")
            performance.write_text('{"p95":123}', encoding="utf-8")
            browser_trace.write_text('{"trace":"ok"}', encoding="utf-8")
            custody.write_text('{"chain":"ok"}', encoding="utf-8")
            audit.write_text('{"head_hash":"abc"}', encoding="utf-8")
            exhibit.write_bytes(b"exhibit bundle")
            signoff.write_text("# Reviewer signoff\n", encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "final-qc-report",
                        "--validation-package",
                        str(validation_package),
                        "--runner-matrix",
                        str(runner_matrix),
                        "--chain-of-custody",
                        str(custody),
                        "--audit-bundle",
                        str(audit),
                        "--exhibit-bundle",
                        str(exhibit),
                        "--performance-run",
                        str(performance),
                        "--browser-trace",
                        str(browser_trace),
                        "--reviewer-signoff",
                        str(signoff),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["profile_version"], "final-qc-execution-report-v1")
            self.assertEqual(payload["qc_prep_item_numbers"], [81, 82, 83, 84, 85, 86, 87, 88, 89, 90])
            self.assertTrue(output.is_file())
            self.assertEqual(len(payload["report_hash"]), 64)
            self.assertEqual(payload["evidence_inputs"]["validation_package"]["exists"], True)
            self.assertEqual(payload["evidence_inputs"]["chain_of_custody"]["exists"], True)
            self.assertEqual(payload["legal_submission_qc_contract"]["qc_prep_item_numbers"], [86, 87, 88, 89, 90])
            self.assertEqual(len(payload["legal_submission_qc_contract"]["attached_evidence_hashes"]["audit_bundle_sha256"]), 64)
            self.assertEqual(payload["final_qc_checklist"]["failed_check_ids"], [])
            self.assertTrue(payload["final_qc_checklist"]["ready_for_final_qc_review"])

    def test_validation_trusted_diffs_promote_legal_validation_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence = root / "known-answer.json"
            evidence.write_text('{"status":"pass"}', encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "datasets": [
                            {
                                "id": "dataset-1",
                                "name": "Dataset 1",
                                "status": "pass",
                                "backlog_items": [81],
                                "expected": {"required_assertions": ["known-answer fixture status is pass"]},
                                "evidence_paths": [str(evidence)],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            known_answer = build_known_answer_validation(manifest)
            known_diff = build_known_answer_trusted_diff(known_answer, known_answer)
            promoted_known = build_known_answer_validation(manifest, trusted_diff=known_diff)

            self.assertEqual(known_diff["status"], "pass")
            self.assertIn("dataset_hash", known_diff["compared_fields"])
            self.assertEqual(promoted_known["manifest_digest"], known_answer["manifest_digest"])
            self.assertEqual(promoted_known["datasets"][0]["expected_assertion_count"], 1)
            self.assertEqual(promoted_known["datasets"][0]["evidence_hash_count"], 1)
            self.assertEqual(len(promoted_known["datasets"][0]["dataset_hash"]), 64)
            self.assertEqual(
                promoted_known["known_answer_pipeline_manifest"]["profile_version"],
                "known-answer-pipeline-manifest-v1",
            )
            self.assertEqual(promoted_known["known_answer_pipeline_manifest"]["dataset_count"], 1)
            self.assertEqual(promoted_known["known_answer_pipeline_manifest"]["expected_assertion_count"], 1)
            self.assertEqual(promoted_known["known_answer_pipeline_manifest"]["evidence_hash_count"], 1)
            self.assertEqual(promoted_known["known_answer_pipeline_manifest"]["trusted_diff_status"], "pass")
            self.assertEqual(len(promoted_known["known_answer_pipeline_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                promoted_known["known_answer_report_grade_validation_plan"]["profile_version"],
                "known-answer-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                promoted_known["known_answer_report_grade_validation_plan"]["manifest_digest"],
                promoted_known["manifest_digest"],
            )
            self.assertEqual(
                promoted_known["known_answer_report_grade_validation_plan"]["pipeline_manifest_hash"],
                promoted_known["known_answer_pipeline_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                promoted_known["known_answer_report_grade_validation_plan_hash"],
                promoted_known["known_answer_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertEqual(len(promoted_known["known_answer_report_grade_validation_plan_hash"]), 64)
            self.assertEqual(
                promoted_known["functional_priority_profile"]["implemented_controls"]["pipeline_manifest_hash"],
                promoted_known["known_answer_pipeline_manifest"]["manifest_hash"],
            )
            self.assertIn("trusted known-answer manifest diff pass", promoted_known["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("known-answer pipeline manifest hash emitted", promoted_known["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "known-answer report-grade validation plan emitted",
                promoted_known["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("evidence file hashes recorded", promoted_known["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertNotIn("trusted-known-answer-manifest-diff-missing", promoted_known["blockers"])
            self.assertIn("trusted-diff-present-but-commercial-retest-required", promoted_known["blockers"])
            self.assertEqual(promoted_known["functional_priority_profile"]["status"], "complete")

            fixture_corpus = build_parser_fixture_corpus(Path.cwd())
            fixture_diff = build_fixture_corpus_trusted_diff(fixture_corpus, fixture_corpus)
            promoted_fixture = build_parser_fixture_corpus(Path.cwd(), trusted_diff=fixture_diff)
            self.assertEqual(fixture_diff["status"], "pass")
            self.assertIn("area_manifest_hash", fixture_diff["compared_fields"])
            self.assertEqual(len(promoted_fixture["fixture_corpus_digest"]), 64)
            self.assertTrue(all(len(area["area_manifest_hash"]) == 64 for area in promoted_fixture["areas"]))
            self.assertEqual(
                promoted_fixture["fixture_corpus_report_grade_validation_plan"]["profile_version"],
                "fixture-corpus-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                promoted_fixture["fixture_corpus_report_grade_validation_plan"]["fixture_corpus_digest"],
                promoted_fixture["fixture_corpus_digest"],
            )
            self.assertEqual(
                promoted_fixture["fixture_corpus_report_grade_validation_plan_hash"],
                promoted_fixture["fixture_corpus_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertIn("trusted fixture corpus manifest diff pass", promoted_fixture["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("fixture/test file hashes recorded", promoted_fixture["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "fixture corpus report-grade validation plan emitted",
                promoted_fixture["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertNotIn("trusted-fixture-corpus-manifest-diff-missing", promoted_fixture["blockers"])
            self.assertIn("trusted-fixture-diff-present-but-commercial-retest-required", promoted_fixture["blockers"])

            fp_fn_notes = build_parser_false_positive_false_negative_notes()
            fp_fn_diff = build_fp_fn_trusted_diff(fp_fn_notes, fp_fn_notes)
            promoted_fp_fn = build_parser_false_positive_false_negative_notes(trusted_diff=fp_fn_diff)
            self.assertEqual(fp_fn_diff["status"], "pass")
            self.assertIn("risk_note_hash", fp_fn_diff["compared_fields"])
            self.assertEqual(len(promoted_fp_fn[0]["risk_note_hash"]), 64)
            self.assertEqual(len(promoted_fp_fn[0]["minimum_quantification_fields"]), 6)
            self.assertTrue(promoted_fp_fn[0]["quantification_required"])
            self.assertIn("reportability_boundary", promoted_fp_fn[0])
            self.assertEqual(
                promoted_fp_fn[0]["fp_fn_report_grade_validation_plan"]["profile_version"],
                "parser-fp-fn-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                promoted_fp_fn[0]["fp_fn_report_grade_validation_plan"]["risk_note_hash"],
                promoted_fp_fn[0]["risk_note_hash"],
            )
            self.assertEqual(
                promoted_fp_fn[0]["fp_fn_report_grade_validation_plan_hash"],
                promoted_fp_fn[0]["fp_fn_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertIn("trusted FP/FN risk register diff pass", promoted_fp_fn[0]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("risk note hash emitted", promoted_fp_fn[0]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "FP/FN report-grade validation plan emitted",
                promoted_fp_fn[0]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertNotIn("trusted-fp-fn-risk-register-diff-missing", promoted_fp_fn[0]["blockers"])
            self.assertIn("trusted-fp-fn-diff-present-but-commercial-retest-required", promoted_fp_fn[0]["blockers"])
            self.assertEqual(promoted_fp_fn[0]["functional_priority_profile"]["status"], "complete")

            report = root / "independent-report.md"
            report.write_text(
                "\n".join(
                    [
                        "# Independent Validation Report",
                        "scope and datasets",
                        "tool version and commit",
                        "known-answer pass/fail table",
                        "false positive/false negative notes",
                        "legal/report wording review",
                    ]
                ),
                encoding="utf-8",
            )
            independent_report = build_independent_validation_report(report)
            independent_diff = build_independent_validation_trusted_diff(independent_report, independent_report)
            promoted_independent = build_independent_validation_report(report, trusted_diff=independent_diff)
            self.assertEqual(independent_diff["status"], "pass")
            self.assertIn("report_manifest_hash", independent_diff["compared_fields"])
            self.assertEqual(len(promoted_independent["independent_validation_manifest"]["report_manifest_hash"]), 64)
            self.assertEqual(len(promoted_independent["independent_validation_package_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                promoted_independent["functional_priority_profile"]["implemented_controls"]["package_manifest_hash"],
                promoted_independent["independent_validation_package_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                promoted_independent["independent_validation_report_grade_validation_plan"]["profile_version"],
                "independent-validation-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                promoted_independent["functional_priority_profile"]["implemented_controls"]["report_grade_validation_plan_hash"],
                promoted_independent["independent_validation_report_grade_validation_plan_hash"],
            )
            self.assertEqual(promoted_independent["report_grade_ready_slot_count"], 6)
            self.assertEqual(promoted_independent["report_grade_blocking_slot_count"], 0)
            self.assertTrue(promoted_independent["independent_validation_package_manifest"]["minimum_sections_complete"])
            self.assertEqual(
                promoted_independent["independent_validation_manifest"]["minimum_sections_present_count"],
                promoted_independent["independent_validation_manifest"]["minimum_sections_required_count"],
            )
            self.assertTrue(all(promoted_independent["minimum_section_presence"].values()))
            self.assertTrue(promoted_independent["ready_for_court_report"])
            self.assertEqual(promoted_independent["functional_priority_profile"]["status"], "complete")
            self.assertIn(
                "trusted independent validation signoff diff pass",
                promoted_independent["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "report manifest hash emitted",
                promoted_independent["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "independent validation report-grade validation plan emitted",
                promoted_independent["core_accuracy_gates"][0]["satisfied_checks"],
            )

            package_file = root / "rapidtriage-validation-package.json"
            package_file.write_text('{"command":"validation"}', encoding="utf-8")
            markdown_file = root / "rapidtriage-validation-report.md"
            markdown_file.write_text("# Validation", encoding="utf-8")
            package_manifest = build_validation_artifact_manifest(root, (package_file, markdown_file))
            package_diff = build_validation_package_trusted_diff(package_manifest, package_manifest)
            promoted_manifest = build_validation_artifact_manifest(root, (package_file, markdown_file), trusted_diff=package_diff)
            promoted_assessment = build_validation_package_assessment(root, trusted_diff=package_diff)
            self.assertEqual(package_diff["status"], "pass")
            self.assertIn("package_manifest_hash", package_diff["compared_fields"])
            self.assertEqual(len(promoted_manifest["validation_package_manifest"]["package_manifest_hash"]), 64)
            self.assertEqual(len(promoted_assessment["validation_package_manifest"]["package_manifest_hash"]), 64)
            self.assertEqual(
                promoted_manifest["validation_package_report_grade_validation_plan"]["profile_version"],
                "validation-package-report-grade-validation-plan-v1",
            )
            self.assertEqual(promoted_manifest["report_grade_ready_slot_count"], 6)
            self.assertEqual(promoted_manifest["report_grade_blocking_slot_count"], 3)
            self.assertIn(
                "trusted validation package manifest diff pass",
                promoted_manifest["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "validation package report-grade validation plan emitted",
                promoted_manifest["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "package manifest hash emitted",
                promoted_manifest["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "trusted validation package manifest diff pass",
                promoted_assessment["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "validation package report-grade validation plan emitted",
                promoted_assessment["core_accuracy_gates"][0]["satisfied_checks"],
            )

    def test_commercial_readiness_command_lists_non_commercial_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["commercial-readiness", "--output-dir", tmp_dir, "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "commercial-readiness")
            self.assertEqual(payload["item_count"], 120)
            self.assertEqual(payload["status"], "commercial-gaps-present")
            self.assertFalse(payload["commercial_claim_allowed"])
            self.assertEqual(payload["stdout_limit_profile"]["profile_version"], "commercial-readiness-stdout-limit-v1")
            self.assertTrue(payload["stdout_limit_profile"]["truncated"])
            self.assertLessEqual(len(payload["all_items"]), 25)
            full_payload = json.loads((Path(tmp_dir) / "rapidtriage-commercial-readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(len(full_payload["all_items"]), 120)
            self.assertEqual(payload["claim_discipline_profile"]["item_number"], 45)
            self.assertEqual(payload["claim_discipline_manifest"]["profile_version"], "claim-discipline-manifest-v1")
            self.assertEqual(payload["claim_discipline_manifest"]["item_number"], 45)
            self.assertEqual(payload["claim_discipline_manifest"]["gap_id"], "#45")
            self.assertEqual(len(payload["claim_discipline_manifest_hash"]), 64)
            self.assertEqual(
                payload["claim_discipline_profile"]["implemented_controls"]["claim_discipline_manifest_hash"],
                payload["claim_discipline_manifest"]["manifest_hash"],
            )
            self.assertIn("commercial-grade", payload["claim_discipline_manifest"]["blocked_wording"])
            self.assertTrue(payload["claim_discipline_manifest"]["ui_guardrails"]["disable_commercial_report_template"])
            self.assertEqual(
                payload["claim_discipline_profile"]["implemented_controls"]["release_claim_guard"],
                "block-commercial-parity-wording",
            )
            self.assertIn(
                "commercial-claim-blocked",
                payload["claim_discipline_profile"]["failed_validation_check_ids"],
            )
            self.assertGreater(payload["non_commercial_count"], 0)
            self.assertIn("maturity_gate_summary", payload)
            self.assertEqual(payload["maturity_gate_summary"]["item_count"], 120)
            self.assertIn("implemented", payload["maturity_gate_summary"]["gate_counts"])
            self.assertIn("next_gate_samples", payload["maturity_gate_summary"])
            self.assertIn("next_gate_blocker_counts", payload["maturity_gate_summary"])
            blocker_matrix = payload["commercial_blocker_matrix"]
            self.assertEqual(blocker_matrix["version"], "commercial-blocker-matrix-v1")
            self.assertEqual(blocker_matrix["item_count"], payload["non_commercial_count"])
            self.assertFalse(blocker_matrix["commercial_claim_allowed"])
            self.assertGreater(blocker_matrix["internally_actionable_count"], 0)
            self.assertGreater(blocker_matrix["external_or_trusted_evidence_count"], 0)
            self.assertIn("native-parser-depth", blocker_matrix["lane_counts"])
            self.assertIn("top_internal_items", blocker_matrix)
            self.assertIn("top_external_evidence_items", blocker_matrix)
            self.assertEqual(blocker_matrix["rows"][0]["number"], 1)
            self.assertIn("native-parser-depth", blocker_matrix["rows"][0]["blocker_lanes"])
            self.assertTrue(blocker_matrix["rows"][0]["external_or_trusted_evidence_required"])
            self.assertIn("next_internal_or_evidence_action", blocker_matrix["rows"][0])
            separation = payload["blocker_separation_profile"]
            self.assertEqual(separation["version"], "blocker-separation-profile-v1")
            self.assertEqual(separation["immediate_queue_item"], 10)
            self.assertGreater(separation["summary"]["internal_work_available"], 0)
            self.assertGreater(separation["summary"]["external_or_trusted_evidence_required"], 0)
            self.assertIn("known-answer-validation", separation["lane_action_map"])
            self.assertLessEqual(len(separation["next_internal_batch"]), 5)
            self.assertLessEqual(len(separation["next_external_evidence_batch"]), 5)
            self.assertFalse(separation["next_internal_batch"][0]["commercial_claim_allowed_after_this_action"])
            platform_uplift = payload["platform_uplift_actionability"]
            self.assertEqual(platform_uplift["profile_version"], "platform-uplift-actionability-v1")
            self.assertEqual(platform_uplift["remaining_score_points"], 100 - payload["readiness_score"])
            self.assertFalse(platform_uplift["can_reach_100_on_mac_alone"])
            self.assertTrue(platform_uplift["mac_can_generate_preparatory_evidence"])
            self.assertFalse(platform_uplift["commercial_claim_allowed"])
            self.assertGreater(platform_uplift["counts"]["mac_preparable_item_count"], 0)
            self.assertGreater(platform_uplift["counts"]["windows_or_windows_evidence_item_count"], 0)
            self.assertGreater(platform_uplift["counts"]["external_or_trusted_evidence_item_count"], 0)
            command_ids = {command["id"] for command in platform_uplift["mac_executable_commands"]}
            self.assertIn("macos-live-smoke", command_ids)
            self.assertIn("final-qc-report", command_ids)
            self.assertIn("commercial-readiness", command_ids)
            self.assertEqual(platform_uplift["windows_or_windows_evidence_samples"][0]["number"], 1)
            self.assertFalse(
                platform_uplift["external_or_trusted_evidence_samples"][0][
                    "commercial_claim_allowed_after_action"
                ]
            )
            self.assertIn("priority_work_plan", payload)
            self.assertGreater(len(payload["priority_work_plan"]), 0)
            self.assertIn("required_action", payload["priority_work_plan"][0])
            progress = payload["functional_defensibility_progress"]
            self.assertEqual(progress["version"], "functional-defensibility-progress-v1")
            self.assertEqual(progress["target_range"], {"start": 42, "end": 70})
            self.assertEqual(progress["item_count"], 29)
            self.assertEqual(progress["batch_size"], 5)
            self.assertEqual(progress["batch_count"], 6)
            self.assertFalse(progress["commercial_claim_allowed"])
            self.assertIn("commercial-grade claims still require", progress["commercial_claim_rule"])
            self.assertEqual(progress["batches"][0]["item_numbers"], [42, 43, 44, 45, 46])
            self.assertEqual(progress["batches"][-1]["item_numbers"], [67, 68, 69, 70])
            self.assertIn("usable", progress["gate_counts"])
            self.assertIn("validated", progress["next_gate_counts"])
            self.assertIn("required_outputs_before_commercial_claim", progress["batches"][0])
            review_scale = payload["review_scale_resilience_progress"]
            self.assertEqual(review_scale["version"], "review-scale-resilience-progress-v1")
            self.assertEqual(review_scale["target_range"], {"start": 76, "end": 80})
            self.assertEqual(review_scale["item_numbers"], [76, 77, 78, 79, 80])
            self.assertFalse(review_scale["commercial_claim_allowed"])
            self.assertIn("trusted-hash-cache-manifest", review_scale["required_outputs_before_commercial_claim"])
            self.assertEqual(review_scale["surface_map"]["76"]["component"], "hash-cache")
            self.assertEqual(review_scale["surface_map"]["80"]["component"], "cancel-retry")
            item_by_number = {item["number"]: item for item in review_scale["items"]}
            self.assertEqual(item_by_number[78]["trusted_manifest_required"], "pagination-cursor-manifest")
            self.assertIn("api pagination.cursor", item_by_number[78]["primary_outputs"])
            self.assertEqual(item_by_number[79]["component"], "ui-virtualization")
            self.assertIn("ui-virtualization-report-grade-validation-plan-v1", item_by_number[79]["primary_outputs"])
            self.assertIn("cancellation-retry-manifest-v1", item_by_number[80]["primary_outputs"])
            self.assertIn("cancellation-retry-report-grade-validation-plan-v1", item_by_number[80]["primary_outputs"])
            self.assertIn("retry_lineage_profile", item_by_number[80]["primary_outputs"])
            validation_spine = payload["validation_spine_progress"]
            self.assertEqual(validation_spine["version"], "validation-spine-progress-v1")
            self.assertEqual(validation_spine["target_range"], {"start": 81, "end": 85})
            self.assertEqual(validation_spine["item_numbers"], [81, 82, 83, 84, 85])
            self.assertFalse(validation_spine["commercial_claim_allowed"])
            self.assertFalse(validation_spine["validation_package_attached"])
            self.assertEqual(validation_spine["mapped_item_numbers_in_range"], [])
            self.assertIn("known-answer-manifest-with-existing-evidence-paths", validation_spine["required_outputs_before_commercial_claim"])
            self.assertEqual(validation_spine["evidence_chain"][0]["component"], "known-answer-validation")
            spine_by_number = {item["number"]: item for item in validation_spine["items"]}
            self.assertEqual(spine_by_number[81]["produces"], "known_answer_validation.datasets")
            self.assertIn("known_answer_validation.manifest_digest", spine_by_number[81]["primary_outputs"])
            self.assertIn(
                "known_answer_validation.known_answer_report_grade_validation_plan_hash",
                spine_by_number[81]["primary_outputs"],
            )
            self.assertIn("datasets[].evidence_files[].sha256", spine_by_number[81]["primary_outputs"])
            self.assertIn("parser_fixture_corpus.fixture_corpus_digest", spine_by_number[82]["primary_outputs"])
            self.assertIn(
                "parser_fixture_corpus.fixture_corpus_report_grade_validation_plan_hash",
                spine_by_number[82]["primary_outputs"],
            )
            self.assertIn("areas[].area_manifest_hash", spine_by_number[82]["primary_outputs"])
            self.assertIn("parser_false_positive_false_negative_notes[].risk_note_hash", spine_by_number[83]["primary_outputs"])
            self.assertIn(
                "parser_false_positive_false_negative_notes[].fp_fn_report_grade_validation_plan_hash",
                spine_by_number[83]["primary_outputs"],
            )
            self.assertIn("parser_fp_fn_risk_register_profile.register_digest", spine_by_number[83]["primary_outputs"])
            self.assertIn(
                "independent_validation_report.independent_validation_manifest.report_manifest_hash",
                spine_by_number[84]["primary_outputs"],
            )
            self.assertIn(
                "independent_validation_report.independent_validation_report_grade_validation_plan_hash",
                spine_by_number[84]["primary_outputs"],
            )
            self.assertIn("validation_package_manifest.package_manifest_hash", spine_by_number[85]["primary_outputs"])
            self.assertIn(
                "validation_package_assessment.validation_package_report_grade_validation_plan_hash",
                spine_by_number[85]["primary_outputs"],
            )
            self.assertEqual(spine_by_number[85]["trusted_diff_required"], "trusted-validation-package-manifest-diff")
            forensic_integrity = payload["forensic_integrity_progress"]
            self.assertEqual(forensic_integrity["version"], "forensic-integrity-progress-v1")
            self.assertEqual(forensic_integrity["target_range"], {"start": 86, "end": 90})
            self.assertEqual(forensic_integrity["item_numbers"], [86, 87, 88, 89, 90])
            self.assertFalse(forensic_integrity["commercial_claim_allowed"])
            self.assertIn("trusted-custody-event-manifest", forensic_integrity["required_outputs_before_commercial_claim"])
            self.assertEqual(forensic_integrity["evidence_chain"][0]["component"], "chain-of-custody")
            integrity_by_number = {item["number"]: item for item in forensic_integrity["items"]}
            self.assertEqual(integrity_by_number[86]["produces"], "case-db-report-export.custody_workflow")
            self.assertIn("custody_workflow.custody_event_manifest.manifest_hash", integrity_by_number[86]["primary_outputs"])
            self.assertIn("custody_workflow.custody_report_grade_validation_plan_hash", integrity_by_number[86]["primary_outputs"])
            self.assertIn("custody_workflow.evidence_sources[].custody_row_hash", integrity_by_number[86]["primary_outputs"])
            self.assertIn("acquisition_hash_workflow.acquisition_hash_manifest.manifest_hash", integrity_by_number[87]["primary_outputs"])
            self.assertIn(
                "acquisition_hash_workflow.acquisition_hash_report_grade_validation_plan_hash",
                integrity_by_number[87]["primary_outputs"],
            )
            self.assertIn("audit_integrity.audit_hash_chain_manifest.manifest_hash", integrity_by_number[88]["primary_outputs"])
            self.assertIn("audit_integrity.immutable_audit_report_grade_validation_plan_hash", integrity_by_number[88]["primary_outputs"])
            self.assertIn("reproducibility.report_replay_manifest.manifest_hash", integrity_by_number[89]["primary_outputs"])
            self.assertIn(
                "reproducibility.report_reproducibility_report_grade_validation_plan_hash",
                integrity_by_number[89]["primary_outputs"],
            )
            self.assertIn(
                "items[].provenance.source_provenance_report_grade_validation_plan_hash",
                integrity_by_number[90]["primary_outputs"],
            )
            self.assertEqual(integrity_by_number[90]["trusted_diff_required"], "trusted-report-provenance-manifest-diff")
            report_quality = payload["report_quality_progress"]
            self.assertEqual(report_quality["version"], "report-quality-progress-v1")
            self.assertEqual(report_quality["target_range"], {"start": 91, "end": 95})
            self.assertEqual(report_quality["item_numbers"], [91, 92, 93, 94, 95])
            self.assertFalse(report_quality["commercial_claim_allowed"])
            self.assertIn("trusted-parser-confidence-calibration-manifest", report_quality["required_outputs_before_commercial_claim"])
            self.assertEqual(report_quality["evidence_chain"][0]["component"], "parser-confidence-scoring")
            quality_by_number = {item["number"]: item for item in report_quality["items"]}
            self.assertEqual(quality_by_number[91]["produces"], "case-db-report-export.items[].validation_assessment.parser_confidence")
            self.assertIn(
                "items[].validation_assessment.parser_confidence_report_grade_validation_plan_hash",
                quality_by_number[91]["primary_outputs"],
            )
            self.assertIn(
                "items[].validation_assessment.validation_warning_report_grade_validation_plan_hash",
                quality_by_number[92]["primary_outputs"],
            )
            self.assertIn(
                "items[].legal_limitations_assessment.legal_limitation_report_grade_validation_plan_hash",
                quality_by_number[93]["primary_outputs"],
            )
            self.assertIn(
                "court_exhibit_index.court_exhibit_report_grade_validation_plan_hash",
                quality_by_number[94]["primary_outputs"],
            )
            self.assertIn(
                "external_tool_version_assessment.external_tool_version_report_grade_validation_plan_hash",
                quality_by_number[95]["primary_outputs"],
            )
            self.assertEqual(quality_by_number[95]["trusted_diff_required"], "trusted-external-tool-transcript-diff")
            acquisition_quality = payload["acquisition_quality_progress"]
            self.assertEqual(acquisition_quality["version"], "acquisition-quality-progress-v1")
            self.assertEqual(acquisition_quality["target_range"], {"start": 96, "end": 100})
            self.assertEqual(acquisition_quality["item_numbers"], [96, 97, 98, 99, 100])
            self.assertFalse(acquisition_quality["commercial_claim_allowed"])
            self.assertIn("signed-acquisition-handoff-with-write-blocker-metadata", acquisition_quality["required_outputs_before_commercial_claim"])
            self.assertEqual(acquisition_quality["evidence_chain"][0]["component"], "write-blocker-acquisition-metadata")
            acquisition_by_number = {item["number"]: item for item in acquisition_quality["items"]}
            self.assertEqual(acquisition_by_number[96]["produces"], "case-db-report-export.acquisition_metadata")
            self.assertIn(
                "acquisition_metadata.acquisition_metadata_report_grade_validation_plan_hash",
                acquisition_by_number[96]["primary_outputs"],
            )
            self.assertIn(
                "timezone_validation.timezone_report_grade_validation_plan_hash",
                acquisition_by_number[97]["primary_outputs"],
            )
            self.assertIn(
                "clock_skew_analysis.clock_skew_report_grade_validation_plan_hash",
                acquisition_by_number[98]["primary_outputs"],
            )
            self.assertIn(
                "contamination_warnings.contamination_report_grade_validation_plan_hash",
                acquisition_by_number[99]["primary_outputs"],
            )
            self.assertIn(
                "tamper_evident_audit_bundle.tamper_evident_report_grade_validation_plan_hash",
                acquisition_by_number[100]["primary_outputs"],
            )
            self.assertEqual(acquisition_by_number[100]["trusted_diff_required"], "trusted-tamper-signature-attestation-diff")
            release_operations = payload["release_operations_progress"]
            self.assertEqual(release_operations["version"], "release-operations-progress-v1")
            self.assertEqual(release_operations["target_range"], {"start": 101, "end": 105})
            self.assertEqual(release_operations["item_numbers"], [101, 102, 103, 104, 105])
            self.assertFalse(release_operations["commercial_claim_allowed"])
            self.assertIn("signed-windows-msi-or-exe-with-authenticode-timestamp-log", release_operations["required_outputs_before_commercial_claim"])
            self.assertEqual(release_operations["evidence_chain"][0]["component"], "windows-signed-installer")
            release_by_number = {item["number"]: item for item in release_operations["items"]}
            self.assertEqual(release_by_number[101]["produces"], "release-manifest.package_readiness.windows_signed_installer")
            self.assertIn(
                "windows_signed_installer.windows_signing_evidence_manifest.manifest_hash",
                release_by_number[101]["primary_outputs"],
            )
            self.assertIn(
                "windows_signed_installer.windows_signing_report_grade_validation_plan_hash",
                release_by_number[101]["primary_outputs"],
            )
            self.assertIn(
                "macos_notarized_package.macos_notarization_evidence_manifest.manifest_hash",
                release_by_number[102]["primary_outputs"],
            )
            self.assertIn(
                "macos_notarized_package.macos_notarization_report_grade_validation_plan_hash",
                release_by_number[102]["primary_outputs"],
            )
            self.assertIn(
                "linux_package.linux_package_evidence_manifest.manifest_hash",
                release_by_number[103]["primary_outputs"],
            )
            self.assertIn(
                "linux_package.linux_package_report_grade_validation_plan_hash",
                release_by_number[103]["primary_outputs"],
            )
            self.assertIn(
                "update-manifest.auto_update_evidence_manifest.manifest_hash",
                release_by_number[104]["primary_outputs"],
            )
            self.assertIn(
                "update-manifest.auto_update_report_grade_validation_plan_hash",
                release_by_number[104]["primary_outputs"],
            )
            self.assertIn(
                "crash-report.crash_export_evidence_manifest.manifest_hash",
                release_by_number[105]["primary_outputs"],
            )
            self.assertIn(
                "crash-report.crash_report_grade_validation_plan_hash",
                release_by_number[105]["primary_outputs"],
            )
            self.assertEqual(release_by_number[105]["trusted_diff_required"], "trusted-crash-redaction-export-diff")
            enterprise_governance = payload["enterprise_governance_progress"]
            self.assertEqual(enterprise_governance["version"], "enterprise-governance-progress-v1")
            self.assertEqual(enterprise_governance["target_range"], {"start": 106, "end": 110})
            self.assertEqual(enterprise_governance["item_numbers"], [106, 107, 108, 109, 110])
            self.assertFalse(enterprise_governance["commercial_claim_allowed"])
            self.assertIn(
                "trusted-local-only-deployment-policy-and-network-egress-smoke",
                enterprise_governance["required_outputs_before_commercial_claim"],
            )
            self.assertEqual(enterprise_governance["evidence_chain"][0]["component"], "telemetry-free-local-only-mode")
            enterprise_by_number = {item["number"]: item for item in enterprise_governance["items"]}
            self.assertEqual(enterprise_by_number[106]["produces"], "enterprise-policy.telemetry")
            self.assertIn(
                "enterprise-policy.telemetry.local_only_evidence_manifest.manifest_hash",
                enterprise_by_number[106]["primary_outputs"],
            )
            self.assertIn(
                "enterprise-policy.telemetry.local_only_report_grade_validation_plan_hash",
                enterprise_by_number[106]["primary_outputs"],
            )
            self.assertIn(
                "enterprise-policy.license_activation.license_evidence_manifest.manifest_hash",
                enterprise_by_number[107]["primary_outputs"],
            )
            self.assertIn(
                "enterprise-policy.rbac.rbac_evidence_manifest.manifest_hash",
                enterprise_by_number[108]["primary_outputs"],
            )
            self.assertIn(
                "enterprise-policy.multi_user_case_server.multi_user_evidence_manifest.manifest_hash",
                enterprise_by_number[109]["primary_outputs"],
            )
            self.assertIn(
                "enterprise-policy.collaboration_audit_trail.collaboration_audit_evidence_manifest.manifest_hash",
                enterprise_by_number[110]["primary_outputs"],
            )
            self.assertEqual(enterprise_by_number[110]["trusted_diff_required"], "trusted-collaboration-audit-diff")
            operations_continuity = payload["operations_continuity_progress"]
            self.assertEqual(operations_continuity["version"], "operations-continuity-progress-v1")
            self.assertEqual(operations_continuity["target_range"], {"start": 111, "end": 115})
            self.assertEqual(operations_continuity["item_numbers"], [111, 112, 113, 114, 115])
            self.assertFalse(operations_continuity["commercial_claim_allowed"])
            self.assertIn(
                "trusted-backup-restore-rehearsal-log-and-migration-corpus",
                operations_continuity["required_outputs_before_commercial_claim"],
            )
            self.assertEqual(operations_continuity["evidence_chain"][0]["component"], "backup-restore-migration")
            continuity_by_number = {item["number"]: item for item in operations_continuity["items"]}
            self.assertEqual(continuity_by_number[111]["produces"], "case-backup/case-restore payloads")
            self.assertIn(
                "case-backup.backup_restore_evidence_manifest.manifest_hash",
                continuity_by_number[111]["primary_outputs"],
            )
            self.assertIn(
                "operations_documents.document_evidence_manifests.112.manifest_hash",
                continuity_by_number[112]["primary_outputs"],
            )
            self.assertIn(
                "operations_documents.document_evidence_manifests.115.manifest_hash",
                continuity_by_number[115]["primary_outputs"],
            )
            self.assertEqual(continuity_by_number[115]["trusted_diff_required"], "trusted-training-delivery-diff")
            final_delivery = payload["final_delivery_progress"]
            self.assertEqual(final_delivery["version"], "final-delivery-progress-v1")
            self.assertEqual(final_delivery["target_range"], {"start": 116, "end": 120})
            self.assertEqual(final_delivery["item_numbers"], [116, 117, 118, 119, 120])
            self.assertFalse(final_delivery["commercial_claim_allowed"])
            self.assertIn("trusted-quickstart-lab-run-log", final_delivery["required_outputs_before_commercial_claim"])
            self.assertEqual(final_delivery["evidence_chain"][0]["component"], "analyst-quickstart-lab")
            final_by_number = {item["number"]: item for item in final_delivery["items"]}
            self.assertEqual(final_by_number[116]["produces"], "docs/rapidtriage-training-curriculum.md quickstart lab section")
            self.assertIn(
                "operations_documents.document_evidence_manifests.116.manifest_hash",
                final_by_number[116]["primary_outputs"],
            )
            self.assertIn(
                "operations_documents.document_evidence_manifests.120.manifest_hash",
                final_by_number[120]["primary_outputs"],
            )
            self.assertEqual(final_by_number[120]["trusted_diff_required"], "trusted-dependency-advisory-sbom-diff")
            self.assertIn("all_items", payload)
            first_item = next(item for item in payload["all_items"] if item["number"] == 1)
            self.assertIn("maturity_gates", first_item)
            self.assertIn("commercial_grade", first_item["maturity_gates"])
            self.assertFalse(first_item["maturity_gates"]["commercial_grade"]["passed"])
            self.assertTrue((Path(tmp_dir) / "rapidtriage-commercial-readiness.json").is_file())
            self.assertTrue((Path(tmp_dir) / "rapidtriage-commercial-readiness.md").is_file())
            markdown = (Path(tmp_dir) / "rapidtriage-commercial-readiness.md").read_text(encoding="utf-8")
            self.assertIn("Internal vs External Blockers", markdown)
            self.assertIn("Platform Uplift Actionability", markdown)
            self.assertIn("Can reach 100 on Mac alone: `False`", markdown)
            critical_numbers = {item["number"] for item in payload["critical_non_commercial_items"]}
            self.assertIn(1, critical_numbers)
            self.assertIn(25, critical_numbers)

    def test_commercial_readiness_includes_prioritized_commercial_uplift_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "commercial-readiness",
                        "--uplift-targets",
                        "70",
                        "--uplift-batch-size",
                        "5",
                        "--output-dir",
                        tmp_dir,
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            plan = payload["commercial_uplift_plan"]
            self.assertEqual(plan["version"], "commercial-uplift-plan-v1")
            self.assertEqual(plan["target_goal_count"], 70)
            self.assertEqual(plan["selected_goal_count"], 70)
            self.assertEqual(plan["batch_size"], 5)
            self.assertEqual(plan["batch_count"], 14)
            self.assertIn("parser_runtime", plan["large_data_strategy"])
            self.assertIn("core-forensics", plan["category_counts"])
            first_goal = plan["goals"][0]
            self.assertEqual(first_goal["number"], 1)
            self.assertEqual(first_goal["priority_rank"], 1)
            self.assertEqual(first_goal["batch_number"], 1)
            self.assertEqual(first_goal["implementation_track"], "native-parser-depth")
            self.assertIn("large_data_strategy", first_goal)
            self.assertGreaterEqual(len(first_goal["acceptance_evidence"]), 4)
            first_batch = plan["batches"][0]
            self.assertEqual(first_batch["item_numbers"], [1, 2, 3, 4, 5])
            self.assertIn("commercial_readiness_recalculation", first_batch["required_outputs"])
            markdown = (Path(tmp_dir) / "rapidtriage-commercial-readiness.md").read_text(encoding="utf-8")
            self.assertIn("70-Goal Commercial Uplift Plan", markdown)
            self.assertIn("Large Data Strategy", markdown)

    def test_commercial_readiness_scores_partial_plus_plus_above_partial_plus(self) -> None:
        base = {
            "severity": "critical",
            "category": "core-forensics",
        }
        partial_plus_score = calculate_readiness_score([{**base, "status": "Partial+"}])
        partial_plus_plus_score = calculate_readiness_score([{**base, "status": "Partial++"}])
        partial_plus_plus_plus_score = calculate_readiness_score([{**base, "status": "Partial+++"}])

        self.assertGreater(partial_plus_plus_score, partial_plus_score)
        self.assertGreater(partial_plus_plus_plus_score, partial_plus_plus_score)
        self.assertLess(partial_plus_plus_score, 100)

    def test_commercial_readiness_scores_validation_evidence_without_allowing_commercial_claim(self) -> None:
        base = {
            "severity": "critical",
            "category": "core-forensics",
            "status": "Partial++",
            "maturity_gates": {
                "validated": {"passed": False},
                "commercial_grade": {"passed": False},
            },
        }
        validated = {
            **base,
            "maturity_gates": {
                "validated": {"passed": True},
                "commercial_grade": {"passed": False},
            },
        }
        commercial = {
            **base,
            "status": "Done",
            "maturity_gates": {
                "validated": {"passed": True},
                "commercial_grade": {"passed": True},
            },
        }

        unvalidated_score = calculate_readiness_score([base])
        internally_validated_score = calculate_readiness_score([validated])
        commercial_score = calculate_readiness_score([commercial])

        self.assertGreater(internally_validated_score, unvalidated_score)
        self.assertLessEqual(internally_validated_score, 90)
        self.assertEqual(commercial_score, 100)

    def test_commercial_readiness_can_focus_next_gate_items(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["commercial-readiness", "--next-gate", "validated", "--limit", "3", "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["focused_next_gate"], "validated")
        self.assertEqual(len(payload["focused_items"]), 3)
        self.assertLessEqual(len(payload["all_items"]), 3)
        self.assertEqual(payload["stdout_limit_profile"]["limit"], 3)
        self.assertTrue(all(item["next_required_gate"] == "validated" for item in payload["focused_items"]))

    def test_commercial_readiness_attaches_passed_validation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence = root / "evtx-known-answer.diff.json"
            evidence.write_text('{"status":"pass"}', encoding="utf-8")
            validation_package = root / "validation.json"
            validation_package.write_text(
                json.dumps(
                    {
                        "command": "validation",
                        "known_answer_validation": {
                            "datasets": [
                                {
                                    "id": "evtx-core-known-answer",
                                    "name": "EVTX core known-answer",
                                    "status": "pass",
                                    "backlog_items": [1],
                                    "evidence_paths": [str(evidence)],
                                    "evidence_paths_present": True,
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["commercial-readiness", "--validation-package", str(validation_package), "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["validation_evidence_summary"]["items_with_passed_validation_evidence"], 1)
        self.assertIn(1, payload["validation_evidence_summary"]["mapped_item_numbers"])
        first_item = next(item for item in payload["all_items"] if item["number"] == 1)
        self.assertTrue(first_item["maturity_gates"]["validated"]["passed"])
        self.assertFalse(first_item["maturity_gates"]["commercial_grade"]["passed"])
        self.assertEqual(first_item["next_required_gate"], "commercial_grade")

    def test_commercial_readiness_combines_repeated_validation_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            evidence_a = root / "evtx-known-answer.diff.json"
            evidence_b = root / "mobile-export-known-answer.diff.json"
            evidence_a.write_text('{"status":"pass"}', encoding="utf-8")
            evidence_b.write_text('{"status":"pass"}', encoding="utf-8")
            validation_package_a = root / "validation-a.json"
            validation_package_b = root / "validation-b.json"
            validation_package_a.write_text(
                json.dumps(
                    {
                        "command": "validation",
                        "known_answer_validation": {
                            "datasets": [
                                {
                                    "id": "evtx-core-known-answer",
                                    "name": "EVTX core known-answer",
                                    "status": "pass",
                                    "backlog_items": [1, 2],
                                    "evidence_paths": [str(evidence_a)],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            validation_package_b.write_text(
                json.dumps(
                    {
                        "command": "validation",
                        "known_answer_validation": {
                            "datasets": [
                                {
                                    "id": "mobile-export-known-answer",
                                    "name": "Mobile export known-answer",
                                    "status": "pass",
                                    "backlog_items": [26],
                                    "evidence_paths": [str(evidence_b)],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "commercial-readiness",
                        "--validation-package",
                        str(validation_package_a),
                        "--validation-package",
                        str(validation_package_b),
                        "--json",
                    ]
                )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        summary = payload["validation_evidence_summary"]
        self.assertEqual(summary["validation_package_count"], 2)
        self.assertEqual(summary["items_with_passed_validation_evidence"], 3)
        self.assertEqual(summary["mapped_item_numbers"], [1, 2, 26])
        self.assertEqual(
            summary["validation_package_paths"],
            [str(validation_package_a.resolve()), str(validation_package_b.resolve())],
        )
        item_26 = next(item for item in payload["all_items"] if item["number"] == 26)
        self.assertTrue(item_26["maturity_gates"]["validated"]["passed"])
        self.assertEqual(item_26["next_required_gate"], "commercial_grade")

    def test_commercial_readiness_requires_present_validation_evidence_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            validation_package = Path(tmp_dir) / "validation.json"
            validation_package.write_text(
                json.dumps(
                    {
                        "command": "validation",
                        "known_answer_validation": {
                            "datasets": [
                                {
                                    "id": "missing-evtx-known-answer",
                                    "name": "Missing EVTX known-answer",
                                    "status": "pass",
                                    "backlog_items": [1],
                                    "evidence_paths": [str(Path(tmp_dir) / "missing.json")],
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["commercial-readiness", "--validation-package", str(validation_package), "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["validation_evidence_summary"]["items_with_passed_validation_evidence"], 0)
        first_item = next(item for item in payload["all_items"] if item["number"] == 1)
        self.assertFalse(first_item["maturity_gates"]["validated"]["passed"])

    def test_commercial_readiness_accepts_core_forensics_001_025_bundle(self) -> None:
        bundle = Path("docs/validation/rapidtriage-core-forensics-001-025-known-answer.json").resolve()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["commercial-readiness", "--validation-package", str(bundle), "--json"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        summary = payload["validation_evidence_summary"]
        self.assertEqual(summary["items_with_passed_validation_evidence"], 25)
        self.assertEqual(summary["mapped_item_numbers"][:25], list(range(1, 26)))
        validated_items = [
            item for item in payload["all_items"]
            if 1 <= int(item["number"]) <= 25
        ]
        self.assertTrue(all(item["maturity_gates"]["validated"]["passed"] for item in validated_items))
        self.assertTrue(all(item["next_required_gate"] == "commercial_grade" for item in validated_items))
        self.assertFalse(payload["commercial_claim_allowed"])
        self.assertEqual(payload["claim_discipline_profile"]["item_number"], 45)
        self.assertIn(
            "all-items-validation-evidence-not-attached",
            payload["claim_discipline_profile"]["failed_validation_check_ids"],
        )

    def test_commercial_readiness_writes_known_answer_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "known-answer-runs.template.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "commercial-readiness",
                        "--next-gate",
                        "validated",
                        "--limit",
                        "5",
                        "--write-known-answer-template",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertIn("known_answer_manifest_template", payload)
            template = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(template["command"], "commercial-readiness-known-answer-template")
            self.assertEqual(template["status"], "template-not-run")
            self.assertEqual(template["next_gate"], "validated")
            self.assertEqual(len(template["datasets"]), 5)
            self.assertEqual(template["datasets"][0]["backlog_items"], [1])
            self.assertEqual(template["datasets"][0]["status"], "not-run")
            self.assertIn("reference_tools", template["datasets"][0]["expected"])
            self.assertTrue(output.with_suffix(".md").is_file())

    def test_commercial_readiness_writes_all_known_answer_template_batches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "known-answer-batches"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "commercial-readiness",
                        "--template-items",
                        "1-120",
                        "--template-batch-size",
                        "5",
                        "--write-known-answer-template-dir",
                        str(output_dir),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            batches = payload["known_answer_manifest_template_batches"]
            self.assertEqual(batches["batch_count"], 24)
            self.assertEqual(batches["item_count"], 120)
            index = json.loads((output_dir / "known-answer-template-batches.index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["batch_count"], 24)
            self.assertTrue((output_dir / "known-answer-template-batches.index.md").is_file())
            self.assertTrue((output_dir / "known-answer-batch-001-005.template.json").is_file())
            self.assertTrue((output_dir / "known-answer-batch-116-120.template.json").is_file())
            first_batch = json.loads((output_dir / "known-answer-batch-001-005.template.json").read_text(encoding="utf-8"))
            last_batch = json.loads((output_dir / "known-answer-batch-116-120.template.json").read_text(encoding="utf-8"))
            self.assertEqual(first_batch["item_numbers"], [1, 2, 3, 4, 5])
            self.assertEqual(last_batch["item_numbers"], [116, 117, 118, 119, 120])
            self.assertTrue(all(dataset["status"] == "not-run" for dataset in first_batch["datasets"]))

    def test_forensic_validation_plan_defaults_to_items_1_through_120(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "forensic-plan"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["forensic-validation-plan", "--output-dir", str(output_dir), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "forensic-validation-plan")
            self.assertEqual(payload["profile_version"], "forensic-validation-plan-v1")
            self.assertEqual(payload["item_count"], 120)
            self.assertEqual(payload["item_numbers"][0], 1)
            self.assertEqual(payload["item_numbers"][-1], 120)
            self.assertEqual(payload["summary"]["commercial_grade_ready_count"], 0)
            self.assertIn(1, payload["summary"]["highest_priority_open_items"])
            self.assertIn("performance-large-scale", payload["summary"]["lane_counts"])
            self.assertIn("validation-legal-defensibility", payload["summary"]["lane_counts"])
            self.assertIn("release-operations-governance", payload["summary"]["lane_counts"])
            self.assertTrue(any(batch["item_numbers"] for batch in payload["sequencing"]))
            self.assertTrue((output_dir / "rapidtriage-forensic-validation-plan.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-forensic-validation-plan.md").is_file())

    def test_forensic_validation_pack_builds_executable_batch_for_items_1_to_5(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "forensic-pack"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["forensic-validation-pack", "--items", "1-5", "--output-dir", str(output_dir), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "forensic-validation-pack")
            self.assertEqual(payload["profile_version"], "forensic-validation-pack-v1")
            self.assertEqual(payload["item_numbers"], [1, 2, 3, 4, 5])
            self.assertEqual(payload["summary"]["required_dataset_count"], 5)
            self.assertIn("EvtxECmd", payload["summary"]["required_tool_families"])
            self.assertIn("RECmd", payload["summary"]["required_tool_families"])
            self.assertFalse(payload["commercial_claim_allowed"])
            self.assertEqual(len(payload["datasets"]), 5)
            self.assertTrue(all(dataset["status"] == "not-run" for dataset in payload["datasets"]))
            self.assertIn("record_id", payload["diff_contract"]["required_diff_fields"])
            self.assertIn("key_path", payload["diff_contract"]["required_diff_fields"])
            self.assertTrue((output_dir / "rapidtriage-forensic-validation-pack.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-forensic-validation-pack.md").is_file())
            self.assertTrue((output_dir / "known-answer-datasets.template.json").is_file())
            self.assertTrue((output_dir / "trusted-reference-commands.md").is_file())

    def test_forensic_validation_pack_covers_performance_validation_and_release_ops_lanes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            perf_dir = Path(tmp_dir) / "performance-pack"
            ops_dir = Path(tmp_dir) / "ops-pack"

            perf_stdout = io.StringIO()
            with contextlib.redirect_stdout(perf_stdout):
                self.assertEqual(main(["forensic-validation-pack", "--items", "66-70", "--output-dir", str(perf_dir), "--json"]), 0)
            perf_payload = json.loads(perf_stdout.getvalue())
            self.assertEqual({dataset["lane"] for dataset in perf_payload["datasets"]}, {"performance-large-scale"})
            self.assertIn("duration_ms", perf_payload["diff_contract"]["required_diff_fields"])
            self.assertIn("system resource telemetry", perf_payload["summary"]["required_tool_families"])

            ops_stdout = io.StringIO()
            with contextlib.redirect_stdout(ops_stdout):
                self.assertEqual(main(["forensic-validation-pack", "--items", "101-105", "--output-dir", str(ops_dir), "--json"]), 0)
            ops_payload = json.loads(ops_stdout.getvalue())
            self.assertEqual({dataset["lane"] for dataset in ops_payload["datasets"]}, {"release-operations-governance"})
            self.assertIn("release_artifact", ops_payload["diff_contract"]["required_diff_fields"])
            self.assertIn("CI advisory/SBOM scanner", ops_payload["summary"]["required_tool_families"])

    def test_forensic_validation_pack_assess_checks_evidence_and_diff_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            pack_dir = root / "pack"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["forensic-validation-pack", "--items", "1", "--output-dir", str(pack_dir), "--json"]), 0)
            pack_path = pack_dir / "rapidtriage-forensic-validation-pack.json"
            source = root / "Security.evtx"
            rapid = root / "rapid.json"
            reference = root / "evtxecmd.csv"
            diff = root / "diff.json"
            signoff = root / "review.md"
            source.write_bytes(b"evtx fixture")
            rapid.write_text('{"artifacts":[]}', encoding="utf-8")
            reference.write_text("EventRecordID,EventID\n1001,4624\n", encoding="utf-8")
            signoff.write_text("Reviewer signoff for fixture diff.\n", encoding="utf-8")
            diff.write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "cross_tool_validation_assessment": {
                            "ready_for_validated_gate": True,
                            "ready_for_commercial_grade": False,
                        },
                        "comparisons": [
                            {
                                "reference_name": "evtxecmd",
                                "status": "pass",
                                "record_field_comparison": {
                                    "mismatch_count": 0,
                                    "missing_common_field_count": 0,
                                    "field_match_ratio": 1.0,
                                    "truncated": False,
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            pack_payload = json.loads(pack_path.read_text(encoding="utf-8"))
            dataset = pack_payload["datasets"][0]
            dataset["evidence_paths"] = {
                "source_evidence": str(source),
                "rapid_output": str(rapid),
                "trusted_reference_output": str(reference),
                "row_level_diff_output": str(diff),
                "reviewer_signoff": str(signoff),
            }
            pack_path.write_text(json.dumps(pack_payload, ensure_ascii=False, indent=2), encoding="utf-8")

            stdout = io.StringIO()
            output = root / "assessment.json"
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["forensic-validation-pack-assess", "--pack", str(pack_path), "--output", str(output), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(output.is_file())
            self.assertEqual(payload["dataset_count"], 1)
            self.assertEqual(payload["ready_dataset_count"], 1)
            self.assertTrue(payload["ready_for_validated_gate"])
            self.assertEqual(payload["external_ready_dataset_count"], 1)
            self.assertTrue(payload["ready_for_external_validated_gate"])
            self.assertFalse(payload["ready_for_commercial_grade"])
            self.assertIn("commercial-grade-diff-evidence-incomplete", payload["remaining_blockers"])

    def test_forensic_validation_pack_assess_rejects_incomplete_field_diffs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            pack_dir = root / "pack"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["forensic-validation-pack", "--items", "1", "--output-dir", str(pack_dir), "--json"]), 0)
            pack_path = pack_dir / "rapidtriage-forensic-validation-pack.json"
            source = root / "Security.evtx"
            rapid = root / "rapid.json"
            reference = root / "evtxecmd.csv"
            diff = root / "diff.json"
            signoff = root / "review.md"
            source.write_bytes(b"evtx fixture")
            rapid.write_text('{"artifacts":[]}', encoding="utf-8")
            reference.write_text("EventRecordID,EventID\n1001,4624\n", encoding="utf-8")
            signoff.write_text("Reviewer signoff for fixture diff.\n", encoding="utf-8")
            diff.write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "cross_tool_validation_assessment": {
                            "ready_for_validated_gate": True,
                            "ready_for_commercial_grade": True,
                        },
                        "comparisons": [
                            {
                                "reference_name": "evtxecmd",
                                "status": "pass",
                                "record_field_comparison": {
                                    "mismatch_count": 0,
                                    "missing_common_field_count": 1,
                                    "field_match_ratio": 0.9,
                                    "truncated": False,
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            pack_payload = json.loads(pack_path.read_text(encoding="utf-8"))
            pack_payload["datasets"][0]["evidence_paths"] = {
                "source_evidence": str(source),
                "rapid_output": str(rapid),
                "trusted_reference_output": str(reference),
                "row_level_diff_output": str(diff),
                "reviewer_signoff": str(signoff),
            }
            pack_path.write_text(json.dumps(pack_payload, ensure_ascii=False, indent=2), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["forensic-validation-pack-assess", "--pack", str(pack_path), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["ready_dataset_count"], 0)
            self.assertFalse(payload["ready_for_validated_gate"])
            diff_assessment = payload["dataset_results"][0]["row_level_diff_assessment"]
            self.assertEqual(diff_assessment["comparison_health"]["missing_common_field_count"], 1)
            self.assertFalse(diff_assessment["comparison_health"]["clean"])

    def test_forensic_validation_batches_write_and_assess_items_1_to_120(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "batches"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["forensic-validation-batches", "--output-dir", str(root), "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "forensic-validation-batches")
            self.assertEqual(payload["profile_version"], "forensic-validation-batches-v1")
            self.assertEqual(payload["item_count"], 120)
            self.assertEqual(payload["batch_count"], 24)
            self.assertTrue((root / "rapidtriage-forensic-validation-batches.json").is_file())
            self.assertTrue((root / "plan" / "rapidtriage-forensic-validation-plan.json").is_file())
            self.assertTrue((root / "batch-001-items-001-005" / "rapidtriage-forensic-validation-pack.json").is_file())
            self.assertTrue((root / "batch-024-items-116-120" / "rapidtriage-forensic-validation-pack.json").is_file())
            self.assertEqual(len(list(root.glob("batch-*/rapidtriage-forensic-validation-pack.json"))), 24)

            assessment_output = root / "batches-assessment.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "forensic-validation-batches-assess",
                        "--root-dir",
                        str(root),
                        "--output",
                        str(assessment_output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            assessment = json.loads(stdout.getvalue())
            self.assertTrue(assessment_output.is_file())
            self.assertEqual(assessment["batch_count"], 24)
            self.assertEqual(assessment["dataset_count"], 120)
            self.assertEqual(assessment["ready_dataset_count"], 0)
            self.assertFalse(assessment["ready_for_validated_gate"])

    def test_forensic_validation_smoke_populate_completes_internal_loop_for_items_1_to_120(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "batches"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["forensic-validation-batches", "--output-dir", str(root), "--json"]), 0)

            stdout = io.StringIO()
            smoke_output = root / "smoke-manifest.json"
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "forensic-validation-smoke-populate",
                        "--root-dir",
                        str(root),
                        "--output",
                        str(smoke_output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(smoke_output.is_file())
            self.assertEqual(payload["command"], "forensic-validation-smoke-populate")
            self.assertEqual(payload["populated_dataset_count"], 120)
            assessment = payload["assessment"]
            self.assertEqual(assessment["batch_count"], 24)
            self.assertEqual(assessment["dataset_count"], 120)
            self.assertEqual(assessment["ready_dataset_count"], 120)
            self.assertTrue(assessment["ready_for_validated_gate"])
            self.assertEqual(assessment["external_ready_dataset_count"], 0)
            self.assertFalse(assessment["ready_for_external_validated_gate"])
            self.assertEqual(assessment["commercial_ready_dataset_count"], 0)
            self.assertFalse(assessment["ready_for_commercial_grade"])
            first_pack = json.loads(
                (root / "batch-001-items-001-005" / "rapidtriage-forensic-validation-pack.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(first_pack["datasets"][0]["status"], "internal-smoke-populated")
            self.assertTrue(Path(first_pack["datasets"][0]["evidence_paths"]["row_level_diff_output"]).is_file())

    def test_forensic_validation_batches_strict_external_rejects_smoke_only_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "batches"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["forensic-validation-batches", "--output-dir", str(root), "--json"]), 0)
                self.assertEqual(main(["forensic-validation-smoke-populate", "--root-dir", str(root), "--json"]), 0)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "forensic-validation-batches-assess",
                        "--root-dir",
                        str(root),
                        "--strict-external",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 2)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["ready_dataset_count"], 120)
            self.assertEqual(payload["external_ready_dataset_count"], 0)
            self.assertFalse(payload["ready_for_external_validated_gate"])

    def test_forensic_validation_evidence_import_can_complete_external_gate_for_items_1_to_120(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "batches"
            evidence_root = Path(tmp_dir) / "external-evidence"
            evidence_root.mkdir()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["forensic-validation-batches", "--output-dir", str(root), "--json"]), 0)

            manifest_rows = []
            for pack_path in sorted(root.glob("batch-*/rapidtriage-forensic-validation-pack.json")):
                pack = json.loads(pack_path.read_text(encoding="utf-8"))
                for dataset in pack["datasets"]:
                    dataset_id = dataset["dataset_id"]
                    item_dir = evidence_root / dataset_id
                    item_dir.mkdir()
                    source = item_dir / "source.bin"
                    rapid = item_dir / "rapid.json"
                    reference = item_dir / "reference.csv"
                    diff = item_dir / "diff.json"
                    signoff = item_dir / "signoff.md"
                    source.write_bytes(f"external source {dataset_id}".encode("utf-8"))
                    rapid.write_text('{"artifacts":[]}', encoding="utf-8")
                    reference.write_text("id,status\n1,ok\n", encoding="utf-8")
                    diff.write_text(
                        json.dumps(
                            {
                                "status": "pass",
                                "cross_tool_validation_assessment": {
                                    "ready_for_validated_gate": True,
                                    "ready_for_commercial_grade": False,
                                },
                                "comparisons": [
                                    {
                                        "reference_name": "external-fixture",
                                        "status": "pass",
                                        "record_field_comparison": {
                                            "mismatch_count": 0,
                                            "missing_common_field_count": 0,
                                            "field_match_ratio": 1.0,
                                            "truncated": False,
                                        },
                                    }
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                    signoff.write_text("External reviewer signoff placeholder.\n", encoding="utf-8")
                    manifest_rows.append(
                        {
                            "dataset_id": dataset_id,
                            "item_number": dataset["item_number"],
                            "evidence_paths": {
                                "source_evidence": str(Path(dataset_id) / source.name),
                                "rapid_output": str(Path(dataset_id) / rapid.name),
                                "trusted_reference_output": str(Path(dataset_id) / reference.name),
                                "row_level_diff_output": str(Path(dataset_id) / diff.name),
                                "reviewer_signoff": str(Path(dataset_id) / signoff.name),
                            },
                        }
                    )

            manifest_path = evidence_root / "external-manifest.json"
            manifest_path.write_text(json.dumps({"datasets": manifest_rows}, ensure_ascii=False, indent=2), encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "forensic-validation-evidence-import",
                        "--root-dir",
                        str(root),
                        "--manifest",
                        str(manifest_path),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["imported_dataset_count"], 120)
            self.assertEqual(payload["missing_dataset_count"], 0)
            assessment = payload["assessment"]
            self.assertEqual(assessment["ready_dataset_count"], 120)
            self.assertEqual(assessment["external_ready_dataset_count"], 120)
            self.assertTrue(assessment["ready_for_external_validated_gate"])
            self.assertEqual(assessment["commercial_ready_dataset_count"], 0)
            first_pack = json.loads(
                (root / "batch-001-items-001-005" / "rapidtriage-forensic-validation-pack.json").read_text(
                    encoding="utf-8"
                )
            )
            first_source_path = Path(first_pack["datasets"][0]["evidence_paths"]["source_evidence"])
            self.assertTrue(first_source_path.is_absolute())
            self.assertTrue(first_source_path.is_file())

            with contextlib.redirect_stdout(io.StringIO()):
                strict_exit = main(["forensic-validation-batches-assess", "--root-dir", str(root), "--strict-external", "--json"])
            self.assertEqual(strict_exit, 0)

    def test_cross_tool_validate_compares_rapid_and_reference_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid.json"
            reference = root / "evtxecmd.csv"
            output = root / "cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {"details": {"event_record_id": 1001}, "path": "Security.evtx"},
                            {"details": {"event_record_id": 1002}, "path": "Security.evtx"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text("EventRecordID,Provider\n1001,Security\n1003,Security\n", encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"evtxecmd={reference}",
                        "--min-overlap",
                        "0.9",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "cross-tool-validate")
            self.assertEqual(payload["status"], "failed")
            self.assertTrue(output.is_file())
            comparison = payload["comparisons"][0]
            self.assertEqual(comparison["reference_name"], "evtxecmd")
            self.assertLess(comparison["overlap_ratio"], 0.9)
            self.assertIn("1003", comparison["missing_in_rapid_sample"])
            qc_contract = payload["validation_qc_contract"]
            self.assertEqual(qc_contract["profile_version"], "validation-qc-controls-v1")
            self.assertEqual(qc_contract["qc_prep_item_numbers"], [71, 72, 73, 74, 75])
            self.assertEqual(
                qc_contract["mismatch_dashboard"]["summary"]["severity_counts"]["critical"],
                1,
            )
            self.assertIn(
                "cross-tool-status-pass",
                qc_contract["qc_checklist"]["failed_check_ids"],
            )
            self.assertFalse(qc_contract["qc_checklist"]["ready_for_validated_review"])

    def test_cross_tool_validate_can_emit_readiness_validation_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid.json"
            reference = root / "evtxecmd.csv"
            source = root / "Security.evtx"
            independent_report = root / "independent-review.md"
            output = root / "cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {"details": {"event_record_id": 1001, "event_id": 4624, "provider_name": "Security"}},
                            {"details": {"event_record_id": 1002, "event_id": 4625, "provider_name": "Security"}},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "EventRecordID,EventID,Provider\n1001,4624,Security\n1002,4625,Security\n",
                encoding="utf-8",
            )
            source.write_bytes(b"fixture evtx source bytes")
            independent_report.write_text(
                "# Independent review\n\nReviewer confirmed row-level overlap for fixture Security.evtx.\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"evtxecmd={reference}",
                        "--backlog-item",
                        "1",
                        "--backlog-item",
                        "2",
                        "--min-overlap",
                        "0.5",
                        "--source-evidence",
                        str(source),
                        "--tool-version",
                        "evtxecmd=EvtxECmd 1.5.0",
                        "--tool-command",
                        "evtxecmd=EvtxECmd.exe -f Security.evtx --csv reference",
                        "--independent-report",
                        str(independent_report),
                        "--corpus-scope",
                        "Fixture Security.evtx with two known EventRecordID rows and external EvtxECmd CSV export.",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["backlog_items"], [1, 2])
            self.assertTrue(payload["cross_tool_validation_assessment"]["ready_for_validated_gate"])
            self.assertTrue(payload["cross_tool_validation_assessment"]["ready_for_commercial_grade"])
            field_comparison = payload["comparisons"][0]["record_field_comparison"]
            self.assertEqual(field_comparison["mode"], "evtx-record-field-diff")
            self.assertEqual(field_comparison["common_record_count"], 2)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertGreaterEqual(field_comparison["compared_field_count"], 6)
            self.assertEqual(len(payload["rapid_output"]["file_integrity"]["sha256"]), 64)
            self.assertEqual(len(payload["reference_outputs"][0]["file_integrity"]["sha256"]), 64)
            self.assertEqual(len(payload["source_evidence_integrity"][0]["sha256"]), 64)
            self.assertEqual(len(payload["independent_review_integrity"][0]["sha256"]), 64)
            self.assertIn("Fixture Security.evtx", payload["corpus_scope"])
            tool_rows = {item["name"]: item for item in payload["tool_metadata"]["tools"]}
            self.assertEqual(tool_rows["evtxecmd"]["version"], "EvtxECmd 1.5.0")
            self.assertEqual(tool_rows["evtxecmd"]["command"], "EvtxECmd.exe -f Security.evtx --csv reference")
            readiness_checks = payload["cross_tool_validation_assessment"]["commercial_grade_readiness_checks"]
            functional_profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            trusted_manifest = payload["cross_tool_validation_assessment"]["trusted_tool_diff_manifest"]
            qc_contract = payload["validation_qc_contract"]
            self.assertEqual(functional_profile["item_number"], 37)
            self.assertEqual(functional_profile["status"], "complete")
            self.assertEqual(functional_profile["implemented_controls"]["mapped_backlog_items"], [1, 2])
            self.assertEqual(trusted_manifest["profile_version"], "trusted-tool-diff-manifest-v1")
            self.assertEqual(trusted_manifest["item_number"], 37)
            self.assertEqual(trusted_manifest["gap_id"], "#37")
            self.assertEqual(trusted_manifest["mapped_backlog_items"], [1, 2])
            self.assertEqual(trusted_manifest["configured_min_overlap"], 0.5)
            self.assertEqual(trusted_manifest["external_reference_hash_count"], 1)
            self.assertEqual(trusted_manifest["source_evidence_hash_count"], 1)
            self.assertEqual(trusted_manifest["independent_review_hash_count"], 1)
            self.assertEqual(trusted_manifest["comparison_summaries"][0]["reference_name"], "evtxecmd")
            self.assertEqual(len(trusted_manifest["manifest_hash"]), 64)
            self.assertEqual(
                payload["cross_tool_validation_assessment"]["trusted_tool_diff_manifest_hash"],
                trusted_manifest["manifest_hash"],
            )
            self.assertEqual(
                functional_profile["implemented_controls"]["trusted_tool_diff_manifest_hash"],
                trusted_manifest["manifest_hash"],
            )
            self.assertEqual(qc_contract["profile_version"], "validation-qc-controls-v1")
            self.assertEqual(qc_contract["qc_prep_item_numbers"], [71, 72, 73, 74, 75])
            self.assertEqual(payload["validation_qc_contract_hash"], qc_contract["contract_hash"])
            self.assertEqual(qc_contract["mismatch_dashboard"]["profile_version"], "trusted-diff-mismatch-dashboard-v1")
            self.assertEqual(qc_contract["mismatch_dashboard"]["summary"]["field_mismatch_count"], 0)
            self.assertEqual(qc_contract["false_positive_false_negative_register"]["profile_version"], "fp-fn-recording-contract-v1")
            self.assertEqual(qc_contract["parser_confidence_matrix"]["profile_version"], "parser-confidence-reportability-v1")
            self.assertEqual(qc_contract["legal_limitation_guardrails"]["profile_version"], "legal-limitation-guardrails-v1")
            self.assertEqual(qc_contract["qc_checklist"]["profile_version"], "auto-qc-checklist-v1")
            self.assertTrue(qc_contract["qc_checklist"]["ready_for_validated_review"])
            self.assertTrue(qc_contract["qc_checklist"]["ready_for_commercial_grade_review"])
            self.assertTrue(readiness_checks["source_evidence_hashes_attached"])
            self.assertTrue(readiness_checks["corpus_scope_attached"])
            self.assertTrue(readiness_checks["external_tool_versions_attached"])
            self.assertTrue(readiness_checks["external_tool_commands_attached"])
            self.assertTrue(readiness_checks["independent_reviewer_signoff_attached"])
            self.assertEqual(
                payload["cross_tool_validation_assessment"]["commercial_grade_blockers"],
                [],
            )
            self.assertEqual(payload["datasets"][0]["status"], "pass")
            self.assertEqual(payload["datasets"][0]["backlog_items"], [1, 2])
            self.assertEqual(payload["datasets"][0]["evidence_paths"], [str(output.resolve())])

            readiness_stdout = io.StringIO()
            with contextlib.redirect_stdout(readiness_stdout):
                readiness_exit = main(["commercial-readiness", "--validation-package", str(output), "--json"])

            self.assertEqual(readiness_exit, 0)
            readiness = json.loads(readiness_stdout.getvalue())
            self.assertEqual(readiness["validation_evidence_summary"]["mapped_item_numbers"], [1, 2])
            item_one = next(item for item in readiness["all_items"] if item["number"] == 1)
            self.assertTrue(item_one["maturity_gates"]["validated"]["passed"])

    def test_cross_tool_validate_fails_on_evtx_record_field_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-eventlog.json"
            reference = root / "evtxecmd.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "details": {
                                    "event_record_id": 1001,
                                    "event_id": 4624,
                                    "provider_name": "Microsoft-Windows-Security-Auditing",
                                    "channel": "Security",
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "EventRecordID,EventID,Provider,Channel\n"
                "1001,4625,Microsoft-Windows-Security-Auditing,Security\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"evtxecmd={reference}",
                        "--min-overlap",
                        "1.0",
                        "--backlog-item",
                        "1",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            comparison = payload["comparisons"][0]
            self.assertEqual(comparison["status"], "failed")
            self.assertGreaterEqual(comparison["overlap_ratio"], 0.5)
            field_comparison = comparison["record_field_comparison"]
            self.assertEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 1)
            self.assertEqual(field_comparison["mismatch_samples"][0]["field"], "event_id")
            self.assertFalse(payload["cross_tool_validation_assessment"]["ready_for_validated_gate"])

    def test_cross_tool_validate_compares_evtx_message_and_event_data_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-eventlog.json"
            reference = root / "evtxecmd.csv"
            output = root / "evtx-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "details": {
                                    "event_record_id": 1001,
                                    "event_id": 4688,
                                    "provider_name": "Microsoft-Windows-Security-Auditing",
                                    "channel": "Security",
                                    "event_message": "A new process has been created.",
                                    "binxml_event_data_fields": {
                                        "NewProcessName": r"C:\\Windows\\System32\\cmd.exe",
                                        "SubjectUserName": "alice",
                                    },
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "EventRecordID,EventID,Provider,Channel,Message,EventData.NewProcessName,EventData.SubjectUserName\n"
                "1001,4688,Microsoft-Windows-Security-Auditing,Security,A new process has been created.,"
                r"C:\\Windows\\System32\\cmd.exe,alice"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"evtxecmd={reference}",
                        "--backlog-item",
                        "1",
                        "--backlog-item",
                        "2",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]
            field_comparison = comparison["record_field_comparison"]
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertIn("event_message", field_comparison["compared_canonical_fields"])
            self.assertIn("event_data:newprocessname", field_comparison["compared_canonical_fields"])
            self.assertIn("event_data:subjectusername", field_comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("evtx-rendered-message-field-diff-supported", profile["passed_validation_check_ids"])
            self.assertIn("evtx-event-data-field-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_compares_registry_values_deleted_cells_and_transaction_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-registry.json"
            reference = root / "recmd.csv"
            output = root / "registry-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "registry-key-tree-node",
                                "details": {
                                    "key_path": r"HKEY_CURRENT_USER\Software\Run",
                                    "value_name": "SecurityUpdater",
                                    "value_type": "REG_SZ",
                                    "decoded_data_preview": r"C:\Users\alice\AppData\updater.exe",
                                    "last_written_at": "2024-04-01T04:05:06+00:00",
                                    "transaction_replay_status": "not-replayed",
                                },
                            },
                            {
                                "artifact_type": "registry-value-recovery-candidate",
                                "details": {
                                    "cell_offset": "0x3000",
                                    "candidate_class": "deleted-value-cell",
                                    "value_name": "SecurityUpdater",
                                    "decoded_data_preview": r"C:\Users\alice\AppData\updater.exe",
                                    "parent_key_path_candidate": r"HKEY_CURRENT_USER\Software\Run",
                                    "allocation_status": "free-or-deleted-candidate",
                                    "transaction_replay_status": "not-replayed",
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "KeyPath,ValueName,ValueType,ValueData,LastWriteTime,TransactionReplayStatus,CellOffset,"
                "CandidateClass,AllocationStatus,ParentKeyPath\n"
                r"HKCU\Software\Run,SecurityUpdater,REG_SZ,C:\Users\alice\AppData\updater.exe,"
                "2024-04-01T04:05:06+00:00,not-replayed,0x3000,deleted-value-cell,"
                r"free-or-deleted-candidate,HKCU\Software\Run"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"recmd={reference}",
                        "--backlog-item",
                        "4",
                        "--backlog-item",
                        "5",
                        "--min-overlap",
                        "0.5",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            registry_comparison = payload["comparisons"][0]["registry_field_comparison"]
            self.assertGreaterEqual(registry_comparison["common_registry_count"], 1)
            self.assertEqual(registry_comparison["mismatch_count"], 0)
            self.assertIn("value_data", registry_comparison["compared_canonical_fields"])
            self.assertIn("cell_offset", registry_comparison["compared_canonical_fields"])
            self.assertIn("transaction_replay_status", registry_comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("registry-key-value-field-diff-supported", profile["passed_validation_check_ids"])
            self.assertIn("registry-deleted-cell-offset-field-diff-supported", profile["passed_validation_check_ids"])
            self.assertIn("registry-transaction-replay-status-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_fails_on_registry_value_data_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-registry.json"
            reference = root / "registry-explorer.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "details": {
                                    "key_path": r"HKEY_CURRENT_USER\Software\Run",
                                    "value_name": "SecurityUpdater",
                                    "value_type": "REG_SZ",
                                    "decoded_data_preview": r"C:\Users\alice\AppData\updater.exe",
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "KeyPath,ValueName,ValueType,ValueData\n"
                r"HKCU\Software\Run,SecurityUpdater,REG_SZ,C:\Users\alice\AppData\other.exe"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"registryexplorer={reference}",
                        "--backlog-item",
                        "4",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "failed")
            registry_comparison = payload["comparisons"][0]["registry_field_comparison"]
            self.assertEqual(registry_comparison["mismatch_count"], 1)
            self.assertEqual(registry_comparison["mismatch_samples"][0]["field"], "value_data")
            self.assertFalse(payload["cross_tool_validation_assessment"]["ready_for_validated_gate"])

    def test_cross_tool_validate_compares_os_account_privilege_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-os-account.json"
            reference = root / "recmd-sam.csv"
            output = root / "os-account-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "windows-os-account",
                                "details": {
                                    "account_name": "alice",
                                    "rid": 1001,
                                    "sid": "S-1-5-21-1-2-3-1001",
                                    "admin_status": True,
                                    "group_name": "Administrators",
                                    "privilege_name": "SeDebugPrivilege",
                                    "secret_redaction_status": "redacted",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "UserName,RID,SID,IsAdmin,GroupName,PrivilegeName,SecretRedactionStatus\n"
                "alice,1001,S-1-5-21-1-2-3-1001,true,Administrators,SeDebugPrivilege,redacted\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"recmd={reference}",
                        "--backlog-item",
                        "6",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["os_account_field_comparison"]
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("privilege_name", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("os-account-sam-security-system-field-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_compares_execution_artifact_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-execution.json"
            reference = root / "amcacheparser.csv"
            output = root / "execution-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "amcache-entry",
                                "details": {
                                    "artifact_family": "amcache",
                                    "executable_path": r"C:\Program Files\App\agent.exe",
                                    "timestamp": "2024-01-02T03:04:05+00:00",
                                    "user_sid": "S-1-5-21-1-2-3-1001",
                                    "sha1": "A" * 40,
                                    "semantics_warning": "install-or-execution-context",
                                    "execution_evidence_status": "corroborate-before-reporting",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ArtifactFamily,ExecutablePath,Timestamp,UserSid,SHA1,SemanticsWarning,ExecutionEvidenceStatus\n"
                r"amcache,C:\Program Files\App\agent.exe,2024-01-02T03:04:05+00:00,S-1-5-21-1-2-3-1001,"
                f"{'A' * 40},install-or-execution-context,corroborate-before-reporting\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"amcacheparser={reference}",
                        "--backlog-item",
                        "7",
                        "--backlog-item",
                        "8",
                        "--backlog-item",
                        "9",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["execution_artifact_field_comparison"]
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("semantics_warning", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn(
                "execution-artifact-amcache-shimcache-bam-dam-field-diff-supported",
                profile["passed_validation_check_ids"],
            )

    def test_cross_tool_validate_compares_mft_records_against_mftecmd_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-mft.json"
            reference = root / "mftecmd.csv"
            output = root / "mft-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "mft-record",
                                "details": {
                                    "record_number": 42,
                                    "sequence_number": 7,
                                    "parent_reference": 5,
                                    "file_path": r"C:\Users\alice\Documents\case.txt",
                                    "deleted_hint": False,
                                    "timestamp": "2024-01-02T03:04:05+00:00",
                                    "record_offset": "0xa800",
                                    "attribute_types": [
                                        "$STANDARD_INFORMATION",
                                        "$FILE_NAME",
                                        "$DATA",
                                    ],
                                    "runlist_decode_status": "decoded-preview",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "EntryNumber,SequenceNumber,ParentEntryNumber,FullPath,Deleted,Created0x10,Offset,"
                "Attributes,DataRunStatus\n"
                r"42,7,5,C:\Users\alice\Documents\case.txt,false,2024-01-02T03:04:05+00:00,"
                "0xa800,$DATA|$FILE_NAME|$STANDARD_INFORMATION,decoded-preview\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"mftecmd={reference}",
                        "--backlog-item",
                        "12",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["mft_field_comparison"]
            self.assertEqual(comparison["mode"], "mft-record-field-diff")
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("record_number", comparison["compared_canonical_fields"])
            self.assertIn("parent_reference", comparison["compared_canonical_fields"])
            self.assertIn("file_path", comparison["compared_canonical_fields"])
            self.assertIn("attribute_types", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("mft-record-field-diff-supported", profile["passed_validation_check_ids"])
            self.assertIn("mft-parent-path-attribute-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_compares_usn_records_against_usnjrnl_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-usn.json"
            reference = root / "usnjrnl.csv"
            output = root / "usn-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "usn-record",
                                "details": {
                                    "usn": 9001,
                                    "file_reference_number": 42,
                                    "parent_file_reference_number": 5,
                                    "file_name": "case.txt",
                                    "reason_flags": ["FILE_CREATE", "CLOSE"],
                                    "timestamp": "2024-01-02T03:05:06+00:00",
                                    "major_version": 3,
                                    "source_info_flags": ["DATA_MANAGEMENT"],
                                    "file_attribute_names": ["ARCHIVE"],
                                    "record_cursor": 128,
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "USN,FRN,ParentFRN,FileName,Reason,Timestamp,MajorVersion,SourceInfo,FileAttributes,RecordOffset\n"
                "9001,42,5,case.txt,CLOSE|FILE_CREATE,2024-01-02T03:05:06+00:00,3,"
                "DATA_MANAGEMENT,ARCHIVE,128\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"usnjrnl2csv={reference}",
                        "--backlog-item",
                        "13",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["usn_field_comparison"]
            self.assertEqual(comparison["mode"], "usn-journal-field-diff")
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("usn", comparison["compared_canonical_fields"])
            self.assertIn("file_reference_number", comparison["compared_canonical_fields"])
            self.assertIn("reason", comparison["compared_canonical_fields"])
            self.assertIn("timestamp", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("usn-frn-reason-timestamp-field-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_fails_on_usn_reason_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-usn.json"
            reference = root / "usnjrnl.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "details": {
                                    "usn": 9001,
                                    "file_reference_number": 42,
                                    "file_name": "case.txt",
                                    "reason_flags": ["FILE_CREATE"],
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "USN,FRN,FileName,Reason\n"
                "9001,42,case.txt,FILE_DELETE\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"usnjrnl2csv={reference}",
                        "--backlog-item",
                        "13",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "failed")
            comparison = payload["comparisons"][0]["usn_field_comparison"]
            self.assertEqual(comparison["mismatch_count"], 1)
            self.assertEqual(comparison["mismatch_samples"][0]["field"], "reason")
            self.assertFalse(payload["cross_tool_validation_assessment"]["ready_for_validated_gate"])

    def test_cross_tool_validate_compares_srum_rows_against_srumecmd_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-srum.json"
            reference = root / "srumecmd.csv"
            output = root / "srum-cross-tool.json"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "srum-network-usage",
                                "details": {
                                    "srum_table_family": "network-usage",
                                    "row_id": 77,
                                    "app_id": r"C:\Program Files\App\agent.exe",
                                    "user_sid": "S-1-5-21-1-2-3-1001",
                                    "timestamp": "2024-04-05T06:07:08+00:00",
                                    "bytes_sent": 1200,
                                    "bytes_received": 3400,
                                    "source_offset": "0x4000",
                                    "decode_status": "export-row-imported",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ESEFamily,TableName,RowId,AppId,UserSid,Timestamp,BytesSent,BytesReceived,SourceOffset,DecodeStatus\n"
                r"srum,network-usage,77,C:\Program Files\App\agent.exe,S-1-5-21-1-2-3-1001,"
                "2024-04-05T06:07:08+00:00,1200,3400,0x4000,export-row-imported\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"srumecmd={reference}",
                        "--backlog-item",
                        "10",
                        "--min-overlap",
                        "1.0",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["ese_field_comparison"]
            self.assertEqual(comparison["mode"], "ese-srum-windows-edb-field-diff")
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("table_name", comparison["compared_canonical_fields"])
            self.assertIn("bytes_sent", comparison["compared_canonical_fields"])
            self.assertIn("bytes_received", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("ese-srum-row-field-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_compares_windows_edb_rows_against_search_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-windows-edb.json"
            reference = root / "winsearch.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "windows-search-edb-row-candidate",
                                "details": {
                                    "table_name": "SystemIndex_Gthr",
                                    "row_id": 501,
                                    "item_path": r"C:\Users\alice\Documents\report.docx",
                                    "timestamp": "2024-06-01T01:02:03+00:00",
                                    "deleted_state": False,
                                    "page_number": 88,
                                    "source_offset": "0x58000",
                                    "content_hash": "a" * 64,
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ESEFamily,TableName,RowId,ItemPath,Timestamp,Deleted,PageNumber,SourceOffset,ContentSHA256\n"
                r"windows-edb,SystemIndex_Gthr,501,C:\Users\alice\Documents\report.docx,"
                "2024-06-01T01:02:03+00:00,false,88,0x58000,"
                + "a" * 64
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"winsearchdbanalyzer={reference}",
                        "--backlog-item",
                        "11",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["ese_field_comparison"]
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("item_path", comparison["compared_canonical_fields"])
            self.assertIn("deleted_state", comparison["compared_canonical_fields"])
            self.assertIn("content_hash", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn("ese-windows-edb-row-field-diff-supported", profile["passed_validation_check_ids"])
            self.assertIn("ese-page-offset-deleted-state-diff-supported", profile["passed_validation_check_ids"])

    def test_cross_tool_validate_fails_on_windows_edb_deleted_state_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-windows-edb.json"
            reference = root / "winsearch.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "windows-search-edb-row-candidate",
                                "details": {
                                    "table_name": "SystemIndex_Gthr",
                                    "row_id": 501,
                                    "item_path": r"C:\Users\alice\Documents\report.docx",
                                    "deleted_state": False,
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ESEFamily,TableName,RowId,ItemPath,Deleted\n"
                r"windows-edb,SystemIndex_Gthr,501,C:\Users\alice\Documents\report.docx,true"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"winsearchdbanalyzer={reference}",
                        "--backlog-item",
                        "11",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "failed")
            comparison = payload["comparisons"][0]["ese_field_comparison"]
            self.assertEqual(comparison["mismatch_count"], 1)
            self.assertEqual(comparison["mismatch_samples"][0]["field"], "deleted_state")

    def test_cross_tool_validate_compares_jumplist_destlist_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-jumplist.json"
            reference = root / "jlecmd.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "jumplist-destlist-entry",
                                "details": {
                                    "artifact_family": "jumplist",
                                    "app_id": "f01b4d95cf55d32a",
                                    "entry_id": 3,
                                    "target_path": r"C:\Users\alice\Desktop\case.xlsx",
                                    "timestamp": "2024-07-01T02:03:04+00:00",
                                    "access_count": 5,
                                    "source_path": r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ArtifactFamily,AppId,DestListEntryNumber,TargetFilename,Timestamp,AccessCount,SourceFile\n"
                r"jumplist,f01b4d95cf55d32a,3,C:\Users\alice\Desktop\case.xlsx,"
                "2024-07-01T02:03:04+00:00,5,"
                r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"jlecmd={reference}",
                        "--backlog-item",
                        "14",
                        "--min-overlap",
                        "0.75",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["user_activity_field_comparison"]
            self.assertEqual(comparison["mode"], "user-activity-jumplist-shellbags-prefetch-lnk-field-diff")
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("app_id", comparison["compared_canonical_fields"])
            self.assertIn("target_path", comparison["compared_canonical_fields"])
            profile = payload["cross_tool_validation_assessment"]["functional_priority_profile"]
            self.assertIn(
                "user-activity-jumplist-shellbags-prefetch-lnk-field-diff-supported",
                profile["passed_validation_check_ids"],
            )

    def test_cross_tool_validate_compares_shellbags_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-shellbags.json"
            reference = root / "sbecmd.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "shellbags-bagmru-entry",
                                "details": {
                                    "artifact_family": "shellbags",
                                    "bag_path": r"Desktop\Cases",
                                    "mru_order": 2,
                                    "timestamp": "2024-08-09T10:11:12+00:00",
                                    "shell_item_type": "directory",
                                    "source_path": r"C:\Users\alice\NTUSER.DAT",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ArtifactFamily,BagPath,MRUOrder,LastAccessTime,ShellItemType,SourceFile\n"
                r"shellbags,Desktop\Cases,2,2024-08-09T10:11:12+00:00,directory,C:\Users\alice\NTUSER.DAT"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"shellbagsexplorer={reference}",
                        "--backlog-item",
                        "15",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["user_activity_field_comparison"]
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("bag_path", comparison["compared_canonical_fields"])
            self.assertIn("mru_order", comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_prefetch_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-prefetch.json"
            reference = root / "pecmd.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "windows-prefetch-entry",
                                "details": {
                                    "artifact_family": "prefetch",
                                    "target_path": r"C:\Windows\System32\cmd.exe",
                                    "file_name": "CMD.EXE-12345678.pf",
                                    "timestamp": "2024-09-01T01:02:03+00:00",
                                    "access_count": 9,
                                    "source_path": r"C:\Windows\Prefetch\CMD.EXE-12345678.pf",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ArtifactFamily,Path,FileName,LastRun,RunCount,SourceFile\n"
                r"prefetch,C:\Windows\System32\cmd.exe,CMD.EXE-12345678.pf,"
                r"2024-09-01T01:02:03+00:00,9,C:\Windows\Prefetch\CMD.EXE-12345678.pf"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"pecmd={reference}",
                        "--backlog-item",
                        "16",
                        "--min-overlap",
                        "0.75",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["user_activity_field_comparison"]
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("access_count", comparison["compared_canonical_fields"])
            self.assertIn("target_path", comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_lnk_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-lnk.json"
            reference = root / "lecmd.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "lnk-shelllink-entry",
                                "details": {
                                    "artifact_family": "lnk",
                                    "target_path": r"C:\Users\alice\Documents\case.docx",
                                    "file_name": "case.lnk",
                                    "timestamp": "2024-10-11T12:13:14+00:00",
                                    "tracker_guid": "{12345678-1234-1234-1234-1234567890ab}",
                                    "source_path": r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\case.lnk",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "ArtifactFamily,TargetPath,FileName,Timestamp,TrackerGuid,SourceFile\n"
                r"lnk,C:\Users\alice\Documents\case.docx,case.lnk,2024-10-11T12:13:14+00:00,"
                r"{12345678-1234-1234-1234-1234567890ab},C:\Users\alice\AppData\Roaming\Microsoft\Windows\Recent\case.lnk"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"lecmd={reference}",
                        "--backlog-item",
                        "17",
                        "--min-overlap",
                        "0.75",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["user_activity_field_comparison"]
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("tracker_guid", comparison["compared_canonical_fields"])
            self.assertIn("target_path", comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_windows_system_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-windows-system.json"
            reference = root / "velociraptor.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "windows-scheduled-task",
                                "details": {
                                    "artifact_family": "task",
                                    "task_uri": r"\SecurityUpdater",
                                    "command": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAAA",
                                    "principal": "SYSTEM",
                                    "trigger": "LogonTrigger",
                                    "source_path": r"C:\Windows\System32\Tasks\SecurityUpdater",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            reference.write_text(
                "Family,TaskURI,Command,Principal,Trigger,SourceFile\n"
                r"task,\SecurityUpdater,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAAA,"
                r"SYSTEM,LogonTrigger,C:\Windows\System32\Tasks\SecurityUpdater"
                "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"velociraptor={reference}",
                        "--backlog-item",
                        "18",
                        "--min-overlap",
                        "0.75",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparison = payload["comparisons"][0]["system_artifact_field_comparison"]
            self.assertGreaterEqual(comparison["common_record_count"], 1)
            self.assertEqual(comparison["mismatch_count"], 0)
            self.assertIn("task_uri", comparison["compared_canonical_fields"])
            self.assertIn("command", comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_browser_storage_and_timeline_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-browser.json"
            hindsight = root / "hindsight.csv"
            history = root / "browser-history.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "browser-summary",
                                "details": {
                                    "browser": "chrome",
                                    "profile": "Default",
                                    "storage_inventory": [
                                        {
                                            "storage_type": "cache",
                                            "storage_name": "Cache_Data",
                                            "relative_path": r"Cache\Cache_Data",
                                            "file_count": 2,
                                            "total_bytes": 4096,
                                            "sensitive": False,
                                        }
                                    ],
                                    "unified_timeline": [
                                        {
                                            "timeline_type": "visit",
                                            "timestamp": "2024-04-01T09:10:11+00:00",
                                            "url": "https://example.test/search?q=rapid",
                                            "title": "Example Search",
                                            "transition": "typed",
                                            "visit_count": 3,
                                            "source_table": "history",
                                            "source_index": 7,
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            hindsight.write_text(
                "Browser,Profile,Type,Name,RelativePath,FileCount,TotalBytes,Sensitive\n"
                r"chrome,Default,cache,Cache_Data,Cache\Cache_Data,2,4096,false"
                "\n",
                encoding="utf-8",
            )
            history.write_text(
                "Browser,Profile,Type,VisitTime,URL,Title,Transition,VisitCount,SourceTable,SourceIndex\n"
                "chrome,Default,visit,2024-04-01T09:10:11+00:00,https://example.test/search?q=rapid,"
                "Example Search,typed,3,history,7\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"hindsight={hindsight}",
                        "--reference-output",
                        f"browserhistoryview={history}",
                        "--backlog-item",
                        "19",
                        "--backlog-item",
                        "20",
                        "--min-overlap",
                        "0.75",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "pass")
            comparisons = {item["reference_name"]: item for item in payload["comparisons"]}
            storage_comparison = comparisons["hindsight"]["browser_storage_field_comparison"]
            timeline_comparison = comparisons["browserhistoryview"]["browser_timeline_field_comparison"]
            self.assertGreaterEqual(storage_comparison["common_record_count"], 1)
            self.assertEqual(storage_comparison["mismatch_count"], 0)
            self.assertIn("storage_type", storage_comparison["compared_canonical_fields"])
            self.assertGreaterEqual(timeline_comparison["common_record_count"], 1)
            self.assertEqual(timeline_comparison["mismatch_count"], 0)
            self.assertIn("url", timeline_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_ai_transcript_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-ai.json"
            service_export = root / "chatgpt-export.csv"
            rapid.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "ai-service-export-conversation",
                                "details": {
                                    "ai_service": "ChatGPT",
                                    "conversation_id": "conv-1",
                                    "conversation_title": "Incident response checklist",
                                    "transcript_pairs": [
                                        {
                                            "pair_id": "pair-1",
                                            "question": "What happened before the suspicious download?",
                                            "answer": "The interactive logon happened first.",
                                            "timestamp": "2024-04-01T09:10:11+00:00",
                                            "source_sha256s": ["a" * 64],
                                            "question_source_path": "Local Storage/leveldb/000003.log",
                                            "answer_source_path": "Local Storage/leveldb/000003.log",
                                            "question_source_offset": 128,
                                            "answer_source_offset": 256,
                                            "storage_area": "Local Storage",
                                            "pairing_confidence": "high-candidate",
                                        }
                                    ],
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            service_export.write_text(
                "Service,ConversationId,ConversationTitle,PairId,Question,Answer,Timestamp,SourceSha256s,"
                "QuestionSourcePath,AnswerSourcePath,QuestionSourceOffset,AnswerSourceOffset,StorageArea,PairingConfidence\n"
                f"chatgpt,conv-1,Incident response checklist,pair-1,"
                "What happened before the suspicious download?,The interactive logon happened first.,"
                f"2024-04-01T09:10:11+00:00,{('a' * 64)},"
                "Local Storage/leveldb/000003.log,Local Storage/leveldb/000003.log,128,256,Local Storage,high-candidate\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"serviceexport={service_export}",
                        "--backlog-item",
                        "21",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["ai_transcript_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("question", field_comparison["compared_canonical_fields"])
            self.assertIn("answer", field_comparison["compared_canonical_fields"])
            manifest = payload["cross_tool_validation_assessment"]["trusted_tool_diff_manifest"]
            self.assertIn("ai_transcript_field_comparison", manifest["comparison_summaries"][0]["field_diffs"])

    def test_cross_tool_validate_compares_mobile_vendor_export_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-mobile.json"
            cellebrite = root / "cellebrite.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "mobile-message",
                            "source_tool": "rapidtriage",
                            "source_record_id": "msg-001",
                            "service": "WhatsApp",
                            "conversation_id": "chat-7",
                            "message_id": "m-001",
                            "timestamp": "2024-04-01T09:10:11+00:00",
                            "sender": "+82 10-1234-5678",
                            "recipient": "alice@example.test",
                            "message_text_hash": "a" * 64,
                            "media_hash": "b" * 64,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            cellebrite.write_text(
                "SourceTool,SourceRecordId,Service,ConversationId,MessageId,Timestamp,Sender,Recipient,MessageTextHash,MediaHash\n"
                f"Cellebrite,msg-001,whatsapp,chat-7,m-001,2024-04-01T09:10:11+00:00,+821012345678,"
                f"alice@example.test,{('a' * 64)},{('b' * 64)}\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"cellebrite={cellebrite}",
                        "--backlog-item",
                        "26",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            comparison = payload["comparisons"][0]
            field_comparison = comparison["mobile_export_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("conversation_id", field_comparison["compared_canonical_fields"])
            manifest = payload["cross_tool_validation_assessment"]["trusted_tool_diff_manifest"]
            self.assertIn("mobile_export_field_comparison", manifest["comparison_summaries"][0]["field_diffs"])

    def test_cross_tool_validate_expands_nested_mobile_export_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-mobile-nested.json"
            cellebrite = root / "cellebrite.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "mobile-export-source",
                            "details": {
                                "source_tool": "rapidtriage",
                                "service": "WhatsApp",
                                "messages": [
                                    {
                                        "source_record_id": "msg-002",
                                        "conversation_id": "chat-8",
                                        "message_id": "m-002",
                                        "timestamp": "2024-04-02T09:10:11+00:00",
                                        "sender": "+82 10-2222-3333",
                                        "recipient": "bob@example.test",
                                        "message_text_hash": "e" * 64,
                                        "media_hash": "f" * 64,
                                    }
                                ],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            cellebrite.write_text(
                "SourceTool,SourceRecordId,Service,ConversationId,MessageId,Timestamp,Sender,Recipient,MessageTextHash,MediaHash\n"
                f"Cellebrite,msg-002,whatsapp,chat-8,m-002,2024-04-02T09:10:11+00:00,+821022223333,"
                f"bob@example.test,{('e' * 64)},{('f' * 64)}\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"cellebrite={cellebrite}",
                        "--backlog-item",
                        "26",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["mobile_export_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("message_text_hash", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_android_app_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-apk.json"
            apktool = root / "apktool.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "android-apk",
                            "package_name": "com.example.caseapp",
                            "app_label": "Case App",
                            "version_name": "1.2.3",
                            "version_code": 42,
                            "permission": ["android.permission.INTERNET", "android.permission.READ_SMS"],
                            "dangerous_permission_count": 1,
                            "cert_sha256": "c" * 64,
                            "apk_sha256": "d" * 64,
                            "dex_count": 2,
                            "native_library_count": 1,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            apktool.write_text(
                "PackageName,AppLabel,VersionName,VersionCode,Permissions,DangerousPermissionCount,CertSHA256,ApkSHA256,DexCount,NativeLibraryCount\n"
                "com.example.caseapp,case app,1.2.3,42,android.permission.INTERNET|android.permission.READ_SMS,"
                f"1,{('c' * 64)},{('d' * 64)},2,1\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"apktool={apktool}",
                        "--backlog-item",
                        "30",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            comparison = payload["comparisons"][0]
            field_comparison = comparison["mobile_app_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("package_name", field_comparison["compared_canonical_fields"])
            manifest = payload["cross_tool_validation_assessment"]["trusted_tool_diff_manifest"]
            self.assertIn("mobile_app_field_comparison", manifest["comparison_summaries"][0]["field_diffs"])

    def test_cross_tool_validate_expands_nested_android_manifest_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-apk-nested.json"
            apktool = root / "apktool.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "android-app-analysis",
                            "details": {
                                "apk_manifest": {
                                    "package_name": "com.example.nested",
                                    "app_label": "Nested App",
                                    "version_name": "2.0.0",
                                    "version_code": 99,
                                    "permission": [
                                        "android.permission.INTERNET",
                                        "android.permission.ACCESS_FINE_LOCATION",
                                    ],
                                    "dangerous_permission_count": 1,
                                    "cert_sha256": "1" * 64,
                                    "apk_sha256": "2" * 64,
                                    "dex_count": 3,
                                    "native_library_count": 2,
                                }
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            apktool.write_text(
                "PackageName,AppLabel,VersionName,VersionCode,Permissions,DangerousPermissionCount,CertSHA256,ApkSHA256,DexCount,NativeLibraryCount\n"
                "com.example.nested,nested app,2.0.0,99,android.permission.INTERNET|android.permission.ACCESS_FINE_LOCATION,"
                f"1,{('1' * 64)},{('2' * 64)},3,2\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"apktool={apktool}",
                        "--backlog-item",
                        "30",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["mobile_app_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("permission", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_expands_nested_android_app_data_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-app-data-nested.json"
            aleapp = root / "aleapp.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "android-app-data-source",
                            "package_name": "com.example.chat",
                            "details": {
                                "app_data_rows": [
                                    {
                                        "database": "/data/data/com.example.chat/databases/messages.db",
                                        "table_name": "messages",
                                        "indicator": "https://case.example/item/7",
                                        "risk_model": "network-artifact-pivot",
                                    }
                                ]
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            aleapp.write_text(
                "PackageName,Database,TableName,Indicator,RiskModel\n"
                "com.example.chat,/data/data/com.example.chat/databases/messages.db,messages,"
                "https://case.example/item/7,network-artifact-pivot\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"aleapp={aleapp}",
                        "--backlog-item",
                        "29",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["mobile_app_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("database", field_comparison["compared_canonical_fields"])
            self.assertIn("table_name", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_chat_app_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-chat.json"
            trusted = root / "whatsapp-export.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "whatsapp-message",
                            "service": "WhatsApp",
                            "conversation_id": "chat-7",
                            "message_id": "m-001",
                            "timestamp": "2024-04-01T09:10:11+00:00",
                            "sender": "+82 10-1234-5678",
                            "recipient": "alice@example.test",
                            "message_text_hash": "e" * 64,
                            "media_hash": "f" * 64,
                            "read_state": "read",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            trusted.write_text(
                "Service,ConversationId,MessageId,Timestamp,Sender,Recipient,MessageTextHash,MediaHash,ReadState\n"
                f"whatsapp,chat-7,m-001,2024-04-01T09:10:11+00:00,+821012345678,"
                f"alice@example.test,{('e' * 64)},{('f' * 64)},read\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"service-export={trusted}",
                        "--backlog-item",
                        "32",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["chat_app_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("conversation_id", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_email_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-email.json"
            trusted = root / "readpst.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "email-message",
                            "message_id": "<case-001@example.test>",
                            "subject": "Case Update",
                            "sent_at": "2024-04-01T09:10:11+00:00",
                            "sender": "bob@example.test",
                            "recipient": "alice@example.test",
                            "folder": "Inbox",
                            "attachment_count": 2,
                            "body_hash": "1" * 64,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            trusted.write_text(
                "InternetMessageId,Subject,Date,From,To,Folder,AttachmentCount,BodyHash\n"
                f"case-001@example.test,case update,2024-04-01T09:10:11+00:00,bob@example.test,"
                f"alice@example.test,Inbox,2,{('1' * 64)}\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"readpst={trusted}",
                        "--backlog-item",
                        "36",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["email_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("message_id", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_cloud_export_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-cloud.json"
            trusted = root / "takeout.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "cloud-file",
                            "provider": "google",
                            "product": "drive",
                            "record_id": "rec-1",
                            "item_id": "file-9",
                            "timestamp": "2024-04-01T09:10:11+00:00",
                            "actor": "alice@example.test",
                            "target": "/Drive/case.docx",
                            "action": "create",
                            "hash": "2" * 64,
                            "size": 4096,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            trusted.write_text(
                "Provider,Product,CloudRecordId,ItemId,Timestamp,Actor,Target,Action,Hash,Size\n"
                f"google,drive,rec-1,file-9,2024-04-01T09:10:11+00:00,alice@example.test,"
                f"/Drive/case.docx,create,{('2' * 64)},4096\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"takeout={trusted}",
                        "--backlog-item",
                        "37",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["cloud_export_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("record_id", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_compares_cloud_api_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-cloud-api.json"
            trusted = root / "graph-api.csv"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "cloud-api-response",
                            "request_id": "req-1",
                            "provider": "m365",
                            "endpoint": "https://graph.microsoft.com/v1.0/me/drive/root/children",
                            "method": "GET",
                            "status_code": 200,
                            "response_hash": "3" * 64,
                            "item_count": 5,
                            "page_token": "next-1",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            trusted.write_text(
                "RequestId,Provider,Endpoint,Method,StatusCode,ResponseHash,ItemCount,PageToken\n"
                f"req-1,m365,https://graph.microsoft.com/v1.0/me/drive/root/children,GET,200,{('3' * 64)},5,next-1\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "cross-tool-validate",
                        "--rapid-output",
                        str(rapid),
                        "--reference-output",
                        f"graph-api={trusted}",
                        "--backlog-item",
                        "40",
                        "--min-overlap",
                        "1.0",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            field_comparison = payload["comparisons"][0]["cloud_api_field_comparison"]
            self.assertEqual(payload["status"], "pass")
            self.assertGreaterEqual(field_comparison["common_record_count"], 1)
            self.assertEqual(field_comparison["mismatch_count"], 0)
            self.assertEqual(field_comparison["missing_common_field_count"], 0)
            self.assertIn("response_hash", field_comparison["compared_canonical_fields"])

    def test_cross_tool_validate_expands_nested_messaging_email_cloud_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)

            chat_rapid = root / "rapid-chat-nested.json"
            chat_trusted = root / "chat-export.csv"
            chat_rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "chat-export-source",
                            "details": {
                                "service": "Telegram",
                                "conversation_id": "chat-9",
                                "messages": [
                                    {
                                        "message_id": "m-009",
                                        "timestamp": "2024-04-01T09:10:11+00:00",
                                        "sender": "@alice",
                                        "recipient": "@bob",
                                        "message_text_hash": "4" * 64,
                                        "read_state": "read",
                                    }
                                ],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            chat_trusted.write_text(
                "Service,ConversationId,MessageId,Timestamp,Sender,Recipient,MessageTextHash,ReadState\n"
                f"telegram,chat-9,m-009,2024-04-01T09:10:11+00:00,@alice,@bob,{('4' * 64)},read\n",
                encoding="utf-8",
            )

            email_rapid = root / "rapid-email-nested.json"
            email_trusted = root / "email-export.csv"
            email_rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "email-mailbox-export",
                            "details": {
                                "mailbox": "case.pst",
                                "folder": "Inbox",
                                "messages": [
                                    {
                                        "message_id": "<nested-001@example.test>",
                                        "subject": "Nested Case",
                                        "sent_at": "2024-04-02T09:10:11+00:00",
                                        "sender": "carol@example.test",
                                        "recipient": "dan@example.test",
                                        "attachment_count": 1,
                                        "body_hash": "5" * 64,
                                    }
                                ],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            email_trusted.write_text(
                "InternetMessageId,Subject,Date,From,To,Mailbox,Folder,AttachmentCount,BodyHash\n"
                f"nested-001@example.test,nested case,2024-04-02T09:10:11+00:00,carol@example.test,"
                f"dan@example.test,case.pst,Inbox,1,{('5' * 64)}\n",
                encoding="utf-8",
            )

            cloud_rapid = root / "rapid-cloud-nested.json"
            cloud_trusted = root / "takeout-nested.csv"
            cloud_rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "cloud-export-source",
                            "details": {
                                "provider": "google",
                                "product": "drive",
                                "files": [
                                    {
                                        "record_id": "rec-2",
                                        "item_id": "file-10",
                                        "timestamp": "2024-04-03T09:10:11+00:00",
                                        "actor": "alice@example.test",
                                        "target": "/Drive/nested.docx",
                                        "action": "create",
                                        "hash": "6" * 64,
                                        "size": 8192,
                                    }
                                ],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            cloud_trusted.write_text(
                "Provider,Product,CloudRecordId,ItemId,Timestamp,Actor,Target,Action,Hash,Size\n"
                f"google,drive,rec-2,file-10,2024-04-03T09:10:11+00:00,alice@example.test,"
                f"/Drive/nested.docx,create,{('6' * 64)},8192\n",
                encoding="utf-8",
            )

            api_rapid = root / "rapid-api-nested.json"
            api_trusted = root / "api-nested.csv"
            api_rapid.write_text(
                json.dumps(
                    [
                        {
                            "artifact_type": "cloud-api-collection",
                            "details": {
                                "provider": "m365",
                                "endpoint": "https://graph.microsoft.com/v1.0/users",
                                "method": "GET",
                                "responses": [
                                    {
                                        "request_id": "req-2",
                                        "status_code": 200,
                                        "response_hash": "7" * 64,
                                        "item_count": 12,
                                        "page_token": "next-2",
                                    }
                                ],
                            },
                        }
                    ]
                ),
                encoding="utf-8",
            )
            api_trusted.write_text(
                "RequestId,Provider,Endpoint,Method,StatusCode,ResponseHash,ItemCount,PageToken\n"
                f"req-2,m365,https://graph.microsoft.com/v1.0/users,GET,200,{('7' * 64)},12,next-2\n",
                encoding="utf-8",
            )

            checks = [
                (chat_rapid, chat_trusted, "service-export", "32", "chat_app_field_comparison", "message_text_hash"),
                (email_rapid, email_trusted, "readpst", "36", "email_field_comparison", "body_hash"),
                (cloud_rapid, cloud_trusted, "takeout", "37", "cloud_export_field_comparison", "record_id"),
                (api_rapid, api_trusted, "graph-api", "40", "cloud_api_field_comparison", "response_hash"),
            ]
            for rapid_output, trusted_output, tool_name, backlog_item, comparison_key, expected_field in checks:
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(
                        [
                            "cross-tool-validate",
                            "--rapid-output",
                            str(rapid_output),
                            "--reference-output",
                            f"{tool_name}={trusted_output}",
                            "--backlog-item",
                            backlog_item,
                            "--min-overlap",
                            "1.0",
                            "--json",
                        ]
                    )

                self.assertEqual(exit_code, 0)
                payload = json.loads(stdout.getvalue())
                field_comparison = payload["comparisons"][0][comparison_key]
                self.assertEqual(payload["status"], "pass")
                self.assertGreaterEqual(field_comparison["common_record_count"], 1)
                self.assertEqual(field_comparison["mismatch_count"], 0)
                self.assertEqual(field_comparison["missing_common_field_count"], 0)
                self.assertIn(expected_field, field_comparison["compared_canonical_fields"])

    def test_image_workflow_validate_command_emits_trusted_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            rapid = root / "rapid-e01.json"
            trusted = root / "ewfverify.csv"
            output = root / "image-diff.json"
            rapid.write_text(
                json.dumps(
                    [
                        {
                            "details": {
                                "source_path": "case.E01",
                                "source_integrity": {"sha256": "a" * 64},
                                "partition_selection": {"selected_start_sector": 2048},
                                "recovery_mode": "partition-offset",
                            }
                        }
                    ]
                ),
                encoding="utf-8",
            )
            trusted.write_text(
                "SourcePath,SHA256,StartSector,Workflow\n"
                f"case.E01,{('a' * 64)},2048,partition-offset\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "image-workflow-validate",
                        "--item-number",
                        "22",
                        "--rapid-output",
                        str(rapid),
                        "--trusted-output",
                        str(trusted),
                        "--trusted-tool",
                        "ewfverify",
                        "--output",
                        str(output),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["command"], "image-workflow-validate")
            self.assertEqual(payload["gap_id"], "#22")
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["trusted_tool"], "ewfverify")
            self.assertEqual(payload["matched_count"], 1)
            self.assertTrue(payload["commercial_grade_evidence"])
            self.assertTrue(output.is_file())

    def test_confidence_explainability_and_reproducibility_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            artifacts = root / "artifacts.json"
            summary = root / "rapidtriage-run-summary.json"
            dashboard = root / "confidence.json"
            explain_json = root / "explain.json"
            explain_md = root / "explain.md"
            repro_dir = root / "repro"
            artifacts.write_text(
                json.dumps(
                    {
                        "command": "artifacts",
                        "artifacts": [
                            {
                                "provider": "eventlog",
                                "artifact_type": "eventlog-record",
                                "path": "/case/Security.evtx",
                                "details": {
                                    "parser": "eventlog",
                                    "parser_version": "test",
                                    "source_path": "/case/Security.evtx",
                                    "parser_confidence": 0.92,
                                    "reportability": "report-grade",
                                    "validation_required": False,
                                    "commercial_grade_ready": True,
                                    "record_offset": 128,
                                    "hashes": {"sha256": "a" * 64},
                                },
                            },
                            {
                                "provider": "eventlog",
                                "artifact_type": "eventlog-record-candidate",
                                "path": "/case/Security.evtx",
                                "details": {
                                    "parser": "eventlog",
                                    "source_path": "/case/Security.evtx",
                                    "parser_confidence": 0.4,
                                    "validation_required": True,
                                    "commercial_grade_ready": False,
                                },
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            summary.write_text(
                json.dumps(
                    {
                        "command": "run",
                        "generated_at": "2026-04-29T00:00:00+00:00",
                        "outputs": {
                            "summary": str(summary),
                            "artifacts_eventlog": str(artifacts),
                        },
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                dashboard_exit = main(["confidence-dashboard", str(summary), "--output", str(dashboard), "--json"])
            with contextlib.redirect_stdout(io.StringIO()):
                explain_exit = main(
                    [
                        "parser-explainability",
                        str(summary),
                        "--output",
                        str(explain_json),
                        "--markdown-output",
                        str(explain_md),
                    ]
                )
                repro_exit = main(
                    [
                        "reproducibility-kit",
                        "--baseline-run",
                        str(summary),
                        "--candidate-run",
                        str(summary),
                        "--output-dir",
                        str(repro_dir),
                    ]
                )

            self.assertEqual(dashboard_exit, 0)
            self.assertEqual(explain_exit, 0)
            self.assertEqual(repro_exit, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["summary"]["confidence_counts"]["report-grade"], 1)
            self.assertEqual(payload["summary"]["confidence_counts"]["needs-validation"], 1)
            self.assertTrue(dashboard.is_file())
            explain = json.loads(explain_json.read_text(encoding="utf-8"))
            self.assertEqual(explain["summary"]["entry_count"], 2)
            self.assertTrue(explain_md.is_file())
            repro = json.loads((repro_dir / "rapidtriage-reproducibility-kit.json").read_text(encoding="utf-8"))
            self.assertEqual(repro["status"], "reproducible")
            self.assertEqual(repro["summary"]["diff_count"], 0)

    def test_case_catalog_adds_exports_and_imports_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            sample = run_sample_workflow(root / "sample", overwrite=True, read_only=True)
            training_manifest_path = Path(sample["run"]["training_lab_manifest"])
            self.assertTrue(training_manifest_path.is_file())
            training_manifest = json.loads(training_manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(training_manifest["profile_version"], "training-lab-workflow-manifest-v1")
            self.assertEqual(training_manifest["commercial_item_number"], 67)
            self.assertEqual(training_manifest["missing_required_outputs"], [])
            self.assertEqual(len(training_manifest["manifest_hash"]), 64)
            self.assertIn("password", training_manifest["expected_keywords"])
            self.assertIn("source preview", training_manifest["viewer_exercise"]["required_viewers"])
            self.assertIn(
                "analyst-scoring-rubric-results-not-attached",
                training_manifest["external_training_blockers"],
            )
            catalog_path = root / "catalog.json"
            archive_path = root / "CASE-CATALOG.zip"
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                add_exit = main(
                    [
                        "case-catalog",
                        "--catalog",
                        str(catalog_path),
                        "--add-run",
                        str(sample["run"]["output_dir"]),
                        "--case-id",
                        "CASE-CATALOG",
                        "--name",
                        "Catalog Case",
                        "--list",
                        "--json",
                    ]
                )
            with contextlib.redirect_stdout(io.StringIO()):
                export_exit = main(
                    [
                        "case-catalog",
                        "--catalog",
                        str(catalog_path),
                        "--export",
                        "CASE-CATALOG",
                        "--archive",
                        str(archive_path),
                    ]
                )
            imported_catalog_path = root / "imported-catalog.json"
            with contextlib.redirect_stdout(io.StringIO()):
                import_exit = main(
                    [
                        "case-catalog",
                        "--catalog",
                        str(imported_catalog_path),
                        "--import",
                        str(archive_path),
                    ]
                )

            self.assertEqual(add_exit, 0)
            self.assertEqual(export_exit, 0)
            self.assertEqual(import_exit, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["cases"][0]["case_id"], "CASE-CATALOG")
            self.assertEqual(payload["cases"][0]["runs"][0]["mode"], "fraud")
            self.assertTrue(archive_path.is_file())
            imported = json.loads(imported_catalog_path.read_text(encoding="utf-8"))
            self.assertEqual(imported["cases"][0]["case_id"], "CASE-CATALOG")

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage operations API tests")
    def test_api_auth_token_protects_api_routes(self) -> None:
        client = TestClient(create_app(RunJobStore(), auth_token="secret"))

        self.assertEqual(client.get("/api/health").status_code, 401)
        self.assertEqual(client.get("/api/health", headers={"X-RapidTriage-Token": "secret"}).status_code, 200)
        query_token_response = client.get("/api/health", params={"token": "secret"})
        self.assertEqual(query_token_response.status_code, 401)
        self.assertIn("query token authentication is disabled", query_token_response.json()["detail"])
        self.assertEqual(client.get("/").status_code, 200)

    def test_non_localhost_web_binding_requires_auth_or_explicit_override(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "non-localhost"):
            run_web_server("0.0.0.0", 8765)

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage operations API tests")
    def test_run_jobs_include_step_status_for_recovery_visibility(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "missing"
            output_dir = Path(tmp_dir) / "run-out"
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "not-a-mode",
                    "output_dir": str(output_dir),
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 202)
            payload = response.json()
            self.assertEqual(payload["status"], "failed")
            step_statuses = {step["name"]: step["status"] for step in payload["steps"]}
            self.assertEqual(step_statuses["prepare"], "completed")
            self.assertEqual(step_statuses["triage"], "failed")
            self.assertEqual(step_statuses["finalize"], "skipped")

    def test_run_job_store_can_cancel_queued_and_retry_failed_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = RunJobStore(max_workers=1, state_path=Path(tmp_dir) / "runs.json")
            failed = store.run_sync(
                RunRequest(
                    root=str(Path(tmp_dir) / "missing"),
                    mode="not-a-mode",
                    output_dir=str(Path(tmp_dir) / "run-out"),
                )
            )

            retry = store.retry(failed.run_id)
            canceled = store.cancel(retry.run_id)
            store._executor.shutdown(wait=True)

            self.assertEqual(failed.status, "failed")
            self.assertEqual(retry.retry_of_run_id, failed.run_id)
            self.assertEqual(retry.retry_attempt, 1)
            self.assertEqual(failed.error_type, "RunModeError")
            self.assertEqual(failed.to_dict()["error_type"], "RunModeError")
            self.assertTrue(
                any(item["event_type"] == "run-sync-exception-observed" for item in failed.transition_log)
            )
            self.assertIn(canceled.status, {"queued", "running", "canceled", "failed"})
            self.assertTrue(canceled.cancellation_requested)
            self.assertIn("#69", canceled.to_dict()["job_queue_assessment"]["commercial_gap_ids"])
            self.assertEqual(canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["gap_id"], "#69")
            self.assertIn("step progress recorded", canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("transition log recorded", canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("job persistence manifest hash emitted", canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("job execution manifest hash emitted", canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "job queue report-grade validation plan emitted",
                canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "job queue report-grade ready slots emitted",
                canceled.to_dict()["job_queue_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(canceled.to_dict()["transition_log_profile"]["profile_version"], "job-transition-log-profile-v1")
            self.assertGreater(canceled.to_dict()["transition_log_profile"]["transition_count"], 0)
            self.assertEqual(canceled.to_dict()["job_persistence_manifest"]["profile_version"], "job-persistence-manifest-v1")
            self.assertEqual(canceled.to_dict()["job_persistence_manifest"]["item_number"], 27)
            self.assertEqual(len(canceled.to_dict()["job_persistence_manifest"]["manifest_hash"]), 64)
            self.assertTrue(canceled.to_dict()["job_persistence_manifest"]["state_file_persisted"])
            self.assertGreaterEqual(canceled.to_dict()["job_persistence_manifest"]["progress_percent"], 0)
            self.assertEqual(canceled.to_dict()["job_queue_execution_manifest"]["profile_version"], "job-queue-execution-manifest-v1")
            self.assertEqual(canceled.to_dict()["job_queue_execution_manifest"]["item_number"], 69)
            self.assertEqual(canceled.to_dict()["job_queue_execution_manifest"]["gap_id"], "#69")
            self.assertEqual(len(canceled.to_dict()["job_queue_execution_manifest"]["manifest_hash"]), 64)
            self.assertGreater(canceled.to_dict()["job_queue_execution_manifest"]["transition_row_count"], 0)
            self.assertGreater(canceled.to_dict()["job_queue_execution_manifest"]["step_row_count"], 0)
            self.assertRegex(canceled.to_dict()["job_queue_execution_manifest"]["transition_head_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(canceled.to_dict()["job_queue_execution_manifest"]["step_head_hash"], r"^[0-9a-f]{64}$")
            assessment = canceled.to_dict()["job_queue_assessment"]
            validation_plan = assessment["job_queue_report_grade_validation_plan"]
            self.assertEqual(validation_plan["profile_version"], "job-queue-report-grade-validation-plan-v1")
            self.assertEqual(validation_plan["item_number"], 69)
            self.assertEqual(validation_plan["gap_id"], "#69")
            self.assertEqual(len(validation_plan["validation_plan_hash"]), 64)
            self.assertEqual(validation_plan["ready_slot_count"], 6)
            self.assertEqual(validation_plan["blocking_slot_count"], 6)
            self.assertFalse(validation_plan["commercial_claim_allowed"])
            self.assertTrue(validation_plan["local_threadpool_only"])
            self.assertFalse(validation_plan["distributed_queue"])
            self.assertIn("distributed-worker-execution-required", validation_plan["blockers"])
            self.assertIn(
                "job-execution-transition-rows",
                {slot["slot_id"] for slot in validation_plan["ready_slots"]},
            )
            self.assertIn(
                "job-external-trusted-transition-log",
                {slot["slot_id"] for slot in validation_plan["blocking_slots"]},
            )
            self.assertEqual(
                assessment["job_queue_report_grade_validation_plan_hash"],
                validation_plan["validation_plan_hash"],
            )
            self.assertEqual(assessment["report_grade_ready_slot_count"], 6)
            self.assertEqual(assessment["report_grade_blocking_slot_count"], 6)
            self.assertEqual(
                validation_plan["persistence_manifest_hash"],
                canceled.to_dict()["job_persistence_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                validation_plan["execution_manifest_hash"],
                canceled.to_dict()["job_queue_execution_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                validation_plan["transition_head_hash"],
                canceled.to_dict()["transition_log_profile"]["head_hash"],
            )
            self.assertEqual(
                validation_plan["step_head_hash"],
                canceled.to_dict()["job_queue_execution_manifest"]["step_head_hash"],
            )
            self.assertEqual(
                canceled.to_dict()["job_queue_assessment"]["persistence_manifest"]["manifest_hash"],
                canceled.to_dict()["job_persistence_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                canceled.to_dict()["job_queue_assessment"]["execution_manifest_hash"],
                canceled.to_dict()["job_queue_execution_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                canceled.to_dict()["job_queue_assessment"]["transition_log_profile"]["head_hash"],
                canceled.to_dict()["transition_log_profile"]["head_hash"],
            )
            event_types = {entry["event_type"] for entry in canceled.to_dict()["transition_log"]}
            self.assertIn("job-retry-queued", event_types)
            self.assertIn("cancel-requested", event_types)
            self.assertIn("#80", canceled.to_dict()["cancellation_retry_assessment"]["commercial_gap_ids"])
            self.assertEqual(canceled.to_dict()["cancellation_retry_assessment"]["core_accuracy_gates"][0]["gap_id"], "#80")
            self.assertIn(
                "failed/canceled retry support",
                canceled.to_dict()["cancellation_retry_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(canceled.to_dict()["retry_lineage_profile"]["profile_version"], "job-retry-lineage-profile-v1")
            self.assertEqual(canceled.to_dict()["retry_lineage_profile"]["retry_of_run_id"], failed.run_id)
            self.assertEqual(canceled.to_dict()["partial_output_policy"]["profile_version"], "job-partial-output-policy-v1")
            self.assertEqual(canceled.to_dict()["partial_output_policy"]["partial_output_cleanup_status"], "preserved-not-cleaned")
            self.assertFalse(canceled.to_dict()["partial_output_policy"]["safe_to_auto_delete_partial_outputs"])
            self.assertTrue(canceled.to_dict()["partial_output_policy"]["review_required_before_cleanup"])
            self.assertTrue(canceled.to_dict()["partial_output_policy"]["cleanup_validation_required"])
            self.assertRegex(canceled.to_dict()["partial_output_policy"]["known_output_head_hash"], r"^[0-9a-f]{64}$")
            cancel_manifest = canceled.to_dict()["cancellation_retry_assessment"]["cancellation_retry_manifest"]
            self.assertEqual(cancel_manifest["profile"], "cancellation-retry-manifest-v1")
            self.assertEqual(cancel_manifest["profile_version"], "cancellation-retry-manifest-v1")
            self.assertEqual(cancel_manifest["retry_of_run_id"], failed.run_id)
            self.assertEqual(cancel_manifest["retry_attempt"], 1)
            self.assertEqual(len(cancel_manifest["manifest_hash"]), 64)
            self.assertEqual(cancel_manifest["partial_output_cleanup_status"], "preserved-not-cleaned")
            self.assertTrue(cancel_manifest["partial_output_review_required"])
            self.assertTrue(cancel_manifest["cleanup_validation_required"])
            self.assertFalse(cancel_manifest["safe_to_auto_delete_partial_outputs"])
            self.assertEqual(
                cancel_manifest["retry_lineage_hash"],
                canceled.to_dict()["retry_lineage_profile"]["lineage_hash"],
            )
            cancel_validation_plan = canceled.to_dict()["cancellation_retry_assessment"][
                "cancellation_retry_report_grade_validation_plan"
            ]
            self.assertEqual(
                cancel_validation_plan["profile_version"],
                "cancellation-retry-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                canceled.to_dict()["cancellation_retry_assessment"][
                    "cancellation_retry_report_grade_validation_plan_hash"
                ],
                cancel_validation_plan["validation_plan_hash"],
            )
            self.assertEqual(cancel_validation_plan["manifest_hash"], cancel_manifest["manifest_hash"])
            self.assertEqual(cancel_validation_plan["retry_lineage_hash"], cancel_manifest["retry_lineage_hash"])
            self.assertEqual(
                cancel_validation_plan["partial_output_policy_hash"],
                cancel_manifest["partial_output_policy_hash"],
            )
            self.assertEqual(canceled.to_dict()["cancellation_retry_assessment"]["report_grade_ready_slot_count"], 6)
            self.assertEqual(canceled.to_dict()["cancellation_retry_assessment"]["report_grade_blocking_slot_count"], 6)
            self.assertEqual(
                cancel_manifest["transition_evidence"]["transition_head_hash"],
                canceled.to_dict()["transition_log_profile"]["head_hash"],
            )
            self.assertRegex(cancel_manifest["step_status_head_hash"], r"^[0-9a-f]{64}$")
            self.assertIn(
                "retry lineage manifest emitted",
                canceled.to_dict()["cancellation_retry_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "cancellation/retry manifest hash emitted",
                canceled.to_dict()["cancellation_retry_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "cancellation/retry report-grade validation plan emitted",
                canceled.to_dict()["cancellation_retry_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "cancellation/retry report-grade ready slots emitted",
                canceled.to_dict()["cancellation_retry_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                canceled.to_dict()["cancellation_retry_assessment"]["trusted_cancellation_retry_diff"]["status"],
                "missing",
            )
            self.assertIn(
                "trusted-cancellation-retry-transition-diff-missing",
                canceled.to_dict()["cancellation_retry_assessment"]["blockers"],
            )
            self.assertTrue(all("#69" in step["commercial_gap_ids"] for step in canceled.to_dict()["steps"]))
            self.assertTrue(all(step["core_accuracy_gates"][0]["gap_id"] == "#69" for step in canceled.to_dict()["steps"]))
            self.assertTrue(all("#80" in step["operational_gap_ids"] for step in canceled.to_dict()["steps"]))
            queue_uplift = canceled.to_dict()["job_queue_assessment"]["commercial_uplift_evidence"]
            self.assertEqual(queue_uplift["batch_id"], "commercial-uplift-066-070")
            self.assertEqual(queue_uplift["item_numbers"], [69])
            self.assertIn("transition log recorded", queue_uplift["passed_validation_check_ids"])
            self.assertIn("job execution manifest emitted", queue_uplift["passed_validation_check_ids"])
            self.assertIn("job queue report-grade validation plan emitted", queue_uplift["passed_validation_check_ids"])
            self.assertIn("local-threadpool limitation", " ".join(queue_uplift["large_data_controls"]))
            self.assertIn("progress percent", " ".join(queue_uplift["large_data_controls"]))
            self.assertIn("execution manifest hashes", " ".join(queue_uplift["large_data_controls"]))
            self.assertIn("report-grade validation plan", " ".join(queue_uplift["large_data_controls"]))
            self.assertIn("trusted-job-transition-log-diff-missing", queue_uplift["remaining_external_validation"])
            self.assertEqual(
                queue_uplift["reportability_decision"]["decision"],
                "do-not-report-job-queue-as-distributed-parser-scheduler",
            )
            job_payload = canceled.to_dict()
            job_diff = build_job_queue_trusted_diff(job_payload, job_payload)
            job_gates = job_queue_core_accuracy_gates(
                status=job_payload["status"],
                steps=job_payload["steps"],
                state_persisted=True,
                cancellation_requested=job_payload["cancellation_requested"],
                persistence_manifest=job_payload["job_persistence_manifest"],
                execution_manifest=job_payload["job_queue_execution_manifest"],
                validation_plan=validation_plan,
                trusted_diff=job_diff,
            )
            self.assertEqual(job_diff["status"], "pass")
            self.assertIn("trusted job transition-log diff pass", job_gates[0]["satisfied_checks"])
            self.assertIn("job queue report-grade validation plan emitted", job_gates[0]["satisfied_checks"])
            cancel_diff = build_cancellation_retry_trusted_diff(job_payload, job_payload)
            cancel_assessment = cancellation_retry_assessment(canceled, trusted_diff=cancel_diff)
            self.assertEqual(cancel_diff["status"], "pass")
            self.assertIn("manifest_hash", cancel_diff["compared_fields"])
            self.assertIn("step_status_head_hash", cancel_diff["compared_fields"])
            self.assertIn("partial_output_cleanup_status", cancel_diff["compared_fields"])
            self.assertIn(
                "trusted cancellation/retry transition diff pass",
                cancel_assessment["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "cancellation/retry report-grade validation plan emitted",
                cancel_assessment["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                cancel_assessment["cancellation_retry_report_grade_validation_plan"]["trusted_diff_status"],
                "pass",
            )
            self.assertTrue(
                all(step["commercial_uplift_evidence"]["batch_id"] == "commercial-uplift-066-070" for step in canceled.to_dict()["steps"])
            )
    def test_build_release_script_can_assemble_portable_zip_without_building_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "release"
            result = subprocess.run(
                [
                    "python",
                    "scripts/build-release.py",
                    "--output-dir",
                    str(output_dir),
                    "--skip-build",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((output_dir / "rapidtriage-portable.zip").is_file())
            self.assertTrue((output_dir / "SHA256SUMS").is_file())
            self.assertTrue((output_dir / "dependency-inventory.txt").is_file())
            self.assertTrue((output_dir / "release-manifest.json").is_file())
            self.assertTrue((output_dir / "update-manifest.json").is_file())
            self.assertTrue((output_dir / "packaging-plan.json").is_file())
            self.assertTrue((output_dir / "packaging-plan.md").is_file())
            self.assertTrue((output_dir / "rapidtriage-commercial-readiness.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-commercial-readiness.md").is_file())
            with zipfile.ZipFile(output_dir / "rapidtriage-portable.zip") as archive:
                names = set(archive.namelist())
            self.assertIn("scripts/start-rapidtriage.sh", names)
            self.assertIn("scripts/smoke-test-rapidtriage.sh", names)
            self.assertIn("scripts/summarize-smoke.py", names)
            self.assertIn("scripts/verify-release-evidence.py", names)
            self.assertIn("scripts/check-dependencies.py", names)
            self.assertIn("scripts/crash-export-smoke.py", names)
            self.assertIn("scripts/crash-redaction-review.py", names)
            self.assertIn("scripts/parser-sandbox-smoke.py", names)
            self.assertIn("scripts/security-hardening-review.py", names)
            self.assertIn("scripts/external-release-evidence-template.py", names)
            self.assertIn("scripts/hostile-evidence-containment-template.py", names)
            self.assertIn("scripts/independent-operations-evidence-template.py", names)
            self.assertIn("scripts/windows/start-rapidtriage.ps1", names)
            self.assertIn("scripts/windows/smoke-test-rapidtriage.ps1", names)
            self.assertIn("scripts/windows/smoke-test-rapidtriage.bat", names)
            self.assertIn("docs/rapidtriage-macos-linux-quickstart.md", names)
            self.assertIn("docs/rapidtriage-fresh-machine-smoke-test.md", names)
            self.assertIn("docs/rapidtriage-sample-case.md", names)
            self.assertIn("docs/rapidtriage-support-sla.md", names)
            self.assertIn("docs/rapidtriage-lts-hotfix-policy.md", names)
            self.assertIn("docs/rapidtriage-training-curriculum.md", names)
            self.assertIn("docs/rapidtriage-admin-deployment-guide.md", names)
            self.assertIn("docs/rapidtriage-commercial-parity-backlog.md", names)
            checksums = (output_dir / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("rapidtriage-portable.zip", checksums)
            self.assertIn("dependency-inventory.txt", checksums)
            self.assertIn("release-manifest.json", checksums)
            self.assertIn("update-manifest.json", checksums)
            self.assertIn("packaging-plan.json", checksums)
            self.assertIn("rapidtriage-commercial-readiness.json", checksums)
            manifest = json.loads((output_dir / "release-manifest.json").read_text(encoding="utf-8"))
            artifact_names = {item["name"] for item in manifest["artifacts"]}
            self.assertIn("rapidtriage-portable.zip", artifact_names)
            self.assertEqual(manifest["commercial_readiness"]["status"], "commercial-gaps-present")
            self.assertFalse(manifest["commercial_readiness"]["commercial_claim_allowed"])
            self.assertIn("#101", manifest["commercialization_gap_ids"])
            self.assertIn("#120", manifest["commercialization_gap_ids"])
            self.assertIn("#101", manifest["package_readiness"]["windows_signed_installer"]["commercial_gap_ids"])
            self.assertEqual(manifest["package_readiness"]["windows_signed_installer"]["core_accuracy_gates"][0]["gap_id"], "#101")
            windows_signing_manifest = manifest["package_readiness"]["windows_signed_installer"][
                "windows_signing_evidence_manifest"
            ]
            self.assertEqual(windows_signing_manifest["profile_version"], "windows-signing-evidence-manifest-v1")
            self.assertEqual(len(windows_signing_manifest["manifest_hash"]), 64)
            self.assertEqual(len(windows_signing_manifest["evidence_slot_matrix_hash"]), 64)
            self.assertEqual(
                manifest["package_readiness"]["windows_signed_installer"]["evidence_slot_matrix_hash"],
                windows_signing_manifest["evidence_slot_matrix_hash"],
            )
            self.assertEqual(windows_signing_manifest["evidence_slot_matrix"]["profile_version"], "release-evidence-slot-matrix-v1")
            self.assertEqual(
                manifest["package_readiness"]["windows_signed_installer"]["windows_signing_evidence_manifest_hash"],
                windows_signing_manifest["manifest_hash"],
            )
            windows_workflow_manifest = manifest["package_readiness"]["windows_signed_installer"][
                "windows_installer_workflow_manifest"
            ]
            self.assertEqual(
                windows_workflow_manifest["profile_version"],
                "windows-installer-workflow-manifest-v1",
            )
            self.assertEqual(windows_workflow_manifest["item_number"], 57)
            self.assertEqual(len(windows_workflow_manifest["manifest_hash"]), 64)
            self.assertEqual(
                manifest["package_readiness"]["windows_signed_installer"][
                    "windows_installer_workflow_manifest_hash"
                ],
                windows_workflow_manifest["manifest_hash"],
            )
            self.assertIn("rapidtriage-setup.exe", windows_workflow_manifest["target_outputs"])
            self.assertIn("installer_wrapper_log", windows_workflow_manifest["evidence_slots"])
            self.assertIn("authenticode-signature-not-attached", windows_workflow_manifest["blockers"])
            windows_report_grade_plan = manifest["package_readiness"]["windows_signed_installer"][
                "windows_signing_report_grade_validation_plan"
            ]
            self.assertEqual(
                windows_report_grade_plan["profile_version"],
                "windows-signing-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                manifest["package_readiness"]["windows_signed_installer"][
                    "windows_signing_report_grade_validation_plan_hash"
                ],
                windows_report_grade_plan["validation_plan_sha256"],
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["windows_signed_installer"][
                    "windows_signing_report_grade_ready_slot_count"
                ],
                7,
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["windows_signed_installer"][
                    "windows_signing_report_grade_blocking_slot_count"
                ],
                6,
            )
            self.assertIn("authenticode-signature-required", windows_report_grade_plan["blockers"])
            self.assertTrue(windows_signing_manifest["release_artifact_hashes"])
            self.assertIn("signature_log", manifest["package_readiness"]["windows_signed_installer"]["signing_slots"])
            self.assertIn(
                "windows signing evidence manifest hash emitted",
                manifest["package_readiness"]["windows_signed_installer"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "windows signing report-grade validation plan",
                manifest["package_readiness"]["windows_signed_installer"]["core_accuracy_gates"][0][
                    "satisfied_checks"
                ],
            )
            self.assertIn(
                "windows evidence slot matrix hash emitted",
                manifest["package_readiness"]["windows_signed_installer"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                manifest["package_readiness"]["windows_signed_installer"]["functional_priority_profile"]["item_number"],
                57,
            )
            self.assertFalse(
                manifest["package_readiness"]["windows_signed_installer"]["functional_priority_profile"][
                    "implemented_controls"
                ]["authenticode_signature_attached"]
            )
            self.assertTrue(
                manifest["package_readiness"]["windows_signed_installer"]["functional_priority_profile"][
                    "implemented_controls"
                ]["installer_workflow_manifest_declared"]
            )
            self.assertEqual(manifest["package_readiness"]["windows_signed_installer"]["trusted_windows_signing_diff"]["status"], "missing")
            self.assertIn(
                "trusted-windows-signing-evidence-diff-missing",
                manifest["package_readiness"]["windows_signed_installer"]["blockers"],
            )
            self.assertIn(
                "authenticode-signature-required",
                manifest["package_readiness"]["windows_signed_installer"]["blockers"],
            )
            self.assertIn("#102", manifest["package_readiness"]["macos_notarized_package"]["commercial_gap_ids"])
            self.assertEqual(manifest["package_readiness"]["macos_notarized_package"]["core_accuracy_gates"][0]["gap_id"], "#102")
            macos_notarization_manifest = manifest["package_readiness"]["macos_notarized_package"][
                "macos_notarization_evidence_manifest"
            ]
            self.assertEqual(
                macos_notarization_manifest["profile_version"],
                "macos-notarization-evidence-manifest-v1",
            )
            self.assertEqual(len(macos_notarization_manifest["manifest_hash"]), 64)
            self.assertEqual(len(macos_notarization_manifest["evidence_slot_matrix_hash"]), 64)
            self.assertEqual(
                manifest["package_readiness"]["macos_notarized_package"]["evidence_slot_matrix_hash"],
                macos_notarization_manifest["evidence_slot_matrix_hash"],
            )
            macos_workflow_manifest = manifest["package_readiness"]["macos_notarized_package"][
                "macos_package_workflow_manifest"
            ]
            self.assertEqual(
                macos_workflow_manifest["profile_version"],
                "macos-package-workflow-manifest-v1",
            )
            self.assertEqual(macos_workflow_manifest["item_number"], 59)
            self.assertEqual(len(macos_workflow_manifest["manifest_hash"]), 64)
            self.assertEqual(
                manifest["package_readiness"]["macos_notarized_package"]["macos_package_workflow_manifest_hash"],
                macos_workflow_manifest["manifest_hash"],
            )
            self.assertIn("rapidtriage.dmg", macos_workflow_manifest["target_outputs"])
            self.assertIn("pkg_dmg_build_log", macos_workflow_manifest["evidence_slots"])
            self.assertIn("notarization-ticket-not-attached", macos_workflow_manifest["blockers"])
            macos_report_grade_plan = manifest["package_readiness"]["macos_notarized_package"][
                "macos_notarization_report_grade_validation_plan"
            ]
            self.assertEqual(
                macos_report_grade_plan["profile_version"],
                "macos-notarization-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                manifest["package_readiness"]["macos_notarized_package"][
                    "macos_notarization_report_grade_validation_plan_hash"
                ],
                macos_report_grade_plan["validation_plan_sha256"],
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["macos_notarized_package"][
                    "macos_notarization_report_grade_ready_slot_count"
                ],
                7,
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["macos_notarized_package"][
                    "macos_notarization_report_grade_blocking_slot_count"
                ],
                7,
            )
            self.assertIn("notarytool-submission-proof-required", macos_report_grade_plan["blockers"])
            self.assertEqual(
                manifest["package_readiness"]["macos_notarized_package"]["macos_notarization_evidence_manifest_hash"],
                macos_notarization_manifest["manifest_hash"],
            )
            self.assertIn("codesign_verification", manifest["package_readiness"]["macos_notarized_package"]["notarization_slots"])
            self.assertIn(
                "macos notarization evidence manifest hash emitted",
                manifest["package_readiness"]["macos_notarized_package"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "macos notarization report-grade validation plan",
                manifest["package_readiness"]["macos_notarized_package"]["core_accuracy_gates"][0][
                    "satisfied_checks"
                ],
            )
            self.assertIn(
                "macos evidence slot matrix hash emitted",
                manifest["package_readiness"]["macos_notarized_package"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                manifest["package_readiness"]["macos_notarized_package"]["functional_priority_profile"]["item_number"],
                59,
            )
            self.assertTrue(
                manifest["package_readiness"]["macos_notarized_package"]["functional_priority_profile"][
                    "implemented_controls"
                ]["package_workflow_manifest_declared"]
            )
            self.assertEqual(manifest["package_readiness"]["macos_notarized_package"]["trusted_macos_notarization_diff"]["status"], "missing")
            self.assertIn(
                "trusted-macos-notarization-evidence-diff-missing",
                manifest["package_readiness"]["macos_notarized_package"]["blockers"],
            )
            self.assertIn(
                "notarytool-submission-proof-required",
                manifest["package_readiness"]["macos_notarized_package"]["blockers"],
            )
            self.assertIn("#103", manifest["package_readiness"]["linux_package"]["commercial_gap_ids"])
            self.assertEqual(manifest["package_readiness"]["linux_package"]["core_accuracy_gates"][0]["gap_id"], "#103")
            self.assertEqual(manifest["package_readiness"]["linux_package"]["status"], "packaging-plan-ready")
            linux_package_manifest = manifest["package_readiness"]["linux_package"]["linux_package_evidence_manifest"]
            self.assertEqual(linux_package_manifest["profile_version"], "linux-package-evidence-manifest-v1")
            self.assertEqual(len(linux_package_manifest["manifest_hash"]), 64)
            self.assertEqual(len(linux_package_manifest["evidence_slot_matrix_hash"]), 64)
            self.assertEqual(
                manifest["package_readiness"]["linux_package"]["evidence_slot_matrix_hash"],
                linux_package_manifest["evidence_slot_matrix_hash"],
            )
            self.assertEqual(
                manifest["package_readiness"]["linux_package"]["linux_package_evidence_manifest_hash"],
                linux_package_manifest["manifest_hash"],
            )
            linux_workflow_manifest = manifest["package_readiness"]["linux_package"]["linux_package_workflow_manifest"]
            self.assertEqual(
                linux_workflow_manifest["profile_version"],
                "linux-package-workflow-manifest-v1",
            )
            self.assertEqual(linux_workflow_manifest["item_number"], 60)
            self.assertEqual(len(linux_workflow_manifest["manifest_hash"]), 64)
            self.assertEqual(
                manifest["package_readiness"]["linux_package"]["linux_package_workflow_manifest_hash"],
                linux_workflow_manifest["manifest_hash"],
            )
            self.assertIn("RapidTriage.AppImage", linux_workflow_manifest["target_outputs"])
            self.assertIn("install_uninstall_log", linux_workflow_manifest["evidence_slots"])
            self.assertIn("clean-container-install-uninstall-smoke-not-attached", linux_workflow_manifest["blockers"])
            linux_report_grade_plan = manifest["package_readiness"]["linux_package"][
                "linux_package_report_grade_validation_plan"
            ]
            self.assertEqual(
                linux_report_grade_plan["profile_version"],
                "linux-package-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                manifest["package_readiness"]["linux_package"]["linux_package_report_grade_validation_plan_hash"],
                linux_report_grade_plan["validation_plan_sha256"],
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["linux_package"]["linux_package_report_grade_ready_slot_count"],
                7,
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["linux_package"]["linux_package_report_grade_blocking_slot_count"],
                7,
            )
            self.assertIn("deb-build-log-required", linux_report_grade_plan["blockers"])
            self.assertIn("deb_build_log", manifest["package_readiness"]["linux_package"]["package_evidence_slots"])
            self.assertIn(
                "linux package evidence manifest hash emitted",
                manifest["package_readiness"]["linux_package"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "linux package report-grade validation plan",
                manifest["package_readiness"]["linux_package"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "linux evidence slot matrix hash emitted",
                manifest["package_readiness"]["linux_package"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(manifest["package_readiness"]["linux_package"]["functional_priority_profile"]["item_number"], 60)
            self.assertTrue(
                manifest["package_readiness"]["linux_package"]["functional_priority_profile"]["implemented_controls"][
                    "linux_package_workflow_manifest_declared"
                ]
            )
            self.assertEqual(manifest["package_readiness"]["linux_package"]["trusted_linux_package_diff"]["status"], "missing")
            self.assertIn("trusted-linux-package-smoke-diff-missing", manifest["package_readiness"]["linux_package"]["blockers"])
            self.assertIn("deb-build-log-required", manifest["package_readiness"]["linux_package"]["blockers"])
            self.assertIn("#104", manifest["package_readiness"]["auto_update_channel"]["commercial_gap_ids"])
            self.assertEqual(manifest["package_readiness"]["auto_update_channel"]["core_accuracy_gates"][0]["gap_id"], "#104")
            self.assertEqual(manifest["package_readiness"]["auto_update_channel"]["status"], "manifest-generated")
            self.assertEqual(
                len(manifest["package_readiness"]["auto_update_channel"]["auto_update_evidence_manifest_hash"]),
                64,
            )
            self.assertEqual(len(manifest["package_readiness"]["auto_update_channel"]["evidence_slot_matrix_hash"]), 64)
            auto_update_report_grade_plan = manifest["package_readiness"]["auto_update_channel"][
                "auto_update_report_grade_validation_plan"
            ]
            self.assertEqual(
                auto_update_report_grade_plan["profile_version"],
                "auto-update-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                manifest["package_readiness"]["auto_update_channel"][
                    "auto_update_report_grade_validation_plan_hash"
                ],
                auto_update_report_grade_plan["validation_plan_sha256"],
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["auto_update_channel"][
                    "auto_update_report_grade_ready_slot_count"
                ],
                8,
            )
            self.assertGreaterEqual(
                manifest["package_readiness"]["auto_update_channel"][
                    "auto_update_report_grade_blocking_slot_count"
                ],
                6,
            )
            self.assertIn("signed-update-manifest-required", auto_update_report_grade_plan["blockers"])
            self.assertIn("signed_manifest", manifest["package_readiness"]["auto_update_channel"]["update_evidence_slots"])
            self.assertIn(
                "auto-update evidence manifest hash emitted",
                manifest["package_readiness"]["auto_update_channel"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "auto-update report-grade validation plan",
                manifest["package_readiness"]["auto_update_channel"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "auto-update evidence slot matrix hash emitted",
                manifest["package_readiness"]["auto_update_channel"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(manifest["package_readiness"]["auto_update_channel"]["trusted_auto_update_channel_diff"]["status"], "missing")
            self.assertIn("trusted-auto-update-channel-diff-missing", manifest["package_readiness"]["auto_update_channel"]["blockers"])
            self.assertIn("signed-update-manifest-required", manifest["package_readiness"]["auto_update_channel"]["blockers"])
            self.assertIn("#112", manifest["package_readiness"]["operations_documents"]["commercial_gap_ids"])
            self.assertIn("#120", manifest["package_readiness"]["operations_documents"]["commercial_gap_ids"])
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["document_evidence_manifests"]["112"][
                    "profile_version"
                ],
                "release-notes-discipline-evidence-manifest-v1",
            )
            self.assertEqual(
                len(manifest["package_readiness"]["operations_documents"]["document_evidence_manifest_hashes"]["112"]),
                64,
            )
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["document_evidence_manifests"]["112"][
                    "document_evidence_matrix"
                ]["profile_version"],
                "operations-document-evidence-matrix-v1",
            )
            self.assertEqual(
                len(manifest["package_readiness"]["operations_documents"]["document_evidence_matrix_hashes"]["112"]),
                64,
            )
            self.assertIn(
                "ci_changelog_gate",
                manifest["package_readiness"]["operations_documents"]["document_evidence_slots"]["112"],
            )
            self.assertIn(
                "operations evidence manifest hash emitted",
                manifest["package_readiness"]["operations_documents"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "operations document evidence matrix hash emitted",
                manifest["package_readiness"]["operations_documents"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            admin_guide_coverage_manifest = manifest["package_readiness"]["operations_documents"][
                "admin_guide_coverage_manifest"
            ]
            self.assertEqual(
                admin_guide_coverage_manifest["profile_version"],
                "admin-guide-coverage-manifest-v1",
            )
            self.assertEqual(admin_guide_coverage_manifest["item_number"], 66)
            self.assertEqual(len(admin_guide_coverage_manifest["manifest_hash"]), 64)
            self.assertEqual(admin_guide_coverage_manifest["missing_coverage"], [])
            self.assertTrue(admin_guide_coverage_manifest["coverage_passed"])
            self.assertTrue(admin_guide_coverage_manifest["coverage"]["install"]["present"])
            self.assertTrue(admin_guide_coverage_manifest["coverage"]["evidence_handling"]["present"])
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["admin_guide_coverage_manifest_hash"],
                admin_guide_coverage_manifest["manifest_hash"],
            )
            self.assertIn(
                "admin-guide-coverage-manifest.json",
                {artifact["name"] for artifact in manifest["artifacts"]},
            )
            support_process_manifest = manifest["package_readiness"]["operations_documents"][
                "support_process_readiness_manifest"
            ]
            self.assertEqual(
                support_process_manifest["profile_version"],
                "support-process-readiness-manifest-v1",
            )
            self.assertEqual(support_process_manifest["item_number"], 68)
            self.assertEqual(support_process_manifest["missing_checks"], [])
            self.assertTrue(support_process_manifest["coverage_passed"])
            self.assertTrue(support_process_manifest["readiness_checks"]["severity_levels"]["present"])
            self.assertTrue(support_process_manifest["readiness_checks"]["secure_intake"]["present"])
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["support_process_readiness_manifest_hash"],
                support_process_manifest["manifest_hash"],
            )
            self.assertIn(
                "support-process-readiness-manifest.json",
                {artifact["name"] for artifact in manifest["artifacts"]},
            )
            release_discipline_manifest = manifest["package_readiness"]["operations_documents"][
                "release_discipline_manifest"
            ]
            self.assertEqual(
                release_discipline_manifest["profile_version"],
                "release-discipline-manifest-v1",
            )
            self.assertEqual(release_discipline_manifest["item_number"], 69)
            self.assertEqual(release_discipline_manifest["missing_sections"], [])
            self.assertEqual(release_discipline_manifest["missing_files"], [])
            self.assertTrue(release_discipline_manifest["coverage_passed"])
            self.assertTrue(release_discipline_manifest["section_checks"]["validation_state"]["present"])
            self.assertTrue(release_discipline_manifest["section_checks"]["smoke_logs"]["present"])
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["release_discipline_manifest_hash"],
                release_discipline_manifest["manifest_hash"],
            )
            self.assertIn(
                "release-discipline-manifest.json",
                {artifact["name"] for artifact in manifest["artifacts"]},
            )
            blocker_ledger_manifest = manifest["package_readiness"]["operations_documents"][
                "external_blocker_ledger_manifest"
            ]
            self.assertEqual(
                blocker_ledger_manifest["profile_version"],
                "external-blocker-ledger-manifest-v1",
            )
            self.assertEqual(blocker_ledger_manifest["item_number"], 70)
            self.assertFalse(blocker_ledger_manifest["commercial_claim_allowed"])
            self.assertGreaterEqual(blocker_ledger_manifest["blocker_count"], 7)
            blocker_ids = {blocker["blocker_id"] for blocker in blocker_ledger_manifest["blockers"]}
            self.assertIn("independent-validation-not-attached", blocker_ids)
            self.assertIn("large-hardware-test-evidence-not-attached", blocker_ids)
            self.assertIn("code-signing-not-attached", blocker_ids)
            self.assertIn("staffed-support-not-attached", blocker_ids)
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["external_blocker_ledger_manifest_hash"],
                blocker_ledger_manifest["manifest_hash"],
            )
            self.assertIn(
                "external-blocker-ledger-manifest.json",
                {artifact["name"] for artifact in manifest["artifacts"]},
            )
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["document_evidence_manifests"]["120"][
                    "profile_version"
                ],
                "dependency-monitoring-evidence-manifest-v1",
            )
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["trusted_operations_document_diffs"]["112"]["status"],
                "missing",
            )
            self.assertEqual(
                manifest["package_readiness"]["operations_documents"]["trusted_operations_document_diffs"]["116"]["status"],
                "missing",
            )
            self.assertIn(
                "trusted-release-notes-ci-gate-diff-missing",
                manifest["package_readiness"]["operations_documents"]["blockers"],
            )
            self.assertIn(
                "trusted-admin-deployment-proof-diff-missing",
                manifest["package_readiness"]["operations_documents"]["blockers"],
            )
            operation_profiles = {
                profile["item_number"]: profile
                for profile in manifest["package_readiness"]["operations_documents"]["functional_priority_profiles"]
            }
            self.assertEqual(sorted(operation_profiles), [66, 67, 68, 69, 70])
            self.assertEqual(operation_profiles[66]["batch_id"], "commercial-uplift-066-070")
            self.assertTrue(operation_profiles[66]["implemented_controls"]["backup_restore_guidance_documented"])
            self.assertTrue(operation_profiles[66]["implemented_controls"]["admin_guide_coverage_manifest_declared"])
            self.assertTrue(operation_profiles[67]["implemented_controls"]["sample_case_workflow_documented"])
            self.assertTrue(
                operation_profiles[67]["implemented_controls"][
                    "training_lab_workflow_manifest_emitted_by_sample_run"
                ]
            )
            self.assertIn("staffed-support-desk-not-attached", operation_profiles[68]["failed_validation_check_ids"])
            self.assertTrue(
                operation_profiles[68]["implemented_controls"][
                    "support_process_readiness_manifest_declared"
                ]
            )
            self.assertTrue(operation_profiles[69]["implemented_controls"]["checksums_generated"])
            self.assertTrue(operation_profiles[69]["implemented_controls"]["release_discipline_manifest_declared"])
            self.assertTrue(operation_profiles[70]["implemented_controls"]["commercial_claim_guard_present"])
            self.assertTrue(
                operation_profiles[70]["implemented_controls"][
                    "external_blocker_ledger_manifest_declared"
                ]
            )
            self.assertEqual(
                [gate["gap_id"] for gate in manifest["package_readiness"]["operations_documents"]["core_accuracy_gates"]],
                [f"#{number}" for number in range(112, 121)],
            )
            update_manifest = json.loads((output_dir / "update-manifest.json").read_text(encoding="utf-8"))
            self.assertIn("#104", update_manifest["commercial_gap_ids"])
            self.assertEqual(update_manifest["core_accuracy_gates"][0]["gap_id"], "#104")
            self.assertFalse(update_manifest["auto_update_enabled_by_default"])
            self.assertEqual(update_manifest["auto_update_evidence_manifest"]["profile_version"], "auto-update-channel-evidence-manifest-v1")
            self.assertEqual(len(update_manifest["auto_update_evidence_manifest_hash"]), 64)
            self.assertEqual(len(update_manifest["evidence_slot_matrix_hash"]), 64)
            self.assertEqual(
                update_manifest["auto_update_report_grade_validation_plan"]["profile_version"],
                "auto-update-report-grade-validation-plan-v1",
            )
            self.assertEqual(
                update_manifest["auto_update_report_grade_validation_plan_hash"],
                update_manifest["auto_update_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertIn("auto-update report-grade ready slots", update_manifest["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(
                update_manifest["evidence_slot_matrix_hash"],
                update_manifest["auto_update_evidence_manifest"]["evidence_slot_matrix_hash"],
            )
            self.assertIn("rollback_test", update_manifest["update_evidence_slots"])
            self.assertEqual(update_manifest["trusted_auto_update_channel_diff"]["status"], "missing")
            self.assertIn("trusted-auto-update-channel-diff-missing", update_manifest["blockers"])
            packaging_plan = json.loads((output_dir / "packaging-plan.json").read_text(encoding="utf-8"))
            self.assertIn("#101", packaging_plan["commercial_gap_ids"])
            self.assertEqual(
                packaging_plan["local_outputs"]["portable_zip"]["functional_priority_profile"]["item_number"],
                58,
            )
            self.assertTrue(
                packaging_plan["local_outputs"]["portable_zip"]["functional_priority_profile"]["implemented_controls"][
                    "double_click_windows_launcher_packaged"
                ]
            )
            self.assertTrue(
                packaging_plan["local_outputs"]["portable_zip"]["functional_priority_profile"]["implemented_controls"][
                    "windows_portable_mode_manifest_emitted"
                ]
            )
            portable_manifest = packaging_plan["local_outputs"]["portable_zip"]["windows_portable_mode_manifest"]
            self.assertEqual(portable_manifest["profile_version"], "windows-portable-mode-manifest-v1")
            self.assertEqual(portable_manifest["item_number"], 58)
            self.assertEqual(len(portable_manifest["manifest_hash"]), 64)
            self.assertEqual(
                packaging_plan["local_outputs"]["portable_zip"]["windows_portable_mode_manifest_hash"],
                portable_manifest["manifest_hash"],
            )
            self.assertTrue(portable_manifest["portable_zip_present"])
            self.assertFalse(portable_manifest["missing_zip_entries"])
            self.assertIn("scripts/windows/start-rapidtriage.ps1", portable_manifest["double_click_entrypoints"])
            self.assertEqual(packaging_plan["platform_packages"]["windows"]["current_status"], "external-signing-required")
            self.assertIn("#101", packaging_plan["platform_packages"]["windows"]["commercial_gap_ids"])
            self.assertEqual(packaging_plan["platform_packages"]["windows"]["core_accuracy_gates"][0]["gap_id"], "#101")
            self.assertEqual(packaging_plan["platform_packages"]["windows"]["functional_priority_profile"]["item_number"], 57)
            self.assertEqual(packaging_plan["platform_packages"]["windows"]["trusted_packaging_diff"]["status"], "missing")
            self.assertIn("#102", packaging_plan["platform_packages"]["macos"]["commercial_gap_ids"])
            self.assertEqual(packaging_plan["platform_packages"]["macos"]["core_accuracy_gates"][0]["gap_id"], "#102")
            self.assertEqual(packaging_plan["platform_packages"]["macos"]["functional_priority_profile"]["item_number"], 59)
            self.assertEqual(packaging_plan["platform_packages"]["macos"]["trusted_packaging_diff"]["status"], "missing")
            self.assertIn("#103", packaging_plan["platform_packages"]["linux"]["commercial_gap_ids"])
            self.assertEqual(packaging_plan["platform_packages"]["linux"]["core_accuracy_gates"][0]["gap_id"], "#103")
            self.assertEqual(packaging_plan["platform_packages"]["linux"]["functional_priority_profile"]["item_number"], 60)
            self.assertIn("AppImage", packaging_plan["platform_packages"]["linux"]["target_outputs"])
            self.assertEqual(packaging_plan["platform_packages"]["linux"]["trusted_packaging_diff"]["status"], "missing")

            build_release = load_build_release_module()
            windows_diff = build_release.build_release_packaging_trusted_diff(
                101,
                packaging_plan["platform_packages"]["windows"],
                packaging_plan["platform_packages"]["windows"],
                trusted_tool="authenticode-signature-log",
            )
            windows_gates = build_release.release_packaging_core_accuracy_gate(
                101,
                trusted_diff=windows_diff,
                evidence_manifest=windows_signing_manifest,
                report_grade_validation_plan=windows_report_grade_plan,
            )
            self.assertEqual(windows_diff["status"], "pass")
            self.assertIn("evidence_slot_matrix_hash", windows_diff["compared_fields"])
            self.assertIn("windows_signing_report_grade_validation_plan_hash", windows_diff["compared_fields"])
            self.assertIn("trusted Windows Authenticode evidence diff pass", windows_gates[0]["satisfied_checks"])
            self.assertIn("windows signing report-grade ready slots", windows_gates[0]["satisfied_checks"])
            macos_diff = build_release.build_release_packaging_trusted_diff(
                102,
                manifest["package_readiness"]["macos_notarized_package"],
                manifest["package_readiness"]["macos_notarized_package"],
                trusted_tool="macos-notarization-log",
            )
            macos_gates = build_release.release_packaging_core_accuracy_gate(
                102,
                trusted_diff=macos_diff,
                evidence_manifest=macos_notarization_manifest,
                report_grade_validation_plan=macos_report_grade_plan,
            )
            self.assertEqual(macos_diff["status"], "pass")
            self.assertIn("macos_notarization_report_grade_validation_plan_hash", macos_diff["compared_fields"])
            self.assertIn("trusted macOS notarization evidence diff pass", macos_gates[0]["satisfied_checks"])
            self.assertIn("macos notarization report-grade ready slots", macos_gates[0]["satisfied_checks"])
            linux_diff = build_release.build_release_packaging_trusted_diff(
                103,
                manifest["package_readiness"]["linux_package"],
                manifest["package_readiness"]["linux_package"],
                trusted_tool="linux-package-smoke-log",
            )
            linux_gates = build_release.release_packaging_core_accuracy_gate(
                103,
                trusted_diff=linux_diff,
                evidence_manifest=linux_package_manifest,
                report_grade_validation_plan=linux_report_grade_plan,
            )
            self.assertEqual(linux_diff["status"], "pass")
            self.assertIn("linux_package_report_grade_validation_plan_hash", linux_diff["compared_fields"])
            self.assertIn("trusted Linux package smoke diff pass", linux_gates[0]["satisfied_checks"])
            self.assertIn("linux package report-grade ready slots", linux_gates[0]["satisfied_checks"])
            update_diff = build_release.build_release_packaging_trusted_diff(
                104,
                update_manifest,
                update_manifest,
                trusted_tool="signed-update-channel-log",
            )
            update_gates = build_release.release_packaging_core_accuracy_gate(
                104,
                trusted_diff=update_diff,
                evidence_manifest=update_manifest["auto_update_evidence_manifest"],
                report_grade_validation_plan=update_manifest["auto_update_report_grade_validation_plan"],
            )
            self.assertEqual(update_diff["status"], "pass")
            self.assertIn("auto_update_report_grade_validation_plan_hash", update_diff["compared_fields"])
            self.assertIn("trusted signed update channel diff pass", update_gates[0]["satisfied_checks"])
            self.assertIn("auto-update report-grade ready slots", update_gates[0]["satisfied_checks"])
            release_notes_diff = build_release.build_operations_document_trusted_diff(
                112,
                manifest["package_readiness"]["operations_documents"],
                manifest["package_readiness"]["operations_documents"],
                trusted_tool="release-notes-ci-gate",
            )
            operations_gates = build_release.operations_documents_core_accuracy_gates(trusted_diffs={112: release_notes_diff})
            self.assertEqual(release_notes_diff["status"], "pass")
            self.assertIn("trusted release notes CI gate diff pass", operations_gates[0]["satisfied_checks"])
            admin_diff = build_release.build_operations_document_trusted_diff(
                117,
                manifest["package_readiness"]["operations_documents"],
                manifest["package_readiness"]["operations_documents"],
                trusted_tool="admin-deployment-proof",
            )
            admin_gates = build_release.operations_documents_core_accuracy_gates(trusted_diffs={117: admin_diff})
            self.assertEqual(admin_diff["status"], "pass")
            self.assertIn("trusted admin deployment proof diff pass", admin_gates[5]["satisfied_checks"])

            verify = subprocess.run(
                [
                    "python",
                    "scripts/build-release.py",
                    "--output-dir",
                    str(output_dir),
                    "--verify",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_crash_report_is_local_and_redacts_sensitive_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            report = write_crash_report(
                RuntimeError("boom"),
                context={"path": "/case/source", "auth_token": "secret-value"},
                output_dir=Path(tmp_dir),
            )

            payload = json.loads(Path(report["path"]).read_text(encoding="utf-8"))
            self.assertIn("#105", payload["commercial_gap_ids"])
            self.assertEqual(payload["functional_priority_profile"]["item_number"], 65)
            self.assertEqual(payload["functional_priority_profile"]["batch_id"], "commercial-uplift-061-065")
            self.assertTrue(payload["functional_priority_profile"]["implemented_controls"]["automatic_upload_disabled"])
            self.assertEqual(payload["functional_priority_profile"]["evidence_counts"]["sensitive_context_key_count"], 1)
            self.assertEqual(payload["core_accuracy_gates"][0]["gap_id"], "#105")
            self.assertEqual(payload["crash_export_evidence_manifest"]["profile_version"], "crash-export-evidence-manifest-v1")
            self.assertEqual(len(payload["crash_export_evidence_manifest_hash"]), 64)
            self.assertEqual(payload["crash_redaction_matrix"]["profile_version"], "crash-redaction-matrix-v1")
            self.assertEqual(len(payload["crash_redaction_matrix_hash"]), 64)
            self.assertEqual(
                payload["crash_redaction_matrix_hash"],
                payload["crash_export_evidence_manifest"]["redaction_matrix_hash"],
            )
            self.assertEqual(payload["crash_no_upload_manifest"]["profile_version"], "crash-no-upload-manifest-v1")
            self.assertEqual(payload["crash_no_upload_manifest"]["item_number"], 65)
            self.assertEqual(len(payload["crash_no_upload_manifest_hash"]), 64)
            self.assertEqual(payload["crash_no_upload_manifest_hash"], payload["crash_no_upload_manifest"]["manifest_hash"])
            self.assertFalse(payload["crash_no_upload_manifest"]["automatic_upload_enabled"])
            self.assertEqual(payload["crash_no_upload_manifest"]["known_upload_endpoint_count"], 0)
            self.assertEqual(
                payload["crash_report_grade_validation_plan"]["profile_version"],
                "crash-reporting-report-grade-validation-plan-v1",
            )
            self.assertEqual(len(payload["crash_report_grade_validation_plan_hash"]), 64)
            self.assertEqual(
                payload["crash_report_grade_validation_plan_hash"],
                payload["crash_report_grade_validation_plan"]["validation_plan_hash"],
            )
            self.assertGreaterEqual(payload["crash_report_grade_ready_slot_count"], 8)
            self.assertGreaterEqual(payload["crash_report_grade_blocking_slot_count"], 8)
            self.assertIn("release-host-crash-export-smoke-required", payload["blockers"])
            self.assertTrue(
                payload["functional_priority_profile"]["implemented_controls"]["crash_no_upload_manifest_emitted"]
            )
            self.assertIn(
                "crash-no-upload-manifest-emitted",
                payload["functional_priority_profile"]["passed_validation_check_ids"],
            )
            self.assertIn("auth_token", payload["crash_export_evidence_manifest"]["redacted_context_keys"])
            self.assertIn("operator_export_ui_smoke", payload["export_evidence_slots"])
            self.assertIn(
                "crash export evidence manifest hash emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "crash no-upload manifest hash emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "crash redaction matrix hash emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "crash report-grade validation plan",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "crash report-grade ready slots",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertTrue(payload["local_only"])
            self.assertEqual(payload["context"]["auth_token"], "<redacted>")
            self.assertEqual(payload["exception"]["type"], "RuntimeError")
            self.assertEqual(payload["trusted_crash_report_diff"]["status"], "missing")
            self.assertIn("trusted-crash-redaction-export-diff-missing", payload["blockers"])
            crash_diff = build_crash_report_trusted_diff(payload, payload)
            crash_gates = crash_report_core_accuracy_gates(
                crash_id=payload["crash_id"],
                report_path=Path(report["path"]),
                trusted_diff=crash_diff,
            )
            self.assertEqual(crash_diff["status"], "pass")
            self.assertIn("crash_redaction_matrix_hash", crash_diff["compared_fields"])
            self.assertIn("crash_report_grade_validation_plan_hash", crash_diff["compared_fields"])
            self.assertIn("trusted crash redaction/export diff pass", crash_gates[0]["satisfied_checks"])

    def test_crash_export_smoke_script_writes_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "crash-smoke"
            result = subprocess.run(
                [
                    "python",
                    "scripts/crash-export-smoke.py",
                    "--output-dir",
                    str(output_dir),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["profile_version"], "crash-export-release-smoke-v1")
            self.assertIn("#105", payload["commercial_gap_ids"])
            self.assertEqual(payload["failed_check_ids"], [])
            self.assertTrue(payload["checks"]["secret_redacted"])
            self.assertTrue(payload["checks"]["dashboard_lists_report"])
            self.assertTrue(payload["checks"]["export_bundle_written"])
            self.assertTrue(payload["checks"]["bundle_hash_verified"])
            self.assertTrue(payload["checks"]["report_grade_plan_present"])
            self.assertTrue(payload["checks"]["export_manifest_preserves_report_grade_hash"])
            self.assertEqual(len(payload["crash_report_grade_validation_plan_hash"]), 64)
            self.assertEqual(len(payload["smoke_hash"]), 64)
            self.assertTrue(Path(payload["export_bundle_path"]).is_file())
            self.assertTrue((output_dir / "crash-export-smoke.json").is_file())
            with zipfile.ZipFile(payload["export_bundle_path"]) as bundle:
                names = set(bundle.namelist())
                self.assertIn("crash-export-manifest.json", names)
                self.assertIn(f"{payload['crash_id']}.json", names)
                self.assertNotIn("release-secret-token", bundle.read(f"{payload['crash_id']}.json").decode("utf-8"))

    def test_crash_redaction_review_script_verifies_smoke_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "crash-smoke"
            smoke_result = subprocess.run(
                [
                    "python",
                    "scripts/crash-export-smoke.py",
                    "--output-dir",
                    str(output_dir),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(smoke_result.returncode, 0, smoke_result.stderr)

            review_result = subprocess.run(
                [
                    "python",
                    "scripts/crash-redaction-review.py",
                    str(output_dir / "crash-export-smoke.json"),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(review_result.returncode, 0, review_result.stderr)
            review = json.loads(review_result.stdout)
            self.assertEqual(review["profile_version"], "crash-redaction-export-review-v1")
            self.assertEqual(review["failed_check_ids"], [])
            self.assertEqual(review["trusted_crash_report_diff"]["status"], "pass")
            self.assertEqual(review["review_tool"], "local-crash-export-log")
            self.assertTrue(review["checks"]["sensitive_tokens_absent"])
            self.assertTrue(review["checks"]["manifest_no_automatic_upload"])
            self.assertTrue(review["checks"]["report_grade_plan_has_hash"])
            self.assertTrue(review["checks"]["manifest_preserves_report_grade_hash"])
            self.assertTrue(review["checks"]["trusted_diff_passes"])
            self.assertEqual(len(review["crash_report_grade_validation_plan_hash"]), 64)
            self.assertEqual(len(review["review_hash"]), 64)
            self.assertTrue((output_dir / "crash-redaction-review.json").is_file())

    def test_parser_sandbox_smoke_script_captures_crash_and_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "parser-sandbox-smoke.json"
            result = subprocess.run(
                [
                    "python",
                    "scripts/parser-sandbox-smoke.py",
                    "--output",
                    str(output_path),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["profile_version"], "parser-subprocess-isolation-smoke-v1")
            self.assertIn("#119", payload["commercial_gap_ids"])
            self.assertEqual(payload["failed_check_ids"], [])
            self.assertTrue(payload["checks"]["benign_subprocess_completes"])
            self.assertTrue(payload["checks"]["crashing_subprocess_is_captured"])
            self.assertTrue(payload["checks"]["timeout_subprocess_is_captured"])
            self.assertTrue(payload["checks"]["active_content_fixture_not_executed"])
            self.assertFalse(payload["sandbox_boundary"]["os_level_sandbox_enabled"])
            self.assertFalse(payload["commercial_claim_allowed"])
            self.assertEqual(len(payload["smoke_hash"]), 64)
            self.assertTrue(output_path.is_file())

    def test_security_hardening_review_script_writes_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "security-hardening-review.json"
            result = subprocess.run(
                [
                    "python",
                    "scripts/security-hardening-review.py",
                    "--output",
                    str(output_path),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "security-hardening-review")
            self.assertEqual(payload["profile_version"], "security-hardening-release-review-v1")
            self.assertIn("#118", payload["commercial_gap_ids"])
            self.assertEqual(payload["failed_check_ids"], [])
            self.assertEqual(len(payload["review_hash"]), 64)
            self.assertTrue(payload["checks"]["remote_bind_requires_auth"])
            self.assertTrue(payload["checks"]["appsec_blocker_preserved"])
            self.assertTrue(payload["checks"]["os_sandbox_limitation_preserved"])
            self.assertFalse(payload["commercial_claim_allowed"])

    def test_external_release_evidence_template_script_writes_required_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "external-commercial-evidence.template.json"
            result = subprocess.run(
                [
                    "python",
                    "scripts/external-release-evidence-template.py",
                    "--output",
                    str(output_path),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["profile_version"], "external-commercial-evidence-v1")
            self.assertEqual(payload["scope"], "release-artifact-evidence-1-8")
            self.assertEqual([item["number"] for item in payload["items"]], list(range(1, 9)))
            self.assertEqual(len(payload["evidence_package_hash"]), 64)
            self.assertTrue(all(item["status"] == "external-evidence-required" for item in payload["items"]))
            self.assertTrue(payload["items"][7]["checks"]["verifier_schema_updated"])

    def test_hostile_evidence_containment_template_script_writes_required_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "hostile-evidence-containment.template.json"
            result = subprocess.run(
                [
                    "python",
                    "scripts/hostile-evidence-containment-template.py",
                    "--output",
                    str(output_path),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["profile_version"], "hostile-evidence-containment-v1")
            self.assertEqual(payload["scope"], "hostile-evidence-containment-9-13")
            self.assertEqual([item["number"] for item in payload["items"]], list(range(9, 14)))
            self.assertEqual(len(payload["evidence_package_hash"]), 64)
            self.assertTrue(all(item["status"] == "external-evidence-required" for item in payload["items"]))
            self.assertFalse(payload["items"][1]["checks"]["os_level_sandbox_enabled"])

    def test_independent_operations_evidence_template_script_writes_required_items(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "independent-operations-evidence.template.json"
            result = subprocess.run(
                [
                    "python",
                    "scripts/independent-operations-evidence-template.py",
                    "--output",
                    str(output_path),
                    "--json",
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["profile_version"], "independent-operations-evidence-v1")
            self.assertEqual(payload["scope"], "independent-validation-operations-14-18")
            self.assertEqual([item["number"] for item in payload["items"]], list(range(14, 19)))
            self.assertEqual(len(payload["evidence_package_hash"]), 64)
            self.assertTrue(all(item["status"] == "external-evidence-required" for item in payload["items"]))
            self.assertFalse(payload["items"][1]["checks"]["signed_report_attached"])

    def test_case_backup_and_restore_commands_copy_database_with_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            db_path = root / "case.db"
            self.assertEqual(main(["case-db", str(db_path), "--create-case", "CASE-BACKUP", "--json"]), 0)
            backup_dir = root / "backup"
            restored = root / "restored.db"

            backup_stdout = io.StringIO()
            with contextlib.redirect_stdout(backup_stdout):
                backup_exit = main(["case-backup", str(db_path), "--output-dir", str(backup_dir), "--json"])
            self.assertEqual(backup_exit, 0)
            backup_payload = json.loads(backup_stdout.getvalue())
            self.assertEqual(backup_payload["command"], "case-backup")
            self.assertIn("#111", backup_payload["commercial_gap_ids"])
            self.assertEqual(backup_payload["functional_priority_profile"]["item_number"], 62)
            self.assertEqual(backup_payload["functional_priority_profile"]["batch_id"], "commercial-uplift-061-065")
            self.assertTrue(backup_payload["functional_priority_profile"]["implemented_controls"]["case_database_backup_manifest"])
            self.assertEqual(backup_payload["core_accuracy_gates"][0]["gap_id"], "#111")
            self.assertEqual(
                backup_payload["backup_restore_evidence_manifest"]["profile_version"],
                "backup-restore-rehearsal-manifest-v1",
            )
            self.assertEqual(len(backup_payload["backup_restore_evidence_manifest_hash"]), 64)
            self.assertEqual(
                backup_payload["backup_restore_continuity_manifest"]["profile_version"],
                "backup-restore-continuity-manifest-v1",
            )
            self.assertEqual(backup_payload["backup_restore_continuity_manifest"]["item_number"], 62)
            self.assertEqual(len(backup_payload["backup_restore_continuity_manifest_hash"]), 64)
            self.assertEqual(
                backup_payload["backup_restore_continuity_manifest_hash"],
                backup_payload["backup_restore_continuity_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                backup_payload["backup_restore_evidence_manifest"]["rehearsal_evidence_matrix"]["profile_version"],
                "backup-restore-rehearsal-evidence-matrix-v1",
            )
            self.assertEqual(len(backup_payload["backup_restore_evidence_matrix_hash"]), 64)
            self.assertEqual(
                backup_payload["backup_restore_evidence_matrix_hash"],
                backup_payload["backup_restore_evidence_manifest"]["rehearsal_evidence_matrix_hash"],
            )
            self.assertTrue(
                backup_payload["functional_priority_profile"]["implemented_controls"][
                    "backup_restore_continuity_manifest_emitted"
                ]
            )
            self.assertIn("restore_drill_log", backup_payload["rehearsal_evidence_slots"])
            self.assertIn(
                "backup restore evidence manifest hash emitted",
                backup_payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "backup restore continuity manifest hash emitted",
                backup_payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "backup restore rehearsal evidence matrix hash emitted",
                backup_payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(backup_payload["trusted_backup_restore_diff"]["status"], "missing")
            self.assertIn("trusted-backup-restore-rehearsal-diff-missing", backup_payload["blockers"])
            self.assertTrue((backup_dir / "rapidtriage-case-backup-manifest.json").is_file())
            self.assertEqual(backup_payload["schema"]["current_schema_version"], 1)
            self.assertIn("#111", backup_payload["migration_readiness"]["commercial_gap_ids"])
            self.assertEqual(backup_payload["migration_readiness"]["core_accuracy_gates"][0]["gap_id"], "#111")
            self.assertEqual(backup_payload["migration_readiness"]["status"], "ready")
            self.assertTrue(backup_payload["migration_readiness"]["restore_rehearsal_required"])

            restore_stdout = io.StringIO()
            with contextlib.redirect_stdout(restore_stdout):
                restore_exit = main(
                    [
                        "case-restore",
                        str(backup_dir / "rapidtriage-case-backup-manifest.json"),
                        "--output",
                        str(restored),
                        "--json",
                    ]
                )
            self.assertEqual(restore_exit, 0)
            restore_payload = json.loads(restore_stdout.getvalue())
            self.assertIn("#111", restore_payload["commercial_gap_ids"])
            self.assertEqual(restore_payload["functional_priority_profile"]["item_number"], 62)
            self.assertTrue(restore_payload["functional_priority_profile"]["implemented_controls"]["restore_hash_verified"])
            self.assertEqual(restore_payload["core_accuracy_gates"][0]["gap_id"], "#111")
            self.assertEqual(len(restore_payload["backup_restore_evidence_manifest_hash"]), 64)
            self.assertEqual(len(restore_payload["backup_restore_evidence_matrix_hash"]), 64)
            self.assertEqual(
                restore_payload["backup_restore_continuity_manifest"]["profile_version"],
                "backup-restore-continuity-manifest-v1",
            )
            self.assertTrue(restore_payload["backup_restore_continuity_manifest"]["hash_verified"])
            self.assertEqual(len(restore_payload["backup_restore_continuity_manifest_hash"]), 64)
            self.assertIn("migration_corpus_run", restore_payload["rehearsal_evidence_slots"])
            self.assertIn(
                "backup restore evidence manifest hash emitted",
                restore_payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "backup restore rehearsal evidence matrix hash emitted",
                restore_payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "continuity hash verification recorded",
                restore_payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(restore_payload["trusted_backup_restore_diff"]["status"], "missing")
            self.assertIn("trusted-backup-restore-rehearsal-diff-missing", restore_payload["blockers"])
            self.assertTrue(restore_payload["hash_verified"])
            self.assertEqual(restore_payload["schema"]["current_schema_version"], 1)
            self.assertEqual(restore_payload["migration_readiness"]["expected_schema_version"], 1)
            self.assertTrue(restored.is_file())
            backup_diff = build_backup_restore_trusted_diff(restore_payload, restore_payload)
            backup_gates = backup_restore_core_accuracy_gates(
                copied=[{"hashes": restore_payload["source_hashes"]}],
                schema=restore_payload["schema"],
                restored=True,
                hash_verified=restore_payload["hash_verified"],
                trusted_diff=backup_diff,
            )
            self.assertEqual(backup_diff["status"], "pass")
            self.assertIn("backup_restore_evidence_matrix_hash", backup_diff["compared_fields"])
            self.assertIn("trusted backup/restore rehearsal diff pass", backup_gates[0]["satisfied_checks"])

    def test_dependency_monitoring_script_writes_vulnerability_policy_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "dependency-monitoring.json"
            result = subprocess.run(
                [
                    "python",
                    "scripts/check-dependencies.py",
                    "--output",
                    str(output_path),
                ],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "dependency-monitoring")
            self.assertIn("#120", payload["commercial_gap_ids"])
            self.assertEqual(payload["functional_priority_profile"]["item_number"], 64)
            self.assertEqual(payload["functional_priority_profile"]["batch_id"], "commercial-uplift-061-065")
            self.assertTrue(payload["functional_priority_profile"]["implemented_controls"]["dependency_inventory_emitted"])
            self.assertTrue(
                payload["functional_priority_profile"]["implemented_controls"]["dependency_sbom_manifest_emitted"]
            )
            self.assertTrue(
                payload["functional_priority_profile"]["implemented_controls"]["scheduled_ci_scan_configured"]
            )
            self.assertTrue(
                payload["functional_priority_profile"]["implemented_controls"]["sbom_archival_configured"]
            )
            self.assertEqual(len(payload["dependency_ci_workflow_evidence_hash"]), 64)
            self.assertTrue(payload["dependency_ci_workflow_evidence"]["configured"])
            self.assertIn("scheduled_trigger", payload["dependency_ci_workflow_evidence"]["passed_checks"])
            self.assertIn("artifact_upload_configured", payload["dependency_ci_workflow_evidence"]["passed_checks"])
            self.assertIn("sbom_archived_in_dependency_artifact", payload["dependency_ci_workflow_evidence"]["passed_checks"])
            self.assertIn(
                "CI scheduled advisory scan workflow configured",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "sbom-publication-not-attached",
                payload["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertNotIn(
                "ci-scheduled-advisory-scan-not-attached",
                payload["functional_priority_profile"]["failed_validation_check_ids"],
            )
            self.assertEqual(payload["core_accuracy_gates"][0]["gap_id"], "#120")
            self.assertEqual(payload["dependency_sbom_manifest"]["profile_version"], "dependency-sbom-manifest-v1")
            self.assertEqual(payload["dependency_sbom_manifest"]["item_number"], 64)
            self.assertEqual(len(payload["dependency_sbom_manifest_hash"]), 64)
            self.assertEqual(payload["dependency_sbom_manifest_hash"], payload["dependency_sbom_manifest"]["manifest_hash"])
            self.assertEqual(
                payload["functional_priority_profile"]["implemented_controls"]["dependency_sbom_manifest_hash"],
                payload["dependency_sbom_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                payload["dependency_monitoring_evidence_manifest"]["profile_version"],
                "dependency-monitoring-evidence-manifest-v1",
            )
            self.assertEqual(
                payload["dependency_monitoring_evidence_manifest"]["sbom_manifest_hash"],
                payload["dependency_sbom_manifest"]["manifest_hash"],
            )
            self.assertEqual(len(payload["dependency_monitoring_evidence_manifest_hash"]), 64)
            self.assertEqual(
                payload["dependency_monitoring_evidence_manifest"]["dependency_evidence_matrix"]["profile_version"],
                "dependency-evidence-matrix-v1",
            )
            self.assertEqual(len(payload["dependency_evidence_matrix_hash"]), 64)
            self.assertEqual(
                payload["dependency_evidence_matrix_hash"],
                payload["dependency_monitoring_evidence_manifest"]["dependency_evidence_matrix_hash"],
            )
            self.assertIn("scheduled_ci_advisory_scan", payload["dependency_evidence_slots"])
            self.assertEqual(
                payload["dependency_evidence_slots"]["scheduled_ci_advisory_scan"]["status"],
                "configured-no-run-attached",
            )
            self.assertEqual(
                payload["dependency_evidence_slots"]["sbom_publication"]["status"],
                "configured-in-ci-artifact-no-run-attached",
            )
            self.assertEqual(
                payload["dependency_monitoring_evidence_manifest"]["dependency_ci_workflow_evidence_hash"],
                payload["dependency_ci_workflow_evidence_hash"],
            )
            self.assertIn(
                "dependency monitoring evidence manifest hash emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "dependency SBOM manifest hash emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "dependency evidence matrix hash emitted",
                payload["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("#120", payload["vulnerability_scan"]["commercial_gap_ids"])
            self.assertEqual(payload["vulnerability_scan"]["core_accuracy_gates"][0]["gap_id"], "#120")
            self.assertIn("Block release", payload["vulnerability_scan"]["release_policy"])
            self.assertEqual(payload["trusted_dependency_monitoring_diff"]["status"], "missing")
            self.assertIn("trusted-dependency-advisory-sbom-diff-missing", payload["blockers"])
            check_dependencies = load_check_dependencies_module()
            dependency_diff = check_dependencies.build_dependency_monitoring_trusted_diff(payload, payload)
            dependency_gates = check_dependencies.dependency_monitoring_core_accuracy_gates(
                package_count=len(payload["pip_list"]["packages"]),
                scan_attempted=True,
                script_packaged=True,
                trusted_diff=dependency_diff,
            )
            self.assertEqual(dependency_diff["status"], "pass")
            self.assertIn("dependency_evidence_matrix_hash", dependency_diff["compared_fields"])
            self.assertIn("trusted dependency advisory/SBOM diff pass", dependency_gates[0]["satisfied_checks"])

    def test_case_acquisition_command_records_and_lists_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "case.db"
            self.assertEqual(main(["case-db", str(db_path), "--create-case", "CASE-ACQ", "--json"]), 0)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "case-acquisition",
                        str(db_path),
                        "--case-id",
                        "CASE-ACQ",
                        "--operator",
                        "Analyst One",
                        "--started-at",
                        "2026-04-28T09:00:00+09:00",
                        "--completed-at",
                        "2026-04-28T10:00:00+09:00",
                        "--source-identifier",
                        "Disk SN ABC123",
                        "--write-blocker",
                        "Tableau TX1 SN WB-01 verified read-only",
                        "--tool",
                        "RapidTriage",
                        "--tool-version",
                        "dev",
                        "--whole-source-sha256",
                        "a" * 64,
                        "--notes",
                        "Lab acquisition metadata",
                        "--json",
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["record"]["citation_id"].startswith("CASE-ACQ-ACQ-"))

            list_stdout = io.StringIO()
            with contextlib.redirect_stdout(list_stdout):
                list_exit = main(["case-acquisition", str(db_path), "--case-id", "CASE-ACQ", "--list", "--json"])
            self.assertEqual(list_exit, 0)
            listed = json.loads(list_stdout.getvalue())
            self.assertEqual(listed["record_count"], 1)
            self.assertEqual(listed["records"][0]["source_identifier"], "Disk SN ABC123")

    def test_smoke_summary_script_reports_pass_for_valid_smoke_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            smoke_dir = Path(tmp_dir) / "smoke"
            smoke_dir.mkdir()
            (smoke_dir / "doctor.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
            (smoke_dir / "sample.json").write_text(
                json.dumps({"run": {"output_dir": str(smoke_dir / "sample" / "run-output")}}),
                encoding="utf-8",
            )
            (smoke_dir / "sample-search.json").write_text(json.dumps({"match_count": 1}), encoding="utf-8")
            (smoke_dir / "benchmark.json").write_text(json.dumps({"metrics": {"ingest_seconds": 0.1}}), encoding="utf-8")
            (smoke_dir / "validation.json").write_text(
                json.dumps({"status": "release-validation-package-ready"}),
                encoding="utf-8",
            )
            (smoke_dir / "evidence-vhdx.json").write_text(
                json.dumps({"adapter": "virtual-disk", "message": "mount/export first"}),
                encoding="utf-8",
            )
            (smoke_dir / "web-index.html").write_text("<!doctype html>", encoding="utf-8")
            (smoke_dir / "workbench-smoke-contract.json").write_text(
                json.dumps(
                    {
                        "profile_version": "single-case-workbench-smoke-v1",
                        "platform_evidence": [{"platform": "windows"}, {"platform": "macos"}],
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                ["python", "scripts/summarize-smoke.py", str(smoke_dir)],
                cwd=Path(__file__).resolve().parent.parent,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((smoke_dir / "smoke-summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["passed"])
            self.assertIn(summary["platform"], {"macos-linux", "windows"})
            check_names = {row["name"] for row in summary["checks"]}
            self.assertIn("workbench-smoke-contract", check_names)
            self.assertTrue((smoke_dir / "smoke-summary.md").is_file())

    def test_release_evidence_script_reports_pass_for_complete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            columnar_benchmark_dir = root / "columnar-benchmark"
            smoke_dir = root / "smoke-windows"
            crash_smoke_dir = root / "crash-export-smoke"
            parser_sandbox_path = root / "parser-sandbox-smoke.json"
            dependency_monitoring_path = root / "dependency-monitoring.json"
            security_hardening_path = root / "security-hardening-review.json"
            external_evidence_path = root / "external-commercial-evidence.json"
            external_files_dir = root / "external-files"
            hostile_evidence_path = root / "hostile-evidence-containment.json"
            hostile_files_dir = root / "hostile-files"
            independent_evidence_path = root / "independent-operations-evidence.json"
            independent_files_dir = root / "independent-files"
            evidence_dir = root / "release-evidence"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)

            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
                columnar_benchmark_exit = main(
                    [
                        "columnar-benchmark",
                        "--output-dir",
                        str(columnar_benchmark_dir),
                        "--record-count",
                        "25",
                        "--query-iterations",
                        "1",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)
            self.assertEqual(columnar_benchmark_exit, 0)

            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(json.dumps({"passed": True, "checks": []}), encoding="utf-8")
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")

            crash_smoke = subprocess.run(
                [
                    "python",
                    "scripts/crash-export-smoke.py",
                    "--output-dir",
                    str(crash_smoke_dir),
                    "--json",
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(crash_smoke.returncode, 0, crash_smoke.stderr)
            crash_review = subprocess.run(
                [
                    "python",
                    "scripts/crash-redaction-review.py",
                    str(crash_smoke_dir / "crash-export-smoke.json"),
                    "--json",
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(crash_review.returncode, 0, crash_review.stderr)
            parser_sandbox = subprocess.run(
                [
                    "python",
                    "scripts/parser-sandbox-smoke.py",
                    "--output",
                    str(parser_sandbox_path),
                    "--json",
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(parser_sandbox.returncode, 0, parser_sandbox.stderr)
            dependency_monitoring = subprocess.run(
                [
                    "python",
                    "scripts/check-dependencies.py",
                    "--output",
                    str(dependency_monitoring_path),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(dependency_monitoring.returncode, 0, dependency_monitoring.stderr)
            security_hardening = subprocess.run(
                [
                    "python",
                    "scripts/security-hardening-review.py",
                    "--output",
                    str(security_hardening_path),
                    "--json",
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(security_hardening.returncode, 0, security_hardening.stderr)
            external_files_dir.mkdir()
            external_items = []
            external_checks = [
                {"ci_artifact_attached": True},
                {"sbom_hash_matches_release": True},
                {"authenticode_valid": True},
                {"windows_11_smoke_passed": True},
                {"codesign_verified": True, "notarization_accepted": True, "gatekeeper_accepted": True},
                {"gatekeeper_smoke_passed": True},
                {"install_smoke_passed": True, "uninstall_smoke_passed": True},
                {"verifier_schema_updated": True, "missing_evidence_fails": True, "attached_hashes_checked": True},
            ]
            for number, checks in enumerate(external_checks, start=1):
                evidence_file = external_files_dir / f"evidence-{number}.txt"
                evidence_file.write_text(f"external evidence {number}\n", encoding="utf-8")
                item = {
                    "number": number,
                    "status": "pass",
                    "checks": checks,
                    "required_files": [
                        {
                            "path": str(evidence_file),
                            "sha256": hashlib.sha256(evidence_file.read_bytes()).hexdigest(),
                        }
                    ],
                }
                if number == 1:
                    item["ci_run_url"] = "https://github.example/actions/runs/1"
                if number == 2:
                    item["sbom_path"] = str(evidence_file)
                if number == 3:
                    item["certificate_subject"] = "CN=RapidTriage Test Signing"
                if number == 4:
                    item["platform"] = "Windows 11"
                if number == 6:
                    item["platform"] = "macOS"
                external_items.append(item)
            external_payload = {
                "profile_version": "external-commercial-evidence-v1",
                "scope": "release-artifact-evidence-1-8",
                "items": external_items,
            }
            external_payload["evidence_package_hash"] = hashlib.sha256(
                json.dumps(external_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            external_evidence_path.write_text(
                json.dumps(external_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            hostile_files_dir.mkdir()
            hostile_items = []
            hostile_checks = [
                {
                    "threat_model_attached": True,
                    "allowed_paths_defined": True,
                    "network_policy_defined": True,
                    "resource_limits_defined": True,
                    "os_matrix_defined": True,
                },
                {
                    "os_level_sandbox_enabled": True,
                    "write_escape_blocked": True,
                    "network_blocked": True,
                    "kill_timeout_supported": True,
                },
                {
                    "path_escape_test_passed": True,
                    "network_probe_blocked": True,
                    "timeout_test_passed": True,
                    "memory_pressure_test_passed": True,
                    "active_content_test_passed": True,
                },
                {
                    "corpus_manifest_attached": True,
                    "license_notes_attached": True,
                    "expected_behavior_recorded": True,
                    "quarantine_expectations_recorded": True,
                    "artifact_families_covered": True,
                },
                {
                    "fuzz_command_recorded": True,
                    "seed_corpus_hash_recorded": True,
                    "crash_quarantine_recorded": True,
                    "timeout_count_recorded": True,
                    "no_silent_corruption": True,
                },
            ]
            for number, checks in enumerate(hostile_checks, start=9):
                evidence_file = hostile_files_dir / f"hostile-evidence-{number}.txt"
                evidence_file.write_text(f"hostile evidence {number}\n", encoding="utf-8")
                hostile_items.append(
                    {
                        "number": number,
                        "status": "pass",
                        "checks": checks,
                        "required_files": [
                            {
                                "path": str(evidence_file),
                                "sha256": hashlib.sha256(evidence_file.read_bytes()).hexdigest(),
                            }
                        ],
                    }
                )
            hostile_payload = {
                "profile_version": "hostile-evidence-containment-v1",
                "scope": "hostile-evidence-containment-9-13",
                "items": hostile_items,
            }
            hostile_payload["evidence_package_hash"] = hashlib.sha256(
                json.dumps(hostile_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            hostile_evidence_path.write_text(
                json.dumps(hostile_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            independent_files_dir.mkdir()
            independent_items = []
            independent_checks = [
                {
                    "architecture_overview_attached": True,
                    "threat_model_attached": True,
                    "auth_network_boundary_attached": True,
                    "export_rendering_policy_attached": True,
                    "sandbox_design_attached": True,
                    "dependency_report_attached": True,
                },
                {
                    "signed_report_attached": True,
                    "scope_recorded": True,
                    "findings_recorded": True,
                    "exceptions_recorded": True,
                    "residual_risk_recorded": True,
                },
                {
                    "support_contact_defined": True,
                    "severity_matrix_defined": True,
                    "staffed_schedule_defined": True,
                    "escalation_owner_defined": True,
                    "secure_intake_defined": True,
                },
                {
                    "simulated_issue_recorded": True,
                    "patch_branch_recorded": True,
                    "validation_run_attached": True,
                    "signed_build_attached": True,
                    "rollback_note_attached": True,
                },
                {
                    "release_package_attached": True,
                    "platform_smoke_outputs_attached": True,
                    "signing_notarization_logs_attached": True,
                    "dependency_sbom_attached": True,
                    "sandbox_corpus_results_attached": True,
                    "appsec_signoff_attached": True,
                    "support_evidence_attached": True,
                    "remaining_blockers_owner_assigned": True,
                },
            ]
            for number, checks in enumerate(independent_checks, start=14):
                evidence_file = independent_files_dir / f"independent-evidence-{number}.txt"
                evidence_file.write_text(f"independent evidence {number}\n", encoding="utf-8")
                item = {
                    "number": number,
                    "status": "pass",
                    "checks": checks,
                    "required_files": [
                        {
                            "path": str(evidence_file),
                            "sha256": hashlib.sha256(evidence_file.read_bytes()).hexdigest(),
                        }
                    ],
                }
                if number == 15:
                    item["reviewer_identity"] = "Independent AppSec Reviewer"
                if number == 16:
                    item["support_contact"] = "support@example.invalid"
                independent_items.append(item)
            independent_payload = {
                "profile_version": "independent-operations-evidence-v1",
                "scope": "independent-validation-operations-14-18",
                "items": independent_items,
            }
            independent_payload["evidence_package_hash"] = hashlib.sha256(
                json.dumps(independent_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
            independent_evidence_path.write_text(
                json.dumps(independent_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--columnar-benchmark-dir",
                    str(columnar_benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--crash-smoke-json",
                    str(crash_smoke_dir / "crash-export-smoke.json"),
                    "--crash-redaction-review-json",
                    str(crash_smoke_dir / "crash-redaction-review.json"),
                    "--parser-sandbox-smoke-json",
                    str(parser_sandbox_path),
                    "--dependency-monitoring-json",
                    str(dependency_monitoring_path),
                    "--security-hardening-review-json",
                    str(security_hardening_path),
                    "--external-release-evidence-json",
                    str(external_evidence_path),
                    "--hostile-evidence-containment-json",
                    str(hostile_evidence_path),
                    "--independent-operations-evidence-json",
                    str(independent_evidence_path),
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["release_gate"], "pass")
            self.assertEqual(report["inputs"]["required_smoke_platforms"], ["windows"])
            self.assertEqual(report["summary"]["fail"], 0)
            check_ids = {item["id"] for item in report["checks"]}
            self.assertIn("smoke-platform-windows", check_ids)
            self.assertIn("columnar-benchmark-jsonl-metrics", check_ids)
            self.assertIn("columnar-benchmark-commercial-disclosure", check_ids)
            self.assertIn("crash-export-smoke-bundle-hash", check_ids)
            self.assertIn("crash-export-smoke-report-grade-plan", check_ids)
            self.assertIn("crash-redaction-review-checks", check_ids)
            self.assertIn("crash-redaction-review-report-grade-plan", check_ids)
            self.assertIn("parser-sandbox-smoke-limitation-preserved", check_ids)
            self.assertIn("dependency-monitoring-ci-workflow", check_ids)
            self.assertIn("dependency-monitoring-limitation-preserved", check_ids)
            self.assertIn("security-hardening-review-boundaries", check_ids)
            self.assertIn("security-hardening-review-hashes", check_ids)
            self.assertIn("external-release-evidence-item-01", check_ids)
            self.assertIn("external-release-evidence-item-08", check_ids)
            self.assertIn("external-release-evidence-package-hash", check_ids)
            self.assertIn("hostile-evidence-containment-item-09", check_ids)
            self.assertIn("hostile-evidence-containment-item-13", check_ids)
            self.assertIn("hostile-evidence-containment-package-hash", check_ids)
            self.assertIn("independent-operations-evidence-item-14", check_ids)
            self.assertIn("independent-operations-evidence-item-18", check_ids)
            self.assertIn("independent-operations-evidence-package-hash", check_ids)
            self.assertEqual(report["inputs"]["crash_smoke_json"], str((crash_smoke_dir / "crash-export-smoke.json").resolve()))
            self.assertEqual(
                report["inputs"]["crash_redaction_review_json"],
                str((crash_smoke_dir / "crash-redaction-review.json").resolve()),
            )
            self.assertEqual(report["inputs"]["parser_sandbox_smoke_json"], str(parser_sandbox_path.resolve()))
            self.assertEqual(report["inputs"]["dependency_monitoring_json"], str(dependency_monitoring_path.resolve()))
            self.assertEqual(report["inputs"]["security_hardening_review_json"], str(security_hardening_path.resolve()))
            self.assertEqual(report["inputs"]["external_release_evidence_json"], str(external_evidence_path.resolve()))
            self.assertEqual(report["inputs"]["hostile_evidence_containment_json"], str(hostile_evidence_path.resolve()))
            self.assertEqual(
                report["inputs"]["independent_operations_evidence_json"],
                str(independent_evidence_path.resolve()),
            )
            self.assertTrue((evidence_dir / "release-evidence-report.md").is_file())

    def test_release_evidence_script_reports_missing_required_smoke_platform(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            smoke_dir = root / "smoke-windows"
            evidence_dir = root / "release-evidence"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)

            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)

            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(
                json.dumps({"passed": True, "platform": "windows", "checks": []}),
                encoding="utf-8",
            )
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--require-smoke-platform",
                    "macos-linux",
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            self.assertFalse(report["passed"])
            self.assertEqual(report["release_gate"], "fail")
            failed = {item["id"]: item for item in report["checks"] if item["status"] == "fail"}
            self.assertIn("smoke-platform-macos-linux", failed)
            self.assertTrue(any("macos-linux" in action for action in report["next_actions"]))

    def test_release_evidence_script_fails_incomplete_external_evidence_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            smoke_dir = root / "smoke-windows"
            evidence_dir = root / "release-evidence"
            external_evidence_path = root / "external-commercial-evidence.json"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)
            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)
            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(
                json.dumps({"passed": True, "platform": "windows", "checks": []}),
                encoding="utf-8",
            )
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")
            external_evidence_path.write_text(
                json.dumps(
                    {
                        "profile_version": "external-commercial-evidence-v1",
                        "scope": "release-artifact-evidence-1-8",
                        "items": [{"number": 1, "status": "pass", "checks": {}, "required_files": []}],
                        "evidence_package_hash": "a" * 64,
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--external-release-evidence-json",
                    str(external_evidence_path),
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            failed = {item["id"]: item for item in report["checks"] if item["status"] == "fail"}
            self.assertIn("external-release-evidence-item-coverage", failed)
            self.assertIn("external-release-evidence-item-01", failed)
            self.assertTrue(any("external-commercial-evidence-v1" in action for action in report["next_actions"]))

    def test_release_evidence_script_fails_incomplete_hostile_evidence_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            smoke_dir = root / "smoke-windows"
            evidence_dir = root / "release-evidence"
            hostile_evidence_path = root / "hostile-evidence-containment.json"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)
            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)
            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(
                json.dumps({"passed": True, "platform": "windows", "checks": []}),
                encoding="utf-8",
            )
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")
            hostile_evidence_path.write_text(
                json.dumps(
                    {
                        "profile_version": "hostile-evidence-containment-v1",
                        "scope": "hostile-evidence-containment-9-13",
                        "items": [{"number": 9, "status": "pass", "checks": {}, "required_files": []}],
                        "evidence_package_hash": "b" * 64,
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--hostile-evidence-containment-json",
                    str(hostile_evidence_path),
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            failed = {item["id"]: item for item in report["checks"] if item["status"] == "fail"}
            self.assertIn("hostile-evidence-containment-item-coverage", failed)
            self.assertIn("hostile-evidence-containment-item-09", failed)
            self.assertTrue(any("hostile-evidence-containment-v1" in action for action in report["next_actions"]))

    def test_release_evidence_script_fails_incomplete_independent_operations_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            repo = Path(__file__).resolve().parent.parent
            release_dir = root / "release"
            validation_dir = root / "validation"
            benchmark_dir = root / "benchmark"
            smoke_dir = root / "smoke-windows"
            evidence_dir = root / "release-evidence"
            independent_evidence_path = root / "independent-operations-evidence.json"

            release = subprocess.run(
                ["python", "scripts/build-release.py", "--output-dir", str(release_dir), "--skip-build"],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(release.returncode, 0, release.stderr)
            with contextlib.redirect_stdout(io.StringIO()):
                validation_exit = main(["validation", "--output-dir", str(validation_dir), "--json"])
                benchmark_exit = main(
                    [
                        "benchmark",
                        "--output-dir",
                        str(benchmark_dir),
                        "--file-count",
                        "3",
                        "--search-iterations",
                        "1",
                        "--overwrite",
                        "--json",
                    ]
                )
            self.assertEqual(validation_exit, 0)
            self.assertEqual(benchmark_exit, 0)
            smoke_dir.mkdir()
            (smoke_dir / "smoke-summary.json").write_text(
                json.dumps({"passed": True, "platform": "windows", "checks": []}),
                encoding="utf-8",
            )
            (smoke_dir / "smoke-summary.md").write_text("# PASS\n", encoding="utf-8")
            independent_evidence_path.write_text(
                json.dumps(
                    {
                        "profile_version": "independent-operations-evidence-v1",
                        "scope": "independent-validation-operations-14-18",
                        "items": [{"number": 14, "status": "pass", "checks": {}, "required_files": []}],
                        "evidence_package_hash": "c" * 64,
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python",
                    "scripts/verify-release-evidence.py",
                    "--release-dir",
                    str(release_dir),
                    "--validation-dir",
                    str(validation_dir),
                    "--benchmark-dir",
                    str(benchmark_dir),
                    "--smoke-dir",
                    str(smoke_dir),
                    "--require-smoke-platform",
                    "windows",
                    "--independent-operations-evidence-json",
                    str(independent_evidence_path),
                    "--output-dir",
                    str(evidence_dir),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            report = json.loads((evidence_dir / "release-evidence-report.json").read_text(encoding="utf-8"))
            failed = {item["id"]: item for item in report["checks"] if item["status"] == "fail"}
            self.assertIn("independent-operations-evidence-item-coverage", failed)
            self.assertIn("independent-operations-evidence-item-14", failed)
            self.assertTrue(any("independent-operations-evidence-v1" in action for action in report["next_actions"]))


if __name__ == "__main__":
    unittest.main()
