from __future__ import annotations

import subprocess
import sys
import unittest

from rapidtriage.core.process_bounds import (
    CHILD_TIMEOUT_EXIT_CODE,
    child_process_boundary_profile,
    run_bounded_command,
)
from rapidtriage.core.release_gates import (
    CAPABILITY_TIERS,
    STATUS_TO_CAPABILITY_TIER,
    build_capability_tier_manifest,
    build_known_answer_matrix,
    build_release_gate_manifest,
)
from rapidtriage.core.visible_capabilities import CAPABILITY_GROUPS


class Stage6CapabilityTierTests(unittest.TestCase):
    def test_every_catalog_status_maps_to_a_declared_tier(self) -> None:
        for group in CAPABILITY_GROUPS:
            for capability in group.get("capabilities", ()):
                status = str(capability.get("status") or "")
                self.assertIn(
                    status,
                    STATUS_TO_CAPABILITY_TIER,
                    f"{group.get('id')}/{capability.get('id')} has unmapped status {status!r}",
                )

    def test_tier_manifest_links_capabilities_to_tests_and_limitations(self) -> None:
        manifest = build_capability_tier_manifest()
        self.assertEqual(tuple(manifest["capability_tiers"]), CAPABILITY_TIERS)
        self.assertGreater(manifest["capability_count"], 0)
        self.assertEqual(
            manifest["capability_count"],
            manifest["executed_capability_count"] + manifest["blocked_capability_count"],
        )
        for group in manifest["groups"]:
            for capability in group["capabilities"]:
                self.assertIn(capability["capability_tier"], CAPABILITY_TIERS)
                if capability["evidence_status"] == "executed":
                    self.assertTrue(capability["executed_tests"])
                else:
                    self.assertEqual(capability["evidence_status"], "blocked")
                self.assertTrue(capability["known_limitations"])
        self.assertEqual(manifest["taxonomy_coverage_role"], "omission-check-only")
        self.assertTrue(manifest["manifest_sha256"])

    def test_tiers_separate_inventory_parsing_import_validation(self) -> None:
        self.assertEqual(STATUS_TO_CAPABILITY_TIER["inventory"], "inventory")
        self.assertEqual(STATUS_TO_CAPABILITY_TIER["partial"], "bounded-native-parsing")
        self.assertEqual(STATUS_TO_CAPABILITY_TIER["usable"], "bounded-native-parsing")
        self.assertEqual(STATUS_TO_CAPABILITY_TIER["external-required"], "external-import")
        self.assertEqual(STATUS_TO_CAPABILITY_TIER["validation-required"], "independent-validation")


class Stage6KnownAnswerMatrixTests(unittest.TestCase):
    def test_matrix_is_versioned_and_covers_required_scopes(self) -> None:
        matrix = build_known_answer_matrix()
        self.assertEqual(matrix["matrix_version"], "known-answer-coverage-matrix-v1")
        slot_ids = {slot["slot_id"] for slot in matrix["slots"]}
        self.assertEqual(
            slot_ids,
            {
                "sqlite-wal-decode",
                "image-segment-sets",
                "timestamp-decoding",
                "archive-member-identity",
                "parser-omission-coverage",
                "external-known-answer-corpus",
            },
        )
        self.assertEqual(matrix["executed_slot_count"] + matrix["blocked_slot_count"], matrix["slot_count"])

    def test_external_corpus_slot_stays_blocked(self) -> None:
        matrix = build_known_answer_matrix()
        external = next(s for s in matrix["slots"] if s["slot_id"] == "external-known-answer-corpus")
        self.assertEqual(external["status"], "blocked-external-evidence-required")
        self.assertEqual(external["executed_tests"], ())


class Stage6ChildProcessBoundaryTests(unittest.TestCase):
    def test_bounded_runner_completes_normal_command(self) -> None:
        result = run_bounded_command([sys.executable, "-c", "print('ok')"], timeout_seconds=30)
        self.assertEqual(result.returncode, 0)
        self.assertIn("ok", result.stdout)

    def test_bounded_runner_times_out_without_raising(self) -> None:
        result = run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout_seconds=1,
        )
        self.assertEqual(result.returncode, CHILD_TIMEOUT_EXIT_CODE)
        self.assertIn("timed out", result.stderr)

    def test_boundary_profile_does_not_claim_sandboxing(self) -> None:
        profile = child_process_boundary_profile()
        self.assertIs(profile["hostile_evidence_sandboxed"], False)
        self.assertIs(profile["commercial_claim_allowed"], False)
        self.assertFalse(profile["enforced"]["shell"])
        if profile["platform_posix"]:
            self.assertGreater(profile["enforced"]["rlimit_cpu_seconds"], 0)
            self.assertGreater(profile["enforced"]["rlimit_fsize_bytes"], 0)
        self.assertIn("filesystem_isolation", profile["not_enforced"])
        self.assertIn("network_isolation", profile["not_enforced"])

    def test_default_runners_use_bounded_runner(self) -> None:
        from rapidtriage.core import archive_image, disk_image, e01, virtual_disk

        for module in (e01, disk_image, virtual_disk, archive_image):
            result = module.default_runner([sys.executable, "-c", "print('bounded')"])
            self.assertIsInstance(result, subprocess.CompletedProcess)
            self.assertEqual(result.returncode, 0)
            self.assertIn("bounded", result.stdout)


class Stage6ReleaseGateManifestTests(unittest.TestCase):
    def test_release_gate_manifest_reports_blocked_gates(self) -> None:
        manifest = build_release_gate_manifest()
        self.assertIs(manifest["release_ready"], False)
        self.assertIn("windows-e01-ex01-recovery", manifest["blocked_gate_ids"])
        self.assertIn("trusted-tool-record-diff", manifest["blocked_gate_ids"])
        self.assertIn("tb-scale-runs", manifest["blocked_gate_ids"])
        self.assertIn("installer-signing", manifest["blocked_gate_ids"])
        self.assertIn("independent-human-review", manifest["blocked_gate_ids"])
        self.assertIs(manifest["ready_for_court_report"], False)
        self.assertIs(manifest["commercial_claim_allowed"], False)
        self.assertTrue(manifest["manifest_sha256"])

    def test_executed_gates_have_evidence(self) -> None:
        manifest = build_release_gate_manifest()
        executed = [gate for gate in manifest["gates"] if gate["status"] == "executed"]
        self.assertTrue(executed)
        for gate in executed:
            self.assertTrue(gate["evidence"])

    def test_evidence_inputs_can_flip_only_documented_gates(self) -> None:
        manifest = build_release_gate_manifest(
            evidence_inputs={"coverage-measurement": {"executed_evidence": "coverage run 2026-09-18: 82%"}}
        )
        coverage = next(g for g in manifest["gates"] if g["gate_id"] == "coverage-measurement")
        self.assertEqual(coverage["status"], "executed")
        self.assertNotIn("coverage-measurement", manifest["blocked_gate_ids"])
        self.assertIs(manifest["release_ready"], False)


if __name__ == "__main__":
    unittest.main()
