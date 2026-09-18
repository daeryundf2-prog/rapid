from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .process_bounds import child_process_boundary_profile, run_bounded_paths
from .visible_capabilities import CAPABILITY_GROUPS, STATUS_LABELS, STATUS_NEXT_ACTIONS

RELEASE_GATE_MANIFEST_VERSION = "release-gate-manifest-v1"
KNOWN_ANSWER_MATRIX_VERSION = "known-answer-coverage-matrix-v1"

CAPABILITY_TIERS = (
    "inventory",
    "bounded-native-parsing",
    "external-import",
    "independent-validation",
)

STATUS_TO_CAPABILITY_TIER = {
    "inventory": "inventory",
    "partial": "bounded-native-parsing",
    "usable": "bounded-native-parsing",
    "validation-required": "independent-validation",
    "external-required": "external-import",
}

GROUP_TEST_EVIDENCE: dict[str, tuple[str, ...]] = {
    "evidence-image-input": (
        "tests/test_rapidtriage_e01.py",
        "tests/test_rapidtriage_e01_hash.py",
        "tests/test_rapidtriage_stage3_integrity.py",
    ),
    "windows-eventlog": ("tests/test_rapidtriage_windows_artifacts.py",),
    "windows-eventlog-dfir": ("tests/test_rapidtriage_windows_artifacts.py",),
    "windows-registry-account": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
    "windows-execution-filesystem": (
        "tests/test_rapidtriage_windows_artifacts_collectors.py",
        "tests/test_rapidtriage_stage5_performance.py",
    ),
    "browser-internet": ("tests/test_rapidtriage_browser_stress.py",),
    "browser-deep-recovery": ("tests/test_rapidtriage_browser_stress.py",),
    "ai-service-usage": ("tests/test_rapidtriage_cloud_collect.py",),
    "ai-local-desktop-recall": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
    "documents-email-database": (
        "tests/test_rapidtriage_email_artifacts.py",
        "tests/test_rapidtriage_generic_documents.py",
    ),
    "docs-leakage-artifacts": ("tests/test_rapidtriage_generic_documents.py",),
    "messenger-mobile": (
        "tests/test_rapidtriage_kakaotalk_windows.py",
        "tests/test_rapidtriage_mobile_export.py",
        "tests/test_rapidtriage_android_apk.py",
    ),
    "mobile-location-behavior": ("tests/test_rapidtriage_mobile_export.py",),
    "cloud-exports": (
        "tests/test_rapidtriage_cloud_export.py",
        "tests/test_rapidtriage_cloud_collect.py",
    ),
    "cloud-iaas-audit": ("tests/test_rapidtriage_cloud_collect.py",),
    "media-ocr-review": (
        "tests/test_rapidtriage_media_image.py",
        "tests/test_rapidtriage_ocr_queue.py",
        "tests/test_rapidtriage_synthetic_media.py",
    ),
    "media-advanced-forensics": (
        "tests/test_rapidtriage_synthetic_media.py",
        "tests/test_rapidtriage_synthetic_media_reporting.py",
    ),
    "dfir-memory-threat": (
        "tests/test_rapidtriage_memory_volatility.py",
        "tests/test_rapidtriage_indicators.py",
    ),
    "memory-disk-artifacts": ("tests/test_rapidtriage_memory_artifacts.py",),
    "evidence-recovery-unlock": (
        "tests/test_rapidtriage_kakaotalk_decrypt.py",
        "tests/test_rapidtriage_carving.py",
    ),
    "filesystem-antiforensics": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
    "usb-persistence-network": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
    "execution-user-activity": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
    "incident-remote-tampering": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
    "review-search-advanced": ("tests/test_rapidtriage_search_analysis.py",),
    "review-report-citation": (
        "tests/test_rapidtriage_final_roadmap.py",
        "tests/test_rapidtriage_reviewer_attribution.py",
    ),
}

KNOWN_ANSWER_MATRIX_SLOTS: tuple[dict[str, Any], ...] = (
    {
        "slot_id": "sqlite-wal-decode",
        "scope": "SQLite WAL membership, snapshot isolation, and frame decode",
        "status": "executed-synthetic",
        "executed_tests": (
            "tests/test_rapidtriage_sqlite_wal.py",
            "tests/test_rapidtriage_sqlite_snapshot.py",
            "tests/test_rapidtriage_sqlite_fuzz.py",
        ),
        "known_limitations": ("synthetic fixtures only; no externally acquired WAL corpus",),
    },
    {
        "slot_id": "image-segment-sets",
        "scope": "E01/Ex01 multi-segment hashing, checkpoint binding, recovery scope",
        "status": "executed-synthetic",
        "executed_tests": (
            "tests/test_rapidtriage_e01.py",
            "tests/test_rapidtriage_e01_hash.py",
            "tests/test_rapidtriage_stage3_integrity.py",
        ),
        "known_limitations": ("no libewf/trusted-tool comparison; synthetic segment fixtures",),
    },
    {
        "slot_id": "timestamp-decoding",
        "scope": "FILETIME/USN/MFT timestamp decode and stomping heuristics",
        "status": "executed-synthetic",
        "executed_tests": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
        "known_limitations": ("parser-structural checks only; not validated against reference parsers",),
    },
    {
        "slot_id": "archive-member-identity",
        "scope": "archive member identity, path confinement, manifest authority",
        "status": "executed-synthetic",
        "executed_tests": (
            "tests/test_rapidtriage_extract_contract.py",
            "tests/test_rapidtriage_extract.py",
            "tests/test_evidence_bundle.py",
        ),
        "known_limitations": ("in-archive manifest remains non-authoritative by design",),
    },
    {
        "slot_id": "parser-omission-coverage",
        "scope": "artifact taxonomy audit as omission check over artifact_type literals",
        "status": "executed-synthetic",
        "executed_tests": ("tests/test_rapidtriage_artifact_taxonomy.py",),
        "known_limitations": ("omission check only; does not prove decode correctness",),
    },
    {
        "slot_id": "external-known-answer-corpus",
        "scope": "externally acquired E01/Ex01, Windows host outputs, trusted-tool exports",
        "status": "blocked-external-evidence-required",
        "executed_tests": (),
        "known_limitations": (
            "requires externally supplied datasets and trusted-tool records outside Git",
        ),
    },
)

RELEASE_GATE_SLOTS: tuple[dict[str, Any], ...] = (
    {
        "gate_id": "unit-and-regression-execution",
        "status": "executed",
        "evidence": "python3 -m unittest targeted suites; see FORENSIC_HARDENING_PLAN.md stage status lines",
    },
    {
        "gate_id": "static-analysis",
        "status": "executed",
        "evidence": "ruff check rapidtriage tests scripts; vulture --min-confidence 80; compileall; node --check",
    },
    {
        "gate_id": "dependency-advisory-disposition",
        "status": "executed",
        "evidence": "pip-audit recorded PASS in FORENSIC_HARDENING_PLAN.md baseline table",
    },
    {
        "gate_id": "coverage-measurement",
        "status": "blocked-not-executed",
        "evidence": "no coverage tooling run; percentage and uncovered-path data unavailable",
    },
    {
        "gate_id": "build-install-smoke",
        "status": "blocked-not-executed",
        "evidence": "no clean build/install smoke executed in this pass",
    },
    {
        "gate_id": "platform-validation-windows",
        "status": "blocked-external-evidence-required",
        "evidence": "no Windows host execution record",
    },
    {
        "gate_id": "platform-validation-linux",
        "status": "blocked-not-executed",
        "evidence": "no Linux execution record in this pass",
    },
    {
        "gate_id": "windows-e01-ex01-recovery",
        "status": "blocked-external-evidence-required",
        "evidence": "real E01/Ex01 acquisition and recovery run required outside Git",
    },
    {
        "gate_id": "trusted-tool-record-diff",
        "status": "blocked-external-evidence-required",
        "evidence": "trusted/reference tool outputs required",
    },
    {
        "gate_id": "tb-scale-runs",
        "status": "blocked-external-evidence-required",
        "evidence": "10 TB / 1M-file survival runs not executed",
    },
    {
        "gate_id": "installer-signing",
        "status": "blocked-external-evidence-required",
        "evidence": "signing pipeline and notarization evidence not present",
    },
    {
        "gate_id": "independent-human-review",
        "status": "blocked-external-evidence-required",
        "evidence": "external reviewer signoff not attached",
    },
)

PARSER_REPORTABILITY_BOUNDARY = {
    "boundary_version": "parser-reportability-boundary-v1",
    "separation": (
        "Parser modules emit decoded fields plus reportability markers "
        "('inventory-only', 'triage', validation checks); report-grade policy "
        "lives in ntfs_report_grade_assessment/hash_cache_report_grade_validation_plan/"
        "known-answer validation layers and does not alter decoded values."
    ),
    "parser_modules_do_not_set": ("ready_for_court_report", "commercial_grade_ready=True"),
    "search_storage_ui_migrations": "separately reviewed changes; not bundled into parser fixes",
}


def capability_tier_for_status(status: str) -> str:
    return STATUS_TO_CAPABILITY_TIER.get(str(status or ""), "inventory")


def build_capability_tier_manifest() -> dict[str, object]:
    groups: list[dict[str, object]] = []
    counts = {tier: 0 for tier in CAPABILITY_TIERS}
    executed = 0
    blocked = 0
    for group in CAPABILITY_GROUPS:
        group_id = str(group.get("id") or "")
        executed_tests = list(GROUP_TEST_EVIDENCE.get(group_id, ()))
        capabilities: list[dict[str, object]] = []
        for capability in group.get("capabilities", ()):
            status = str(capability.get("status") or "")
            tier = capability_tier_for_status(status)
            counts[tier] += 1
            evidence_status = "executed" if executed_tests else "blocked"
            if executed_tests:
                executed += 1
            else:
                blocked += 1
            capabilities.append(
                {
                    "id": capability.get("id"),
                    "label": capability.get("label"),
                    "status": status,
                    "status_label": STATUS_LABELS.get(status, status),
                    "capability_tier": tier,
                    "evidence_status": evidence_status,
                    "executed_tests": executed_tests,
                    "known_limitations": [STATUS_NEXT_ACTIONS.get(status, "")],
                }
            )
        groups.append(
            {
                "group_id": group_id,
                "label": group.get("label"),
                "capability_count": len(capabilities),
                "executed_tests": executed_tests,
                "capabilities": capabilities,
            }
        )
    manifest_core = {
        "profile_version": "capability-tier-manifest-v1",
        "capability_tiers": list(CAPABILITY_TIERS),
        "status_to_tier": dict(STATUS_TO_CAPABILITY_TIER),
        "tier_counts": counts,
        "capability_count": sum(counts.values()),
        "executed_capability_count": executed,
        "blocked_capability_count": blocked,
        "taxonomy_coverage_role": "omission-check-only",
        "groups": groups,
        "commercial_claim_allowed": False,
    }
    manifest_core["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest_core, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return manifest_core


def build_known_answer_matrix() -> dict[str, object]:
    slots = [dict(slot) for slot in KNOWN_ANSWER_MATRIX_SLOTS]
    matrix_core = {
        "matrix_version": KNOWN_ANSWER_MATRIX_VERSION,
        "slot_count": len(slots),
        "executed_slot_count": sum(1 for slot in slots if str(slot["status"]).startswith("executed")),
        "blocked_slot_count": sum(1 for slot in slots if str(slot["status"]).startswith("blocked")),
        "slots": slots,
        "commercial_claim_allowed": False,
    }
    matrix_core["matrix_sha256"] = hashlib.sha256(
        json.dumps(matrix_core, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return matrix_core


def build_release_gate_manifest(*, evidence_inputs: Mapping[str, object] | None = None) -> dict[str, object]:
    capability_manifest = build_capability_tier_manifest()
    known_answer_matrix = build_known_answer_matrix()
    boundary_profile = child_process_boundary_profile()
    gates = [dict(gate) for gate in RELEASE_GATE_SLOTS]
    if evidence_inputs:
        for gate in gates:
            override = (evidence_inputs.get(gate["gate_id"]) or {}) if isinstance(
                evidence_inputs.get(gate["gate_id"]), Mapping
            ) else {}
            if override.get("executed_evidence"):
                gate["status"] = "executed"
                gate["evidence"] = str(override["executed_evidence"])
    blocked_gates = [gate["gate_id"] for gate in gates if str(gate["status"]).startswith("blocked")]
    manifest_core = {
        "profile_version": RELEASE_GATE_MANIFEST_VERSION,
        "release_ready": not blocked_gates,
        "blocked_gate_ids": blocked_gates,
        "gate_count": len(gates),
        "gates": gates,
        "capability_tier_manifest": capability_manifest,
        "capability_tier_manifest_sha256": capability_manifest["manifest_sha256"],
        "known_answer_matrix": known_answer_matrix,
        "known_answer_matrix_sha256": known_answer_matrix["matrix_sha256"],
        "child_process_boundary": boundary_profile,
        "bounded_runner_paths": run_bounded_paths(),
        "parser_reportability_boundary": dict(PARSER_REPORTABILITY_BOUNDARY),
        "external_evidence_policy": (
            "Windows E01/Ex01 recovery, trusted-tool diffs, TB-scale runs, installer signing, "
            "and independent human review stay blocked until externally supplied evidence exists."
        ),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
    }
    manifest_core["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest_core, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return manifest_core
