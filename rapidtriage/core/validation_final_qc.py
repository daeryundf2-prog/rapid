from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from .validation_diff_runners import build_validation_diff_runner_matrix


def build_final_qc_execution_report(
    *,
    validation_package: Path | None = None,
    runner_matrix: Path | None = None,
    performance_runs: Sequence[Path] | None = None,
    browser_traces: Sequence[Path] | None = None,
    reviewer_signoffs: Sequence[Path] | None = None,
) -> dict[str, object]:
    diff_runner_matrix = build_validation_diff_runner_matrix()
    performance_runs = performance_runs or []
    browser_traces = browser_traces or []
    reviewer_signoffs = reviewer_signoffs or []
    evidence_inputs = {
        "validation_package": _file_state(validation_package),
        "runner_matrix": _file_state(runner_matrix),
        "performance_runs": [_file_state(path) for path in performance_runs],
        "browser_traces": [_file_state(path) for path in browser_traces],
        "reviewer_signoffs": [_file_state(path) for path in reviewer_signoffs],
    }
    e01_contract = _windows11_e01_known_answer_contract()
    fixture_contract = _adverse_fixture_corpus_contract()
    large_case_contract = _large_case_browser_trace_contract()
    final_report_contract = _final_report_contract(evidence_inputs=evidence_inputs)
    checklist = _final_qc_checklist(
        evidence_inputs=evidence_inputs,
        runner_matrix=diff_runner_matrix,
    )
    core = {
        "profile_version": "final-qc-execution-report-v1",
        "qc_prep_item_numbers": [81, 82, 83, 84, 85],
        "status": "external-evidence-required" if checklist["failed_check_ids"] else "ready-for-qc-review",
        "diff_runner_matrix": diff_runner_matrix,
        "windows11_e01_known_answer_contract": e01_contract,
        "adverse_fixture_corpus_contract": fixture_contract,
        "large_case_browser_trace_contract": large_case_contract,
        "final_report_contract": final_report_contract,
        "evidence_inputs": evidence_inputs,
        "final_qc_checklist": checklist,
        "commercial_grade_blockers": [
            "real-windows11-e01-known-answer-case-required",
            "adverse-fixture-corpus-execution-required",
            "large-case-performance-and-browser-trace-required",
            "reviewer-signoff-required",
            "remaining-blocker-ledger-review-required",
        ],
    }
    return {
        **core,
        "report_hash": hashlib.sha256(json.dumps(core, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def write_final_qc_execution_report(payload: Mapping[str, object], output: Path) -> dict[str, object]:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "output": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "bytes": output.stat().st_size,
    }


def _windows11_e01_known_answer_contract() -> dict[str, object]:
    return {
        "profile_version": "windows11-e01-known-answer-qc-contract-v1",
        "qc_prep_item_number": 82,
        "generator_command": "rapidtriage e01-known-answer <Windows11.E01> --output windows11-e01-known-answer.json",
        "required_evidence_slots": [
            "source E01/segment SHA256 and segment order",
            "dependency/preflight transcript",
            "partition selection and filesystem assertion",
            "expected Windows artifact list",
            "RapidTriage output paths",
            "trusted tool exports",
            "cross-tool diff outputs",
            "reviewer signoff",
        ],
        "reportability": "not-commercial-grade-until-real-case-diff-and-signoff",
    }


def _adverse_fixture_corpus_contract() -> dict[str, object]:
    fixture_types = ["corrupt", "deleted", "slack", "encrypted", "malformed"]
    return {
        "profile_version": "adverse-fixture-corpus-contract-v1",
        "qc_prep_item_number": 83,
        "fixture_types": [
            {
                "fixture_type": fixture_type,
                "required_metadata": [
                    "fixture_id",
                    "source_hash",
                    "expected_behavior",
                    "parser_family",
                    "expected_warning_or_error",
                    "trusted_oracle",
                ],
            }
            for fixture_type in fixture_types
        ],
        "required_parser_families": ["evtx", "registry", "ntfs", "ese", "browser", "messenger-email-cloud"],
        "release_gate": "all claimed parser families need at least one adverse fixture or documented exclusion",
    }


def _large_case_browser_trace_contract() -> dict[str, object]:
    return {
        "profile_version": "large-case-browser-trace-contract-v1",
        "qc_prep_item_number": 84,
        "required_runs": [
            {
                "run_type": "large-case-performance",
                "minimum_scenarios": ["100k-record", "1m-record", "10m-record-or-hardware-waiver"],
                "metrics": ["ingest_rows_per_second", "search_p95_ms", "peak_rss_bytes", "failure_count"],
            },
            {
                "run_type": "browser-trace",
                "minimum_scenarios": ["large-result-table", "source-viewer-open", "review-tagging", "report-selection"],
                "metrics": ["dom_node_count", "interaction_p95_ms", "memory_mb", "screenshot_or_trace_path"],
            },
        ],
        "recommended_commands": [
            "rapidtriage benchmark --record-count 100000 --json",
            "rapidtriage stress-plan --output-dir stress-plan --json",
            "browser trace via Playwright or equivalent on the workbench large-result flow",
        ],
    }


def _final_report_contract(*, evidence_inputs: Mapping[str, object]) -> dict[str, object]:
    return {
        "profile_version": "final-qc-report-contract-v1",
        "qc_prep_item_number": 85,
        "required_sections": [
            "validation package summary",
            "trusted-diff mismatch dashboard summary",
            "performance and browser trace summary",
            "reviewer signoff inventory",
            "remaining blocker ledger",
            "commercial-grade claim decision",
        ],
        "attached_evidence_counts": {
            "performance_runs": len(evidence_inputs.get("performance_runs") or []),
            "browser_traces": len(evidence_inputs.get("browser_traces") or []),
            "reviewer_signoffs": len(evidence_inputs.get("reviewer_signoffs") or []),
        },
        "commercial_claim_allowed": False,
        "operator_warning": "This report is a QC execution wrapper. It does not make commercial-grade claims unless all external evidence files pass review.",
    }


def _final_qc_checklist(
    *,
    evidence_inputs: Mapping[str, object],
    runner_matrix: Mapping[str, object],
) -> dict[str, object]:
    checks = [
        _check("execution-user-activity-runners-defined", _has_runner_group(runner_matrix, 81), "#81 runner group exists"),
        _check("validation-package-attached", bool(evidence_inputs["validation_package"]["exists"]), "validation package path exists"),
        _check("runner-matrix-attached", bool(evidence_inputs["runner_matrix"]["exists"]), "runner matrix path exists"),
        _check("performance-run-attached", bool(evidence_inputs.get("performance_runs")), "at least one performance run path provided"),
        _check("browser-trace-attached", bool(evidence_inputs.get("browser_traces")), "at least one browser trace path provided"),
        _check("reviewer-signoff-attached", bool(evidence_inputs.get("reviewer_signoffs")), "at least one reviewer signoff path provided"),
    ]
    failed = [str(item["check_id"]) for item in checks if not item["passed"]]
    return {
        "profile_version": "final-qc-checklist-v1",
        "ready_for_final_qc_review": not failed,
        "ready_for_commercial_grade_claim": False,
        "checks": checks,
        "failed_check_ids": failed,
    }


def _has_runner_group(runner_matrix: Mapping[str, object], item_number: int) -> bool:
    groups = runner_matrix.get("runner_groups") if isinstance(runner_matrix.get("runner_groups"), list) else []
    return any(isinstance(group, Mapping) and group.get("item_number") == item_number for group in groups)


def _check(check_id: str, passed: bool, evidence: str) -> dict[str, object]:
    return {"check_id": check_id, "passed": bool(passed), "evidence": evidence}


def _file_state(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"path": "", "exists": False, "sha256": "", "bytes": 0}
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        return {"path": str(resolved), "exists": False, "sha256": "", "bytes": 0}
    data = resolved.read_bytes()
    return {
        "path": str(resolved),
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }
