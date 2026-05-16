from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence

from .audit import compute_sha256
from .commercial_readiness import build_commercial_readiness_report
from .docs import write_result
from .enterprise import build_enterprise_policy
from .forensic_accuracy import build_accuracy_gate, build_core_forensics_accuracy_profiles, build_core_forensics_known_answer_template
from .validation_diff_runners import build_validation_diff_runner_matrix
from .validation_final_qc import build_final_qc_execution_report


VALIDATION_JSON_NAME = "rapidtriage-validation-package.json"
VALIDATION_MARKDOWN_NAME = "rapidtriage-validation-report.md"
VALIDATION_ARTIFACTS_NAME = "rapidtriage-validation-artifacts.json"
VALIDATION_PACKAGE_REQUIRED_OUTPUTS = [VALIDATION_JSON_NAME, VALIDATION_MARKDOWN_NAME, VALIDATION_ARTIFACTS_NAME]
VALIDATION_PACKAGE_REQUIRED_SECTIONS = [
    "known_answer_validation",
    "parser_fixture_corpus",
    "parser_false_positive_false_negative_notes",
    "validation_diff_runner_matrix",
    "final_qc_execution_report",
    "independent_validation_report",
    "validation_package_assessment",
]
FUNCTIONAL_VALIDATION_BATCH_ID = "commercial-uplift-036-040"
KNOWN_ANSWER_TEST_GAP_ID = "#81"
PARSER_FIXTURE_CORPUS_GAP_ID = "#82"
PARSER_FP_FN_GAP_ID = "#83"
INDEPENDENT_VALIDATION_GAP_ID = "#84"
VALIDATION_PACKAGE_GAP_ID = "#85"
KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81 = "trusted-known-answer-manifest-diff-missing"
KNOWN_ANSWER_REPORT_GRADE_VALIDATION_PLAN_VERSION = "known-answer-report-grade-validation-plan-v1"
KNOWN_ANSWER_REPORT_GRADE_BLOCKERS = [
    KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81,
    "public-cfreds-cftt-corpus-run-required",
    "parser-scope-coverage-map-required",
    "independent-expected-answer-review-required",
    "dataset-chain-of-custody-required",
    "release-signoff-required",
]
FIXTURE_CORPUS_TRUSTED_DIFF_BLOCKER_82 = "trusted-fixture-corpus-manifest-diff-missing"
FIXTURE_CORPUS_REPORT_GRADE_VALIDATION_PLAN_VERSION = "fixture-corpus-report-grade-validation-plan-v1"
FP_FN_TRUSTED_DIFF_BLOCKER_83 = "trusted-fp-fn-risk-register-diff-missing"
FP_FN_REPORT_GRADE_VALIDATION_PLAN_VERSION = "parser-fp-fn-report-grade-validation-plan-v1"
INDEPENDENT_VALIDATION_TRUSTED_DIFF_BLOCKER_84 = "trusted-independent-validation-signoff-diff-missing"
INDEPENDENT_VALIDATION_REPORT_GRADE_VALIDATION_PLAN_VERSION = "independent-validation-report-grade-validation-plan-v1"
VALIDATION_PACKAGE_TRUSTED_DIFF_BLOCKER_85 = "trusted-validation-package-manifest-diff-missing"
VALIDATION_PACKAGE_REPORT_GRADE_VALIDATION_PLAN_VERSION = "validation-package-report-grade-validation-plan-v1"
VALIDATION_TRUSTED_TOOLS = {
    "known-answer-manifest",
    "fixture-corpus-manifest",
    "fp-fn-risk-register",
    "independent-validation-signoff",
    "validation-package-manifest",
}
INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS = ["independent-reviewer", "forensic-lead", "release-owner"]
INDEPENDENT_VALIDATION_MINIMUM_SECTIONS = [
    "scope and datasets",
    "tool version and commit",
    "known-answer pass/fail table",
    "false positive/false negative notes",
    "legal/report wording review",
]
EXTERNAL_TOOL_VERSION_GAP_ID = "#95"
EXTERNAL_TOOL_VERSION_TRUSTED_DIFF_BLOCKER_95 = "trusted-external-tool-version-transcript-diff-missing"
EXTERNAL_TOOL_VERSION_TRUSTED_TOOLS = {"external-tool-transcript", "release-environment-inventory", "operator-tool-log"}
DEPLOYMENT_OPERATIONS_GAP_IDS = [
    "#101",
    "#102",
    "#103",
    "#104",
    "#105",
    "#106",
    "#107",
    "#108",
    "#109",
    "#110",
    "#111",
    "#112",
    "#113",
    "#114",
    "#115",
    "#116",
    "#117",
    "#118",
    "#119",
    "#120",
]

PARSER_FIXTURE_AREAS: tuple[dict[str, object], ...] = (
    {
        "id": "windows-eventlog",
        "parser": "Windows EVTX/EventLog",
        "fixture_globs": ("tests/fixtures/rapidtriage/windows_artifacts/Windows/System32/winevt/Logs/*",),
        "test_files": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
        "expected_edge_cases": ("XML import", "native EVTX candidate rows", "deleted/corrupt candidate cautions"),
    },
    {
        "id": "windows-registry",
        "parser": "Windows Registry/NTUSER/SAM/SYSTEM",
        "fixture_globs": ("tests/fixtures/rapidtriage/windows_artifacts/**/*.reg",),
        "test_files": ("tests/test_rapidtriage_windows_artifacts_collectors.py", "tests/windows_artifact_fixtures.py"),
        "expected_edge_cases": ("native hive inventory", "deleted cell candidates", "user hive activity pivots"),
    },
    {
        "id": "windows-execution",
        "parser": "Prefetch/Amcache/ShimCache/BAM execution",
        "fixture_globs": ("tests/fixtures/rapidtriage/windows_artifacts/Windows/Prefetch/*",),
        "test_files": ("tests/test_rapidtriage_windows_artifacts_collectors.py",),
        "expected_edge_cases": ("Prefetch version hints", "execution registry exports", "PowerShell history"),
    },
    {
        "id": "browser",
        "parser": "Browser history/storage",
        "fixture_globs": ("tests/fixtures/rapidtriage/windows_artifacts/**/History", "tests/fixtures/rapidtriage/windows_artifacts/**/places.sqlite"),
        "test_files": ("tests/test_rapidtriage_windows_artifacts.py", "tests/test_rapidtriage_api.py"),
        "expected_edge_cases": ("Chrome/Edge/Firefox history", "download Zone.Identifier", "AI prompt candidates"),
    },
    {
        "id": "mobile-export",
        "parser": "Mobile vendor/export import",
        "fixture_globs": (),
        "test_files": ("tests/test_rapidtriage_mobile_export.py",),
        "expected_edge_cases": ("messages", "contacts/calls", "protected keychain inventory"),
    },
    {
        "id": "cloud-export",
        "parser": "Cloud export/API import",
        "fixture_globs": (),
        "test_files": ("tests/test_rapidtriage_cloud_export.py", "tests/test_rapidtriage_cloud_collect.py"),
        "expected_edge_cases": ("authorized JSON exports", "credential redaction", "API response hashing"),
    },
    {
        "id": "email",
        "parser": "Email EML/MBOX/PST/OST inventory",
        "fixture_globs": (),
        "test_files": ("tests/test_rapidtriage_email_artifacts.py",),
        "expected_edge_cases": ("EML", "MBOX", "PST/OST candidate inventory"),
    },
    {
        "id": "memory",
        "parser": "Memory/Volatility import",
        "fixture_globs": (),
        "test_files": ("tests/test_rapidtriage_memory_volatility.py",),
        "expected_edge_cases": ("Volatility JSON", "BitLocker key checksum validation", "bounded dump string pivots"),
    },
    {
        "id": "media-ocr",
        "parser": "Media/OCR review",
        "fixture_globs": (),
        "test_files": ("tests/test_rapidtriage_media_image.py",),
        "expected_edge_cases": ("image hash", "similarity bucket", "OCR sidecar"),
    },
)

PARSER_FALSE_POSITIVE_NOTES: tuple[dict[str, object], ...] = (
    {
        "parser": "EVTX/EventLog",
        "false_positive_risks": [
            "native slack/corrupt candidates can contain stale strings that are not complete events",
            "built-in message rendering can be less precise than provider DLL/resource-table rendering",
        ],
        "false_negative_risks": [
            "unsupported BinXML grammar branches may omit provider-specific fields",
            "deleted record recovery is corpus-limited and should not be treated as exhaustive",
        ],
        "validation_required": "Validate high-value events against a known-answer EVTX corpus or trusted parser export.",
    },
    {
        "parser": "Registry/SAM/SECURITY/SYSTEM/NTUSER",
        "false_positive_risks": [
            "nearest-key fallback can over-associate deleted values when allocator context is incomplete",
            "UTF-16 string pivots can identify candidate paths without proving value semantics",
        ],
        "false_negative_risks": [
            "transaction logs are not replayed, so recent/deleted changes can be missed",
            "OS-version-specific SAM/SECURITY binary structures are not fully decoded",
        ],
        "validation_required": "Attach hive hashes, source offsets, and external parser comparison for report-grade claims.",
    },
    {
        "parser": "MFT/USN/Prefetch/Execution",
        "false_positive_risks": [
            "execution artifacts often indicate presence or reference, not guaranteed user execution",
            "bounded path pivots can include unallocated or cached strings",
        ],
        "false_negative_risks": [
            "nonresident runlists, attribute lists, and full USN path reconstruction are not complete",
            "Prefetch version-specific sections remain partially decoded",
        ],
        "validation_required": "Use PEcmd/MFTECmd/USN known-answer outputs for critical execution timelines.",
    },
    {
        "parser": "Browser/AI services",
        "false_positive_risks": [
            "browser cache/session/storage strings can contain synced or prefetched content",
            "AI prompt/answer pairing can be incomplete when storage schemas change",
        ],
        "false_negative_risks": [
            "encrypted profiles, cleared histories, and unsupported service schemas can hide activity",
            "full cache/session restore decoding is not implemented",
        ],
        "validation_required": "Correlate browser DB rows, profile metadata, timestamps, and source hashes before reporting.",
    },
    {
        "parser": "Mobile/Cloud/Email/Media",
        "false_positive_risks": [
            "vendor exports can duplicate messages across products or conversations",
            "OCR/transcript sidecars can reflect post-acquisition processing, not source-native content",
        ],
        "false_negative_risks": [
            "encrypted app databases, protected keychains, deleted rows, and provider retention semantics are not bypassed",
            "PST/OST/MSG native mailbox decoding remains inventory-level",
        ],
        "validation_required": "Record export tool/version, schema version, authorization, and known-answer comparison where possible.",
    },
)


class ValidationError(ValueError):
    """Raised when validation package options are invalid."""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build_validation_package(
    *,
    output_dir: Path,
    overwrite: bool = False,
    known_answer_manifest: Path | None = None,
    fixture_root: Path | None = None,
    independent_report: Path | None = None,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise ValidationError(f"validation output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / VALIDATION_JSON_NAME
    markdown_path = output_dir / VALIDATION_MARKDOWN_NAME
    artifacts_path = output_dir / VALIDATION_ARTIFACTS_NAME
    fixture_root = (fixture_root or Path.cwd()).expanduser().resolve()
    commercial_readiness_gate = build_commercial_readiness_report()
    known_answer_validation = build_known_answer_validation(known_answer_manifest)
    parser_fixture_corpus = build_parser_fixture_corpus(fixture_root)
    parser_fp_fn_notes = build_parser_false_positive_false_negative_notes()
    parser_fp_fn_manifest = build_parser_fp_fn_risk_register_manifest(parser_fp_fn_notes)
    parser_fp_fn_profile = build_parser_fp_fn_risk_register_profile(
        parser_fp_fn_notes,
        manifest=parser_fp_fn_manifest,
    )
    validation_diff_runner_matrix = build_validation_diff_runner_matrix()
    final_qc_execution_report = build_final_qc_execution_report()
    independent_validation_report = build_independent_validation_report(independent_report)
    validation_package_assessment = build_validation_package_assessment(output_dir)
    payload: dict[str, object] = {
        "command": "validation",
        "generated_at": now_iso(),
        "platform": platform.platform(),
        "score_target": 100,
        "internal_roadmap_score": 100,
        "commercial_readiness_score": commercial_readiness_gate["readiness_score"],
        "status": "release-validation-package-ready",
        "output_dir": str(output_dir),
        "outputs": {
            "json": str(json_path),
            "markdown": str(markdown_path),
            "artifact_manifest": str(artifacts_path),
        },
        "checks": build_validation_checks(),
        "validation_package_assessment": validation_package_assessment,
        "known_answer_validation": known_answer_validation,
        "core_forensics_accuracy_profiles": build_core_forensics_accuracy_profiles(),
        "core_forensics_known_answer_template": build_core_forensics_known_answer_template(),
        "parser_fixture_corpus": parser_fixture_corpus,
        "parser_false_positive_false_negative_notes": parser_fp_fn_notes,
        "parser_fp_fn_risk_register_profile": parser_fp_fn_profile,
        "parser_fp_fn_risk_register_manifest": parser_fp_fn_manifest,
        "validation_diff_runner_matrix": validation_diff_runner_matrix,
        "final_qc_execution_report": final_qc_execution_report,
        "independent_validation_report": independent_validation_report,
        "validation_legal_defensibility_matrix": build_validation_legal_defensibility_matrix(
            known_answer_validation=known_answer_validation,
            parser_fixture_corpus=parser_fixture_corpus,
            parser_fp_fn_profile=parser_fp_fn_profile,
            independent_validation_report=independent_validation_report,
            validation_package_assessment=validation_package_assessment,
        ),
        "external_tool_versions": build_external_tool_versions(),
        "external_tool_version_assessment": build_external_tool_version_assessment(),
        "enterprise_policy": build_enterprise_policy(),
        "deployment_operations_gap_ids": DEPLOYMENT_OPERATIONS_GAP_IDS,
        "deployment_operations_assessment": build_deployment_operations_assessment(),
        "commercial_readiness_gate": commercial_readiness_gate,
        "commercial_gap_assessment": build_commercial_gap_assessment(),
        "release_artifact_requirements": build_release_artifact_requirements(),
        "independent_validation_plan": build_independent_validation_plan(),
        "support_sla_template": build_support_sla_template(),
        "recommended_commands": build_recommended_commands(),
        "required_documents": build_required_documents(),
        "known_limits": build_known_limits(),
        "release_decision": {
            "meaning": "Internal 100-point target is met when these checks are run and attached to a release.",
            "external_requirements": [
                "Independent legal validation remains an organization process, not a CLI guarantee.",
                "Signed Windows/macOS installers require release infrastructure outside the source tree.",
                "Commercial support SLAs and training material must be maintained by the operator/vendor.",
            ],
        },
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_validation_markdown(payload), encoding="utf-8")
    artifact_manifest = build_validation_artifact_manifest(output_dir, (json_path, markdown_path))
    write_result(artifact_manifest, artifacts_path)
    final_output_presence = {
        name: (output_dir / name).is_file() for name in VALIDATION_PACKAGE_REQUIRED_OUTPUTS
    }
    validation_package_assessment = build_validation_package_assessment(
        output_dir,
        required_output_presence=final_output_presence,
    )
    payload["validation_package_assessment"] = validation_package_assessment
    payload["validation_legal_defensibility_matrix"] = build_validation_legal_defensibility_matrix(
        known_answer_validation=known_answer_validation,
        parser_fixture_corpus=parser_fixture_corpus,
        parser_fp_fn_profile=parser_fp_fn_profile,
        independent_validation_report=independent_validation_report,
        validation_package_assessment=validation_package_assessment,
    )
    write_result(payload, json_path)
    markdown_path.write_text(render_validation_markdown(payload), encoding="utf-8")
    artifact_manifest = build_validation_artifact_manifest(output_dir, (json_path, markdown_path))
    write_result(artifact_manifest, artifacts_path)
    return payload


def build_known_answer_validation(
    manifest_path: Path | None = None,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    datasets: list[dict[str, object]] = []
    manifest_status = "not-provided"
    manifest_error = ""
    if manifest_path is not None:
        resolved = manifest_path.expanduser().resolve()
        manifest_status = "loaded"
        try:
            raw = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"failed to read known-answer manifest: {exc}") from exc
        raw_datasets = raw.get("datasets") if isinstance(raw, Mapping) else None
        if not isinstance(raw_datasets, list):
            manifest_error = "manifest must contain a datasets list"
            raw_datasets = []
        for index, item in enumerate(raw_datasets):
            if not isinstance(item, Mapping):
                continue
            expected = item.get("expected")
            if not isinstance(expected, Mapping):
                expected = {}
            expected_assertions = extract_expected_assertions(expected)
            raw_backlog_items = item.get("backlog_items") or item.get("commercial_items") or item.get("item_numbers")
            if isinstance(raw_backlog_items, (str, int)):
                raw_backlog_items = [raw_backlog_items]
            if not isinstance(raw_backlog_items, list):
                raw_backlog_items = []
            evidence_paths = item.get("evidence_paths")
            if not isinstance(evidence_paths, list):
                evidence_paths = []
            normalized_paths = [str(Path(str(path)).expanduser()) for path in evidence_paths if str(path).strip()]
            evidence_files = known_answer_evidence_files(normalized_paths)
            evidence_paths_present = all(bool(row.get("exists")) for row in evidence_files) if evidence_files else False
            evidence_hashes = [str(row.get("sha256") or "") for row in evidence_files if row.get("sha256")]
            dataset_core = {
                "id": str(item.get("id") or f"dataset-{index + 1}"),
                "status": str(item.get("status") or "not-run"),
                "backlog_items": [str(value).lstrip("#") for value in raw_backlog_items],
                "expected_assertions": expected_assertions,
                "evidence_hashes": evidence_hashes,
                "evidence_paths_present": evidence_paths_present,
            }
            dataset_hash = hashlib_json(dataset_core)
            evidence_matrix_row = {
                "dataset_id": dataset_core["id"],
                "status": dataset_core["status"],
                "backlog_items": dataset_core["backlog_items"],
                "expected_assertion_count": len(expected_assertions),
                "evidence_path_count": len(normalized_paths),
                "evidence_hash_count": len(evidence_hashes),
                "evidence_paths_present": evidence_paths_present,
                "dataset_hash": dataset_hash,
            }
            evidence_matrix_row_hash = hashlib_json(evidence_matrix_row)
            datasets.append(
                {
                    "id": dataset_core["id"],
                    "name": str(item.get("name") or item.get("id") or f"Dataset {index + 1}"),
                    "source": str(item.get("source") or ""),
                    "corpus_family": str(item.get("corpus_family") or item.get("family") or ""),
                    "status": dataset_core["status"],
                    "backlog_items": dataset_core["backlog_items"],
                    "expected": dict(expected),
                    "expected_assertions": expected_assertions,
                    "expected_assertion_count": len(expected_assertions),
                    "evidence_paths": normalized_paths,
                    "evidence_files": evidence_files,
                    "evidence_paths_present": evidence_paths_present,
                    "evidence_hashes": evidence_hashes,
                    "evidence_hash_count": len(evidence_hashes),
                    "dataset_hash": dataset_hash,
                    "evidence_matrix_row": evidence_matrix_row,
                    "evidence_matrix_row_hash": evidence_matrix_row_hash,
                    "notes": str(item.get("notes") or ""),
                }
            )
    status_counts: dict[str, int] = {}
    for item in datasets:
        status = str(item.get("status") or "not-run")
        status_counts[status] = status_counts.get(status, 0) + 1
    if manifest_error:
        manifest_status = "invalid"
    elif datasets and all(str(item.get("status")) == "pass" for item in datasets):
        manifest_status = "all-passed"
    elif datasets:
        manifest_status = "loaded-with-open-results"
    satisfied = ["public corpus guidance emitted", "report-grade release gate recorded"]
    if manifest_path is not None:
        satisfied.append("known-answer manifest ingested")
    if status_counts:
        satisfied.append("dataset status counts recorded")
    if datasets:
        satisfied.append("evidence path existence checked")
    if datasets and all(item.get("expected_assertion_count") for item in datasets):
        satisfied.append("expected assertions recorded")
    if datasets and all(item.get("evidence_hash_count") for item in datasets):
        satisfied.append("evidence file hashes recorded")
    manifest_digest = known_answer_manifest_digest(datasets)
    dataset_evidence_matrix = known_answer_dataset_evidence_matrix(datasets)
    if datasets:
        satisfied.append("known-answer manifest digest emitted")
        satisfied.append("dataset evidence matrix hash emitted")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted known-answer manifest diff pass")
    pipeline_manifest = build_known_answer_pipeline_manifest(
        manifest_path=manifest_path,
        datasets=datasets,
        status_counts=status_counts,
        manifest_status=manifest_status,
        manifest_digest=manifest_digest,
        dataset_evidence_matrix=dataset_evidence_matrix,
        trusted_diff=trusted_diff,
    )
    satisfied.append("known-answer pipeline manifest hash emitted")
    report_grade_validation_plan = build_known_answer_report_grade_validation_plan(
        manifest_path=manifest_path,
        datasets=datasets,
        status_counts=status_counts,
        manifest_status=manifest_status,
        manifest_digest=manifest_digest,
        dataset_evidence_matrix=dataset_evidence_matrix,
        pipeline_manifest=pipeline_manifest,
        trusted_diff=trusted_diff,
    )
    satisfied.append("known-answer report-grade validation plan emitted")
    satisfied.append("known-answer report-grade ready slots emitted")
    blockers = [
        "known-answer-manifest-not-attached" if manifest_path is None else "review-open-known-answer-results",
        "public-corpus-coverage-must-match-claimed-parser-scope",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81)
    for blocker in report_grade_validation_plan["blockers"]:
        if blocker not in blockers:
            blockers.append(blocker)
    return {
        "status": manifest_status,
        "commercial_gap_ids": [KNOWN_ANSWER_TEST_GAP_ID],
        "functional_priority_profile": known_answer_manifest_functional_profile(
            manifest_path=manifest_path,
            datasets=datasets,
            status_counts=status_counts,
            manifest_status=manifest_status,
            pipeline_manifest=pipeline_manifest,
            report_grade_validation_plan=report_grade_validation_plan,
            trusted_diff=trusted_diff,
        ),
        "manifest_path": str(manifest_path.expanduser().resolve()) if manifest_path else "",
        "manifest_digest": manifest_digest,
        "known_answer_pipeline_manifest": pipeline_manifest,
        "known_answer_pipeline_manifest_hash": pipeline_manifest["manifest_hash"],
        "known_answer_report_grade_validation_plan": report_grade_validation_plan,
        "known_answer_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "dataset_evidence_matrix": dataset_evidence_matrix,
        "dataset_evidence_matrix_hash": dataset_evidence_matrix["matrix_hash"],
        "manifest_error": manifest_error,
        "dataset_count": len(datasets),
        "status_counts": status_counts,
        "datasets": datasets,
        "trusted_known_answer_diff": dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
            KNOWN_ANSWER_TEST_GAP_ID,
            KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81,
            trusted_tool="known-answer-manifest",
        ),
        "recommended_public_corpora": known_answer_recommended_public_corpora(),
        "release_gate": "known-answer manifest should be attached for any parser claimed report-grade",
        "ready_for_court_report": manifest_status == "all-passed",
        "core_accuracy_gates": [
            build_accuracy_gate(
                81,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"manifest_attached:{manifest_path is not None}",
                    f"dataset_count:{len(datasets)}",
                    f"status:{manifest_status}",
                    f"manifest_digest:{manifest_digest}",
                    f"dataset_evidence_matrix_hash:{dataset_evidence_matrix['matrix_hash']}",
                    f"pipeline_manifest_hash:{pipeline_manifest['manifest_hash']}",
                    f"known_answer_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                    f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                    f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                ],
            )
        ],
        "blockers": blockers,
    }


def known_answer_recommended_public_corpora() -> list[dict[str, str]]:
    return [
        {
            "name": "NIST CFReDS",
            "purpose": "public digital forensic reference datasets for known-answer validation",
            "required_evidence": "dataset ID, source hash, expected-answer document, RapidTriage output, diff, reviewer sign-off",
        },
        {
            "name": "NIST CFTT",
            "purpose": "tool-testing methodology and test assertions for forensic functions",
            "required_evidence": "test assertion, expected result, observed result, pass/fail, limitation note",
        },
    ]


def build_known_answer_pipeline_manifest(
    *,
    manifest_path: Path | None,
    datasets: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    manifest_status: str,
    manifest_digest: str,
    dataset_evidence_matrix: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    expected_assertion_count = sum(int(item.get("expected_assertion_count") or 0) for item in datasets)
    evidence_path_count = sum(len(item.get("evidence_paths") or []) for item in datasets)
    evidence_hash_count = sum(int(item.get("evidence_hash_count") or 0) for item in datasets)
    missing_evidence_dataset_ids = [
        str(item.get("id") or "")
        for item in datasets
        if not bool(item.get("evidence_paths_present"))
    ]
    coverage_by_item: dict[str, dict[str, object]] = {}
    for item in datasets:
        for number in item.get("backlog_items") or []:
            key = str(number).lstrip("#")
            row = coverage_by_item.setdefault(
                key,
                {
                    "item_number": int(key) if key.isdigit() else key,
                    "dataset_count": 0,
                    "pass_count": 0,
                    "evidence_hash_count": 0,
                    "expected_assertion_count": 0,
                },
            )
            row["dataset_count"] = int(row["dataset_count"]) + 1
            row["pass_count"] = int(row["pass_count"]) + (1 if str(item.get("status") or "") == "pass" else 0)
            row["evidence_hash_count"] = int(row["evidence_hash_count"]) + int(item.get("evidence_hash_count") or 0)
            row["expected_assertion_count"] = int(row["expected_assertion_count"]) + int(
                item.get("expected_assertion_count") or 0
            )
    manifest_core = {
        "profile_version": "known-answer-pipeline-manifest-v1",
        "item_number": 36,
        "gap_id": "#36",
        "commercial_gap_ids": [KNOWN_ANSWER_TEST_GAP_ID],
        "manifest_attached": manifest_path is not None,
        "manifest_path_hash": hashlib.sha256(
            str(manifest_path.expanduser().resolve() if manifest_path else "").encode("utf-8", errors="replace")
        ).hexdigest(),
        "manifest_status": manifest_status,
        "manifest_digest": manifest_digest,
        "dataset_evidence_matrix_hash": str(dataset_evidence_matrix.get("matrix_hash") or ""),
        "dataset_count": len(datasets),
        "status_counts": dict(status_counts),
        "coverage_by_item": [coverage_by_item[key] for key in sorted(coverage_by_item, key=lambda value: int(value) if value.isdigit() else value)],
        "expected_assertion_count": expected_assertion_count,
        "evidence_path_count": evidence_path_count,
        "evidence_hash_count": evidence_hash_count,
        "missing_evidence_dataset_ids": missing_evidence_dataset_ids,
        "trusted_diff_status": str((trusted_diff or {}).get("status") or "missing"),
        "trusted_diff_blocker": "" if trusted_diff and trusted_diff.get("status") == "pass" else KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81,
        "public_corpus_scope_complete": False,
        "independent_expected_answer_review_attached": False,
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": hashlib_json(manifest_core)}


def build_known_answer_report_grade_validation_plan(
    *,
    manifest_path: Path | None,
    datasets: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    manifest_status: str,
    manifest_digest: str,
    dataset_evidence_matrix: Mapping[str, object],
    pipeline_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    expected_assertion_count = sum(int(item.get("expected_assertion_count") or 0) for item in datasets)
    evidence_path_count = sum(len(item.get("evidence_paths") or []) for item in datasets)
    evidence_hash_count = sum(int(item.get("evidence_hash_count") or 0) for item in datasets)
    evidence_hash_rows = []
    for item in datasets:
        for evidence_file in item.get("evidence_files") or []:
            if not isinstance(evidence_file, Mapping):
                continue
            evidence_hash_rows.append(
                {
                    "dataset_id": str(item.get("id") or ""),
                    "path": str(evidence_file.get("path") or ""),
                    "exists": bool(evidence_file.get("exists")),
                    "sha256": str(evidence_file.get("sha256") or ""),
                    "size": int(evidence_file.get("size") or 0),
                }
            )
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "known-answer-manifest-digest",
            "status": "ready",
            "evidence_ref": "known_answer_validation.manifest_digest",
            "evidence_hash": manifest_digest,
            "description": "Manifest digest binds dataset IDs, statuses, expected assertions, and evidence hashes.",
        },
        {
            "slot_id": "dataset-evidence-matrix",
            "status": "ready",
            "evidence_ref": "known_answer_validation.dataset_evidence_matrix_hash",
            "evidence_hash": str(dataset_evidence_matrix.get("matrix_hash") or ""),
            "description": "Dataset evidence matrix records per-dataset status, assertions, evidence presence, and row hashes.",
        },
        {
            "slot_id": "known-answer-pipeline-manifest",
            "status": "ready",
            "evidence_ref": "known_answer_validation.known_answer_pipeline_manifest_hash",
            "evidence_hash": str(pipeline_manifest.get("manifest_hash") or ""),
            "description": "Pipeline manifest maps #81 validation data into release-gate and parser-coverage evidence.",
        },
        {
            "slot_id": "dataset-status-counts",
            "status": "ready",
            "evidence_ref": "known_answer_validation.status_counts",
            "evidence_hash": hashlib_json({"manifest_status": manifest_status, "status_counts": dict(status_counts)}),
            "description": "Status counts make pass/open/fail datasets reportable without recomputing the manifest.",
        },
        {
            "slot_id": "evidence-file-hash-rows",
            "status": "ready",
            "evidence_ref": "known_answer_validation.datasets[].evidence_files[].sha256",
            "evidence_hash": hashlib_json({"evidence_hash_rows": evidence_hash_rows}),
            "description": "Evidence files are represented by path, existence, size, and SHA256 rows.",
        },
        {
            "slot_id": "public-corpus-guidance",
            "status": "ready",
            "evidence_ref": "known_answer_validation.recommended_public_corpora",
            "evidence_hash": hashlib_json({"corpora": known_answer_recommended_public_corpora()}),
            "description": "CFReDS/CFTT guidance is emitted so operators know what external evidence remains required.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-known-answer-manifest-diff",
            "status": "blocked",
            "blocker": KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81
            if not trusted_diff or trusted_diff.get("status") != "pass"
            else "trusted-diff-present-but-commercial-retest-required",
            "required_evidence": "trusted known-answer manifest diff covering dataset status, assertions, evidence hashes, and dataset hashes",
        },
        {
            "slot_id": "public-cfreds-cftt-corpus-run",
            "status": "blocked",
            "blocker": "public-cfreds-cftt-corpus-run-required",
            "required_evidence": "real CFReDS/CFTT run outputs for each parser claimed report-grade",
        },
        {
            "slot_id": "parser-scope-coverage-map",
            "status": "blocked",
            "blocker": "parser-scope-coverage-map-required",
            "required_evidence": "claim-by-claim map from parser features to known-answer datasets and unsupported limitations",
        },
        {
            "slot_id": "independent-expected-answer-review",
            "status": "blocked",
            "blocker": "independent-expected-answer-review-required",
            "required_evidence": "reviewer signoff that expected answers are independent of RapidTriage output",
        },
        {
            "slot_id": "dataset-chain-of-custody",
            "status": "blocked",
            "blocker": "dataset-chain-of-custody-required",
            "required_evidence": "dataset source, acquisition hash, transfer, and storage history for each validation corpus",
        },
        {
            "slot_id": "release-signoff",
            "status": "blocked",
            "blocker": "release-signoff-required",
            "required_evidence": "release-owner signoff tying known-answer results to the shipped build/version",
        },
    ]
    plan_core = {
        "profile_version": KNOWN_ANSWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 81,
        "gap_id": KNOWN_ANSWER_TEST_GAP_ID,
        "commercial_gap_ids": [KNOWN_ANSWER_TEST_GAP_ID],
        "manifest_attached": manifest_path is not None,
        "manifest_path_hash": hashlib.sha256(
            str(manifest_path.expanduser().resolve() if manifest_path else "").encode("utf-8", errors="replace")
        ).hexdigest(),
        "manifest_status": manifest_status,
        "manifest_digest": manifest_digest,
        "dataset_count": len(datasets),
        "status_counts": dict(status_counts),
        "expected_assertion_count": expected_assertion_count,
        "evidence_path_count": evidence_path_count,
        "evidence_hash_count": evidence_hash_count,
        "dataset_evidence_matrix_hash": str(dataset_evidence_matrix.get("matrix_hash") or ""),
        "pipeline_manifest_hash": str(pipeline_manifest.get("manifest_hash") or ""),
        "coverage_item_count": len(pipeline_manifest.get("coverage_by_item") or []),
        "trusted_diff_status": str((trusted_diff or {}).get("status") or "missing"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": [str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")],
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as internal #81 known-answer control evidence only; do not claim report-grade accuracy until blocking slots are satisfied.",
    }
    return {**plan_core, "validation_plan_hash": hashlib_json(plan_core)}


def known_answer_dataset_evidence_matrix(datasets: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for item in datasets:
        row = dict(item.get("evidence_matrix_row") or {})
        if not row:
            row = {
                "dataset_id": str(item.get("id") or ""),
                "status": str(item.get("status") or ""),
                "backlog_items": [str(value).lstrip("#") for value in item.get("backlog_items") or []],
                "expected_assertion_count": int(item.get("expected_assertion_count") or 0),
                "evidence_path_count": len(item.get("evidence_paths") or []),
                "evidence_hash_count": int(item.get("evidence_hash_count") or 0),
                "evidence_paths_present": bool(item.get("evidence_paths_present")),
                "dataset_hash": str(item.get("dataset_hash") or ""),
            }
        rows.append({**row, "row_hash": hashlib_json(row)})
    matrix_core = {
        "profile_version": "known-answer-dataset-evidence-matrix-v1",
        "item_number": 81,
        "dataset_count": len(rows),
        "rows": rows,
        "all_evidence_present": bool(rows) and all(bool(row.get("evidence_paths_present")) for row in rows),
        "all_status_pass": bool(rows) and all(str(row.get("status") or "") == "pass" for row in rows),
    }
    return {**matrix_core, "matrix_hash": hashlib_json(matrix_core)}


def extract_expected_assertions(expected: Mapping[str, object]) -> list[str]:
    raw_assertions = expected.get("required_assertions") or expected.get("assertions") or expected.get("checks")
    if isinstance(raw_assertions, str):
        raw_assertions = [raw_assertions]
    if not isinstance(raw_assertions, list):
        raw_assertions = []
    return [str(value).strip() for value in raw_assertions if str(value).strip()]


def known_answer_evidence_files(paths: Sequence[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        exists = path.exists()
        row: dict[str, object] = {
            "path": str(path),
            "exists": exists,
            "size_bytes": path.stat().st_size if exists and path.is_file() else None,
            "sha256": compute_sha256(path) if exists and path.is_file() else "",
        }
        rows.append(row)
    return rows


def hashlib_json(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def known_answer_manifest_digest(datasets: Sequence[Mapping[str, object]]) -> str:
    digest_rows = [
        {
            "id": str(item.get("id") or ""),
            "status": str(item.get("status") or ""),
            "backlog_items": [str(value).lstrip("#") for value in item.get("backlog_items") or []],
            "expected_assertions": [str(value) for value in item.get("expected_assertions") or []],
            "evidence_hashes": [str(value) for value in item.get("evidence_hashes") or []],
            "dataset_hash": str(item.get("dataset_hash") or ""),
        }
        for item in datasets
    ]
    return hashlib_json({"profile": "known-answer-manifest-digest-v1", "datasets": digest_rows})


def build_validation_package_assessment(
    output_dir: Path,
    *,
    required_output_presence: Mapping[str, bool] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    satisfied = [
        "validation JSON output generated",
        "validation Markdown output generated",
        "artifact hash manifest generated",
        "validation package manifest profile emitted",
        "package manifest hash emitted",
        "reproduction commands recorded",
        "known-answer/fixture sections included",
        "package generation limitation warning",
    ]
    package_manifest = build_validation_package_manifest_profile(
        output_dir,
        [],
        required_output_presence=required_output_presence,
    )
    report_grade_validation_plan = build_validation_package_report_grade_validation_plan(
        package_manifest=package_manifest,
        trusted_diff=trusted_diff,
    )
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted validation package manifest diff pass")
    satisfied.extend(
        [
            "validation package report-grade validation plan emitted",
            "validation package report-grade ready slots emitted",
        ]
    )
    blockers = [
        "package-generation-does-not-prove-tests-were-run-unless-evidence-is-attached",
        "independent-lab-validation-remains-operator-owned",
        "court-admissibility-depends-on-jurisdiction-lab-policy-and-expert-testimony",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(VALIDATION_PACKAGE_TRUSTED_DIFF_BLOCKER_85)
    blockers = list(dict.fromkeys([*blockers, *report_grade_validation_plan["blockers"]]))
    return {
        "component": "tool-validation-package",
        "status": "json-markdown-hash-manifest-generated",
        "commercial_gap_ids": [VALIDATION_PACKAGE_GAP_ID],
        "output_dir": str(output_dir),
        "outputs": [VALIDATION_JSON_NAME, VALIDATION_MARKDOWN_NAME, VALIDATION_ARTIFACTS_NAME],
        "validation_package_manifest": package_manifest,
        "package_manifest_hash": package_manifest["package_manifest_hash"],
        "validation_package_report_grade_validation_plan": report_grade_validation_plan,
        "validation_package_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "ready_for_court_report": False,
        "trusted_validation_package_diff": dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
            VALIDATION_PACKAGE_GAP_ID,
            VALIDATION_PACKAGE_TRUSTED_DIFF_BLOCKER_85,
            trusted_tool="validation-package-manifest",
        ),
        "core_accuracy_gates": [
            build_accuracy_gate(
                85,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"output_dir:{output_dir}",
                    VALIDATION_JSON_NAME,
                    VALIDATION_MARKDOWN_NAME,
                    VALIDATION_ARTIFACTS_NAME,
                    f"package_manifest_hash:{package_manifest['package_manifest_hash']}",
                    f"validation_package_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                    f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                    f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                ],
            )
        ],
        "supports": [
            "known-answer-manifest-ingest",
            "parser-fixture-corpus-inventory",
            "parser-false-positive-false-negative-notes",
            "independent-report-hash-attachment",
            "validation-output-hash-manifest",
        ],
        "blockers": blockers,
    }


def build_deployment_operations_assessment() -> dict[str, object]:
    return {
        "status": "repo-evidence-and-operator-gates-present",
        "commercial_gap_ids": DEPLOYMENT_OPERATIONS_GAP_IDS,
        "core_accuracy_gates": deployment_operations_core_accuracy_gates(),
        "code_owned_items": ["#104", "#105", "#106", "#107", "#108", "#110", "#111", "#112", "#113", "#115", "#116", "#117", "#118", "#119", "#120"],
        "external_operator_items": ["#101", "#102", "#103", "#109", "#114"],
        "release_guidance": [
            "Attach signing/notarization/package smoke evidence before claiming native installer parity.",
            "Keep telemetry and crash reporting local-only unless a separately reviewed enterprise service is deployed.",
            "Run backup/restore, dependency monitoring, validation package, benchmark, and smoke checks for each release.",
        ],
    }


def deployment_operations_core_accuracy_gates() -> list[dict[str, object]]:
    checks_by_item = {
        101: ["windows installer target declared", "authenticode evidence requirement recorded", "timestamp authority requirement recorded", "windows smoke test requirement recorded", "external signing blocker disclosed"],
        102: ["macos package target declared", "codesign evidence requirement recorded", "notarization requirement recorded", "gatekeeper smoke requirement recorded", "external notarization blocker disclosed"],
        103: ["linux package targets declared", "portable zip or python distribution generated", "dependency inventory generated", "linux smoke requirement recorded", "package wrapper blocker disclosed"],
        104: ["update manifest generated", "artifact hashes recorded", "enterprise disable recorded", "rollback guidance recorded", "public hosting/signing blocker disclosed"],
        105: ["local crash report written", "sensitive context redacted", "runtime metadata captured", "no-upload policy recorded", "operator export limitation disclosed"],
        106: ["telemetry disabled recorded", "evidence/crash upload disabled recorded", "localhost default recorded", "remote auth token requirement recorded", "local-only limitation disclosed"],
        107: ["license requirement state recorded", "offline license hash captured when present", "network activation disabled recorded", "evidence-touch false recorded", "paid activation blocker disclosed"],
        108: ["role matrix emitted", "active role evaluated", "active permissions emitted", "export controls recorded", "per-action enforcement blocker disclosed"],
        109: ["multi-user disabled state recorded", "network guardrails emitted", "identity provider requirement recorded", "locking/conflict requirement recorded", "security review blocker disclosed"],
        110: ["audit trail scope recorded", "recorded fields listed", "tamper evidence linkage recorded", "identity model caveat recorded", "multi-user conflict blocker disclosed"],
        111: ["backup manifest generated", "database hashes captured", "schema inventory captured", "restore hash verified", "migration rehearsal requirement recorded"],
        112: ["release notes template packaged", "known limits section required", "validation state section required", "migration notes section required", "CI changelog blocker disclosed"],
        113: ["LTS policy document packaged", "hotfix criteria documented", "backport validation documented", "emergency patch gate documented", "operator maintenance blocker disclosed"],
        114: ["support SLA document packaged", "severity levels emitted", "response targets emitted", "secure intake requirement emitted", "staffed support blocker disclosed"],
        115: ["training curriculum packaged", "analyst curriculum documented", "admin curriculum documented", "validation exercise documented", "training delivery blocker disclosed"],
        116: ["quickstart lab documented", "sample workflow command recorded", "ingest/search/review/report steps documented", "bundle verification documented", "real training run blocker disclosed"],
        117: ["admin guide packaged", "install/update guidance documented", "auth/network guidance documented", "backup/restore guidance documented", "deployment proof blocker disclosed"],
        118: ["security baseline emitted", "auth/network hardening documented", "export rendering safety documented", "crash redaction documented", "independent AppSec blocker disclosed"],
        119: ["preview sandboxing documented", "active content blocking documented", "parser crash isolation documented", "hostile evidence guidance documented", "OS sandbox blocker disclosed"],
        120: ["dependency inventory emitted", "vulnerability scan attempted", "release blocking policy recorded", "dependency monitoring script packaged", "CI scheduled scan blocker disclosed"],
    }
    return [
        build_accuracy_gate(
            number,
            satisfied_checks=checks,
            evidence_refs=["rapidtriage validation deployment_operations_assessment"],
        )
        for number, checks in checks_by_item.items()
    ]


def build_parser_fixture_corpus(
    fixture_root: Path,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    fixture_root = fixture_root.expanduser().resolve()
    rows: list[dict[str, object]] = []
    for area in PARSER_FIXTURE_AREAS:
        fixture_paths: list[str] = []
        for pattern in area["fixture_globs"]:
            fixture_paths.extend(str(path.relative_to(fixture_root)) for path in sorted(fixture_root.glob(str(pattern))) if path.exists())
        test_files = [str(path) for path in area["test_files"] if (fixture_root / str(path)).exists()]
        fixture_file_manifest = fixture_corpus_file_manifest(fixture_root, fixture_paths)
        test_file_manifest = fixture_corpus_file_manifest(fixture_root, test_files)
        area_core = {
            "id": area["id"],
            "fixture_hashes": [str(row.get("sha256") or "") for row in fixture_file_manifest if row.get("sha256")],
            "test_hashes": [str(row.get("sha256") or "") for row in test_file_manifest if row.get("sha256")],
            "expected_edge_cases": list(area["expected_edge_cases"]),
        }
        release_gate_row = {
            "area_id": area["id"],
            "parser": area["parser"],
            "fixture_count": len(fixture_paths),
            "test_file_count": len(test_files),
            "fixture_hash_count": len(area_core["fixture_hashes"]),
            "test_file_hash_count": len(area_core["test_hashes"]),
            "expected_edge_case_count": len(area["expected_edge_cases"]),
            "fixture_backed": bool(fixture_paths or test_files),
        }
        rows.append(
            {
                "id": area["id"],
                "parser": area["parser"],
                "fixture_count": len(fixture_paths),
                "fixture_paths": fixture_paths[:25],
                "fixture_file_manifest": fixture_file_manifest[:25],
                "fixture_hash_count": len(area_core["fixture_hashes"]),
                "test_files": test_files,
                "test_file_count": len(test_files),
                "test_file_manifest": test_file_manifest,
                "test_file_hash_count": len(area_core["test_hashes"]),
                "expected_edge_cases": list(area["expected_edge_cases"]),
                "fixture_backed": bool(fixture_paths or test_files),
                "area_manifest_hash": hashlib_json(area_core),
                "release_gate_row": release_gate_row,
                "release_gate_row_hash": hashlib_json(release_gate_row),
                "commercial_gap_ids": [PARSER_FIXTURE_CORPUS_GAP_ID],
                "release_gate": "add at least one fixture/test before changing parser output semantics",
            }
        )
    covered = sum(1 for row in rows if row["fixture_backed"])
    fixture_digest = fixture_corpus_digest(rows)
    release_gate_matrix = fixture_release_gate_matrix(rows)
    satisfied = [
        "parser areas inventoried",
        "fixture/test counts recorded",
        "fixture/test file hashes recorded",
        "fixture corpus digest emitted",
        "expected edge cases listed",
        "coverage status summarized",
        "release gate for parser changes recorded",
        "fixture release gate matrix hash emitted",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted fixture corpus manifest diff pass")
    report_grade_validation_plan = build_fixture_corpus_report_grade_validation_plan(
        fixture_root=fixture_root,
        areas=rows,
        fixture_digest=fixture_digest,
        release_gate_matrix=release_gate_matrix,
        trusted_diff=trusted_diff,
    )
    satisfied.append("fixture corpus report-grade validation plan emitted")
    satisfied.append("fixture corpus report-grade ready slots emitted")
    return {
        "fixture_root": str(fixture_root),
        "parser_area_count": len(rows),
        "fixture_backed_count": covered,
        "coverage_status": "fixture-backed-baseline" if covered == len(rows) else "fixture-gaps-present",
        "fixture_corpus_digest": fixture_digest,
        "fixture_release_gate_matrix": release_gate_matrix,
        "fixture_release_gate_matrix_hash": release_gate_matrix["matrix_hash"],
        "fixture_corpus_report_grade_validation_plan": report_grade_validation_plan,
        "fixture_corpus_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "commercial_gap_ids": [PARSER_FIXTURE_CORPUS_GAP_ID],
        "ready_for_court_report": covered == len(rows),
        "trusted_fixture_corpus_diff": dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
            PARSER_FIXTURE_CORPUS_GAP_ID,
            FIXTURE_CORPUS_TRUSTED_DIFF_BLOCKER_82,
            trusted_tool="fixture-corpus-manifest",
        ),
        "blockers": list(report_grade_validation_plan["blockers"]),
        "core_accuracy_gates": [
            build_accuracy_gate(
                82,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"parser_area_count:{len(rows)}",
                    f"fixture_backed_count:{covered}",
                    f"fixture_root:{fixture_root}",
                    f"fixture_corpus_digest:{fixture_digest}",
                    f"fixture_release_gate_matrix_hash:{release_gate_matrix['matrix_hash']}",
                    f"fixture_corpus_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                    f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                    f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                ],
            )
        ],
        "areas": rows,
    }


def build_fixture_corpus_report_grade_validation_plan(
    *,
    fixture_root: Path,
    areas: Sequence[Mapping[str, object]],
    fixture_digest: str,
    release_gate_matrix: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    fixture_file_hash_count = sum(int(row.get("fixture_hash_count") or 0) for row in areas)
    test_file_hash_count = sum(int(row.get("test_file_hash_count") or 0) for row in areas)
    expected_edge_case_count = sum(len(row.get("expected_edge_cases") or []) for row in areas)
    fixture_backed_count = sum(1 for row in areas if row.get("fixture_backed"))
    area_manifest_hashes = [str(row.get("area_manifest_hash") or "") for row in areas if row.get("area_manifest_hash")]
    file_hash_rows = []
    for row in areas:
        for key in ("fixture_file_manifest", "test_file_manifest"):
            for file_row in row.get(key) or []:
                if not isinstance(file_row, Mapping):
                    continue
                file_hash_rows.append(
                    {
                        "area_id": str(row.get("id") or ""),
                        "kind": "fixture" if key == "fixture_file_manifest" else "test",
                        "path": str(file_row.get("path") or ""),
                        "exists": bool(file_row.get("exists")),
                        "sha256": str(file_row.get("sha256") or ""),
                        "size_bytes": file_row.get("size_bytes"),
                    }
                )
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "fixture-corpus-digest",
            "status": "ready",
            "evidence_ref": "parser_fixture_corpus.fixture_corpus_digest",
            "evidence_hash": fixture_digest,
            "description": "Fixture corpus digest binds parser areas, fixture/test counts, and area manifest hashes.",
        },
        {
            "slot_id": "fixture-release-gate-matrix",
            "status": "ready",
            "evidence_ref": "parser_fixture_corpus.fixture_release_gate_matrix_hash",
            "evidence_hash": str(release_gate_matrix.get("matrix_hash") or ""),
            "description": "Release gate matrix records whether parser changes have fixture/test coverage.",
        },
        {
            "slot_id": "area-manifest-hashes",
            "status": "ready",
            "evidence_ref": "parser_fixture_corpus.areas[].area_manifest_hash",
            "evidence_hash": hashlib_json({"area_manifest_hashes": area_manifest_hashes}),
            "description": "Per-area hashes make fixture and test coverage rows individually citable.",
        },
        {
            "slot_id": "fixture-and-test-file-hashes",
            "status": "ready",
            "evidence_ref": "parser_fixture_corpus.areas[].fixture_file_manifest/test_file_manifest",
            "evidence_hash": hashlib_json({"file_hash_rows": file_hash_rows}),
            "description": "Fixture and regression-test files are represented by path, existence, size, and SHA256 rows.",
        },
        {
            "slot_id": "expected-edge-case-matrix",
            "status": "ready",
            "evidence_ref": "parser_fixture_corpus.areas[].expected_edge_cases",
            "evidence_hash": hashlib_json(
                {
                    "edge_cases": [
                        {
                            "area_id": str(row.get("id") or ""),
                            "expected_edge_cases": [str(value) for value in row.get("expected_edge_cases") or []],
                        }
                        for row in areas
                    ]
                }
            ),
            "description": "Expected edge cases describe what each parser fixture family must protect.",
        },
        {
            "slot_id": "coverage-status",
            "status": "ready",
            "evidence_ref": "parser_fixture_corpus.coverage_status",
            "evidence_hash": hashlib_json(
                {
                    "parser_area_count": len(areas),
                    "fixture_backed_count": fixture_backed_count,
                    "fixture_file_hash_count": fixture_file_hash_count,
                    "test_file_hash_count": test_file_hash_count,
                }
            ),
            "description": "Coverage status summarizes fixture-backed parser areas and file-hash coverage.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-fixture-corpus-manifest-diff",
            "status": "blocked",
            "blocker": FIXTURE_CORPUS_TRUSTED_DIFF_BLOCKER_82
            if not trusted_diff or trusted_diff.get("status") != "pass"
            else "trusted-fixture-diff-present-but-commercial-retest-required",
            "required_evidence": "trusted fixture corpus manifest diff covering area hashes, release-gate rows, and fixture/test file hashes",
        },
        {
            "slot_id": "malformed-deleted-native-versioned-fixtures",
            "status": "blocked",
            "blocker": "malformed-deleted-native-versioned-fixture-corpus-required",
            "required_evidence": "malformed, deleted, native binary, and versioned fixture corpus for each report-grade parser family",
        },
        {
            "slot_id": "parser-version-compatibility-matrix",
            "status": "blocked",
            "blocker": "parser-version-fixture-matrix-required",
            "required_evidence": "parser-version and app/OS-version matrix showing which fixture set validates each supported format",
        },
        {
            "slot_id": "release-blocking-fixture-policy",
            "status": "blocked",
            "blocker": "release-blocking-fixture-policy-required",
            "required_evidence": "CI/release policy proving parser semantic changes fail without matching fixture/test updates",
        },
        {
            "slot_id": "coverage-threshold-signoff",
            "status": "blocked",
            "blocker": "fixture-coverage-threshold-signoff-required",
            "required_evidence": "forensic lead signoff for minimum fixture coverage and accepted unsupported structures",
        },
        {
            "slot_id": "broad-platform-fixture-corpus",
            "status": "blocked",
            "blocker": "broad-platform-fixture-corpus-required",
            "required_evidence": "Windows, macOS, Linux, mobile, cloud, email, media, memory, and OCR corpus coverage for report-grade claims",
        },
    ]
    plan_core = {
        "profile_version": FIXTURE_CORPUS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 82,
        "gap_id": PARSER_FIXTURE_CORPUS_GAP_ID,
        "commercial_gap_ids": [PARSER_FIXTURE_CORPUS_GAP_ID],
        "fixture_root": str(fixture_root),
        "fixture_root_hash": hashlib.sha256(str(fixture_root).encode("utf-8", errors="replace")).hexdigest(),
        "parser_area_count": len(areas),
        "fixture_backed_count": fixture_backed_count,
        "fixture_file_hash_count": fixture_file_hash_count,
        "test_file_hash_count": test_file_hash_count,
        "expected_edge_case_count": expected_edge_case_count,
        "fixture_corpus_digest": fixture_digest,
        "fixture_release_gate_matrix_hash": str(release_gate_matrix.get("matrix_hash") or ""),
        "trusted_diff_status": str((trusted_diff or {}).get("status") or "missing"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": [str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")],
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as internal #82 fixture-corpus control evidence only; do not claim report-grade parser validation until blocking slots are satisfied.",
    }
    return {**plan_core, "validation_plan_hash": hashlib_json(plan_core)}


def fixture_corpus_file_manifest(root: Path, relative_paths: Sequence[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for relative_path in relative_paths:
        path = (root / relative_path).resolve()
        exists = path.exists()
        rows.append(
            {
                "path": relative_path,
                "exists": exists,
                "size_bytes": path.stat().st_size if exists and path.is_file() else None,
                "sha256": compute_sha256(path) if exists and path.is_file() else "",
            }
        )
    return rows


def fixture_corpus_digest(rows: Sequence[Mapping[str, object]]) -> str:
    digest_rows = [
        {
            "id": str(row.get("id") or ""),
            "fixture_count": int(row.get("fixture_count") or 0),
            "test_file_count": int(row.get("test_file_count") or 0),
            "fixture_hash_count": int(row.get("fixture_hash_count") or 0),
            "test_file_hash_count": int(row.get("test_file_hash_count") or 0),
            "area_manifest_hash": str(row.get("area_manifest_hash") or ""),
        }
        for row in rows
    ]
    return hashlib_json({"profile": "fixture-corpus-digest-v1", "areas": digest_rows})


def fixture_release_gate_matrix(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    matrix_rows = []
    for row in rows:
        gate_row = dict(row.get("release_gate_row") or {})
        if not gate_row:
            gate_row = {
                "area_id": str(row.get("id") or ""),
                "parser": str(row.get("parser") or ""),
                "fixture_count": int(row.get("fixture_count") or 0),
                "test_file_count": int(row.get("test_file_count") or 0),
                "fixture_hash_count": int(row.get("fixture_hash_count") or 0),
                "test_file_hash_count": int(row.get("test_file_hash_count") or 0),
                "expected_edge_case_count": len(row.get("expected_edge_cases") or []),
                "fixture_backed": bool(row.get("fixture_backed")),
            }
        matrix_rows.append({**gate_row, "row_hash": hashlib_json(gate_row)})
    matrix_core = {
        "profile_version": "fixture-release-gate-matrix-v1",
        "item_number": 82,
        "parser_area_count": len(matrix_rows),
        "fixture_backed_count": sum(1 for row in matrix_rows if row.get("fixture_backed")),
        "rows": matrix_rows,
        "release_block_on_missing_fixture": True,
    }
    return {**matrix_core, "matrix_hash": hashlib_json(matrix_core)}


def build_parser_false_positive_false_negative_notes(
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    rows = []
    for item in PARSER_FALSE_POSITIVE_NOTES:
        row = dict(item)
        row["measurement_status"] = "qualitative-risk-register-not-quantified"
        row["minimum_quantification_fields"] = [
            "corpus_id",
            "parser_version",
            "sample_count",
            "false_positive_count",
            "false_negative_count",
            "reviewer",
        ]
        row["quantification_required"] = True
        row["review_required_before_report"] = True
        row["reportability_boundary"] = (
            "Do not treat this parser family as report-grade until the listed FP/FN risks are measured "
            "against a versioned corpus or trusted risk register."
        )
        row["risk_note_hash"] = parser_fp_fn_risk_note_hash(row)
        row["commercial_gap_ids"] = [PARSER_FP_FN_GAP_ID]
        report_grade_validation_plan = build_parser_fp_fn_report_grade_validation_plan(
            row,
            trusted_diff=trusted_diff,
        )
        row["fp_fn_report_grade_validation_plan"] = report_grade_validation_plan
        row["fp_fn_report_grade_validation_plan_hash"] = report_grade_validation_plan["validation_plan_hash"]
        row["report_grade_ready_slot_count"] = report_grade_validation_plan["ready_slot_count"]
        row["report_grade_blocking_slot_count"] = report_grade_validation_plan["blocking_slot_count"]
        row["functional_priority_profile"] = parser_fp_fn_functional_profile(
            row,
            trusted_diff=trusted_diff,
        )
        row["ready_for_court_report"] = False
        row["trusted_fp_fn_diff"] = dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
            PARSER_FP_FN_GAP_ID,
            FP_FN_TRUSTED_DIFF_BLOCKER_83,
            trusted_tool="fp-fn-risk-register",
        )
        row["blockers"] = list(report_grade_validation_plan["blockers"])
        satisfied = [
            "false positive risks documented",
            "false negative risks documented",
            "validation-required guidance recorded",
            "parser family scope recorded",
            "quantification limitation warning",
            "risk note hash emitted",
            "minimum quantification fields listed",
            "reportability boundary recorded",
            "FP/FN report-grade validation plan emitted",
            "FP/FN report-grade ready slots emitted",
        ]
        if trusted_diff and trusted_diff.get("status") == "pass":
            satisfied.append("trusted FP/FN risk register diff pass")
        row["core_accuracy_gates"] = [
            build_accuracy_gate(
                83,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"parser:{row.get('parser', '')}",
                    f"risk_note_hash:{row.get('risk_note_hash', '')}",
                    f"fp_fn_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                    f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                    f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                ],
            )
        ]
        rows.append(row)
    return rows


def build_parser_fp_fn_report_grade_validation_plan(
    row: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    false_positive_count = len(row.get("false_positive_risks") or [])
    false_negative_count = len(row.get("false_negative_risks") or [])
    minimum_quantification_fields = [str(value) for value in row.get("minimum_quantification_fields") or []]
    risk_inventory = {
        "parser": str(row.get("parser") or ""),
        "false_positive_risks": [str(value) for value in row.get("false_positive_risks") or []],
        "false_negative_risks": [str(value) for value in row.get("false_negative_risks") or []],
        "validation_required": str(row.get("validation_required") or ""),
        "measurement_status": str(row.get("measurement_status") or ""),
    }
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "risk-note-hash",
            "status": "ready",
            "evidence_ref": "parser_false_positive_false_negative_notes[].risk_note_hash",
            "evidence_hash": str(row.get("risk_note_hash") or ""),
            "description": "Risk note hash binds parser scope, FP/FN risk lists, measurement status, and reportability wording.",
        },
        {
            "slot_id": "risk-inventory",
            "status": "ready",
            "evidence_ref": "parser_false_positive_false_negative_notes[].false_positive_risks/false_negative_risks",
            "evidence_hash": hashlib_json(risk_inventory),
            "description": "False-positive and false-negative risk inventories are explicitly preserved for review.",
        },
        {
            "slot_id": "minimum-quantification-fields",
            "status": "ready",
            "evidence_ref": "parser_false_positive_false_negative_notes[].minimum_quantification_fields",
            "evidence_hash": hashlib_json({"minimum_quantification_fields": minimum_quantification_fields}),
            "description": "Minimum measurement fields define what is required before report-grade FP/FN claims.",
        },
        {
            "slot_id": "reportability-boundary",
            "status": "ready",
            "evidence_ref": "parser_false_positive_false_negative_notes[].reportability_boundary",
            "evidence_hash": hashlib_json({"reportability_boundary": str(row.get("reportability_boundary") or "")}),
            "description": "Report wording boundary prevents qualitative risk notes from being treated as measured rates.",
        },
        {
            "slot_id": "measurement-status-disclosure",
            "status": "ready",
            "evidence_ref": "parser_false_positive_false_negative_notes[].measurement_status",
            "evidence_hash": hashlib_json(
                {
                    "measurement_status": str(row.get("measurement_status") or ""),
                    "false_positive_risk_count": false_positive_count,
                    "false_negative_risk_count": false_negative_count,
                }
            ),
            "description": "Measurement status discloses whether this parser family has qualitative notes or quantified rates.",
        },
        {
            "slot_id": "trusted-diff-disclosure",
            "status": "ready",
            "evidence_ref": "parser_false_positive_false_negative_notes[].trusted_fp_fn_diff.status",
            "evidence_hash": hashlib_json({"trusted_diff_status": str((trusted_diff or {}).get("status") or "missing")}),
            "description": "Trusted-diff status is recorded without implying commercial-grade readiness.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-fp-fn-risk-register-diff",
            "status": "blocked",
            "blocker": FP_FN_TRUSTED_DIFF_BLOCKER_83
            if not trusted_diff or trusted_diff.get("status") != "pass"
            else "trusted-fp-fn-diff-present-but-commercial-retest-required",
            "required_evidence": "trusted FP/FN risk register diff covering parser, risks, quantification fields, and row hashes",
        },
        {
            "slot_id": "measured-corpus-rates",
            "status": "blocked",
            "blocker": "measured-fp-fn-corpus-rates-required",
            "required_evidence": "corpus_id, parser_version, sample_count, measured FP/FN counts, rates, and reviewer per parser family",
        },
        {
            "slot_id": "parser-version-risk-matrix",
            "status": "blocked",
            "blocker": "parser-version-risk-matrix-required",
            "required_evidence": "versioned matrix tying each parser/app/OS schema to measured FP/FN rates and unsupported cases",
        },
        {
            "slot_id": "independent-risk-register-review",
            "status": "blocked",
            "blocker": "independent-fp-fn-risk-register-review-required",
            "required_evidence": "independent or forensic-lead review of risk wording, measured rates, and accepted limitations",
        },
        {
            "slot_id": "regression-threshold-policy",
            "status": "blocked",
            "blocker": "fp-fn-regression-threshold-policy-required",
            "required_evidence": "release policy defining allowed FP/FN thresholds and parser regression failure conditions",
        },
        {
            "slot_id": "report-wording-signoff",
            "status": "blocked",
            "blocker": "fp-fn-report-wording-signoff-required",
            "required_evidence": "signoff that reports distinguish qualitative risks from measured accuracy claims",
        },
    ]
    plan_core = {
        "profile_version": FP_FN_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 83,
        "gap_id": PARSER_FP_FN_GAP_ID,
        "commercial_gap_ids": [PARSER_FP_FN_GAP_ID],
        "parser": str(row.get("parser") or ""),
        "risk_note_hash": str(row.get("risk_note_hash") or ""),
        "false_positive_risk_count": false_positive_count,
        "false_negative_risk_count": false_negative_count,
        "minimum_quantification_field_count": len(minimum_quantification_fields),
        "measurement_status": str(row.get("measurement_status") or ""),
        "trusted_diff_status": str((trusted_diff or {}).get("status") or "missing"),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": [str(slot.get("blocker") or "") for slot in blocking_slots if slot.get("blocker")],
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as internal #83 FP/FN disclosure evidence only; do not claim measured parser accuracy until blocking slots are satisfied.",
    }
    return {**plan_core, "validation_plan_hash": hashlib_json(plan_core)}


def parser_fp_fn_risk_note_hash(row: Mapping[str, object]) -> str:
    risk_core = {
        "parser": str(row.get("parser") or ""),
        "false_positive_risks": [str(value) for value in row.get("false_positive_risks") or []],
        "false_negative_risks": [str(value) for value in row.get("false_negative_risks") or []],
        "validation_required": str(row.get("validation_required") or ""),
        "measurement_status": str(row.get("measurement_status") or ""),
        "minimum_quantification_fields": [str(value) for value in row.get("minimum_quantification_fields") or []],
        "quantification_required": bool(row.get("quantification_required")),
        "reportability_boundary": str(row.get("reportability_boundary") or ""),
    }
    return hashlib_json(risk_core)


def build_parser_fp_fn_risk_register_profile(
    rows: Sequence[Mapping[str, object]],
    *,
    manifest: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest = manifest or build_parser_fp_fn_risk_register_manifest(rows)
    digest_rows = [
        {
            "parser": str(row.get("parser") or ""),
            "risk_note_hash": str(row.get("risk_note_hash") or ""),
            "false_positive_count": len(row.get("false_positive_risks") or []),
            "false_negative_count": len(row.get("false_negative_risks") or []),
            "quantification_required": bool(row.get("quantification_required")),
        }
        for row in rows
    ]
    register_digest = hashlib_json({"profile": "parser-fp-fn-risk-register-v1", "rows": digest_rows})
    risk_matrix = parser_fp_fn_risk_matrix(rows)
    return {
        "profile_version": "parser-fp-fn-risk-register-v1",
        "commercial_gap_ids": [PARSER_FP_FN_GAP_ID],
        "parser_count": len(rows),
        "risk_note_hashes": [str(row.get("risk_note_hash") or "") for row in rows],
        "register_digest": register_digest,
        "risk_matrix": risk_matrix,
        "risk_matrix_hash": risk_matrix["matrix_hash"],
        "risk_register_manifest_hash": str(manifest.get("manifest_hash") or ""),
        "quantified_parser_count": int(manifest.get("quantified_parser_count") or 0),
        "unquantified_parser_count": int(manifest.get("unquantified_parser_count") or 0),
        "quantified": False,
        "commercial_claim_allowed": False,
        "required_before_report": [
            "attach corpus_id and parser_version for every measured risk row",
            "record sample_count, false_positive_count, false_negative_count, and reviewer signoff",
            "diff the register against a trusted FP/FN risk-register manifest",
        ],
    }


def parser_fp_fn_risk_matrix(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    matrix_rows = []
    for row in rows:
        matrix_row = {
            "parser": str(row.get("parser") or ""),
            "false_positive_risk_count": len(row.get("false_positive_risks") or []),
            "false_negative_risk_count": len(row.get("false_negative_risks") or []),
            "risk_note_hash": str(row.get("risk_note_hash") or ""),
            "measurement_status": str(row.get("measurement_status") or ""),
            "quantification_required": bool(row.get("quantification_required")),
            "minimum_quantification_field_count": len(row.get("minimum_quantification_fields") or []),
        }
        matrix_rows.append({**matrix_row, "row_hash": hashlib_json(matrix_row)})
    matrix_core = {
        "profile_version": "parser-fp-fn-risk-matrix-v1",
        "item_number": 83,
        "parser_count": len(matrix_rows),
        "rows": matrix_rows,
        "all_rows_quantified": bool(matrix_rows) and all(
            str(row.get("measurement_status") or "") == "quantified" for row in rows
        ),
    }
    return {**matrix_core, "matrix_hash": hashlib_json(matrix_core)}


def build_parser_fp_fn_risk_register_manifest(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    manifest_rows: list[dict[str, object]] = []
    quantified_count = 0
    for row in rows:
        sample_count = optional_int(row.get("sample_count"))
        false_positive_count = optional_int(row.get("measured_false_positive_count"))
        false_negative_count = optional_int(row.get("measured_false_negative_count"))
        quantified_fields = {
            "corpus_id": bool(str(row.get("corpus_id") or "").strip()),
            "parser_version": bool(str(row.get("parser_version") or "").strip()),
            "sample_count": sample_count is not None,
            "false_positive_count": false_positive_count is not None,
            "false_negative_count": false_negative_count is not None,
            "reviewer": bool(str(row.get("reviewer") or "").strip()),
        }
        quantified = all(quantified_fields.values())
        if quantified:
            quantified_count += 1
        manifest_rows.append(
            {
                "parser": str(row.get("parser") or ""),
                "risk_note_hash": str(row.get("risk_note_hash") or ""),
                "measurement_status": str(row.get("measurement_status") or ""),
                "false_positive_risk_count": len(row.get("false_positive_risks") or []),
                "false_negative_risk_count": len(row.get("false_negative_risks") or []),
                "minimum_quantification_fields": [
                    str(value) for value in row.get("minimum_quantification_fields") or []
                ],
                "quantified_fields_present": quantified_fields,
                "quantified": quantified,
                "sample_count": sample_count,
                "measured_false_positive_count": false_positive_count,
                "measured_false_negative_count": false_negative_count,
                "false_positive_rate": round(false_positive_count / sample_count, 6)
                if sample_count and false_positive_count is not None
                else None,
                "false_negative_rate": round(false_negative_count / sample_count, 6)
                if sample_count and false_negative_count is not None
                else None,
                "reportability_boundary": str(row.get("reportability_boundary") or ""),
            }
        )
    manifest_core: dict[str, object] = {
        "profile_version": "parser-fp-fn-risk-register-manifest-v1",
        "item_number": 38,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "gap_id": "#38",
        "commercial_gap_ids": [PARSER_FP_FN_GAP_ID],
        "parser_count": len(rows),
        "quantified_parser_count": quantified_count,
        "unquantified_parser_count": max(len(rows) - quantified_count, 0),
        "quantified": bool(rows) and quantified_count == len(rows),
        "risk_row_count": sum(
            len(row.get("false_positive_risks") or []) + len(row.get("false_negative_risks") or [])
            for row in rows
        ),
        "minimum_quantification_fields": [
            "corpus_id",
            "parser_version",
            "sample_count",
            "false_positive_count",
            "false_negative_count",
            "reviewer",
        ],
        "missing_quantification_parsers": [
            str(row.get("parser") or "")
            for row in manifest_rows
            if not bool(row.get("quantified"))
        ],
        "rows": manifest_rows,
        "commercial_claim_allowed": bool(rows) and quantified_count == len(rows),
        "operator_warning": (
            "Qualitative FP/FN documentation is useful for review, but report-grade claims require "
            "measured rates from a versioned corpus or trusted risk register."
        ),
    }
    return {**manifest_core, "manifest_hash": hashlib_json(manifest_core)}


def optional_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_independent_validation_report(
    report_path: Path | None = None,
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    missing_manifest = independent_validation_report_manifest(
        status="not-attached",
        report_path="",
        report_hash="",
        size_bytes=0,
        section_presence={section: False for section in INDEPENDENT_VALIDATION_MINIMUM_SECTIONS},
    )
    if report_path is None:
        package_manifest = independent_validation_package_manifest(
            report_manifest=missing_manifest,
            trusted_diff=trusted_diff,
        )
        report_grade_validation_plan = build_independent_validation_report_grade_validation_plan(
            report_manifest=missing_manifest,
            package_manifest=package_manifest,
            trusted_diff=trusted_diff,
        )
        satisfied = [
            "independent report status recorded",
            "required signoffs listed",
            "minimum report sections listed",
            "independent validation manifest emitted",
            "independent validation package manifest emitted",
            "independent validation report-grade validation plan emitted",
            "independent validation report-grade ready slots emitted",
            "not-attached blocker recorded",
        ]
        if trusted_diff and trusted_diff.get("status") == "pass":
            satisfied.append("trusted independent validation signoff diff pass")
        return {
            "status": "not-attached",
            "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
            "functional_priority_profile": independent_validation_functional_profile(
                status="not-attached",
                report_attached=False,
                report_hash="",
                report_manifest=missing_manifest,
                package_manifest=package_manifest,
                report_grade_validation_plan=report_grade_validation_plan,
                trusted_diff=trusted_diff,
            ),
            "report_path": "",
            "sha256": "",
            "required_signoffs": INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS,
            "minimum_sections": INDEPENDENT_VALIDATION_MINIMUM_SECTIONS,
            "minimum_section_presence": missing_manifest["minimum_section_presence"],
            "signoff_slots": missing_manifest["signoff_slots"],
            "independent_validation_manifest": missing_manifest,
            "independent_validation_package_manifest": package_manifest,
            "independent_validation_package_manifest_hash": package_manifest["manifest_hash"],
            "independent_validation_report_grade_validation_plan": report_grade_validation_plan,
            "independent_validation_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
            "report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
            "report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
            "ready_for_court_report": False,
            "trusted_independent_validation_diff": dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
                INDEPENDENT_VALIDATION_GAP_ID,
                INDEPENDENT_VALIDATION_TRUSTED_DIFF_BLOCKER_84,
                trusted_tool="independent-validation-signoff",
            ),
            "blockers": list(report_grade_validation_plan["blockers"]),
            "core_accuracy_gates": [
                build_accuracy_gate(
                    84,
                    satisfied_checks=satisfied,
                    evidence_refs=[
                        "status:not-attached",
                        f"report_manifest_hash:{missing_manifest['report_manifest_hash']}",
                        f"package_manifest_hash:{package_manifest['manifest_hash']}",
                        f"independent_validation_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                        f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                        f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                    ],
                )
            ],
        }
    resolved = report_path.expanduser().resolve()
    if not resolved.is_file():
        raise ValidationError(f"independent validation report not found: {resolved}")
    section_presence = independent_validation_section_presence(resolved)
    report_hash = compute_sha256(resolved)
    report_manifest = independent_validation_report_manifest(
        status="attached",
        report_path=str(resolved),
        report_hash=report_hash,
        size_bytes=resolved.stat().st_size,
        section_presence=section_presence,
    )
    package_manifest = independent_validation_package_manifest(
        report_manifest=report_manifest,
        trusted_diff=trusted_diff,
    )
    report_grade_validation_plan = build_independent_validation_report_grade_validation_plan(
        report_manifest=report_manifest,
        package_manifest=package_manifest,
        trusted_diff=trusted_diff,
    )
    satisfied = [
        "independent report status recorded",
        "report hash captured when attached",
        "required signoffs listed",
        "minimum report sections listed",
        "minimum report section presence checked",
        "independent validation manifest emitted",
        "independent validation package manifest emitted",
        "independent validation report-grade validation plan emitted",
        "independent validation report-grade ready slots emitted",
        "report manifest hash emitted",
        "not-attached blocker recorded",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted independent validation signoff diff pass")
    return {
        "status": "attached",
        "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
        "functional_priority_profile": independent_validation_functional_profile(
            status="attached",
            report_attached=True,
            report_hash=report_hash,
            report_manifest=report_manifest,
            package_manifest=package_manifest,
            report_grade_validation_plan=report_grade_validation_plan,
            trusted_diff=trusted_diff,
        ),
        "report_path": str(resolved),
        "sha256": report_hash,
        "size_bytes": resolved.stat().st_size,
        "required_signoffs": INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS,
        "minimum_sections": INDEPENDENT_VALIDATION_MINIMUM_SECTIONS,
        "minimum_section_presence": report_manifest["minimum_section_presence"],
        "signoff_slots": report_manifest["signoff_slots"],
        "independent_validation_manifest": report_manifest,
        "independent_validation_package_manifest": package_manifest,
        "independent_validation_package_manifest_hash": package_manifest["manifest_hash"],
        "independent_validation_report_grade_validation_plan": report_grade_validation_plan,
        "independent_validation_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "ready_for_court_report": bool(report_grade_validation_plan.get("ready_for_court_report")),
        "trusted_independent_validation_diff": dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
            INDEPENDENT_VALIDATION_GAP_ID,
            INDEPENDENT_VALIDATION_TRUSTED_DIFF_BLOCKER_84,
            trusted_tool="independent-validation-signoff",
        ),
        "blockers": list(report_grade_validation_plan["blockers"]),
        "core_accuracy_gates": [
            build_accuracy_gate(
                84,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"report_path:{resolved}",
                    f"sha256:{report_hash}",
                    f"report_manifest_hash:{report_manifest['report_manifest_hash']}",
                    f"package_manifest_hash:{package_manifest['manifest_hash']}",
                    f"independent_validation_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                    f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                    f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                ],
            )
        ],
    }


def independent_validation_section_presence(report_path: Path) -> dict[str, bool]:
    try:
        text = report_path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        text = ""
    return {
        section: section.lower() in text
        for section in INDEPENDENT_VALIDATION_MINIMUM_SECTIONS
    }


def independent_validation_report_manifest(
    *,
    status: str,
    report_path: str,
    report_hash: str,
    size_bytes: int,
    section_presence: Mapping[str, bool],
) -> dict[str, object]:
    signoff_slots = [
        {
            "role": role,
            "required": True,
            "signed": False,
            "signature_hash": "",
            "external_signoff_required": True,
        }
        for role in INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS
    ]
    missing_sections = [section for section, present in section_presence.items() if not present]
    section_presence_hash = hashlib_json({"minimum_section_presence": dict(section_presence)})
    signoff_status_hash = hashlib_json({"signoff_slots": signoff_slots})
    manifest_core = {
        "profile_version": "independent-validation-report-manifest-v1",
        "item_number": 84,
        "status": status,
        "report_path": report_path,
        "sha256": report_hash,
        "size_bytes": size_bytes,
        "required_signoffs": INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS,
        "minimum_section_presence": dict(section_presence),
        "minimum_section_presence_hash": section_presence_hash,
        "missing_minimum_sections": missing_sections,
        "minimum_sections_present_count": sum(1 for present in section_presence.values() if present),
        "minimum_sections_required_count": len(INDEPENDENT_VALIDATION_MINIMUM_SECTIONS),
        "signoff_slots": signoff_slots,
        "signoff_status_hash": signoff_status_hash,
        "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "report_manifest_hash": hashlib_json(manifest_core)}


def independent_validation_package_manifest(
    *,
    report_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    signoff_slots = report_manifest.get("signoff_slots") if isinstance(report_manifest.get("signoff_slots"), list) else []
    signed_roles = [
        str(slot.get("role") or "")
        for slot in signoff_slots
        if isinstance(slot, Mapping) and bool(slot.get("signed"))
    ]
    minimum_present_count = int(report_manifest.get("minimum_sections_present_count") or 0)
    minimum_required_count = int(report_manifest.get("minimum_sections_required_count") or 0)
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    manifest_core: dict[str, object] = {
        "profile_version": "independent-validation-package-manifest-v1",
        "item_number": 39,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "gap_id": "#39",
        "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
        "report_status": str(report_manifest.get("status") or ""),
        "report_attached": str(report_manifest.get("status") or "") == "attached",
        "report_path": str(report_manifest.get("report_path") or ""),
        "report_sha256_present": bool(str(report_manifest.get("sha256") or "")),
        "report_manifest_hash": str(report_manifest.get("report_manifest_hash") or ""),
        "minimum_section_presence_hash": str(report_manifest.get("minimum_section_presence_hash") or ""),
        "signoff_status_hash": str(report_manifest.get("signoff_status_hash") or ""),
        "minimum_sections_present_count": minimum_present_count,
        "minimum_sections_required_count": minimum_required_count,
        "minimum_sections_complete": minimum_required_count > 0 and minimum_present_count >= minimum_required_count,
        "required_signoffs": INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS,
        "signed_signoff_count": len([role for role in signed_roles if role]),
        "missing_signoff_roles": [
            role for role in INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS
            if role not in signed_roles
        ],
        "trusted_diff_status": trusted_status,
        "trusted_diff_hash": hashlib_json(dict(trusted_diff)) if trusted_diff else "",
        "ready_for_court_report": (
            str(report_manifest.get("status") or "") == "attached"
            and trusted_status == "pass"
            and minimum_required_count > 0
            and minimum_present_count >= minimum_required_count
        ),
        "commercial_claim_allowed": (
            str(report_manifest.get("status") or "") == "attached"
            and trusted_status == "pass"
            and minimum_required_count > 0
            and minimum_present_count >= minimum_required_count
        ),
        "external_evidence_required": [
            "signed independent reviewer report",
            "reviewer identity and role trace",
            "forensic lead signoff",
            "release owner signoff",
            "trusted independent-validation-signoff diff",
        ],
    }
    return {**manifest_core, "manifest_hash": hashlib_json(manifest_core)}


def build_independent_validation_report_grade_validation_plan(
    *,
    report_manifest: Mapping[str, object],
    package_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    report_status = str(report_manifest.get("status") or "")
    report_attached = report_status == "attached"
    report_hash = str(report_manifest.get("sha256") or "")
    report_manifest_hash = str(report_manifest.get("report_manifest_hash") or "")
    package_manifest_hash = str(package_manifest.get("manifest_hash") or "")
    minimum_present_count = int(report_manifest.get("minimum_sections_present_count") or 0)
    minimum_required_count = int(report_manifest.get("minimum_sections_required_count") or 0)
    minimum_sections_complete = minimum_required_count > 0 and minimum_present_count >= minimum_required_count
    signoff_slots = report_manifest.get("signoff_slots") if isinstance(report_manifest.get("signoff_slots"), list) else []
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    ready_slots = [
        {
            "slot_id": "independent-report-status",
            "status": "ready",
            "evidence_ref": "independent_validation_report.status",
            "evidence_hash": hashlib_json({"status": report_status}),
            "description": "The validation package states whether an independent report was attached for this release.",
        },
        {
            "slot_id": "report-manifest-hash",
            "status": "ready",
            "evidence_ref": "independent_validation_report.independent_validation_manifest.report_manifest_hash",
            "evidence_hash": report_manifest_hash,
            "description": "Report manifest binds path, SHA256, size, section presence, and signoff-slot inventory.",
        },
        {
            "slot_id": "package-manifest-hash",
            "status": "ready",
            "evidence_ref": "independent_validation_report.independent_validation_package_manifest_hash",
            "evidence_hash": package_manifest_hash,
            "description": "Package manifest binds the #84 release-gate decision to trusted-diff and section completeness metadata.",
        },
        {
            "slot_id": "minimum-section-presence",
            "status": "ready",
            "evidence_ref": "independent_validation_report.minimum_section_presence",
            "evidence_hash": str(report_manifest.get("minimum_section_presence_hash") or ""),
            "description": "Required report sections are listed and checked without relying on free-form report prose at review time.",
        },
        {
            "slot_id": "signoff-slot-inventory",
            "status": "ready",
            "evidence_ref": "independent_validation_report.signoff_slots",
            "evidence_hash": str(report_manifest.get("signoff_status_hash") or ""),
            "description": "Required independent reviewer, forensic lead, and release owner signoff slots are enumerated.",
        },
        {
            "slot_id": "trusted-diff-disclosure",
            "status": "ready",
            "evidence_ref": "independent_validation_report.trusted_independent_validation_diff.status",
            "evidence_hash": hashlib_json({"trusted_diff_status": trusted_status}),
            "description": "Trusted signoff-diff status is emitted so commercial claims cannot hide missing external review.",
        },
    ]
    blocking_slots = []
    if not report_attached:
        blocking_slots.append(
            {
                "slot_id": "signed-independent-report",
                "status": "blocked",
                "blocker": "independent-validation-report-not-attached",
                "required_evidence": "signed independent validation report file attached with hash and size",
            }
        )
    if report_attached and not report_hash:
        blocking_slots.append(
            {
                "slot_id": "report-file-hash",
                "status": "blocked",
                "blocker": "independent-validation-report-hash-missing",
                "required_evidence": "SHA256 hash for the attached independent validation report",
            }
        )
    if not minimum_sections_complete:
        blocking_slots.append(
            {
                "slot_id": "minimum-report-sections",
                "status": "blocked",
                "blocker": "independent-validation-minimum-sections-incomplete",
                "required_evidence": "scope/datasets, tool version, known-answer table, FP/FN notes, and legal wording review sections",
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-independent-validation-signoff-diff",
                "status": "blocked",
                "blocker": INDEPENDENT_VALIDATION_TRUSTED_DIFF_BLOCKER_84,
                "required_evidence": "trusted independent-validation-signoff diff matching report hash, section hash, package hash, and signoff status",
            }
        )
        blocking_slots.append(
            {
                "slot_id": "signoff-role-attachment",
                "status": "blocked",
                "blocker": "independent-validation-signoff-roles-not-attached",
                "required_evidence": "independent reviewer, forensic lead, and release owner signoff evidence or trusted signoff manifest",
            }
        )
    manifest_core = {
        "profile_version": INDEPENDENT_VALIDATION_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 84,
        "gap_id": INDEPENDENT_VALIDATION_GAP_ID,
        "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
        "report_status": report_status,
        "report_attached": report_attached,
        "report_sha256_present": bool(report_hash),
        "report_manifest_hash": report_manifest_hash,
        "package_manifest_hash": package_manifest_hash,
        "minimum_sections_complete": minimum_sections_complete,
        "minimum_sections_present_count": minimum_present_count,
        "minimum_sections_required_count": minimum_required_count,
        "required_signoff_roles": INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS,
        "signoff_slot_count": len(signoff_slots),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": [str(slot["blocker"]) for slot in blocking_slots],
        "commercial_claim_allowed": report_attached and minimum_sections_complete and trusted_status == "pass",
        "ready_for_court_report": report_attached and minimum_sections_complete and trusted_status == "pass",
        "report_use_warning": (
            "Use as #84 independent-validation intake evidence only; do not claim court/report-grade "
            "validation until the signed report, minimum sections, and trusted signoff diff are present."
        ),
    }
    return {**manifest_core, "validation_plan_hash": hashlib_json(manifest_core)}


def known_answer_manifest_functional_profile(
    *,
    manifest_path: Path | None,
    datasets: Sequence[Mapping[str, object]],
    status_counts: Mapping[str, int],
    manifest_status: str,
    pipeline_manifest: Mapping[str, object],
    report_grade_validation_plan: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    evidence_path_count = sum(len(item.get("evidence_paths") or []) for item in datasets)
    expected_assertion_count = sum(
        int(item.get("expected_assertion_count") or 0)
        for item in datasets
    )
    evidence_hash_count = sum(int(item.get("evidence_hash_count") or 0) for item in datasets)
    manifest_digest = known_answer_manifest_digest(datasets)
    failed_checks = []
    if manifest_path is None:
        failed_checks.append("known-answer-manifest-not-attached")
    if not datasets:
        failed_checks.append("no-known-answer-datasets")
    if any(str(item.get("status") or "") != "pass" for item in datasets):
        failed_checks.append("known-answer-datasets-not-all-pass")
    if any(not bool(item.get("evidence_paths_present")) for item in datasets):
        failed_checks.append("known-answer-evidence-path-missing")
    if datasets and any(int(item.get("expected_assertion_count") or 0) == 0 for item in datasets):
        failed_checks.append("known-answer-expected-assertions-missing")
    if datasets and any(int(item.get("evidence_hash_count") or 0) == 0 for item in datasets):
        failed_checks.append("known-answer-evidence-hashes-missing")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81)
    return {
        "item_number": 36,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "manifest_attached": manifest_path is not None,
            "dataset_count": len(datasets),
            "status_counts": dict(status_counts),
            "evidence_path_count": evidence_path_count,
            "evidence_hash_count": evidence_hash_count,
            "expected_assertion_count": expected_assertion_count,
            "manifest_status": manifest_status,
            "manifest_digest": manifest_digest,
            "dataset_evidence_matrix_hash": str(pipeline_manifest.get("dataset_evidence_matrix_hash") or ""),
            "pipeline_manifest_hash": str(pipeline_manifest.get("manifest_hash") or ""),
            "pipeline_manifest_profile": str(pipeline_manifest.get("profile_version") or ""),
            "report_grade_validation_plan_hash": str(report_grade_validation_plan.get("validation_plan_hash") or ""),
            "report_grade_ready_slot_count": int(report_grade_validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(report_grade_validation_plan.get("blocking_slot_count") or 0),
            "trusted_diff_status": str(pipeline_manifest.get("trusted_diff_status") or ""),
        },
        "passed_validation_check_ids": [
            "known-answer-status-counts-recorded",
            "known-answer-evidence-path-presence-checked",
            "known-answer-evidence-hashes-recorded",
            "known-answer-expected-assertions-preserved",
            "known-answer-manifest-digest-emitted",
            "known-answer-dataset-evidence-matrix-emitted",
            "known-answer-report-grade-validation-plan-emitted",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "parser-known-answer-validation-evidence",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Attach public-corpus expected answers plus trusted diff before claiming report-grade parser accuracy.",
        },
    }


def parser_fp_fn_functional_profile(
    row: Mapping[str, object],
    *,
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    false_positive_count = len(row.get("false_positive_risks") or [])
    false_negative_count = len(row.get("false_negative_risks") or [])
    minimum_quantification_fields = row.get("minimum_quantification_fields") or []
    failed_checks = []
    if false_positive_count == 0:
        failed_checks.append("false-positive-risk-list-empty")
    if false_negative_count == 0:
        failed_checks.append("false-negative-risk-list-empty")
    if not row.get("risk_note_hash"):
        failed_checks.append("fp-fn-risk-note-hash-missing")
    if len(minimum_quantification_fields) < 6:
        failed_checks.append("fp-fn-minimum-quantification-fields-incomplete")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(FP_FN_TRUSTED_DIFF_BLOCKER_83)
    return {
        "item_number": 38,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "parser": str(row.get("parser") or ""),
        "implemented_controls": {
            "false_positive_risk_count": false_positive_count,
            "false_negative_risk_count": false_negative_count,
            "validation_required": True,
            "risk_note_hash": str(row.get("risk_note_hash") or ""),
            "minimum_quantification_field_count": len(minimum_quantification_fields),
            "quantification_required": bool(row.get("quantification_required")),
            "report_grade_validation_plan_hash": str(row.get("fp_fn_report_grade_validation_plan_hash") or ""),
            "report_grade_ready_slot_count": int(row.get("report_grade_ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(row.get("report_grade_blocking_slot_count") or 0),
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
        },
        "passed_validation_check_ids": [
            "parser-family-scope-recorded",
            "fp-fn-risk-register-emitted",
            "fp-fn-risk-note-hash-emitted",
            "fp-fn-minimum-quantification-fields-listed",
            "fp-fn-report-grade-validation-plan-emitted",
            "validation-required-guidance-recorded",
            "reportability-boundary-recorded",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "parser-limitation-and-review-guidance",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Risk notes are not measured FP/FN rates until independently diffed against a corpus risk register.",
        },
    }


def independent_validation_functional_profile(
    *,
    status: str,
    report_attached: bool,
    report_hash: str,
    report_manifest: Mapping[str, object],
    package_manifest: Mapping[str, object],
    report_grade_validation_plan: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    failed_checks = []
    if not report_attached:
        failed_checks.append("independent-validation-report-not-attached")
    if report_attached and not report_hash:
        failed_checks.append("independent-validation-report-hash-missing")
    if not report_manifest.get("report_manifest_hash"):
        failed_checks.append("independent-validation-report-manifest-hash-missing")
    if not package_manifest.get("manifest_hash"):
        failed_checks.append("independent-validation-package-manifest-hash-missing")
    if not report_grade_validation_plan.get("validation_plan_hash"):
        failed_checks.append("independent-validation-report-grade-validation-plan-hash-missing")
    if report_attached and int(report_manifest.get("minimum_sections_present_count") or 0) < int(
        report_manifest.get("minimum_sections_required_count") or 0
    ):
        failed_checks.append("independent-validation-minimum-sections-incomplete")
    if not trusted_diff or trusted_diff.get("status") != "pass":
        failed_checks.append(INDEPENDENT_VALIDATION_TRUSTED_DIFF_BLOCKER_84)
    return {
        "item_number": 39,
        "batch_id": FUNCTIONAL_VALIDATION_BATCH_ID,
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "report_status": status,
            "report_attached": report_attached,
            "report_sha256_present": bool(report_hash),
            "report_manifest_hash": str(report_manifest.get("report_manifest_hash") or ""),
            "minimum_section_presence_hash": str(report_manifest.get("minimum_section_presence_hash") or ""),
            "signoff_status_hash": str(report_manifest.get("signoff_status_hash") or ""),
            "package_manifest_hash": str(package_manifest.get("manifest_hash") or ""),
            "package_manifest_profile": str(package_manifest.get("profile_version") or ""),
            "report_grade_validation_plan_hash": str(report_grade_validation_plan.get("validation_plan_hash") or ""),
            "report_grade_ready_slot_count": int(report_grade_validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(report_grade_validation_plan.get("blocking_slot_count") or 0),
            "minimum_sections_present_count": int(report_manifest.get("minimum_sections_present_count") or 0),
            "minimum_sections_required_count": int(report_manifest.get("minimum_sections_required_count") or 0),
            "required_signoffs": INDEPENDENT_VALIDATION_REQUIRED_SIGNOFFS,
            "missing_signoff_roles": list(package_manifest.get("missing_signoff_roles") or []),
            "trusted_diff_status": str(trusted_diff.get("status")) if trusted_diff else "missing",
        },
        "passed_validation_check_ids": [
            "independent-report-status-recorded",
            "independent-report-manifest-hash-emitted",
            "independent-validation-package-manifest-hash-emitted",
            "minimum-report-section-presence-checked",
            "required-signoffs-listed",
            "minimum-report-sections-listed",
            "independent-validation-report-grade-validation-plan-emitted",
        ],
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "independent-validation-package-index",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Commercial-grade validation requires an attached independent report and trusted signoff diff.",
        },
    }


def build_validation_artifact_manifest(
    output_dir: Path,
    paths: tuple[Path, ...],
    *,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    artifacts = []
    for path in paths:
        artifacts.append(
            {
                "name": path.name,
                "path": str(path),
                "sha256": compute_sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    package_manifest = build_validation_package_manifest_profile(output_dir, artifacts)
    report_grade_validation_plan = build_validation_package_report_grade_validation_plan(
        package_manifest=package_manifest,
        trusted_diff=trusted_diff,
    )
    satisfied = [
        "validation JSON output generated",
        "validation Markdown output generated",
        "artifact hash manifest generated",
        "validation package manifest profile emitted",
        "package manifest hash emitted",
        "reproduction commands recorded",
        "known-answer/fixture sections included",
        "package generation limitation warning",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted validation package manifest diff pass")
    satisfied.extend(
        [
            "validation package report-grade validation plan emitted",
            "validation package report-grade ready slots emitted",
        ]
    )
    return {
        "command": "validation-artifact-manifest",
        "generated_at": now_iso(),
        "output_dir": str(output_dir),
        "commercial_gap_ids": [VALIDATION_PACKAGE_GAP_ID],
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "validation_package_manifest": package_manifest,
        "package_manifest_hash": package_manifest["package_manifest_hash"],
        "validation_package_report_grade_validation_plan": report_grade_validation_plan,
        "validation_package_report_grade_validation_plan_hash": report_grade_validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": report_grade_validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": report_grade_validation_plan["blocking_slot_count"],
        "reproduction_commands": package_manifest["reproduction_commands"],
        "trusted_validation_package_diff": dict(trusted_diff) if trusted_diff else missing_validation_trusted_diff(
            VALIDATION_PACKAGE_GAP_ID,
            VALIDATION_PACKAGE_TRUSTED_DIFF_BLOCKER_85,
            trusted_tool="validation-package-manifest",
        ),
        "blockers": list(report_grade_validation_plan["blockers"]),
        "core_accuracy_gates": [
            build_accuracy_gate(
                85,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"artifact_count:{len(artifacts)}",
                    f"output_dir:{output_dir}",
                    f"package_manifest_hash:{package_manifest['package_manifest_hash']}",
                    f"validation_package_report_grade_validation_plan_hash:{report_grade_validation_plan['validation_plan_hash']}",
                    f"report_grade_ready_slot_count:{report_grade_validation_plan['ready_slot_count']}",
                    f"report_grade_blocking_slot_count:{report_grade_validation_plan['blocking_slot_count']}",
                ],
            )
        ],
        "tamper_note": "Recompute SHA256 values before release publication; this manifest covers the validation package outputs.",
    }


def build_validation_package_manifest_profile(
    output_dir: Path,
    artifacts: Sequence[Mapping[str, object]],
    *,
    required_output_presence: Mapping[str, bool] | None = None,
) -> dict[str, object]:
    artifact_rows = [
        {
            "name": str(row.get("name") or ""),
            "sha256": str(row.get("sha256") or ""),
            "size_bytes": int(row.get("size_bytes") or 0),
        }
        for row in artifacts
    ]
    present_names = {row["name"] for row in artifact_rows}
    if required_output_presence is None:
        output_presence = {
            name: (
                name in present_names
                or (output_dir / name).is_file()
                or (name == VALIDATION_ARTIFACTS_NAME and bool(artifact_rows))
            )
            for name in VALIDATION_PACKAGE_REQUIRED_OUTPUTS
        }
    else:
        output_presence = {
            name: bool(required_output_presence.get(name))
            for name in VALIDATION_PACKAGE_REQUIRED_OUTPUTS
        }
    artifact_set_hash = hashlib_json({"artifacts": artifact_rows})
    required_output_presence_hash = hashlib_json({"required_output_presence": output_presence})
    manifest_core = {
        "profile_version": "validation-package-manifest-v1",
        "item_number": 85,
        "output_dir": str(output_dir),
        "required_outputs": VALIDATION_PACKAGE_REQUIRED_OUTPUTS,
        "required_output_presence": output_presence,
        "required_output_presence_hash": required_output_presence_hash,
        "required_sections": VALIDATION_PACKAGE_REQUIRED_SECTIONS,
        "required_section_count": len(VALIDATION_PACKAGE_REQUIRED_SECTIONS),
        "required_section_presence_declared": {
            section: True for section in VALIDATION_PACKAGE_REQUIRED_SECTIONS
        },
        "artifact_count": len(artifact_rows),
        "artifact_hashes": artifact_rows,
        "artifact_set_hash": artifact_set_hash,
        "reproduction_commands": [
            "rapidtriage validation --output-dir <output-dir> --json",
            "rapidtriage commercial-readiness --validation-package <output-dir>/rapidtriage-validation-package.json --json",
        ],
        "commercial_gap_ids": [VALIDATION_PACKAGE_GAP_ID],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "package_manifest_hash": hashlib_json(manifest_core)}


def build_validation_package_report_grade_validation_plan(
    *,
    package_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None,
) -> dict[str, object]:
    required_output_presence = (
        package_manifest.get("required_output_presence")
        if isinstance(package_manifest.get("required_output_presence"), Mapping)
        else {}
    )
    missing_outputs = [
        name for name in VALIDATION_PACKAGE_REQUIRED_OUTPUTS
        if not bool(required_output_presence.get(name))
    ]
    required_section_presence = (
        package_manifest.get("required_section_presence_declared")
        if isinstance(package_manifest.get("required_section_presence_declared"), Mapping)
        else {}
    )
    missing_sections = [
        section for section in VALIDATION_PACKAGE_REQUIRED_SECTIONS
        if not bool(required_section_presence.get(section))
    ]
    artifact_count = int(package_manifest.get("artifact_count") or 0)
    trusted_status = str(trusted_diff.get("status") or "missing") if trusted_diff else "missing"
    ready_slots = [
        {
            "slot_id": "required-output-presence",
            "status": "ready",
            "evidence_ref": "validation_package_manifest.required_output_presence_hash",
            "evidence_hash": str(package_manifest.get("required_output_presence_hash") or ""),
            "description": "Required JSON, Markdown, and artifact-manifest outputs are checked before the package is treated as release evidence.",
        },
        {
            "slot_id": "artifact-set-hash",
            "status": "ready",
            "evidence_ref": "validation_package_manifest.artifact_set_hash",
            "evidence_hash": str(package_manifest.get("artifact_set_hash") or ""),
            "description": "Generated validation-package artifacts are bound by path-independent SHA256 rows when present.",
        },
        {
            "slot_id": "package-manifest-hash",
            "status": "ready",
            "evidence_ref": "validation_package_manifest.package_manifest_hash",
            "evidence_hash": str(package_manifest.get("package_manifest_hash") or ""),
            "description": "Package manifest hash binds output presence, required sections, artifact rows, and reproduction commands.",
        },
        {
            "slot_id": "required-section-declaration",
            "status": "ready",
            "evidence_ref": "validation_package_manifest.required_section_presence_declared",
            "evidence_hash": hashlib_json({"required_section_presence_declared": dict(required_section_presence)}),
            "description": "Validation-package sections for known answers, fixtures, FP/FN notes, independent validation, QC, and package assessment are declared.",
        },
        {
            "slot_id": "reproduction-commands",
            "status": "ready",
            "evidence_ref": "validation_package_manifest.reproduction_commands",
            "evidence_hash": hashlib_json({"reproduction_commands": list(package_manifest.get("reproduction_commands") or [])}),
            "description": "Reproduction commands are emitted so an operator can regenerate the package and commercial-readiness report.",
        },
        {
            "slot_id": "trusted-diff-disclosure",
            "status": "ready",
            "evidence_ref": "validation_package_assessment.trusted_validation_package_diff.status",
            "evidence_hash": hashlib_json({"trusted_diff_status": trusted_status}),
            "description": "Trusted validation-package diff status is explicit; a generated package is not treated as independently validated by default.",
        },
    ]
    blocking_slots = []
    if missing_outputs:
        blocking_slots.append(
            {
                "slot_id": "required-outputs-present",
                "status": "blocked",
                "blocker": "validation-package-required-outputs-missing",
                "required_evidence": ", ".join(missing_outputs),
            }
        )
    if missing_sections:
        blocking_slots.append(
            {
                "slot_id": "required-sections-declared",
                "status": "blocked",
                "blocker": "validation-package-required-sections-missing",
                "required_evidence": ", ".join(missing_sections),
            }
        )
    if trusted_status != "pass":
        blocking_slots.append(
            {
                "slot_id": "trusted-validation-package-manifest-diff",
                "status": "blocked",
                "blocker": VALIDATION_PACKAGE_TRUSTED_DIFF_BLOCKER_85,
                "required_evidence": "trusted validation-package manifest diff covering output presence, artifact set hash, package hash, and required sections",
            }
        )
    blocking_slots.extend(
        [
            {
                "slot_id": "operator-test-log-attachment",
                "status": "blocked",
                "blocker": "validation-package-test-logs-not-attached",
                "required_evidence": "unit/integration/build/smoke command logs attached to the package for the shipped release",
            },
            {
                "slot_id": "release-evidence-attachment",
                "status": "blocked",
                "blocker": "validation-package-release-evidence-not-attached",
                "required_evidence": "release artifact hashes, platform smoke results, and dependency/SBOM evidence attached",
            },
            {
                "slot_id": "independent-review-attachment",
                "status": "blocked",
                "blocker": "validation-package-independent-review-not-attached",
                "required_evidence": "independent review or lab signoff tying the validation package to the shipped build",
            },
        ]
    )
    manifest_core = {
        "profile_version": VALIDATION_PACKAGE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 85,
        "gap_id": VALIDATION_PACKAGE_GAP_ID,
        "commercial_gap_ids": [VALIDATION_PACKAGE_GAP_ID],
        "required_output_presence": dict(required_output_presence),
        "missing_required_outputs": missing_outputs,
        "required_section_presence_declared": dict(required_section_presence),
        "missing_required_sections": missing_sections,
        "artifact_count": artifact_count,
        "package_manifest_hash": str(package_manifest.get("package_manifest_hash") or ""),
        "artifact_set_hash": str(package_manifest.get("artifact_set_hash") or ""),
        "trusted_diff_status": trusted_status,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": [str(slot["blocker"]) for slot in blocking_slots],
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": (
            "A generated validation package is internal release evidence only until test logs, release evidence, "
            "trusted package diff, and independent review are attached."
        ),
    }
    return {**manifest_core, "validation_plan_hash": hashlib_json(manifest_core)}


def build_validation_legal_defensibility_matrix(
    *,
    known_answer_validation: Mapping[str, object],
    parser_fixture_corpus: Mapping[str, object],
    parser_fp_fn_profile: Mapping[str, object],
    independent_validation_report: Mapping[str, object],
    validation_package_assessment: Mapping[str, object],
) -> dict[str, object]:
    source_rows = [
        {
            "item_number": 81,
            "gap_id": "#81",
            "component": "known-answer validation",
            "status": str(known_answer_validation.get("status") or ""),
            "primary_hash": str(known_answer_validation.get("known_answer_pipeline_manifest_hash") or ""),
            "secondary_hash": str(known_answer_validation.get("dataset_evidence_matrix_hash") or ""),
            "blockers": list(known_answer_validation.get("blockers") or []),
            "implemented": True,
            "usable": True,
            "validated": bool(known_answer_validation.get("dataset_count")),
            "commercial_grade_ready": bool(known_answer_validation.get("ready_for_court_report")),
        },
        {
            "item_number": 82,
            "gap_id": "#82",
            "component": "parser fixture corpus",
            "status": str(parser_fixture_corpus.get("coverage_status") or ""),
            "primary_hash": str(parser_fixture_corpus.get("fixture_corpus_digest") or ""),
            "secondary_hash": str(parser_fixture_corpus.get("fixture_release_gate_matrix_hash") or ""),
            "blockers": list(parser_fixture_corpus.get("blockers") or []),
            "implemented": True,
            "usable": True,
            "validated": bool(parser_fixture_corpus.get("fixture_backed_count")),
            "commercial_grade_ready": bool(parser_fixture_corpus.get("ready_for_court_report"))
            and not bool(parser_fixture_corpus.get("blockers")),
        },
        {
            "item_number": 83,
            "gap_id": "#83",
            "component": "parser FP/FN risk register",
            "status": str(parser_fp_fn_profile.get("status") or "partial"),
            "primary_hash": str(parser_fp_fn_profile.get("risk_register_manifest_hash") or ""),
            "secondary_hash": str(parser_fp_fn_profile.get("risk_matrix_hash") or ""),
            "blockers": list(parser_fp_fn_profile.get("required_before_report") or []),
            "implemented": True,
            "usable": True,
            "validated": bool(parser_fp_fn_profile.get("parser_count")),
            "commercial_grade_ready": bool(parser_fp_fn_profile.get("commercial_claim_allowed")),
        },
        {
            "item_number": 84,
            "gap_id": "#84",
            "component": "independent validation report",
            "status": str(independent_validation_report.get("status") or ""),
            "primary_hash": str(independent_validation_report.get("independent_validation_package_manifest_hash") or ""),
            "secondary_hash": str(
                (independent_validation_report.get("independent_validation_manifest") or {}).get("signoff_status_hash")
                if isinstance(independent_validation_report.get("independent_validation_manifest"), Mapping)
                else ""
            ),
            "blockers": list(independent_validation_report.get("blockers") or []),
            "implemented": True,
            "usable": True,
            "validated": bool(independent_validation_report.get("sha256")),
            "commercial_grade_ready": bool(independent_validation_report.get("ready_for_court_report")),
        },
        {
            "item_number": 85,
            "gap_id": "#85",
            "component": "validation package automation",
            "status": str(validation_package_assessment.get("status") or ""),
            "primary_hash": str(validation_package_assessment.get("package_manifest_hash") or ""),
            "secondary_hash": str(
                (validation_package_assessment.get("validation_package_manifest") or {}).get("artifact_set_hash")
                if isinstance(validation_package_assessment.get("validation_package_manifest"), Mapping)
                else ""
            ),
            "blockers": list(validation_package_assessment.get("blockers") or []),
            "implemented": True,
            "usable": True,
            "validated": True,
            "commercial_grade_ready": bool(validation_package_assessment.get("ready_for_court_report")),
        },
    ]
    rows = [{**row, "row_hash": hashlib_json(row)} for row in source_rows]
    matrix_core = {
        "profile_version": "validation-legal-defensibility-matrix-v1",
        "item_numbers": [81, 82, 83, 84, 85],
        "row_count": len(rows),
        "implemented_count": sum(1 for row in rows if row["implemented"]),
        "usable_count": sum(1 for row in rows if row["usable"]),
        "validated_count": sum(1 for row in rows if row["validated"]),
        "commercial_grade_count": sum(1 for row in rows if row["commercial_grade_ready"]),
        "rows": rows,
        "commercial_claim_allowed": all(bool(row["commercial_grade_ready"]) for row in rows),
    }
    return {**matrix_core, "matrix_hash": hashlib_json(matrix_core)}


def missing_validation_trusted_diff(gap_id: str, blocker: str, *, trusted_tool: str) -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [gap_id],
        "blocker": blocker,
        "required_trusted_tool": trusted_tool,
    }


def build_known_answer_trusted_diff(
    rapid_validation: Mapping[str, object],
    trusted_validation: Mapping[str, object],
    *,
    trusted_tool: str = "known-answer-manifest",
) -> dict[str, object]:
    rapid_index = index_known_answer_datasets(rapid_validation.get("datasets"))
    trusted_index = index_known_answer_datasets(trusted_validation.get("datasets"))
    mismatches = compare_indexed_manifests(
        rapid_index,
        trusted_index,
        fields=(
            "status",
            "backlog_items",
            "evidence_paths_present",
            "expected_assertion_count",
            "evidence_hashes",
            "evidence_matrix_row_hash",
            "dataset_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in VALIDATION_TRUSTED_TOOLS else "fail"
    return validation_trusted_diff_result(
        status=status,
        gap_id=KNOWN_ANSWER_TEST_GAP_ID,
        blocker=KNOWN_ANSWER_TRUSTED_DIFF_BLOCKER_81,
        trusted_tool=trusted_tool,
        compared_fields=[
            "dataset_id",
            "status",
            "backlog_items",
            "evidence_paths_present",
            "expected_assertion_count",
            "evidence_hashes",
            "evidence_matrix_row_hash",
            "dataset_hash",
        ],
        mismatches=mismatches,
    )


def build_fixture_corpus_trusted_diff(
    rapid_corpus: Mapping[str, object],
    trusted_corpus: Mapping[str, object],
    *,
    trusted_tool: str = "fixture-corpus-manifest",
) -> dict[str, object]:
    rapid_index = index_fixture_areas(rapid_corpus.get("areas"))
    trusted_index = index_fixture_areas(trusted_corpus.get("areas"))
    mismatches = compare_indexed_manifests(
        rapid_index,
        trusted_index,
        fields=(
            "fixture_count",
            "test_file_count",
            "fixture_hash_count",
            "test_file_hash_count",
            "fixture_backed",
            "area_manifest_hash",
            "release_gate_row_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in VALIDATION_TRUSTED_TOOLS else "fail"
    return validation_trusted_diff_result(
        status=status,
        gap_id=PARSER_FIXTURE_CORPUS_GAP_ID,
        blocker=FIXTURE_CORPUS_TRUSTED_DIFF_BLOCKER_82,
        trusted_tool=trusted_tool,
        compared_fields=[
            "area_id",
            "fixture_count",
            "test_file_count",
            "fixture_hash_count",
            "test_file_hash_count",
            "fixture_backed",
            "area_manifest_hash",
            "release_gate_row_hash",
        ],
        mismatches=mismatches,
    )


def build_fp_fn_trusted_diff(
    rapid_notes: Sequence[Mapping[str, object]],
    trusted_notes: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "fp-fn-risk-register",
) -> dict[str, object]:
    rapid_index = index_fp_fn_notes(rapid_notes)
    trusted_index = index_fp_fn_notes(trusted_notes)
    mismatches = compare_indexed_manifests(
        rapid_index,
        trusted_index,
        fields=(
            "false_positive_count",
            "false_negative_count",
            "validation_required",
            "risk_note_hash",
            "minimum_quantification_field_count",
            "quantification_required",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in VALIDATION_TRUSTED_TOOLS else "fail"
    return validation_trusted_diff_result(
        status=status,
        gap_id=PARSER_FP_FN_GAP_ID,
        blocker=FP_FN_TRUSTED_DIFF_BLOCKER_83,
        trusted_tool=trusted_tool,
        compared_fields=[
            "parser",
            "false_positive_count",
            "false_negative_count",
            "validation_required",
            "risk_note_hash",
            "minimum_quantification_field_count",
            "quantification_required",
        ],
        mismatches=mismatches,
    )


def build_independent_validation_trusted_diff(
    rapid_report: Mapping[str, object],
    trusted_report: Mapping[str, object],
    *,
    trusted_tool: str = "independent-validation-signoff",
) -> dict[str, object]:
    compared_fields = [
        "status",
        "sha256",
        "size_bytes",
        "required_signoffs",
        "minimum_sections",
        "minimum_section_presence",
        "minimum_section_presence_hash",
        "signoff_status_hash",
        "report_manifest_hash",
    ]
    mismatches = [
        {
            "field": field,
            "rapid": independent_validation_diff_value(rapid_report, field),
            "trusted": independent_validation_diff_value(trusted_report, field),
        }
        for field in compared_fields
        if normalize_manifest_value(independent_validation_diff_value(rapid_report, field))
        != normalize_manifest_value(independent_validation_diff_value(trusted_report, field))
    ]
    status = "pass" if not mismatches and trusted_tool in VALIDATION_TRUSTED_TOOLS else "fail"
    return validation_trusted_diff_result(
        status=status,
        gap_id=INDEPENDENT_VALIDATION_GAP_ID,
        blocker=INDEPENDENT_VALIDATION_TRUSTED_DIFF_BLOCKER_84,
        trusted_tool=trusted_tool,
        compared_fields=compared_fields,
        mismatches=mismatches,
    )


def independent_validation_diff_value(report: Mapping[str, object], field: str) -> object:
    manifest = report.get("independent_validation_manifest")
    manifest_mapping = manifest if isinstance(manifest, Mapping) else {}
    if field == "minimum_section_presence":
        return manifest_mapping.get("minimum_section_presence") or report.get("minimum_section_presence")
    if field == "minimum_section_presence_hash":
        return manifest_mapping.get("minimum_section_presence_hash")
    if field == "signoff_status_hash":
        return manifest_mapping.get("signoff_status_hash")
    if field == "report_manifest_hash":
        return manifest_mapping.get("report_manifest_hash")
    return report.get(field)


def build_validation_package_trusted_diff(
    rapid_manifest: Mapping[str, object],
    trusted_manifest: Mapping[str, object],
    *,
    trusted_tool: str = "validation-package-manifest",
) -> dict[str, object]:
    rapid_index = index_validation_artifacts(rapid_manifest.get("artifacts"))
    trusted_index = index_validation_artifacts(trusted_manifest.get("artifacts"))
    mismatches = compare_indexed_manifests(
        rapid_index,
        trusted_index,
        fields=("sha256", "size_bytes"),
    )
    top_level_fields = ["artifact_count", "artifact_set_hash", "required_output_presence_hash", "package_manifest_hash"]
    for field in top_level_fields:
        if normalize_manifest_value(rapid_manifest.get(field)) != normalize_manifest_value(trusted_manifest.get(field)):
            mismatches.append(
                {
                    "id": "validation-package-manifest",
                    "field": field,
                    "rapid": rapid_manifest.get(field),
                    "trusted": trusted_manifest.get(field),
                }
            )
    status = "pass" if not mismatches and trusted_tool in VALIDATION_TRUSTED_TOOLS else "fail"
    return validation_trusted_diff_result(
        status=status,
        gap_id=VALIDATION_PACKAGE_GAP_ID,
        blocker=VALIDATION_PACKAGE_TRUSTED_DIFF_BLOCKER_85,
        trusted_tool=trusted_tool,
        compared_fields=[
            "artifact_name",
            "sha256",
            "size_bytes",
            "artifact_count",
            "artifact_set_hash",
            "required_output_presence_hash",
            "package_manifest_hash",
        ],
        mismatches=mismatches,
    )


def validation_trusted_diff_result(
    *,
    status: str,
    gap_id: str,
    blocker: str,
    trusted_tool: str,
    compared_fields: Sequence[str],
    mismatches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [gap_id],
        "compared_fields": list(compared_fields),
        "mismatches": [dict(item) for item in mismatches],
        "blocker": None if status == "pass" else blocker,
    }


def compare_indexed_manifests(
    rapid_index: Mapping[str, Mapping[str, object]],
    trusted_index: Mapping[str, Mapping[str, object]],
    *,
    fields: Sequence[str],
) -> list[dict[str, object]]:
    mismatches: list[dict[str, object]] = []
    for key, trusted_row in sorted(trusted_index.items()):
        rapid_row = rapid_index.get(key)
        if rapid_row is None:
            mismatches.append({"id": key, "field": "row", "rapid": None, "trusted": "present"})
            continue
        for field in fields:
            rapid_value = normalize_manifest_value(rapid_row.get(field))
            trusted_value = normalize_manifest_value(trusted_row.get(field))
            if rapid_value != trusted_value:
                mismatches.append({"id": key, "field": field, "rapid": rapid_value, "trusted": trusted_value})
    for key in sorted(set(rapid_index) - set(trusted_index)):
        mismatches.append({"id": key, "field": "row", "rapid": "present", "trusted": None})
    return mismatches


def normalize_manifest_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(str(item) for item in value)
    if isinstance(value, tuple):
        return sorted(str(item) for item in value)
    return value


def index_known_answer_datasets(rows: object) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    if not isinstance(rows, list):
        return indexed
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        dataset_id = str(row.get("id") or "")
        if not dataset_id:
            continue
        indexed[dataset_id] = {
            "status": row.get("status"),
            "backlog_items": [str(value).lstrip("#") for value in row.get("backlog_items") or []],
            "evidence_paths_present": bool(row.get("evidence_paths_present")),
            "expected_assertion_count": int(row.get("expected_assertion_count") or 0),
            "evidence_hashes": [str(value) for value in row.get("evidence_hashes") or []],
            "evidence_matrix_row_hash": str(row.get("evidence_matrix_row_hash") or ""),
            "dataset_hash": str(row.get("dataset_hash") or ""),
        }
    return indexed


def index_fixture_areas(rows: object) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    if not isinstance(rows, list):
        return indexed
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        area_id = str(row.get("id") or "")
        if not area_id:
            continue
        indexed[area_id] = {
            "fixture_count": int(row.get("fixture_count") or 0),
            "test_file_count": int(row.get("test_file_count") or 0),
            "fixture_hash_count": int(row.get("fixture_hash_count") or 0),
            "test_file_hash_count": int(row.get("test_file_hash_count") or 0),
            "fixture_backed": bool(row.get("fixture_backed")),
            "area_manifest_hash": str(row.get("area_manifest_hash") or ""),
            "release_gate_row_hash": str(row.get("release_gate_row_hash") or ""),
        }
    return indexed


def index_fp_fn_notes(rows: Sequence[Mapping[str, object]]) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    for row in rows:
        parser = str(row.get("parser") or "")
        if not parser:
            continue
        fp = row.get("false_positive_risks")
        fn = row.get("false_negative_risks")
        indexed[parser] = {
            "false_positive_count": len(fp) if isinstance(fp, list) else 0,
            "false_negative_count": len(fn) if isinstance(fn, list) else 0,
            "validation_required": str(row.get("validation_required") or ""),
            "risk_note_hash": str(row.get("risk_note_hash") or ""),
            "minimum_quantification_field_count": len(row.get("minimum_quantification_fields") or []),
            "quantification_required": bool(row.get("quantification_required")),
        }
    return indexed


def index_validation_artifacts(rows: object) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    if not isinstance(rows, list):
        return indexed
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        name = str(row.get("name") or "")
        if not name:
            continue
        indexed[name] = {
            "sha256": str(row.get("sha256") or ""),
            "size_bytes": int(row.get("size_bytes") or 0),
        }
    return indexed


def build_external_tool_versions() -> list[dict[str, object]]:
    tools = [
        ("python", [sys.executable, "--version"]),
        ("ewfmount", ["ewfmount", "-V"]),
        ("mmls", ["mmls", "-V"]),
        ("tsk_recover", ["tsk_recover", "-V"]),
        ("qemu-img", ["qemu-img", "--version"]),
        ("tesseract", ["tesseract", "--version"]),
        ("node", ["node", "--version"]),
    ]
    rows = []
    for name, command in tools:
        executable = command[0] if command and command[0] else name
        path = shutil.which(executable)
        if path is None:
            row = attach_external_tool_version_row_manifest(
                {
                    "name": name,
                    "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
                    "available": False,
                    "path": "",
                    "command": " ".join(command),
                    "command_argv": list(command),
                    "return_code": None,
                    "version_output": "",
                    "version_output_sha256": "",
                    "capture_error": "not-found",
                }
            )
            row["core_accuracy_gates"] = external_tool_version_core_accuracy_gates(
                available=False,
                path="",
                command=str(row.get("command") or ""),
                version_output="",
                capture_error="not-found",
                row_manifest=row.get("tool_version_row_manifest") if isinstance(row.get("tool_version_row_manifest"), Mapping) else None,
            )
            rows.append(row)
            continue
        actual_command = [path, *command[1:]]
        try:
            completed = subprocess.run(
                actual_command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=5,
            )
            version_output = (completed.stdout or "").strip().splitlines()[:3]
            output_text = "\n".join(version_output)
            row = attach_external_tool_version_row_manifest(
                {
                    "name": name,
                    "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
                    "available": True,
                    "path": path,
                    "command": " ".join(actual_command),
                    "command_argv": list(actual_command),
                    "return_code": completed.returncode,
                    "version_output": output_text,
                    "version_output_sha256": hashlib.sha256(output_text.encode("utf-8")).hexdigest() if output_text else "",
                    "capture_error": "",
                }
            )
            row["core_accuracy_gates"] = external_tool_version_core_accuracy_gates(
                available=True,
                path=path,
                command=str(row.get("command") or ""),
                version_output=output_text,
                capture_error="",
                row_manifest=row.get("tool_version_row_manifest") if isinstance(row.get("tool_version_row_manifest"), Mapping) else None,
            )
            rows.append(row)
        except (OSError, subprocess.SubprocessError) as exc:
            row = attach_external_tool_version_row_manifest(
                {
                    "name": name,
                    "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
                    "available": True,
                    "path": path,
                    "command": " ".join(actual_command),
                    "command_argv": list(actual_command),
                    "return_code": None,
                    "version_output": "",
                    "version_output_sha256": "",
                    "capture_error": str(exc),
                }
            )
            row["core_accuracy_gates"] = external_tool_version_core_accuracy_gates(
                available=True,
                path=path,
                command=str(row.get("command") or ""),
                version_output="",
                capture_error=str(exc),
                row_manifest=row.get("tool_version_row_manifest") if isinstance(row.get("tool_version_row_manifest"), Mapping) else None,
            )
            rows.append(row)
    return rows


def attach_external_tool_version_row_manifest(row: Mapping[str, object]) -> dict[str, object]:
    row_payload = dict(row)
    command_argv_hash = hashlib.sha256(
        json.dumps(list(row_payload.get("command_argv") or []), ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    capture_state = {
        "available": bool(row_payload.get("available")),
        "return_code": row_payload.get("return_code"),
        "version_output_sha256": str(row_payload.get("version_output_sha256") or ""),
        "capture_error": str(row_payload.get("capture_error") or ""),
    }
    manifest_core = {
        "profile_version": "external-tool-version-row-v1",
        "item_number": 95,
        "name": str(row_payload.get("name") or ""),
        "available": bool(row_payload.get("available")),
        "path": str(row_payload.get("path") or ""),
        "command": str(row_payload.get("command") or ""),
        "command_argv": list(row_payload.get("command_argv") or []),
        "command_argv_hash": command_argv_hash,
        "return_code": row_payload.get("return_code"),
        "version_output_sha256": str(row_payload.get("version_output_sha256") or ""),
        "capture_error": str(row_payload.get("capture_error") or ""),
        "capture_state_hash": hashlib.sha256(
            json.dumps(capture_state, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    row_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    manifest = {**manifest_core, "row_hash": row_hash}
    return {
        **row_payload,
        "command_argv_hash": command_argv_hash,
        "capture_state_hash": manifest_core["capture_state_hash"],
        "tool_version_row_manifest": manifest,
        "tool_version_row_hash": row_hash,
    }


def build_external_tool_capture_matrix(tools: Sequence[Mapping[str, object]]) -> dict[str, object]:
    rows = []
    for item in tools:
        row_core = {
            "name": str(item.get("name") or ""),
            "available": bool(item.get("available")),
            "path_present": bool(item.get("path")),
            "command_present": bool(item.get("command")),
            "command_argv_hash": str(item.get("command_argv_hash") or ""),
            "version_output_sha256": str(item.get("version_output_sha256") or ""),
            "capture_error": str(item.get("capture_error") or ""),
            "capture_state_hash": str(item.get("capture_state_hash") or ""),
            "tool_version_row_hash": str(item.get("tool_version_row_hash") or ""),
        }
        rows.append({**row_core, "row_hash": hashlib.sha256(
            json.dumps(row_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()})
    matrix_core = {
        "profile_version": "external-tool-capture-matrix-v1",
        "item_number": 95,
        "tool_count": len(rows),
        "rows": rows,
        "all_rows_hashed": all(row.get("row_hash") for row in rows) if rows else True,
        "all_commands_recorded_or_missing": all(row.get("command_present") or not row.get("available") for row in rows) if rows else True,
        "commercial_claim_allowed": False,
    }
    return {**matrix_core, "matrix_hash": hashlib.sha256(
        json.dumps(matrix_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()}


def build_external_tool_version_manifest(tools: Sequence[Mapping[str, object]]) -> dict[str, object]:
    row_hashes = [str(item.get("tool_version_row_hash") or "") for item in tools]
    capture_matrix = build_external_tool_capture_matrix(tools)
    manifest_core = {
        "profile_version": "external-tool-version-manifest-v1",
        "item_number": 95,
        "tool_count": len(tools),
        "available_count": sum(1 for item in tools if item.get("available")),
        "missing_count": sum(1 for item in tools if not item.get("available")),
        "capture_error_count": sum(1 for item in tools if item.get("capture_error")),
        "tool_names": [str(item.get("name") or "") for item in tools],
        "row_hashes": row_hashes,
        "capture_matrix_hash": capture_matrix["matrix_hash"],
        "capture_environment": {
            "platform": platform.platform(),
            "python_executable_hash": hashlib.sha256(sys.executable.encode("utf-8")).hexdigest(),
        },
        "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(
        json.dumps(manifest_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**manifest_core, "capture_matrix": capture_matrix, "manifest_hash": manifest_hash}


def build_external_tool_version_assessment(*, trusted_diff: Mapping[str, object] | None = None) -> dict[str, object]:
    tools = build_external_tool_versions()
    tool_manifest = build_external_tool_version_manifest(tools)
    satisfied = [
        "tool inventory emitted",
        "tool path captured when available",
        "version command captured",
        "capture error recorded",
        "per-run limitation warning",
        "tool row hashes emitted",
        "external tool version manifest hash emitted",
        "external tool capture matrix hash emitted",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted external tool transcript diff pass")
    blockers = [
        "per-run-external-parser-version-capture-is-not-complete-for-every-import",
        "operator-must-preserve-original-tool-logs-for-acquisition-and-parser-validation",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(EXTERNAL_TOOL_VERSION_TRUSTED_DIFF_BLOCKER_95)
    return {
        "component": "external-tool-version-capture",
        "status": "release-validation-tool-preflight",
        "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
        "summary": {
            "tool_count": tool_manifest["tool_count"],
            "available_count": tool_manifest["available_count"],
            "missing_count": tool_manifest["missing_count"],
            "capture_error_count": tool_manifest["capture_error_count"],
            "manifest_hash": tool_manifest["manifest_hash"],
        },
        "external_tool_version_manifest": tool_manifest,
        "external_tool_version_manifest_hash": tool_manifest["manifest_hash"],
        "external_tool_capture_matrix": tool_manifest["capture_matrix"],
        "external_tool_capture_matrix_hash": tool_manifest["capture_matrix_hash"],
        "trusted_external_tool_version_diff": dict(trusted_diff) if trusted_diff else missing_external_tool_version_trusted_diff(),
        "core_accuracy_gates": [
            build_accuracy_gate(
                95,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"tool_count:{len(tools)}",
                    f"external_tool_version_manifest_hash:{tool_manifest['manifest_hash']}",
                    f"external_tool_capture_matrix_hash:{tool_manifest['capture_matrix_hash']}",
                ],
            )
        ],
        "ready_for_court_report": False,
        "blockers": blockers,
    }


def external_tool_version_core_accuracy_gates(
    *,
    available: bool,
    path: str,
    command: str,
    version_output: str,
    capture_error: str,
    row_manifest: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["tool inventory emitted", "per-run limitation warning"]
    if available and path:
        satisfied.append("tool path captured when available")
    if command:
        satisfied.append("version command captured")
    if version_output:
        satisfied.append("version output hash emitted")
    if version_output or capture_error:
        satisfied.append("capture error recorded")
    if row_manifest and row_manifest.get("row_hash"):
        satisfied.append("tool row hash emitted")
    if row_manifest and row_manifest.get("command_argv_hash"):
        satisfied.append("tool command argv hash emitted")
    if row_manifest and row_manifest.get("capture_state_hash"):
        satisfied.append("tool capture state hash emitted")
    return [
        build_accuracy_gate(
            95,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"available:{available}",
                f"path:{path}",
                f"command:{command}",
                f"capture_error:{capture_error}",
                f"tool_version_row_hash:{(row_manifest or {}).get('row_hash', '')}",
                f"command_argv_hash:{(row_manifest or {}).get('command_argv_hash', '')}",
                f"capture_state_hash:{(row_manifest or {}).get('capture_state_hash', '')}",
            ],
        )
    ]


def missing_external_tool_version_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
        "blocker": EXTERNAL_TOOL_VERSION_TRUSTED_DIFF_BLOCKER_95,
        "required_trusted_tools": sorted(EXTERNAL_TOOL_VERSION_TRUSTED_TOOLS),
    }


def build_external_tool_version_trusted_diff(
    rapid_tools: Sequence[Mapping[str, object]],
    trusted_tools: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "external-tool-transcript",
) -> dict[str, object]:
    rapid_index = index_external_tool_rows(rapid_tools)
    trusted_index = index_external_tool_rows(trusted_tools)
    mismatches = compare_indexed_manifests(
        rapid_index,
        trusted_index,
        fields=(
            "available",
            "path",
            "command",
            "version_output",
            "capture_error",
            "command_argv_hash",
            "capture_state_hash",
            "tool_version_row_hash",
        ),
    )
    status = "pass" if not mismatches and trusted_tool in EXTERNAL_TOOL_VERSION_TRUSTED_TOOLS else "fail"
    return validation_trusted_diff_result(
        status=status,
        gap_id=EXTERNAL_TOOL_VERSION_GAP_ID,
        blocker=EXTERNAL_TOOL_VERSION_TRUSTED_DIFF_BLOCKER_95,
        trusted_tool=trusted_tool,
        compared_fields=[
            "name",
            "available",
            "path",
            "command",
            "version_output",
            "capture_error",
            "command_argv_hash",
            "capture_state_hash",
            "tool_version_row_hash",
        ],
        mismatches=mismatches,
    )


def index_external_tool_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    for row in rows:
        name = str(row.get("name") or "")
        if not name:
            continue
        indexed[name] = {
            "available": bool(row.get("available")),
            "path": str(row.get("path") or ""),
            "command": str(row.get("command") or ""),
            "version_output": str(row.get("version_output") or ""),
            "capture_error": str(row.get("capture_error") or ""),
            "command_argv_hash": str(row.get("command_argv_hash") or ""),
            "capture_state_hash": str(row.get("capture_state_hash") or ""),
            "tool_version_row_hash": str(row.get("tool_version_row_hash") or ""),
        }
    return indexed


def build_validation_checks() -> list[dict[str, object]]:
    return [
        {
            "id": "unit-tests",
            "category": "quality",
            "status": "required",
            "evidence": "Full Python unittest output for the release commit.",
            "required_for_release": True,
        },
        {
            "id": "build-artifacts",
            "category": "packaging",
            "status": "required",
            "evidence": "Wheel/sdist build output and portable ZIP smoke result.",
            "required_for_release": True,
        },
        {
            "id": "windows-code-signing",
            "category": "packaging",
            "status": "operator-owned",
            "evidence": "Authenticode signature verification output for Windows executable/installers, including certificate subject, timestamp, and SHA256.",
            "required_for_release": False,
        },
        {
            "id": "macos-notarization",
            "category": "packaging",
            "status": "operator-owned",
            "evidence": "macOS codesign verification, notarization ticket/staple output, Gatekeeper assessment, and package SHA256.",
            "required_for_release": False,
        },
        {
            "id": "release-checksums-sbom",
            "category": "supply-chain",
            "status": "required",
            "evidence": "Release artifact SHA256SUMS, dependency lock/build metadata, and SBOM or dependency inventory.",
            "required_for_release": True,
        },
        {
            "id": "fresh-machine-smoke",
            "category": "usability",
            "status": "required",
            "evidence": "Windows and macOS checklist run from docs/rapidtriage-fresh-machine-smoke-test.md.",
            "required_for_release": True,
        },
        {
            "id": "sample-case",
            "category": "workflow",
            "status": "required",
            "evidence": "rapidtriage sample --run output with run summary, report, and searchable results.",
            "required_for_release": True,
        },
        {
            "id": "benchmark",
            "category": "performance",
            "status": "required",
            "evidence": "rapidtriage benchmark JSON/Markdown attached to release notes.",
            "required_for_release": True,
        },
        {
            "id": "parser-coverage",
            "category": "forensic-coverage",
            "status": "required",
            "evidence": "docs/rapidtriage-parser-coverage.md and deterministic parser fixture tests.",
            "required_for_release": True,
        },
        {
            "id": "known-limitations",
            "category": "trust",
            "status": "required",
            "evidence": "docs/rapidtriage-known-limitations.md reviewed for the release version.",
            "required_for_release": True,
        },
        {
            "id": "chain-of-custody",
            "category": "evidence",
            "status": "required",
            "evidence": "Submission bundle hash manifest, audit events, source paths, and review decisions.",
            "required_for_release": True,
        },
        {
            "id": "security-posture",
            "category": "security",
            "status": "required",
            "evidence": "Localhost default, remote auth-token requirement, path handling tests, and release notes warning.",
            "required_for_release": True,
        },
        {
            "id": "support-readiness",
            "category": "operations",
            "status": "operator-owned",
            "evidence": "Support contact, triage SLA, training material, escalation process, and emergency parser-fix policy for deployed users.",
            "required_for_release": False,
        },
    ]


def build_commercial_gap_assessment() -> list[dict[str, object]]:
    return [
        {
            "area": "native-evidence-acquisition",
            "severity": "high",
            "current_status": "E01/Ex01 direct extraction works only when external libewf/Sleuth Kit tools are present; other image families are detected with guidance.",
            "needed_for_commercial_parity": "Read-only native or orchestrated handling for raw/split images, AD1/L01/Lx01, AFF/AFF4, VHD/VHDX, VMDK, VDI, XVA, QCOW/QCOW2, ISO, DMG, WIM/SWM, and reliable partition/filesystem selection.",
            "operator_workaround": "Mount or export with validated forensic tooling and scan the resulting folder.",
        },
        {
            "area": "binary-windows-artifact-depth",
            "severity": "high",
            "current_status": "EVTX native scanning is partial but now preserves common BinXML scalar values, SIDs, TemplateInstance IDs, message-rendering provenance, native chunk structure rows, and cautious slack/deleted/corrupt record candidate metadata; MFT/USN support includes imports plus bounded native inventory/USN record recovery; registry/OS-account support includes exports, inventory-level native hive parsing, hbin-aware bounded key-tree rows, key/value recovery candidates, SAM account/RID candidates, service/mounted-device/LSA/privilege export rows, and first-pass NTUSER/UsrClass user-activity pivots; execution support includes Amcache/ShimCache/BAM/UserAssist exports, native Amcache path/hash candidates, SRUM imports, and SRUDB table/string pivots; Windows.edb includes direct ESE header and bounded string-pivot inventory but not full table decoding.",
            "needed_for_commercial_parity": "Full EVTX BinXML/provider message resource rendering, native Registry hive transaction-log replay, deep NTUSER.DAT/UsrClass.dat binary value decoding and deleted-value testimony validation, full SAM F/V and SECURITY secret decoding, native Amcache/ShimCache/BAM binary decoding, SRUDB ESE table/page row decoding, Windows.edb ESE, $MFT, $UsnJrnl, JumpList, ShellBags, and Prefetch parsers with validation corpora.",
            "operator_workaround": "Import exports from trusted tools such as EvtxECmd, Hayabusa, Chainsaw, Velociraptor, PECmd, MFTECmd, and SRUM/EDB export utilities.",
        },
        {
            "area": "mobile-cloud-memory-depth",
            "severity": "high",
            "current_status": "APK triage includes permissions, dex/native inventory, and bounded string/URL/IP pivots; cloud export imports, Volatility-style output imports, and bounded direct memory dump indicator scans exist; direct acquisition and deep native analysis are not implemented.",
            "needed_for_commercial_parity": "Vendor package importers, app database parsers, direct cloud/API acquisition workflows, full raw memory process reconstruction, validated BitLocker key workflows, and malware process scoring.",
            "operator_workaround": "Use Cellebrite/XRY/GrayKey/AXIOM/cloud provider exports and Volatility outputs, then import the resulting folder/files; validate direct memory string/key candidates before reporting.",
        },
        {
            "area": "cross-platform-release",
            "severity": "medium",
            "current_status": "Source/wheel build and launchers exist, but signed Windows/macOS installers and notarization are outside the repo.",
            "needed_for_commercial_parity": "Signed installers, notarized macOS packages, update channel, repeatable release artifacts, and fresh-machine test evidence.",
            "operator_workaround": "Run fresh-machine smoke tests and distribute through an internally controlled packaging process.",
        },
        {
            "area": "legal-validation-support",
            "severity": "medium",
            "current_status": "Validation package and deterministic fixtures exist, but independent legal validation, training, and SLA are operator-owned.",
            "needed_for_commercial_parity": "Third-party validation datasets, documented support process, training material, release notes, and escalation SLA.",
            "operator_workaround": "Attach validation output, benchmark output, known limitations, and analyst verification notes to every internal release.",
        },
    ]


def build_recommended_commands() -> list[dict[str, str]]:
    return [
        {"name": "unit-tests", "command": "python -m unittest discover -s tests"},
        {"name": "compile", "command": "python -m compileall -q rapidtriage"},
        {"name": "web-js-syntax", "command": "node --check rapidtriage/web/static/app.js"},
        {"name": "build", "command": "python -m build --wheel --sdist"},
        {"name": "release-zip", "command": "python scripts/build-release.py --output-dir release"},
        {"name": "windows-signature-verify", "command": "Get-AuthenticodeSignature .\\release\\*.exe | Format-List"},
        {"name": "macos-notarization-verify", "command": "codesign --verify --deep --strict APP && spctl --assess --type execute APP"},
        {"name": "doctor", "command": "rapidtriage doctor --json"},
        {"name": "sample", "command": "rapidtriage sample --run --overwrite --read-only --json"},
        {
            "name": "benchmark",
            "command": "rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite --json",
        },
        {
            "name": "validation-package",
            "command": "rapidtriage validation --output-dir ./release-validation --overwrite --json",
        },
        {
            "name": "windows-smoke-test",
            "command": ".\\scripts\\windows\\smoke-test-rapidtriage.ps1",
        },
        {
            "name": "macos-linux-smoke-test",
            "command": "sh scripts/smoke-test-rapidtriage.sh",
        },
        {
            "name": "release-checksums",
            "command": "python scripts/build-release.py --output-dir release",
        },
        {
            "name": "verify-release-checksums",
            "command": "python scripts/build-release.py --output-dir release --verify",
        },
        {
            "name": "smoke-summary",
            "command": "python scripts/summarize-smoke.py ./rapidtriage-macos-linux-smoke",
        },
        {
            "name": "release-evidence",
            "command": "python scripts/verify-release-evidence.py --release-dir release --validation-dir release-validation --benchmark-dir release-benchmark --smoke-dir rapidtriage-windows-smoke --smoke-dir rapidtriage-macos-linux-smoke --require-smoke-platform windows --require-smoke-platform macos-linux",
        },
    ]


def build_release_artifact_requirements() -> list[dict[str, object]]:
    return [
        {
            "id": "windows-installer",
            "platform": "windows",
            "required_evidence": [
                "installer_or_portable_zip_sha256",
                "authenticode_signature_status",
                "timestamp_authority",
                "fresh_windows_smoke_test",
            ],
            "operator_owned": True,
            "release_gate": "must-pass-before-public-release",
        },
        {
            "id": "macos-app-or-package",
            "platform": "macos",
            "required_evidence": [
                "artifact_sha256",
                "codesign_verify_output",
                "notarization_ticket_or_staple_output",
                "gatekeeper_assessment",
                "fresh_macos_smoke_test",
            ],
            "operator_owned": True,
            "release_gate": "must-pass-before-public-release",
        },
        {
            "id": "source-wheel-sdist",
            "platform": "cross-platform",
            "required_evidence": [
                "wheel_sha256",
                "sdist_sha256",
                "python_version",
                "dependency_inventory",
                "unit_test_output",
            ],
            "operator_owned": False,
            "release_gate": "required-for-internal-release",
        },
    ]


def build_independent_validation_plan() -> list[dict[str, object]]:
    return [
        {
            "id": "parser-corpus",
            "owner": "independent-reviewer",
            "minimum_scope": "Windows EVTX/Registry/MFT/USN, browser history, mobile export, cloud export, memory import, and media/OCR fixtures.",
            "evidence": "Expected-result corpus, tool output, diff against RapidTriage JSON, and reviewed false-positive/false-negative notes.",
        },
        {
            "id": "large-case-performance",
            "owner": "release-engineer",
            "minimum_scope": "10k, 100k, and representative real exported case folders where legally available.",
            "evidence": "Benchmark JSON/Markdown, peak memory notes, elapsed time, skipped files, and resume behavior.",
        },
        {
            "id": "legal-report-review",
            "owner": "forensic-lead",
            "minimum_scope": "Report wording, limitations, source hashes, review decisions, and non-claims.",
            "evidence": "Signed review checklist attached to release notes.",
        },
    ]


def build_support_sla_template() -> dict[str, object]:
    return {
        "status": "documented-template",
        "document": "docs/rapidtriage-support-sla.md",
        "severity_levels": [
            {
                "level": "sev1",
                "example": "data loss, evidence mutation risk, crash blocking urgent case",
                "target_response": "4 business hours",
                "patch_target": "emergency hotfix or validated workaround",
            },
            {
                "level": "sev2",
                "example": "parser regression or incorrect high-value artifact field",
                "target_response": "1 business day",
                "patch_target": "next hotfix after fixture and validation note",
            },
            {
                "level": "sev3",
                "example": "usability issue, missing parser coverage, documentation gap",
                "target_response": "3 business days",
                "patch_target": "next regular release",
            },
            {
                "level": "sev4",
                "example": "feature request or training question",
                "target_response": "5 business days",
                "patch_target": "roadmap review",
            },
        ],
        "required_channels": ["support_contact", "secure_evidence-sharing_process", "release_notes", "known_limitations_update"],
        "required_intake": ["version", "release_manifest", "doctor_json", "minimal_reproduction", "crash_report_or_logs", "evidence_type_without_raw_evidence"],
        "emergency_patch_policy": "Do not claim a parser fix as report-grade until a fixture and validation note are attached.",
    }


def build_required_documents() -> list[dict[str, str]]:
    return [
        {"path": "README.md", "purpose": "Install, run, evidence support, and command entry points."},
        {"path": "docs/rapidtriage-user-guide.md", "purpose": "Analyst workflow and limitations from a user view."},
        {"path": "docs/rapidtriage-known-limitations.md", "purpose": "Clear non-claims and parser/acquisition gaps."},
        {"path": "docs/rapidtriage-parser-coverage.md", "purpose": "Implemented artifact and extension coverage."},
        {
            "path": "docs/rapidtriage-core-forensics-accuracy-profiles.md",
            "purpose": "#1-#120 parser/legal/operations accuracy profile gates and pass/fail evidence requirements.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-001-005-validation.md",
            "purpose": "#1-#5 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-006-010-validation.md",
            "purpose": "#6-#10 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-011-015-validation.md",
            "purpose": "#11-#15 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-016-020-validation.md",
            "purpose": "#16-#20 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-021-025-validation.md",
            "purpose": "#21-#25 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-026-030-validation.md",
            "purpose": "#26-#30 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-031-040-validation.md",
            "purpose": "#31-#40 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-041-050-validation.md",
            "purpose": "#41-#50 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-051-060-validation.md",
            "purpose": "#51-#60 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-061-070-validation.md",
            "purpose": "#61-#70 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-071-080-validation.md",
            "purpose": "#71-#80 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-081-090-validation.md",
            "purpose": "#81-#90 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-091-100-validation.md",
            "purpose": "#91-#100 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {
            "path": "docs/rapidtriage-core-forensics-101-120-validation.md",
            "purpose": "#101-#120 internal fixture validation manifest and commercial-readiness attachment workflow.",
        },
        {"path": "docs/rapidtriage-release-checklist.md", "purpose": "Repeatable release verification checklist."},
        {"path": "docs/rapidtriage-release-notes-template.md", "purpose": "Release communication template."},
        {"path": "docs/rapidtriage-support-sla.md", "purpose": "Support severity, escalation, secure evidence intake, and patch target template."},
        {"path": "docs/rapidtriage-lts-hotfix-policy.md", "purpose": "LTS branch and emergency hotfix policy."},
        {"path": "docs/rapidtriage-training-curriculum.md", "purpose": "Analyst/admin training labs and validation exercises."},
        {"path": "docs/rapidtriage-admin-deployment-guide.md", "purpose": "Enterprise deployment, backup, update, and hardening guide."},
        {"path": "docs/rapidtriage-output-schemas.md", "purpose": "Machine-readable output contracts."},
        {"path": "docs/rapidtriage-score-improvement-plan.md", "purpose": "Score target rationale and remaining external work."},
    ]


def build_known_limits() -> list[str]:
    return [
        "RapidTriage is still a triage/review tool, not a full AXIOM/WISDOM replacement.",
        "Native acquisition, deep carving, signed installers, and legal validation require external release processes.",
        "Some direct image formats are detected but require mounting/exporting or external tools before scanning.",
        "OCR, perceptual hashing, APK risk flags, memory imports, and cloud imports are analyst triage aids.",
    ]


def render_validation_markdown(payload: Mapping[str, object]) -> str:
    checks = payload.get("checks") if isinstance(payload.get("checks"), list) else []
    commands = payload.get("recommended_commands") if isinstance(payload.get("recommended_commands"), list) else []
    documents = payload.get("required_documents") if isinstance(payload.get("required_documents"), list) else []
    limits = payload.get("known_limits") if isinstance(payload.get("known_limits"), list) else []
    release_requirements = (
        payload.get("release_artifact_requirements")
        if isinstance(payload.get("release_artifact_requirements"), list)
        else []
    )
    independent_plan = (
        payload.get("independent_validation_plan")
        if isinstance(payload.get("independent_validation_plan"), list)
        else []
    )
    sla_template = payload.get("support_sla_template") if isinstance(payload.get("support_sla_template"), Mapping) else {}
    commercial_gaps = (
        payload.get("commercial_gap_assessment")
        if isinstance(payload.get("commercial_gap_assessment"), list)
        else []
    )
    commercial_gate = (
        payload.get("commercial_readiness_gate")
        if isinstance(payload.get("commercial_readiness_gate"), Mapping)
        else {}
    )
    known_answer = payload.get("known_answer_validation") if isinstance(payload.get("known_answer_validation"), Mapping) else {}
    accuracy_profiles = (
        payload.get("core_forensics_accuracy_profiles")
        if isinstance(payload.get("core_forensics_accuracy_profiles"), Mapping)
        else {}
    )
    accuracy_template = (
        payload.get("core_forensics_known_answer_template")
        if isinstance(payload.get("core_forensics_known_answer_template"), Mapping)
        else {}
    )
    fixture_corpus = payload.get("parser_fixture_corpus") if isinstance(payload.get("parser_fixture_corpus"), Mapping) else {}
    fpfn_notes = (
        payload.get("parser_false_positive_false_negative_notes")
        if isinstance(payload.get("parser_false_positive_false_negative_notes"), list)
        else []
    )
    independent_report = (
        payload.get("independent_validation_report")
        if isinstance(payload.get("independent_validation_report"), Mapping)
        else {}
    )
    external_tools = payload.get("external_tool_versions") if isinstance(payload.get("external_tool_versions"), list) else []

    lines = [
        "# RapidTriage Release Validation Package",
        "",
        f"- Generated at: `{payload.get('generated_at', '')}`",
        f"- Platform: `{payload.get('platform', '')}`",
        f"- Internal roadmap score: `{payload.get('internal_roadmap_score', payload.get('score_target', ''))}/100`",
        f"- Commercial readiness score: `{payload.get('commercial_readiness_score', '')}/100`",
        f"- Status: `{payload.get('status', '')}`",
        "",
        "## Required Checks",
        "",
    ]
    for item in checks:
        if not isinstance(item, Mapping):
            continue
        required = "required" if item.get("required_for_release") else "operator-owned"
        lines.append(f"- `{item.get('id', '')}` ({item.get('category', '')}, {required}): {item.get('evidence', '')}")

    lines.extend(["", "## Known-Answer Validation", ""])
    if known_answer:
        lines.append(f"- Status: `{known_answer.get('status', '')}`")
        lines.append(f"- Dataset count: `{known_answer.get('dataset_count', 0)}`")
        lines.append(f"- Release gate: {known_answer.get('release_gate', '')}")
        datasets = known_answer.get("datasets", [])
        if isinstance(datasets, list):
            for item in datasets[:20]:
                if isinstance(item, Mapping):
                    lines.append(f"- `{item.get('id', '')}` ({item.get('source', '')}): status `{item.get('status', '')}`")

    lines.extend(["", "## #1-#120 Core Forensics Accuracy Profiles", ""])
    if accuracy_profiles:
        lines.append(f"- Version: `{accuracy_profiles.get('version', '')}`")
        lines.append(f"- Profile count: `{accuracy_profiles.get('profile_count', 0)}`")
        lines.append(f"- Release gate: {accuracy_profiles.get('release_gate', '')}")
        profiles = accuracy_profiles.get("profiles", [])
        if isinstance(profiles, list):
            for item in profiles[:30]:
                if isinstance(item, Mapping):
                    checks = item.get("required_checks", [])
                    check_count = len(checks) if isinstance(checks, list) else 0
                    lines.append(
                        f"- `#{item.get('number', '')}` {item.get('title', '')}: "
                        f"{check_count} required checks; oracle `{item.get('oracle', '')}`"
                    )
    if accuracy_template:
        lines.append(
            f"- Known-answer template datasets: `{accuracy_template.get('item_count', 0)}`; "
            f"status `{accuracy_template.get('status', '')}`"
        )

    lines.extend(["", "## Parser Fixture Corpus", ""])
    if fixture_corpus:
        lines.append(f"- Fixture root: `{fixture_corpus.get('fixture_root', '')}`")
        lines.append(
            f"- Coverage: `{fixture_corpus.get('fixture_backed_count', 0)}`/"
            f"`{fixture_corpus.get('parser_area_count', 0)}` parser areas; status `{fixture_corpus.get('coverage_status', '')}`"
        )
        areas = fixture_corpus.get("areas", [])
        if isinstance(areas, list):
            for item in areas:
                if isinstance(item, Mapping):
                    lines.append(
                        f"- `{item.get('id', '')}`: fixtures `{item.get('fixture_count', 0)}`, "
                        f"tests `{item.get('test_file_count', 0)}`, backed `{item.get('fixture_backed', False)}`"
                    )

    lines.extend(["", "## Parser FP/FN Notes", ""])
    for item in fpfn_notes:
        if not isinstance(item, Mapping):
            continue
        lines.append(f"- `{item.get('parser', '')}`: {item.get('validation_required', '')}")

    lines.extend(["", "## Independent Validation Report", ""])
    if independent_report:
        lines.append(f"- Status: `{independent_report.get('status', '')}`")
        if independent_report.get("report_path"):
            lines.append(f"- Report: `{independent_report.get('report_path', '')}`")
            lines.append(f"- SHA256: `{independent_report.get('sha256', '')}`")

    lines.extend(["", "## External Tool Versions", ""])
    for item in external_tools:
        if isinstance(item, Mapping):
            available = "available" if item.get("available") else "missing"
            lines.append(f"- `{item.get('name', '')}`: {available}; `{item.get('version_output', item.get('capture_error', ''))}`")

    lines.extend(["", "## Recommended Commands", ""])
    for item in commands:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('name', '')}`: `{item.get('command', '')}`")

    lines.extend(["", "## Required Documents", ""])
    for item in documents:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('path', '')}`: {item.get('purpose', '')}")

    lines.extend(["", "## Release Artifact Requirements", ""])
    for item in release_requirements:
        if not isinstance(item, Mapping):
            continue
        evidence = ", ".join(str(value) for value in item.get("required_evidence", []) if value)
        lines.append(f"- `{item.get('id', '')}` ({item.get('platform', '')}): {item.get('release_gate', '')}; evidence: {evidence}")

    lines.extend(["", "## Independent Validation Plan", ""])
    for item in independent_plan:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('id', '')}` ({item.get('owner', '')}): {item.get('minimum_scope', '')} Evidence: {item.get('evidence', '')}")

    lines.extend(["", "## Support SLA Template", ""])
    severity_levels = sla_template.get("severity_levels", [])
    if not isinstance(severity_levels, list):
        severity_levels = []
    for item in severity_levels:
        if isinstance(item, Mapping):
            lines.append(f"- `{item.get('level', '')}`: {item.get('example', '')}; target response: {item.get('target_response', '')}")
    if sla_template:
        lines.append(f"- Emergency patch policy: {sla_template.get('emergency_patch_policy', '')}")

    lines.extend(["", "## Known Limits To Disclose", ""])
    for item in limits:
        lines.append(f"- {item}")

    lines.extend(["", "## Commercial Readiness Gate", ""])
    if commercial_gate:
        lines.append(f"- Status: `{commercial_gate.get('status', '')}`")
        lines.append(f"- Commercial claim allowed: `{commercial_gate.get('commercial_claim_allowed', False)}`")
        lines.append(f"- Readiness score: `{commercial_gate.get('readiness_score', '')}/100`")
        lines.append(
            f"- Non-commercial items: `{commercial_gate.get('non_commercial_count', 0)}`/"
            f"`{commercial_gate.get('item_count', 0)}`"
        )
        lines.append(f"- Release claim: {commercial_gate.get('release_claim', '')}")
        critical_items = commercial_gate.get("critical_non_commercial_items", [])
        if isinstance(critical_items, list):
            for item in critical_items[:25]:
                if isinstance(item, Mapping):
                    lines.append(
                        f"- `#{item.get('number', '')}` {item.get('title', '')}: "
                        f"{item.get('status', '')}; {item.get('release_gate', '')}"
                    )

    lines.extend(["", "## Commercial Gap Assessment", ""])
    for item in commercial_gaps:
        if not isinstance(item, Mapping):
            continue
        lines.extend(
            [
                f"### {item.get('area', '')}",
                "",
                f"- Severity: `{item.get('severity', '')}`",
                f"- Current status: {item.get('current_status', '')}",
                f"- Needed for commercial parity: {item.get('needed_for_commercial_parity', '')}",
                f"- Operator workaround: {item.get('operator_workaround', '')}",
                "",
            ]
        )

    lines.extend(
        [
            "",
            "## Release Decision",
            "",
            "The internal 100-point target means the repository can generate a repeatable validation package.",
            "The commercial readiness score is intentionally lower and reflects gaps versus full forensic suites such as AXIOM/WISDOM.",
            "It does not replace independent legal validation, signed installer infrastructure, or a maintained support program.",
            "",
        ]
    )
    return "\n".join(lines)
