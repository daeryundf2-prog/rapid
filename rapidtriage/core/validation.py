from __future__ import annotations

import datetime as dt
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from .audit import compute_sha256
from .commercial_readiness import build_commercial_readiness_report
from .docs import write_result
from .enterprise import build_enterprise_policy
from .forensic_accuracy import build_core_forensics_accuracy_profiles, build_core_forensics_known_answer_template


VALIDATION_JSON_NAME = "rapidtriage-validation-package.json"
VALIDATION_MARKDOWN_NAME = "rapidtriage-validation-report.md"
VALIDATION_ARTIFACTS_NAME = "rapidtriage-validation-artifacts.json"
KNOWN_ANSWER_TEST_GAP_ID = "#81"
PARSER_FIXTURE_CORPUS_GAP_ID = "#82"
PARSER_FP_FN_GAP_ID = "#83"
INDEPENDENT_VALIDATION_GAP_ID = "#84"
VALIDATION_PACKAGE_GAP_ID = "#85"
EXTERNAL_TOOL_VERSION_GAP_ID = "#95"
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
        "validation_package_assessment": build_validation_package_assessment(output_dir),
        "known_answer_validation": build_known_answer_validation(known_answer_manifest),
        "core_forensics_accuracy_profiles": build_core_forensics_accuracy_profiles(),
        "core_forensics_known_answer_template": build_core_forensics_known_answer_template(),
        "parser_fixture_corpus": build_parser_fixture_corpus(fixture_root),
        "parser_false_positive_false_negative_notes": build_parser_false_positive_false_negative_notes(),
        "independent_validation_report": build_independent_validation_report(independent_report),
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
    return payload


def build_known_answer_validation(manifest_path: Path | None = None) -> dict[str, object]:
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
            raw_backlog_items = item.get("backlog_items") or item.get("commercial_items") or item.get("item_numbers")
            if isinstance(raw_backlog_items, (str, int)):
                raw_backlog_items = [raw_backlog_items]
            if not isinstance(raw_backlog_items, list):
                raw_backlog_items = []
            evidence_paths = item.get("evidence_paths")
            if not isinstance(evidence_paths, list):
                evidence_paths = []
            normalized_paths = [str(Path(str(path)).expanduser()) for path in evidence_paths if str(path).strip()]
            datasets.append(
                {
                    "id": str(item.get("id") or f"dataset-{index + 1}"),
                    "name": str(item.get("name") or item.get("id") or f"Dataset {index + 1}"),
                    "source": str(item.get("source") or ""),
                    "corpus_family": str(item.get("corpus_family") or item.get("family") or ""),
                    "status": str(item.get("status") or "not-run"),
                    "backlog_items": [str(value).lstrip("#") for value in raw_backlog_items],
                    "expected": dict(expected),
                    "evidence_paths": normalized_paths,
                    "evidence_paths_present": all(Path(path).expanduser().exists() for path in normalized_paths),
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
    return {
        "status": manifest_status,
        "commercial_gap_ids": [KNOWN_ANSWER_TEST_GAP_ID],
        "manifest_path": str(manifest_path.expanduser().resolve()) if manifest_path else "",
        "manifest_error": manifest_error,
        "dataset_count": len(datasets),
        "status_counts": status_counts,
        "datasets": datasets,
        "recommended_public_corpora": [
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
        ],
        "release_gate": "known-answer manifest should be attached for any parser claimed report-grade",
        "ready_for_court_report": manifest_status == "all-passed",
        "blockers": [
            "known-answer-manifest-not-attached" if manifest_path is None else "review-open-known-answer-results",
            "public-corpus-coverage-must-match-claimed-parser-scope",
        ],
    }


def build_validation_package_assessment(output_dir: Path) -> dict[str, object]:
    return {
        "component": "tool-validation-package",
        "status": "json-markdown-hash-manifest-generated",
        "commercial_gap_ids": [VALIDATION_PACKAGE_GAP_ID],
        "output_dir": str(output_dir),
        "outputs": [VALIDATION_JSON_NAME, VALIDATION_MARKDOWN_NAME, VALIDATION_ARTIFACTS_NAME],
        "ready_for_court_report": False,
        "supports": [
            "known-answer-manifest-ingest",
            "parser-fixture-corpus-inventory",
            "parser-false-positive-false-negative-notes",
            "independent-report-hash-attachment",
            "validation-output-hash-manifest",
        ],
        "blockers": [
            "package-generation-does-not-prove-tests-were-run-unless-evidence-is-attached",
            "independent-lab-validation-remains-operator-owned",
            "court-admissibility-depends-on-jurisdiction-lab-policy-and-expert-testimony",
        ],
    }


def build_deployment_operations_assessment() -> dict[str, object]:
    return {
        "status": "repo-evidence-and-operator-gates-present",
        "commercial_gap_ids": DEPLOYMENT_OPERATIONS_GAP_IDS,
        "code_owned_items": ["#104", "#105", "#106", "#107", "#108", "#110", "#111", "#112", "#113", "#115", "#116", "#117", "#118", "#119", "#120"],
        "external_operator_items": ["#101", "#102", "#103", "#109", "#114"],
        "release_guidance": [
            "Attach signing/notarization/package smoke evidence before claiming native installer parity.",
            "Keep telemetry and crash reporting local-only unless a separately reviewed enterprise service is deployed.",
            "Run backup/restore, dependency monitoring, validation package, benchmark, and smoke checks for each release.",
        ],
    }


def build_parser_fixture_corpus(fixture_root: Path) -> dict[str, object]:
    fixture_root = fixture_root.expanduser().resolve()
    rows: list[dict[str, object]] = []
    for area in PARSER_FIXTURE_AREAS:
        fixture_paths: list[str] = []
        for pattern in area["fixture_globs"]:
            fixture_paths.extend(str(path.relative_to(fixture_root)) for path in sorted(fixture_root.glob(str(pattern))) if path.exists())
        test_files = [str(path) for path in area["test_files"] if (fixture_root / str(path)).exists()]
        rows.append(
            {
                "id": area["id"],
                "parser": area["parser"],
                "fixture_count": len(fixture_paths),
                "fixture_paths": fixture_paths[:25],
                "test_files": test_files,
                "test_file_count": len(test_files),
                "expected_edge_cases": list(area["expected_edge_cases"]),
                "fixture_backed": bool(fixture_paths or test_files),
                "commercial_gap_ids": [PARSER_FIXTURE_CORPUS_GAP_ID],
                "release_gate": "add at least one fixture/test before changing parser output semantics",
            }
        )
    covered = sum(1 for row in rows if row["fixture_backed"])
    return {
        "fixture_root": str(fixture_root),
        "parser_area_count": len(rows),
        "fixture_backed_count": covered,
        "coverage_status": "fixture-backed-baseline" if covered == len(rows) else "fixture-gaps-present",
        "commercial_gap_ids": [PARSER_FIXTURE_CORPUS_GAP_ID],
        "ready_for_court_report": covered == len(rows),
        "areas": rows,
    }


def build_parser_false_positive_false_negative_notes() -> list[dict[str, object]]:
    rows = []
    for item in PARSER_FALSE_POSITIVE_NOTES:
        row = dict(item)
        row["commercial_gap_ids"] = [PARSER_FP_FN_GAP_ID]
        row["ready_for_court_report"] = False
        rows.append(row)
    return rows


def build_independent_validation_report(report_path: Path | None = None) -> dict[str, object]:
    if report_path is None:
        return {
            "status": "not-attached",
            "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
            "report_path": "",
            "sha256": "",
            "required_signoffs": ["independent-reviewer", "forensic-lead", "release-owner"],
            "minimum_sections": [
                "scope and datasets",
                "tool version and commit",
                "known-answer pass/fail table",
                "false positive/false negative notes",
                "legal/report wording review",
            ],
            "ready_for_court_report": False,
        }
    resolved = report_path.expanduser().resolve()
    if not resolved.is_file():
        raise ValidationError(f"independent validation report not found: {resolved}")
    return {
        "status": "attached",
        "commercial_gap_ids": [INDEPENDENT_VALIDATION_GAP_ID],
        "report_path": str(resolved),
        "sha256": compute_sha256(resolved),
        "size_bytes": resolved.stat().st_size,
        "required_signoffs": ["independent-reviewer", "forensic-lead", "release-owner"],
        "minimum_sections": [
            "scope and datasets",
            "tool version and commit",
            "known-answer pass/fail table",
            "false positive/false negative notes",
            "legal/report wording review",
        ],
        "ready_for_court_report": True,
    }


def build_validation_artifact_manifest(output_dir: Path, paths: tuple[Path, ...]) -> dict[str, object]:
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
    return {
        "command": "validation-artifact-manifest",
        "generated_at": now_iso(),
        "output_dir": str(output_dir),
        "commercial_gap_ids": [VALIDATION_PACKAGE_GAP_ID],
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "tamper_note": "Recompute SHA256 values before release publication; this manifest covers the validation package outputs.",
    }


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
            rows.append(
                {
                    "name": name,
                    "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
                    "available": False,
                    "path": "",
                    "version_output": "",
                    "capture_error": "not-found",
                }
            )
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
            rows.append(
                {
                    "name": name,
                    "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
                    "available": True,
                    "path": path,
                    "command": " ".join(actual_command),
                    "return_code": completed.returncode,
                    "version_output": "\n".join(version_output),
                    "capture_error": "",
                }
            )
        except (OSError, subprocess.SubprocessError) as exc:
            rows.append(
                {
                    "name": name,
                    "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
                    "available": True,
                    "path": path,
                    "command": " ".join(actual_command),
                    "version_output": "",
                    "capture_error": str(exc),
                }
            )
    return rows


def build_external_tool_version_assessment() -> dict[str, object]:
    return {
        "component": "external-tool-version-capture",
        "status": "release-validation-tool-preflight",
        "commercial_gap_ids": [EXTERNAL_TOOL_VERSION_GAP_ID],
        "ready_for_court_report": False,
        "blockers": [
            "per-run-external-parser-version-capture-is-not-complete-for-every-import",
            "operator-must-preserve-original-tool-logs-for-acquisition-and-parser-validation",
        ],
    }


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
            "purpose": "#1-#30 parser accuracy profile gates and pass/fail evidence requirements.",
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

    lines.extend(["", "## #1-#30 Core Forensics Accuracy Profiles", ""])
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
