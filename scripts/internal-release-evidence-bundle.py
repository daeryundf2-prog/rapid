#!/usr/bin/env python3
"""Build internal release evidence for commercial-readiness items #116-#120.

This script intentionally does not claim commercial-grade completion. It
collects the strongest evidence we can generate in a local/macOS developer
environment and preserves the external blockers needed for a court/report-grade
release decision.
"""

from __future__ import annotations

# Force UTF-8 stdio so JSON output with non-ASCII evidence text (e.g.
# Korean filenames) survives Windows consoles whose default codec is cp1252.
import sys as _sys

if hasattr(_sys.stdout, "reconfigure"):
    _sys.stdout.reconfigure(encoding="utf-8")
if hasattr(_sys.stderr, "reconfigure"):
    _sys.stderr.reconfigure(encoding="utf-8")

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.sample_case import SampleCaseError, run_sample_workflow


PROFILE_VERSION = "internal-release-evidence-bundle-v1"
ITEM_NUMBERS = [116, 117, 118, 119, 120]
EXTERNAL_BLOCKERS = [
    "trusted-quickstart-lab-run-log",
    "trusted-admin-deployment-proof",
    "independent-appsec-review",
    "trusted-malicious-evidence-sandbox-corpus",
    "scheduled-ci-advisory-scan-and-sbom-publication",
]
DOC_PATHS = [
    "docs/rapidtriage-training-curriculum.md",
    "docs/rapidtriage-admin-deployment-guide.md",
    "docs/rapidtriage-security-policy.md",
    "docs/rapidtriage-release-checklist.md",
    "docs/rapidtriage-windows-quickstart.md",
    "docs/rapidtriage-macos-linux-quickstart.md",
]
SCRIPT_PATHS = [
    "scripts/build-release.py",
    "scripts/check-dependencies.py",
    "scripts/parser-sandbox-smoke.py",
    "scripts/security-hardening-review.py",
    "scripts/smoke-test-rapidtriage.sh",
    "scripts/windows/smoke-test-rapidtriage.ps1",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_entry(path: Path, base: Path | None = None) -> dict[str, Any]:
    base = base or REPO_ROOT
    try:
        relative = path.relative_to(base)
    except ValueError:
        relative = path
    return {
        "path": relative.as_posix(),
        "sha256": hash_file(path),
        "size": path.stat().st_size,
    }


def write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(
    argv: list[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 180,
) -> dict[str, Any]:
    started_at = utc_now()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "command": argv,
            "command_hash": stable_hash(argv),
            "started_at": started_at,
            "completed_at": utc_now(),
            "returncode": completed.returncode,
            "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest(),
            "stdout_tail": completed.stdout[-2000:],
            "stderr_tail": completed.stderr[-2000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "command": argv,
            "command_hash": stable_hash(argv),
            "started_at": started_at,
            "completed_at": utc_now(),
            "returncode": None,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            "stdout_tail": stdout[-2000:],
            "stderr_tail": stderr[-2000:],
            "timed_out": True,
        }


def clear_output_dir(output_dir: Path, overwrite: bool) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        if not overwrite:
            raise FileExistsError(f"{output_dir} is not empty; pass --overwrite to replace it")
        for child in output_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)


def build_quickstart_lab_run(output_dir: Path) -> dict[str, Any]:
    quickstart_dir = output_dir / "quickstart-lab" / "sample"
    try:
        sample_result = run_sample_workflow(
            quickstart_dir,
            mode="fraud",
            overwrite=True,
            read_only=True,
        )
        error = None
    except SampleCaseError as exc:
        sample_result = None
        error = str(exc)

    output_files: list[dict[str, Any]] = []
    training_manifest: dict[str, Any] | None = None
    training_manifest_path: Path | None = None
    expected_path: Path | None = None
    run_summary: dict[str, Any] = {}

    if sample_result is not None:
        run_payload = sample_result.get("run", {})
        training_manifest_value = run_payload.get("training_lab_manifest")
        if training_manifest_value:
            training_manifest_path = Path(training_manifest_value)
            if training_manifest_path.exists():
                training_manifest = read_json(training_manifest_path)
                output_files.append(file_entry(training_manifest_path, output_dir))
        expected_value = sample_result.get("expected")
        if expected_value:
            expected_path = Path(expected_value)
            if expected_path.exists():
                output_files.append(file_entry(expected_path, output_dir))
        for value in run_payload.get("outputs", {}).values():
            candidate = Path(value)
            if candidate.exists() and candidate.is_file():
                output_files.append(file_entry(candidate, output_dir))
        run_summary = {
            "case_dir": sample_result.get("case_dir"),
            "expected": sample_result.get("expected"),
            "run_output_count": len(run_payload.get("outputs", {})),
            "training_manifest": training_manifest_value,
        }

    checks = {
        "sample_workflow_completed": sample_result is not None,
        "training_lab_manifest_exists": training_manifest_path is not None
        and training_manifest_path.exists(),
        "expected_output_exists": expected_path is not None and expected_path.exists(),
        "run_outputs_present": bool(output_files),
        "read_only_mode": True,
    }
    payload = {
        "profile_version": "quickstart-lab-internal-run-v1",
        "item_number": 116,
        "generated_at": utc_now(),
        "commercial_claim_allowed": False,
        "internal_evidence_status": "usable-internal-validation-required",
        "checks": checks,
        "run_summary": run_summary,
        "output_files": output_files,
        "training_manifest_summary": {
            "profile_version": training_manifest.get("profile_version")
            if training_manifest
            else None,
            "commercial_claim_allowed": training_manifest.get("commercial_claim_allowed")
            if training_manifest
            else False,
            "external_blockers": training_manifest.get("external_blockers", [])
            if training_manifest
            else [],
        },
        "error": error,
        "external_blockers": ["trusted-quickstart-lab-run-log"],
    }
    payload["profile_hash"] = stable_hash(payload)
    return write_json(output_dir / "quickstart-lab-run.json", payload)


def build_admin_deployment_smoke(output_dir: Path) -> dict[str, Any]:
    doc_entries = [
        file_entry(REPO_ROOT / rel)
        for rel in DOC_PATHS
        if (REPO_ROOT / rel).exists()
    ]
    script_entries = [
        file_entry(REPO_ROOT / rel)
        for rel in SCRIPT_PATHS
        if (REPO_ROOT / rel).exists()
    ]
    help_commands = [
        [sys.executable, "-m", "rapidtriage", "--help"],
        [sys.executable, "-m", "rapidtriage", "sample", "--help"],
        [sys.executable, str(REPO_ROOT / "scripts" / "build-release.py"), "--help"],
        [sys.executable, str(REPO_ROOT / "scripts" / "check-dependencies.py"), "--help"],
    ]
    command_results = [run_command(command, timeout=60) for command in help_commands]
    admin_doc = (REPO_ROOT / "docs" / "rapidtriage-admin-deployment-guide.md").read_text(
        encoding="utf-8"
    )
    lower_doc = admin_doc.lower()
    coverage_keywords = {
        "installation": "install" in lower_doc,
        "upgrade": "update" in lower_doc or "upgrade" in lower_doc,
        "authentication": "auth" in lower_doc,
        "backup": "backup" in lower_doc,
        "logging": "log" in lower_doc,
        "security": "security" in lower_doc,
        "rollback_or_restore": "rollback" in lower_doc or "restore" in lower_doc,
    }
    checks = {
        "required_docs_present": len(doc_entries) == len(DOC_PATHS),
        "required_scripts_present": len(script_entries) == len(SCRIPT_PATHS),
        "help_commands_passed": all(
            result["returncode"] == 0 and not result["timed_out"]
            for result in command_results
        ),
        "admin_coverage_keywords_present": all(coverage_keywords.values()),
    }
    payload = {
        "profile_version": "admin-deployment-internal-smoke-v1",
        "item_number": 117,
        "generated_at": utc_now(),
        "commercial_claim_allowed": False,
        "internal_evidence_status": "usable-internal-validation-required",
        "checks": checks,
        "coverage_keywords": coverage_keywords,
        "doc_entries": doc_entries,
        "script_entries": script_entries,
        "help_command_results": command_results,
        "external_blockers": ["trusted-admin-deployment-proof"],
    }
    payload["profile_hash"] = stable_hash(payload)
    return write_json(output_dir / "admin-deployment-smoke.json", payload)


def build_synthetic_hostile_corpus(output_dir: Path) -> dict[str, Any]:
    corpus_dir = output_dir / "synthetic-hostile-corpus"
    if corpus_dir.exists():
        shutil.rmtree(corpus_dir)
    corpus_dir.mkdir(parents=True)
    (corpus_dir / "active-content.html").write_text(
        "<!doctype html><title>synthetic</title><script>alert('blocked')</script>\n",
        encoding="utf-8",
    )
    (corpus_dir / "active-vector.svg").write_text(
        "<svg xmlns='http://www.w3.org/2000/svg'><script>0</script></svg>\n",
        encoding="utf-8",
    )
    (corpus_dir / "crash-trigger.json").write_text(
        json.dumps({"synthetic": True, "parser_behavior": "must-not-crash"}) + "\n",
        encoding="utf-8",
    )
    (corpus_dir / ("long-name-" + ("a" * 80) + ".txt")).write_text(
        "long filename parser smoke\n",
        encoding="utf-8",
    )
    (corpus_dir / "benign.txt").write_text("benign control\n", encoding="utf-8")
    archive_path = corpus_dir / "zip-slip-candidate.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../escape.txt", "synthetic path traversal candidate\n")
        archive.writestr("safe/nested.txt", "safe nested member\n")

    files = sorted(path for path in corpus_dir.rglob("*") if path.is_file())
    entries = [file_entry(path, output_dir) for path in files]
    zip_entries = []
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            zip_entries.append(
                {
                    "name": info.filename,
                    "file_size": info.file_size,
                    "compress_size": info.compress_size,
                    "path_traversal_candidate": ".." in Path(info.filename).parts,
                }
            )
    expected_behaviors = [
        "preview-renderers-must-not-execute-active-content",
        "archive-handlers-must-block-path-traversal-on-extract",
        "parser-subprocesses-must-isolate-crash-or-timeout",
        "evidence-outputs-must-record-hashes-and-limitations",
    ]
    payload = {
        "profile_version": "synthetic-hostile-corpus-v1",
        "item_number": 119,
        "generated_at": utc_now(),
        "commercial_claim_allowed": False,
        "internal_evidence_status": "usable-internal-validation-required",
        "corpus_dir": corpus_dir.as_posix(),
        "corpus_files": entries,
        "zip_entries": zip_entries,
        "expected_behaviors": expected_behaviors,
        "active_content_file_count": 2,
        "unsafe_archive_entry_count": sum(
            1 for entry in zip_entries if entry["path_traversal_candidate"]
        ),
        "external_blockers": ["trusted-malicious-evidence-sandbox-corpus"],
    }
    payload["corpus_hash"] = stable_hash(
        {
            "entries": entries,
            "zip_entries": zip_entries,
            "expected_behaviors": expected_behaviors,
        }
    )
    payload["profile_hash"] = stable_hash(payload)
    return write_json(output_dir / "synthetic-hostile-corpus-manifest.json", payload)


def run_json_evidence_script(
    output_dir: Path,
    *,
    script_name: str,
    output_name: str,
    item_number: int,
) -> dict[str, Any]:
    output_path = output_dir / output_name
    command = [
        sys.executable,
        str(REPO_ROOT / "scripts" / script_name),
        "--output",
        str(output_path),
    ]
    command_result = run_command(command, timeout=240)
    payload: dict[str, Any] = {}
    if output_path.exists():
        try:
            payload = read_json(output_path)
        except json.JSONDecodeError as exc:
            payload = {"json_error": str(exc)}
    summary = {
        "profile_version": "internal-evidence-script-run-v1",
        "item_number": item_number,
        "script": script_name,
        "output": output_name,
        "generated_at": utc_now(),
        "commercial_claim_allowed": False,
        "command_result": command_result,
        "output_file": file_entry(output_path, output_dir) if output_path.exists() else None,
        "output_profile_version": payload.get("profile_version"),
        "output_commercial_claim_allowed": payload.get("commercial_claim_allowed", False),
        "output_failed_check_ids": payload.get("failed_check_ids", []),
        "output_required_external_evidence": payload.get("required_external_evidence", []),
    }
    summary["profile_hash"] = stable_hash(summary)
    return summary


def build_dependency_release_linkage(
    output_dir: Path,
    *,
    dependency_run: dict[str, Any],
    component_files: list[Path],
) -> dict[str, Any]:
    workflow_path = REPO_ROOT / ".github" / "workflows" / "dependency-monitoring.yml"
    checksum_entries = [
        file_entry(path, output_dir)
        for path in sorted(component_files)
        if path.exists() and path.is_file()
    ]
    sbom_path = output_dir / "dependency-monitoring.json"
    sbom_hash = hash_file(sbom_path) if sbom_path.exists() else None
    checks = {
        "dependency_monitoring_script_ran": dependency_run["command_result"]["returncode"] == 0,
        "dependency_monitoring_json_exists": sbom_path.exists(),
        "ci_workflow_present": workflow_path.exists(),
        "component_checksums_present": bool(checksum_entries),
        "release_artifact_checksum_linkage_ready": True,
    }
    payload = {
        "profile_version": "dependency-release-linkage-v1",
        "item_number": 120,
        "generated_at": utc_now(),
        "commercial_claim_allowed": False,
        "internal_evidence_status": "usable-internal-validation-required",
        "checks": checks,
        "dependency_monitoring_output": file_entry(sbom_path, output_dir)
        if sbom_path.exists()
        else None,
        "dependency_monitoring_output_sha256": sbom_hash,
        "dependency_script": file_entry(REPO_ROOT / "scripts" / "check-dependencies.py"),
        "dependency_ci_workflow": file_entry(workflow_path) if workflow_path.exists() else None,
        "component_checksums": checksum_entries,
        "dependency_run_summary": dependency_run,
        "external_blockers": ["scheduled-ci-advisory-scan-and-sbom-publication"],
    }
    payload["profile_hash"] = stable_hash(payload)
    return write_json(output_dir / "dependency-release-linkage.json", payload)


def write_sha256sums(output_dir: Path) -> Path:
    checksum_path = output_dir / "SHA256SUMS"
    files = sorted(
        path
        for path in output_dir.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and path.name != "internal-release-evidence-bundle.json"
    )
    lines = []
    for path in files:
        relative = path.relative_to(output_dir).as_posix()
        lines.append(f"{hash_file(path)}  {relative}")
    checksum_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return checksum_path


def build_internal_evidence_bundle(
    output_dir: Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    clear_output_dir(output_dir, overwrite)
    quickstart = build_quickstart_lab_run(output_dir)
    admin = build_admin_deployment_smoke(output_dir)
    synthetic_corpus = build_synthetic_hostile_corpus(output_dir)
    parser_sandbox_run = run_json_evidence_script(
        output_dir,
        script_name="parser-sandbox-smoke.py",
        output_name="parser-sandbox-smoke.json",
        item_number=119,
    )
    security_run = run_json_evidence_script(
        output_dir,
        script_name="security-hardening-review.py",
        output_name="security-hardening-review.json",
        item_number=118,
    )
    dependency_run = run_json_evidence_script(
        output_dir,
        script_name="check-dependencies.py",
        output_name="dependency-monitoring.json",
        item_number=120,
    )
    component_files = [
        output_dir / "quickstart-lab-run.json",
        output_dir / "admin-deployment-smoke.json",
        output_dir / "synthetic-hostile-corpus-manifest.json",
        output_dir / "parser-sandbox-smoke.json",
        output_dir / "security-hardening-review.json",
        output_dir / "dependency-monitoring.json",
    ]
    dependency_linkage = build_dependency_release_linkage(
        output_dir,
        dependency_run=dependency_run,
        component_files=component_files,
    )
    sha256sums_path = write_sha256sums(output_dir)
    generated_files = [
        file_entry(path, output_dir)
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path.name != "internal-release-evidence-bundle.json"
    ]
    component_checks = {
        "quickstart_lab_internal_checks_passed": all(quickstart["checks"].values()),
        "admin_deployment_internal_checks_passed": all(admin["checks"].values()),
        "synthetic_hostile_corpus_built": bool(synthetic_corpus["corpus_files"]),
        "parser_sandbox_smoke_passed": parser_sandbox_run["command_result"]["returncode"] == 0,
        "security_hardening_review_passed": security_run["command_result"]["returncode"] == 0,
        "dependency_monitoring_passed": dependency_run["command_result"]["returncode"] == 0,
        "dependency_release_linkage_ready": all(dependency_linkage["checks"].values()),
        "sha256sums_written": sha256sums_path.exists(),
    }
    manifest = {
        "profile_version": PROFILE_VERSION,
        "item_numbers": ITEM_NUMBERS,
        "generated_at": utc_now(),
        "repository_root": REPO_ROOT.as_posix(),
        "commercial_claim_allowed": False,
        "final_status": "usable-internal-validation-required",
        "component_checks": component_checks,
        "all_internal_checks_passed": all(component_checks.values()),
        "components": {
            "quickstart_lab": {
                "output": "quickstart-lab-run.json",
                "profile_hash": quickstart["profile_hash"],
            },
            "admin_deployment": {
                "output": "admin-deployment-smoke.json",
                "profile_hash": admin["profile_hash"],
            },
            "security_hardening": {
                "output": "security-hardening-review.json",
                "run_profile_hash": security_run["profile_hash"],
            },
            "malicious_evidence_sandbox": {
                "corpus_manifest": "synthetic-hostile-corpus-manifest.json",
                "parser_sandbox_output": "parser-sandbox-smoke.json",
                "corpus_hash": synthetic_corpus["corpus_hash"],
                "parser_run_profile_hash": parser_sandbox_run["profile_hash"],
            },
            "dependency_monitoring": {
                "output": "dependency-monitoring.json",
                "linkage_output": "dependency-release-linkage.json",
                "run_profile_hash": dependency_run["profile_hash"],
                "linkage_profile_hash": dependency_linkage["profile_hash"],
            },
        },
        "generated_files": generated_files,
        "external_blockers": EXTERNAL_BLOCKERS,
        "claim_guard": (
            "This bundle is internal evidence only. Commercial-grade claims still "
            "require the listed trusted external artifacts."
        ),
    }
    manifest["bundle_hash"] = stable_hash(manifest)
    return write_json(output_dir / "internal-release-evidence-bundle.json", manifest)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate internal release evidence for #116-#120 while preserving "
            "external commercial-readiness blockers."
        )
    )
    parser.add_argument(
        "--output-dir",
        default="internal-release-evidence-bundle",
        help="Directory where evidence artifacts will be written.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing non-empty output directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    try:
        manifest = build_internal_evidence_bundle(output_dir, overwrite=args.overwrite)
    except Exception as exc:  # pragma: no cover - CLI guard
        print(f"internal evidence bundle failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "output": (output_dir / "internal-release-evidence-bundle.json").as_posix(),
                "all_internal_checks_passed": manifest["all_internal_checks_passed"],
                "commercial_claim_allowed": manifest["commercial_claim_allowed"],
                "external_blockers": manifest["external_blockers"],
                "bundle_hash": manifest["bundle_hash"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if manifest["all_internal_checks_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
