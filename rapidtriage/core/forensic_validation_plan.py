from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping

from .commercial_readiness import build_commercial_readiness_report, parse_item_range
from .docs import write_result
from .forensic_accuracy import accuracy_profile_for_item


FORENSIC_VALIDATION_PLAN_VERSION = "forensic-validation-plan-v1"
FORENSIC_VALIDATION_PACK_VERSION = "forensic-validation-pack-v1"
FORENSIC_VALIDATION_BATCHES_VERSION = "forensic-validation-batches-v1"
DEFAULT_FORENSIC_VALIDATION_ITEMS = "1-120"
DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS = "1-5"


def build_forensic_validation_plan(
    *,
    item_range: str = DEFAULT_FORENSIC_VALIDATION_ITEMS,
    output_dir: Path | None = None,
) -> dict[str, object]:
    numbers = parse_item_range(item_range)
    if not numbers:
        raise ValueError("forensic validation plan item range is empty")
    readiness = build_commercial_readiness_report(output_dir=output_dir)
    readiness_by_number = {
        int(item.get("number") or 0): item
        for item in readiness.get("all_items", [])
        if isinstance(item, Mapping)
    }
    rows = [build_forensic_validation_plan_row(number, readiness_by_number.get(number, {})) for number in numbers]
    summary = summarize_forensic_validation_plan(rows)
    plan_core: dict[str, object] = {
        "command": "forensic-validation-plan",
        "profile_version": FORENSIC_VALIDATION_PLAN_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "item_range": item_range,
        "item_numbers": numbers,
        "item_count": len(rows),
        "summary": summary,
        "sequencing": build_forensic_validation_sequence(rows),
        "rows": rows,
        "commercial_claim_allowed": False,
        "rule": "Items remain non-commercial until required validation, trusted diffs, and remaining blockers are closed.",
    }
    return {**plan_core, "plan_hash": stable_plan_hash(plan_core)}


def build_forensic_validation_pack(
    *,
    item_range: str = DEFAULT_FORENSIC_VALIDATION_PACK_ITEMS,
    output_dir: Path | None = None,
) -> dict[str, object]:
    """Build an executable evidence pack for a focused validation batch.

    The plan command says what remains. The pack command turns a small item
    range into concrete files an examiner can populate and rerun through
    trusted-diff validation without changing the contract by hand.
    """

    plan = build_forensic_validation_plan(item_range=item_range, output_dir=output_dir)
    rows = [row for row in plan.get("rows", []) if isinstance(row, Mapping)]
    if not rows:
        raise ValueError("forensic validation pack item range is empty")
    pack_core: dict[str, object] = {
        "command": "forensic-validation-pack",
        "profile_version": FORENSIC_VALIDATION_PACK_VERSION,
        "plan_profile_version": plan.get("profile_version"),
        "generated_at": plan.get("generated_at"),
        "item_range": item_range,
        "item_numbers": [int(row.get("number") or 0) for row in rows],
        "item_count": len(rows),
        "summary": build_forensic_validation_pack_summary(rows),
        "datasets": [build_validation_dataset_template(row) for row in rows],
        "reference_commands": [build_reference_command_template(row) for row in rows],
        "diff_contract": build_diff_contract(rows),
        "commercial_claim_allowed": False,
        "rule": (
            "This pack is an execution scaffold. Commercial-grade status requires populated "
            "source/reference/diff evidence, passing checks, and a rerun commercial-readiness report."
        ),
    }
    return {**pack_core, "pack_hash": stable_plan_hash(pack_core)}


def assess_forensic_validation_pack(pack_path: Path, *, output: Path | None = None) -> dict[str, object]:
    pack_path = pack_path.expanduser().resolve()
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    datasets = [item for item in pack.get("datasets", []) if isinstance(item, Mapping)]
    results = [assess_validation_dataset(item) for item in datasets]
    ready_for_validated_gate = bool(results) and all(bool(item.get("ready_for_validated_gate")) for item in results)
    ready_for_commercial_grade = bool(results) and all(bool(item.get("ready_for_commercial_grade")) for item in results)
    external_ready_count = sum(1 for item in results if item.get("ready_for_external_validated_gate"))
    assessment_core: dict[str, object] = {
        "command": "forensic-validation-pack-assess",
        "profile_version": "forensic-validation-pack-assessment-v1",
        "pack_path": str(pack_path),
        "pack_hash": file_sha256(pack_path),
        "source_pack_hash": str(pack.get("pack_hash") or ""),
        "item_numbers": [int(item.get("item_number") or 0) for item in datasets],
        "dataset_count": len(results),
        "ready_dataset_count": sum(1 for item in results if item.get("ready_for_validated_gate")),
        "external_ready_dataset_count": external_ready_count,
        "commercial_ready_dataset_count": sum(1 for item in results if item.get("ready_for_commercial_grade")),
        "ready_for_validated_gate": ready_for_validated_gate,
        "ready_for_external_validated_gate": bool(results) and external_ready_count == len(results),
        "ready_for_commercial_grade": ready_for_commercial_grade,
        "dataset_results": results,
        "remaining_blockers": sorted(
            {
                blocker
                for item in results
                for blocker in item.get("blockers", [])
                if str(blocker)
            }
        ),
        "commercial_claim_allowed": ready_for_commercial_grade,
    }
    assessment = {**assessment_core, "assessment_hash": stable_plan_hash(assessment_core)}
    if output is not None:
        write_result(assessment, output.expanduser().resolve())
    return assessment


def write_forensic_validation_batches(
    *,
    item_range: str = DEFAULT_FORENSIC_VALIDATION_ITEMS,
    output_dir: Path,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    plan = build_forensic_validation_plan(item_range=item_range, output_dir=output_dir)
    plan_outputs = write_forensic_validation_plan(plan, output_dir / "plan")
    batch_outputs: list[dict[str, object]] = []
    for batch in plan.get("sequencing", []) if isinstance(plan.get("sequencing"), list) else []:
        if not isinstance(batch, Mapping):
            continue
        item_numbers = [int(number) for number in batch.get("item_numbers", []) if int(number)]
        if not item_numbers:
            continue
        batch_dir_name = f"batch-{int(batch.get('batch_number') or len(batch_outputs) + 1):03d}-items-{item_numbers[0]:03d}-{item_numbers[-1]:03d}"
        batch_dir = output_dir / batch_dir_name
        pack = build_forensic_validation_pack(item_range=",".join(str(number) for number in item_numbers), output_dir=batch_dir)
        pack_outputs = write_forensic_validation_pack(pack, batch_dir)
        batch_outputs.append(
            {
                "batch_number": int(batch.get("batch_number") or len(batch_outputs) + 1),
                "item_numbers": item_numbers,
                "batch_dir": str(batch_dir),
                "pack_hash": pack.get("pack_hash"),
                "outputs": pack_outputs,
                "goal": str(batch.get("goal") or ""),
            }
        )
    index_core: dict[str, object] = {
        "command": "forensic-validation-batches",
        "profile_version": FORENSIC_VALIDATION_BATCHES_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "item_range": item_range,
        "item_numbers": plan.get("item_numbers", []),
        "item_count": plan.get("item_count", 0),
        "batch_count": len(batch_outputs),
        "plan_hash": plan.get("plan_hash"),
        "plan_outputs": plan_outputs,
        "batch_outputs": batch_outputs,
        "commercial_claim_allowed": False,
        "rule": "Batch generation is not validation; populate each pack and run forensic-validation-batches-assess.",
    }
    index = {**index_core, "batch_index_hash": stable_plan_hash(index_core)}
    write_result(index, output_dir / "rapidtriage-forensic-validation-batches.json")
    (output_dir / "rapidtriage-forensic-validation-batches.md").write_text(
        render_forensic_validation_batches_markdown(index),
        encoding="utf-8",
    )
    index["outputs"] = {
        "json": str(output_dir / "rapidtriage-forensic-validation-batches.json"),
        "markdown": str(output_dir / "rapidtriage-forensic-validation-batches.md"),
    }
    return index


def assess_forensic_validation_batches(root_dir: Path, *, output: Path | None = None) -> dict[str, object]:
    root_dir = root_dir.expanduser().resolve()
    pack_paths = sorted(root_dir.glob("batch-*/rapidtriage-forensic-validation-pack.json"))
    assessments = [
        assess_forensic_validation_pack(path, output=path.parent / "assessment.json")
        for path in pack_paths
    ]
    dataset_count = sum(int(item.get("dataset_count") or 0) for item in assessments)
    ready_dataset_count = sum(int(item.get("ready_dataset_count") or 0) for item in assessments)
    external_ready_dataset_count = sum(int(item.get("external_ready_dataset_count") or 0) for item in assessments)
    commercial_ready_dataset_count = sum(int(item.get("commercial_ready_dataset_count") or 0) for item in assessments)
    assessment_core: dict[str, object] = {
        "command": "forensic-validation-batches-assess",
        "profile_version": "forensic-validation-batches-assessment-v1",
        "root_dir": str(root_dir),
        "batch_count": len(assessments),
        "dataset_count": dataset_count,
        "ready_dataset_count": ready_dataset_count,
        "external_ready_dataset_count": external_ready_dataset_count,
        "commercial_ready_dataset_count": commercial_ready_dataset_count,
        "ready_for_validated_gate": bool(assessments) and ready_dataset_count == dataset_count,
        "ready_for_external_validated_gate": bool(assessments) and external_ready_dataset_count == dataset_count,
        "ready_for_commercial_grade": bool(assessments) and commercial_ready_dataset_count == dataset_count,
        "batch_assessments": [
            {
                "pack_path": item.get("pack_path"),
                "item_numbers": item.get("item_numbers", []),
                "dataset_count": item.get("dataset_count", 0),
                "ready_dataset_count": item.get("ready_dataset_count", 0),
                "external_ready_dataset_count": item.get("external_ready_dataset_count", 0),
                "commercial_ready_dataset_count": item.get("commercial_ready_dataset_count", 0),
                "remaining_blockers": item.get("remaining_blockers", []),
                "assessment_hash": item.get("assessment_hash", ""),
            }
            for item in assessments
        ],
        "remaining_blockers": sorted(
            {
                blocker
                for item in assessments
                for blocker in item.get("remaining_blockers", [])
                if str(blocker)
            }
        ),
        "commercial_claim_allowed": bool(assessments) and commercial_ready_dataset_count == dataset_count,
    }
    assessment = {**assessment_core, "assessment_hash": stable_plan_hash(assessment_core)}
    if output is not None:
        write_result(assessment, output.expanduser().resolve())
    return assessment


def populate_forensic_validation_smoke_fixtures(root_dir: Path, *, output: Path | None = None) -> dict[str, object]:
    """Populate validation packs with deterministic internal smoke evidence.

    This proves that all generated pack contracts can be populated and
    assessed end-to-end. It intentionally does not create commercial-grade
    evidence because the source/reference rows are synthetic fixtures.
    """

    root_dir = root_dir.expanduser().resolve()
    pack_paths = sorted(root_dir.glob("batch-*/rapidtriage-forensic-validation-pack.json"))
    populated: list[dict[str, object]] = []
    for pack_path in pack_paths:
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
        datasets = [item for item in pack.get("datasets", []) if isinstance(item, Mapping)]
        updated_datasets: list[dict[str, object]] = []
        for dataset in datasets:
            updated = dict(dataset)
            fixture_info = write_smoke_fixture_for_dataset(pack_path.parent, updated)
            updated["status"] = "internal-smoke-populated"
            updated["evidence_paths"] = fixture_info["evidence_paths"]
            updated["hash_requirements"] = fixture_info["hash_requirements"]
            updated["smoke_fixture_notice"] = {
                "kind": "internal-smoke-fixture",
                "commercial_claim_allowed": False,
                "warning": "Synthetic fixture evidence proves validation plumbing only, not parser correctness on external corpora.",
            }
            updated_datasets.append(updated)
            populated.append(
                {
                    "dataset_id": updated.get("dataset_id"),
                    "item_number": updated.get("item_number"),
                    "fixture_dir": fixture_info["fixture_dir"],
                    "diff_output": fixture_info["evidence_paths"]["row_level_diff_output"],
                }
            )
        pack["datasets"] = updated_datasets
        pack["commercial_claim_allowed"] = False
        pack["smoke_fixture_populated"] = True
        pack["pack_hash"] = stable_plan_hash({key: value for key, value in pack.items() if key != "pack_hash"})
        write_result(pack, pack_path)
    assessment = assess_forensic_validation_batches(root_dir, output=root_dir / "smoke-assessment.json")
    result_core = {
        "command": "forensic-validation-smoke-populate",
        "profile_version": "forensic-validation-smoke-populate-v1",
        "root_dir": str(root_dir),
        "pack_count": len(pack_paths),
        "populated_dataset_count": len(populated),
        "populated_datasets": populated,
        "assessment": assessment,
        "commercial_claim_allowed": False,
        "rule": "Internal smoke fixtures complete plumbing validation only; attach real corpora and trusted tools for report-grade validation.",
    }
    result = {**result_core, "smoke_manifest_hash": stable_plan_hash(result_core)}
    if output is not None:
        write_result(result, output.expanduser().resolve())
    return result


def import_forensic_validation_evidence_manifest(
    root_dir: Path,
    manifest_path: Path,
    *,
    output: Path | None = None,
) -> dict[str, object]:
    """Apply real external evidence paths to generated validation packs."""

    root_dir = root_dir.expanduser().resolve()
    manifest_path = manifest_path.expanduser().resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_datasets = manifest.get("datasets") if isinstance(manifest.get("datasets"), list) else []
    by_dataset_id: dict[str, Mapping[str, object]] = {}
    by_item_number: dict[int, Mapping[str, object]] = {}
    for record in manifest_datasets:
        if not isinstance(record, Mapping):
            continue
        dataset_id = str(record.get("dataset_id") or "")
        if dataset_id:
            by_dataset_id[dataset_id] = record
        item_number = int(record.get("item_number") or 0)
        if item_number:
            by_item_number[item_number] = record

    imported: list[dict[str, object]] = []
    missing: list[dict[str, object]] = []
    for pack_path in sorted(root_dir.glob("batch-*/rapidtriage-forensic-validation-pack.json")):
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
        updated_datasets: list[dict[str, object]] = []
        for dataset in [item for item in pack.get("datasets", []) if isinstance(item, Mapping)]:
            updated = dict(dataset)
            dataset_id = str(updated.get("dataset_id") or "")
            item_number = int(updated.get("item_number") or 0)
            record = by_dataset_id.get(dataset_id) or by_item_number.get(item_number)
            if record is None:
                missing.append({"dataset_id": dataset_id, "item_number": item_number})
                updated_datasets.append(updated)
                continue
            evidence_paths = normalized_manifest_evidence_paths(record, base_dir=manifest_path.parent)
            updated["status"] = "external-evidence-populated"
            updated["evidence_paths"] = evidence_paths
            updated["hash_requirements"] = normalized_manifest_hash_requirements(record, evidence_paths)
            updated.pop("smoke_fixture_notice", None)
            updated["external_evidence_notice"] = {
                "kind": "external-validation-evidence",
                "manifest_path": str(manifest_path),
                "commercial_claim_allowed": False,
                "warning": "External evidence can satisfy external validation only when row-level diff and sign-off are present; commercial-grade still requires commercial readiness gates.",
            }
            updated_datasets.append(updated)
            imported.append({"dataset_id": dataset_id, "item_number": item_number})
        pack["datasets"] = updated_datasets
        pack["smoke_fixture_populated"] = False
        pack["commercial_claim_allowed"] = False
        pack["pack_hash"] = stable_plan_hash({key: value for key, value in pack.items() if key != "pack_hash"})
        write_result(pack, pack_path)

    assessment = assess_forensic_validation_batches(root_dir, output=root_dir / "external-evidence-assessment.json")
    result_core = {
        "command": "forensic-validation-evidence-import",
        "profile_version": "forensic-validation-evidence-import-v1",
        "root_dir": str(root_dir),
        "manifest_path": str(manifest_path),
        "manifest_sha256": file_sha256(manifest_path),
        "imported_dataset_count": len(imported),
        "missing_dataset_count": len(missing),
        "imported_datasets": imported,
        "missing_datasets": missing,
        "assessment": assessment,
        "commercial_claim_allowed": bool(assessment.get("ready_for_commercial_grade")),
    }
    result = {**result_core, "import_manifest_hash": stable_plan_hash(result_core)}
    if output is not None:
        write_result(result, output.expanduser().resolve())
    return result


def normalized_manifest_evidence_paths(record: Mapping[str, object], *, base_dir: Path | None = None) -> dict[str, str]:
    source = record.get("evidence_paths") if isinstance(record.get("evidence_paths"), Mapping) else record
    return {
        "source_evidence": normalize_manifest_evidence_path(source.get("source_evidence"), base_dir=base_dir),
        "rapid_output": normalize_manifest_evidence_path(source.get("rapid_output"), base_dir=base_dir),
        "trusted_reference_output": normalize_manifest_evidence_path(source.get("trusted_reference_output"), base_dir=base_dir),
        "row_level_diff_output": normalize_manifest_evidence_path(source.get("row_level_diff_output"), base_dir=base_dir),
        "reviewer_signoff": normalize_manifest_evidence_path(source.get("reviewer_signoff"), base_dir=base_dir),
    }


def normalize_manifest_evidence_path(value: object, *, base_dir: Path | None = None) -> str:
    path_text = str(value or "").strip()
    if not path_text:
        return ""
    path = Path(path_text).expanduser()
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    return str(path.resolve())


def normalized_manifest_hash_requirements(
    record: Mapping[str, object],
    evidence_paths: Mapping[str, str],
) -> dict[str, str]:
    raw = record.get("hash_requirements") if isinstance(record.get("hash_requirements"), Mapping) else {}
    requirements = {str(key): str(value) for key, value in raw.items() if str(value)}
    for name, path_text in evidence_paths.items():
        key = f"{name}_sha256"
        if key in requirements:
            continue
        path = Path(path_text).expanduser()
        requirements[key] = file_sha256(path) if path.is_file() else ""
    return requirements


def write_smoke_fixture_for_dataset(batch_dir: Path, dataset: Mapping[str, object]) -> dict[str, object]:
    dataset_id = str(dataset.get("dataset_id") or "dataset")
    item_number = int(dataset.get("item_number") or 0)
    fixture_dir = batch_dir / "smoke-fixtures" / dataset_id
    fixture_dir.mkdir(parents=True, exist_ok=True)
    source_path = fixture_dir / "source-evidence.bin"
    rapid_path = fixture_dir / "rapid-output.json"
    reference_path = fixture_dir / "trusted-reference.csv"
    diff_path = fixture_dir / "row-level-diff.json"
    signoff_path = fixture_dir / "reviewer-signoff.md"
    source_path.write_bytes(f"RapidTriage smoke source for item {item_number}: {dataset.get('title')}\n".encode("utf-8"))
    rapid_path.write_text(
        json.dumps(build_smoke_rapid_output(dataset), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    reference_path.write_text(build_smoke_reference_csv(dataset), encoding="utf-8")
    diff_path.write_text(
        json.dumps(build_smoke_diff_output(dataset), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    signoff_path.write_text(
        (
            f"# Internal smoke sign-off for {dataset_id}\n\n"
            "This synthetic fixture verifies validation-pack plumbing only. "
            "It must not be cited as external forensic parser validation.\n"
        ),
        encoding="utf-8",
    )
    evidence_paths = {
        "source_evidence": str(source_path),
        "rapid_output": str(rapid_path),
        "trusted_reference_output": str(reference_path),
        "row_level_diff_output": str(diff_path),
        "reviewer_signoff": str(signoff_path),
    }
    return {
        "fixture_dir": str(fixture_dir),
        "evidence_paths": evidence_paths,
        "hash_requirements": {
            f"{name}_sha256": file_sha256(Path(path))
            for name, path in evidence_paths.items()
        },
    }


def assess_validation_dataset(dataset: Mapping[str, object]) -> dict[str, object]:
    evidence_paths = dataset.get("evidence_paths") if isinstance(dataset.get("evidence_paths"), Mapping) else {}
    hash_requirements = dataset.get("hash_requirements") if isinstance(dataset.get("hash_requirements"), Mapping) else {}
    evidence_results = {
        name: assess_evidence_path(str(path or ""), expected_hash_for_evidence(name, hash_requirements))
        for name, path in evidence_paths.items()
    }
    diff_result = assess_row_level_diff_output(str(evidence_paths.get("row_level_diff_output") or ""))
    required_names = ("source_evidence", "rapid_output", "trusted_reference_output", "row_level_diff_output", "reviewer_signoff")
    missing_required = [
        name
        for name in required_names
        if not evidence_results.get(name, {}).get("present")
    ]
    hash_mismatches = [
        name
        for name, result in evidence_results.items()
        if result.get("expected_sha256") and not result.get("sha256_matches")
    ]
    blockers = []
    if missing_required:
        blockers.append("required-evidence-path-missing")
    if hash_mismatches:
        blockers.append("evidence-hash-mismatch")
    if not diff_result.get("ready_for_validated_gate"):
        blockers.append("row-level-diff-not-ready")
    if not diff_result.get("ready_for_commercial_grade"):
        blockers.append("commercial-grade-diff-evidence-incomplete")
    ready_for_validated_gate = not missing_required and not hash_mismatches and bool(diff_result.get("ready_for_validated_gate"))
    internal_smoke_fixture = bool(is_internal_smoke_dataset(dataset) or diff_result.get("internal_smoke_fixture"))
    ready_for_external_validated_gate = ready_for_validated_gate and not internal_smoke_fixture
    ready_for_commercial_grade = ready_for_validated_gate and bool(diff_result.get("ready_for_commercial_grade"))
    result_core = {
        "dataset_id": str(dataset.get("dataset_id") or ""),
        "item_number": int(dataset.get("item_number") or 0),
        "title": str(dataset.get("title") or ""),
        "internal_smoke_fixture": internal_smoke_fixture,
        "evidence_results": evidence_results,
        "missing_required_evidence": missing_required,
        "hash_mismatches": hash_mismatches,
        "row_level_diff_assessment": diff_result,
        "ready_for_validated_gate": ready_for_validated_gate,
        "ready_for_external_validated_gate": ready_for_external_validated_gate,
        "ready_for_commercial_grade": ready_for_commercial_grade,
        "blockers": blockers,
        "external_validation_blockers": ["internal-smoke-fixture-not-external-validation"] if internal_smoke_fixture else [],
    }
    return {**result_core, "dataset_assessment_hash": stable_plan_hash(result_core)}


def is_internal_smoke_dataset(dataset: Mapping[str, object]) -> bool:
    notice = dataset.get("smoke_fixture_notice")
    if isinstance(notice, Mapping) and str(notice.get("kind") or "") == "internal-smoke-fixture":
        return True
    if str(dataset.get("status") or "") == "internal-smoke-populated":
        return True
    return False


def expected_hash_for_evidence(name: str, hash_requirements: Mapping[str, object]) -> str:
    direct = str(hash_requirements.get(f"{name}_sha256") or "")
    if direct:
        return direct
    legacy_aliases = {
        "source_evidence": "source_sha256",
        "rapid_output": "rapid_output_sha256",
        "trusted_reference_output": "trusted_reference_sha256",
        "row_level_diff_output": "diff_output_sha256",
        "reviewer_signoff": "reviewer_signoff_sha256",
    }
    return str(hash_requirements.get(legacy_aliases.get(name, "")) or "")


def assess_evidence_path(path_text: str, expected_sha256: str = "") -> dict[str, object]:
    if not path_text.strip():
        return {"path": "", "present": False, "sha256": "", "expected_sha256": expected_sha256, "sha256_matches": False}
    path = Path(path_text).expanduser().resolve()
    present = path.is_file()
    actual = file_sha256(path) if present else ""
    return {
        "path": str(path),
        "present": present,
        "size_bytes": path.stat().st_size if present else 0,
        "sha256": actual,
        "expected_sha256": expected_sha256,
        "sha256_matches": bool(actual and expected_sha256 and actual.lower() == expected_sha256.lower())
        if expected_sha256
        else True,
    }


def assess_row_level_diff_output(path_text: str) -> dict[str, object]:
    if not path_text.strip():
        return {"path": "", "present": False, "status": "missing", "ready_for_validated_gate": False, "ready_for_commercial_grade": False}
    path = Path(path_text).expanduser().resolve()
    if not path.is_file():
        return {
            "path": str(path),
            "present": False,
            "status": "missing",
            "ready_for_validated_gate": False,
            "ready_for_commercial_grade": False,
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "path": str(path),
            "present": True,
            "status": "invalid-json",
            "error": str(exc),
            "ready_for_validated_gate": False,
            "ready_for_commercial_grade": False,
        }
    assessment = payload.get("cross_tool_validation_assessment") if isinstance(payload.get("cross_tool_validation_assessment"), Mapping) else {}
    comparison_health = summarize_diff_comparison_health(payload.get("comparisons", []))
    diff_status_passed = str(payload.get("status") or "") == "pass"
    diff_has_comparisons = int(comparison_health.get("comparison_count") or 0) > 0
    diff_health_clean = bool(comparison_health.get("clean")) and diff_has_comparisons
    validated_ready = bool(assessment.get("ready_for_validated_gate")) and diff_status_passed and diff_health_clean
    commercial_ready = bool(assessment.get("ready_for_commercial_grade")) and diff_status_passed and diff_health_clean
    return {
        "path": str(path),
        "present": True,
        "status": str(payload.get("status") or ""),
        "fixture_kind": str(payload.get("fixture_kind") or ""),
        "internal_smoke_fixture": str(payload.get("fixture_kind") or "") == "internal-smoke",
        "ready_for_validated_gate": validated_ready,
        "ready_for_commercial_grade": commercial_ready,
        "comparison_health": comparison_health,
    }


def build_forensic_validation_plan_row(number: int, readiness_item: Mapping[str, object]) -> dict[str, object]:
    profile = accuracy_profile_for_item(number)
    gates = readiness_item.get("maturity_gates") if isinstance(readiness_item.get("maturity_gates"), Mapping) else {}
    validated_gate = gates.get("validated") if isinstance(gates.get("validated"), Mapping) else {}
    commercial_gate = gates.get("commercial_grade") if isinstance(gates.get("commercial_grade"), Mapping) else {}
    blockers = list(readiness_item.get("commercial_blockers") or []) if isinstance(readiness_item.get("commercial_blockers"), list) else []
    required_checks = [str(item) for item in profile.get("required_checks", []) if str(item)]
    row_core: dict[str, object] = {
        "number": number,
        "title": str(profile.get("title") or readiness_item.get("title") or f"Item {number}"),
        "lane": forensic_lane_for_number(number),
        "priority": forensic_priority_for_number(number),
        "current_maturity": str(readiness_item.get("highest_maturity_stage") or "unknown"),
        "next_required_gate": str(readiness_item.get("next_required_gate") or "validated"),
        "validated": bool(validated_gate.get("passed")),
        "commercial_grade_ready": bool(commercial_gate.get("passed")),
        "surface": str(profile.get("surface") or ""),
        "corpus": str(profile.get("corpus") or ""),
        "oracle": str(profile.get("oracle") or ""),
        "required_checks": required_checks,
        "required_check_count": len(required_checks),
        "remaining_gap": str(
            readiness_item.get("remaining_gap")
            or validated_gate.get("remaining")
            or commercial_gate.get("remaining")
            or "Attach known-answer and trusted diff evidence."
        ),
        "commercial_blockers": blockers,
        "blocker_count": len(blockers),
        "implementation_order": implementation_order_for_number(number),
        "next_internal_work": next_internal_work_for_number(number),
        "external_evidence_required": external_evidence_for_number(number),
        "completion_definition": completion_definition_for_number(number),
    }
    return {**row_core, "row_hash": stable_plan_hash(row_core)}


def summarize_forensic_validation_plan(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    row_list = list(rows)
    lane_counts: dict[str, int] = {}
    for row in row_list:
        lane = str(row.get("lane") or "unknown")
        lane_counts[lane] = lane_counts.get(lane, 0) + 1
    return {
        "item_count": len(row_list),
        "validated_count": sum(1 for row in row_list if row.get("validated")),
        "commercial_grade_ready_count": sum(1 for row in row_list if row.get("commercial_grade_ready")),
        "validation_required_count": sum(1 for row in row_list if not row.get("validated")),
        "commercial_blocked_count": sum(1 for row in row_list if not row.get("commercial_grade_ready")),
        "lane_counts": lane_counts,
        "highest_priority_open_items": [
            int(row.get("number") or 0)
            for row in sorted(row_list, key=lambda item: (int(item.get("priority") or 99), int(item.get("number") or 999)))
            if not row.get("commercial_grade_ready")
        ][:10],
    }


def build_forensic_validation_sequence(rows: Iterable[Mapping[str, object]], *, batch_size: int = 5) -> list[dict[str, object]]:
    ordered = sorted(rows, key=lambda item: (int(item.get("implementation_order") or 999), int(item.get("number") or 999)))
    batches = []
    for index in range(0, len(ordered), batch_size):
        batch_rows = ordered[index : index + batch_size]
        batches.append(
            {
                "batch_number": len(batches) + 1,
                "item_numbers": [int(row.get("number") or 0) for row in batch_rows],
                "primary_lane": str(batch_rows[0].get("lane") or "unknown") if batch_rows else "unknown",
                "goal": batch_goal(batch_rows),
                "required_evidence": [
                    "fixture or known-answer input",
                    "RapidTriage output hash",
                    "trusted reference output or expected-result manifest",
                    "record/row/assertion-level diff",
                    "reviewer limitation note",
                ],
            }
        )
    return batches


def build_forensic_validation_pack_summary(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    row_list = list(rows)
    item_numbers = [int(row.get("number") or 0) for row in row_list]
    tool_families: list[str] = []
    required_checks = 0
    for row in row_list:
        for tool in trusted_reference_tools_for_number(int(row.get("number") or 0)):
            if tool not in tool_families:
                tool_families.append(tool)
        required_checks += int(row.get("required_check_count") or 0)
    return {
        "item_numbers": item_numbers,
        "required_dataset_count": len(row_list),
        "required_check_count": required_checks,
        "required_tool_families": tool_families,
        "ready_to_claim_commercial": False,
        "next_action": "Populate every dataset path, run RapidTriage and trusted references, then attach row-level diffs.",
    }


def build_validation_dataset_template(row: Mapping[str, object]) -> dict[str, object]:
    number = int(row.get("number") or 0)
    dataset_core = {
        "dataset_id": f"forensic-item-{number:03d}",
        "item_number": number,
        "title": str(row.get("title") or f"Item {number}"),
        "status": "not-run",
        "lane": str(row.get("lane") or "unknown"),
        "surface": str(row.get("surface") or ""),
        "corpus_requirement": str(row.get("corpus") or ""),
        "trusted_oracle": str(row.get("oracle") or ""),
        "trusted_reference_tools": trusted_reference_tools_for_number(number),
        "required_checks": list(row.get("required_checks") or []),
        "evidence_paths": {
            "source_evidence": "",
            "rapid_output": "",
            "trusted_reference_output": "",
            "row_level_diff_output": "",
            "reviewer_signoff": "",
        },
        "hash_requirements": {
            "source_sha256": "",
            "source_evidence_sha256": "",
            "rapid_output_sha256": "",
            "trusted_reference_sha256": "",
            "trusted_reference_output_sha256": "",
            "diff_output_sha256": "",
            "row_level_diff_output_sha256": "",
            "reviewer_signoff_sha256": "",
        },
        "pass_fail_contract": [
            "source_evidence path exists and hash matches manifest",
            "rapid_output contains item-specific normalized rows",
            "trusted_reference_output is produced by a recognized independent tool or hand-labeled fixture",
            "row_level_diff_output has zero unexpected missing rows, extra rows, or field mismatches",
            "limitations and reportability blockers remain present when evidence is incomplete",
        ],
        "commercial_blockers": list(row.get("commercial_blockers") or []),
        "remaining_gap": str(row.get("remaining_gap") or ""),
    }
    return {**dataset_core, "dataset_hash": stable_plan_hash(dataset_core)}


def build_reference_command_template(row: Mapping[str, object]) -> dict[str, object]:
    number = int(row.get("number") or 0)
    command_core = {
        "item_number": number,
        "title": str(row.get("title") or f"Item {number}"),
        "rapidtriage_command": rapidtriage_command_hint_for_number(number),
        "trusted_reference_command": trusted_reference_command_hint_for_number(number),
        "diff_command": (
            "rapidtriage cross-tool-validate --rapid-output <rapid.json> "
            "--reference-output reference=<trusted-output> --output <diff.json> --json"
        ),
        "required_output_fields": required_output_fields_for_number(number),
    }
    return {**command_core, "command_hash": stable_plan_hash(command_core)}


def build_diff_contract(rows: Iterable[Mapping[str, object]]) -> dict[str, object]:
    row_list = list(rows)
    contract_core = {
        "version": "row-level-diff-contract-v1",
        "item_numbers": [int(row.get("number") or 0) for row in row_list],
        "minimum_result": {
            "missing_rows": 0,
            "unexpected_rows": 0,
            "field_mismatches": 0,
            "unparsed_source_records": 0,
        },
        "required_diff_fields": sorted(
            {
                field
                for row in row_list
                for field in required_output_fields_for_number(int(row.get("number") or 0))
            }
        ),
        "failure_policy": (
            "Any missing/extra/mismatched row keeps the item at validation-required unless the discrepancy "
            "is documented as a trusted-tool limitation and independently reviewed."
        ),
    }
    return {**contract_core, "contract_hash": stable_plan_hash(contract_core)}


def summarize_diff_comparison_health(comparisons: object) -> dict[str, object]:
    comparison_rows = [item for item in comparisons if isinstance(item, Mapping)] if isinstance(comparisons, list) else []
    field_blocks = (
        "record_field_comparison",
        "registry_field_comparison",
        "mft_field_comparison",
        "usn_field_comparison",
        "usn_state_replay_field_comparison",
        "ese_field_comparison",
        "os_account_field_comparison",
        "execution_artifact_field_comparison",
        "user_activity_field_comparison",
        "system_artifact_field_comparison",
        "browser_storage_field_comparison",
        "browser_timeline_field_comparison",
    )
    mismatch_count = 0
    missing_common_field_count = 0
    truncated = False
    failed_references: list[str] = []
    for comparison in comparison_rows:
        if str(comparison.get("status") or "") != "pass":
            failed_references.append(str(comparison.get("reference_name") or "reference"))
        for block_name in field_blocks:
            block = comparison.get(block_name)
            if not isinstance(block, Mapping):
                continue
            mismatch_count += int(block.get("mismatch_count") or 0)
            missing_common_field_count += int(block.get("missing_common_field_count") or 0)
            truncated = truncated or bool(block.get("truncated"))
    return {
        "comparison_count": len(comparison_rows),
        "failed_references": failed_references,
        "mismatch_count": mismatch_count,
        "missing_common_field_count": missing_common_field_count,
        "truncated": truncated,
        "clean": not failed_references and mismatch_count == 0 and missing_common_field_count == 0,
    }


def build_smoke_rapid_output(dataset: Mapping[str, object]) -> dict[str, object]:
    item_number = int(dataset.get("item_number") or 0)
    artifact = {
        "artifact_type": "forensic-validation-smoke",
        "path": f"smoke://item-{item_number:03d}",
        "details": {
            "item_number": item_number,
            "dataset_id": dataset.get("dataset_id"),
            "title": dataset.get("title"),
            "record_id": 1000 + item_number,
            "event_id": 4000 + item_number,
            "provider": "RapidTriageSmoke",
            "key_path": r"HKEY_CURRENT_USER\Software\RapidTriageSmoke",
            "value_name": f"Item{item_number:03d}",
            "normalized_identity": f"item-{item_number:03d}",
            "source_offset": item_number * 16,
            "parser_confidence": "internal-smoke",
        },
    }
    return {"artifacts": [artifact], "commercial_claim_allowed": False, "fixture_kind": "internal-smoke"}


def build_smoke_reference_csv(dataset: Mapping[str, object]) -> str:
    item_number = int(dataset.get("item_number") or 0)
    if item_number in {1, 2, 3}:
        return (
            "EventRecordID,EventID,Provider,Channel,Timestamp\n"
            f"{1000 + item_number},{4000 + item_number},RapidTriageSmoke,Smoke,2026-01-01T00:00:00+00:00\n"
        )
    if item_number in {4, 5}:
        return (
            "KeyPath,ValueName,ValueType,ValueData,CellOffset,TransactionReplayStatus\n"
            rf"HKCU\Software\RapidTriageSmoke,Item{item_number:03d},REG_SZ,smoke,{item_number * 16},not-replayed"
            "\n"
        )
    return (
        "SourcePath,ArtifactType,NormalizedIdentity,Timestamp,SourceOffset,ParserConfidence\n"
        f"smoke://item-{item_number:03d},forensic-validation-smoke,item-{item_number:03d},"
        f"2026-01-01T00:00:00+00:00,{item_number * 16},internal-smoke\n"
    )


def build_smoke_diff_output(dataset: Mapping[str, object]) -> dict[str, object]:
    item_number = int(dataset.get("item_number") or 0)
    comparison_block_name = smoke_comparison_block_name(item_number)
    comparison = {
        "reference_name": "internal-smoke-reference",
        "status": "pass",
        "rapid_row_count": 1,
        "reference_row_count": 1,
        "overlap_ratio": 1.0,
        "overlap_count": 1,
        comparison_block_name: {
            "mode": f"{comparison_block_name}-smoke",
            "mismatch_count": 0,
            "missing_common_field_count": 0,
            "field_match_ratio": 1.0,
            "truncated": False,
        },
    }
    return {
        "command": "cross-tool-validate",
        "status": "pass",
        "fixture_kind": "internal-smoke",
        "commercial_claim_allowed": False,
        "comparisons": [comparison],
        "cross_tool_validation_assessment": {
            "status": "pass",
            "backlog_items": [item_number],
            "ready_for_validated_gate": True,
            "ready_for_commercial_grade": False,
            "commercial_grade_blockers": ["internal-smoke-fixture-not-external-validation"],
        },
    }


def smoke_comparison_block_name(item_number: int) -> str:
    if item_number in {1, 2, 3}:
        return "record_field_comparison"
    if item_number in {4, 5}:
        return "registry_field_comparison"
    if item_number == 12:
        return "mft_field_comparison"
    if item_number == 13:
        return "usn_field_comparison"
    if item_number in {10, 11}:
        return "ese_field_comparison"
    return "record_field_comparison"


def forensic_lane_for_number(number: int) -> str:
    if 1 <= number <= 25:
        return "core-windows-forensics"
    if 26 <= number <= 45:
        return "mobile-messenger-mail-cloud"
    if 46 <= number <= 65:
        return "search-viewer-review-report"
    if 66 <= number <= 80:
        return "performance-large-scale"
    if 81 <= number <= 100:
        return "validation-legal-defensibility"
    if 101 <= number <= 120:
        return "release-operations-governance"
    return "other"


def forensic_priority_for_number(number: int) -> int:
    if number in {1, 2, 3, 4, 5, 12, 13, 22, 81, 82, 85}:
        return 1
    if number in {6, 7, 8, 9, 10, 11, 16, 17, 18, 49, 54, 64, 65, 66, 67, 68, 69, 70, 86, 87, 88, 89, 90}:
        return 2
    if 19 <= number <= 21 or 46 <= number <= 63 or 71 <= number <= 80 or 91 <= number <= 100:
        return 3
    if 26 <= number <= 45:
        return 4
    return 5


def implementation_order_for_number(number: int) -> int:
    priority = forensic_priority_for_number(number)
    lane_bias = {
        "core-windows-forensics": 0,
        "search-viewer-review-report": 100,
        "performance-large-scale": 150,
        "validation-legal-defensibility": 180,
        "mobile-messenger-mail-cloud": 200,
        "release-operations-governance": 300,
    }
    return priority * 1000 + lane_bias.get(forensic_lane_for_number(number), 300) + number


def next_internal_work_for_number(number: int) -> str:
    if 1 <= number <= 3:
        return "Add native EVTX parser fixtures, record-offset citations, and trusted EvtxECmd/Hayabusa diff assertions."
    if 4 <= number <= 6 or number == 15:
        return "Add Registry hive transaction/deleted-cell/account fixtures with RECmd/RegRipper/ShellBagsExplorer diff assertions."
    if number in {10, 11}:
        return "Add bounded ESE table/page fixture decoding and source-row citation manifests."
    if number in {12, 13}:
        return "Add NTFS MFT/USN known-answer fixtures for path reconstruction, rename/delete replay, and cursor determinism."
    if 46 <= number <= 65:
        return "Add source citation, reviewer state, large-result, and report evidence fixtures with stable manifest hashes."
    if 66 <= number <= 80:
        return "Add repeatable benchmark/stress/checkpoint/cursor fixtures with run logs, resource caps, and regression thresholds."
    if 81 <= number <= 100:
        return "Add validation/legal/integrity manifests with known-answer coverage, hash-chain evidence, provenance, and trusted diff gates."
    if 101 <= number <= 120:
        return "Add release-operation evidence slots, signed artifact checks, local-only proofs, security review hooks, and deployment smoke manifests."
    if 26 <= number <= 45:
        return "Add versioned export schema fixtures and legal/secret redaction gates for the service/app family."
    return "Attach known-answer fixtures, trusted reference output, and row-level diff evidence."


def external_evidence_for_number(number: int) -> list[str]:
    evidence = ["reviewer sign-off", "known-answer source hash", "trusted reference output"]
    if 1 <= number <= 25:
        evidence.append("Windows artifact corpus across OS versions")
    if 26 <= number <= 45:
        evidence.append("authorized export/acquisition scope record")
    if 46 <= number <= 65:
        evidence.append("analyst workflow replay or UI/source-citation oracle")
    if 66 <= number <= 80:
        evidence.append("repeatable performance run log with hardware/profile metadata")
    if 81 <= number <= 100:
        evidence.append("validation/legal reviewer sign-off and manifest hash")
    if 101 <= number <= 120:
        evidence.append("release/build/security/operations evidence artifact")
    return evidence


def completion_definition_for_number(number: int) -> str:
    return (
        f"Item #{number} is complete only when implemented and usable evidence remains present, "
        "known-answer/trusted diff validation passes, limitations are emitted in outputs, "
        "and commercial_readiness marks validated without commercial-grade overclaim."
    )


def trusted_reference_tools_for_number(number: int) -> list[str]:
    if number in {1, 2, 3}:
        return ["EvtxECmd", "Hayabusa", "Windows Event Viewer or wevtutil"]
    if number in {4, 5}:
        return ["RECmd", "Registry Explorer", "RegRipper"]
    if number == 6:
        return ["RECmd", "RegRipper", "Eric Zimmerman's Registry tools"]
    if 7 <= number <= 10:
        return ["AmcacheParser", "AppCompatCacheParser", "RECmd", "SrumECmd"]
    if number == 11:
        return ["libesedb", "WinSearchDBAnalyzer"]
    if number in {12, 13}:
        return ["MFTECmd", "analyzeMFT", "The Sleuth Kit"]
    if number in {14, 15}:
        return ["JLECmd", "ShellBagsExplorer", "RECmd"]
    if 66 <= number <= 80:
        return ["RapidTriage benchmark output", "system resource telemetry", "case-scale regression oracle"]
    if 81 <= number <= 100:
        return ["NIST CFReDS/CFTT or equivalent known-answer corpus", "independent reviewer manifest", "trusted report/audit manifest"]
    if 101 <= number <= 120:
        return ["platform signing/notarization tools", "CI advisory/SBOM scanner", "independent AppSec or operations evidence"]
    return ["trusted external parser", "hand-labeled known-answer fixture"]


def rapidtriage_command_hint_for_number(number: int) -> str:
    if number in {1, 2, 3}:
        return "rapidtriage artifacts <case-root> --windows-event-logs --json --output <rapid-evtx.json>"
    if number in {4, 5}:
        return "rapidtriage artifacts <case-root> --windows-registry --json --output <rapid-registry.json>"
    if 66 <= number <= 80:
        return "rapidtriage benchmark <case-root> --output <rapid-performance.json> plus the item-specific run/checkpoint command"
    if 81 <= number <= 100:
        return "rapidtriage validation --output-dir <validation-dir> --known-answer-manifest <manifest.json> --json"
    if 101 <= number <= 120:
        return "rapidtriage validation-diff-runners --output <runner-matrix.json> --json plus release evidence verifier commands"
    return "rapidtriage artifacts <case-root> --json --output <rapid-output.json>"


def trusted_reference_command_hint_for_number(number: int) -> str:
    if number == 1:
        return "EvtxECmd -f <source.evtx> --json <reference-dir> plus Hayabusa csv-json export for record cross-check"
    if number == 2:
        return "wevtutil qe <log> /f:RenderedXml or EvtxECmd with maps to verify provider/message rendering"
    if number == 3:
        return "EvtxECmd against corrupt/deleted/slack fixture plus hand-labeled recovered offsets"
    if number == 4:
        return "RECmd -f <hive> --nl plus Registry Explorer export for full key/value tree comparison"
    if number == 5:
        return "Registry Explorer deleted-cell export or hand-labeled free-cell fixture with key/value offsets"
    if 66 <= number <= 80:
        return "Run the matching benchmark/stress/checkpoint scenario twice and preserve resource telemetry, thresholds, and failure logs"
    if 81 <= number <= 100:
        return "Attach NIST/CFReDS/CFTT-style manifest, independent reviewer sign-off, and trusted report/audit/exhibit diff outputs"
    if 101 <= number <= 120:
        return "Attach signed build/notarization/CI/SBOM/AppSec/support evidence from the release environment"
    return "Run the item-specific trusted parser listed in trusted_reference_tools and export JSON/CSV"


def required_output_fields_for_number(number: int) -> list[str]:
    if number in {1, 2, 3}:
        return [
            "source_path",
            "record_id",
            "event_id",
            "provider",
            "channel",
            "timestamp",
            "record_offset",
            "template_id",
            "rendered_message",
            "recovery_status",
        ]
    if number in {4, 5}:
        return [
            "source_path",
            "hive_path",
            "key_path",
            "value_name",
            "value_type",
            "value_data_hash",
            "cell_offset",
            "allocation_state",
            "transaction_replay_status",
        ]
    if 66 <= number <= 80:
        return [
            "scenario_id",
            "input_scale",
            "record_count",
            "duration_ms",
            "peak_rss_bytes",
            "p95_latency_ms",
            "resume_or_retry_status",
            "threshold_status",
        ]
    if 81 <= number <= 100:
        return [
            "evidence_id",
            "source_hash",
            "manifest_hash",
            "reviewer_status",
            "provenance_status",
            "limitation_status",
            "audit_chain_head",
            "validation_status",
        ]
    if 101 <= number <= 120:
        return [
            "release_artifact",
            "platform",
            "version",
            "evidence_hash",
            "signoff_status",
            "smoke_status",
            "security_status",
            "blocker_status",
        ]
    return ["source_path", "artifact_type", "normalized_identity", "timestamp", "source_offset", "parser_confidence"]


def batch_goal(rows: list[Mapping[str, object]]) -> str:
    if not rows:
        return ""
    numbers = [int(row.get("number") or 0) for row in rows]
    return f"Close validation evidence for #{min(numbers)}-#{max(numbers)} without claiming commercial grade prematurely."


def write_forensic_validation_plan(plan: dict[str, object], output_dir: Path) -> dict[str, str]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rapidtriage-forensic-validation-plan.json"
    md_path = output_dir / "rapidtriage-forensic-validation-plan.md"
    write_result(plan, json_path)
    md_path.write_text(render_forensic_validation_plan_markdown(plan), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def write_forensic_validation_pack(pack: dict[str, object], output_dir: Path) -> dict[str, str]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "rapidtriage-forensic-validation-pack.json"
    md_path = output_dir / "rapidtriage-forensic-validation-pack.md"
    dataset_path = output_dir / "known-answer-datasets.template.json"
    commands_path = output_dir / "trusted-reference-commands.md"
    write_result(pack, json_path)
    md_path.write_text(render_forensic_validation_pack_markdown(pack), encoding="utf-8")
    write_result(
        {
            "profile_version": pack.get("profile_version"),
            "item_numbers": pack.get("item_numbers"),
            "datasets": pack.get("datasets", []),
            "diff_contract": pack.get("diff_contract", {}),
        },
        dataset_path,
    )
    commands_path.write_text(render_reference_commands_markdown(pack), encoding="utf-8")
    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "dataset_template": str(dataset_path),
        "reference_commands": str(commands_path),
    }


def render_forensic_validation_plan_markdown(plan: Mapping[str, object]) -> str:
    summary = plan.get("summary") if isinstance(plan.get("summary"), Mapping) else {}
    lines = [
        "# RapidTriage Forensic Validation Plan",
        "",
        f"- Profile: `{plan.get('profile_version')}`",
        f"- Items: `{plan.get('item_range')}`",
        f"- Item count: {summary.get('item_count', 0)}",
        f"- Validated: {summary.get('validated_count', 0)}",
        f"- Commercial-ready: {summary.get('commercial_grade_ready_count', 0)}",
        f"- Plan hash: `{plan.get('plan_hash', '')}`",
        "",
        "## Execution Batches",
        "",
    ]
    for batch in plan.get("sequencing", []) if isinstance(plan.get("sequencing"), list) else []:
        if not isinstance(batch, Mapping):
            continue
        lines.append(
            f"- Batch {batch.get('batch_number')}: "
            f"{', '.join(f'#{number}' for number in batch.get('item_numbers', []))} - {batch.get('goal')}"
        )
    lines.extend(["", "## Item Matrix", ""])
    for row in plan.get("rows", []) if isinstance(plan.get("rows"), list) else []:
        if not isinstance(row, Mapping):
            continue
        lines.extend(
            [
                f"### #{row.get('number')} {row.get('title')}",
                "",
                f"- Lane: `{row.get('lane')}`",
                f"- Current maturity: `{row.get('current_maturity')}`",
                f"- Next gate: `{row.get('next_required_gate')}`",
                f"- Validated: `{row.get('validated')}`",
                f"- Commercial-ready: `{row.get('commercial_grade_ready')}`",
                f"- Next internal work: {row.get('next_internal_work')}",
                f"- Remaining gap: {row.get('remaining_gap')}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_forensic_validation_pack_markdown(pack: Mapping[str, object]) -> str:
    summary = pack.get("summary") if isinstance(pack.get("summary"), Mapping) else {}
    lines = [
        "# RapidTriage Forensic Validation Pack",
        "",
        f"- Profile: `{pack.get('profile_version')}`",
        f"- Items: `{pack.get('item_range')}`",
        f"- Required datasets: {summary.get('required_dataset_count', 0)}",
        f"- Required checks: {summary.get('required_check_count', 0)}",
        f"- Pack hash: `{pack.get('pack_hash', '')}`",
        "",
        "## Required Tool Families",
        "",
    ]
    for tool in summary.get("required_tool_families", []) if isinstance(summary.get("required_tool_families"), list) else []:
        lines.append(f"- {tool}")
    lines.extend(["", "## Dataset Checklist", ""])
    for dataset in pack.get("datasets", []) if isinstance(pack.get("datasets"), list) else []:
        if not isinstance(dataset, Mapping):
            continue
        lines.extend(
            [
                f"### #{dataset.get('item_number')} {dataset.get('title')}",
                "",
                f"- Status: `{dataset.get('status')}`",
                f"- Source evidence: `{dataset.get('evidence_paths', {}).get('source_evidence', '') if isinstance(dataset.get('evidence_paths'), Mapping) else ''}`",
                f"- Trusted oracle: {dataset.get('trusted_oracle')}",
                f"- Remaining gap: {dataset.get('remaining_gap')}",
                "",
            ]
        )
    lines.extend(["## Diff Contract", ""])
    diff = pack.get("diff_contract") if isinstance(pack.get("diff_contract"), Mapping) else {}
    lines.append(f"- Failure policy: {diff.get('failure_policy', '')}")
    return "\n".join(lines).rstrip() + "\n"


def render_forensic_validation_batches_markdown(index: Mapping[str, object]) -> str:
    lines = [
        "# RapidTriage Forensic Validation Batches",
        "",
        f"- Profile: `{index.get('profile_version')}`",
        f"- Items: `{index.get('item_range')}`",
        f"- Item count: {index.get('item_count', 0)}",
        f"- Batch count: {index.get('batch_count', 0)}",
        f"- Plan hash: `{index.get('plan_hash', '')}`",
        f"- Batch index hash: `{index.get('batch_index_hash', '')}`",
        "",
        "## Batches",
        "",
    ]
    for batch in index.get("batch_outputs", []) if isinstance(index.get("batch_outputs"), list) else []:
        if not isinstance(batch, Mapping):
            continue
        item_numbers = ", ".join(f"#{number}" for number in batch.get("item_numbers", []))
        lines.extend(
            [
                f"### Batch {batch.get('batch_number')} - {item_numbers}",
                "",
                f"- Directory: `{batch.get('batch_dir')}`",
                f"- Pack hash: `{batch.get('pack_hash')}`",
                f"- Goal: {batch.get('goal')}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def render_reference_commands_markdown(pack: Mapping[str, object]) -> str:
    lines = ["# Trusted Reference Commands", ""]
    for command in pack.get("reference_commands", []) if isinstance(pack.get("reference_commands"), list) else []:
        if not isinstance(command, Mapping):
            continue
        lines.extend(
            [
                f"## #{command.get('item_number')} {command.get('title')}",
                "",
                "```bash",
                str(command.get("rapidtriage_command") or ""),
                str(command.get("trusted_reference_command") or ""),
                str(command.get("diff_command") or ""),
                "```",
                "",
                "Required fields: "
                + ", ".join(str(field) for field in command.get("required_output_fields", []) if str(field)),
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def stable_plan_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
