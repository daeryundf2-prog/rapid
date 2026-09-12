from __future__ import annotations
import contextlib
import csv
import datetime as dt
import hashlib
import json
import plistlib
import shlex
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from ...core.submission import compute_hashes
from ..review import build_forensic_review

from .constants import (
    CHAT_APP_PROFILES,
    FUNCTIONAL_EXPANSION_BATCH_ID,
    MAX_ROWS_PER_SOURCE,
    MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS,
    MOBILE_SCHEMA_REPORT_GRADE_BLOCKERS,
    MOBILE_SCHEMA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    MOBILE_VENDOR_EXPORT_REPORT_GRADE_BLOCKERS,
    MOBILE_VENDOR_EXPORT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    PARSER_VERSION,
    VENDOR_ARTIFACT_MAPPER_KEYS,
    VENDOR_SCHEMA_REGISTRY,
)
from .helpers import (
    _gap_item_numbers,
    _matrix_item_numbers,
    _mobile_matrix_status,
    _mobile_vendor_export_validation_command,
    chat_app_blockers,
    chat_app_gap_ids,
    compute_file_sha256,
    discover_vendor_export_manifest,
    first_value,
    normalize_keys,
    optional_text,
    sha256_text,
    source_record_id,
    stable_mobile_sha256,
)
from .detect import (
    service_family,
)
from .messengers import (
    chat_app_profile,
)


def build_vendor_export_manifest_profile(
    path: Path,
    *,
    source_hashes: Mapping[str, str],
    source_tool: str,
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    manifest_path = discover_vendor_export_manifest(path)
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    if manifest_path is None:
        return {
            "profile_version": "mobile-vendor-export-manifest-v1",
            "manifest_present": False,
            "source_tool": source_tool,
            "vendor_family": registry.get("family", source_tool),
            "required_export_metadata": list(registry.get("required_export_metadata", ())),
            "expected_sidecar_names": [
                path.with_suffix(path.suffix + ".export-metadata.json").name,
                path.with_suffix(path.suffix + ".manifest.json").name,
                "export-metadata.json",
                "export_manifest.json",
            ],
            "validation_status": "metadata-missing",
            "warnings": ["Vendor export metadata sidecar is missing; parser version, settings, and original acquisition hash are unverified."],
        }
    profile: dict[str, object] = {
        "profile_version": "mobile-vendor-export-manifest-v1",
        "manifest_present": True,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_file_sha256(manifest_path),
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "validation_status": "review-required",
        "warnings": [],
    }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        profile.update({"parse_status": "failed", "error": str(exc), "warnings": ["Vendor export metadata sidecar is not valid JSON."]})
        return profile
    if not isinstance(manifest, Mapping):
        profile.update({"parse_status": "failed", "warnings": ["Vendor export metadata sidecar root must be a JSON object."]})
        return profile
    normalized_manifest = normalize_keys(manifest)
    source_sha256 = source_hashes.get("sha256", "")
    manifest_source_sha256 = optional_text(
        first_value(normalized_manifest, ("source_sha256", "export_sha256", "export_file_sha256", "file_sha256"))
    )
    original_hash = optional_text(
        first_value(
            normalized_manifest,
            ("original_acquisition_sha256", "device_acquisition_sha256", "image_sha256", "ufdr_sha256", "source_device_sha256"),
        )
    )
    version_keys = tuple(registry.get("version_keys", ()))
    vendor_tool_version = optional_text(first_value(normalized_manifest, (*version_keys, "vendor_tool_version", "tool_version")))
    parser_version = optional_text(first_value(normalized_manifest, ("parser_version", "export_parser_version", "schema_version")))
    export_settings = first_value(normalized_manifest, ("export_settings", "settings", "options", "export_options"))
    missing_required: list[str] = []
    for field in registry.get("required_export_metadata", ()):
        if field == "vendor_tool" and not optional_text(first_value(normalized_manifest, ("vendor_tool", "tool", "product"))) or field == "vendor_tool_version" and not vendor_tool_version or field == "export_settings" and not export_settings or field == "original_acquisition_sha256" and not original_hash:
            missing_required.append(field)
    source_hash_matches = bool(source_sha256 and manifest_source_sha256 and source_sha256.lower() == manifest_source_sha256.lower())
    profile.update(
        {
            "parse_status": "json-parsed",
            "vendor_tool": optional_text(first_value(normalized_manifest, ("vendor_tool", "tool", "product"))) or source_tool,
            "vendor_tool_version": vendor_tool_version,
            "parser_version": parser_version,
            "schema_version": optional_text(first_value(normalized_manifest, ("schema_version", "export_schema_version", "format_version"))),
            "source_sha256": manifest_source_sha256,
            "source_hash_matches_manifest": source_hash_matches,
            "original_acquisition_sha256": original_hash,
            "original_acquisition_hash_present": bool(original_hash),
            "export_settings_present": bool(export_settings),
            "missing_required_metadata": missing_required,
            "manifest_key_count": len(normalized_manifest),
            "input_row_count": len(rows),
            "validation_status": "metadata-linked" if source_hash_matches and original_hash and vendor_tool_version and not missing_required else "review-required",
        }
    )
    if not source_hash_matches:
        profile["warnings"].append("Source export SHA-256 in sidecar is missing or does not match the imported export file.")
    if missing_required:
        profile["warnings"].append(f"Vendor export metadata is missing required fields: {', '.join(missing_required)}")
    return profile


def build_vendor_schema_registry_profile(
    *,
    source_tool: str,
    rows: Sequence[Mapping[str, object]],
    detected_types: set[str],
    vendor_manifest_profile: Mapping[str, object],
) -> dict[str, object]:
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    normalized_rows = [normalize_keys(row) for row in rows[:500]]
    key_set = sorted({key for row in normalized_rows for key in row})
    version_keys = tuple(registry.get("version_keys", ()))
    schema_versions = sorted(
        {
            optional_text(first_value(row, (*version_keys, "schemaversion", "schema_version", "exportversion", "export_version")))
            for row in normalized_rows
            if optional_text(first_value(row, (*version_keys, "schemaversion", "schema_version", "exportversion", "export_version")))
        }
    )
    expected_artifacts = set(registry.get("expected_artifacts", ()))
    family_aliases = {
        "message": "messages",
        "contact": "contacts",
        "call": "calls",
        "app": "apps",
        "file": "files",
        "account": "accounts",
        "browser": "browser",
        "media": "media",
    }
    observed_families = {
        family_aliases.get(artifact_type.removeprefix("mobile-"), artifact_type.removeprefix("mobile-"))
        for artifact_type in detected_types
    }
    missing_expected = sorted(expected_artifacts - observed_families)
    return {
        "profile_version": "mobile-vendor-schema-registry-v1",
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "known_vendor_profile": bool(registry),
        "schema_versions": schema_versions[:50],
        "schema_version_count": len(schema_versions),
        "observed_artifact_families": sorted(observed_families),
        "expected_artifact_families": sorted(expected_artifacts),
        "missing_expected_artifact_families": missing_expected,
        "sampled_normalized_key_count": len(key_set),
        "sampled_normalized_keys": key_set[:100],
        "manifest_validation_status": vendor_manifest_profile.get("validation_status", "metadata-missing"),
        "manifest_vendor_tool_version": vendor_manifest_profile.get("vendor_tool_version", ""),
        "schema_registry_known_answer_validated": False,
        "reporting_status": "schema-mapped-but-known-answer-required",
    }


def build_mobile_vendor_schema_mapper_manifest(
    *,
    path: Path,
    source_format: str,
    source_tool: str,
    source_hashes: Mapping[str, str],
    rows: Sequence[Mapping[str, object]],
    detected_type_counts: Mapping[str, int],
    source_profile: Mapping[str, object],
    vendor_manifest_profile: Mapping[str, object],
) -> dict[str, object]:
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    normalized_rows = [normalize_keys(row) for row in rows[:500]]
    sampled_keys = sorted({key for row in normalized_rows for key in row})
    output_to_family = {
        str(definition["output_artifact_type"]): family
        for family, definition in VENDOR_ARTIFACT_MAPPER_KEYS.items()
    }
    mapper_statuses: list[dict[str, object]] = []
    for family, definition in VENDOR_ARTIFACT_MAPPER_KEYS.items():
        output_type = str(definition["output_artifact_type"])
        key_sets = definition.get("required_key_sets", ())
        recognized_keys = sorted(
            {
                key
                for key_set in key_sets
                for key in key_set
                if key in sampled_keys
            }
        )
        mapper_statuses.append(
            {
                "family": family,
                "output_artifact_type": output_type,
                "observed": int(detected_type_counts.get(output_type, 0)) > 0,
                "normalized_row_count": int(detected_type_counts.get(output_type, 0)),
                "recognized_key_count": len(recognized_keys),
                "recognized_key_sample": recognized_keys[:40],
                "semantic_fields": list(definition.get("semantic_fields", ())),
                "mapper_status": "active" if detected_type_counts.get(output_type, 0) else "available-not-observed",
            }
        )
    observed_families = sorted(
        {
            output_to_family.get(artifact_type, artifact_type.removeprefix("mobile-"))
            for artifact_type in detected_type_counts
        }
    )
    expected_families = sorted(str(item) for item in registry.get("expected_artifacts", ()))
    missing_expected = sorted(set(expected_families) - set(observed_families))
    source_hash_matches = bool(vendor_manifest_profile.get("source_hash_matches_manifest"))
    original_hash_present = bool(vendor_manifest_profile.get("original_acquisition_hash_present"))
    settings_present = bool(vendor_manifest_profile.get("export_settings_present"))
    vendor_version_present = bool(vendor_manifest_profile.get("vendor_tool_version"))
    manifest: dict[str, object] = {
        "manifest_version": "mobile-vendor-schema-mapper-manifest-v1",
        "item_number": 26,
        "gap_id": "#26",
        "artifact_goal": "Cellebrite/XRY/GrayKey/AXIOM export deep import schema registry and mapper evidence",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "known_vendor_profile": bool(registry),
        "supported_vendor_families": [
            {
                "source_tool": vendor,
                "vendor_family": str(profile.get("family", vendor)),
                "expected_artifacts": list(profile.get("expected_artifacts", ())),
            }
            for vendor, profile in sorted(VENDOR_SCHEMA_REGISTRY.items())
        ],
        "source": {
            "source_format": source_format,
            "source_sha256": source_hashes.get("sha256", ""),
            "input_row_count": int(source_profile.get("input_row_count") or len(rows)),
            "emitted_row_count": int(source_profile.get("emitted_row_count") or sum(detected_type_counts.values())),
            "unclassified_or_skipped_row_count": int(source_profile.get("unclassified_or_skipped_row_count") or 0),
            "truncated_by_row_cap": bool(source_profile.get("truncated_by_row_cap")),
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
        },
        "schema_registry": {
            "profile_version": "mobile-vendor-schema-registry-v1",
            "schema_versions": list(
                (source_profile.get("vendor_schema_registry_profile") or {}).get("schema_versions", [])
            )
            if isinstance(source_profile.get("vendor_schema_registry_profile"), Mapping)
            else [],
            "expected_artifact_families": expected_families,
            "observed_artifact_families": observed_families,
            "missing_expected_artifact_families": missing_expected,
            "sampled_normalized_key_count": len(sampled_keys),
            "sampled_normalized_keys": sampled_keys[:100],
        },
        "artifact_mappers": mapper_statuses,
        "source_manifest_linkage": {
            "manifest_present": bool(vendor_manifest_profile.get("manifest_present")),
            "manifest_path": optional_text(vendor_manifest_profile.get("manifest_path")),
            "manifest_sha256": optional_text(vendor_manifest_profile.get("manifest_sha256")),
            "vendor_tool_version": optional_text(vendor_manifest_profile.get("vendor_tool_version")),
            "vendor_parser_version": optional_text(vendor_manifest_profile.get("parser_version")),
            "schema_version": optional_text(vendor_manifest_profile.get("schema_version")),
            "source_hash_matches_manifest": source_hash_matches,
            "original_acquisition_hash_present": original_hash_present,
            "export_settings_present": settings_present,
            "validation_status": optional_text(vendor_manifest_profile.get("validation_status")),
        },
        "source_viewer_locator": {
            "viewer": "mobile-vendor-export-source",
            "source_path": str(path.resolve()),
            "artifact_type": "mobile-export-source",
            "source_tool": source_tool,
        },
        "validation": {
            "implemented": True,
            "usable": True,
            "internal_fixture_validated": True,
            "vendor_version_schema_matrix_present": bool(registry),
            "source_hash_linked_to_sidecar": source_hash_matches,
            "original_acquisition_hash_recorded": original_hash_present,
            "export_settings_recorded": settings_present,
            "vendor_tool_version_recorded": vendor_version_present,
            "trusted_vendor_diff_attached": False,
            "known_answer_deleted_semantics_attached": False,
            "commercial_grade": False,
        },
        "commercial_blockers": [
            "trusted-vendor-mobile-export-diff-required",
            "per-vendor-version-schema-fixtures-required",
            "deleted-record-semantics-known-answer-required",
            "original-acquisition-hash-and-export-settings-independent-review-required",
        ],
        "reporting_status": "schema-mapper-ready-for-review-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_vendor_export_report_grade_validation_plan(
    *,
    path: Path,
    source_format: str,
    source_tool: str,
    source_hashes: Mapping[str, str],
    rows: Sequence[Mapping[str, object]],
    detected_type_counts: Mapping[str, int],
    source_profile: Mapping[str, object],
    vendor_manifest_profile: Mapping[str, object],
    mapper_manifest: Mapping[str, object],
) -> dict[str, object]:
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    output_root = path.parent / f"{path.stem}-rapidtriage-validation"
    vendor_version = optional_text(vendor_manifest_profile.get("vendor_tool_version"))
    source_hash_matches = bool(vendor_manifest_profile.get("source_hash_matches_manifest"))
    original_hash_present = bool(vendor_manifest_profile.get("original_acquisition_hash_present"))
    settings_present = bool(vendor_manifest_profile.get("export_settings_present"))
    manifest_linked = bool(vendor_manifest_profile.get("manifest_present"))
    known_vendor = bool(registry)
    emitted_count = int(source_profile.get("emitted_row_count") or sum(detected_type_counts.values()))
    input_count = int(source_profile.get("input_row_count") or len(rows))
    metadata_sidecar = discover_vendor_export_manifest(path) or path.with_suffix(path.suffix + ".export-metadata.json")
    validation_commands = [
        _mobile_vendor_export_validation_command(
            "source-export-manifest",
            ["rapidtriage", "manifest", str(path.parent), "--output", str(output_root / "source-export-manifest.json")],
            purpose="Hash the vendor export folder and preserve the imported source file inventory.",
            expected_output=str(output_root / "source-export-manifest.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "mobile-export-import",
            [
                "rapidtriage",
                "artifacts",
                str(path.parent),
                "--kind",
                "mobile-export",
                "--output",
                str(output_root / "rapidtriage-mobile-export.json"),
            ],
            purpose="Regenerate RapidTriage mobile export rows from the vendor export folder.",
            expected_output=str(output_root / "rapidtriage-mobile-export.json"),
            status="ready",
        ),
        _mobile_vendor_export_validation_command(
            "vendor-metadata-sidecar",
            [
                "<analyst>",
                "create-or-review-export-metadata",
                str(metadata_sidecar),
            ],
            purpose="Attach vendor tool/version, export settings, source SHA-256, and original acquisition hash linkage.",
            expected_output=str(metadata_sidecar),
            trusted_tool=True,
            status="complete" if manifest_linked and source_hash_matches and vendor_version and settings_present else "operator-action-required",
        ),
        _mobile_vendor_export_validation_command(
            "trusted-vendor-mobile-export-diff",
            [
                "rapidtriage",
                "cross-tool-validate",
                "--rapid-output",
                str(output_root / "rapidtriage-mobile-export.json"),
                "--reference-output",
                f"{source_tool}=<trusted-vendor-export.csv>",
                "--backlog-item",
                "26",
                "--source-evidence",
                str(path),
                "--tool-version",
                f"{source_tool}={vendor_version or '<vendor-version>'}",
                "--tool-command",
                f"{source_tool}=<trusted-tool-export-command>",
                "--corpus-scope",
                "<vendor-version-and-deleted-record-known-answer-scope>",
                "--output",
                str(output_root / "mobile-vendor-trusted-diff.json"),
                "--json",
            ],
            purpose="Compare normalized RapidTriage rows against trusted Cellebrite/XRY/GrayKey/AXIOM export rows.",
            expected_output=str(output_root / "mobile-vendor-trusted-diff.json"),
            trusted_tool=True,
            status="pending-cross-tool-validate",
        ),
    ]
    evidence_slots = [
        {
            "id": "source-export-integrity",
            "label": "Imported vendor export source SHA-256",
            "status": "complete" if source_hashes.get("sha256") else "pending-source-hash",
            "required_before_report": True,
            "sha256": source_hashes.get("sha256", ""),
        },
        {
            "id": "vendor-tool-family-detected",
            "label": "Cellebrite/XRY/GrayKey/AXIOM family detected",
            "status": "complete" if known_vendor else "review-required",
            "required_before_report": True,
            "source_tool": source_tool,
            "vendor_family": registry.get("family", source_tool),
        },
        {
            "id": "vendor-metadata-sidecar",
            "label": "Vendor export metadata sidecar linked to source hash",
            "status": "complete" if manifest_linked and source_hash_matches else ("review-required" if manifest_linked else "missing"),
            "required_before_report": True,
            "manifest_sha256": vendor_manifest_profile.get("manifest_sha256", ""),
            "source_hash_matches_manifest": source_hash_matches,
            "validation_status": vendor_manifest_profile.get("validation_status", ""),
        },
        {
            "id": "vendor-tool-version-and-export-settings",
            "label": "Vendor tool version and export settings recorded",
            "status": "complete" if vendor_version and settings_present else "pending-vendor-version-or-settings",
            "required_before_report": True,
            "vendor_tool_version": vendor_version,
            "export_settings_present": settings_present,
        },
        {
            "id": "original-acquisition-hash-linkage",
            "label": "Original device/acquisition hash linkage recorded",
            "status": "complete" if original_hash_present else "pending-original-acquisition-hash",
            "required_before_report": True,
            "original_acquisition_hash_present": original_hash_present,
        },
        {
            "id": "schema-mapper-and-row-identity",
            "label": "Schema mapper, source row identity, and row caps recorded",
            "status": "complete" if mapper_manifest.get("manifest_sha256") and emitted_count > 0 else "pending-schema-mapper",
            "required_before_report": True,
            "mapper_manifest_sha256": mapper_manifest.get("manifest_sha256", ""),
            "input_row_count": input_count,
            "emitted_row_count": emitted_count,
            "detected_type_counts": dict(detected_type_counts),
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
        },
        {
            "id": "trusted-vendor-mobile-export-diff",
            "label": "Independent trusted vendor export row diff",
            "status": "pending-cross-tool-validate",
            "required_before_report": True,
            "required_fields": [
                "source_record_id",
                "timestamp",
                "sender",
                "recipient",
                "message_text_sha256",
                "contact",
                "call",
                "media",
                "browser",
            ],
        },
        {
            "id": "per-vendor-version-schema-fixtures",
            "label": "Per-vendor/version schema known-answer fixtures",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["cellebrite", "xry", "graykey", "axiom"],
        },
        {
            "id": "deleted-record-semantics-corpus",
            "label": "Deleted-record and retention-semantics known-answer corpus",
            "status": "external-corpus-required",
            "required_before_commercial_grade": True,
            "minimum_cases": ["live-row", "deleted-row", "edited-row", "attachment-or-media-row"],
        },
        {
            "id": "independent-review-signoff",
            "label": "Independent analyst review of original acquisition/export procedure",
            "status": "external-review-required",
            "required_before_commercial_grade": True,
            "required_materials": ["tool version log", "export command/log", "original acquisition hash", "trusted diff"],
        },
    ]
    ready_slots = [slot["id"] for slot in evidence_slots if str(slot.get("status", "")).startswith("complete")]
    blocker_slots = [
        slot["id"]
        for slot in evidence_slots
        if slot.get("required_before_report") and not str(slot.get("status", "")).startswith("complete")
    ]
    payload: dict[str, object] = {
        "profile_version": MOBILE_VENDOR_EXPORT_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 26,
        "gap_id": "#26",
        "source_path": str(path.resolve()),
        "source_tool": source_tool,
        "source_format": source_format,
        "vendor_family": registry.get("family", source_tool),
        "output_root": str(output_root),
        "status": "report-validation-blocked" if blocker_slots else "ready-for-report-review",
        "commercial_grade_ready": False,
        "source_hashes": dict(source_hashes),
        "source_profile": dict(source_profile),
        "vendor_export_manifest_profile": dict(vendor_manifest_profile),
        "mobile_vendor_schema_mapper_manifest_hash": optional_text(mapper_manifest.get("manifest_sha256")),
        "validation_commands": validation_commands,
        "evidence_slots": evidence_slots,
        "ready_slot_ids": ready_slots,
        "blocking_slot_ids": blocker_slots,
        "report_claim_boundary": (
            "This plan can make one vendor mobile export reviewable when all report-required slots pass; "
            "it is still not proof of complete device acquisition, deleted-record semantics, encrypted store coverage, "
            "or vendor-version parser parity without trusted diffs and external known-answer corpora."
        ),
        "commercial_grade_blockers": list(MOBILE_VENDOR_EXPORT_REPORT_GRADE_BLOCKERS),
        "operator_next_steps": [
            "Preserve the original acquisition hash and vendor export transcript before importing rows.",
            "Attach or review the export metadata sidecar and confirm the source export SHA-256 matches.",
            "Regenerate RapidTriage mobile export rows, then run cross-tool validation against the trusted vendor export.",
            "Attach vendor-version schema fixtures and deleted-record known-answer evidence before using commercial-grade wording.",
        ],
    }
    payload["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    return payload


def build_mobile_schema_compatibility_matrix(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
    gap_ids: Sequence[str],
) -> dict[str, object]:
    service = optional_text(details.get("service"))
    profile = chat_app_profile(service) if service else None
    source_profile = (
        details.get("mobile_export_source_profile")
        if isinstance(details.get("mobile_export_source_profile"), Mapping)
        else {}
    )
    vendor_manifest = (
        details.get("vendor_export_manifest_profile")
        if isinstance(details.get("vendor_export_manifest_profile"), Mapping)
        else {}
    )
    mapper_manifest = (
        details.get("mobile_vendor_schema_mapper_manifest")
        if isinstance(details.get("mobile_vendor_schema_mapper_manifest"), Mapping)
        else {}
    )
    validation_plan = (
        details.get("mobile_vendor_export_validation_plan")
        if isinstance(details.get("mobile_vendor_export_validation_plan"), Mapping)
        else {}
    )
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    matrix_rows: list[dict[str, object]] = []
    base_item_numbers = _gap_item_numbers(gap_ids)

    if "#26" in gap_ids:
        observed_artifacts = (
            source_profile.get("detected_artifact_types")
            if isinstance(source_profile.get("detected_artifact_types"), list)
            else []
        )
        registry_profile = source_profile.get("vendor_schema_registry_profile")
        schema_versions: list[str] = []
        if isinstance(registry_profile, Mapping):
            raw_versions = registry_profile.get("schema_versions")
            if isinstance(raw_versions, list):
                schema_versions = [optional_text(value) for value in raw_versions if optional_text(value)]
        for vendor, registry in sorted(VENDOR_SCHEMA_REGISTRY.items()):
            observed_vendor = vendor == source_tool
            metadata_complete = observed_vendor and all(
                bool(vendor_manifest.get(key))
                for key in ("vendor_tool_version", "source_hash_matches_manifest", "original_acquisition_hash_present")
            )
            matrix_rows.append(
                {
                    "row_id": f"vendor-export:{vendor}",
                    "scope": "vendor-export",
                    "item_number": 26,
                    "target": vendor,
                    "vendor_family": optional_text(registry.get("family") or vendor),
                    "observed_in_source": observed_vendor,
                    "source_tool_version": optional_text(
                        vendor_manifest.get("vendor_tool_version") or source_profile.get("vendor_tool_version")
                    )
                    if observed_vendor
                    else "",
                    "schema_versions": schema_versions if observed_vendor else [],
                    "source_format": source_format if observed_vendor else "",
                    "required_export_metadata": list(registry.get("required_export_metadata", ())),
                    "metadata_linkage_complete": bool(metadata_complete),
                    "expected_artifact_families": list(registry.get("expected_artifacts", ())),
                    "observed_artifact_types": observed_artifacts if observed_vendor else [],
                    "mapper_manifest_sha256": optional_text(mapper_manifest.get("manifest_sha256")) if observed_vendor else "",
                    "validation_plan_sha256": optional_text(validation_plan.get("manifest_sha256")) if observed_vendor else "",
                    "known_answer_validated": False,
                    "commercial_grade_ready": False,
                    "status": _mobile_matrix_status(False, observed_vendor),
                    "blockers": [
                        "per-vendor-version-schema-fixtures-required",
                        "trusted-vendor-mobile-export-diff-required",
                    ],
                }
            )
        artifact_mappers = mapper_manifest.get("artifact_mappers")
        if isinstance(artifact_mappers, list):
            for mapper in artifact_mappers:
                if not isinstance(mapper, Mapping):
                    continue
                observed_mapper = bool(mapper.get("observed"))
                matrix_rows.append(
                    {
                        "row_id": f"vendor-mapper:{optional_text(mapper.get('family'))}",
                        "scope": "vendor-artifact-mapper",
                        "item_number": 26,
                        "target": optional_text(mapper.get("family")),
                        "output_artifact_type": optional_text(mapper.get("output_artifact_type")),
                        "observed_in_source": observed_mapper,
                        "normalized_row_count": int(mapper.get("normalized_row_count") or 0),
                        "semantic_fields": list(mapper.get("semantic_fields", ())),
                        "known_answer_validated": False,
                        "commercial_grade_ready": False,
                        "status": _mobile_matrix_status(False, observed_mapper),
                        "blockers": [
                            "mapper-field-semantics-known-answer-required",
                            "deleted-record-semantics-known-answer-required",
                        ],
                    }
                )

    if artifact_type in {"ios-backup-file", "ios-backup-source", "ios-backup-metadata", "ios-keychain-inventory"}:
        root_profile = details.get("ios_backup_root_profile") if isinstance(details.get("ios_backup_root_profile"), Mapping) else {}
        scope_profile = details.get("ios_backup_scope_profile") if isinstance(details.get("ios_backup_scope_profile"), Mapping) else {}
        is_keychain = artifact_type == "ios-keychain-inventory"
        matrix_rows.append(
            {
                "row_id": "ios-backup:manifest-db",
                "scope": "ios-backup",
                "item_number": 27,
                "target": "Manifest.db / Info.plist / Status.plist",
                "observed_in_source": artifact_type != "ios-keychain-inventory",
                "product_version": optional_text(root_profile.get("product_version") or details.get("product_version")),
                "manifest_row_count": int(scope_profile.get("manifest_row_count") or details.get("manifest_row_count") or 0),
                "required_files_present": bool(root_profile.get("required_files_present") or validation_checks.get("required_backup_files_present")),
                "encrypted_backup_unlocked": bool(validation_checks.get("encrypted_backup_unlocked")),
                "commercial_grade_ready": False,
                "status": _mobile_matrix_status(False, artifact_type != "ios-keychain-inventory"),
                "blockers": [
                    "trusted-ios-backup-parser-diff-required",
                    "encrypted-backup-authority-review-required",
                ],
            }
        )
        matrix_rows.append(
            {
                "row_id": "ios-keychain:redacted-inventory",
                "scope": "ios-keychain",
                "item_number": 28,
                "target": "keychain inventory",
                "observed_in_source": is_keychain or bool(root_profile.get("keychain_file")),
                "values_redacted": bool(validation_checks.get("values_redacted", True)),
                "secrets_extracted": bool(validation_checks.get("secrets_extracted")),
                "lawful_authority_gate_required": True,
                "commercial_grade_ready": False,
                "status": _mobile_matrix_status(False, is_keychain or bool(root_profile.get("keychain_file"))),
                "blockers": [
                    "trusted-ios-keychain-inventory-diff-required",
                    "lawful-authority-and-controlled-reveal-audit-required",
                ],
            }
        )

    if artifact_type == "mobile-app":
        package = optional_text(details.get("package") or details.get("bundle_id") or details.get("bundle") or details.get("app_id"))
        matrix_rows.append(
            {
                "row_id": f"android-app-package:{package or 'unknown'}",
                "scope": "android-app-or-ios-bundle",
                "item_numbers": [29, 30],
                "target": package or optional_text(details.get("app_name") or "unknown"),
                "observed_in_source": True,
                "app_version": optional_text(details.get("version") or details.get("app_version")),
                "apk_or_app_data_inventory": True,
                "native_app_database_decoded": False,
                "permission_risk_model_present": bool(details.get("risk_flags")),
                "commercial_grade_ready": False,
                "status": "inventory-only-validation-required",
                "blockers": [
                    "android-backup-artifact-known-answer-required",
                    "apk-binary-manifest-and-data-schema-validation-required",
                ],
            }
        )

    if service:
        selected_services = {
            "KakaoTalk",
            "WhatsApp",
            "Telegram",
            "Signal",
            "LINE",
            "Discord",
            "Instagram",
            "WeChat",
        }
        for chat_profile in CHAT_APP_PROFILES:
            chat_service = optional_text(chat_profile.get("service"))
            if chat_service not in selected_services and chat_service != service:
                continue
            observed_chat = chat_service == service
            chat_gap_ids = chat_app_gap_ids(chat_service)
            blockers = chat_app_blockers(chat_service)
            if chat_service == "KakaoTalk":
                blockers = sorted(
                    {
                        *blockers,
                        "post-bigbang-known-answer-corpus-required",
                        "kakaotalk-version-and-memory-key-boundary-validation-required",
                    }
                )
            matrix_rows.append(
                {
                    "row_id": f"messenger-service:{service_family(chat_service)}",
                    "scope": "messenger-service",
                    "item_numbers": _gap_item_numbers(chat_gap_ids),
                    "target": chat_service,
                    "observed_in_source": observed_chat,
                    "aliases": list(chat_profile.get("aliases", ())),
                    "message_tables": list(chat_profile.get("message_tables", ())),
                    "source_tool": source_tool if observed_chat else "",
                    "app_version": optional_text(details.get("app_version")) if observed_chat else "",
                    "schema_version": optional_text(details.get("schema_version")) if observed_chat else "",
                    "strategy_track": optional_text(
                        (details.get("chat_app_strategy_profile") or {}).get("selected_track")
                        if isinstance(details.get("chat_app_strategy_profile"), Mapping)
                        else ""
                    )
                    if observed_chat
                    else "supported-profile",
                    "row_citation_present": bool(details.get("source_record_id") or source_index is not None) if observed_chat else False,
                    "known_answer_validated": False,
                    "commercial_grade_ready": False,
                    "status": _mobile_matrix_status(False, observed_chat),
                    "blockers": blockers,
                }
            )

    row_item_numbers = _matrix_item_numbers(matrix_rows, base_item_numbers)
    row_blockers = sorted(
        {
            str(blocker)
            for row in matrix_rows
            for blocker in row.get("blockers", [])
            if isinstance(blocker, str) and blocker
        }
    )
    scope = "mobile-record"
    if artifact_type == "mobile-export-source":
        scope = "vendor-export-source"
    elif service:
        scope = "messenger-service"
    elif artifact_type.startswith("ios-"):
        scope = "ios-backup-or-keychain"
    elif artifact_type == "mobile-app":
        scope = "mobile-app-package"
    matrix: dict[str, object] = {
        "profile_version": "mobile-schema-compatibility-matrix-v1",
        "scope": scope,
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": optional_text(source_hashes.get("sha256")),
        "gap_ids": list(gap_ids),
        "item_numbers": row_item_numbers,
        "service": service,
        "known_service_profile": profile is not None if service else False,
        "matrix_row_count": len(matrix_rows),
        "matrix_rows": matrix_rows,
        "coverage": {
            "vendor_export_rows": sum(1 for row in matrix_rows if row.get("scope") == "vendor-export"),
            "vendor_mapper_rows": sum(1 for row in matrix_rows if row.get("scope") == "vendor-artifact-mapper"),
            "messenger_service_rows": sum(1 for row in matrix_rows if row.get("scope") == "messenger-service"),
            "backup_or_keychain_rows": sum(1 for row in matrix_rows if str(row.get("scope", "")).startswith("ios-")),
            "android_or_app_rows": sum(1 for row in matrix_rows if row.get("scope") == "android-app-or-ios-bundle"),
            "observed_row_count": sum(1 for row in matrix_rows if row.get("observed_in_source")),
            "commercial_grade_row_count": sum(1 for row in matrix_rows if row.get("commercial_grade_ready")),
        },
        "reportability_decision": {
            "decision": "do-not-report-mobile-schema-as-commercial-complete",
            "allowed_use": "triage-schema-version-and-source-review-pivot",
            "blockers": row_blockers,
        },
        "commercial_grade_ready": False,
        "ready_for_court_report": False,
    }
    matrix["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in matrix.items() if key != "manifest_sha256"}
    )
    return matrix


def build_schema_version_registry(rows: list[Mapping[str, object]], *, limit: int = 200) -> list[dict[str, object]]:
    registry: dict[tuple[str, str, str], dict[str, object]] = {}
    for row in rows:
        app_identifier = optional_text(row.get("package") or row.get("service") or row.get("app_name") or "unknown")
        version = optional_text(row.get("schema_version") or row.get("version") or "unknown")
        event_type = optional_text(row.get("event_type") or row.get("artifact_type") or "unknown")
        key = (app_identifier, version, event_type)
        entry = registry.setdefault(
            key,
            {
                "app_identifier": app_identifier,
                "schema_or_app_version": version,
                "event_type": event_type,
                "row_count": 0,
                "known_schema_validated": False,
                "validation_status": "candidate",
            },
        )
        entry["row_count"] = int(entry["row_count"]) + 1
    values = sorted(registry.values(), key=lambda item: (str(item["app_identifier"]), str(item["schema_or_app_version"])))
    return values[:limit]


def build_mobile_schema_compatibility_profile(registry: list[Mapping[str, object]]) -> dict[str, object]:
    known_validated = [row for row in registry if row.get("known_schema_validated")]
    unvalidated = [row for row in registry if not row.get("known_schema_validated")]
    app_ids = sorted({optional_text(row.get("app_identifier") or "unknown") for row in registry})
    versions = sorted({optional_text(row.get("schema_or_app_version") or "unknown") for row in registry})
    release_gate_entries = [
        {
            "app_identifier": optional_text(row.get("app_identifier") or "unknown"),
            "schema_or_app_version": optional_text(row.get("schema_or_app_version") or "unknown"),
            "event_type": optional_text(row.get("event_type") or "unknown"),
            "row_count": int(row.get("row_count") or 0),
            "known_schema_validated": bool(row.get("known_schema_validated")),
            "release_gate_status": "blocked-pending-known-answer-fixture"
            if not row.get("known_schema_validated")
            else "validated-fixture-attached",
        }
        for row in registry[:200]
    ]
    return {
        "profile_version": "mobile-schema-compatibility-v1",
        "selected_track": "app-schema-version-registry-with-release-gates",
        "entry_count": len(registry),
        "app_identifier_count": len(app_ids),
        "schema_or_app_version_count": len(versions),
        "validated_entry_count": len(known_validated),
        "unvalidated_entry_count": len(unvalidated),
        "app_identifiers": app_ids[:100],
        "schema_or_app_versions": versions[:100],
        "release_gate_entries": release_gate_entries,
        "release_gate_entry_count": len(release_gate_entries),
        "known_answer_fixture_required": bool(unvalidated),
        "schema_migration_matrix_required": True,
        "commercial_release_blocked": bool(unvalidated),
        "reporting_status": "schema-compatibility-validation-required",
        "required_before_report": [
            "attach app/version-specific schema fixtures for every message/contact/media database family",
            "record migration behavior when app schema versions change across releases",
            "block commercial parser claims for unvalidated app/schema combinations",
        ],
    }


def build_mobile_schema_version_manifest(
    *,
    registry: list[Mapping[str, object]],
    source_rows: list[Mapping[str, object]],
    limit: int = 200,
) -> dict[str, object]:
    schema_entries: list[dict[str, object]] = []
    for index, row in enumerate(registry[:limit], start=1):
        app_identifier = optional_text(row.get("app_identifier") or "unknown")
        version = optional_text(row.get("schema_or_app_version") or "unknown")
        event_type = optional_text(row.get("event_type") or "unknown")
        linked_sources: list[dict[str, object]] = []
        for source in source_rows:
            source_app = optional_text(source.get("package") or source.get("service") or source.get("app_name") or "unknown")
            source_version = optional_text(
                source.get("schema_version")
                or source.get("version")
                or source.get("app_version")
                or source.get("appversion")
                or "unknown"
            )
            source_event_type = optional_text(source.get("event_type") or source.get("artifact_type") or "unknown")
            if (source_app, source_version, source_event_type) != (app_identifier, version, event_type):
                continue
            linked_sources.append(
                {
                    "source_index": int(source.get("source_index") or len(linked_sources) + 1),
                    "source_record_id": optional_text(source.get("source_record_id") or source_record_id(source, len(linked_sources))),
                    "source_path_sha256": sha256_text(optional_text(source.get("source_path"))),
                    "source_hash_sha256": optional_text(
                        (source.get("source_hashes") or {}).get("sha256")
                        if isinstance(source.get("source_hashes"), Mapping)
                        else ""
                    ),
                }
            )
        entry_payload = {
            "entry_index": index,
            "app_identifier": app_identifier,
            "schema_or_app_version": version,
            "event_type": event_type,
            "row_count": int(row.get("row_count") or 0),
            "known_schema_validated": bool(row.get("known_schema_validated")),
            "validation_status": optional_text(row.get("validation_status") or "candidate"),
            "linked_source_count": len(linked_sources),
            "release_gate_status": "validated-fixture-attached"
            if row.get("known_schema_validated")
            else "blocked-pending-known-answer-fixture",
        }
        schema_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_mobile_sha256(entry_payload),
                "linked_source_refs": linked_sources[:25],
                "linked_source_refs_truncated": len(linked_sources) > 25,
                "source_viewer_locator": {
                    "viewer": "mobile-schema-version-review",
                    "app_identifier": app_identifier,
                    "schema_or_app_version": version,
                    "event_type": event_type,
                    "open_requires_known_answer_fixture": not row.get("known_schema_validated"),
                },
                "required_fixture_id": stable_mobile_sha256(
                    {
                        "app_identifier": app_identifier,
                        "schema_or_app_version": version,
                        "event_type": event_type,
                    }
                )[:16],
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "mobile-schema-version-manifest-v1",
        "item_number": 45,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "app-schema-version-registry-release-gates",
        "schema_entry_count": len(schema_entries),
        "schema_entry_cap": limit,
        "schema_entries_truncated": len(registry) > limit,
        "schema_entries": schema_entries,
        "source_row_count": len(source_rows),
        "known_answer_fixture_required": any(not row.get("known_schema_validated") for row in registry),
        "schema_migration_matrix_required": True,
        "release_gate_blocked": any(not row.get("known_schema_validated") for row in registry),
        "passed_validation_check_ids": [
            "mobile-schema-version-manifest-emitted",
            "schema-source-viewer-locators-built",
            "schema-release-gates-recorded",
        ],
        "failed_validation_check_ids": [
            "schema-version-registry-known-answer-not-attached",
            "schema-migration-matrix-not-attached",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[45],
        ],
        "commercial_blockers": [
            "schema-version-registry-known-answer-not-attached",
            "schema-migration-matrix-not-attached",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[45],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_schema_report_grade_validation_plan(
    *,
    registry: list[Mapping[str, object]],
    source_rows: list[Mapping[str, object]],
    schema_compatibility_profile: Mapping[str, object],
    schema_version_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    schema_profile_hash = stable_mobile_sha256(schema_compatibility_profile)
    schema_manifest_hash = optional_text(schema_version_manifest.get("manifest_sha256"))
    schema_entries = schema_version_manifest.get("schema_entries")
    if not isinstance(schema_entries, list):
        schema_entries = []
    locators_present = all(
        isinstance(entry, Mapping) and isinstance(entry.get("source_viewer_locator"), Mapping)
        for entry in schema_entries
    )
    fixture_ids_present = all(
        isinstance(entry, Mapping) and optional_text(entry.get("required_fixture_id"))
        for entry in schema_entries
    )

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    validation_slots = [
        slot(
            "mobile-schema-version-registry-built",
            ready=bool(registry),
            evidence=f"schema_entry_count={len(registry)} source_row_count={len(source_rows)}",
            blocker_id="mobile-schema-version-registry-required",
            operator_action="Regenerate mobile correlation so app/schema version registry entries are present.",
        ),
        slot(
            "mobile-schema-compatibility-profile-emitted",
            ready=schema_compatibility_profile.get("profile_version") == "mobile-schema-compatibility-v1",
            evidence=f"schema_compatibility_profile_sha256={schema_profile_hash}",
            blocker_id="mobile-schema-compatibility-profile-required",
            operator_action="Regenerate mobile correlation so compatibility/release-gate profile is emitted.",
        ),
        slot(
            "mobile-schema-version-manifest-emitted",
            ready=bool(schema_manifest_hash),
            evidence=f"schema_version_manifest_sha256={schema_manifest_hash}",
            blocker_id="mobile-schema-version-manifest-required",
            operator_action="Generate the schema version manifest before release/report review.",
        ),
        slot(
            "mobile-schema-source-viewer-locators",
            ready=locators_present and bool(schema_entries),
            evidence=f"schema_entry_count={len(schema_entries)} locators_present={locators_present}",
            blocker_id="mobile-schema-source-viewer-locator-required",
            operator_action="Attach source viewer locators for every app/schema entry.",
        ),
        slot(
            "mobile-schema-release-gates-recorded",
            ready=bool(schema_version_manifest.get("release_gate_blocked")) or bool(schema_entries),
            evidence=f"release_gate_blocked={bool(schema_version_manifest.get('release_gate_blocked'))}",
            blocker_id="mobile-schema-release-gates-required",
            operator_action="Record release gates for every unvalidated app/schema combination.",
        ),
        slot(
            "mobile-schema-fixture-ids-emitted",
            ready=fixture_ids_present and bool(schema_entries),
            evidence=f"fixture_ids_present={fixture_ids_present} schema_entry_count={len(schema_entries)}",
            blocker_id="mobile-schema-fixture-id-required",
            operator_action="Generate stable fixture IDs so missing schema corpora are trackable.",
        ),
        slot(
            "mobile-schema-version-fixture-corpus",
            ready=False,
            evidence="schema_version_fixture_corpus_attached=false",
            blocker_id="mobile-schema-version-fixture-corpus-required",
            operator_action="Attach known-answer fixtures for every supported app/schema/event family.",
        ),
        slot(
            "mobile-schema-migration-matrix",
            ready=False,
            evidence="schema_migration_matrix_attached=false",
            blocker_id="mobile-schema-migration-matrix-required",
            operator_action="Attach schema migration behavior across app upgrades and DB version changes.",
        ),
        slot(
            "mobile-schema-trusted-migration-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[45],
            operator_action="Attach a passing trusted app-schema migration diff.",
        ),
        slot(
            "mobile-schema-release-policy-approval",
            ready=False,
            evidence="operator_release_policy_approved=false",
            blocker_id="mobile-schema-release-policy-approval-required",
            operator_action="Require an operator-approved release gate before marking a schema parser supported.",
        ),
        slot(
            "mobile-schema-upgrade-deleted-state-corpus",
            ready=False,
            evidence="upgrade_deleted_state_corpus_attached=false",
            blocker_id="mobile-schema-upgrade-deleted-state-corpus-required",
            operator_action="Validate deleted/edited/read-state semantics across schema upgrades.",
        ),
        slot(
            "mobile-schema-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="mobile-schema-independent-review-required",
            operator_action="Attach independent reviewer signoff before release-safe schema wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": MOBILE_SCHEMA_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 45,
        "gap_id": "#45",
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "app-schema-version-release-gate-report-validation",
        "schema_entry_count": len(registry),
        "source_row_count": len(source_rows),
        "schema_compatibility_profile_sha256": schema_profile_hash,
        "schema_version_manifest_sha256": schema_manifest_hash,
        "schema_manifest_entry_count": int(schema_version_manifest.get("schema_entry_count") or 0),
        "schema_unvalidated_entry_count": int(schema_compatibility_profile.get("unvalidated_entry_count") or 0),
        "release_gate_entry_count": int(schema_compatibility_profile.get("release_gate_entry_count") or 0),
        "release_gate_blocked": bool(schema_version_manifest.get("release_gate_blocked")),
        "known_answer_fixture_required": bool(schema_version_manifest.get("known_answer_fixture_required")),
        "schema_migration_matrix_required": bool(schema_version_manifest.get("schema_migration_matrix_required")),
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MOBILE_SCHEMA_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapidtriage-mobile-export.json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-mobile-export.json --reference-output <trusted-schema-migration-fixture> --backlog-item 45 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 45 --json",
        ],
        "report_guidance": {
            "allowed_use": "mobile-app-schema-version-release-gate-pivot",
            "forbidden_claims": [
                "all app schemas are supported",
                "schema migration behavior is validated",
                "deleted/read-state semantics are release-safe",
                "parser compatibility is commercial-grade for unvalidated app versions",
            ],
            "required_disclaimer": (
                "Schema/version entries are release-gate candidates. Do not claim parser support for an app/version "
                "until fixture corpora, migration matrices, trusted diffs, release approval, upgrade/deleted-state "
                "tests, and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def build_mobile_vendor_import_manifest(
    *,
    artifact_type: str,
    source_tool: str,
    source_format: str,
    source_index: int,
    source_hashes: Mapping[str, str],
    source_path: Path,
    details: Mapping[str, object],
) -> dict[str, object]:
    source_profile = (
        details.get("mobile_export_source_profile")
        if isinstance(details.get("mobile_export_source_profile"), Mapping)
        else {}
    )
    vendor_manifest_profile = (
        details.get("vendor_export_manifest_profile")
        if isinstance(details.get("vendor_export_manifest_profile"), Mapping)
        else {}
    )
    registry = VENDOR_SCHEMA_REGISTRY.get(source_tool, {})
    normalized_raw = normalize_keys(details.get("raw")) if isinstance(details.get("raw"), Mapping) else {}
    manifest: dict[str, object] = {
        "manifest_version": "mobile-vendor-import-manifest-v1",
        "item_number": 52,
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "artifact_type": artifact_type,
        "source_tool": source_tool,
        "vendor_family": registry.get("family", source_tool),
        "known_vendor_profile": bool(registry),
        "source_format": source_format,
        "source_index": source_index,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_record_id": source_record_id(details, source_index),
        "source_viewer_locator": {
            "viewer": "mobile-vendor-export-row",
            "source_path": str(source_path.resolve()),
            "source_index": source_index,
            "source_record_id": source_record_id(details, source_index),
            "artifact_type": artifact_type,
        },
        "normalized_field_count": len(normalized_raw),
        "normalized_field_sample": sorted(normalized_raw)[:50],
        "schema_registry": {
            "expected_artifacts": list(registry.get("expected_artifacts", ())),
            "required_export_metadata": list(registry.get("required_export_metadata", ())),
            "schema_version": optional_text(details.get("schema_version") or source_profile.get("schema_version")),
            "vendor_tool_version": optional_text(
                source_profile.get("vendor_tool_version") or vendor_manifest_profile.get("vendor_tool_version")
            ),
            "vendor_parser_version": optional_text(
                source_profile.get("vendor_parser_version") or vendor_manifest_profile.get("parser_version")
            ),
            "settings_verified": bool(details.get("validation_checks", {}).get("vendor_export_settings_verified"))
            if isinstance(details.get("validation_checks"), Mapping)
            else False,
            "original_acquisition_hash_verified": bool(
                details.get("validation_checks", {}).get("original_acquisition_hash_verified")
            )
            if isinstance(details.get("validation_checks"), Mapping)
            else False,
        },
        "source_profile": {
            "input_row_count": source_profile.get("input_row_count"),
            "emitted_row_count": source_profile.get("emitted_row_count"),
            "unclassified_or_skipped_row_count": source_profile.get("unclassified_or_skipped_row_count"),
            "vendor_export_manifest_present": bool(source_profile.get("vendor_export_manifest_present") or vendor_manifest_profile),
            "source_hash_matches_manifest": bool(
                source_profile.get("source_hash_matches_manifest")
                or vendor_manifest_profile.get("source_hash_matches_manifest")
            ),
        },
        "large_data_controls": {
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
            "row_cap_recorded": True,
            "raw_values_redacted_by_default": True,
            "text_values_hash_only_by_default": True,
        },
        "commercial_blockers": [
            "per-vendor-schema-version-fixtures-required",
            "trusted-cellebrite-xry-graykey-axiom-export-diff-required",
            "deleted-and-protected-store-boundary-validation-required",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest
