"""Evidence-level incremental ingest for run checkpoint/resume (R-7c).

The stage-level checkpoint contract reuses a whole JSON stage output only when
the persisted input fingerprint is unchanged. This module adds a bounded
per-file delta layer on top of that contract: when the fingerprint changes and
``--resume`` is requested, files that are unchanged by path+size+mtime (or by
their bounded content hash) keep their prior artifact rows, and only
added/changed files are recollected inside a materialized delta-scope
directory. Removed files drop their prior rows.

Run profiles are unchanged; the delta layer only engages when a previous
fingerprint with per-file records exists for the same resolved root.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .docs import write_result

__all__ = [
    "EVIDENCE_DELTA_MANIFEST_NAME",
    "EVIDENCE_DELTA_PROFILE_VERSION",
    "EVIDENCE_DELTA_SCOPE_DIR_NAME",
    "EVIDENCE_DELTA_SCOPE_MANIFEST_NAME",
    "EvidenceDeltaContext",
    "artifact_record_relative_path",
    "build_evidence_delta",
    "build_evidence_delta_manifest",
    "fingerprint_file_index",
    "materialize_delta_scope",
    "merge_delta_artifact_payload",
    "merge_delta_files_payload",
    "rewrite_scoped_paths",
]

EVIDENCE_DELTA_MANIFEST_NAME = "rapidtriage-run-evidence-delta.json"
EVIDENCE_DELTA_SCOPE_DIR_NAME = "incremental-delta-scope"
EVIDENCE_DELTA_SCOPE_MANIFEST_NAME = "rapidtriage-incremental-delta-scope.json"
EVIDENCE_DELTA_PROFILE_VERSION = "evidence-delta-ingest-v1"
EVIDENCE_DELTA_MAX_SCOPE_FILES = 5000
_EVIDENCE_DELTA_LIST_CAP = 1000


@dataclass(frozen=True)
class EvidenceDeltaContext:
    """Resolved per-file delta between the previous and current fingerprints."""

    scope_root: Path
    source_root: Path
    scope_file_count: int
    added: frozenset[str]
    removed: frozenset[str]
    changed: frozenset[str]
    unchanged: frozenset[str]
    files_delta_enabled: bool
    artifacts_delta_enabled: bool
    blockers: tuple[str, ...]
    scope_manifest: Mapping[str, object]


def fingerprint_file_index(payload: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    records = payload.get("files")
    if not isinstance(records, list):
        return {}
    indexed: dict[str, Mapping[str, object]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            continue
        relative_path = str(record.get("relative_path") or "")
        if relative_path:
            indexed[relative_path] = record
    return indexed


def _fingerprint_summary(payload: Mapping[str, object]) -> Mapping[str, object]:
    summary = payload.get("summary")
    return summary if isinstance(summary, Mapping) else {}


def build_evidence_delta(
    previous_fingerprint: Mapping[str, object],
    current_fingerprint: Mapping[str, object],
) -> dict[str, object]:
    """Diff two run input fingerprints into per-file delta sets."""
    blockers: list[str] = []
    previous_files = fingerprint_file_index(previous_fingerprint)
    current_files = fingerprint_file_index(current_fingerprint)
    previous_root = str(previous_fingerprint.get("root") or "")
    current_root = str(current_fingerprint.get("root") or "")
    previous_truncated = bool(_fingerprint_summary(previous_fingerprint).get("truncated"))
    current_truncated = bool(_fingerprint_summary(current_fingerprint).get("truncated"))
    if not previous_files:
        blockers.append("previous fingerprint has no per-file records")
    if not current_files:
        blockers.append("current fingerprint has no per-file records")
    if not previous_root or previous_root != current_root:
        blockers.append("fingerprinted input root changed between runs")
    if previous_truncated or current_truncated:
        blockers.append("fingerprint scan truncated; per-file delta is unsafe")

    added = sorted(path for path in current_files if path not in previous_files)
    removed = sorted(path for path in previous_files if path not in current_files)
    changed: list[str] = []
    unchanged: list[str] = []
    metadata_only: list[str] = []
    for path in sorted(set(previous_files).intersection(current_files)):
        previous = previous_files[path]
        current = current_files[path]
        previous_hash = str(previous.get("sha256") or "")
        current_hash = str(current.get("sha256") or "")
        if previous_hash and current_hash:
            if previous_hash == current_hash:
                unchanged.append(path)
            else:
                changed.append(path)
            continue
        metadata_changed = (
            int(previous.get("size_bytes") or 0) != int(current.get("size_bytes") or 0)
            or int(previous.get("mtime_ns") or 0) != int(current.get("mtime_ns") or 0)
        )
        if metadata_changed:
            changed.append(path)
            metadata_only.append(path)
        else:
            unchanged.append(path)
            metadata_only.append(path)

    scope_paths = sorted(set(added) | set(changed))
    if len(scope_paths) > EVIDENCE_DELTA_MAX_SCOPE_FILES:
        blockers.append("changed-file scope exceeds the evidence delta cap")

    return {
        "profile_version": EVIDENCE_DELTA_PROFILE_VERSION,
        "usable": not blockers,
        "blockers": blockers,
        "previous_fingerprint": str(previous_fingerprint.get("fingerprint") or ""),
        "current_fingerprint": str(current_fingerprint.get("fingerprint") or ""),
        "fingerprinted_root": current_root,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "metadata_only": len(metadata_only),
            "scope": len(scope_paths),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "metadata_only": metadata_only[:_EVIDENCE_DELTA_LIST_CAP],
        "unchanged_sample": unchanged[:50],
        "scope_paths": scope_paths,
        "unchanged_paths": unchanged,
        "delta_model": "unchanged rows reused; added/changed files recollected inside a materialized scope directory",
        "commercial_claim_allowed": False,
    }


def materialize_delta_scope(
    source_root: Path,
    scope_dir: Path,
    scope_paths: Sequence[str],
    *,
    max_files: int = EVIDENCE_DELTA_MAX_SCOPE_FILES,
) -> dict[str, object]:
    """Hardlink (or copy) changed/added files into a dedicated scope directory.

    The scope manifest is written next to the scope directory, never inside it,
    so artifact collectors scanning the scope root never ingest the manifest.
    """
    scope_dir = scope_dir.expanduser().resolve()
    if scope_dir.exists():
        shutil.rmtree(scope_dir)
    scope_dir.mkdir(parents=True, exist_ok=True)
    source_root = source_root.expanduser().resolve()
    entries: list[dict[str, object]] = []
    skipped: list[dict[str, str]] = []
    truncated = False
    for relative_path in scope_paths:
        if len(entries) >= max_files:
            truncated = True
            break
        rel = Path(str(relative_path))
        if rel.is_absolute() or ".." in rel.parts:
            skipped.append({"relative_path": str(relative_path), "reason": "unsafe-path"})
            continue
        source = source_root / rel
        destination = scope_dir / rel
        if not source.is_file():
            skipped.append({"relative_path": str(relative_path), "reason": "missing"})
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        link_kind = "hardlink"
        try:
            os.link(source, destination)
        except OSError:
            try:
                shutil.copy2(source, destination)
                link_kind = "copy"
            except OSError:
                skipped.append({"relative_path": str(relative_path), "reason": "link-failed"})
                continue
        try:
            size_bytes = destination.stat().st_size
        except OSError:
            size_bytes = 0
        entries.append(
            {
                "relative_path": str(relative_path),
                "size_bytes": size_bytes,
                "link_kind": link_kind,
            }
        )
    manifest = {
        "command": "evidence-delta-scope",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_root": str(source_root),
        "scope_root": str(scope_dir),
        "file_count": len(entries),
        "truncated": truncated,
        "entries": entries,
        "skipped": skipped,
        "commercial_claim_allowed": False,
    }
    write_result(manifest, scope_dir.parent / EVIDENCE_DELTA_SCOPE_MANIFEST_NAME)
    return manifest


def _normalize_relative(path: str) -> str:
    return path.replace("\\", "/").lstrip("/")


def _relative_to_root(path_value: object, source_root: Path) -> str | None:
    text = str(path_value or "").strip()
    if not text:
        return None
    candidate = Path(text)
    if candidate.is_absolute():
        try:
            return _normalize_relative(str(candidate.resolve().relative_to(source_root)))
        except (OSError, ValueError):
            return None
    return _normalize_relative(text)


def artifact_record_relative_path(row: object, source_root: Path) -> str | None:
    """Best-effort source path for an artifact record relative to its root."""
    if not isinstance(row, Mapping):
        return None
    record = row.get("artifact_record")
    record_source = record.get("source") if isinstance(record, Mapping) else None
    details = row.get("details")
    details_source = details.get("source_path") if isinstance(details, Mapping) else None
    for value in (
        row.get("path"),
        details_source,
        record_source.get("source_path") if isinstance(record_source, Mapping) else None,
    ):
        relative = _relative_to_root(value, source_root)
        if relative:
            return relative
    return None


def file_candidate_relative_path(row: object, source_root: Path) -> str | None:
    if not isinstance(row, Mapping):
        return None
    return _relative_to_root(row.get("path"), source_root)


def rewrite_scoped_paths(
    value: object,
    *,
    scope_root: Path,
    source_root: Path,
) -> object:
    """Rewrite absolute paths collected under the scope dir back to the real root."""
    scope_text = str(scope_root)
    source_text = str(source_root)
    if isinstance(value, Mapping):
        return {
            str(key): rewrite_scoped_paths(item, scope_root=scope_root, source_root=source_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            rewrite_scoped_paths(item, scope_root=scope_root, source_root=source_root)
            for item in value
        ]
    if isinstance(value, str):
        if value == scope_text:
            return source_text
        if value.startswith(scope_text + os.sep):
            return source_text + value[len(scope_text):]
    return value


def _reuse_decision(relative: str | None, delta: EvidenceDeltaContext) -> str:
    if relative is None:
        return "recollected-in-delta-scope"
    if relative in delta.changed:
        return "recollected-changed-evidence"
    if relative in delta.added:
        return "recollected-added-evidence"
    return "recollected-in-delta-scope"


def merge_delta_artifact_payload(
    previous: Mapping[str, object],
    delta_payload: Mapping[str, object] | None,
    *,
    delta: EvidenceDeltaContext,
) -> dict[str, object]:
    """Merge prior artifact rows for unchanged files with delta-scope rows."""
    source_root = delta.source_root
    scope_root = delta.scope_root
    kept: list[object] = []
    reused_count = 0
    dropped_count = 0
    unbound_previous: list[Mapping[str, object]] = []
    previous_rows = previous.get("artifacts") if isinstance(previous.get("artifacts"), list) else []
    for row in previous_rows:
        relative = artifact_record_relative_path(row, source_root)
        if relative is None:
            if isinstance(row, Mapping):
                unbound_previous.append(row)
            continue
        if relative in delta.unchanged:
            merged_row = dict(row)
            merged_row["incremental_reuse"] = {"decision": "reused-unchanged-evidence"}
            kept.append(merged_row)
            reused_count += 1
        else:
            dropped_count += 1

    recollected_count = 0
    delta_unbound_types: set[str] = set()
    delta_rows = (
        delta_payload.get("artifacts")
        if isinstance(delta_payload, Mapping) and isinstance(delta_payload.get("artifacts"), list)
        else []
    )
    for row in delta_rows:
        if not isinstance(row, Mapping):
            kept.append(row)
            continue
        merged_row = dict(
            rewrite_scoped_paths(dict(row), scope_root=scope_root, source_root=source_root)
        )
        relative = artifact_record_relative_path(merged_row, source_root)
        if relative is None:
            delta_unbound_types.add(str(merged_row.get("artifact_type") or ""))
        merged_row["incremental_reuse"] = {"decision": _reuse_decision(relative, delta)}
        kept.append(merged_row)
        recollected_count += 1

    reused_scope_independent = 0
    replaced_scope_independent = 0
    for row in unbound_previous:
        artifact_type = str(row.get("artifact_type") or "")
        if artifact_type and artifact_type in delta_unbound_types:
            replaced_scope_independent += 1
            continue
        merged_row = dict(row)
        merged_row["incremental_reuse"] = {"decision": "reused-scope-independent"}
        kept.append(merged_row)
        reused_scope_independent += 1

    merged = dict(delta_payload) if isinstance(delta_payload, Mapping) else dict(previous)
    merged["artifacts"] = kept
    merged["root"] = str(source_root)
    merged["generated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    type_counts: Counter[str] = Counter()
    for row in kept:
        if isinstance(row, Mapping) and row.get("artifact_type"):
            type_counts[str(row["artifact_type"])] += 1
    previous_errors = (
        previous.get("parser_errors") if isinstance(previous.get("parser_errors"), list) else []
    )
    delta_errors = (
        delta_payload.get("parser_errors")
        if isinstance(delta_payload, Mapping) and isinstance(delta_payload.get("parser_errors"), list)
        else []
    )
    parser_errors = [*previous_errors, *delta_errors]
    merged["parser_errors"] = parser_errors
    summary = dict(merged.get("summary")) if isinstance(merged.get("summary"), Mapping) else {}
    summary["artifact_count"] = len(kept)
    summary["artifact_type_counts"] = dict(type_counts)
    summary["parser_error_count"] = len(parser_errors)
    summary["collection_status"] = "delta-merged"
    merged["summary"] = summary

    contract = (
        dict(merged["artifact_record_contract"])
        if isinstance(merged.get("artifact_record_contract"), Mapping)
        else {"profile_version": "artifact-output-contract-v1"}
    )
    valid_count = sum(
        1 for row in kept if isinstance(row, Mapping) and isinstance(row.get("artifact_record"), Mapping)
    )
    contract["record_count"] = len(kept)
    contract["valid_count"] = valid_count
    contract["invalid_count"] = len(kept) - valid_count
    contract["errors"] = list(contract.get("errors") or [])[:100]
    contract["delta_merged"] = True
    merged["artifact_record_contract"] = contract

    merged["incremental_delta"] = {
        "profile_version": EVIDENCE_DELTA_PROFILE_VERSION,
        "mode": "delta-merged",
        "source_root": str(source_root),
        "scope_root": str(scope_root),
        "scope_file_count": delta.scope_file_count,
        "reused_record_count": reused_count,
        "recollected_record_count": recollected_count,
        "dropped_record_count": dropped_count,
        "reused_scope_independent_count": reused_scope_independent,
        "replaced_scope_independent_count": replaced_scope_independent,
        "note": "rows bound to unchanged evidence paths were reused; the delta scope was recollected",
        "commercial_claim_allowed": False,
    }
    return merged


def merge_delta_files_payload(
    previous: Mapping[str, object],
    delta_payload: Mapping[str, object] | None,
    *,
    delta: EvidenceDeltaContext,
) -> dict[str, object]:
    """Merge prior file candidates for unchanged paths with delta-scope rows."""
    source_root = delta.source_root
    scope_root = delta.scope_root
    kept: list[object] = []
    reused_count = 0
    dropped_count = 0
    previous_rows = previous.get("candidates") if isinstance(previous.get("candidates"), list) else []
    for row in previous_rows:
        relative = file_candidate_relative_path(row, source_root)
        if relative is not None and relative in delta.unchanged:
            merged_row = dict(row)
            merged_row["incremental_reuse"] = {"decision": "reused-unchanged-evidence"}
            kept.append(merged_row)
            reused_count += 1
        else:
            dropped_count += 1

    recollected_count = 0
    delta_rows = (
        delta_payload.get("candidates")
        if isinstance(delta_payload, Mapping) and isinstance(delta_payload.get("candidates"), list)
        else []
    )
    for row in delta_rows:
        if not isinstance(row, Mapping):
            kept.append(row)
            continue
        merged_row = dict(
            rewrite_scoped_paths(dict(row), scope_root=scope_root, source_root=source_root)
        )
        relative = file_candidate_relative_path(merged_row, source_root)
        merged_row["incremental_reuse"] = {"decision": _reuse_decision(relative, delta)}
        kept.append(merged_row)
        recollected_count += 1

    merged = dict(delta_payload) if isinstance(delta_payload, Mapping) else dict(previous)
    merged["candidates"] = kept
    merged["root"] = str(source_root)
    merged["generated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()

    category_counts: Counter[str] = Counter()
    modified_values: list[str] = []
    for row in kept:
        if not isinstance(row, Mapping):
            continue
        categories = row.get("categories")
        if isinstance(categories, list):
            for category in categories:
                category_counts[str(category)] += 1
        modified = str(row.get("modified_at") or "")
        if modified:
            modified_values.append(modified)
    summary = dict(merged.get("summary")) if isinstance(merged.get("summary"), Mapping) else {}
    delta_scanned = (
        int(summary.get("scanned_file_count") or 0)
        if isinstance(delta_payload, Mapping)
        else 0
    )
    summary["candidate_count"] = len(kept)
    summary["raw_candidate_count"] = reused_count + recollected_count
    summary["category_counts"] = dict(category_counts)
    summary["scanned_file_count"] = delta_scanned + len(delta.unchanged)
    summary["newest_modified_at"] = max(modified_values) if modified_values else None
    summary["oldest_modified_at"] = min(modified_values) if modified_values else None
    merged["summary"] = summary

    merged["incremental_delta"] = {
        "profile_version": EVIDENCE_DELTA_PROFILE_VERSION,
        "mode": "delta-merged",
        "source_root": str(source_root),
        "scope_root": str(scope_root),
        "scope_file_count": delta.scope_file_count,
        "reused_candidate_count": reused_count,
        "recollected_candidate_count": recollected_count,
        "dropped_candidate_count": dropped_count,
        "scope_limited_fields": [
            "duplicate_content_manifest",
            "duplicate_content_groups",
            "fuzzy_text_duplicate_groups",
            "file_signature_profile",
            "signature_mismatch_candidates",
            "known_good_suppression_profile",
            "known_good_suppressed_candidates",
            "duplicate_detection_assessment",
        ],
        "note": "duplicate/signature/known-good aggregates reflect the delta scope plus reused rows",
        "commercial_claim_allowed": False,
    }
    return merged


def build_evidence_delta_manifest(
    *,
    delta: Mapping[str, object],
    context: EvidenceDeltaContext | None,
    output_dir: Path,
    files_stage: Mapping[str, object] | None,
    artifact_stages: Mapping[str, object],
    resume_requested: bool,
) -> dict[str, object]:
    """Persist the evidence-delta decision manifest into the run output dir."""
    stage_entries: list[dict[str, object]] = []
    if files_stage is not None:
        files_delta = files_stage.get("incremental_delta")
        stage_entries.append(
            {
                "stage": "files",
                "delta_merged": isinstance(files_delta, Mapping),
                "stats": dict(files_delta) if isinstance(files_delta, Mapping) else {},
            }
        )
    for kind in sorted(artifact_stages):
        payload = artifact_stages[kind]
        stage_delta = payload.get("incremental_delta") if isinstance(payload, Mapping) else None
        stage_entries.append(
            {
                "stage": f"artifacts-{kind}",
                "delta_merged": isinstance(stage_delta, Mapping),
                "stats": dict(stage_delta) if isinstance(stage_delta, Mapping) else {},
            }
        )
    manifest = {
        "command": "evidence-delta",
        "profile_version": EVIDENCE_DELTA_PROFILE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "output_dir": str(output_dir),
        "resume_requested": resume_requested,
        "delta": dict(delta) if isinstance(delta, Mapping) else {},
        "usable": bool(delta.get("usable")) if isinstance(delta, Mapping) else False,
        "files_delta_enabled": bool(context and context.files_delta_enabled),
        "artifacts_delta_enabled": bool(context and context.artifacts_delta_enabled),
        "scope_manifest": dict(context.scope_manifest) if context else {},
        "stages": stage_entries,
        "commercial_claim_allowed": False,
    }
    manifest["manifest_hash"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode("utf-8")
    ).hexdigest()
    write_result(manifest, output_dir / EVIDENCE_DELTA_MANIFEST_NAME)
    return manifest
