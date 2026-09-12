"""Run input fingerprinting and incremental reuse decisions."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import (
    Mapping,
    Sequence,
)
from pathlib import Path

from ..forensic_accuracy import build_accuracy_gate
from ..incremental import fingerprint_file_index
from .constants import (
    DEFAULT_INCREMENTAL_HASH_MAX_BYTES,
    INCREMENTAL_INDEXING_GAP_ID,
    INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS,
    INCREMENTAL_INDEXING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
)
from .performance import performance_commercial_uplift_evidence

__all__ = [
    "build_incremental_indexing_manifest",
    "build_incremental_indexing_trusted_diff",
    "build_incremental_indexing_validation_plan",
    "build_incremental_reuse_decision_manifest",
    "build_incremental_reuse_plan",
    "build_run_input_fingerprint",
    "hash_incremental_file_content",
    "incremental_file_record_index",
    "incremental_file_records_head_hash",
    "incremental_fingerprint_diff_value",
    "incremental_indexing_assessment",
    "incremental_indexing_core_accuracy_gates",
    "load_or_build_json",
    "load_reusable_json",
    "refresh_incremental_fingerprint_manifest",
]


def load_or_build_json(
    path: Path,
    *,
    resume: bool,
    producer,
    expected_command: str | None = None,
    required_keys: Sequence[str] = (),
) -> tuple[dict[str, object], bool]:
    if resume:
        payload = load_reusable_json(path, expected_command=expected_command, required_keys=required_keys)
        if payload is not None:
            return payload, True
    return producer(), False


def load_reusable_json(
    path: Path,
    *,
    expected_command: str | None,
    required_keys: Sequence[str],
) -> dict[str, object] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if expected_command is not None and payload.get("command") != expected_command:
        return None
    if any(key not in payload for key in required_keys):
        return None
    return payload


def build_run_input_fingerprint(
    root: Path,
    *,
    max_files: int = 5000,
    max_content_hash_bytes: int = DEFAULT_INCREMENTAL_HASH_MAX_BYTES,
) -> dict[str, object]:
    hasher = hashlib.sha256()
    scanned_files = 0
    total_size = 0
    latest_mtime = 0.0
    truncated = False
    file_records: list[dict[str, object]] = []
    content_hashed_count = 0
    content_skipped_count = 0
    content_error_count = 0
    try:
        iterator = root.rglob("*") if root.is_dir() else iter([root])
        for path in iterator:
            if not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            relative = str(path.relative_to(root)) if root.is_dir() else path.name
            normalized_relative = relative.replace("\\", "/")
            content_sha256, hash_status = hash_incremental_file_content(
                path,
                size_bytes=stat.st_size,
                max_content_hash_bytes=max_content_hash_bytes,
            )
            if hash_status == "hashed":
                content_hashed_count += 1
            elif hash_status == "error":
                content_error_count += 1
            else:
                content_skipped_count += 1
            hasher.update(normalized_relative.lower().encode("utf-8", errors="replace"))
            hasher.update(str(stat.st_size).encode("ascii"))
            hasher.update(str(int(stat.st_mtime_ns)).encode("ascii"))
            if content_sha256:
                hasher.update(content_sha256.encode("ascii"))
            file_records.append(
                {
                    "relative_path": normalized_relative,
                    "size_bytes": stat.st_size,
                    "mtime_ns": int(stat.st_mtime_ns),
                    "sha256": content_sha256,
                    "hash_status": hash_status,
                }
            )
            scanned_files += 1
            total_size += stat.st_size
            latest_mtime = max(latest_mtime, stat.st_mtime)
            if max_files and scanned_files >= max_files:
                truncated = True
                break
    except OSError:
        truncated = True
    fingerprint_value = hasher.hexdigest()
    payload: dict[str, object] = {
        "command": "run-fingerprint",
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "fingerprint": fingerprint_value,
        "summary": {
            "scanned_file_count": scanned_files,
            "total_size_bytes": total_size,
            "latest_mtime_epoch": latest_mtime,
            "max_files": max_files,
            "truncated": truncated,
            "content_hash_max_bytes": max_content_hash_bytes,
            "content_hashed_file_count": content_hashed_count,
            "content_hash_skipped_file_count": content_skipped_count,
            "content_hash_error_count": content_error_count,
            "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
            "commercial_grade_ready": False,
        },
        "content_hash_policy": {
            "profile_version": "incremental-content-hash-policy-v1",
            "max_content_hash_bytes": max_content_hash_bytes,
            "hash_algorithm": "sha256",
            "hashed_files": content_hashed_count,
            "skipped_files": content_skipped_count,
            "error_files": content_error_count,
            "large_file_behavior": "metadata-fingerprint-only-when-size-exceeds-policy-limit",
            "commercial_claim_allowed": False,
        },
        "files": file_records,
        "incremental_indexing_assessment": incremental_indexing_assessment(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            content_hashed_files=content_hashed_count,
            content_skipped_files=content_skipped_count,
        ),
        "core_accuracy_gates": incremental_indexing_core_accuracy_gates(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            fingerprint=fingerprint_value,
            reuse_disabled=False,
            content_hashed_files=content_hashed_count,
        ),
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=68,
            validation_ids=[
                "input fingerprint emitted",
                "path/size/mtime metadata captured",
                "bounded per-file content hashes captured",
                "truncation disclosure",
                "per-file reindex limitation warning",
            ],
            large_data_controls=[
                "bounded fingerprint prevents unsafe reuse when source metadata changes",
                "per-file SHA-256 records support changed-file reuse planning for files inside the hash policy",
                "resume disables reuse when the input fingerprint changes",
                "scan count, total bytes, latest mtime, and truncation status are persisted",
                "the evidence explicitly warns that this is not full large-file content-hash delta indexing",
            ],
            external_validation=[
                "full large-file content-hash per-file incremental reindexing",
                "large-case validation on changed multi-million-file evidence roots",
                INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
            ],
        ),
    }
    refresh_incremental_fingerprint_manifest(payload, reuse_disabled=False)
    return payload


def refresh_incremental_fingerprint_manifest(payload: dict[str, object], *, reuse_disabled: bool) -> None:
    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    manifest = build_incremental_indexing_manifest(payload)
    decision_manifest = build_incremental_reuse_decision_manifest(payload, reuse_disabled=reuse_disabled)
    validation_plan = build_incremental_indexing_validation_plan(
        payload,
        manifest=manifest,
        decision_manifest=decision_manifest,
        reuse_disabled=reuse_disabled,
    )
    payload["incremental_indexing_manifest"] = manifest
    payload["incremental_reuse_decision_manifest"] = decision_manifest
    payload["incremental_indexing_report_grade_validation_plan"] = validation_plan
    payload["incremental_indexing_report_grade_validation_plan_hash"] = str(
        validation_plan.get("validation_plan_hash") or ""
    )
    payload["report_grade_ready_slot_count"] = int(validation_plan.get("ready_slot_count") or 0)
    payload["report_grade_blocking_slot_count"] = int(validation_plan.get("blocking_slot_count") or 0)
    payload["incremental_indexing_assessment"] = incremental_indexing_assessment(
        scanned_files=int(summary.get("scanned_file_count") or 0),
        max_files=int(summary.get("max_files") or 0),
        truncated=bool(summary.get("truncated")),
        content_hashed_files=int(summary.get("content_hashed_file_count") or 0),
        content_skipped_files=int(summary.get("content_hash_skipped_file_count") or 0),
        manifest_hash=str(manifest.get("manifest_hash") or ""),
        decision_manifest_hash=str(decision_manifest.get("manifest_hash") or ""),
        validation_plan=validation_plan,
    )
    payload["core_accuracy_gates"] = incremental_indexing_core_accuracy_gates(
        scanned_files=int(summary.get("scanned_file_count") or 0),
        max_files=int(summary.get("max_files") or 0),
        truncated=bool(summary.get("truncated")),
        fingerprint=str(payload.get("fingerprint") or ""),
        reuse_disabled=reuse_disabled,
        content_hashed_files=int(summary.get("content_hashed_file_count") or 0),
        manifest_hash=str(manifest.get("manifest_hash") or ""),
        decision_manifest_hash=str(decision_manifest.get("manifest_hash") or ""),
        validation_plan=validation_plan,
    )


def build_incremental_indexing_manifest(fingerprint_payload: Mapping[str, object]) -> dict[str, object]:
    summary = fingerprint_payload.get("summary") if isinstance(fingerprint_payload.get("summary"), Mapping) else {}
    policy = fingerprint_payload.get("content_hash_policy") if isinstance(fingerprint_payload.get("content_hash_policy"), Mapping) else {}
    files = fingerprint_payload.get("files") if isinstance(fingerprint_payload.get("files"), list) else []
    reuse_plan = (
        fingerprint_payload.get("incremental_reuse_plan")
        if isinstance(fingerprint_payload.get("incremental_reuse_plan"), Mapping)
        else {}
    )
    manifest_core = {
        "profile_version": "incremental-indexing-manifest-v1",
        "item_number": 30,
        "gap_id": "#30",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "fingerprint": str(fingerprint_payload.get("fingerprint") or ""),
        "root_sha256": hashlib.sha256(
            str(fingerprint_payload.get("root") or "").encode("utf-8", errors="replace")
        ).hexdigest(),
        "scanned_file_count": int(summary.get("scanned_file_count") or 0),
        "total_size_bytes": int(summary.get("total_size_bytes") or 0),
        "max_files": int(summary.get("max_files") or 0),
        "truncated": bool(summary.get("truncated")),
        "content_hash_max_bytes": int(summary.get("content_hash_max_bytes") or 0),
        "content_hashed_file_count": int(summary.get("content_hashed_file_count") or 0),
        "content_hash_skipped_file_count": int(summary.get("content_hash_skipped_file_count") or 0),
        "content_hash_error_count": int(summary.get("content_hash_error_count") or 0),
        "file_record_count": len(files),
        "file_record_head_hash": incremental_file_records_head_hash(files),
        "content_hash_policy_hash": hashlib.sha256(
            json.dumps(dict(policy), sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "reuse_plan_hash": hashlib.sha256(
            json.dumps(dict(reuse_plan), sort_keys=True).encode("utf-8")
        ).hexdigest()
        if reuse_plan
        else "",
        "resume_requested": bool(reuse_plan.get("resume_requested")) if reuse_plan else False,
        "resume_effective": bool(reuse_plan.get("resume_effective")) if reuse_plan else False,
        "resume_disabled_reason": str(reuse_plan.get("resume_disabled_reason") or "") if reuse_plan else "",
        "reindex_recommendation": str(reuse_plan.get("reindex_recommendation") or "fresh-run-no-prior-fingerprint"),
        "decision_model": "safe-full-stage-reuse-only-when-input-fingerprint-and-stage-checkpoints-match",
        "row_level_delta_reindexing": False,
        "required_external_evidence": [
            "multi-million-file changed-source replay validation",
            "large-file full content-hash delta indexing validation",
            "trusted incremental reuse manifest diff",
        ],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_incremental_reuse_decision_manifest(
    fingerprint_payload: Mapping[str, object],
    *,
    reuse_disabled: bool,
) -> dict[str, object]:
    reuse_plan = (
        fingerprint_payload.get("incremental_reuse_plan")
        if isinstance(fingerprint_payload.get("incremental_reuse_plan"), Mapping)
        else {}
    )
    rows: list[dict[str, object]] = []
    if reuse_plan:
        for change_type, decision, paths in (
            ("added", "rebuild-affected-stages", reuse_plan.get("added")),
            ("removed", "rebuild-affected-stages", reuse_plan.get("removed")),
            ("changed", "rebuild-affected-stages", reuse_plan.get("changed")),
            ("metadata-only", "verify-or-rebuild-affected-stages", reuse_plan.get("metadata_only")),
            ("unchanged-sample", "reuse-eligible-at-stage-level", reuse_plan.get("unchanged_sample")),
        ):
            if not isinstance(paths, list):
                continue
            for path in paths[:500]:
                row_core = {
                    "relative_path": str(path),
                    "change_type": change_type,
                    "reuse_decision": decision,
                    "row_level_delta_reindexing": False,
                }
                rows.append(
                    {
                        **row_core,
                        "row_hash": hashlib.sha256(
                            json.dumps(row_core, sort_keys=True).encode("utf-8")
                        ).hexdigest(),
                    }
                )
    else:
        row_core = {
            "relative_path": "",
            "change_type": "fresh-run",
            "reuse_decision": "no-prior-fingerprint",
            "row_level_delta_reindexing": False,
        }
        rows.append(
            {
                **row_core,
                "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
            }
        )
    row_hashes = [str(row["row_hash"]) for row in rows]
    row_head_hash = hashlib.sha256("\n".join(row_hashes).encode("ascii")).hexdigest()
    manifest_core = {
        "profile_version": "incremental-reuse-decision-manifest-v1",
        "item_number": 68,
        "gap_id": INCREMENTAL_INDEXING_GAP_ID,
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "fingerprint": str(fingerprint_payload.get("fingerprint") or ""),
        "previous_fingerprint": str(reuse_plan.get("previous_fingerprint") or "") if reuse_plan else "",
        "current_fingerprint": str(reuse_plan.get("current_fingerprint") or fingerprint_payload.get("fingerprint") or ""),
        "resume_requested": bool(reuse_plan.get("resume_requested")) if reuse_plan else False,
        "resume_effective": bool(reuse_plan.get("resume_effective")) if reuse_plan else False,
        "reuse_disabled": reuse_disabled,
        "resume_disabled_reason": str(reuse_plan.get("resume_disabled_reason") or "") if reuse_plan else "",
        "reindex_recommendation": str(reuse_plan.get("reindex_recommendation") or "fresh-run-no-prior-fingerprint"),
        "counts": dict(reuse_plan.get("counts") or {}) if isinstance(reuse_plan.get("counts"), Mapping) else {},
        "decision_row_count": len(rows),
        "decision_row_head_hash": row_head_hash,
        "decision_rows": rows,
        "decision_policy": {
            "safe_to_reuse_outputs": bool(
                reuse_plan and reuse_plan.get("reindex_recommendation") == "safe-to-reuse-stage-outputs"
            ),
            "changed_source_disables_stage_reuse": reuse_disabled,
            "whole_stage_reuse_only": True,
            "row_level_delta_reindexing": False,
            "large_file_metadata_only_paths_are_not_content_complete": True,
        },
        "required_external_evidence": [
            "row-level per-file content-hash delta reindex validation",
            "large-case changed-source replay validation",
            "trusted incremental reuse manifest diff",
        ],
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def build_incremental_indexing_validation_plan(
    fingerprint_payload: Mapping[str, object],
    *,
    manifest: Mapping[str, object],
    decision_manifest: Mapping[str, object],
    reuse_disabled: bool,
) -> dict[str, object]:
    summary = fingerprint_payload.get("summary") if isinstance(fingerprint_payload.get("summary"), Mapping) else {}
    content_policy = (
        fingerprint_payload.get("content_hash_policy")
        if isinstance(fingerprint_payload.get("content_hash_policy"), Mapping)
        else {}
    )

    def slot_hash(slot_core: Mapping[str, object]) -> str:
        return hashlib.sha256(json.dumps(dict(slot_core), sort_keys=True).encode("utf-8")).hexdigest()

    ready_slots: list[dict[str, object]] = []
    for slot_id, evidence_ref, evidence_hash, report_use in (
        (
            "incremental-input-fingerprint",
            "rapidtriage-run-fingerprint.json:fingerprint",
            str(fingerprint_payload.get("fingerprint") or ""),
            "Identifies the bounded source state used to permit or deny whole-stage reuse.",
        ),
        (
            "incremental-file-record-head-hash",
            "incremental_indexing_manifest.file_record_head_hash",
            str(manifest.get("file_record_head_hash") or ""),
            "Summarizes path/size/mtime/content-hash rows without embedding every row in reports.",
        ),
        (
            "incremental-content-hash-policy",
            "incremental_indexing_manifest.content_hash_policy_hash",
            str(manifest.get("content_hash_policy_hash") or ""),
            "Discloses that large files beyond the configured byte cap are metadata-only deltas.",
        ),
        (
            "incremental-reuse-plan",
            "incremental_indexing_manifest.reuse_plan_hash",
            str(manifest.get("reuse_plan_hash") or ""),
            "Shows whether the run is fresh, safe whole-stage reuse, or rebuild-required.",
        ),
        (
            "incremental-reuse-decision-rows",
            "incremental_reuse_decision_manifest.decision_row_head_hash",
            str(decision_manifest.get("decision_row_head_hash") or ""),
            "Hashes per-path reuse/rebuild decisions for reviewer traceability.",
        ),
        (
            "incremental-safety-rebuild-policy",
            "incremental_reuse_decision_manifest.decision_policy",
            hashlib.sha256(
                json.dumps(dict(decision_manifest.get("decision_policy") or {}), sort_keys=True).encode("utf-8")
            ).hexdigest(),
            "Confirms changed inputs force rebuild instead of stale-output reuse.",
        ),
    ):
        slot_core = {
            "slot_id": slot_id,
            "status": "ready" if evidence_hash else "ready-empty",
            "evidence_ref": evidence_ref,
            "evidence_hash": evidence_hash,
            "report_use": report_use,
        }
        ready_slots.append({**slot_core, "slot_hash": slot_hash(slot_core)})

    blocking_slots: list[dict[str, object]] = []
    for slot_id, blocker, required_evidence in (
        (
            "incremental-full-large-file-content-delta",
            "full-large-file-content-hash-delta-required",
            "Run evidence where files above the bounded content hash cap are fully hashed and selectively reindexed.",
        ),
        (
            "incremental-row-level-stage-delta",
            "row-level-stage-delta-reindex-required",
            "Parser/output evidence proving changed rows are updated without rebuilding unaffected rows.",
        ),
        (
            "incremental-trusted-reuse-manifest",
            "trusted-incremental-reuse-manifest-required",
            "Diff against an independent trusted reuse manifest for identical and changed inputs.",
        ),
        (
            "incremental-multi-million-file-replay",
            "multi-million-file-replay-validation-required",
            "Replay logs for unchanged and changed roots at large corpus scale.",
        ),
        (
            "incremental-case-db-dedup-validation",
            "case-db-stage-dedup-validation-required",
            "Case DB import evidence proving resumed runs do not duplicate indexed artifacts.",
        ),
        (
            "incremental-cross-platform-fingerprint-semantics",
            "cross-platform-fingerprint-semantics-required",
            "macOS, Windows, and Linux path/mtime/Unicode semantics comparison for identical evidence.",
        ),
    ):
        slot_core = {
            "slot_id": slot_id,
            "status": "blocking-commercial-grade",
            "blocker": blocker,
            "required_evidence": required_evidence,
        }
        blocking_slots.append({**slot_core, "slot_hash": slot_hash(slot_core)})

    plan_core = {
        "profile_version": INCREMENTAL_INDEXING_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 68,
        "gap_id": INCREMENTAL_INDEXING_GAP_ID,
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "fingerprint": str(fingerprint_payload.get("fingerprint") or ""),
        "incremental_indexing_manifest_hash": str(manifest.get("manifest_hash") or ""),
        "incremental_reuse_decision_manifest_hash": str(decision_manifest.get("manifest_hash") or ""),
        "content_hash_policy_hash": str(manifest.get("content_hash_policy_hash") or ""),
        "content_hash_policy_profile": str(content_policy.get("profile_version") or ""),
        "scanned_file_count": int(summary.get("scanned_file_count") or 0),
        "content_hashed_file_count": int(summary.get("content_hashed_file_count") or 0),
        "content_hash_skipped_file_count": int(summary.get("content_hash_skipped_file_count") or 0),
        "reuse_disabled": reuse_disabled,
        "row_level_delta_reindexing": False,
        "whole_stage_reuse_only": True,
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "report_use_warning": (
            "Use this as evidence of bounded fingerprint-controlled whole-stage reuse only; "
            "do not describe it as content-complete row-level incremental indexing."
        ),
    }
    return {
        **plan_core,
        "validation_plan_hash": hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def incremental_file_records_head_hash(records: Sequence[object]) -> str:
    row_hashes: list[str] = []
    for record in records:
        if isinstance(record, Mapping):
            row_hashes.append(hashlib.sha256(json.dumps(dict(record), sort_keys=True).encode("utf-8")).hexdigest())
    return hashlib.sha256("\n".join(row_hashes).encode("ascii")).hexdigest()


def hash_incremental_file_content(
    path: Path,
    *,
    size_bytes: int,
    max_content_hash_bytes: int,
) -> tuple[str | None, str]:
    if max_content_hash_bytes <= 0:
        return None, "disabled"
    if size_bytes > max_content_hash_bytes:
        return None, "size-excluded"
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None, "error"
    return digest.hexdigest(), "hashed"


def build_incremental_reuse_plan(
    previous_fingerprint: Mapping[str, object],
    current_fingerprint: Mapping[str, object],
    *,
    resume_requested: bool,
    resume_effective: bool,
    resume_disabled_reason: str,
) -> dict[str, object]:
    previous_files = incremental_file_record_index(previous_fingerprint)
    current_files = incremental_file_record_index(current_fingerprint)
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
    return {
        "profile_version": "incremental-reuse-plan-v1",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "resume_requested": resume_requested,
        "resume_effective": resume_effective,
        "resume_disabled_reason": resume_disabled_reason,
        "previous_fingerprint": str(previous_fingerprint.get("fingerprint") or ""),
        "current_fingerprint": str(current_fingerprint.get("fingerprint") or ""),
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "metadata_only": len(metadata_only),
        },
        "added": added[:200],
        "removed": removed[:200],
        "changed": changed[:200],
        "metadata_only": metadata_only[:200],
        "unchanged_sample": unchanged[:50],
        "reindex_recommendation": "rebuild-affected-stages" if added or removed or changed else "safe-to-reuse-stage-outputs",
        "ready_for_commercial_claim": False,
        "blockers": [
            "stage outputs are still reused/rebuilt as whole JSON stages, not rewritten at row-level deltas",
            "large files above content_hash_policy.max_content_hash_bytes use metadata-only comparison",
            INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
        ],
    }


def incremental_file_record_index(fingerprint_payload: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    return fingerprint_file_index(fingerprint_payload)


def incremental_indexing_assessment(
    *,
    scanned_files: int,
    max_files: int,
    truncated: bool,
    content_hashed_files: int = 0,
    content_skipped_files: int = 0,
    manifest_hash: str = "",
    decision_manifest_hash: str = "",
    validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    plan = validation_plan or {}
    validation_plan_hash = str(plan.get("validation_plan_hash") or "")
    ready_slot_count = int(plan.get("ready_slot_count") or 0)
    blocking_slot_count = int(plan.get("blocking_slot_count") or 0)
    return {
        "component": "incremental-indexing",
        "status": "fingerprint-based-reuse-enabled",
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "scanned_file_count": scanned_files,
        "fingerprint_max_files": max_files,
        "fingerprint_truncated": truncated,
        "content_hashed_file_count": content_hashed_files,
        "content_hash_skipped_file_count": content_skipped_files,
        "incremental_indexing_manifest_hash": manifest_hash,
        "incremental_reuse_decision_manifest_hash": decision_manifest_hash,
        "incremental_indexing_report_grade_validation_plan_hash": validation_plan_hash,
        "report_grade_ready_slot_count": ready_slot_count,
        "report_grade_blocking_slot_count": blocking_slot_count,
        "ready_for_court_report": False,
        "blockers": [
            "large-files-above-content-hash-policy-still-use-metadata-only-delta",
            "changed-source-disables-stage-reuse-instead-of-row-level-incremental-reindex",
            "case-db-deduplication-and-reindex-policy-require-large-corpus-validation",
            INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
            *INCREMENTAL_INDEXING_REPORT_GRADE_BLOCKERS,
        ],
        "recommended_validation": [
            "Preserve rapidtriage-run-fingerprint.json with resumed run outputs.",
            "Rebuild outputs when the fingerprint changes or when bounded fingerprint truncation is unacceptable.",
            "Attach an independent reuse-manifest diff and multi-million-file replay before making a commercial-grade incremental-indexing claim.",
            "Treat row-level delta reuse as unimplemented until parser output rows can be selectively updated with trusted validation.",
        ],
        "commercial_uplift_evidence": performance_commercial_uplift_evidence(
            item_number=68,
            validation_ids=[
                "input fingerprint emitted",
                "path/size/mtime metadata captured",
                "bounded per-file content hashes captured",
                "incremental indexing report-grade validation plan emitted",
                "incremental indexing report-grade ready slots emitted",
                "per-file reindex limitation warning",
            ],
            large_data_controls=[
                "bounded per-file SHA-256 records allow changed-file reuse planning",
                "scan counts and fingerprint truncation status are visible",
                "changed-source reuse behavior is safety-first rebuild rather than silent reuse",
                "report-grade validation slots separate usable whole-stage reuse evidence from commercial-grade row-level delta requirements",
            ],
            external_validation=[
                "full content-hash delta index and large-case validation remain required",
                "row-level stage delta reindex validation remains required",
                "case-db deduplication validation remains required",
                INCREMENTAL_TRUSTED_DIFF_BLOCKER_68,
            ],
        ),
        "core_accuracy_gates": incremental_indexing_core_accuracy_gates(
            scanned_files=scanned_files,
            max_files=max_files,
            truncated=truncated,
            fingerprint="assessment",
            reuse_disabled=False,
            content_hashed_files=content_hashed_files,
            manifest_hash=manifest_hash,
            decision_manifest_hash=decision_manifest_hash,
            validation_plan=plan,
        ),
    }


def build_incremental_indexing_trusted_diff(
    rapid_fingerprint: Mapping[str, object],
    trusted_fingerprint: Mapping[str, object],
    *,
    trusted_tool: str = "incremental-reuse-manifest",
) -> dict[str, object]:
    rapid_value = incremental_fingerprint_diff_value(rapid_fingerprint)
    trusted_value = incremental_fingerprint_diff_value(trusted_fingerprint)
    mismatched = [
        {"field": key, "rapid": rapid_value[key], "trusted": trusted_value[key]}
        for key in sorted(set(rapid_value).union(trusted_value))
        if rapid_value.get(key) != trusted_value.get(key)
    ]
    status = "pass" if not mismatched else "fail"
    return {
        "profile": "incremental-indexing-trusted-reuse-diff-v1",
        "item_number": 68,
        "trusted_tool": trusted_tool,
        "status": status,
        "mismatched": mismatched,
        "commercial_gap_ids": [INCREMENTAL_INDEXING_GAP_ID],
        "commercial_claim_allowed": status == "pass",
    }


def incremental_fingerprint_diff_value(item: Mapping[str, object]) -> dict[str, object]:
    summary = item.get("summary") if isinstance(item.get("summary"), Mapping) else {}
    manifest = item.get("incremental_indexing_manifest") if isinstance(item.get("incremental_indexing_manifest"), Mapping) else {}
    decision_manifest = (
        item.get("incremental_reuse_decision_manifest")
        if isinstance(item.get("incremental_reuse_decision_manifest"), Mapping)
        else {}
    )
    return {
        "fingerprint": str(item.get("fingerprint") or ""),
        "scanned_file_count": int(summary.get("scanned_file_count") or 0),
        "total_size_bytes": int(summary.get("total_size_bytes") or 0),
        "truncated": bool(summary.get("truncated")),
        "file_record_head_hash": str(manifest.get("file_record_head_hash") or ""),
        "incremental_manifest_hash": str(manifest.get("manifest_hash") or ""),
        "reuse_decision_manifest_hash": str(decision_manifest.get("manifest_hash") or ""),
        "reuse_decision_row_head_hash": str(decision_manifest.get("decision_row_head_hash") or ""),
    }


def incremental_indexing_core_accuracy_gates(
    *,
    scanned_files: int,
    max_files: int,
    truncated: bool,
    fingerprint: str,
    reuse_disabled: bool,
    content_hashed_files: int = 0,
    manifest_hash: str = "",
    decision_manifest_hash: str = "",
    validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["input fingerprint emitted", "path/size/mtime metadata captured", "per-file reindex limitation warning"]
    if content_hashed_files:
        satisfied.append("bounded per-file content hashes captured")
    if manifest_hash:
        satisfied.append("incremental indexing manifest hash emitted")
    if decision_manifest_hash:
        satisfied.append("reuse decision manifest emitted")
    plan = validation_plan or {}
    validation_plan_hash = str(plan.get("validation_plan_hash") or "")
    ready_slot_count = int(plan.get("ready_slot_count") or 0)
    blocking_slot_count = int(plan.get("blocking_slot_count") or 0)
    if validation_plan_hash:
        satisfied.append("incremental indexing report-grade validation plan emitted")
    if ready_slot_count:
        satisfied.append("incremental indexing report-grade ready slots emitted")
    if reuse_disabled:
        satisfied.append("changed-source reuse disabled")
    if truncated or max_files:
        satisfied.append("truncation disclosure")
    evidence_refs = [
        f"fingerprint:{fingerprint}",
        f"scanned_file_count:{scanned_files}",
        f"max_files:{max_files}",
        f"truncated:{truncated}",
        f"content_hashed_files:{content_hashed_files}",
    ]
    if manifest_hash:
        evidence_refs.append(f"incremental_manifest_hash:{manifest_hash}")
    if decision_manifest_hash:
        evidence_refs.append(f"reuse_decision_manifest_hash:{decision_manifest_hash}")
    if validation_plan_hash:
        evidence_refs.append(f"incremental_report_grade_validation_plan_hash:{validation_plan_hash}")
        evidence_refs.append(f"incremental_report_grade_ready_slots:{ready_slot_count}")
        evidence_refs.append(f"incremental_report_grade_blocking_slots:{blocking_slot_count}")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted incremental reuse diff pass")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    return [
        build_accuracy_gate(
            68,
            satisfied_checks=satisfied,
            evidence_refs=evidence_refs,
        )
    ]
