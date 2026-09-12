"""SQLite FTS run optimization manifest and validation plan."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from ..audit import compute_sha256
from .constants import (
    LARGE_SQLITE_FTS_GAP_ID,
    LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS,
    LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74,
)

__all__ = [
    "build_sqlite_fts_run_optimization_manifest",
    "sqlite_fts_report_grade_validation_plan",
    "sqlite_fts_tracked_output_row",
]


def build_sqlite_fts_run_optimization_manifest(*, outputs: Mapping[str, Path]) -> dict[str, object]:
    tracked_output_names = ["docs_index", "docs", "files", "timeline", "summary"]
    tracked_outputs = []
    for name in tracked_output_names:
        path = outputs.get(name)
        if not path:
            tracked_outputs.append(sqlite_fts_tracked_output_row(name=name, status="missing"))
            continue
        if path.is_file():
            tracked_outputs.append(
                sqlite_fts_tracked_output_row(
                    name=name,
                    path=str(path),
                    sha256=compute_sha256(path),
                    size_bytes=path.stat().st_size,
                )
            )
        else:
            tracked_outputs.append(sqlite_fts_tracked_output_row(name=name, path=str(path), status="missing"))
    missing_outputs = sorted(str(item["name"]) for item in tracked_outputs if item.get("status") == "missing")
    row_hashes = [str(item["row_hash"]) for item in tracked_outputs if item.get("row_hash")]
    manifest_core: dict[str, object] = {
        "profile_version": "sqlite-fts-run-optimization-manifest-v1",
        "item_number": 74,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "commercial_claim_allowed": False,
        "tracked_outputs": tracked_outputs,
        "tracked_output_row_count": len(tracked_outputs),
        "tracked_output_row_head_hash": hashlib.sha256("\n".join(row_hashes).encode("utf-8")).hexdigest(),
        "missing_outputs": missing_outputs,
        "optimization_policy": {
            "case_db_wal_pragmas_expected": True,
            "case_db_fts_tables_expected": True,
            "bounded_source_sqlite_preview_expected": True,
            "cursor_pagination_required": True,
            "query_plan_hash_required_for_case_db_viewers": True,
            "ten_million_row_regression_attached": False,
            "deleted_row_wal_replay_validation_attached": False,
        },
        "operator_review_requirements": [
            "Archive Case DB query-plan profiles for large review tables.",
            "Use cursor pagination for artifact/search/timeline APIs.",
            "Do not claim 10M-row performance until hardware regression evidence is attached.",
        ],
        "blockers": [
            LARGE_SQLITE_FTS_TRUSTED_DIFF_BLOCKER_74,
            "10m-row-query-plan-regression-not-attached",
            "deleted-row-wal-replay-validation-not-attached",
        ],
    }
    manifest_core["tracked_output_head_hash"] = hashlib.sha256(
        json.dumps(tracked_outputs, sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_core["manifest_hash"] = hashlib.sha256(
        json.dumps(manifest_core, sort_keys=True).encode("utf-8")
    ).hexdigest()
    validation_plan = sqlite_fts_report_grade_validation_plan(optimization_manifest=manifest_core)
    return {
        **manifest_core,
        "large_sqlite_fts_report_grade_validation_plan": validation_plan,
        "large_sqlite_fts_report_grade_validation_plan_hash": validation_plan["validation_plan_hash"],
        "report_grade_ready_slot_count": validation_plan["ready_slot_count"],
        "report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
    }


def sqlite_fts_report_grade_validation_plan(*, optimization_manifest: Mapping[str, object]) -> dict[str, object]:
    optimization_policy = (
        optimization_manifest.get("optimization_policy")
        if isinstance(optimization_manifest.get("optimization_policy"), Mapping)
        else {}
    )
    manifest_hash = str(optimization_manifest.get("manifest_hash") or "")
    tracked_row_head_hash = str(optimization_manifest.get("tracked_output_row_head_hash") or "")
    tracked_output_head_hash = str(optimization_manifest.get("tracked_output_head_hash") or "")
    tracked_output_count = int(optimization_manifest.get("tracked_output_row_count") or 0)
    policy_hash = hashlib.sha256(json.dumps(dict(optimization_policy), sort_keys=True).encode("utf-8")).hexdigest()
    ready_slots: list[dict[str, object]] = [
        {
            "slot_id": "run-optimization-manifest",
            "status": "ready",
            "evidence_ref": "sqlite_fts_optimization_manifest_hash",
            "evidence_hash": manifest_hash,
            "description": "Run emits a SQLite/FTS optimization manifest for key output stores.",
        },
        {
            "slot_id": "tracked-output-row-hashes",
            "status": "ready",
            "evidence_ref": "tracked_output_row_head_hash",
            "evidence_hash": tracked_row_head_hash,
            "description": "Tracked run outputs are row-hashed for replayable performance evidence.",
        },
        {
            "slot_id": "tracked-output-content-hash",
            "status": "ready",
            "evidence_ref": "tracked_output_head_hash",
            "evidence_hash": tracked_output_head_hash,
            "description": "Tracked output content fingerprints are summarized for regression comparison.",
        },
        {
            "slot_id": "cursor-pagination-policy",
            "status": "ready",
            "evidence_ref": "optimization_policy.cursor_pagination_required",
            "evidence_hash": hashlib.sha256(
                str(bool(optimization_policy.get("cursor_pagination_required"))).encode("ascii")
            ).hexdigest(),
            "description": "Run policy requires cursor pagination for large artifact/search/timeline surfaces.",
        },
        {
            "slot_id": "query-plan-requirement",
            "status": "ready",
            "evidence_ref": "optimization_policy.query_plan_hash_required_for_case_db_viewers",
            "evidence_hash": hashlib.sha256(
                str(bool(optimization_policy.get("query_plan_hash_required_for_case_db_viewers"))).encode("ascii")
            ).hexdigest(),
            "description": "Case DB/source SQLite viewers must expose query-plan hashes before report use.",
        },
        {
            "slot_id": "sqlite-policy-profile",
            "status": "ready",
            "evidence_ref": "optimization_policy_hash",
            "evidence_hash": policy_hash,
            "description": "Optimization policy records WAL/FTS expectations, bounded previews, and blocker flags.",
        },
    ]
    blocking_slots: list[dict[str, object]] = [
        {
            "slot_id": "trusted-query-plan-manifest",
            "status": "blocked",
            "blocker": "trusted-large-sqlite-fts-query-plan-manifest-required",
            "required_evidence": "trusted query-plan manifest diff for Case DB and source SQLite viewers",
        },
        {
            "slot_id": "10m-row-query-plan-regression",
            "status": "blocked",
            "blocker": "10m-row-query-plan-regression-required",
            "required_evidence": "10M-row query-plan and latency regression evidence on release hardware",
        },
        {
            "slot_id": "deleted-row-wal-replay",
            "status": "blocked",
            "blocker": "deleted-row-wal-replay-validation-required",
            "required_evidence": "WAL/deleted-row replay corpus with expected row recovery and non-recovery states",
        },
        {
            "slot_id": "large-source-db-corpus",
            "status": "blocked",
            "blocker": "large-source-db-corpus-required",
            "required_evidence": "large source SQLite corpus covering multi-GB DBs, indexes, FTS, and corrupt pages",
        },
        {
            "slot_id": "browser-pagination-query-plan-e2e",
            "status": "blocked",
            "blocker": "browser-pagination-query-plan-e2e-required",
            "required_evidence": "browser E2E evidence that large SQLite/table pages stay cursor-paged and bounded",
        },
        {
            "slot_id": "index-maintenance-vacuum-regression",
            "status": "blocked",
            "blocker": "index-maintenance-vacuum-regression-required",
            "required_evidence": "index maintenance, PRAGMA optimize, and vacuum/rebuild regression run logs",
        },
    ]
    plan_core = {
        "profile_version": LARGE_SQLITE_FTS_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 74,
        "gap_id": LARGE_SQLITE_FTS_GAP_ID,
        "commercial_gap_ids": [LARGE_SQLITE_FTS_GAP_ID],
        "scope": "run-sqlite-fts-optimization",
        "optimization_manifest_hash": manifest_hash,
        "tracked_output_row_count": tracked_output_count,
        "tracked_output_row_head_hash": tracked_row_head_hash,
        "tracked_output_head_hash": tracked_output_head_hash,
        "optimization_policy_hash": policy_hash,
        "case_db_wal_pragmas_expected": bool(optimization_policy.get("case_db_wal_pragmas_expected")),
        "case_db_fts_tables_expected": bool(optimization_policy.get("case_db_fts_tables_expected")),
        "bounded_source_sqlite_preview_expected": bool(
            optimization_policy.get("bounded_source_sqlite_preview_expected")
        ),
        "cursor_pagination_required": bool(optimization_policy.get("cursor_pagination_required")),
        "ten_million_row_regression_attached": bool(
            optimization_policy.get("ten_million_row_regression_attached")
        ),
        "deleted_row_wal_replay_validation_attached": bool(
            optimization_policy.get("deleted_row_wal_replay_validation_attached")
        ),
        "ready_slots": ready_slots,
        "blocking_slots": blocking_slots,
        "ready_slot_count": len(ready_slots),
        "blocking_slot_count": len(blocking_slots),
        "blockers": list(LARGE_SQLITE_FTS_REPORT_GRADE_BLOCKERS),
        "commercial_claim_allowed": False,
        "ready_for_court_report": False,
        "report_use_warning": "Use as Mac-local SQLite/FTS optimization evidence only until trusted query-plan, WAL/deleted-row, and 10M-row regression evidence are attached.",
    }
    validation_plan_hash = hashlib.sha256(json.dumps(plan_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        **plan_core,
        "validation_plan_hash": validation_plan_hash,
        "validation_plan_sha256": validation_plan_hash,
    }


def sqlite_fts_tracked_output_row(
    *,
    name: str,
    path: str = "",
    sha256: str = "",
    size_bytes: int = 0,
    status: str = "present",
) -> dict[str, object]:
    row_core = {
        "name": name,
        "path": path,
        "status": status,
        "sha256": sha256,
        "size_bytes": size_bytes,
    }
    return {
        **row_core,
        "row_hash": hashlib.sha256(json.dumps(row_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }
