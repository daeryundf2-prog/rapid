"""Console review-mark helpers over the run's case DB.

Locator <-> case-DB row resolution lives in :mod:`core.case_db.run_locator`;
this module adds the console's batch-target parsing and the review-board
entries (titles, analysis-row labels).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path

from fastapi import HTTPException

from ...core.case_db.helpers import parse_json_object
from ...core.case_db.review import load_review_target_match
from ...core.case_db.review_conflict import (
    ACTIVE_MARK_SQL,
    EXPECTATION_KEYS,
    ReviewConflictError,
)
from ...core.case_db.review_verdict import verdict_select_sql
from ...core.case_db.run_locator import (
    ANALYSIS_ROW_TARGET,
    RunLocatorIndex,
)
from ...core.case_db.schema import artifact_data_select_sql, artifact_row_data_json


def split_batch_targets(
    targets: Iterable[Mapping[str, object]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Separate ``{target_type, target_id}`` targets from run-locator targets (expectations kept)."""
    direct: list[dict[str, str]] = []
    located: list[dict[str, str]] = []
    for target in targets:
        if target.get("target_type") and target.get("target_id"):
            entry = {"target_type": str(target["target_type"]), "target_id": str(target["target_id"])}
            for key in EXPECTATION_KEYS:
                if target.get(key) is not None:
                    entry[key] = str(target[key])
            direct.append(entry)
        else:
            located.append({key: str(value) for key, value in target.items() if value is not None})
    return direct, located


def review_conflict_http_error(exc: ReviewConflictError) -> HTTPException:
    """409 with every conflicting target, its current mark and what changed since; nothing was written."""
    return HTTPException(
        status_code=409,
        detail={"code": "review-conflict", "message": str(exc), "conflicts": exc.conflicts},
    )


def analysis_row_entries(output_dir: Path | None, target_ids: Iterable[str]) -> dict[str, dict[str, object]]:
    """Board fields of ``analysis_row`` marks by target id: human ``title``, ``path``, ``target_kind`` ("카빙 결과").

    Rows are read from ``analyses/<id>/rows.jsonl`` of the run output, one
    pass per analysis; a row that can no longer be read keeps a Korean
    fallback title (never the raw ``<analysis_id>/<n>`` id).
    """
    from .analyses import read_analysis_rows
    from .analysis_kinds import analysis_kind_label, analysis_row_title

    wanted: dict[str, set[int]] = {}
    for target_id in target_ids:
        analysis_id, _, index = target_id.partition("/")
        if index.isdigit():
            wanted.setdefault(analysis_id, set()).add(int(index))
    result: dict[str, dict[str, object]] = {}
    for analysis_id, indices in wanted.items():
        state, rows = read_analysis_rows(output_dir, analysis_id, indices) if output_dir is not None else (None, {})
        kind = str((state or {}).get("kind") or "")
        for record_index in indices:
            row = rows.get(record_index)
            key = f"{analysis_id}/{record_index}"
            if state is None or row is None:
                result[key] = {
                    "title": f"분석 결과 행 #{record_index} (읽을 수 없음)",
                    "target_kind": analysis_kind_label(kind) if kind else "분석 결과",
                    "analysis_kind": kind,
                }
                continue
            details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
            result[key] = {
                "title": analysis_row_title(kind, row, record_index),
                "path": str(row.get("path") or details.get("source_path") or ""),
                "preview": "",
                "timestamp": str(details.get("timestamp") or details.get("modified_at") or state.get("finished_at") or ""),
                "target_kind": analysis_kind_label(kind),
                "analysis_kind": kind,
            }
    return result


def review_map_entries(
    connection: sqlite3.Connection,
    case_id: str,
    outputs: Mapping[str, object],
    *,
    limit: int,
    output_dir: Path | None = None,
) -> tuple[list[dict[str, object]], bool]:
    """Every review mark of the case with its run-output locator (when known).

    Each mark names who last wrote it and when (``reviewer``, ``created_at``, ``updated_at``), who
    set its verdict and when (``status_by``, ``status_at``; P2-1), how many times it changed
    (``change_count``, its ``review_mark_history`` versions; F13) and its version token
    (``version``: a write sends it back as ``expected_version``; F14).
    """
    index = RunLocatorIndex(connection, case_id, outputs, output_dir=output_dir)
    rows = connection.execute(
        "SELECT citation_id, target_type, target_id, status, tags_json, note, include_in_report, updated_at, "
        f"reviewer, created_at, {verdict_select_sql(connection)}, "
        "(SELECT COALESCE(MAX(h.version), 0) FROM review_mark_history h WHERE h.case_id = review_mark.case_id "
        "AND h.target_type = review_mark.target_type AND h.target_id = review_mark.target_id) "
        f"FROM review_mark WHERE case_id = ? AND {ACTIVE_MARK_SQL} ORDER BY updated_at DESC, id DESC LIMIT ?",
        (case_id, limit + 1),
    ).fetchall()
    truncated = len(rows) > limit
    entries: list[dict[str, object]] = []
    analysis_entries: list[dict[str, object]] = []
    artifact_columns: str | None = None
    for row in rows[:limit]:
        try:
            tags = json.loads(str(row[4] or "[]"))
        except json.JSONDecodeError:
            tags = []
        target_type, target_id = str(row[1]), str(row[2])
        entry: dict[str, object] = {
            "citation_id": str(row[0]),
            "target_type": target_type,
            "target_id": target_id,
            "status": str(row[3]),
            "tags": [str(tag) for tag in tags] if isinstance(tags, list) else [],
            "note": str(row[5] or ""),
            "include_in_report": bool(row[6]),
            "updated_at": str(row[7] or ""),
            "reviewer": str(row[8] or ""),
            "created_at": str(row[9] or ""),
            "status_by": str(row[10] or ""),
            "status_at": str(row[11] or ""),
            # Listed marks are active, so the token is the newest history version (P3-1).
            "change_count": int(row[12] or 0),
            "version": int(row[12] or 0),
            "collection": "",
            "kind": "",
            "locator": "",
        }
        location = index.locate(target_type, target_id)
        if location is not None:
            entry.update(location)
        if target_type == ANALYSIS_ROW_TARGET:
            analysis_entries.append(entry)
            entries.append(entry)
            continue
        match = load_review_target_match(connection, case_id, target_type=target_type, target_id=target_id)
        if match is not None:
            entry["title"] = str(match.get("title") or "")
            entry["path"] = str(match.get("path") or "")
            entry["preview"] = str(match.get("preview") or "")
            entry["timestamp"] = str(match.get("timestamp") or "")
            entry["target_kind"] = str(match.get("kind") or "")
            metadata = match.get("metadata")
            if target_type == "file_record" and isinstance(metadata, Mapping):
                # A file has no event time; the board shows the copy's mtime as such (F12).
                entry["file_modified_at"] = str(metadata.get("modified_at") or "")
            elif target_type == "artifact" and not entry["timestamp"]:
                if artifact_columns is None:
                    artifact_columns = artifact_data_select_sql(connection)
                entry["timestamp"] = _artifact_record_time(connection, artifact_columns, target_id)
        entries.append(entry)
    if analysis_entries:
        labels = analysis_row_entries(output_dir, [str(entry["target_id"]) for entry in analysis_entries])
        for entry in analysis_entries:
            entry.update(labels.get(str(entry["target_id"]), {}))
    return entries, truncated


def _artifact_record_time(connection: sqlite3.Connection, columns: str, target_id: str) -> str:
    """The artifact record's own ``timestamp`` (its event time), "" when it has none."""
    if not target_id.isdigit():
        return ""
    row = connection.execute(f"SELECT {columns} FROM artifact WHERE id = ?", (int(target_id),)).fetchone()
    if row is None:
        return ""
    data = parse_json_object(artifact_row_data_json(row))
    return str(data.get("timestamp") or "")
