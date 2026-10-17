"""Review-tool operations (AXIOM adoption E3, plan §3.3): case tags, tag batches with
hash propagation, histogram baselines and a mark's change history.

Every function takes an open, writable connection on which ``apply_schema``
already ran (``CaseDatabase.connect`` + ``apply_schema``), so one request is
one transaction. Errors are :class:`ReviewToolError` with Korean messages and
an HTTP status hint.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager

from .base import CaseDatabaseError, now_iso
from .constants import REVIEW_TARGET_TABLES
from .database import insert_review_history, next_citation_id_for_connection
from .review import normalize_review_priority, review_mark_to_dict
from .review_schema import (
    COLOR_TOKENS,
    SYSTEM_TAGS,
    TAG_DESCRIPTION_MAX,
    ReviewToolError,
    ensure_system_tags,
    next_color_token,
    normalize_tag_name,
    tag_names_for_ids,
)
from .schema import artifact_row_data_json

__all__ = [
    "HASH_COLUMNS",
    "PROPAGATION_CAP",
    "apply_tag_ids",
    "create_case_tag",
    "create_histogram_baseline",
    "delete_case_tag",
    "get_histogram_baseline",
    "hash_propagation_targets",
    "list_case_tags",
    "list_histogram_baselines",
    "review_mark_history_entries",
    "tag_to_dict",
    "target_hashes",
    "update_case_tag",
]

PROPAGATION_CAP = 10_000
HASH_COLUMNS = ("hash_md5", "hash_sha1", "hash_sha256")
_HASH_KEYS = {"md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256"}
_HASH_LENGTHS = {"hash_md5": 32, "hash_sha1": 40, "hash_sha256": 64}
# Review-target tables that carry ``evidence_source_id`` (the run a row belongs to).
_SOURCE_TABLES = {
    "file_record": "file_record",
    "artifact": "artifact",
    "indexed_document": "indexed_document",
    "event": "event",
}
BASELINE_NAME_MAX = 80
BASELINE_MAX_CATEGORIES = 2_000
_UNSET = object()


# --- helpers ------------------------------------------------------------------


def _audit(connection: sqlite3.Connection, case_id: str, actor: str, action: str, target_id: str, params: Mapping[str, object]) -> None:
    connection.execute(
        """
        INSERT INTO audit_event (
            citation_id, case_id, actor, action, target_type, target_id,
            timestamp, tool_name, tool_version, params_json, result, error
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            next_citation_id_for_connection(connection, case_id, "audit"),
            case_id,
            actor or "local-user",
            action,
            "case_tag" if action.startswith("tag.") else "review_mark",
            target_id,
            now_iso(),
            "rapidtriage",
            "",
            json.dumps(dict(params), ensure_ascii=False, sort_keys=True),
            "ok",
            "",
        ),
    )


@contextmanager
def _unique_conflicts() -> Iterator[None]:
    """A unique-index hit (a concurrent request took the name or shortcut after our check) -> Korean 409."""
    try:
        yield
    except sqlite3.IntegrityError as exc:
        raise ReviewToolError(
            "같은 이름 또는 단축키의 태그가 방금 다른 요청으로 만들어졌습니다. 태그 목록을 새로 고친 뒤 다시 시도하세요.",
            status=409,
        ) from exc


def _tag_ids_of(raw: object) -> list[int]:
    try:
        value = json.loads(str(raw or "[]"))
    except json.JSONDecodeError:
        return []
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for item in value:
        if isinstance(item, int) and not isinstance(item, bool) and item not in out:
            out.append(item)
    return out


def _tag_row(connection: sqlite3.Connection, case_id: str, tag_id: int) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM case_tag WHERE case_id = ? AND id = ?", (case_id, tag_id)).fetchone()
    if row is None or str(row["deleted_at"] or ""):
        raise ReviewToolError(f"태그를 찾을 수 없습니다: {tag_id}", status=404)
    return row


def _tag_counts(connection: sqlite3.Connection, case_id: str) -> dict[int, int]:
    counts: dict[int, int] = {}
    for row in connection.execute(
        "SELECT j.value, COUNT(*) FROM review_mark, json_each(review_mark.tag_ids_json) AS j "
        "WHERE review_mark.case_id = ? AND review_mark.tag_ids_json IS NOT NULL "
        "AND json_valid(review_mark.tag_ids_json) GROUP BY j.value",
        (case_id,),
    ):
        if isinstance(row[0], int):
            counts[int(row[0])] = int(row[1])
    return counts


def tag_to_dict(row: sqlite3.Row, count: int = 0) -> dict[str, object]:
    return {
        "id": int(row["id"]),
        "case_id": str(row["case_id"]),
        "name": str(row["name"]),
        "kind": str(row["kind"]),
        "color_token": str(row["color_token"]),
        "shortcut": int(row["shortcut"]) if row["shortcut"] is not None else None,
        "description": str(row["description"] or ""),
        "created_by": str(row["created_by"] or ""),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
        "deleted_at": str(row["deleted_at"] or "") or None,
        "deleted_by": str(row["deleted_by"] or "") or None,
        "count": count,
    }


def _check_color(value: object) -> str:
    token = str(value or "").strip()
    if token not in COLOR_TOKENS:
        raise ReviewToolError(f"색은 {', '.join(COLOR_TOKENS)} 중 하나여야 합니다.", status=422)
    return token


def _check_shortcut(connection: sqlite3.Connection, case_id: str, value: object, *, own_id: int | None = None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
        raise ReviewToolError("단축키는 1부터 9까지의 숫자여야 합니다.", status=422)
    digit = int(value)
    if not 1 <= digit <= 9:
        raise ReviewToolError("단축키는 1부터 9까지의 숫자여야 합니다.", status=422)
    owner = connection.execute(
        "SELECT id, name FROM case_tag WHERE case_id = ? AND deleted_at = '' AND shortcut = ?", (case_id, digit)
    ).fetchone()
    if owner is not None and int(owner[0]) != own_id:
        raise ReviewToolError(f"단축키 {digit}은(는) 이미 '{owner[1]}' 태그에 지정되어 있습니다.", status=409)
    return digit


def _check_description(value: object) -> str:
    text = str(value or "").strip()
    if len(text) > TAG_DESCRIPTION_MAX:
        raise ReviewToolError(f"설명은 {TAG_DESCRIPTION_MAX}자 이하여야 합니다.", status=422)
    return text


def _check_name_free(connection: sqlite3.Connection, case_id: str, name: str, *, own_id: int | None = None) -> None:
    row = connection.execute(
        "SELECT id FROM case_tag WHERE case_id = ? AND deleted_at = '' AND name = ? COLLATE NOCASE", (case_id, name)
    ).fetchone()
    if row is not None and int(row[0]) != own_id:
        raise ReviewToolError(f"같은 이름의 태그가 이미 있습니다: {name}", status=409)


def _rewrite_mark_names(connection: sqlite3.Connection, case_id: str, tag_id: int) -> int:
    """Re-derive ``tags_json`` names of every mark that carries ``tag_id`` (after a rename)."""
    rows = connection.execute(
        "SELECT review_mark.id, review_mark.tag_ids_json FROM review_mark, json_each(review_mark.tag_ids_json) AS j "
        "WHERE review_mark.case_id = ? AND review_mark.tag_ids_json IS NOT NULL "
        "AND json_valid(review_mark.tag_ids_json) AND j.value = ?",
        (case_id, tag_id),
    ).fetchall()
    for row in rows:
        names = tag_names_for_ids(connection, _tag_ids_of(row[1]))
        connection.execute(
            "UPDATE review_mark SET tags_json = ? WHERE id = ?", (json.dumps(names, ensure_ascii=False), int(row[0]))
        )
    return len(rows)


# --- tags -----------------------------------------------------------------------


def list_case_tags(connection: sqlite3.Connection, case_id: str, *, include_deleted: bool = False) -> list[dict[str, object]]:
    """Live tags of a case with their mark counts.

    The first read of a case creates its missing system tags (북마크, 우선순위 1-5) -- an
    explicit, write-safe migration (see ``ensure_system_tags``) on a case DB that already
    exists; the API never opens a new DB file for a read (routes_review_tools.py).
    """
    ensure_system_tags(connection, case_id)
    counts = _tag_counts(connection, case_id)
    where = "" if include_deleted else " AND deleted_at = ''"
    rows = connection.execute(f"SELECT * FROM case_tag WHERE case_id = ?{where} ORDER BY id", (case_id,)).fetchall()
    return [tag_to_dict(row, counts.get(int(row["id"]), 0)) for row in rows]


def create_case_tag(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    name: object,
    color_token: object = None,
    shortcut: object = None,
    description: object = "",
    actor: str = "",
) -> dict[str, object]:
    ensure_system_tags(connection, case_id)
    clean = normalize_tag_name(name)
    if clean in SYSTEM_TAGS:
        raise ReviewToolError(f"'{clean}'은(는) 기본 태그 이름이라 새로 만들 수 없습니다.", status=409)
    _check_name_free(connection, case_id, clean)
    color = _check_color(color_token) if color_token else None
    digit = _check_shortcut(connection, case_id, shortcut)
    text = _check_description(description)
    timestamp = now_iso()
    if color is None:
        color = next_color_token(connection, case_id)
    with _unique_conflicts():
        cursor = connection.execute(
            "INSERT INTO case_tag (case_id, name, kind, color_token, shortcut, description, created_by, created_at, updated_at) "
            "VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?)",
            (case_id, clean, color, digit, text, actor or "local-user", timestamp, timestamp),
        )
    tag_id = int(cursor.lastrowid or 0)
    _audit(connection, case_id, actor, "tag.created", str(tag_id), {"name": clean, "color_token": color, "shortcut": digit})
    return tag_to_dict(_tag_row(connection, case_id, tag_id))


def update_case_tag(
    connection: sqlite3.Connection,
    case_id: str,
    tag_id: int,
    *,
    name: object = _UNSET,
    color_token: object = _UNSET,
    shortcut: object = _UNSET,
    description: object = _UNSET,
    actor: str = "",
) -> dict[str, object]:
    row = _tag_row(connection, case_id, tag_id)
    changes: dict[str, object] = {}
    if name is not _UNSET:
        clean = normalize_tag_name(name)
        if clean != str(row["name"]):
            if str(row["kind"]) == "system":
                raise ReviewToolError(f"기본 태그 '{row['name']}'은(는) 이름을 바꿀 수 없습니다.", status=409)
            if clean in SYSTEM_TAGS:
                raise ReviewToolError(f"'{clean}'은(는) 기본 태그 이름이라 쓸 수 없습니다.", status=409)
            _check_name_free(connection, case_id, clean, own_id=tag_id)
            changes["name"] = clean
    if color_token is not _UNSET:
        changes["color_token"] = _check_color(color_token)
    if shortcut is not _UNSET:
        changes["shortcut"] = _check_shortcut(connection, case_id, shortcut, own_id=tag_id)
    if description is not _UNSET:
        changes["description"] = _check_description(description)
    if changes:
        assignments = ", ".join(f"{column} = ?" for column in changes)
        with _unique_conflicts():
            connection.execute(
                f"UPDATE case_tag SET {assignments}, updated_at = ? WHERE id = ?",
                (*changes.values(), now_iso(), tag_id),
            )
        if "name" in changes:
            changes["renamed_marks"] = _rewrite_mark_names(connection, case_id, tag_id)
        _audit(connection, case_id, actor, "tag.updated", str(tag_id), changes)
    counts = _tag_counts(connection, case_id)
    return tag_to_dict(_tag_row(connection, case_id, tag_id), counts.get(tag_id, 0))


def delete_case_tag(connection: sqlite3.Connection, case_id: str, tag_id: int, *, actor: str = "") -> dict[str, object]:
    """Soft-delete a user tag, free its shortcut and take it off every mark (with history)."""
    row = _tag_row(connection, case_id, tag_id)
    if str(row["kind"]) == "system":
        raise ReviewToolError(f"기본 태그 '{row['name']}'은(는) 삭제할 수 없습니다.", status=409)
    timestamp = now_iso()
    marks = connection.execute(
        "SELECT review_mark.target_type, review_mark.target_id FROM review_mark, json_each(review_mark.tag_ids_json) AS j "
        "WHERE review_mark.case_id = ? AND review_mark.tag_ids_json IS NOT NULL "
        "AND json_valid(review_mark.tag_ids_json) AND j.value = ?",
        (case_id, tag_id),
    ).fetchall()
    targets = [{"target_type": str(mark[0]), "target_id": str(mark[1])} for mark in marks]
    # The marks keep their reviewer: the history row records who deleted the tag.
    result = _apply_tag_changes(
        connection, case_id, targets, add_ids=[], remove_ids=[tag_id], actor=actor, timestamp=timestamp, keep_reviewer=True
    )
    connection.execute(
        "UPDATE case_tag SET deleted_at = ?, deleted_by = ?, shortcut = NULL, updated_at = ? WHERE id = ?",
        (timestamp, actor or "local-user", timestamp, tag_id),
    )
    _audit(connection, case_id, actor, "tag.deleted", str(tag_id), {"name": str(row["name"]), "removed_from_marks": result["changed_count"]})
    deleted = connection.execute("SELECT * FROM case_tag WHERE id = ?", (tag_id,)).fetchone()
    payload = tag_to_dict(deleted)
    payload["removed_from_marks"] = result["changed_count"]
    return payload


# --- tag batches ------------------------------------------------------------------


def _snapshot(previous: Mapping[str, object], **changes: object) -> dict[str, object]:
    keys = (
        "citation_id",
        "case_id",
        "target_type",
        "target_id",
        "status",
        "verification_status",
        "tags",
        "note",
        "include_in_report",
        "reviewer",
        "assignee",
        "priority",
        "due_at",
        "source_citation_package",
        "source_citation_package_hash",
        "updated_at",
    )
    current = {key: previous.get(key) for key in keys if key in previous}
    current.update(changes)
    return current


def _apply_tag_changes(
    connection: sqlite3.Connection,
    case_id: str,
    targets: Sequence[Mapping[str, str]],
    *,
    add_ids: Sequence[int],
    remove_ids: Sequence[int],
    actor: str,
    timestamp: str,
    keep_reviewer: bool = False,
    workflow: Mapping[str, str] | None = None,
) -> dict[str, int]:
    """Tag ids (and optional ``workflow`` fields: assignee / priority / due_at) on each target."""
    workflow = dict(workflow or {})
    changed = 0
    created = 0
    remove = set(remove_ids)
    for target in targets:
        target_type, target_id = str(target["target_type"]), str(target["target_id"])
        existing = connection.execute(
            "SELECT * FROM review_mark WHERE case_id = ? AND target_type = ? AND target_id = ? LIMIT 1",
            (case_id, target_type, target_id),
        ).fetchone()
        previous = review_mark_to_dict(existing) if existing is not None else {}
        old_ids = _tag_ids_of(existing["tag_ids_json"]) if existing is not None else []
        new_ids = [tag_id for tag_id in old_ids if tag_id not in remove]
        new_ids += [tag_id for tag_id in add_ids if tag_id not in new_ids]
        workflow_changed = existing is not None and any(
            str(existing[key] or "") != value for key, value in workflow.items()
        )
        if existing is not None and new_ids == old_ids and not workflow_changed:
            continue
        if existing is None and not new_ids and not workflow:
            continue
        names = tag_names_for_ids(connection, new_ids)
        names_json = json.dumps(names, ensure_ascii=False)
        if existing is None:
            citation_id = next_citation_id_for_connection(connection, case_id, "review")
            connection.execute(
                """
                INSERT INTO review_mark (
                    citation_id, case_id, target_type, target_id, status, verification_status,
                    tags_json, tag_ids_json, note, include_in_report, reviewer, assignee, priority, due_at,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'unreviewed', 'unverified', ?, ?, '', 0, ?, ?, ?, ?, ?, ?)
                """,
                (
                    citation_id,
                    case_id,
                    target_type,
                    target_id,
                    names_json,
                    json.dumps(new_ids),
                    actor,
                    workflow.get("assignee", ""),
                    workflow.get("priority", "normal"),
                    workflow.get("due_at", ""),
                    timestamp,
                    timestamp,
                ),
            )
            previous = {}
            base = {
                "citation_id": citation_id,
                "case_id": case_id,
                "target_type": target_type,
                "target_id": target_id,
                "status": "unreviewed",
                "verification_status": "unverified",
                "note": "",
                "include_in_report": False,
                "assignee": workflow.get("assignee", ""),
                "priority": workflow.get("priority", "normal"),
                "due_at": workflow.get("due_at", ""),
            }
            current = _snapshot(base, tags=names, reviewer=actor, updated_at=timestamp)
            created += 1
        else:
            citation_id = str(existing["citation_id"])
            reviewer = str(existing["reviewer"] or "") if keep_reviewer else (actor or str(existing["reviewer"] or ""))
            assignments = "".join(f", {key} = ?" for key in workflow)
            connection.execute(
                f"UPDATE review_mark SET tags_json = ?, tag_ids_json = ?, reviewer = ?{assignments}, updated_at = ? WHERE id = ?",
                (names_json, json.dumps(new_ids), reviewer, *workflow.values(), timestamp, int(existing["id"])),
            )
            current = _snapshot(previous, tags=names, reviewer=reviewer, updated_at=timestamp, **workflow)
        insert_review_history(
            connection,
            case_id=case_id,
            review_citation_id=citation_id,
            target_type=target_type,
            target_id=target_id,
            previous_review=previous,
            current_review=current,
            actor=actor or "local-user",
            changed_at=timestamp,
        )
        changed += 1
    return {"changed_count": changed, "created_count": created}


def _check_targets(connection: sqlite3.Connection, targets: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for target in targets:
        target_type = str(target.get("target_type") or "").strip()
        target_id = str(target.get("target_id") or "").strip()
        if not target_type or not target_id:
            raise ReviewToolError("모든 대상에 target_type과 target_id가 있어야 합니다.", status=422)
        if (target_type, target_id) in seen:
            continue
        table = REVIEW_TARGET_TABLES.get(target_type)
        if table and connection.execute(f"SELECT 1 FROM {table} WHERE id = ? LIMIT 1", (target_id,)).fetchone() is None:
            raise ReviewToolError(f"검토 대상 행이 없습니다: {target_type}:{target_id}", status=404)
        seen.add((target_type, target_id))
        out.append({"target_type": target_type, "target_id": target_id})
    return out


def apply_tag_ids(
    connection: sqlite3.Connection,
    case_id: str,
    targets: Iterable[Mapping[str, object]],
    *,
    add_ids: Sequence[int] = (),
    remove_ids: Sequence[int] = (),
    actor: str = "",
    propagate_by_hash: bool = False,
    evidence_source_id: int | None = None,
    cap: int = PROPAGATION_CAP,
    assignee: str | None = None,
    priority: str | None = None,
    due_at: str | None = None,
) -> dict[str, object]:
    """Add/remove tags (by id) on rows; with ``propagate_by_hash`` also on every same-hash file row.

    ``assignee`` / ``priority`` / ``due_at`` (when given) are set on the same rows in the same
    transaction, like ``mark_reviews_batch`` does for a tag-name batch.
    """
    for tag_id in [*add_ids, *remove_ids]:
        _tag_row(connection, case_id, int(tag_id))
    workflow = _workflow_fields(assignee=assignee, priority=priority, due_at=due_at)
    target_list = list(targets)
    # Before any per-target query or hash IN-list: an oversized request is refused up front.
    if len(target_list) > cap:
        raise ReviewToolError(
            f"한 번에 {cap:,}행까지 태그를 적용할 수 있습니다 (요청 {len(target_list):,}행). 선택을 줄이세요.", status=422
        )
    checked = _check_targets(connection, target_list)
    if not checked:
        raise ReviewToolError("태그를 적용할 행이 없습니다.", status=422)
    propagation: dict[str, object] | None = None
    if propagate_by_hash:
        checked, propagation = hash_propagation_targets(
            connection, case_id, checked, evidence_source_id=evidence_source_id, cap=cap
        )
    if len(checked) > cap:
        raise ReviewToolError(
            f"한 번에 {cap:,}행까지 태그를 적용할 수 있습니다 (요청 {len(checked):,}행). 선택을 줄이세요.", status=422
        )
    timestamp = now_iso()
    result = _apply_tag_changes(
        connection,
        case_id,
        checked,
        add_ids=[int(tag_id) for tag_id in add_ids],
        remove_ids=[int(tag_id) for tag_id in remove_ids],
        actor=actor,
        timestamp=timestamp,
        workflow=workflow,
    )
    _audit(
        connection,
        case_id,
        actor,
        "review.tags-applied",
        "",
        {
            "add_tag_ids": list(add_ids),
            "remove_tag_ids": list(remove_ids),
            **workflow,
            "target_count": len(checked),
            "changed_count": result["changed_count"],
            "propagate_by_hash": propagate_by_hash,
        },
    )
    payload: dict[str, object] = {
        "command": "case-review-tags",
        "case_id": case_id,
        "applied_count": len(checked),
        "changed_count": result["changed_count"],
        "created_count": result["created_count"],
        "targets": checked,
        "tags": [tag_to_dict(_tag_row(connection, case_id, int(tag_id))) for tag_id in add_ids],
    }
    if propagation is not None:
        payload["propagation"] = propagation
    return payload


def _workflow_fields(*, assignee: str | None, priority: str | None, due_at: str | None) -> dict[str, str]:
    """The given review-workflow fields, checked (Korean 422)."""
    fields: dict[str, str] = {}
    if assignee is not None:
        fields["assignee"] = str(assignee).strip()
    if priority is not None:
        try:
            fields["priority"] = normalize_review_priority(str(priority))
        except CaseDatabaseError as exc:
            raise ReviewToolError("우선순위(priority)는 urgent, high, normal, low 중 하나여야 합니다.", status=422) from exc
    if due_at is not None:
        fields["due_at"] = str(due_at).strip()
    return fields


# --- hash propagation ---------------------------------------------------------------


def _normalize_hash(column: str, value: object) -> str:
    text = str(value or "").strip().lower()
    if len(text) != _HASH_LENGTHS[column] or any(ch not in "0123456789abcdef" for ch in text):
        return ""
    return text


def _artifact_hashes(connection: sqlite3.Connection, artifact_id: str) -> tuple[int | None, dict[str, str]]:
    columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(artifact)")}
    select = "file_record_id, data_json" + (", data_blob, data_codec" if {"data_blob", "data_codec"} <= columns else "")
    row = connection.execute(f"SELECT {select} FROM artifact WHERE id = ?", (artifact_id,)).fetchone()
    if row is None:
        return None, {}
    hashes: dict[str, str] = {}
    try:
        data = json.loads(artifact_row_data_json(row) or "{}")
    except (json.JSONDecodeError, ValueError):
        data = {}
    if isinstance(data, Mapping):
        scopes = [data] + [data[key] for key in ("details", "hashes") if isinstance(data.get(key), Mapping)]
        for scope in scopes:
            for key, column in _HASH_KEYS.items():
                value = _normalize_hash(column, scope.get(key))
                if value and column not in hashes:
                    hashes[column] = value
    file_record_id = row["file_record_id"]
    return (int(file_record_id) if file_record_id is not None else None), hashes


def _file_hashes(connection: sqlite3.Connection, file_record_id: int) -> dict[str, str]:
    row = connection.execute(
        f"SELECT {', '.join(HASH_COLUMNS)} FROM file_record WHERE id = ?", (file_record_id,)
    ).fetchone()
    if row is None:
        return {}
    return {column: value for column in HASH_COLUMNS if (value := _normalize_hash(column, row[column]))}


def target_hashes(connection: sqlite3.Connection, target_type: str, target_id: str) -> dict[str, str]:
    """``{hash column: lowercase hex}`` of a review target (file row, its document, or an artifact)."""
    if target_type == "file_record" and target_id.isdigit():
        return _file_hashes(connection, int(target_id))
    if target_type == "indexed_document" and target_id.isdigit():
        row = connection.execute("SELECT file_record_id FROM indexed_document WHERE id = ?", (int(target_id),)).fetchone()
        return _file_hashes(connection, int(row[0])) if row is not None and row[0] is not None else {}
    if target_type == "artifact" and target_id.isdigit():
        file_record_id, hashes = _artifact_hashes(connection, target_id)
        if file_record_id is not None:
            for column, value in _file_hashes(connection, file_record_id).items():
                hashes.setdefault(column, value)
        return hashes
    return {}


def hash_propagation_targets(
    connection: sqlite3.Connection,
    case_id: str,
    targets: Sequence[Mapping[str, str]],
    *,
    evidence_source_id: int | None = None,
    cap: int = PROPAGATION_CAP,
) -> tuple[list[dict[str, str]], dict[str, object]]:
    """The targets plus every file row of the same run whose MD5/SHA-1/SHA-256 equals a target's.

    "Same run" = the evidence sources the target rows come from (a case DB can hold several
    runs' evidence); ``evidence_source_id`` is the fallback when no target names its source.
    With neither, the whole case is the scope only when its file rows belong to one evidence
    source (or none); otherwise the request is refused (Korean 422) instead of tagging other
    runs' files. Refuses (Korean, 422) when the targets or the result exceed ``cap`` rows.
    Hash and source lists are bound as one JSON parameter each (``json_each``), so the SQL
    never exceeds SQLite's variable limit however many hashes the targets carry.
    """
    if len(targets) > cap:
        raise ReviewToolError(
            f"한 번에 {cap:,}행까지 태그를 적용할 수 있습니다 (요청 {len(targets):,}행). 선택을 줄이세요.", status=422
        )
    wanted: dict[str, set[str]] = {column: set() for column in HASH_COLUMNS}
    hashless = 0
    sources: set[int] = set()
    for target in targets:
        target_type, target_id = str(target["target_type"]), str(target["target_id"])
        hashes = target_hashes(connection, target_type, target_id)
        if not hashes:
            hashless += 1
        for column, value in hashes.items():
            wanted[column].add(value)
        table = _SOURCE_TABLES.get(target_type)
        if table and target_id.isdigit():
            row = connection.execute(f"SELECT evidence_source_id FROM {table} WHERE id = ?", (int(target_id),)).fetchone()
            if row is not None and row[0] is not None:
                sources.add(int(row[0]))
    if not sources and evidence_source_id is not None:
        sources.add(evidence_source_id)
    if any(wanted.values()) and not sources:
        distinct = int(
            connection.execute(
                "SELECT COUNT(DISTINCT coalesce(evidence_source_id, -1)) FROM file_record WHERE case_id = ?", (case_id,)
            ).fetchone()[0]
        )
        if distinct > 1:
            raise ReviewToolError(
                "선택한 행이 어느 런(증거)에 속하는지 알 수 없어 같은 해시 전파를 하지 않았습니다. "
                "런(run_id)을 지정하거나 런에 속한 행을 고르세요.",
                status=422,
            )
    clauses: list[str] = []
    params: list[object] = [case_id]
    scope = ""
    if sources:
        scope = " AND evidence_source_id IN (SELECT value FROM json_each(?))"
        params.append(json.dumps(sorted(sources)))
    for column, values in wanted.items():
        if values:
            clauses.append(f"lower({column}) IN (SELECT value FROM json_each(?))")
            params.append(json.dumps(sorted(values)))
    matched: list[int] = []
    if clauses:
        where = f"case_id = ?{scope} AND ({' OR '.join(clauses)})"
        total = int(connection.execute(f"SELECT COUNT(*) FROM file_record WHERE {where}", params).fetchone()[0])
        if total > cap:
            raise ReviewToolError(
                f"같은 해시 행이 {total:,}건으로 전파 상한 {cap:,}건을 넘어 적용하지 않았습니다. 선택을 줄이세요.",
                status=422,
            )
        matched = [int(row[0]) for row in connection.execute(f"SELECT id FROM file_record WHERE {where} ORDER BY id", params)]
    out = [dict(target) for target in targets]
    seen = {(item["target_type"], item["target_id"]) for item in out}
    added = 0
    for file_id in matched:
        key = ("file_record", str(file_id))
        if key not in seen:
            seen.add(key)
            out.append({"target_type": "file_record", "target_id": str(file_id)})
            added += 1
    if len(out) > cap:
        raise ReviewToolError(
            f"같은 해시 행이 {len(out):,}건으로 전파 상한 {cap:,}건을 넘어 적용하지 않았습니다. 선택을 줄이세요.",
            status=422,
        )
    return out, {
        "hash_values": sum(len(values) for values in wanted.values()),
        "matched_file_rows": len(matched),
        "added_rows": added,
        "hashless_targets": hashless,
        "cap": cap,
    }


# --- history ------------------------------------------------------------------------


def review_mark_history_entries(
    connection: sqlite3.Connection, case_id: str, target_type: str, target_id: str, *, limit: int = 200
) -> list[dict[str, object]]:
    """A mark's change history, newest first: author, time, changed fields, note/tags before and after."""
    rows = connection.execute(
        "SELECT version, changed_at, actor, changed_fields_json, previous_json, current_json "
        "FROM review_mark_history WHERE case_id = ? AND target_type = ? AND target_id = ? "
        "ORDER BY version DESC LIMIT ?",
        (case_id, target_type, target_id, limit),
    ).fetchall()
    entries: list[dict[str, object]] = []
    for row in rows:
        def load(raw: object, fallback: object) -> object:
            try:
                return json.loads(str(raw or ""))
            except json.JSONDecodeError:
                return fallback

        previous = load(row[4], {})
        current = load(row[5], {})
        previous = previous if isinstance(previous, dict) else {}
        current = current if isinstance(current, dict) else {}
        fields = load(row[3], [])
        entries.append(
            {
                "version": int(row[0]),
                "changed_at": str(row[1] or ""),
                "author": str(row[2] or ""),
                "changed_fields": [str(item) for item in fields] if isinstance(fields, list) else [],
                "note_before": str(previous.get("note") or ""),
                "note_after": str(current.get("note") or ""),
                "tags_before": list(previous.get("tags") or []),
                "tags_after": list(current.get("tags") or []),
                "status_before": str(previous.get("status") or ""),
                "status_after": str(current.get("status") or ""),
            }
        )
    return entries


# --- histogram baselines ---------------------------------------------------------------


def _baseline_to_dict(row: sqlite3.Row, *, with_counts: bool = False) -> dict[str, object]:
    try:
        counts = json.loads(str(row["counts_json"] or "{}"))
    except json.JSONDecodeError:
        counts = {}
    payload: dict[str, object] = {
        "id": int(row["id"]),
        "case_id": str(row["case_id"]),
        "name": str(row["name"]),
        "run_id": str(row["run_id"] or ""),
        "created_by": str(row["created_by"] or ""),
        "created_at": str(row["created_at"] or ""),
        "category_count": len(counts) if isinstance(counts, dict) else 0,
    }
    if with_counts:
        payload["counts"] = counts if isinstance(counts, dict) else {}
    return payload


def create_histogram_baseline(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    name: object,
    run_id: str,
    counts: Mapping[str, Mapping[str, object]],
    actor: str = "",
) -> dict[str, object]:
    clean = " ".join(str(name or "").split())
    if not clean:
        raise ReviewToolError("기준선 이름을 입력하세요.", status=422)
    if len(clean) > BASELINE_NAME_MAX:
        raise ReviewToolError(f"기준선 이름은 {BASELINE_NAME_MAX}자 이하여야 합니다.", status=422)
    if len(counts) > BASELINE_MAX_CATEGORIES:
        raise ReviewToolError(f"기준선 범주는 {BASELINE_MAX_CATEGORIES:,}개까지 저장할 수 있습니다.", status=422)
    if connection.execute("SELECT 1 FROM histogram_baseline WHERE case_id = ? AND name = ?", (case_id, clean)).fetchone():
        raise ReviewToolError(f"같은 이름의 기준선이 이미 있습니다: {clean}", status=409)
    stored = {
        str(key): {"label": str(value.get("label") or key), "count": int(value.get("count") or 0)}
        for key, value in counts.items()
    }
    cursor = connection.execute(
        "INSERT INTO histogram_baseline (case_id, name, run_id, created_by, created_at, counts_json) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, clean, run_id, actor or "local-user", now_iso(), json.dumps(stored, ensure_ascii=False, sort_keys=True)),
    )
    row = connection.execute("SELECT * FROM histogram_baseline WHERE id = ?", (int(cursor.lastrowid or 0),)).fetchone()
    return _baseline_to_dict(row, with_counts=True)


def list_histogram_baselines(connection: sqlite3.Connection, case_id: str) -> list[dict[str, object]]:
    rows = connection.execute(
        "SELECT * FROM histogram_baseline WHERE case_id = ? ORDER BY created_at DESC, id DESC", (case_id,)
    ).fetchall()
    return [_baseline_to_dict(row) for row in rows]


def get_histogram_baseline(connection: sqlite3.Connection, case_id: str, baseline_id: int) -> dict[str, object]:
    row = connection.execute(
        "SELECT * FROM histogram_baseline WHERE case_id = ? AND id = ?", (case_id, baseline_id)
    ).fetchone()
    if row is None:
        raise ReviewToolError(f"기준선을 찾을 수 없습니다: {baseline_id}", status=404)
    return _baseline_to_dict(row, with_counts=True)
