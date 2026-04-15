from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any, Mapping

from .docs import write_result


class CaseBookmarkError(ValueError):
    """Raised when case/bookmark input is invalid."""


PATH_KEYS = (
    "path",
    "original_path",
    "source_path",
    "evidence_path",
    "artifact_path",
    "target_path",
)
TIMESTAMP_KEYS = (
    "timestamp",
    "event_at",
    "observed_at",
    "occurred_at",
    "modified_at",
    "last_visited_at",
    "started_at",
    "ended_at",
    "visited_at",
    "created_at",
    "accessed_at",
)


def load_case_payload(path: Path) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"case JSON does not exist: {resolved}")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaseBookmarkError(f"case JSON is not valid JSON: {resolved}") from exc
    if not isinstance(payload, dict):
        raise CaseBookmarkError(f"case JSON must be a JSON object: {resolved}")
    if payload.get("command") != "case":
        raise CaseBookmarkError(f"case JSON must have command='case': {resolved}")
    bookmarks = payload.get("bookmarks")
    if not isinstance(bookmarks, list):
        raise CaseBookmarkError(f"case JSON must include a bookmarks array: {resolved}")
    return payload


def save_case_payload(path: Path, payload: Mapping[str, object]) -> None:
    write_result(dict(payload), path.expanduser().resolve())


def create_or_update_case_payload(
    case_path: Path,
    *,
    case_id: str | None = None,
    title: str | None = None,
    source_path: Path | None = None,
    source_pointer: str | None = None,
    bookmark_id: str | None = None,
    tags: list[str] | None = None,
    note: str | None = None,
) -> dict[str, object]:
    resolved_case_path = case_path.expanduser().resolve()
    payload = (
        load_case_payload(resolved_case_path)
        if resolved_case_path.exists()
        else build_empty_case_payload(resolved_case_path, case_id=case_id, title=title)
    )

    if case_id:
        payload["case_id"] = case_id.strip()
    if title:
        payload["title"] = title.strip()

    if source_path is not None:
        if not source_pointer:
            raise CaseBookmarkError("case bookmark updates require --pointer when --source is provided")
        source_payload = load_source_payload(source_path)
        upsert_bookmark(
            payload,
            source_path=source_path.expanduser().resolve(),
            source_payload=source_payload,
            source_pointer=source_pointer,
            bookmark_id=bookmark_id,
            tags=tags or [],
            note=note,
        )
    elif source_pointer or bookmark_id or tags or note:
        raise CaseBookmarkError("--source is required when using bookmark-specific options")

    payload["summary"] = build_case_summary(payload.get("bookmarks", []))
    payload["updated_at"] = now_iso()
    return payload


def build_empty_case_payload(case_path: Path, *, case_id: str | None, title: str | None) -> dict[str, object]:
    now = now_iso()
    normalized_case_id = (case_id or case_path.stem or "rapidtriage-case").strip()
    normalized_title = (title or normalized_case_id).strip()
    payload = {
        "command": "case",
        "generated_at": now,
        "updated_at": now,
        "case_id": normalized_case_id,
        "title": normalized_title,
        "summary": build_case_summary([]),
        "bookmarks": [],
    }
    return payload


def load_source_payload(path: Path) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"bookmark source JSON does not exist: {resolved}")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CaseBookmarkError(f"bookmark source is not valid JSON: {resolved}") from exc
    if not isinstance(payload, dict):
        raise CaseBookmarkError(f"bookmark source must be a JSON object: {resolved}")
    return payload


def upsert_bookmark(
    payload: dict[str, object],
    *,
    source_path: Path,
    source_payload: Mapping[str, object],
    source_pointer: str,
    bookmark_id: str | None,
    tags: list[str],
    note: str | None,
) -> None:
    item = resolve_json_pointer(source_payload, source_pointer)
    if not isinstance(item, dict):
        raise CaseBookmarkError("bookmark pointer must resolve to a JSON object row")

    bookmarks = payload.setdefault("bookmarks", [])
    if not isinstance(bookmarks, list):
        raise CaseBookmarkError("case payload bookmarks must be a list")

    existing = find_existing_bookmark(bookmarks, bookmark_id=bookmark_id, source_path=source_path, source_pointer=source_pointer)
    now = now_iso()
    extracted_path = find_first_string(item, PATH_KEYS)
    summary = build_bookmark_summary(item, extracted_path, source_pointer)
    merged_tags = normalize_tags(tags)

    if existing is None:
        record = {
            "bookmark_id": bookmark_id.strip() if bookmark_id else next_bookmark_id(bookmarks),
            "created_at": now,
            "updated_at": now,
            "source_command": str(source_payload.get("command") or "unknown"),
            "source_file": str(source_path),
            "source_pointer": source_pointer,
            "source_root": str(source_payload.get("root")) if source_payload.get("root") else None,
            "source_path": extracted_path,
            "source_summary": summary,
            "source_timestamp": find_first_string(item, TIMESTAMP_KEYS),
            "summary": summary,
            "tags": merged_tags,
            "note": note or "",
            "item": item,
        }
        bookmarks.append(record)
        return

    existing["updated_at"] = now
    existing["source_command"] = str(source_payload.get("command") or existing.get("source_command") or "unknown")
    existing["source_file"] = str(source_path)
    existing["source_pointer"] = source_pointer
    existing["source_root"] = str(source_payload.get("root")) if source_payload.get("root") else existing.get("source_root")
    existing["source_path"] = extracted_path
    existing["source_summary"] = summary
    existing["source_timestamp"] = find_first_string(item, TIMESTAMP_KEYS)
    existing["summary"] = summary
    existing["item"] = item
    if merged_tags:
        previous_tags = existing.get("tags")
        prior = previous_tags if isinstance(previous_tags, list) else []
        existing["tags"] = normalize_tags([*prior, *merged_tags])
    else:
        existing["tags"] = normalize_tags(existing.get("tags", []))
    if note is not None:
        existing["note"] = note


def find_existing_bookmark(
    bookmarks: list[object],
    *,
    bookmark_id: str | None,
    source_path: Path,
    source_pointer: str,
) -> dict[str, object] | None:
    normalized_bookmark_id = bookmark_id.strip() if bookmark_id else None
    normalized_source_path = str(source_path)
    for item in bookmarks:
        if not isinstance(item, dict):
            continue
        if normalized_bookmark_id and item.get("bookmark_id") == normalized_bookmark_id:
            return item
        if item.get("source_file") == normalized_source_path and item.get("source_pointer") == source_pointer:
            return item
    return None


def resolve_json_pointer(payload: Mapping[str, object], pointer: str) -> Any:
    if pointer == "":
        return payload
    if not pointer.startswith("/"):
        raise CaseBookmarkError("bookmark pointer must start with '/'")

    current: Any = payload
    for raw_token in pointer.lstrip("/").split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            try:
                index = int(token)
            except ValueError as exc:
                raise CaseBookmarkError(f"bookmark pointer segment is not a list index: {token!r}") from exc
            try:
                current = current[index]
            except IndexError as exc:
                raise CaseBookmarkError(f"bookmark pointer index out of range: {index}") from exc
            continue
        if isinstance(current, dict):
            if token not in current:
                raise CaseBookmarkError(f"bookmark pointer key not found: {token!r}")
            current = current[token]
            continue
        raise CaseBookmarkError(f"bookmark pointer cannot descend through {type(current).__name__}")
    return current


def build_case_summary(bookmarks: object) -> dict[str, object]:
    rows = [item for item in bookmarks if isinstance(item, dict)]
    tag_counts: dict[str, int] = {}
    source_command_counts: dict[str, int] = {}
    tagged_bookmark_count = 0
    for bookmark in rows:
        source_command = str(bookmark.get("source_command") or "unknown")
        source_command_counts[source_command] = source_command_counts.get(source_command, 0) + 1
        raw_tags = bookmark.get("tags")
        tags = normalize_tags(raw_tags if isinstance(raw_tags, list) else [])
        if tags:
            tagged_bookmark_count += 1
        for tag in tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    return {
        "bookmark_count": len(rows),
        "tagged_bookmark_count": tagged_bookmark_count,
        "tag_counts": dict(sorted(tag_counts.items())),
        "source_command_counts": dict(sorted(source_command_counts.items())),
    }


def normalize_tags(tags: object) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for item in tags if isinstance(tags, list) else []:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


def next_bookmark_id(bookmarks: list[object]) -> str:
    existing = {
        str(item.get("bookmark_id"))
        for item in bookmarks
        if isinstance(item, dict) and item.get("bookmark_id")
    }
    index = 1
    while True:
        candidate = f"bookmark-{index:04d}"
        if candidate not in existing:
            return candidate
        index += 1


def find_first_string(item: object, keys: tuple[str, ...]) -> str | None:
    if isinstance(item, dict):
        for key in keys:
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
        nested_details = item.get("details")
        if isinstance(nested_details, dict):
            for key in keys:
                value = nested_details.get(key)
                if isinstance(value, str) and value:
                    return value
    return None


def build_bookmark_summary(item: Mapping[str, object], source_path: str | None, source_pointer: str) -> str:
    summary = item.get("summary")
    if isinstance(summary, str) and summary:
        return summary
    preview = item.get("preview")
    if isinstance(preview, str) and preview:
        return preview
    name = item.get("name")
    if isinstance(name, str) and name:
        return name
    if source_path:
        return Path(source_path).name or source_path
    return f"Bookmark from {source_pointer}"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()
