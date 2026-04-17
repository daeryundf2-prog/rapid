from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .docs import write_result
from .schema_validation import SchemaValidationError, load_schema, validate


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
HASH_KEYS = (
    "sha256",
    "sha1",
    "md5",
    "hash",
)
ARTIFACT_KEYS = (
    "artifact_key",
    "artifact_id",
    "artifact_type",
    "event_type",
    "url",
    "source_url",
    "target_path",
    "tab_url",
)

CASE_SOURCE_ROWS = {
    "files": "candidates",
    "docs": "results",
    "artifacts": "artifacts",
    "timeline": "events",
}

EXPERIMENTAL_CASE_SOURCE_ROWS = {
    "compare": "results",
}

CASE_SOURCE_SCHEMAS = {
    "files": "files.schema.json",
    "docs": "docs.schema.json",
    "artifacts": "artifacts.schema.json",
    "timeline": "timeline.schema.json",
}

CASE_SOURCE_ROWS = {
    "files": "candidates",
    "docs": "results",
    "artifacts": "artifacts",
    "timeline": "events",
}

EXPERIMENTAL_CASE_SOURCE_ROWS = {
    "compare": "results",
}

CASE_SOURCE_SCHEMAS = {
    "files": "files.schema.json",
    "docs": "docs.schema.json",
    "artifacts": "artifacts.schema.json",
    "timeline": "timeline.schema.json",
}


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
    command = str(payload.get("command") or "").strip()
    if command in EXPERIMENTAL_CASE_SOURCE_ROWS:
        raise CaseBookmarkError(
            "bookmark source command 'compare' is not implemented yet; "
            "case currently supports files, docs, artifacts, and timeline outputs"
        )
    if command not in CASE_SOURCE_ROWS:
        supported = ", ".join(sorted(CASE_SOURCE_ROWS))
        raise CaseBookmarkError(f"unsupported bookmark source command {command!r}; expected one of: {supported}")
    schema_name = CASE_SOURCE_SCHEMAS[command]
    try:
        validate(payload, load_schema(schema_name))
    except SchemaValidationError as exc:
        raise CaseBookmarkError(f"{command} source JSON failed schema validation: {exc}") from exc
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
    source_command = str(source_payload.get("command") or "").strip()
    item = resolve_case_source_row(source_payload, source_command=source_command, source_pointer=source_pointer)

    bookmarks = payload.setdefault("bookmarks", [])
    if not isinstance(bookmarks, list):
        raise CaseBookmarkError("case payload bookmarks must be a list")

    source_command = str(source_payload.get("command") or "unknown")
    now = now_iso()
    extracted_path = find_first_string(item, PATH_KEYS)
    source_hash = find_first_string(item, HASH_KEYS)
    source_timestamp = find_first_string(item, TIMESTAMP_KEYS)
    artifact_key = find_artifact_key(item)
    summary = build_bookmark_summary(item, extracted_path, source_pointer)
    stable_key = build_stable_bookmark_key(
        source_command=source_command,
        source_file=str(source_path),
        source_path=extracted_path,
        source_hash=source_hash,
        source_timestamp=source_timestamp,
        artifact_key=artifact_key,
        summary=summary,
    )
    existing = find_existing_bookmark(
        bookmarks,
        bookmark_id=bookmark_id,
        stable_key=stable_key,
        source_path=source_path,
        source_pointer=source_pointer,
    )
    merged_tags = normalize_tags(tags)
    reference = build_bookmark_reference(
        source_command=source_command,
        source_file=str(source_path),
        source_pointer=source_pointer,
        source_root=str(source_payload.get("root")) if source_payload.get("root") else None,
        stable_key=stable_key,
    )
    snapshot = build_bookmark_snapshot(
        source_path=extracted_path,
        source_hash=source_hash,
        source_timestamp=source_timestamp,
        artifact_key=artifact_key,
        summary=summary,
    )

    if existing is None:
        record = {
            "bookmark_id": bookmark_id.strip() if bookmark_id else stable_key,
            "created_at": now,
            "updated_at": now,
            "source_command": source_command or "unknown",
            "source_file": str(source_path),
            "source_pointer": source_pointer,
            "source_root": str(source_payload.get("root")) if source_payload.get("root") else None,
            "source_path": extracted_path,
            "source_summary": summary,
            "source_timestamp": find_first_string(item, TIMESTAMP_KEYS),
            "summary": summary,
            "tags": merged_tags,
            "note": note or "",
            "reference": reference,
            "snapshot": snapshot,
        }
        bookmarks.append(record)
        return

    existing_bookmark_id = bookmark_id.strip() if bookmark_id else str(existing.get("bookmark_id") or "").strip() or stable_key
    prior_tags = normalize_tags(existing.get("tags", []))
    created_at_value = existing.get("created_at")
    created_at = str(created_at_value) if isinstance(created_at_value, str) and created_at_value else now
    prior_note = str(existing.get("note") or "")
    existing.clear()
    existing["bookmark_id"] = existing_bookmark_id
    existing["created_at"] = created_at
    existing["updated_at"] = now
    existing["source_command"] = source_command or str(existing.get("source_command") or "unknown")
    existing["source_file"] = str(source_path)
    existing["source_pointer"] = source_pointer
    existing["source_root"] = str(source_payload.get("root")) if source_payload.get("root") else existing.get("source_root")
    existing["source_path"] = extracted_path
    existing["source_summary"] = summary
    existing["source_timestamp"] = find_first_string(item, TIMESTAMP_KEYS)
    existing["summary"] = summary
    existing["reference"] = reference
    existing["snapshot"] = snapshot
    if merged_tags:
        existing["tags"] = normalize_tags([*prior_tags, *merged_tags])
    else:
        existing["tags"] = prior_tags
    if note is not None:
        existing["note"] = note
    else:
        existing["note"] = prior_note


def find_existing_bookmark(
    bookmarks: list[object],
    *,
    bookmark_id: str | None,
    stable_key: str,
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
        reference = item.get("reference")
        if isinstance(reference, dict) and reference.get("stable_key") == stable_key:
            return item
        if item.get("source_file") == normalized_source_path and item.get("source_pointer") == source_pointer:
            return item
    return None


def resolve_case_source_row(
    payload: Mapping[str, object],
    *,
    source_command: str,
    source_pointer: str,
) -> dict[str, object]:
    collection_name = CASE_SOURCE_ROWS.get(source_command)
    if collection_name is None:
        supported = ", ".join(sorted(CASE_SOURCE_ROWS))
        raise CaseBookmarkError(f"unsupported bookmark source command {source_command!r}; expected one of: {supported}")

    tokens = split_json_pointer(source_pointer)
    if len(tokens) != 2 or tokens[0] != collection_name:
        raise CaseBookmarkError(
            f"{source_command} bookmarks require a row pointer in the form '/{collection_name}/<index>'"
        )

    collection = payload.get(collection_name)
    if not isinstance(collection, list):
        raise CaseBookmarkError(f"{source_command} source JSON must include a {collection_name} array")

    try:
        index = int(tokens[1])
    except ValueError as exc:
        raise CaseBookmarkError(f"bookmark pointer segment is not a list index: {tokens[1]!r}") from exc

    try:
        item = collection[index]
    except IndexError as exc:
        raise CaseBookmarkError(f"bookmark pointer index out of range: {index}") from exc

    if not isinstance(item, dict):
        raise CaseBookmarkError("bookmark pointer must resolve to a JSON object row")
    return item


def split_json_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise CaseBookmarkError("bookmark pointer must start with '/'")
    return [raw_token.replace("~1", "/").replace("~0", "~") for raw_token in pointer.lstrip("/").split("/")]


def resolve_json_pointer(payload: Mapping[str, object], pointer: str) -> Any:
    tokens = split_json_pointer(pointer)
    if not tokens:
        return payload

    current: Any = payload
    for token in tokens:
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
        reference = bookmark.get("reference")
        source_command = (
            str(reference.get("command") or "unknown")
            if isinstance(reference, dict)
            else str(bookmark.get("source_command") or "unknown")
        )
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


def build_bookmark_reference(
    *,
    source_command: str,
    source_file: str,
    source_pointer: str,
    source_root: str | None,
    stable_key: str,
) -> dict[str, str | None]:
    return {
        "command": source_command,
        "file": source_file,
        "pointer": source_pointer,
        "root": source_root,
        "stable_key": stable_key,
    }


def build_bookmark_snapshot(
    *,
    source_path: str | None,
    source_hash: str | None,
    source_timestamp: str | None,
    artifact_key: str | None,
    summary: str,
) -> dict[str, str | None]:
    return {
        "path": source_path,
        "hash": source_hash,
        "timestamp": source_timestamp,
        "artifact_key": artifact_key,
        "summary": summary,
    }


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


def find_artifact_key(item: object) -> str | None:
    return find_first_string(item, ARTIFACT_KEYS)


def build_stable_bookmark_key(
    *,
    source_command: str,
    source_file: str,
    source_path: str | None,
    source_hash: str | None,
    source_timestamp: str | None,
    artifact_key: str | None,
    summary: str,
) -> str:
    identity: dict[str, str | None] = {
        "source_command": source_command,
        "source_file": source_file,
        "path": source_path,
        "hash": source_hash,
        "timestamp": source_timestamp,
        "artifact_key": artifact_key,
    }
    if not any(identity[key] for key in ("path", "hash", "timestamp", "artifact_key")):
        identity["summary"] = summary
    serialized = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
    return f"bookmark-{digest}"


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
