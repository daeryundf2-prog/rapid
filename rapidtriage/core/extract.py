from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .files import (
    ALL_FILE_CATEGORIES,
    DEFAULT_FILE_CATEGORIES,
    normalize_extensions,
    normalize_text_filters,
    normalized_name_mismatch,
    normalized_path_mismatch,
)

SUPPORTED_EXTRACT_COMMANDS: Tuple[str, ...] = ("docs", "files")
SUPPORTED_DOC_KINDS: Tuple[str, ...] = ("docx", "pdf", "txt")
DEFAULT_EXTRACT_MANIFEST_NAME = "rapidtriage-extract-manifest.json"


class ExtractError(ValueError):
    """Raised when extract command inputs are invalid."""


def run_extract(
    input_json: Path,
    output_dir: Path,
    *,
    name_contains: Optional[Sequence[str]] = None,
    path_contains: Optional[Sequence[str]] = None,
    extensions: Optional[Sequence[str]] = None,
    categories: Optional[Sequence[str]] = None,
    kinds: Optional[Sequence[str]] = None,
    limit: int = 0,
) -> Dict[str, object]:
    payload = load_extract_payload(input_json)
    source_command = payload["command"]
    root = resolve_payload_root(payload.get("root"), input_json.parent)
    source_items = extract_source_items(payload, source_command)
    normalized_name_filters = normalize_text_filters(name_contains)
    normalized_path_filters = normalize_text_filters(path_contains)
    normalized_extensions = normalize_extensions(extensions)
    normalized_categories = normalize_extract_categories(categories, source_command)
    normalized_kinds = normalize_extract_kinds(kinds, source_command)

    selected_items = select_items_for_extraction(
        source_items,
        source_command=source_command,
        root=root,
        input_base_dir=input_json.parent,
        name_contains=normalized_name_filters,
        path_contains=normalized_path_filters,
        extensions=normalized_extensions,
        categories=normalized_categories,
        kinds=normalized_kinds,
        limit=limit,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_entries: List[Dict[str, object]] = []
    skipped_entries: List[Dict[str, object]] = []
    for item, source_path in selected_items:
        if not source_path.exists() or not source_path.is_file():
            skipped_entries.append(
                {
                    "original_path": str(source_path),
                    "reason": "missing",
                }
            )
            continue

        destination_relative = build_destination_relative_path(source_path, root)
        destination_path = output_dir / destination_relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)

        source_stat = source_path.stat()
        entry: Dict[str, object] = {
            "original_path": str(source_path),
            "extracted_path": str(destination_path),
            "relative_path": destination_relative.as_posix(),
            "sha256": compute_sha256(source_path),
            "modified_at": dt.datetime.fromtimestamp(source_stat.st_mtime).isoformat(),
            "size": source_stat.st_size,
        }
        if source_command == "files":
            entry["categories"] = extract_candidate_categories(item)
        if source_command == "docs":
            if item.get("kind"):
                entry["kind"] = str(item["kind"])
            if item.get("matched_keywords"):
                entry["matched_keywords"] = list(item["matched_keywords"])
        extracted_entries.append(entry)

    return {
        "command": "extract",
        "source_command": source_command,
        "input_json": str(input_json),
        "root": str(root) if root else None,
        "generated_at": dt.datetime.now().isoformat(),
        "output_dir": str(output_dir),
        "filters": {
            "name_contains": normalized_name_filters,
            "path_contains": normalized_path_filters,
            "extensions": normalized_extensions,
            "categories": normalized_categories if source_command == "files" else [],
            "kinds": normalized_kinds if source_command == "docs" else [],
            "limit": limit,
        },
        "summary": {
            "input_count": len(source_items),
            "selected_count": len(selected_items),
            "extracted_count": len(extracted_entries),
            "skipped_count": len(skipped_entries),
        },
        "entries": extracted_entries,
        "skipped": skipped_entries,
    }


def load_extract_payload(input_json: Path) -> Dict[str, object]:
    try:
        payload = json.loads(input_json.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ExtractError(f"input JSON not found: {input_json}") from exc
    except json.JSONDecodeError as exc:
        raise ExtractError(f"invalid JSON input: {input_json}") from exc

    if not isinstance(payload, dict):
        raise ExtractError("input JSON must contain an object payload")
    command = payload.get("command")
    if command not in SUPPORTED_EXTRACT_COMMANDS:
        supported = ", ".join(SUPPORTED_EXTRACT_COMMANDS)
        raise ExtractError(f"input JSON command must be one of: {supported}")
    return payload


def extract_source_items(payload: Dict[str, object], source_command: str) -> List[Dict[str, object]]:
    key = "candidates" if source_command == "files" else "results"
    source_items = payload.get(key)
    if not isinstance(source_items, list):
        raise ExtractError(f"input JSON is missing a valid '{key}' array")
    normalized_items: List[Dict[str, object]] = []
    for item in source_items:
        if not isinstance(item, dict) or not item.get("path"):
            raise ExtractError(f"every '{key}' entry must include a path")
        normalized_items.append(item)
    return normalized_items


def select_items_for_extraction(
    source_items: Sequence[Dict[str, object]],
    *,
    source_command: str,
    root: Optional[Path],
    input_base_dir: Path,
    name_contains: Sequence[str],
    path_contains: Sequence[str],
    extensions: Sequence[str],
    categories: Sequence[str],
    kinds: Sequence[str],
    limit: int,
) -> List[Tuple[Dict[str, object], Path]]:
    selected: List[Tuple[Dict[str, object], Path]] = []
    for item in source_items:
        source_path = resolve_source_path(str(item["path"]), root, input_base_dir)
        if normalized_path_mismatch(str(source_path), path_contains):
            continue
        if normalized_name_mismatch(source_path.name, name_contains):
            continue
        if extensions and source_path.suffix.lower() not in extensions:
            continue
        if source_command == "files" and categories:
            item_categories = extract_candidate_categories(item)
            if not any(category in item_categories for category in categories):
                continue
        if source_command == "docs" and kinds:
            kind = str(item.get("kind", "")).lower()
            if kind not in kinds:
                continue
        selected.append((item, source_path))
        if limit and len(selected) >= limit:
            break
    return selected


def normalize_extract_categories(categories: Optional[Sequence[str]], source_command: str) -> List[str]:
    if not categories:
        return []
    if source_command != "files":
        raise ExtractError("--category can only be used with files JSON input")

    normalized: List[str] = []
    seen = set()
    for category in categories:
        key = category.lower()
        if key not in ALL_FILE_CATEGORIES:
            supported = ", ".join(sorted(ALL_FILE_CATEGORIES))
            raise ExtractError(f"unsupported category for extract: {category} (supported: {supported})")
        if key in seen:
            continue
        seen.add(key)
        normalized.append(key)
    return normalized


def normalize_extract_kinds(kinds: Optional[Sequence[str]], source_command: str) -> List[str]:
    if not kinds:
        return []
    if source_command != "docs":
        raise ExtractError("--kind can only be used with docs JSON input")

    normalized: List[str] = []
    seen = set()
    for kind in kinds:
        key = kind.lower()
        if key not in SUPPORTED_DOC_KINDS:
            supported = ", ".join(sorted(SUPPORTED_DOC_KINDS))
            raise ExtractError(f"unsupported kind for extract: {kind} (supported: {supported})")
        if key in seen:
            continue
        seen.add(key)
        normalized.append(key)
    return normalized


def resolve_payload_root(root_value: object, base_dir: Path) -> Optional[Path]:
    if not isinstance(root_value, str) or not root_value.strip():
        return None
    root_path = Path(root_value).expanduser()
    if root_path.is_absolute():
        return root_path.resolve()
    return (base_dir / root_path).resolve()


def resolve_source_path(path_value: str, root: Optional[Path], base_dir: Path) -> Path:
    source_path = Path(path_value).expanduser()
    if source_path.is_absolute():
        return source_path.resolve()
    if root is not None:
        return (root / source_path).resolve()
    return (base_dir / source_path).resolve()


def build_destination_relative_path(source_path: Path, root: Optional[Path]) -> Path:
    if root is not None:
        try:
            return source_path.relative_to(root)
        except ValueError:
            pass

    safe_parts = sanitize_path_parts(source_path.parts, source_path.anchor)
    return Path("_external", *safe_parts)


def sanitize_path_parts(parts: Iterable[str], anchor: str) -> List[str]:
    safe_parts: List[str] = []
    for part in parts:
        if not part or part == anchor:
            continue
        safe_parts.append(part.replace(":", "_"))
    return safe_parts or ["copied-file"]


def extract_candidate_categories(item: Dict[str, object]) -> List[str]:
    categories = item.get("categories")
    if isinstance(categories, list):
        return [str(category).lower() for category in categories]
    category = item.get("category")
    if category:
        return [str(category).lower()]
    return []


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
