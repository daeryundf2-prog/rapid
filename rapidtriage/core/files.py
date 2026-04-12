from __future__ import annotations

import datetime as dt
import os
import stat as stat_module
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import FileCandidate

DEFAULT_FILE_CATEGORIES: Tuple[str, ...] = ("documents", "archives", "databases", "executables")
EXECUTABLE_BITS = stat_module.S_IXUSR | stat_module.S_IXGRP | stat_module.S_IXOTH

CATEGORY_RULES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "documents": {
        "extensions": (
            ".txt",
            ".pdf",
            ".doc",
            ".docx",
            ".rtf",
            ".odt",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".csv",
            ".tsv",
            ".md",
            ".json",
            ".xml",
            ".log",
        ),
        "name_keywords": ("report", "note", "notes", "memo", "document", "evidence", "invoice", "letter"),
        "path_keywords": ("document", "documents", "desktop", "downloads", "evidence", "report"),
    },
    "archives": {
        "extensions": (
            ".zip",
            ".7z",
            ".rar",
            ".tar",
            ".gz",
            ".tgz",
            ".bz2",
            ".xz",
            ".cab",
            ".iso",
        ),
        "name_keywords": ("archive", "backup", "compressed", "bundle"),
        "path_keywords": ("archive", "archives", "backup", "backups", "compressed"),
    },
    "databases": {
        "extensions": (
            ".db",
            ".db3",
            ".sqlite",
            ".sqlite3",
            ".mdb",
            ".accdb",
            ".edb",
            ".sdf",
            ".ldb",
            ".wal",
        ),
        "name_keywords": ("database", "sqlite"),
        "path_keywords": ("database", "databases", "sqlite"),
    },
    "executables": {
        "extensions": (
            ".exe",
            ".dll",
            ".sys",
            ".msi",
            ".bat",
            ".cmd",
            ".ps1",
            ".sh",
            ".com",
            ".scr",
            ".bin",
            ".jar",
            ".apk",
            ".appimage",
        ),
        "name_keywords": ("setup", "install", "run", "launcher", "dropper"),
        "path_keywords": ("bin", "sbin", "program files", "startup", "launchagents", "launchdaemons"),
    },
    "images": {
        "extensions": (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".tif",
            ".tiff",
            ".heic",
            ".webp",
        ),
        "name_keywords": ("photo", "image", "screenshot", "scan", "camera", "picture"),
        "path_keywords": ("pictures", "photos", "dcim", "camera", "images", "screenshots"),
    },
}
ALL_FILE_CATEGORIES: Tuple[str, ...] = tuple(CATEGORY_RULES)


class FileScanError(ValueError):
    """Raised when invalid file scan options are provided."""


def run_files_scan(
    root: Path,
    *,
    categories: Optional[Sequence[str]] = None,
    name_contains: Optional[Sequence[str]] = None,
    path_contains: Optional[Sequence[str]] = None,
    extensions: Optional[Sequence[str]] = None,
    modified_after: Optional[str] = None,
    modified_before: Optional[str] = None,
    limit: int = 0,
) -> Dict[str, object]:
    selected_categories = normalize_categories(categories)
    normalized_name_filters = normalize_text_filters(name_contains)
    normalized_path_filters = normalize_text_filters(path_contains)
    normalized_extensions = normalize_extensions(extensions)
    modified_after_dt = parse_modified_bound(modified_after)
    modified_before_dt = parse_modified_bound(modified_before)

    candidates, scanned_files = scan_file_candidates(
        root,
        categories=selected_categories,
        name_contains=normalized_name_filters,
        path_contains=normalized_path_filters,
        extensions=normalized_extensions,
        modified_after=modified_after_dt,
        modified_before=modified_before_dt,
        limit=limit,
    )

    category_counts = {category: 0 for category in selected_categories}
    for candidate in candidates:
        for category in candidate.categories:
            category_counts[category] = category_counts.get(category, 0) + 1

    modified_values = [candidate.modified_at for candidate in candidates]
    return {
        "command": "files",
        "root": str(root),
        "generated_at": dt.datetime.now().isoformat(),
        "filters": {
            "categories": list(selected_categories),
            "name_contains": normalized_name_filters,
            "path_contains": normalized_path_filters,
            "extensions": normalized_extensions,
            "modified_after": modified_after_dt.isoformat() if modified_after_dt else None,
            "modified_before": modified_before_dt.isoformat() if modified_before_dt else None,
            "limit": limit,
        },
        "summary": {
            "scanned_file_count": scanned_files,
            "candidate_count": len(candidates),
            "category_counts": category_counts,
            "newest_modified_at": max(modified_values) if modified_values else None,
            "oldest_modified_at": min(modified_values) if modified_values else None,
        },
        "candidates": [item.to_dict() for item in candidates],
    }


def scan_file_candidates(
    root: Path,
    *,
    categories: Sequence[str],
    name_contains: Sequence[str],
    path_contains: Sequence[str],
    extensions: Sequence[str],
    modified_after: Optional[dt.datetime],
    modified_before: Optional[dt.datetime],
    limit: int,
) -> Tuple[List[FileCandidate], int]:
    candidates: List[FileCandidate] = []
    scanned_files = 0
    pending = [root]

    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        entry_stat = entry.stat(follow_symlinks=False)
                    except (FileNotFoundError, PermissionError, OSError):
                        continue
                    scanned_files += 1
                    candidate = build_file_candidate(Path(entry.path), entry_stat, categories)
                    if candidate is None:
                        continue
                    if normalized_path_mismatch(candidate.path, path_contains):
                        continue
                    if normalized_name_mismatch(candidate.name, name_contains):
                        continue
                    if extensions and candidate.extension not in extensions:
                        continue
                    modified_dt = dt.datetime.fromtimestamp(candidate.modified_epoch)
                    if modified_after and modified_dt < modified_after:
                        continue
                    if modified_before and modified_dt > modified_before:
                        continue
                    candidates.append(candidate)
                    if limit and len(candidates) >= limit:
                        candidates.sort(key=lambda item: (-item.modified_epoch, item.path))
                        return candidates, scanned_files
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue

    candidates.sort(key=lambda item: (-item.modified_epoch, item.path))
    return candidates, scanned_files


def build_file_candidate(path: Path, entry_stat: os.stat_result, categories: Sequence[str]) -> Optional[FileCandidate]:
    extension = path.suffix.lower()
    filename = path.name.lower()
    path_text = str(path).lower()
    matched_categories: List[str] = []
    reasons: Dict[str, List[str]] = {}

    for category in categories:
        rule = CATEGORY_RULES[category]
        category_reasons: List[str] = []
        if extension and extension in rule["extensions"]:
            category_reasons.append(f"extension:{extension}")
        name_keyword = first_contains(filename, rule["name_keywords"])
        if name_keyword:
            category_reasons.append(f"name:{name_keyword}")
        path_keyword = first_contains(path_text, rule["path_keywords"])
        if path_keyword:
            category_reasons.append(f"path:{path_keyword}")
        if category == "executables" and entry_stat.st_mode & EXECUTABLE_BITS:
            category_reasons.append("mode:executable")
        if not category_reasons:
            continue
        matched_categories.append(category)
        reasons[category] = category_reasons

    if not matched_categories:
        return None

    modified_dt = dt.datetime.fromtimestamp(entry_stat.st_mtime)
    return FileCandidate(
        path=str(path),
        name=path.name,
        extension=extension,
        size=entry_stat.st_size,
        modified_at=modified_dt.isoformat(),
        modified_epoch=entry_stat.st_mtime,
        categories=matched_categories,
        reasons=reasons,
    )


def normalize_categories(categories: Optional[Sequence[str]]) -> List[str]:
    selected = list(categories or DEFAULT_FILE_CATEGORIES)
    normalized: List[str] = []
    seen = set()
    for category in selected:
        key = category.lower()
        if key not in CATEGORY_RULES:
            raise FileScanError(f"unsupported category: {category}")
        if key in seen:
            continue
        seen.add(key)
        normalized.append(key)
    return normalized


def normalize_text_filters(values: Optional[Sequence[str]]) -> List[str]:
    normalized: List[str] = []
    for value in values or []:
        key = value.strip().lower()
        if key:
            normalized.append(key)
    return normalized


def normalize_extensions(values: Optional[Sequence[str]]) -> List[str]:
    normalized: List[str] = []
    for value in values or []:
        key = value.strip().lower()
        if not key:
            continue
        if not key.startswith("."):
            key = f".{key}"
        normalized.append(key)
    return sorted(set(normalized))


def parse_modified_bound(value: Optional[str]) -> Optional[dt.datetime]:
    if value is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise FileScanError(f"invalid ISO timestamp: {value}") from exc
    if parsed.tzinfo is not None:
        return parsed.astimezone().replace(tzinfo=None)
    return parsed


def normalized_name_mismatch(name: str, filters: Sequence[str]) -> bool:
    lowered = name.lower()
    return any(fragment not in lowered for fragment in filters)


def normalized_path_mismatch(path: str, filters: Sequence[str]) -> bool:
    lowered = path.lower()
    return any(fragment not in lowered for fragment in filters)


def first_contains(text: str, values: Iterable[str]) -> Optional[str]:
    for value in values:
        if value in text:
            return value
    return None
