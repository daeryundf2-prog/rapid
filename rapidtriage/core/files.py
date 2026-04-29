from __future__ import annotations

import datetime as dt
import os
import stat as stat_module
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .input_root import InputRoot, resolve_input_root
from .hash_cache import compute_hashes_cached
from .models import FileCandidate
from .rules import RuleSet, annotate_files_payload

DEFAULT_FILE_CATEGORIES: Tuple[str, ...] = (
    "documents",
    "archives",
    "databases",
    "executables",
    "emails",
    "disk-images",
    "mobile-images",
    "memory-dumps",
    "vehicle-images",
    "images",
)
EXECUTABLE_BITS = stat_module.S_IXUSR | stat_module.S_IXGRP | stat_module.S_IXOTH

CATEGORY_RULES: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "documents": {
        "extensions": (
            ".txt",
            ".pdf",
            ".doc",
            ".docx",
            ".docm",
            ".rtf",
            ".odt",
            ".ods",
            ".xls",
            ".xlsx",
            ".xlsm",
            ".ppt",
            ".pptx",
            ".pptm",
            ".csv",
            ".tsv",
            ".md",
            ".json",
            ".jsonl",
            ".xml",
            ".html",
            ".htm",
            ".yaml",
            ".yml",
            ".ini",
            ".cfg",
            ".conf",
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
            ".rar5",
            ".tar",
            ".gz",
            ".gzip",
            ".tgz",
            ".bz2",
            ".xz",
            ".zst",
            ".cpio",
            ".dar",
            ".hpak",
            ".crash",
            ".cab",
            ".iso",
            ".dmg",
            ".wim",
            ".swm",
            ".z00",
            ".z01",
            ".7z001",
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
            ".sqlite-wal",
            ".sqlite-shm",
            ".plist",
            ".dat",
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
            ".vbs",
            ".js",
            ".jse",
            ".wsf",
            ".hta",
            ".py",
            ".pl",
            ".rb",
            ".elf",
            ".so",
            ".dylib",
            ".service",
            ".lnk",
        ),
        "name_keywords": ("setup", "install", "run", "launcher", "dropper"),
        "path_keywords": ("bin", "sbin", "program files", "startup", "launchagents", "launchdaemons"),
    },
    "emails": {
        "extensions": (
            ".eml",
            ".msg",
            ".mbox",
            ".pst",
            ".ost",
            ".olm",
            ".nsf",
        ),
        "name_keywords": ("mail", "email", "message", "inbox", "outbox", "sent", "archive"),
        "path_keywords": ("mail", "email", "outlook", "thunderbird", "inbox", "sent", "messages"),
    },
    "disk-images": {
        "extensions": (
            ".e01",
            ".ex01",
            ".aff",
            ".aff4",
            ".aff4-l",
            ".ad1",
            ".l01",
            ".lx01",
            ".bif",
            ".bin",
            ".dd",
            ".dmp",
            ".fip",
            ".ima",
            ".raw",
            ".img",
            ".mfd",
            ".mem",
            ".vfd",
            ".000",
            ".0000",
            ".0001",
            ".00001",
            ".001",
            ".vdi",
            ".vhd",
            ".vhdx",
            ".vmdk",
            ".xva",
            ".qcow",
            ".qcow2",
        ),
        "name_keywords": ("forensic-image", "disk-image", "drive-image", "volume-image"),
        "path_keywords": ("forensic-images", "disk-images", "drive-images", "volume-images"),
    },
    "mobile-images": {
        "extensions": (
            ".ab",
            ".aff4",
            ".aff4-l",
            ".ad1",
            ".bif",
            ".bin",
            ".dd",
            ".dmp",
            ".e01",
            ".ex01",
            ".fip",
            ".ima",
            ".img",
            ".l01",
            ".lx01",
            ".mfd",
            ".mem",
            ".raw",
            ".ufd",
            ".ufdx",
            ".vfd",
        ),
        "name_keywords": ("mobile-image", "phone-image", "ios-backup", "android-backup", "cellebrite", "graykey"),
        "path_keywords": ("mobile-images", "phone-images", "ios-backups", "android-backups", "cellebrite", "graykey"),
    },
    "memory-dumps": {
        "extensions": (
            ".bif",
            ".bin",
            ".crash",
            ".dd",
            ".dmg",
            ".dmp",
            ".elf",
            ".flp",
            ".hpak",
            ".ima",
            ".img",
            ".mdf",
            ".mem",
            ".raw",
            ".vfd",
            ".vmem",
            ".vmsn",
            ".vmss",
        ),
        "name_keywords": ("memory", "memdump", "ram", "dumpit", "volatility", "vmem"),
        "path_keywords": ("memory", "memdump", "ram", "dumpit", "volatility", "memory-dumps"),
    },
    "vehicle-images": {
        "extensions": (".ivo",),
        "name_keywords": ("vehicle", "ive", "route", "trackpoint", "waypoint"),
        "path_keywords": ("vehicle", "vehicles", "ive", "routes", "trackpoints", "waypoints"),
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
    root: Union[InputRoot, Path],
    *,
    input_kind: str | None = None,
    categories: Optional[Sequence[str]] = None,
    name_contains: Optional[Sequence[str]] = None,
    path_contains: Optional[Sequence[str]] = None,
    extensions: Optional[Sequence[str]] = None,
    modified_after: Optional[str] = None,
    modified_before: Optional[str] = None,
    limit: int = 0,
    rule_set: RuleSet | None = None,
) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    selected_categories = normalize_categories(categories)
    normalized_name_filters = normalize_text_filters(name_contains)
    normalized_path_filters = normalize_text_filters(path_contains)
    normalized_extensions = normalize_extensions(extensions)
    modified_after_dt = parse_modified_bound(modified_after)
    modified_before_dt = parse_modified_bound(modified_before)

    candidates, scanned_files = scan_file_candidates(
        input_root.root_path,
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
    duplicate_groups = build_duplicate_content_groups(candidates)
    payload = {
        "command": "files",
        "root": str(input_root.root_path),
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
            "duplicate_group_count": len(duplicate_groups),
            "duplicate_file_count": sum(int(group["file_count"]) for group in duplicate_groups),
        },
        "duplicate_content_groups": duplicate_groups,
        "candidates": [item.to_dict() for item in candidates],
    }
    if rule_set is not None:
        annotate_files_payload(payload, rule_set)
    return payload


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


def build_duplicate_content_groups(
    candidates: Sequence[FileCandidate],
    *,
    max_hash_bytes: int = 50 * 1024 * 1024,
    max_files_to_hash: int = 500,
) -> list[dict[str, object]]:
    size_buckets: dict[int, list[FileCandidate]] = {}
    for candidate in candidates:
        size_buckets.setdefault(int(candidate.size), []).append(candidate)
    hash_buckets: dict[str, list[FileCandidate]] = {}
    hashed_count = 0
    for size, bucket in size_buckets.items():
        if len(bucket) < 2 or size > max_hash_bytes:
            continue
        for candidate in bucket:
            if hashed_count >= max_files_to_hash:
                break
            try:
                sha256 = compute_hashes_cached(Path(candidate.path))["sha256"]
            except OSError:
                continue
            hash_buckets.setdefault(sha256, []).append(candidate)
            hashed_count += 1
    groups = []
    for sha256, bucket in sorted(hash_buckets.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(bucket) < 2:
            continue
        groups.append(
            {
                "sha256": sha256,
                "file_count": len(bucket),
                "size": bucket[0].size,
                "paths": [candidate.path for candidate in bucket[:20]],
                "truncated_paths": len(bucket) > 20,
            }
        )
        if len(groups) >= 50:
            break
    return groups
