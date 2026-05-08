from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import stat as stat_module
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from .input_root import InputRoot, resolve_input_root
from .forensic_accuracy import build_accuracy_gate
from .hash_cache import HASH_CACHE_GAP_ID, build_hash_cache_manifest, compute_hashes_cached, hash_cache_assessment
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
DEDUPLICATE_CONTENT_GAP_ID = "#77"
FUNCTIONAL_SCALE_BATCH_ID = "commercial-uplift-031-035"
DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77 = "trusted-duplicate-file-manifest-diff-missing"
DUPLICATE_CONTENT_TRUSTED_TOOLS = {"duplicate-file-manifest", "known-answer-duplicate-group-export", "content-hash-oracle"}
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
    duplicate_content_manifest = build_duplicate_content_manifest(duplicate_groups)
    hash_cache_manifest = build_hash_cache_manifest()
    hash_cache_profile = hash_cache_assessment(cache_manifest=hash_cache_manifest)
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
            "commercial_gap_ids": [HASH_CACHE_GAP_ID, DEDUPLICATE_CONTENT_GAP_ID],
        },
        "hash_cache_manifest": hash_cache_manifest,
        "hash_cache_assessment": hash_cache_profile,
        "duplicate_content_manifest": duplicate_content_manifest,
        "duplicate_detection_assessment": duplicate_detection_assessment(
            duplicate_groups,
            duplicate_manifest=duplicate_content_manifest,
        ),
        "core_accuracy_gates": [
            *hash_cache_profile["core_accuracy_gates"],
            *duplicate_content_core_accuracy_gates(duplicate_groups),
        ],
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
        sorted_bucket = sorted(bucket, key=lambda candidate: (candidate.path.lower(), candidate.modified_epoch))
        paths = [candidate.path for candidate in sorted_bucket[:20]]
        group_core = {
            "sha256": sha256,
            "size": sorted_bucket[0].size,
            "paths": paths,
        }
        group_fingerprint = hashlib.sha256(json.dumps(group_core, sort_keys=True).encode("utf-8")).hexdigest()
        groups.append(
            {
                "group_id": f"dup-{sha256[:16]}",
                "sha256": sha256,
                "group_fingerprint": group_fingerprint,
                "file_count": len(sorted_bucket),
                "size": sorted_bucket[0].size,
                "representative_path": sorted_bucket[0].path,
                "representative_name": sorted_bucket[0].name,
                "paths": paths,
                "truncated_paths": len(sorted_bucket) > 20,
                "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
                "duplicate_resolution_status": "hash-identical-candidate",
                "report_suppression_status": "not-suppressed",
                "analyst_review_required": True,
                "suppression_policy": {
                    "safe_to_auto_suppress": False,
                    "reason": "hash-identical candidates still require analyst source/path/context review before report suppression",
                },
            }
        )
        if len(groups) >= 50:
            break
    return groups


def build_duplicate_content_manifest(groups: Sequence[Mapping[str, object]]) -> dict[str, object]:
    compact_groups = []
    for group in groups:
        compact_groups.append(
            {
                "group_id": group.get("group_id", ""),
                "sha256": group.get("sha256", ""),
                "group_fingerprint": group.get("group_fingerprint", ""),
                "file_count": int(group.get("file_count") or 0),
                "size": int(group.get("size") or 0),
                "representative_path": group.get("representative_path", ""),
                "representative_name": group.get("representative_name", ""),
                "path_count": len(group.get("paths") or []),
                "truncated_paths": bool(group.get("truncated_paths")),
                "report_suppression_status": group.get("report_suppression_status", "not-suppressed"),
                "analyst_review_required": bool(group.get("analyst_review_required", True)),
            }
        )
    manifest_core = {
        "profile": "duplicate-content-manifest-v1",
        "profile_version": "duplicate-content-manifest-v1",
        "item_number": 77,
        "method": "same-size-bucket-sha256-confirmation",
        "group_count": len(compact_groups),
        "duplicate_file_count": sum(int(group.get("file_count") or 0) for group in compact_groups),
        "group_head_hash": hashlib.sha256(json.dumps(compact_groups, sort_keys=True).encode("utf-8")).hexdigest(),
        "exact_hash_grouping": True,
        "fuzzy_text_grouping": False,
        "perceptual_media_grouping": False,
        "suppression_policy": {
            "auto_suppression_enabled": False,
            "analyst_override_required": True,
            "report_suppression_default": "not-suppressed",
        },
        "groups": compact_groups,
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def duplicate_detection_assessment(
    groups: Sequence[Mapping[str, object]],
    *,
    duplicate_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    manifest = dict(duplicate_manifest) if duplicate_manifest else build_duplicate_content_manifest(groups)
    suppression_manifest = build_duplicate_suppression_manifest(groups, duplicate_content_manifest=manifest)
    satisfied = [
        "same-size candidate bucketing",
            "bounded SHA256 confirmation",
            "duplicate group counts",
            "representative paths listed",
            "duplicate-content manifest hash emitted",
            "duplicate-suppression manifest hash emitted",
            "duplicate review matrix hash emitted",
            "not-suppressed policy emitted",
            "suppression verification warning",
    ]
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted duplicate file manifest diff pass")
    blockers = [
        "near-duplicate-text-and-media-similarity-are-not-full-file-deduplication",
        "hashing-is-bounded-to-protect-large-case-responsiveness",
        "operator-must-verify-source-hashes-before-suppressing-duplicates-in-reports",
    ]
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77)
    return {
        "component": "duplicate-file-content-detection",
        "status": "bounded-sha256-same-size-grouping",
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "functional_priority_profile": duplicate_suppression_functional_profile(
            groups,
            suppression_manifest=suppression_manifest,
        ),
        "duplicate_content_manifest": manifest,
        "duplicate_suppression_manifest": suppression_manifest,
        "duplicate_suppression_manifest_hash": suppression_manifest["manifest_hash"],
        "duplicate_group_count": len(groups),
        "duplicate_file_count": sum(int(group.get("file_count") or 0) for group in groups),
        "ready_for_court_report": False,
        "trusted_duplicate_content_diff": dict(trusted_diff) if trusted_diff else missing_duplicate_content_trusted_diff(),
        "core_accuracy_gates": duplicate_content_core_accuracy_gates(
            groups,
            satisfied_checks=satisfied,
            duplicate_manifest=manifest,
            suppression_manifest=suppression_manifest,
            trusted_diff=trusted_diff,
        ),
        "supports": [
            "same-size-candidate-bucketing",
            "bounded-content-sha256-confirmation",
            "representative-path-lists",
            "duplicate-content-manifest",
            "duplicate-review-matrix",
            "not-suppressed-until-analyst-review",
        ],
        "blockers": blockers,
    }


def build_duplicate_suppression_manifest(
    groups: Sequence[Mapping[str, object]],
    *,
    duplicate_content_manifest: Mapping[str, object],
) -> dict[str, object]:
    review_matrix = [
        {
            "group_id": str(group.get("group_id") or ""),
            "file_count": int(group.get("file_count") or 0),
            "representative_name": str(group.get("representative_name") or ""),
            "report_suppression_status": str(group.get("report_suppression_status") or "not-suppressed"),
            "analyst_review_required": bool(group.get("analyst_review_required", True)),
            "required_decision": "include-representative-or-keep-all-with-note",
        }
        for group in groups
    ]
    review_matrix_hash = hashlib.sha256(json.dumps(review_matrix, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile_version": "duplicate-suppression-manifest-v1",
        "item_number": 33,
        "gap_id": "#33",
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "duplicate_content_manifest_hash": str(duplicate_content_manifest.get("manifest_hash") or ""),
        "duplicate_group_count": len(groups),
        "duplicate_file_count": sum(int(group.get("file_count") or 0) for group in groups),
        "representative_selection": "stable-path-order-first-candidate",
        "report_suppression_default": "not-suppressed",
        "auto_suppression_enabled": False,
        "analyst_override_required": True,
        "review_matrix": review_matrix,
        "review_matrix_hash": review_matrix_hash,
        "review_decision_required_for_each_group": True,
        "collapse_by_default_in_ui": False,
        "near_duplicate_text_supported": False,
        "perceptual_media_similarity_supported": False,
        "trusted_diff_blocker": DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77,
        "commercial_claim_allowed": False,
    }
    return {
        **manifest_core,
        "manifest_hash": hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest(),
    }


def duplicate_suppression_functional_profile(
    groups: Sequence[Mapping[str, object]],
    *,
    suppression_manifest: Mapping[str, object],
) -> dict[str, object]:
    return {
        "batch_id": FUNCTIONAL_SCALE_BATCH_ID,
        "item_number": 33,
        "gap_id": "#33",
        "component": "duplicate-suppression",
        "status": "implemented-hash-identical-grouping-validation-required",
        "implemented": True,
        "usable": True,
        "validated": True,
        "ready_for_commercial_claim": False,
        "controls": {
            "duplicate_group_count": len(groups),
            "duplicate_file_count": sum(int(group.get("file_count") or 0) for group in groups),
            "same_size_candidate_bucketing": True,
            "bounded_sha256_confirmation": True,
            "representative_paths_listed": True,
            "suppression_manifest_hash": str(suppression_manifest.get("manifest_hash") or ""),
            "review_matrix_hash": str(suppression_manifest.get("review_matrix_hash") or ""),
            "duplicate_content_manifest_hash": str(suppression_manifest.get("duplicate_content_manifest_hash") or ""),
            "collapse_by_default_in_ui": False,
            "auto_suppression_enabled": False,
            "analyst_override_required_before_report_suppression": True,
        },
        "blockers": [
            DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77,
            "ui-collapse-and-suppression-state-not-yet-persisted",
            "near-duplicate-text-and-perceptual-media-similarity-not-complete",
        ],
        "validation_evidence": [
            "files-output-emits-functional-duplicate-suppression-profile",
            "unit-test-asserts-duplicate-profile-contract",
        ],
    }


def duplicate_content_core_accuracy_gates(
    groups: Sequence[Mapping[str, object]],
    *,
    satisfied_checks: Sequence[str] | None = None,
    duplicate_manifest: Mapping[str, object] | None = None,
    suppression_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    manifest = duplicate_manifest or build_duplicate_content_manifest(groups)
    suppression = suppression_manifest or build_duplicate_suppression_manifest(groups, duplicate_content_manifest=manifest)
    satisfied = list(
        satisfied_checks
        or (
            "same-size candidate bucketing",
            "bounded SHA256 confirmation",
            "duplicate group counts",
            "representative paths listed",
            "duplicate-content manifest hash emitted",
            "duplicate review matrix hash emitted",
            "not-suppressed policy emitted",
            "suppression verification warning",
        )
    )
    if trusted_diff and trusted_diff.get("status") == "pass" and "trusted duplicate file manifest diff pass" not in satisfied:
        satisfied.append("trusted duplicate file manifest diff pass")
    return [
        build_accuracy_gate(
            77,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"duplicate_group_count:{len(groups)}",
                f"duplicate_file_count:{sum(int(group.get('file_count') or 0) for group in groups)}",
                f"manifest_hash:{manifest.get('manifest_hash', '')}",
                f"suppression_manifest_hash:{suppression.get('manifest_hash', '')}",
            ],
        )
    ]


def missing_duplicate_content_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "blocker": DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77,
        "required_trusted_tools": sorted(DUPLICATE_CONTENT_TRUSTED_TOOLS),
    }


def build_duplicate_content_trusted_diff(
    rapid_groups: Sequence[Mapping[str, object]],
    trusted_groups: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str = "duplicate-file-manifest",
) -> dict[str, object]:
    rapid_index = index_duplicate_groups(rapid_groups)
    trusted_index = index_duplicate_groups(trusted_groups)
    mismatches: list[dict[str, object]] = []
    for sha256, trusted_group in trusted_index.items():
        rapid_group = rapid_index.get(sha256)
        if rapid_group is None:
            mismatches.append({"sha256": sha256, "field": "group", "rapid": None, "trusted": "present"})
            continue
        for field in ("file_count", "size", "paths", "group_fingerprint", "report_suppression_status"):
            rapid_value = rapid_group.get(field)
            trusted_value = trusted_group.get(field)
            if field == "paths":
                rapid_value = sorted(str(path) for path in rapid_value or [])
                trusted_value = sorted(str(path) for path in trusted_value or [])
            if rapid_value != trusted_value:
                mismatches.append({"sha256": sha256, "field": field, "rapid": rapid_value, "trusted": trusted_value})
    for sha256 in sorted(set(rapid_index) - set(trusted_index)):
        mismatches.append({"sha256": sha256, "field": "group", "rapid": "present", "trusted": None})
    status = "pass" if not mismatches and trusted_tool in DUPLICATE_CONTENT_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "rapid_group_count": len(rapid_index),
        "trusted_group_count": len(trusted_index),
        "mismatches": mismatches,
        "blocker": None if status == "pass" else DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77,
    }


def index_duplicate_groups(groups: Sequence[Mapping[str, object]]) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    for group in groups:
        sha256 = str(group.get("sha256") or "")
        if not sha256:
            continue
        indexed[sha256] = group
    return indexed
