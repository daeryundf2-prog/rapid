from __future__ import annotations

import datetime as dt
import csv
import difflib
import hashlib
import json
import os
import re
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
DENISTING_GAP_ID = "visible-denisting"
FUNCTIONAL_SCALE_BATCH_ID = "commercial-uplift-031-035"
DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77 = "trusted-duplicate-file-manifest-diff-missing"
DUPLICATE_CONTENT_TRUSTED_TOOLS = {"duplicate-file-manifest", "known-answer-duplicate-group-export", "content-hash-oracle"}
EXECUTABLE_BITS = stat_module.S_IXUSR | stat_module.S_IXGRP | stat_module.S_IXOTH
DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES = 64 * 1024 * 1024
KNOWN_GOOD_HASH_ALGORITHMS = ("md5", "sha1", "sha256")
HASH_TOKEN_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
FUZZY_TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".csv",
    ".tsv",
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
}

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
    known_good_hash_feeds: Optional[Sequence[Union[str, Path]]] = None,
    hide_known_good: bool = False,
    known_good_max_hash_bytes: int = DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES,
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

    known_good_index = load_known_good_hash_feeds(known_good_hash_feeds or [])
    known_good_result = apply_known_good_hash_profile(
        candidates,
        known_good_index=known_good_index,
        hide_known_good=hide_known_good,
        max_hash_bytes=known_good_max_hash_bytes,
    )
    visible_candidates = known_good_result["visible_candidates"]
    candidate_payloads = known_good_result["candidate_payloads"]
    known_good_profile = known_good_result["profile"]

    category_counts = {category: 0 for category in selected_categories}
    for candidate in visible_candidates:
        for category in candidate.categories:
            category_counts[category] = category_counts.get(category, 0) + 1

    modified_values = [candidate.modified_at for candidate in visible_candidates]
    duplicate_groups = build_duplicate_content_groups(visible_candidates)
    fuzzy_text_groups = build_fuzzy_text_duplicate_groups(visible_candidates)
    duplicate_content_manifest = build_duplicate_content_manifest(
        duplicate_groups,
        fuzzy_text_groups=fuzzy_text_groups,
    )
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
            "known_good_hash_feeds": [str(path) for path in known_good_index["feed_paths"]],
            "hide_known_good": hide_known_good,
            "known_good_max_hash_bytes": known_good_max_hash_bytes,
        },
        "summary": {
            "scanned_file_count": scanned_files,
            "candidate_count": len(visible_candidates),
            "raw_candidate_count": len(candidates),
            "category_counts": category_counts,
            "newest_modified_at": max(modified_values) if modified_values else None,
            "oldest_modified_at": min(modified_values) if modified_values else None,
            "duplicate_group_count": len(duplicate_groups),
            "duplicate_file_count": sum(int(group["file_count"]) for group in duplicate_groups),
            "fuzzy_text_duplicate_group_count": len(fuzzy_text_groups),
            "fuzzy_text_duplicate_file_count": sum(int(group["file_count"]) for group in fuzzy_text_groups),
            "known_good_feed_count": len(known_good_index["feed_paths"]),
            "known_good_hash_count": known_good_profile["known_good_hash_count"],
            "known_good_match_count": known_good_profile["match_count"],
            "known_good_suppressed_count": known_good_profile["suppressed_count"],
            "known_good_hash_skipped_large_count": known_good_profile["skipped_large_count"],
            "commercial_gap_ids": [HASH_CACHE_GAP_ID, DEDUPLICATE_CONTENT_GAP_ID, DENISTING_GAP_ID],
        },
        "known_good_suppression_profile": known_good_profile,
        "known_good_suppressed_candidates": known_good_result["suppressed_candidates"],
        "hash_cache_manifest": hash_cache_manifest,
        "hash_cache_assessment": hash_cache_profile,
        "duplicate_content_manifest": duplicate_content_manifest,
        "duplicate_detection_assessment": duplicate_detection_assessment(
            duplicate_groups,
            duplicate_manifest=duplicate_content_manifest,
            fuzzy_text_groups=fuzzy_text_groups,
        ),
        "core_accuracy_gates": [
            *hash_cache_profile["core_accuracy_gates"],
            *duplicate_content_core_accuracy_gates(
                duplicate_groups,
                fuzzy_text_groups=fuzzy_text_groups,
                duplicate_manifest=duplicate_content_manifest,
            ),
        ],
        "duplicate_content_groups": duplicate_groups,
        "fuzzy_text_duplicate_groups": fuzzy_text_groups,
        "candidates": candidate_payloads,
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


def load_known_good_hash_feeds(paths: Sequence[Union[str, Path]]) -> dict[str, object]:
    """Load analyst-provided known-good hash feeds without requiring a full NSRL install."""

    index: dict[str, set[str]] = {algorithm: set() for algorithm in KNOWN_GOOD_HASH_ALGORITHMS}
    feed_paths: list[Path] = []
    feed_summaries: list[dict[str, object]] = []
    duplicate_count = 0
    rejected_token_count = 0

    for raw_path in paths:
        feed_path = Path(raw_path).expanduser().resolve()
        if not feed_path.exists():
            raise FileScanError(f"known-good hash feed not found: {feed_path}")
        if not feed_path.is_file():
            raise FileScanError(f"known-good hash feed is not a file: {feed_path}")
        feed_paths.append(feed_path)
        before_count = sum(len(values) for values in index.values())
        raw_tokens = extract_hash_feed_tokens(feed_path)
        accepted_for_feed = 0
        rejected_for_feed = 0
        duplicates_for_feed = 0
        for token in raw_tokens:
            normalized = normalize_known_good_hash(token)
            if normalized is None:
                rejected_for_feed += 1
                continue
            algorithm, value = normalized
            if value in index[algorithm]:
                duplicates_for_feed += 1
                continue
            index[algorithm].add(value)
            accepted_for_feed += 1
        after_count = sum(len(values) for values in index.values())
        duplicate_count += duplicates_for_feed
        rejected_token_count += rejected_for_feed
        feed_summaries.append(
            {
                "path": str(feed_path),
                "format": guess_known_good_feed_format(feed_path),
                "accepted_hash_count": accepted_for_feed,
                "duplicate_hash_count": duplicates_for_feed,
                "rejected_token_count": rejected_for_feed,
                "cumulative_hash_count_before": before_count,
                "cumulative_hash_count_after": after_count,
            }
        )

    return {
        "hashes": index,
        "feed_paths": feed_paths,
        "feed_summaries": feed_summaries,
        "duplicate_count": duplicate_count,
        "rejected_token_count": rejected_token_count,
    }


def extract_hash_feed_tokens(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        tokens: list[str] = []
        collect_hash_tokens_from_json(data, tokens)
        return tokens
    if suffix == ".csv":
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        tokens = []
        for row in csv.DictReader(text.splitlines()):
            for key, value in row.items():
                lowered_key = (key or "").strip().lower()
                if lowered_key in {"md5", "sha1", "sha256", "hash", "value", "digest"}:
                    tokens.extend(HASH_TOKEN_RE.findall(value or ""))
        if tokens:
            return tokens
        return HASH_TOKEN_RE.findall(text)
    return HASH_TOKEN_RE.findall(path.read_text(encoding="utf-8", errors="replace"))


def collect_hash_tokens_from_json(value: object, tokens: list[str]) -> None:
    if isinstance(value, str):
        tokens.extend(HASH_TOKEN_RE.findall(value))
        return
    if isinstance(value, Mapping):
        for item in value.values():
            collect_hash_tokens_from_json(item, tokens)
        return
    if isinstance(value, list):
        for item in value:
            collect_hash_tokens_from_json(item, tokens)


def guess_known_good_feed_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".json", ".csv"}:
        return suffix[1:]
    return "text"


def normalize_known_good_hash(value: str) -> Optional[tuple[str, str]]:
    token = value.strip().lower()
    if len(token) == 32 and all(char in "0123456789abcdef" for char in token):
        return "md5", token
    if len(token) == 40 and all(char in "0123456789abcdef" for char in token):
        return "sha1", token
    if len(token) == 64 and all(char in "0123456789abcdef" for char in token):
        return "sha256", token
    return None


def apply_known_good_hash_profile(
    candidates: Sequence[FileCandidate],
    *,
    known_good_index: Mapping[str, object],
    hide_known_good: bool,
    max_hash_bytes: int,
) -> dict[str, object]:
    if max_hash_bytes < 0:
        raise FileScanError("known-good max hash bytes must be >= 0")

    raw_hash_index = known_good_index.get("hashes", {})
    if not isinstance(raw_hash_index, Mapping):
        raw_hash_index = {}
    known_good_hashes = {algorithm: set(raw_hash_index.get(algorithm, set())) for algorithm in KNOWN_GOOD_HASH_ALGORITHMS}
    configured = any(known_good_hashes.values())
    visible_candidates: list[FileCandidate] = []
    candidate_payloads: list[dict[str, object]] = []
    suppressed_candidates: list[dict[str, object]] = []
    match_count = 0
    skipped_large_count = 0
    hashed_candidate_count = 0

    for candidate in candidates:
        candidate_payload = candidate.to_dict()
        known_good_match: Optional[dict[str, object]] = None
        if configured:
            if int(candidate.size) > max_hash_bytes:
                skipped_large_count += 1
                candidate_payload["known_good_status"] = "not-checked-size-limit"
            else:
                try:
                    hashes = compute_hashes_cached(Path(candidate.path))
                except OSError as exc:
                    candidate_payload["known_good_status"] = "hash-error"
                    candidate_payload["known_good_error"] = exc.__class__.__name__
                else:
                    hashed_candidate_count += 1
                    known_good_match = first_known_good_hash_match(hashes, known_good_hashes)
                    if known_good_match:
                        match_count += 1
                        candidate_payload["known_good_status"] = "known-good-feed-match"
                        candidate_payload["known_good_match"] = known_good_match
                        candidate_payload["report_suppression_status"] = (
                            "suppressed-known-good" if hide_known_good else "candidate-known-good-reviewable"
                        )
                        candidate_payload["analyst_review_required"] = not hide_known_good
                    else:
                        candidate_payload["known_good_status"] = "not-known-good"
        else:
            candidate_payload["known_good_status"] = "not-configured"

        if known_good_match and hide_known_good:
            suppressed_candidates.append(
                {
                    "path": candidate.path,
                    "name": candidate.name,
                    "size": candidate.size,
                    "modified_at": candidate.modified_at,
                    "known_good_match": known_good_match,
                    "suppression_reason": "analyst-enabled-known-good-feed-match",
                    "source_viewer_locator": {
                        "source": "files",
                        "path": candidate.path,
                        "viewer": "file-metadata",
                    },
                }
            )
            continue
        visible_candidates.append(candidate)
        candidate_payloads.append(candidate_payload)

    suppressed_candidates_truncated = len(suppressed_candidates) > 200
    suppressed_head = suppressed_candidates[:200]
    profile_core = {
        "profile": "known-good-hash-suppression-v1",
        "profile_version": "known-good-hash-suppression-v1",
        "capability_id": "denisting-nsrl-whitelist",
        "commercial_gap_ids": [DENISTING_GAP_ID],
        "configured": configured,
        "hide_known_good": hide_known_good,
        "max_hash_bytes": max_hash_bytes,
        "candidate_count": len(candidates),
        "visible_candidate_count": len(visible_candidates),
        "hashed_candidate_count": hashed_candidate_count,
        "known_good_hash_count": sum(len(values) for values in known_good_hashes.values()),
        "known_good_hash_counts_by_algorithm": {
            algorithm: len(known_good_hashes[algorithm]) for algorithm in KNOWN_GOOD_HASH_ALGORITHMS
        },
        "feed_count": len(known_good_index.get("feed_paths", [])),
        "feed_summaries": list(known_good_index.get("feed_summaries", [])),
        "duplicate_feed_hash_count": int(known_good_index.get("duplicate_count", 0)),
        "rejected_feed_token_count": int(known_good_index.get("rejected_token_count", 0)),
        "match_count": match_count,
        "suppressed_count": len(suppressed_candidates) if hide_known_good else 0,
        "skipped_large_count": skipped_large_count,
        "suppressed_candidates_truncated": suppressed_candidates_truncated,
        "policy": {
            "default_behavior": "mark-known-good-without-hiding",
            "hide_behavior": "hide only when --hide-known-good is explicitly provided",
            "scope": "analyst-supplied MD5/SHA1/SHA256 feeds; full NSRL RDS ingestion is not bundled",
            "legal_review_note": "Known-good suppression reduces triage noise but does not prove irrelevance by itself.",
        },
        "limitations": [
            "Full NSRL RDS database ingestion/update workflow is not implemented.",
            "Files larger than max_hash_bytes are skipped to avoid surprise long-running scans.",
            "Hash-based known-good checks cannot identify modified-but-benign files without a trusted feed match.",
        ],
        "source_viewer_contract": {
            "candidate_field": "known_good_match",
            "suppressed_list": "known_good_suppressed_candidates",
            "review_action": "toggle --hide-known-good off when the analyst needs to inspect suppressed rows",
        },
        "commercial_claim_allowed": False,
    }
    profile_hash = hashlib.sha256(json.dumps(profile_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "visible_candidates": visible_candidates,
        "candidate_payloads": candidate_payloads,
        "suppressed_candidates": suppressed_head,
        "profile": {**profile_core, "profile_hash": profile_hash},
    }


def first_known_good_hash_match(
    hashes: Mapping[str, str],
    known_good_hashes: Mapping[str, set[str]],
) -> Optional[dict[str, object]]:
    for algorithm in KNOWN_GOOD_HASH_ALGORITHMS:
        value = hashes.get(algorithm, "").lower()
        if value and value in known_good_hashes.get(algorithm, set()):
            return {
                "algorithm": algorithm,
                "value": value,
                "source": "analyst-known-good-feed",
                "classification": "known-good",
                "confidence": "hash-exact",
            }
    return None


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


def build_fuzzy_text_duplicate_groups(
    candidates: Sequence[FileCandidate],
    *,
    max_files: int = 200,
    max_text_bytes: int = 256 * 1024,
    min_similarity: float = 0.82,
) -> list[dict[str, object]]:
    text_items = []
    for candidate in candidates:
        if len(text_items) >= max_files:
            break
        if candidate.extension not in FUZZY_TEXT_EXTENSIONS or int(candidate.size) <= 0 or int(candidate.size) > max_text_bytes:
            continue
        try:
            normalized = normalized_text_for_duplicate_candidate(Path(candidate.path), max_text_bytes=max_text_bytes)
        except OSError:
            continue
        if len(normalized) < 16:
            continue
        tokens = set(normalized.split())
        if len(tokens) < 3:
            continue
        text_items.append(
            {
                "candidate": candidate,
                "normalized": normalized,
                "tokens": tokens,
                "normalized_sha256": hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            }
        )
    adjacency: dict[int, set[int]] = {index: set() for index in range(len(text_items))}
    for left_index, left in enumerate(text_items):
        for right_index in range(left_index + 1, len(text_items)):
            right = text_items[right_index]
            token_score = jaccard_similarity(left["tokens"], right["tokens"])
            if token_score < min_similarity:
                sequence_score = difflib.SequenceMatcher(None, left["normalized"], right["normalized"]).ratio()
                if sequence_score < min_similarity:
                    continue
            adjacency[left_index].add(right_index)
            adjacency[right_index].add(left_index)
    groups: list[dict[str, object]] = []
    visited: set[int] = set()
    for start in range(len(text_items)):
        if start in visited or not adjacency[start]:
            continue
        stack = [start]
        component: set[int] = set()
        while stack:
            index = stack.pop()
            if index in component:
                continue
            component.add(index)
            stack.extend(adjacency[index] - component)
        visited.update(component)
        if len(component) < 2:
            continue
        members = sorted((text_items[index] for index in component), key=lambda item: item["candidate"].path.lower())
        paths = [item["candidate"].path for item in members[:20]]
        group_core = {
            "paths": paths,
            "normalized_sha256_values": [item["normalized_sha256"] for item in members],
            "min_similarity": min_similarity,
        }
        group_fingerprint = hashlib.sha256(json.dumps(group_core, sort_keys=True).encode("utf-8")).hexdigest()
        representative = members[0]["candidate"]
        groups.append(
            {
                "group_id": f"textdup-{group_fingerprint[:16]}",
                "group_fingerprint": group_fingerprint,
                "file_count": len(members),
                "representative_path": representative.path,
                "representative_name": representative.name,
                "paths": paths,
                "truncated_paths": len(members) > 20,
                "min_similarity": min_similarity,
                "match_type": "normalized-text-near-duplicate-candidate",
                "normalized_sha256_values": [item["normalized_sha256"] for item in members[:20]],
                "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
                "duplicate_resolution_status": "near-duplicate-text-candidate",
                "report_suppression_status": "not-suppressed",
                "analyst_review_required": True,
                "suppression_policy": {
                    "safe_to_auto_suppress": False,
                    "reason": "near-duplicate text candidates require analyst semantic review before report suppression",
                },
            }
        )
        if len(groups) >= 50:
            break
    return groups


def normalized_text_for_duplicate_candidate(path: Path, *, max_text_bytes: int) -> str:
    raw = path.read_bytes()[:max_text_bytes]
    text = raw.decode("utf-8", errors="ignore").lower()
    normalized_chars = [char if char.isalnum() else " " for char in text]
    return " ".join("".join(normalized_chars).split())


def jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def build_duplicate_content_manifest(
    groups: Sequence[Mapping[str, object]],
    *,
    fuzzy_text_groups: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    fuzzy_text_groups = fuzzy_text_groups or []
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
    compact_fuzzy_text_groups = []
    for group in fuzzy_text_groups:
        compact_fuzzy_text_groups.append(
            {
                "group_id": group.get("group_id", ""),
                "group_fingerprint": group.get("group_fingerprint", ""),
                "file_count": int(group.get("file_count") or 0),
                "representative_path": group.get("representative_path", ""),
                "representative_name": group.get("representative_name", ""),
                "path_count": len(group.get("paths") or []),
                "truncated_paths": bool(group.get("truncated_paths")),
                "min_similarity": float(group.get("min_similarity") or 0.0),
                "match_type": group.get("match_type", ""),
                "report_suppression_status": group.get("report_suppression_status", "not-suppressed"),
                "analyst_review_required": bool(group.get("analyst_review_required", True)),
            }
        )
    manifest_core = {
        "profile": "duplicate-content-manifest-v1",
        "profile_version": "duplicate-content-manifest-v1",
        "item_number": 77,
        "method": "same-size-bucket-sha256-confirmation-and-normalized-text-near-duplicate-candidates",
        "group_count": len(compact_groups),
        "duplicate_file_count": sum(int(group.get("file_count") or 0) for group in compact_groups),
        "fuzzy_text_group_count": len(compact_fuzzy_text_groups),
        "fuzzy_text_file_count": sum(int(group.get("file_count") or 0) for group in compact_fuzzy_text_groups),
        "group_head_hash": hashlib.sha256(json.dumps(compact_groups, sort_keys=True).encode("utf-8")).hexdigest(),
        "fuzzy_text_group_head_hash": hashlib.sha256(
            json.dumps(compact_fuzzy_text_groups, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "exact_hash_grouping": True,
        "fuzzy_text_grouping": True,
        "perceptual_media_grouping": False,
        "fuzzy_text_policy": {
            "method": "normalized-token-jaccard-with-sequence-ratio-fallback",
            "auto_suppression_enabled": False,
            "analyst_review_required": True,
        },
        "suppression_policy": {
            "auto_suppression_enabled": False,
            "analyst_override_required": True,
            "report_suppression_default": "not-suppressed",
        },
        "groups": compact_groups,
        "fuzzy_text_groups": compact_fuzzy_text_groups,
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "commercial_claim_allowed": False,
    }
    manifest_hash = hashlib.sha256(json.dumps(manifest_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {**manifest_core, "manifest_hash": manifest_hash}


def duplicate_detection_assessment(
    groups: Sequence[Mapping[str, object]],
    *,
    fuzzy_text_groups: Sequence[Mapping[str, object]] | None = None,
    duplicate_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    fuzzy_text_groups = fuzzy_text_groups or []
    manifest = (
        dict(duplicate_manifest)
        if duplicate_manifest
        else build_duplicate_content_manifest(groups, fuzzy_text_groups=fuzzy_text_groups)
    )
    suppression_manifest = build_duplicate_suppression_manifest(
        groups,
        duplicate_content_manifest=manifest,
        fuzzy_text_groups=fuzzy_text_groups,
    )
    satisfied = [
        "same-size candidate bucketing",
            "bounded SHA256 confirmation",
            "duplicate group counts",
            "fuzzy text duplicate candidate grouping",
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
        "perceptual-media-similarity-not-implemented",
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
        "fuzzy_text_duplicate_group_count": len(fuzzy_text_groups),
        "fuzzy_text_duplicate_file_count": sum(int(group.get("file_count") or 0) for group in fuzzy_text_groups),
        "ready_for_court_report": False,
        "trusted_duplicate_content_diff": dict(trusted_diff) if trusted_diff else missing_duplicate_content_trusted_diff(),
        "core_accuracy_gates": duplicate_content_core_accuracy_gates(
            groups,
            fuzzy_text_groups=fuzzy_text_groups,
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
            "normalized-text-near-duplicate-candidates",
            "duplicate-review-matrix",
            "not-suppressed-until-analyst-review",
        ],
        "blockers": blockers,
    }


def build_duplicate_suppression_manifest(
    groups: Sequence[Mapping[str, object]],
    *,
    duplicate_content_manifest: Mapping[str, object],
    fuzzy_text_groups: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    fuzzy_text_groups = fuzzy_text_groups or []
    review_matrix = [
        {
            "group_id": str(group.get("group_id") or ""),
            "group_kind": "exact-hash",
            "file_count": int(group.get("file_count") or 0),
            "representative_name": str(group.get("representative_name") or ""),
            "report_suppression_status": str(group.get("report_suppression_status") or "not-suppressed"),
            "analyst_review_required": bool(group.get("analyst_review_required", True)),
            "required_decision": "include-representative-or-keep-all-with-note",
        }
        for group in groups
    ]
    review_matrix.extend(
        {
            "group_id": str(group.get("group_id") or ""),
            "group_kind": "fuzzy-text",
            "file_count": int(group.get("file_count") or 0),
            "representative_name": str(group.get("representative_name") or ""),
            "report_suppression_status": str(group.get("report_suppression_status") or "not-suppressed"),
            "analyst_review_required": bool(group.get("analyst_review_required", True)),
            "required_decision": "review-near-duplicate-text-before-collapse-or-suppression",
        }
        for group in fuzzy_text_groups
    )
    review_matrix_hash = hashlib.sha256(json.dumps(review_matrix, sort_keys=True).encode("utf-8")).hexdigest()
    manifest_core = {
        "profile_version": "duplicate-suppression-manifest-v1",
        "item_number": 33,
        "gap_id": "#33",
        "commercial_gap_ids": [DEDUPLICATE_CONTENT_GAP_ID],
        "duplicate_content_manifest_hash": str(duplicate_content_manifest.get("manifest_hash") or ""),
        "duplicate_group_count": len(groups),
        "duplicate_file_count": sum(int(group.get("file_count") or 0) for group in groups),
        "fuzzy_text_duplicate_group_count": len(fuzzy_text_groups),
        "fuzzy_text_duplicate_file_count": sum(int(group.get("file_count") or 0) for group in fuzzy_text_groups),
        "representative_selection": "stable-path-order-first-candidate",
        "report_suppression_default": "not-suppressed",
        "auto_suppression_enabled": False,
        "analyst_override_required": True,
        "review_matrix": review_matrix,
        "review_matrix_hash": review_matrix_hash,
        "review_decision_required_for_each_group": True,
        "collapse_by_default_in_ui": False,
        "near_duplicate_text_supported": True,
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
            "fuzzy_text_duplicate_group_count": int(suppression_manifest.get("fuzzy_text_duplicate_group_count") or 0),
            "fuzzy_text_duplicate_file_count": int(suppression_manifest.get("fuzzy_text_duplicate_file_count") or 0),
            "same_size_candidate_bucketing": True,
            "bounded_sha256_confirmation": True,
            "normalized_text_near_duplicate_candidates": True,
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
            "perceptual-media-similarity-not-complete",
        ],
        "validation_evidence": [
            "files-output-emits-functional-duplicate-suppression-profile",
            "unit-test-asserts-duplicate-profile-contract",
        ],
    }


def duplicate_content_core_accuracy_gates(
    groups: Sequence[Mapping[str, object]],
    *,
    fuzzy_text_groups: Sequence[Mapping[str, object]] | None = None,
    satisfied_checks: Sequence[str] | None = None,
    duplicate_manifest: Mapping[str, object] | None = None,
    suppression_manifest: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    fuzzy_text_groups = fuzzy_text_groups or []
    manifest = duplicate_manifest or build_duplicate_content_manifest(groups, fuzzy_text_groups=fuzzy_text_groups)
    suppression = suppression_manifest or build_duplicate_suppression_manifest(
        groups,
        duplicate_content_manifest=manifest,
        fuzzy_text_groups=fuzzy_text_groups,
    )
    satisfied = list(
        satisfied_checks
        or (
            "same-size candidate bucketing",
            "bounded SHA256 confirmation",
            "duplicate group counts",
            "fuzzy text duplicate candidate grouping",
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
                f"fuzzy_text_duplicate_group_count:{len(fuzzy_text_groups)}",
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
