from __future__ import annotations

import datetime as dt
import csv
import difflib
import hashlib
import json
import os
import re
import stat as stat_module
import zipfile
from pathlib import Path, PurePosixPath
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
SIGNATURE_MISMATCH_GAP_ID = "visible-file-signature-mismatch"
FUNCTIONAL_SCALE_BATCH_ID = "commercial-uplift-031-035"
DUPLICATE_CONTENT_TRUSTED_DIFF_BLOCKER_77 = "trusted-duplicate-file-manifest-diff-missing"
DUPLICATE_CONTENT_TRUSTED_TOOLS = {"duplicate-file-manifest", "known-answer-duplicate-group-export", "content-hash-oracle"}
EXECUTABLE_BITS = stat_module.S_IXUSR | stat_module.S_IXGRP | stat_module.S_IXOTH
DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES = 64 * 1024 * 1024
KNOWN_GOOD_HASH_ALGORITHMS = ("md5", "sha1", "sha256")
HASH_TOKEN_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
KNOWN_GOOD_FEED_TEXT_SUFFIXES = {".txt", ".hash", ".hashes", ".md5", ".sha1", ".sha256", ".csv", ".json"}
KNOWN_GOOD_FEED_FILE_SUFFIXES = {*KNOWN_GOOD_FEED_TEXT_SUFFIXES, ".zip"}
KNOWN_GOOD_ZIP_MAX_MEMBERS = 128
KNOWN_GOOD_ZIP_MAX_MEMBER_BYTES = DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
KNOWN_GOOD_ZIP_MAX_TOTAL_BYTES = DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES * 4
KNOWN_GOOD_ZIP_MAX_COMPRESSION_RATIO = 200
KNOWN_GOOD_CSV_HASH_FIELDS = {
    "md5": "md5",
    "sha1": "sha1",
    "sha": "sha1",
    "sha256": "sha256",
    "hash": "",
    "digest": "",
    "value": "",
}
NSRL_RDS_HEADER_FIELDS = {"sha1", "md5", "crc32", "filename", "filesize", "productcode", "opsystemcode", "specialcode"}
KNOWN_GOOD_SOURCE_FIELD_LIMIT = 160
MAX_SIGNATURE_HEADER_BYTES = 64
SIGNATURE_RULES: tuple[dict[str, object], ...] = (
    {"id": "windows-pe", "extensions": (".exe", ".dll", ".sys", ".scr", ".com"), "magics": (b"MZ",)},
    {"id": "pdf", "extensions": (".pdf",), "magics": (b"%PDF-",)},
    {"id": "zip-container", "extensions": (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"), "magics": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")},
    {"id": "sqlite", "extensions": (".db", ".sqlite", ".sqlite3"), "magics": (b"SQLite format 3\x00",)},
    {"id": "png", "extensions": (".png",), "magics": (b"\x89PNG\r\n\x1a\n",)},
    {"id": "jpeg", "extensions": (".jpg", ".jpeg"), "magics": (b"\xff\xd8\xff",)},
    {"id": "gif", "extensions": (".gif",), "magics": (b"GIF87a", b"GIF89a")},
    {"id": "ole-cfb", "extensions": (".doc", ".xls", ".ppt", ".msg"), "magics": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)},
    {"id": "7z", "extensions": (".7z",), "magics": (b"7z\xbc\xaf\x27\x1c",)},
    {"id": "rar", "extensions": (".rar",), "magics": (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")},
    {"id": "gzip", "extensions": (".gz", ".gzip", ".tgz"), "magics": (b"\x1f\x8b",)},
)
EXPECTED_SIGNATURES_BY_EXTENSION: dict[str, set[str]] = {
    extension: {str(rule["id"])}
    for rule in SIGNATURE_RULES
    for extension in rule["extensions"]  # type: ignore[union-attr]
}
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
    signature_result = apply_file_signature_profile(visible_candidates, candidate_payloads)
    signature_profile = signature_result["profile"]

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
            "known_good_nsrl_rds_feed_count": known_good_profile["nsrl_rds_feed_count"],
            "known_good_nsrl_rds_row_count": known_good_profile["nsrl_rds_row_count"],
            "signature_checked_count": signature_profile["checked_count"],
            "signature_mismatch_count": signature_profile["mismatch_count"],
            "signature_unrecognized_known_extension_count": signature_profile["unrecognized_known_extension_count"],
            "commercial_gap_ids": [
                HASH_CACHE_GAP_ID,
                DEDUPLICATE_CONTENT_GAP_ID,
                DENISTING_GAP_ID,
                SIGNATURE_MISMATCH_GAP_ID,
            ],
        },
        "known_good_suppression_profile": known_good_profile,
        "known_good_suppressed_candidates": known_good_result["suppressed_candidates"],
        "file_signature_profile": signature_profile,
        "signature_mismatch_candidates": signature_result["mismatch_candidates"],
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
    source_index: dict[str, dict[str, dict[str, object]]] = {algorithm: {} for algorithm in KNOWN_GOOD_HASH_ALGORITHMS}
    feed_paths: list[Path] = []
    feed_summaries: list[dict[str, object]] = []
    duplicate_count = 0
    rejected_token_count = 0

    for feed_path in expand_known_good_hash_feed_paths(paths):
        if not feed_path.exists():
            raise FileScanError(f"known-good hash feed not found: {feed_path}")
        if not feed_path.is_file():
            raise FileScanError(f"known-good hash feed is not a file: {feed_path}")
        feed_paths.append(feed_path)
        before_count = sum(len(values) for values in index.values())
        parsed_feed = parse_known_good_hash_feed(feed_path)
        raw_records = parsed_feed["records"]
        accepted_for_feed = 0
        rejected_for_feed = 0
        duplicates_for_feed = 0
        for record in raw_records:
            if not isinstance(record, Mapping):
                rejected_for_feed += 1
                continue
            normalized = normalize_known_good_hash(str(record.get("token") or ""))
            if normalized is None:
                rejected_for_feed += 1
                continue
            algorithm, value = normalized
            if value in index[algorithm]:
                duplicates_for_feed += 1
                continue
            index[algorithm].add(value)
            source = record.get("source")
            if isinstance(source, Mapping):
                source_index[algorithm][value] = dict(source)
            accepted_for_feed += 1
        after_count = sum(len(values) for values in index.values())
        duplicate_count += duplicates_for_feed
        rejected_token_count += rejected_for_feed
        feed_summary = {
            "path": str(feed_path),
            "format": parsed_feed["format"],
            "header_fields": parsed_feed["header_fields"],
            "hash_column_fields": parsed_feed["hash_column_fields"],
            "row_count": parsed_feed["row_count"],
            "nsrl_rds_header_detected": parsed_feed["nsrl_rds_header_detected"],
            "accepted_hash_count": accepted_for_feed,
            "duplicate_hash_count": duplicates_for_feed,
            "rejected_token_count": rejected_for_feed,
            "cumulative_hash_count_before": before_count,
            "cumulative_hash_count_after": after_count,
        }
        for extra_key in (
            "archive_member_count",
            "parsed_archive_member_count",
            "skipped_archive_member_count",
            "archive_members",
            "skipped_archive_members",
        ):
            if extra_key in parsed_feed:
                feed_summary[extra_key] = parsed_feed[extra_key]
        feed_summaries.append(feed_summary)

    return {
        "hashes": index,
        "hash_sources": source_index,
        "feed_paths": feed_paths,
        "feed_summaries": feed_summaries,
        "duplicate_count": duplicate_count,
        "rejected_token_count": rejected_token_count,
    }


def expand_known_good_hash_feed_paths(paths: Sequence[Union[str, Path]]) -> list[Path]:
    expanded: list[Path] = []
    for raw_path in paths:
        feed_path = Path(raw_path).expanduser().resolve()
        if feed_path.is_dir():
            for child in sorted(feed_path.rglob("*")):
                if child.is_file() and child.suffix.lower() in KNOWN_GOOD_FEED_FILE_SUFFIXES:
                    expanded.append(child)
        else:
            expanded.append(feed_path)
    return expanded


def build_known_good_index_payload(paths: Sequence[Union[str, Path]]) -> dict[str, object]:
    known_good_index = load_known_good_hash_feeds(paths)
    records: list[dict[str, object]] = []
    raw_hashes = known_good_index.get("hashes", {})
    raw_sources = known_good_index.get("hash_sources", {})
    hashes = raw_hashes if isinstance(raw_hashes, Mapping) else {}
    sources = raw_sources if isinstance(raw_sources, Mapping) else {}
    hash_counts: dict[str, int] = {}
    for algorithm in KNOWN_GOOD_HASH_ALGORITHMS:
        values = sorted(str(value) for value in hashes.get(algorithm, set()))
        hash_counts[algorithm] = len(values)
        source_for_algorithm = sources.get(algorithm, {}) if isinstance(sources.get(algorithm, {}), Mapping) else {}
        for value in values:
            source_detail = source_for_algorithm.get(value, {}) if isinstance(source_for_algorithm, Mapping) else {}
            record: dict[str, object] = {
                "algorithm": algorithm,
                "token": value,
                "hash": value,
            }
            if isinstance(source_detail, Mapping) and source_detail:
                record["source_detail"] = dict(source_detail)
            records.append(record)
    summary = {
        "feed_count": len(known_good_index.get("feed_paths", [])),
        "record_count": len(records),
        "known_good_hash_counts_by_algorithm": hash_counts,
        "duplicate_feed_hash_count": int(known_good_index.get("duplicate_count", 0)),
        "rejected_feed_token_count": int(known_good_index.get("rejected_token_count", 0)),
        "nsrl_rds_feed_count": sum(
            1
            for item in known_good_index.get("feed_summaries", [])
            if isinstance(item, Mapping)
            and (item.get("format") == "nsrl-rds-csv" or (item.get("format") == "zip" and item.get("nsrl_rds_header_detected")))
        ),
        "nsrl_rds_row_count": sum(
            int(item.get("row_count") or 0)
            for item in known_good_index.get("feed_summaries", [])
            if isinstance(item, Mapping)
            and (item.get("format") == "nsrl-rds-csv" or (item.get("format") == "zip" and item.get("nsrl_rds_header_detected")))
        ),
        "zip_feed_count": sum(
            1 for item in known_good_index.get("feed_summaries", []) if isinstance(item, Mapping) and item.get("format") == "zip"
        ),
        "zip_parsed_member_count": sum(
            int(item.get("parsed_archive_member_count") or 0)
            for item in known_good_index.get("feed_summaries", [])
            if isinstance(item, Mapping) and item.get("format") == "zip"
        ),
        "zip_skipped_member_count": sum(
            int(item.get("skipped_archive_member_count") or 0)
            for item in known_good_index.get("feed_summaries", [])
            if isinstance(item, Mapping) and item.get("format") == "zip"
        ),
    }
    core = {
        "command": "known-good-index",
        "profile_version": "known-good-index-v1",
        "generated_at": dt.datetime.now().isoformat(),
        "summary": summary,
        "feed_paths": [str(path) for path in known_good_index.get("feed_paths", [])],
        "feed_summaries": known_good_index.get("feed_summaries", []),
        "records": records,
        "usage": {
            "files": "rapidtriage files <case-root> --known-good-hash-feed <known-good-index.json>",
            "run": "rapidtriage run <case-root> --known-good-hash-feed <known-good-index.json>",
            "search": "rapidtriage search <run-output> -k <keyword> --hide-known-good",
        },
        "limitations": [
            "This is a local normalized index builder; it does not download or update the full NSRL database.",
            "Use organization-approved NSRL/RDS source files and preserve this index with the case validation bundle.",
            "Large public NSRL releases should be benchmarked on release hardware before claiming commercial-scale performance.",
        ],
    }
    return {**core, "manifest_hash": hashlib.sha256(json.dumps(core, sort_keys=True).encode("utf-8")).hexdigest()}


def extract_hash_feed_tokens(path: Path) -> list[str]:
    parsed = parse_known_good_hash_feed(path)
    return [str(record.get("token") or "") for record in parsed["records"] if isinstance(record, Mapping)]


def parse_known_good_hash_feed(path: Path) -> dict[str, object]:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return parse_known_good_zip_feed(path)
    if suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        records: list[dict[str, object]] = []
        if isinstance(data, Mapping) and data.get("profile_version") == "known-good-index-v1" and isinstance(data.get("records"), list):
            for item in data.get("records", []):
                if not isinstance(item, Mapping):
                    continue
                token = str(item.get("token") or item.get("hash") or item.get("value") or "")
                source_detail = item.get("source_detail")
                source = dict(source_detail) if isinstance(source_detail, Mapping) else known_good_feed_source(path, feed_format="json-index")
                records.append({"token": token, "source": source})
        else:
            collect_hash_records_from_json(
                data,
                records,
                source=known_good_feed_source(path, feed_format="json"),
            )
        return {
            "records": records,
            "format": "json-index" if isinstance(data, Mapping) and data.get("profile_version") == "known-good-index-v1" else "json",
            "header_fields": [],
            "hash_column_fields": [],
            "row_count": len(records) if isinstance(data, Mapping) and data.get("profile_version") == "known-good-index-v1" else 0,
            "nsrl_rds_header_detected": False,
        }
    if suffix == ".csv":
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        return parse_known_good_csv_text(path, text)
    text = path.read_text(encoding="utf-8", errors="replace")
    header = next(csv.reader(text.splitlines()), [])
    if is_nsrl_rds_csv_headers(header):
        return parse_known_good_csv_text(path, text)
    records = [
        {"token": token, "source": known_good_feed_source(path, feed_format="text")}
        for token in HASH_TOKEN_RE.findall(text)
    ]
    return {
        "records": records,
        "format": "text",
        "header_fields": [],
        "hash_column_fields": [],
        "row_count": 0,
        "nsrl_rds_header_detected": False,
    }


def parse_known_good_zip_feed(path: Path) -> dict[str, object]:
    records: list[dict[str, object]] = []
    header_fields: list[str] = []
    hash_column_fields: list[str] = []
    row_count = 0
    nsrl_detected = False
    archive_members: list[dict[str, object]] = []
    skipped_members: list[dict[str, object]] = []
    total_uncompressed = 0
    parsed_count = 0

    try:
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.infolist()):
                if index >= KNOWN_GOOD_ZIP_MAX_MEMBERS:
                    skipped_members.append(
                        {
                            "member": info.filename,
                            "reason": "member-count-limit",
                            "max_members": KNOWN_GOOD_ZIP_MAX_MEMBERS,
                        }
                    )
                    continue
                if info.is_dir():
                    continue
                member_name = info.filename
                member_path = PurePosixPath(member_name)
                suffix = member_path.suffix.lower()
                if suffix not in KNOWN_GOOD_FEED_TEXT_SUFFIXES:
                    skipped_members.append({"member": member_name, "reason": "unsupported-member-suffix"})
                    continue
                if member_path.is_absolute() or ".." in member_path.parts or "\\" in member_name:
                    skipped_members.append({"member": member_name, "reason": "unsafe-member-path"})
                    continue
                if info.file_size > KNOWN_GOOD_ZIP_MAX_MEMBER_BYTES:
                    skipped_members.append(
                        {
                            "member": member_name,
                            "reason": "member-size-limit",
                            "size": info.file_size,
                            "max_member_bytes": KNOWN_GOOD_ZIP_MAX_MEMBER_BYTES,
                        }
                    )
                    continue
                if total_uncompressed + info.file_size > KNOWN_GOOD_ZIP_MAX_TOTAL_BYTES:
                    skipped_members.append(
                        {
                            "member": member_name,
                            "reason": "archive-total-size-limit",
                            "size": info.file_size,
                            "max_total_bytes": KNOWN_GOOD_ZIP_MAX_TOTAL_BYTES,
                        }
                    )
                    continue
                compression_ratio = info.file_size / max(info.compress_size, 1)
                if compression_ratio > KNOWN_GOOD_ZIP_MAX_COMPRESSION_RATIO:
                    skipped_members.append(
                        {
                            "member": member_name,
                            "reason": "compression-ratio-limit",
                            "compression_ratio": round(compression_ratio, 2),
                            "max_compression_ratio": KNOWN_GOOD_ZIP_MAX_COMPRESSION_RATIO,
                        }
                    )
                    continue
                raw = archive.read(info)
                total_uncompressed += info.file_size
                text = raw.decode("utf-8-sig", errors="replace")
                parsed = parse_known_good_member_text(path, member_name, suffix, text)
                records.extend(parsed["records"])
                row_count += int(parsed.get("row_count") or 0)
                nsrl_detected = nsrl_detected or bool(parsed.get("nsrl_rds_header_detected"))
                for field in parsed.get("header_fields", []):
                    if str(field) not in header_fields:
                        header_fields.append(str(field))
                for field in parsed.get("hash_column_fields", []):
                    if str(field) not in hash_column_fields:
                        hash_column_fields.append(str(field))
                parsed_count += 1
                archive_members.append(
                    {
                        "member": member_name,
                        "format": parsed["format"],
                        "size": info.file_size,
                        "row_count": parsed.get("row_count", 0),
                        "record_count": len(parsed["records"]),
                        "nsrl_rds_header_detected": parsed.get("nsrl_rds_header_detected", False),
                    }
                )
    except zipfile.BadZipFile as exc:
        raise FileScanError(f"known-good ZIP feed is not readable: {path}: {exc}") from exc

    return {
        "records": records,
        "format": "zip",
        "header_fields": header_fields,
        "hash_column_fields": hash_column_fields,
        "row_count": row_count,
        "nsrl_rds_header_detected": nsrl_detected,
        "archive_member_count": len(archive_members) + len(skipped_members),
        "parsed_archive_member_count": parsed_count,
        "skipped_archive_member_count": len(skipped_members),
        "archive_members": archive_members[:20],
        "skipped_archive_members": skipped_members[:20],
    }


def parse_known_good_member_text(path: Path, archive_member: str, suffix: str, text: str) -> dict[str, object]:
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        records: list[dict[str, object]] = []
        collect_hash_records_from_json(
            data,
            records,
            source=known_good_feed_source(path, feed_format="json", archive_member=archive_member),
        )
        return {
            "records": records,
            "format": "json",
            "header_fields": [],
            "hash_column_fields": [],
            "row_count": 0,
            "nsrl_rds_header_detected": False,
        }
    header = next(csv.reader(text.splitlines()), [])
    if suffix == ".csv" or is_nsrl_rds_csv_headers(header):
        return parse_known_good_csv_text(path, text, archive_member=archive_member)
    records = [
        {"token": token, "source": known_good_feed_source(path, feed_format="text", archive_member=archive_member)}
        for token in HASH_TOKEN_RE.findall(text)
    ]
    return {
        "records": records,
        "format": "text",
        "header_fields": [],
        "hash_column_fields": [],
        "row_count": 0,
        "nsrl_rds_header_detected": False,
    }


def parse_known_good_csv_text(path: Path, text: str, *, archive_member: str | None = None) -> dict[str, object]:
    records = []
    reader = csv.DictReader(text.splitlines())
    header_fields = [str(field or "") for field in (reader.fieldnames or [])]
    hash_column_fields: list[str] = []
    row_count = 0
    feed_format = "nsrl-rds-csv" if is_nsrl_rds_csv_headers(header_fields) else "csv"
    for row_number, row in enumerate(reader, start=2):
        row_count += 1
        for key, value in row.items():
            algorithm_hint = known_good_csv_hash_algorithm(key)
            if algorithm_hint is None:
                continue
            field_name = str(key or "")
            if field_name and field_name not in hash_column_fields:
                hash_column_fields.append(field_name)
            for token in HASH_TOKEN_RE.findall(value or ""):
                records.append(
                    {
                        "token": token,
                        "source": known_good_feed_source(
                            path,
                            feed_format=feed_format,
                            row=row,
                            row_number=row_number,
                            hash_column=field_name,
                            archive_member=archive_member,
                        ),
                    }
                )
    if not records:
        for token in HASH_TOKEN_RE.findall(text):
            records.append(
                {
                    "token": token,
                    "source": known_good_feed_source(path, feed_format="csv", archive_member=archive_member),
                }
            )
    return {
        "records": records,
        "format": feed_format,
        "header_fields": header_fields,
        "hash_column_fields": hash_column_fields,
        "row_count": row_count,
        "nsrl_rds_header_detected": feed_format == "nsrl-rds-csv",
    }


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


def collect_hash_records_from_json(value: object, records: list[dict[str, object]], *, source: Mapping[str, object]) -> None:
    if isinstance(value, str):
        for token in HASH_TOKEN_RE.findall(value):
            records.append({"token": token, "source": dict(source)})
        return
    if isinstance(value, Mapping):
        for item in value.values():
            collect_hash_records_from_json(item, records, source=source)
        return
    if isinstance(value, list):
        for item in value:
            collect_hash_records_from_json(item, records, source=source)


def guess_known_good_feed_format(path: Path) -> str:
    if path.suffix.lower() == ".csv":
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            header = next(csv.reader(text.splitlines()), [])
        except (OSError, StopIteration, csv.Error):
            header = []
        if is_nsrl_rds_csv_headers(header):
            return "nsrl-rds-csv"
    suffix = path.suffix.lower()
    if suffix in {".json", ".csv"}:
        return suffix[1:]
    return "text"


def normalize_known_good_csv_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def known_good_csv_hash_algorithm(header: object) -> Optional[str]:
    normalized = normalize_known_good_csv_header(header)
    if normalized in KNOWN_GOOD_CSV_HASH_FIELDS:
        return KNOWN_GOOD_CSV_HASH_FIELDS[normalized]
    return None


def is_nsrl_rds_csv_headers(header_fields: Sequence[object]) -> bool:
    normalized = {normalize_known_good_csv_header(field) for field in header_fields}
    return {"sha1", "md5", "filename", "productcode"}.issubset(normalized) or len(normalized & NSRL_RDS_HEADER_FIELDS) >= 6


def known_good_feed_source(
    path: Path,
    *,
    feed_format: str,
    row: Mapping[str, str] | None = None,
    row_number: int | None = None,
    hash_column: str | None = None,
    archive_member: str | None = None,
) -> dict[str, object]:
    source: dict[str, object] = {
        "source": "analyst-known-good-feed",
        "feed_name": path.name,
        "feed_path": str(path),
        "feed_format": feed_format,
    }
    if archive_member:
        source["archive_member"] = archive_member
        source["feed_container_format"] = "zip"
    if row_number is not None:
        source["row_number"] = row_number
    if hash_column:
        source["hash_column"] = hash_column
    if row and feed_format == "nsrl-rds-csv":
        nsrl_fields = {
            "nsrl_file_name": csv_row_value(row, "FileName"),
            "nsrl_file_size": csv_row_value(row, "FileSize"),
            "nsrl_product_code": csv_row_value(row, "ProductCode"),
            "nsrl_os_code": csv_row_value(row, "OpSystemCode"),
            "nsrl_special_code": csv_row_value(row, "SpecialCode"),
        }
        for key, value in nsrl_fields.items():
            if value:
                source[key] = bounded_source_value(value)
    return source


def csv_row_value(row: Mapping[str, str], wanted_header: str) -> str:
    wanted = normalize_known_good_csv_header(wanted_header)
    for key, value in row.items():
        if normalize_known_good_csv_header(key) == wanted:
            return value or ""
    return ""


def bounded_source_value(value: object) -> str:
    text = str(value or "").strip()
    if len(text) <= KNOWN_GOOD_SOURCE_FIELD_LIMIT:
        return text
    return text[:KNOWN_GOOD_SOURCE_FIELD_LIMIT] + "...[truncated]"


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
    raw_source_index = known_good_index.get("hash_sources", {})
    if not isinstance(raw_source_index, Mapping):
        raw_source_index = {}
    known_good_hashes = {algorithm: set(raw_hash_index.get(algorithm, set())) for algorithm in KNOWN_GOOD_HASH_ALGORITHMS}
    known_good_sources = {
        algorithm: dict(raw_source_index.get(algorithm, {})) if isinstance(raw_source_index.get(algorithm, {}), Mapping) else {}
        for algorithm in KNOWN_GOOD_HASH_ALGORITHMS
    }
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
                    known_good_match = first_known_good_hash_match(
                        hashes,
                        known_good_hashes,
                        known_good_sources=known_good_sources,
                    )
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
    feed_summaries = list(known_good_index.get("feed_summaries", []))
    feed_format_counts: dict[str, int] = {}
    nsrl_rds_feed_count = 0
    nsrl_rds_row_count = 0
    for summary in feed_summaries:
        if not isinstance(summary, Mapping):
            continue
        feed_format = str(summary.get("format") or "unknown")
        feed_format_counts[feed_format] = feed_format_counts.get(feed_format, 0) + 1
        if feed_format == "nsrl-rds-csv":
            nsrl_rds_feed_count += 1
            nsrl_rds_row_count += int(summary.get("row_count") or 0)
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
        "feed_format_counts": feed_format_counts,
        "nsrl_rds_feed_count": nsrl_rds_feed_count,
        "nsrl_rds_row_count": nsrl_rds_row_count,
        "feed_summaries": feed_summaries,
        "duplicate_feed_hash_count": int(known_good_index.get("duplicate_count", 0)),
        "rejected_feed_token_count": int(known_good_index.get("rejected_token_count", 0)),
        "match_count": match_count,
        "suppressed_count": len(suppressed_candidates) if hide_known_good else 0,
        "skipped_large_count": skipped_large_count,
        "suppressed_candidates_truncated": suppressed_candidates_truncated,
        "policy": {
            "default_behavior": "mark-known-good-without-hiding",
            "hide_behavior": "hide only when --hide-known-good is explicitly provided",
            "scope": "analyst-supplied TXT/CSV/JSON MD5/SHA1/SHA256 feeds plus NSRL RDS CSV hash columns",
            "legal_review_note": "Known-good suppression reduces triage noise but does not prove irrelevance by itself.",
        },
        "limitations": [
            "Bundled NSRL database download/update workflow is not implemented; analysts must supply a trusted local feed.",
            "Files larger than max_hash_bytes are skipped to avoid surprise long-running scans.",
            "Hash-based known-good checks cannot identify modified-but-benign files without a trusted feed match.",
        ],
        "source_viewer_contract": {
            "candidate_field": "known_good_match",
            "suppressed_list": "known_good_suppressed_candidates",
            "review_action": "toggle --hide-known-good off when the analyst needs to inspect suppressed rows",
            "source_traceability": "known_good_match.source_detail records feed, row, hash column, and NSRL metadata when available",
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
    *,
    known_good_sources: Mapping[str, Mapping[str, Mapping[str, object]]] | None = None,
) -> Optional[dict[str, object]]:
    source_index = known_good_sources or {}
    for algorithm in KNOWN_GOOD_HASH_ALGORITHMS:
        value = hashes.get(algorithm, "").lower()
        if value and value in known_good_hashes.get(algorithm, set()):
            source_detail = source_index.get(algorithm, {}).get(value, {})
            match: dict[str, object] = {
                "algorithm": algorithm,
                "value": value,
                "source": "analyst-known-good-feed",
                "classification": "known-good",
                "confidence": "hash-exact",
            }
            if source_detail:
                match["source_detail"] = dict(source_detail)
                match["feed_name"] = str(source_detail.get("feed_name") or "")
                match["feed_format"] = str(source_detail.get("feed_format") or "")
            return match
    return None


def apply_file_signature_profile(
    candidates: Sequence[FileCandidate],
    candidate_payloads: Sequence[dict[str, object]],
) -> dict[str, object]:
    checked_count = 0
    mismatch_candidates: list[dict[str, object]] = []
    unrecognized_known_extension_count = 0
    read_error_count = 0

    for candidate, payload in zip(candidates, candidate_payloads):
        expected = sorted(EXPECTED_SIGNATURES_BY_EXTENSION.get(candidate.extension, set()))
        signature = {
            "status": "not-applicable",
            "detected": None,
            "expected": expected,
            "mismatch": False,
            "risk_flags": [],
        }
        if not expected:
            payload["file_signature"] = signature
            continue
        checked_count += 1
        try:
            with Path(candidate.path).open("rb") as handle:
                header = handle.read(MAX_SIGNATURE_HEADER_BYTES)
        except OSError as exc:
            read_error_count += 1
            payload["file_signature"] = {
                **signature,
                "status": "read-error",
                "error": exc.__class__.__name__,
            }
            continue
        detected = detect_file_signature(header)
        if detected is None:
            unrecognized_known_extension_count += 1
            payload["file_signature"] = {
                **signature,
                "status": "unrecognized-header-for-known-extension",
                "risk_flags": ["signature-unrecognized"],
            }
            continue
        mismatch = detected not in expected
        status = "extension-signature-mismatch" if mismatch else "signature-matches-extension"
        risk_flags = ["extension-signature-mismatch"] if mismatch else []
        payload["file_signature"] = {
            **signature,
            "status": status,
            "detected": detected,
            "mismatch": mismatch,
            "risk_flags": risk_flags,
        }
        if mismatch:
            mismatch_candidates.append(
                {
                    "path": candidate.path,
                    "name": candidate.name,
                    "extension": candidate.extension,
                    "size": candidate.size,
                    "modified_at": candidate.modified_at,
                    "expected": expected,
                    "detected": detected,
                    "risk_flags": risk_flags,
                    "source_viewer_locator": {
                        "source": "files",
                        "path": candidate.path,
                        "viewer": "file-header",
                    },
                    "forensic_review": {
                        "status": "needs-review",
                        "reason": "file extension does not match detected header signature",
                        "report_use_warning": "Confirm with a second parser or manual hex review before report-grade use.",
                    },
                }
            )

    mismatch_candidates_truncated = len(mismatch_candidates) > 200
    mismatch_head = mismatch_candidates[:200]
    profile_core = {
        "profile": "file-signature-mismatch-v1",
        "profile_version": "file-signature-mismatch-v1",
        "capability_id": "file-system-signature-mismatch",
        "commercial_gap_ids": [SIGNATURE_MISMATCH_GAP_ID],
        "checked_count": checked_count,
        "mismatch_count": len(mismatch_candidates),
        "unrecognized_known_extension_count": unrecognized_known_extension_count,
        "read_error_count": read_error_count,
        "mismatch_candidates_truncated": mismatch_candidates_truncated,
        "max_header_bytes": MAX_SIGNATURE_HEADER_BYTES,
        "known_signature_count": len(SIGNATURE_RULES),
        "known_extensions": sorted(EXPECTED_SIGNATURES_BY_EXTENSION),
        "policy": {
            "scope": "bounded first-bytes magic signature check during file inventory",
            "default_behavior": "flag mismatch but keep the file visible",
            "legal_review_note": "Signature mismatch is an anti-forensic indicator, not standalone proof of malicious intent.",
        },
        "limitations": [
            "Container formats can share ZIP/OLE signatures, so deeper file-format validation still matters.",
            "Header-only checks do not validate full file integrity or embedded payloads.",
            "Known extension coverage is intentionally conservative to avoid noisy false positives.",
        ],
        "commercial_claim_allowed": False,
    }
    profile_hash = hashlib.sha256(json.dumps(profile_core, sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "profile": {**profile_core, "profile_hash": profile_hash},
        "mismatch_candidates": mismatch_head,
    }


def detect_file_signature(header: bytes) -> Optional[str]:
    for rule in SIGNATURE_RULES:
        for magic in rule["magics"]:  # type: ignore[union-attr]
            if header.startswith(magic):
                return str(rule["id"])
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
