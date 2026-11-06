from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import mmap
import re
import sqlite3
import struct
import zipfile
import zlib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipInfo

from ..core.models import ArtifactRecord
from ..core.safe_xml import UnsafeXmlError, safe_xml_fromstring
from ..core.sqlite_snapshot import open_sqlite_snapshot
from ..core.submission import compute_hashes
from ._walk import iter_evidence_paths

PARSER_VERSION = "generic-documents-v5"
STICKY_NOTE_ROW_LIMIT = 5000
STICKY_NOTE_RECOVERY_SCAN_BYTES = 8 * 1024 * 1024
STICKY_NOTE_RECOVERY_LIMIT = 40
LARGE_FILE_HASH_DEFER_BYTES = 64 * 1024 * 1024
DESKTOP_AI_TABLE_LIMIT = 20
DESKTOP_AI_MESSAGE_ROW_LIMIT = 200
DESKTOP_AI_MESSAGE_TABLE_LIMIT = 5
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")
LOCAL_LLM_PATH_TERMS = {
    "ollama": "Ollama",
    "lm studio": "LM Studio",
    "lmstudio": "LM Studio",
    "gpt4all": "GPT4All",
}
DESKTOP_AI_APP_PATH_TERMS = {
    "chatgpt": "ChatGPT Desktop",
    "openai": "OpenAI/ChatGPT Desktop",
    "copilot": "Microsoft Copilot Desktop",
    "claude": "Claude Desktop",
    "anthropic": "Claude Desktop",
    "gemini": "Gemini Desktop/WebView",
    "perplexity": "Perplexity Desktop/WebView",
}
LOCAL_LLM_MODEL_SUFFIXES = {".gguf", ".ggml", ".bin", ".safetensors"}
# ``.bin`` is far too generic (firmware, caches, VBA projects): it is only a
# model file when the content carries a GGUF / safetensors header.
LOCAL_LLM_MAGIC_REQUIRED_SUFFIXES = {".bin"}
LOCAL_LLM_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".log", ".txt", ".sqlite", ".db"}
LOCAL_LLM_PROMPT_SCAN_BYTES = 2 * 1024 * 1024
LOCAL_LLM_PROMPT_ROW_LIMIT = 200
LOCAL_LLM_TEXT_PROMPT_TERMS = (
    "prompt",
    "user:",
    "assistant:",
    "human:",
    "system:",
    "response",
    "completion",
    "conversation",
    "chat",
)
DOCUMENT_METADATA_SUFFIXES = {
    ".docx",
    ".xlsx",
    ".pptx",
    ".docm",
    ".xlsm",
    ".pptm",
    ".odt",
    ".ods",
    ".odp",
    ".doc",
    ".xls",
    ".ppt",
    ".hwp",
    ".hwpx",
    ".pdf",
}
OFFICE_LOCK_SUFFIXES = {
    ".doc",
    ".docx",
    ".docm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".ppt",
    ".pptx",
    ".pptm",
    ".hwp",
    ".hwpx",
    ".cell",
    ".show",
}
OOXML_VBA_PATHS = {"word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin"}
OOXML_PROPS_PATHS = {"docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"}
ODF_META_PATHS = {"meta.xml"}
DESKTOP_AI_APP_SUFFIXES = {
    ".sqlite",
    ".sqlite3",
    ".db",
    ".json",
    ".log",
    ".ldb",
    ".localstorage",
    ".dat",
    ".txt",
}
DESKTOP_AI_APP_STORAGE_MARKERS = (
    "appdata",
    "application support",
    "containers",
    "packages",
    "local storage",
    "indexeddb",
    "leveldb",
    "session storage",
)
# R5 L3 (재감사 §3 items 9, 18): EGG / ALZ (core.egg_archive) and ISO 9660 (core.iso9660) entry listings.
EXTENDED_ARCHIVE_FORMATS = {".egg": "egg", ".alz": "alz", ".iso": "iso9660"}
ARCHIVE_SUFFIXES = {".zip", ".rar", ".7z", *EXTENDED_ARCHIVE_FORMATS}
ARCHIVE_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ARCHIVE_ENTRY_SAMPLE_LIMIT = 80
ARCHIVE_RISK_ENTRY_LIMIT = 100
ARCHIVE_BOMB_RATIO_THRESHOLD = 100.0
ARCHIVE_BOMB_SIZE_THRESHOLD = 50 * 1024 * 1024
ARCHIVE_EXECUTABLE_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".hta",
    ".js",
    ".jse",
    ".lnk",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
    ".wsf",
}
ARCHIVE_NESTED_SUFFIXES = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"}


class GenericDocumentArtifactProvider:
    collector_kind = "generic-documents"
    name = "generic-documents"
    description = "Cross-platform document candidates discovered from the filesystem"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_archive_inventory(root)
        yield from collect_document_metadata_risk(root)
        yield from collect_sticky_notes(root)
        yield from collect_local_llm_inventory(root)
        yield from collect_desktop_ai_app_inventory(root)


def collect_archive_inventory(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not safe_is_file(path) or path.suffix.lower() not in ARCHIVE_SUFFIXES:
            continue
        stat_result = safe_stat(path)
        profile = archive_inventory_profile(path)
        risk_flags = archive_risk_flags(profile)
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="archive-file-inventory",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "archive-file-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": safe_source_hashes(path),
                "source_size": stat_result.get("size", 0),
                "source_file_mtime": stat_result.get("modified_at", ""),
                "archive_format": archive_format_hint(path),
                "archive_inventory_profile": profile,
                "entry_count": profile.get("entry_count", 0),
                "encrypted_entry_count": profile.get("encrypted_entry_count", 0),
                "path_traversal_entry_count": profile.get("path_traversal_entry_count", 0),
                "executable_entry_count": profile.get("executable_entry_count", 0),
                "nested_archive_entry_count": profile.get("nested_archive_entry_count", 0),
                "compression_ratio": profile.get("compression_ratio", 0.0),
                "coverage_status": profile.get("analysis_status", "archive-inventory"),
                "archive_review_profile": archive_review_profile(profile),
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "archive-recursive-extraction-sandbox-required",
                    "password-candidate-workflow-not-implemented",
                    "archive-family-trusted-parser-diff-required",
                ],
                "risk_flags": risk_flags,
            },
        )


def archive_inventory_profile(path: Path) -> dict[str, object]:
    suffix = path.suffix.lower()
    if suffix in (".egg", ".alz") and read_prefix(path, 4) in ARCHIVE_ZIP_MAGICS:
        # R6 S1: Python eggs / Java-style ZIPs named .egg — list them as the ZIP they are.
        profile = zip_inventory_profile(path)
        profile["format_hint"] = "zip"
        profile["format_mismatch"] = "zip"
        profile["format_mismatch_reason_ko"] = f"확장자는 {suffix}이지만 파일 서명상 실제 형식은 ZIP입니다 — ZIP 목록으로 냈습니다"
        return profile
    if suffix in EXTENDED_ARCHIVE_FORMATS:
        return extended_archive_profile(path, EXTENDED_ARCHIVE_FORMATS[suffix])
    if suffix != ".zip":
        return archive_metadata_only_profile(path)
    return zip_inventory_profile(path)


def zip_inventory_profile(path: Path) -> dict[str, object]:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
    except (OSError, zipfile.BadZipFile):
        return {
            "profile_version": "archive-inventory-profile-v1",
            "analysis_status": "zip-open-failed",
            "entry_count": 0,
            "sample_entries": [],
            "validation_guidance": "ZIP metadata could not be opened. Validate with a dedicated archive parser.",
        }
    sample_entries: list[dict[str, object]] = []
    total_compressed = 0
    total_uncompressed = 0
    encrypted_count = 0
    path_traversal_count = 0
    executable_count = 0
    nested_archive_count = 0
    suspicious_entries: list[dict[str, object]] = []
    for index, info in enumerate(entries):
        entry = zip_entry_profile(info, index)
        total_compressed += int(entry["compressed_size"])
        total_uncompressed += int(entry["uncompressed_size"])
        if entry["encrypted"]:
            encrypted_count += 1
        if entry["path_traversal_risk"]:
            path_traversal_count += 1
        if entry["executable_or_script"]:
            executable_count += 1
        if entry["nested_archive"]:
            nested_archive_count += 1
        if len(sample_entries) < ARCHIVE_ENTRY_SAMPLE_LIMIT:
            sample_entries.append(entry)
        if entry["risk_flags"] and len(suspicious_entries) < ARCHIVE_RISK_ENTRY_LIMIT:
            suspicious_entries.append(entry)
    ratio = float(total_uncompressed / max(total_compressed, 1)) if total_uncompressed else 0.0
    return {
        "profile_version": "archive-inventory-profile-v1",
        "analysis_status": "zip-central-directory-parsed",
        "entry_count": len(entries),
        "sample_entries": sample_entries,
        "suspicious_entries": suspicious_entries,
        "encrypted_entry_count": encrypted_count,
        "path_traversal_entry_count": path_traversal_count,
        "executable_entry_count": executable_count,
        "nested_archive_entry_count": nested_archive_count,
        "total_compressed_size": total_compressed,
        "total_uncompressed_size": total_uncompressed,
        "compression_ratio": round(ratio, 3),
        "zip_bomb_candidate": total_uncompressed >= ARCHIVE_BOMB_SIZE_THRESHOLD and ratio >= ARCHIVE_BOMB_RATIO_THRESHOLD,
        "truncated_entries": len(entries) > ARCHIVE_ENTRY_SAMPLE_LIMIT,
        "sample_entries_truncated": len(entries) > ARCHIVE_ENTRY_SAMPLE_LIMIT,
        "sample_entry_limit": ARCHIVE_ENTRY_SAMPLE_LIMIT,
        "entry_time_timezone": "local-unknown",
        "entry_time_note": "ZIP DOS 시각은 압축 당시 PC의 로컬 시각이며 시간대 정보가 없습니다.",
        "values_are_metadata_only": True,
        "validation_guidance": (
            "ZIP central-directory metadata is safe to review, but extraction, passwords, path traversal, and nested "
            "archives require a sandboxed recursive workflow before reporting file contents."
        ),
    }


EXTENDED_ARCHIVE_NOTES = {
    "egg": "EGG 시각은 파일 헤더의 Windows FILETIME(UTC) 또는 POSIX 시각입니다. AZO 압축·암호화·솔리드 항목은 목록만 냅니다.",
    "alz": "ALZ 시각은 DOS 시각(압축 당시 PC의 로컬 시각, 시간대 없음)입니다. ALZ는 목록만 냅니다(해제하지 않음).",
    "iso9660": "ISO 9660 디렉터리 레코드의 기록 시각(GMT 오프셋 포함)입니다. UDF는 존재만 표시합니다.",
}


def extended_archive_profile(path: Path, fmt: str) -> dict[str, object]:
    """Archive inventory profile of an EGG / ALZ / ISO 9660 file (R5 L3); a corrupt file is isolated."""
    from ..core.egg_archive import list_alz, list_egg
    from ..core.iso9660 import list_iso

    readers = {"egg": list_egg, "alz": list_alz, "iso9660": list_iso}
    try:
        listing = readers[fmt](path)
    except (ValueError, OSError, EOFError, struct.error) as exc:
        return {
            "profile_version": "archive-inventory-profile-v1",
            "analysis_status": f"{fmt}-open-failed",
            "format_hint": fmt,
            "entry_count": 0,
            "sample_entries": [],
            "open_error": f"{type(exc).__name__}: {exc}"[:300],
            "validation_guidance": "압축 헤더를 읽지 못했습니다(손상·잘림·다른 형식). 전용 도구로 확인하세요.",
        }
    entries = list(listing.get("entries") or [])
    sample_entries: list[dict[str, object]] = []
    suspicious_entries: list[dict[str, object]] = []
    counts = {"encrypted": 0, "traversal": 0, "executable": 0, "nested": 0}
    for index, raw in enumerate(entries):
        name = str(raw.get("name") or "")
        suffix = Path(name).suffix.lower()
        entry = {"source_index": index, **raw}
        flags: list[str] = []
        if raw.get("encrypted"):
            counts["encrypted"] += 1
            flags.append("archive-encrypted-entry")
        traversal = archive_entry_path_traversal_risk(name)
        executable = suffix in ARCHIVE_EXECUTABLE_SUFFIXES
        nested = suffix in ARCHIVE_NESTED_SUFFIXES or suffix in EXTENDED_ARCHIVE_FORMATS
        for hit, key, flag in (
            (traversal, "traversal", "archive-path-traversal-entry"),
            (executable, "executable", "archive-executable-or-script-entry"),
            (nested, "nested", "archive-nested-container-entry"),
        ):
            if hit:
                counts[key] += 1
                flags.append(flag)
        entry.update({"path_traversal_risk": traversal, "executable_or_script": executable, "nested_archive": nested, "risk_flags": flags})
        if len(sample_entries) < ARCHIVE_ENTRY_SAMPLE_LIMIT:
            sample_entries.append(entry)
        if flags and len(suspicious_entries) < ARCHIVE_RISK_ENTRY_LIMIT:
            suspicious_entries.append(entry)
    total_compressed = int(listing.get("total_compressed_size") or 0)
    total_uncompressed = int(listing.get("total_uncompressed_size") or 0)
    ratio = float(total_uncompressed / max(total_compressed, 1)) if total_uncompressed else 0.0
    profile: dict[str, object] = {
        "profile_version": "archive-inventory-profile-v1",
        "analysis_status": listing.get("analysis_status"),
        "format_hint": fmt,
        "parser_version": listing.get("parser_version"),
        "entry_count": len(entries),
        "sample_entries": sample_entries,
        "suspicious_entries": suspicious_entries,
        "encrypted_entry_count": counts["encrypted"],
        "path_traversal_entry_count": counts["traversal"],
        "executable_entry_count": counts["executable"],
        "nested_archive_entry_count": counts["nested"],
        "total_compressed_size": total_compressed,
        "total_uncompressed_size": total_uncompressed,
        "compression_ratio": round(ratio, 3),
        "zip_bomb_candidate": total_uncompressed >= ARCHIVE_BOMB_SIZE_THRESHOLD and ratio >= ARCHIVE_BOMB_RATIO_THRESHOLD,
        "header_encrypted": bool(listing.get("header_encrypted")),
        "split_archive": bool(listing.get("split")),
        "solid_archive": bool(listing.get("solid")),
        "listing_notes": list(listing.get("notes") or []),
        "truncated_entries": len(entries) > ARCHIVE_ENTRY_SAMPLE_LIMIT,
        "sample_entries_truncated": len(entries) > ARCHIVE_ENTRY_SAMPLE_LIMIT,
        "sample_entry_limit": ARCHIVE_ENTRY_SAMPLE_LIMIT,
        "entry_time_note": EXTENDED_ARCHIVE_NOTES[fmt],
        "values_are_metadata_only": True,
        "validation_guidance": "항목 목록은 헤더 메타데이터입니다. 내용 검토는 격리된 환경에서 전용 도구로 해제한 뒤 하세요.",
    }
    # R6 S1: split EGG sets (listed once, from the first volume) and extension/format mismatches.
    for key in ("split_volumes", "volume_count", "split_link", "missing_volumes", "split_member", "split_first_volume",
                "format_mismatch", "reason_ko"):
        if key in listing:
            profile[key] = listing[key]
    # R6 S1: an EGG entry cut by the end of the stream (truncated file / missing split volume) is
    # still listed; its data_truncated / truncated_at fields pass through in the entry dicts.
    if fmt == "egg":
        profile["data_truncated_entry_count"] = sum(1 for entry in entries if entry.get("data_truncated"))
    if fmt == "iso9660":
        profile["udf_present"] = bool(listing.get("udf_present"))
        profile["iso_volume"] = listing.get("volume") or {}
        profile["motw_note"] = (
            "ISO 안의 파일은 마운트 후 실행 시 Zone.Identifier(MOTW)가 붙지 않을 수 있습니다 — "
            "같은 ISO 경로의 Zone.Identifier(안티 포렌식 › ADS) 행과 대조하세요"
        )
    return profile


def archive_metadata_only_profile(path: Path) -> dict[str, object]:
    signature = read_prefix(path, 8).hex()
    return {
        "profile_version": "archive-inventory-profile-v1",
        "analysis_status": "archive-metadata-only",
        "format_hint": archive_format_hint(path),
        "signature_hex": signature,
        "entry_count": 0,
        "encrypted_entry_count": 0,
        "path_traversal_entry_count": 0,
        "executable_entry_count": 0,
        "nested_archive_entry_count": 0,
        "compression_ratio": 0.0,
        "sample_entries": [],
        "suspicious_entries": [],
        "values_are_metadata_only": True,
        "validation_guidance": "RAR/7z metadata is inventoried without extraction. Use a sandboxed parser for entry-level review.",
    }


def zip_entry_name(info: ZipInfo) -> tuple[str, str]:
    """Entry name and its encoding: UTF-8 flag (0x800) honoured, otherwise the raw bytes are
    re-read as cp949 (Korean Windows zips) instead of Python's cp437 default."""
    if info.flag_bits & 0x800:
        return info.filename, "utf-8"
    try:
        raw = info.filename.encode("cp437")
    except UnicodeEncodeError:
        return info.filename, "unknown"
    if raw.isascii():
        return info.filename, "ascii"
    for encoding in ("utf-8", "cp949"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return info.filename, "cp437"


def zip_entry_profile(info: ZipInfo, index: int) -> dict[str, object]:
    name, name_encoding = zip_entry_name(info)
    suffix = Path(name).suffix.lower()
    risk_flags: list[str] = []
    encrypted = bool(info.flag_bits & 0x1)
    traversal = archive_entry_path_traversal_risk(name)
    executable = suffix in ARCHIVE_EXECUTABLE_SUFFIXES
    nested = suffix in ARCHIVE_NESTED_SUFFIXES
    if encrypted:
        risk_flags.append("archive-encrypted-entry")
    if traversal:
        risk_flags.append("archive-path-traversal-entry")
    if executable:
        risk_flags.append("archive-executable-or-script-entry")
    if nested:
        risk_flags.append("archive-nested-container-entry")
    if info.file_size >= ARCHIVE_BOMB_SIZE_THRESHOLD and info.file_size / max(info.compress_size, 1) >= ARCHIVE_BOMB_RATIO_THRESHOLD:
        risk_flags.append("archive-high-compression-ratio-entry")
    return {
        "source_index": index,
        "name": name[:500],
        "name_encoding": name_encoding,
        "is_dir": info.is_dir(),
        "compressed_size": int(info.compress_size),
        "uncompressed_size": int(info.file_size),
        "compression_type": int(info.compress_type),
        "encrypted": encrypted,
        "path_traversal_risk": traversal,
        "executable_or_script": executable,
        "nested_archive": nested,
        "last_modified": zip_datetime_to_iso(info.date_time),
        # ZIP DOS date/time has no zone: it is the writer's local wall clock.
        "timezone": "local-unknown",
        "crc32": f"{info.CRC:08x}",
        "risk_flags": risk_flags,
    }


def archive_entry_path_traversal_risk(name: str) -> bool:
    normalized = name.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    return (
        normalized.startswith("/")
        or normalized.startswith("//")
        or bool(re.match(r"(?i)^[a-z]:/", normalized))
        or any(part == ".." for part in parts)
    )


def archive_risk_flags(profile: Mapping[str, object]) -> list[str]:
    flags = ["archive-file-inventory"]
    if str(profile.get("analysis_status") or "").endswith("-open-failed"):
        flags.append("archive-open-failed")
    if int(profile.get("encrypted_entry_count") or 0):
        flags.append("archive-encrypted-entry")
    if int(profile.get("path_traversal_entry_count") or 0):
        flags.append("archive-path-traversal-risk")
    if int(profile.get("executable_entry_count") or 0):
        flags.append("archive-executable-or-script-entry")
    if int(profile.get("nested_archive_entry_count") or 0):
        flags.append("archive-nested-container-entry")
    if profile.get("zip_bomb_candidate"):
        flags.append("archive-zip-bomb-candidate")
    if profile.get("analysis_status") == "archive-metadata-only":
        flags.append("archive-metadata-only")
    return flags


def archive_review_profile(profile: Mapping[str, object]) -> dict[str, object]:
    return {
        "profile_version": "archive-review-profile-v1",
        "analysis_status": profile.get("analysis_status", ""),
        "entry_count": profile.get("entry_count", 0),
        "encrypted_entry_count": profile.get("encrypted_entry_count", 0),
        "path_traversal_entry_count": profile.get("path_traversal_entry_count", 0),
        "executable_entry_count": profile.get("executable_entry_count", 0),
        "nested_archive_entry_count": profile.get("nested_archive_entry_count", 0),
        "review_priority": archive_review_priority(profile),
        "source_viewer_hint": "Open the archive metadata row first; extract only through a sandboxed recursive workflow.",
        "not_proof_of": [
            "archive-content-review-without-extraction",
            "password-success-or-decryption",
            "malicious-intent",
        ],
        "report_blockers": [
            "sandboxed-recursive-extraction-required",
            "entry-hash-manifest-required",
            "trusted-archive-parser-diff-required",
        ],
    }


def archive_review_priority(profile: Mapping[str, object]) -> str:
    if int(profile.get("path_traversal_entry_count") or 0):
        return "high-review-path-traversal-entry"
    if int(profile.get("encrypted_entry_count") or 0):
        return "review-encrypted-archive-workflow"
    if int(profile.get("executable_entry_count") or 0):
        return "review-executable-archive-entry"
    if profile.get("zip_bomb_candidate"):
        return "high-review-compression-bomb-candidate"
    if profile.get("analysis_status") == "archive-metadata-only":
        return "review-with-dedicated-archive-parser"
    return "review-archive-metadata"


def archive_format_hint(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return "zip"
    if suffix == ".rar":
        return "rar"
    if suffix == ".7z":
        return "7z"
    if suffix in EXTENDED_ARCHIVE_FORMATS:
        return EXTENDED_ARCHIVE_FORMATS[suffix]
    return suffix.lstrip(".")


def zip_datetime_to_iso(value: Sequence[int]) -> str:
    try:
        year, month, day, hour, minute, second = [int(part) for part in value[:6]]
        return dt.datetime(year, month, day, hour, minute, second).isoformat()
    except (TypeError, ValueError):
        return ""


def collect_document_metadata_risk(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not safe_is_file(path):
            continue
        suffix = path.suffix.lower()
        if path.name.startswith("~$") and suffix in OFFICE_LOCK_SUFFIXES:
            lock_record = document_lock_owner_record(path)
            if lock_record is not None:
                yield lock_record
                continue
        if suffix not in DOCUMENT_METADATA_SUFFIXES:
            continue
        profile = document_metadata_profile(path)
        if profile.get("analysis_status") in {"not-a-zip-document", "unrecognized-document-container"}:
            continue
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="document-metadata-risk",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "document-metadata-risk",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": safe_source_hashes(path),
                "document_family": profile.get("document_family", ""),
                "container_format": profile.get("container_format", ""),
                **document_top_level_fields(profile),
                "metadata_profile": profile,
                "author_candidates": profile.get("author_candidates", []),
                "timestamp_candidates": profile.get("timestamp_candidates", {}),
                "macro_profile": profile.get("macro_profile", {}),
                "external_reference_candidates": profile.get("external_reference_candidates", []),
                "coverage_status": "document-metadata-and-risk-profile",
                "validation_required": bool(profile.get("risk_flags")),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "office-version-metadata-fixture-required",
                    "macro-static-analysis-not-complete",
                    "trusted-document-parser-diff-required",
                ],
                "risk_flags": profile.get("risk_flags", []),
            },
        )


def collect_sticky_notes(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not safe_is_file(path) or path.name.lower() != "plum.sqlite":
            continue
        yield from collect_sticky_notes_sqlite(path)


def document_metadata_profile(path: Path) -> dict[str, object]:
    suffix = path.suffix.lower()
    head = read_prefix(path, 1024)
    if head.startswith(CFB_MAGIC):
        return ole_document_profile(path, suffix)
    if b"%PDF-" in head:
        return pdf_document_profile(path)
    if head.startswith(b"PK"):
        return zip_document_profile(path, suffix)
    if head.startswith(b"HWP Document File V3"):
        return {
            "profile_version": "document-metadata-risk-profile-v2",
            "analysis_status": "parsed-header-only",
            "document_family": "hwp",
            "container_format": "hwp3-binary",
            "hwp_file_header": {"status": "hwp3", "version": head[19:23].decode("ascii", errors="replace")},
            "normalized_metadata": {},
            "encryption": {"encrypted": False, "encryption_check": "not-implemented-for-hwp3"},
            "risk_flags": ["document-metadata-profile"],
            "validation_guidance": "HWP 3.0 형식은 헤더만 확인했습니다. 메타데이터는 한컴오피스로 확인하세요.",
        }
    if suffix == ".pdf":
        return {"analysis_status": "unrecognized-document-container", "document_family": "pdf"}
    return {"analysis_status": "not-a-zip-document", "document_family": suffix.lstrip(".")}


def zip_document_profile(path: Path, suffix: str) -> dict[str, object]:
    encryption: dict[str, object] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if suffix in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"} or "[Content_Types].xml" in names:
                props = extract_ooxml_properties(archive, names)
                field_map = OOXML_TOP_LEVEL_KEYS
                macro_paths = sorted(
                    name for name in names if name in OOXML_VBA_PATHS or name.lower().endswith("vbaproject.bin")
                )
                external_refs = extract_ooxml_external_references(archive, names)
                family = suffix.lstrip(".")
                container = "ooxml-zip"
            elif suffix in {".odt", ".ods", ".odp"} or "meta.xml" in names:
                props = extract_odf_properties(archive, names)
                field_map = ODF_TOP_LEVEL_KEYS
                macro_paths = sorted(name for name in names if "script" in name.lower() or "basic/" in name.lower())
                external_refs = []
                family = suffix.lstrip(".")
                container = "odf-zip"
                encryption = zip_manifest_encryption(archive, names)
            elif suffix == ".hwpx" or any(name.lower().startswith("contents/") for name in names):
                props = extract_hwpx_properties(archive, names)
                field_map = OOXML_TOP_LEVEL_KEYS
                macro_paths = sorted(name for name in names if name.lower().startswith("scripts/"))
                external_refs = []
                family = "hwpx"
                container = "hwpx-zip"
                encryption = zip_manifest_encryption(archive, names)
            else:
                props = {}
                field_map = OOXML_TOP_LEVEL_KEYS
                macro_paths = []
                external_refs = []
                family = suffix.lstrip(".")
                container = "zip"
    except (OSError, zipfile.BadZipFile, ValueError):
        return {"analysis_status": "not-a-zip-document", "document_family": suffix.lstrip(".")}
    author_candidates = unique_values(
        [
            str(props.get(key) or "")
            for key in ("creator", "lastModifiedBy", "initialCreator", "generator", "company", "manager", "Company", "Manager")
        ]
    )
    timestamp_candidates = {
        key: value
        for key, value in props.items()
        if key.lower() in {"created", "modified", "creationdate", "date", "lastprinted"} and value
    }
    metadata = ooxml_normalized_metadata(props, field_map)
    risk_flags = document_metadata_risk_flags(author_candidates, macro_paths, external_refs, props)
    if encryption.get("encrypted"):
        risk_flags.append("document-encrypted")
    return {
        "profile_version": "document-metadata-risk-profile-v2",
        "analysis_status": "parsed",
        "document_family": family,
        "container_format": container,
        "properties": props,
        "normalized_metadata": metadata,
        "encryption": encryption or {"encrypted": False},
        "author_candidates": author_candidates,
        "timestamp_candidates": timestamp_candidates,
        "macro_profile": {
            "macro_present": bool(macro_paths),
            "macro_paths": macro_paths[:20],
            "macro_path_count": len(macro_paths),
            "macro_scan_status": "vba-project-present" if macro_paths else "not-detected",
        },
        "external_reference_candidates": external_refs[:50],
        "external_reference_count": len(external_refs),
        "external_references_truncated": len(external_refs) > 50,
        "risk_flags": risk_flags,
        "values_are_candidates": True,
        "validation_guidance": (
            "Document metadata and VBA presence are triage pivots. Confirm author/timestamp semantics and macro behavior "
            "with a dedicated Office/ODF parser or sandbox before reporting intent or malware conclusions."
        ),
    }


def zip_manifest_encryption(archive: zipfile.ZipFile, names: set[str]) -> dict[str, object]:
    manifest_name = next((name for name in names if name.lower() == "meta-inf/manifest.xml"), "")
    if not manifest_name:
        return {}
    try:
        manifest = archive.read(manifest_name)
    except (KeyError, OSError, zipfile.BadZipFile):
        return {}
    if b"encryption-data" in manifest:
        return {"encrypted": True, "encryption_reason": "zip-manifest-encryption-data"}
    return {}


def extract_hwpx_properties(archive: zipfile.ZipFile, names: set[str]) -> dict[str, str]:
    props: dict[str, str] = {}
    for name in sorted(names):
        if name.lower() not in {"contents/content.hpf", "docprops/core.xml", "meta-inf/container.rdf"}:
            continue
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        try:
            root = safe_xml_fromstring(xml_data)
        except (ET.ParseError, UnsafeXmlError):
            continue
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag == "meta":
                key = str(node.attrib.get("name") or "")
                if key and node.text and node.text.strip():
                    props.setdefault(key, node.text.strip()[:500])
            elif tag == "title" and node.text and node.text.strip():
                props.setdefault("title", node.text.strip()[:500])
    return props


OOXML_TOP_LEVEL_KEYS = {
    "title": "title",
    "subject": "subject",
    "creator": "author",
    "lastModifiedBy": "last_modified_by",
    "lastsaveby": "last_modified_by",
    "keywords": "keywords",
    "description": "comments",
    "category": "category",
    "Company": "company",
    "Manager": "manager",
    "Template": "template",
    "revision": "revision",
    "created": "created_at",
    "modified": "modified_at",
    "lastPrinted": "last_printed_at",
    "Application": "application",
    "AppVersion": "application_version",
    "Pages": "page_count",
    "Words": "word_count",
    # HWPX content.hpf <opf:meta name="..."> keys
    "CreatedDate": "created_at",
    "ModifiedDate": "modified_at",
    "date": "date_string",
}


ODF_TOP_LEVEL_KEYS = {
    "title": "title",
    "subject": "subject",
    "initial-creator": "author",
    "creator": "last_modified_by",
    "keyword": "keywords",
    "description": "comments",
    "creation-date": "created_at",
    "date": "modified_at",
    "print-date": "last_printed_at",
    "generator": "application",
    "editing-cycles": "revision",
}
ISO_DURATION_RE = re.compile(r"^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)(?:\.\d+)?S)?$")


def ooxml_normalized_metadata(props: Mapping[str, str], field_map: Mapping[str, str]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    duration = ISO_DURATION_RE.match(str(props.get("editing-duration") or ""))
    if duration and any(duration.groups()):
        days, hours, minutes, secs = (int(part or 0) for part in duration.groups())
        seconds = days * 86400 + hours * 3600 + minutes * 60 + secs
        metadata["total_edit_time_seconds"] = seconds
        metadata["total_edit_time"] = seconds_to_iso_duration(seconds)
    for source_key, target_key in field_map.items():
        value = props.get(source_key)
        if value in (None, ""):
            continue
        if target_key in {"page_count", "word_count"}:
            with contextlib.suppress(ValueError):
                metadata[target_key] = int(str(value))
            continue
        metadata.setdefault(target_key, value)
    total_time = props.get("TotalTime")
    if total_time not in (None, ""):
        with contextlib.suppress(ValueError):
            # app.xml TotalTime is the cumulative editing time in minutes.
            seconds = int(str(total_time)) * 60
            metadata["total_edit_time_seconds"] = seconds
            metadata["total_edit_time"] = seconds_to_iso_duration(seconds)
    naive = [
        key
        for key in ("created_at", "modified_at", "last_printed_at")
        if isinstance(metadata.get(key), str) and not W3CDTF_ZONE_RE.search(str(metadata[key]))
    ]
    if naive:
        metadata["timestamps_without_zone"] = naive
    return metadata


W3CDTF_ZONE_RE = re.compile(r"(?:Z|[+-]\d{2}:?\d{2})$")
DOCUMENT_TOP_LEVEL_KEYS = (
    "title",
    "subject",
    "author",
    "last_modified_by",
    "keywords",
    "comments",
    "category",
    "company",
    "manager",
    "template",
    "revision",
    "created_at",
    "modified_at",
    "last_printed_at",
    "total_edit_time_seconds",
    "total_edit_time",
    "application",
    "application_version",
    "page_count",
    "word_count",
    "timestamps_without_zone",
)


def document_top_level_fields(profile: Mapping[str, object]) -> dict[str, object]:
    metadata = profile.get("normalized_metadata")
    fields: dict[str, object] = {}
    if isinstance(metadata, Mapping):
        for key in DOCUMENT_TOP_LEVEL_KEYS:
            value = metadata.get(key)
            if value not in (None, "", []):
                fields[key] = value
    encryption = profile.get("encryption")
    encrypted = bool(isinstance(encryption, Mapping) and encryption.get("encrypted"))
    fields["encrypted"] = encrypted
    if encrypted and isinstance(encryption, Mapping):
        fields["encryption_reason"] = str(encryption.get("encryption_reason") or "")
        fields["encryption_note"] = "암호화된 문서입니다. 본문·일부 메타데이터는 복호화 없이 확인할 수 없습니다."
    return fields


def seconds_to_iso_duration(seconds: int) -> str:
    hours, remainder = divmod(max(0, int(seconds)), 3600)
    minutes, secs = divmod(remainder, 60)
    return f"PT{hours}H{minutes}M{secs}S"


def filetime_to_iso(value: int) -> str:
    """FILETIME (100 ns since 1601-01-01 UTC) to ISO-8601 UTC using integer math."""
    if not value or value < 0:
        return ""
    try:
        moment = FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)
    except OverflowError:
        return ""
    if not 1970 <= moment.year <= 2200:
        return ""
    return moment.isoformat()


FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
CFB_FREE = 0xFFFFFFFF
CFB_END_OF_CHAIN = 0xFFFFFFFE
CFB_MAX_REGULAR = 0xFFFFFFFA


class CompoundFileError(ValueError):
    pass


class CompoundFile:
    """Minimal read-only OLE2 / Compound File Binary reader (FAT, miniFAT, directory)."""

    def __init__(self, data: bytes | mmap.mmap) -> None:
        if len(data) < 512 or bytes(data[:8]) != CFB_MAGIC:
            raise CompoundFileError("not a compound file")
        self.data = data
        major = struct.unpack_from("<H", data, 0x1A)[0]
        sector_shift = struct.unpack_from("<H", data, 0x1E)[0]
        mini_shift = struct.unpack_from("<H", data, 0x20)[0]
        if sector_shift not in (9, 12) or mini_shift != 6:
            raise CompoundFileError("unsupported sector size")
        self.major_version = major
        self.sector_size = 1 << sector_shift
        self.mini_sector_size = 1 << mini_shift
        self.mini_cutoff = struct.unpack_from("<I", data, 0x38)[0] or 4096
        first_dir = struct.unpack_from("<I", data, 0x30)[0]
        first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
        minifat_count = struct.unpack_from("<I", data, 0x40)[0]
        first_difat = struct.unpack_from("<I", data, 0x44)[0]
        difat_count = struct.unpack_from("<I", data, 0x48)[0]
        self.sector_count = max(0, (len(data) - self.sector_size) // self.sector_size + 1)
        fat_sectors = [sid for sid in struct.unpack_from("<109I", data, 0x4C) if sid <= CFB_MAX_REGULAR]
        per_sector = self.sector_size // 4
        sid = first_difat
        seen: set[int] = set()
        while sid <= CFB_MAX_REGULAR and sid not in seen and len(seen) < max(difat_count, 1) + 1:
            seen.add(sid)
            block = self.sector(sid)
            if len(block) < self.sector_size:
                break
            entries = struct.unpack_from(f"<{per_sector}I", block, 0)
            fat_sectors.extend(entry for entry in entries[:-1] if entry <= CFB_MAX_REGULAR)
            sid = entries[-1]
        fat: list[int] = []
        for fat_sid in fat_sectors:
            block = self.sector(fat_sid)
            if len(block) < self.sector_size:
                continue
            fat.extend(struct.unpack_from(f"<{per_sector}I", block, 0))
        self.fat = fat
        directory = self.read_chain(first_dir, self.fat, regular=True)
        self.entries: list[dict[str, object]] = []
        for offset in range(0, len(directory) - 127, 128):
            self.entries.append(self.parse_entry(directory[offset : offset + 128]))
        if not self.entries or self.entries[0].get("type") != 5:
            raise CompoundFileError("missing root entry")
        self.minifat: list[int] = []
        if minifat_count and first_minifat <= CFB_MAX_REGULAR:
            raw = self.read_chain(first_minifat, self.fat, regular=True)
            self.minifat = list(struct.unpack_from(f"<{len(raw) // 4}I", raw, 0))
        root = self.entries[0]
        self.mini_stream = self.read_chain(int(root["start"]), self.fat, regular=True)
        self.paths = self.build_paths()

    def sector(self, sid: int) -> bytes:
        offset = (sid + 1) * self.sector_size
        return bytes(self.data[offset : offset + self.sector_size])

    def read_chain(self, start: int, table: Sequence[int], *, regular: bool, size: int | None = None) -> bytes:
        chunks: list[bytes] = []
        seen: set[int] = set()
        sid = start
        unit = self.sector_size if regular else self.mini_sector_size
        while sid <= CFB_MAX_REGULAR and sid < len(table) and sid not in seen:
            seen.add(sid)
            if regular:
                chunks.append(self.sector(sid))
            else:
                offset = sid * unit
                chunks.append(self.mini_stream[offset : offset + unit])
            sid = table[sid]
            if size is not None and len(chunks) * unit >= size:
                break
        blob = b"".join(chunks)
        return blob if size is None else blob[:size]

    def parse_entry(self, raw: bytes) -> dict[str, object]:
        name_length = struct.unpack_from("<H", raw, 0x40)[0]
        name = raw[: max(0, min(64, name_length) - 2)].decode("utf-16le", errors="replace")
        size = struct.unpack_from("<Q", raw, 0x78)[0]
        if self.major_version == 3:
            size &= 0xFFFFFFFF
        return {
            "name": name,
            "type": raw[0x42],
            "left": struct.unpack_from("<I", raw, 0x44)[0],
            "right": struct.unpack_from("<I", raw, 0x48)[0],
            "child": struct.unpack_from("<I", raw, 0x4C)[0],
            "created": struct.unpack_from("<Q", raw, 0x64)[0],
            "modified": struct.unpack_from("<Q", raw, 0x6C)[0],
            "start": struct.unpack_from("<I", raw, 0x74)[0],
            "size": size,
        }

    def build_paths(self) -> dict[str, int]:
        paths: dict[str, int] = {}
        stack: list[tuple[int, str]] = [(int(self.entries[0]["child"]), "")]
        visited: set[int] = set()
        while stack:
            index, prefix = stack.pop()
            if index > CFB_MAX_REGULAR or index >= len(self.entries) or index in visited:
                continue
            visited.add(index)
            entry = self.entries[index]
            path = f"{prefix}{entry['name']}"
            paths.setdefault(path, index)
            stack.append((int(entry["left"]), prefix))
            stack.append((int(entry["right"]), prefix))
            if entry["type"] == 1:
                stack.append((int(entry["child"]), path + "/"))
        return paths

    def has_stream(self, name: str) -> bool:
        index = self.paths.get(name)
        return index is not None and self.entries[index]["type"] == 2

    def read_stream(self, name: str) -> bytes | None:
        index = self.paths.get(name)
        if index is None:
            return None
        entry = self.entries[index]
        if entry["type"] != 2:
            return None
        size = int(entry["size"])
        if size < self.mini_cutoff:
            return self.read_chain(int(entry["start"]), self.minifat, regular=False, size=size)
        return self.read_chain(int(entry["start"]), self.fat, regular=True, size=size)


SUMMARY_INFORMATION_PIDS = {
    2: "title",
    3: "subject",
    4: "author",
    5: "keywords",
    6: "comments",
    7: "template",
    8: "last_modified_by",
    9: "revision",
    10: "total_edit_time",
    11: "last_printed_at",
    12: "created_at",
    13: "modified_at",
    14: "page_count",
    15: "word_count",
    16: "char_count",
    18: "application",
    19: "doc_security",
}
# HwpSummaryInformation reuses the SummaryInformation PIDs, but Hangul stores its program
# version string in PID 9 and a formatted date string in PID 20.
HWP_SUMMARY_INFORMATION_PIDS = {
    2: "title",
    3: "subject",
    4: "author",
    5: "keywords",
    6: "comments",
    8: "last_modified_by",
    9: "application_version",
    11: "last_printed_at",
    12: "created_at",
    13: "modified_at",
    20: "date_string",
}
DOC_SUMMARY_INFORMATION_PIDS = {
    2: "category",
    3: "presentation_format",
    4: "byte_count",
    5: "line_count",
    6: "paragraph_count",
    7: "slide_count",
    8: "note_count",
    9: "hidden_count",
    14: "manager",
    15: "company",
}
PROPERTY_SET_TIME_KEYS = {"last_printed_at", "created_at", "modified_at"}
CODEPAGE_NAMES = {949: "cp949", 1252: "cp1252", 65001: "utf-8", 1200: "utf-16le", 932: "cp932", 936: "gbk", 950: "cp950"}


def decode_ansi_text(raw: bytes, codepage: int | None = None) -> str:
    raw = raw.split(b"\x00", 1)[0]
    encodings: list[str] = []
    if codepage and CODEPAGE_NAMES.get(codepage):
        encodings.append(CODEPAGE_NAMES[codepage])
    encodings.extend(["utf-8", "cp949"])
    for encoding in encodings:
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("cp949", errors="replace")


def parse_property_set(data: bytes) -> list[dict[int, object]]:
    """Parse an OLE property set stream ([MS-OLEPS]); one dict per section."""
    if len(data) < 48 or struct.unpack_from("<H", data, 0)[0] != 0xFFFE:
        return []
    section_count = struct.unpack_from("<I", data, 24)[0]
    sections: list[dict[int, object]] = []
    for section_index in range(min(section_count, 4)):
        header = 28 + section_index * 20
        if header + 20 > len(data):
            break
        offset = struct.unpack_from("<I", data, header + 16)[0]
        if offset + 8 > len(data):
            continue
        count = struct.unpack_from("<I", data, offset + 4)[0]
        entries: list[tuple[int, int]] = []
        for index in range(min(count, 4096)):
            position = offset + 8 + index * 8
            if position + 8 > len(data):
                break
            entries.append(struct.unpack_from("<II", data, position))
        codepage: int | None = None
        for pid, relative in entries:
            if pid == 1:
                value = read_typed_property(data, offset + relative, None)
                if isinstance(value, int):
                    codepage = value & 0xFFFF
        values: dict[int, object] = {}
        for pid, relative in entries:
            if pid in (0, 1):
                continue
            value = read_typed_property(data, offset + relative, codepage)
            if value is not None:
                values[pid] = value
        sections.append(values)
    return sections


def read_typed_property(data: bytes, position: int, codepage: int | None) -> object:
    if position + 4 > len(data):
        return None
    vt = struct.unpack_from("<I", data, position)[0] & 0xFFFF
    body = position + 4
    try:
        if vt == 0x02:
            return struct.unpack_from("<h", data, body)[0]
        if vt in (0x03, 0x16):
            return struct.unpack_from("<i", data, body)[0]
        if vt in (0x13, 0x17):
            return struct.unpack_from("<I", data, body)[0]
        if vt == 0x0B:
            return struct.unpack_from("<h", data, body)[0] != 0
        if vt == 0x05:
            return struct.unpack_from("<d", data, body)[0]
        if vt == 0x40:
            return ("filetime", struct.unpack_from("<Q", data, body)[0])
        if vt == 0x1E:
            size = struct.unpack_from("<I", data, body)[0]
            raw = data[body + 4 : body + 4 + min(size, 1 << 20)]
            if codepage == 1200:
                return raw.decode("utf-16le", errors="replace").split("\x00", 1)[0]
            return decode_ansi_text(raw, codepage)
        if vt == 0x1F:
            count = struct.unpack_from("<I", data, body)[0]
            raw = data[body + 4 : body + 4 + min(count, 1 << 19) * 2]
            return raw.decode("utf-16le", errors="replace").split("\x00", 1)[0]
    except struct.error:
        return None
    return None


def property_set_metadata(sections: Sequence[Mapping[int, object]], pid_map: Mapping[int, str]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    if not sections:
        return metadata
    for pid, value in sections[0].items():
        key = pid_map.get(pid)
        if not key:
            continue
        if isinstance(value, tuple) and value and value[0] == "filetime":
            raw = int(value[1])
            if key == "total_edit_time":
                # PIDSI_EDITTIME is a duration in 100 ns units, not a point in time.
                seconds = raw // 10_000_000
                metadata["total_edit_time_seconds"] = seconds
                metadata["total_edit_time"] = seconds_to_iso_duration(seconds)
                continue
            iso = filetime_to_iso(raw)
            if iso:
                metadata[key] = iso
            elif raw:
                metadata[f"{key}_raw_filetime"] = raw
            continue
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                metadata[key] = cleaned[:1000]
            continue
        metadata[key] = value
    return metadata


def ole_document_profile(path: Path, suffix: str) -> dict[str, object]:
    family = suffix.lstrip(".")
    try:
        with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            compound = CompoundFile(data)
            return ole_profile_from_compound(compound, family)
    except (OSError, ValueError, struct.error) as exc:
        return {
            "profile_version": "document-metadata-risk-profile-v2",
            "analysis_status": "ole-parse-failed",
            "document_family": family,
            "container_format": "ole2-cfb",
            "error": str(exc)[:200],
            "encryption": {"encrypted": False},
            "risk_flags": ["document-metadata-profile", "document-parse-failed"],
        }


def ole_profile_from_compound(compound: CompoundFile, family: str) -> dict[str, object]:
    stream_names = sorted(name for name, index in compound.paths.items() if compound.entries[index]["type"] == 2)
    metadata: dict[str, object] = {}
    property_sets: list[str] = []
    for stream_name, pid_map in (
        ("\x05SummaryInformation", SUMMARY_INFORMATION_PIDS),
        ("\x05HwpSummaryInformation", HWP_SUMMARY_INFORMATION_PIDS),
        ("\x05DocumentSummaryInformation", DOC_SUMMARY_INFORMATION_PIDS),
    ):
        data = compound.read_stream(stream_name)
        if not data:
            continue
        parsed = property_set_metadata(parse_property_set(data), pid_map)
        if parsed:
            property_sets.append(stream_name.lstrip("\x05"))
            for key, value in parsed.items():
                metadata.setdefault(key, value)
    container = "ole2-cfb"
    encryption: dict[str, object] = {"encrypted": False}
    hwp_header: dict[str, object] = {}
    if compound.has_stream("EncryptionInfo") and compound.has_stream("EncryptedPackage"):
        container = "ole2-encrypted-ooxml"
        encryption = {"encrypted": True, "encryption_reason": "ooxml-encrypted-package"}
        info = compound.read_stream("EncryptionInfo") or b""
        if len(info) >= 4:
            major, minor = struct.unpack_from("<HH", info, 0)
            encryption["encryption_info_version"] = f"{major}.{minor}"
            encryption["encryption_scheme"] = (
                "agile" if (major, minor) == (4, 4) else "standard" if minor == 2 else "extensible" if minor == 3 else "unknown"
            )
    elif compound.has_stream("FileHeader"):
        container = "hwp5-cfb"
        family = "hwp"
        hwp_header = parse_hwp_file_header(compound.read_stream("FileHeader") or b"")
        if hwp_header.get("encrypted_reasons"):
            encryption = {
                "encrypted": True,
                "encryption_reason": ",".join(str(item) for item in hwp_header["encrypted_reasons"]),
            }
    elif compound.has_stream("WordDocument"):
        encryption = word_fib_encryption(compound.read_stream("WordDocument") or b"")
    elif compound.has_stream("Workbook") or compound.has_stream("Book"):
        encryption = biff_filepass_encryption(compound.read_stream("Workbook") or compound.read_stream("Book") or b"")
    elif compound.has_stream("PowerPoint Document"):
        if compound.has_stream("EncryptedSummary"):
            encryption = {"encrypted": True, "encryption_reason": "powerpoint-encrypted-summary-stream"}
    macro_paths = [name for name in stream_names if name.lower().startswith(("macros/", "_vba_project_cur/", "vba/")) or "/vba/" in name.lower()]
    author_candidates = unique_values(
        [str(metadata.get(key) or "") for key in ("author", "last_modified_by", "company", "manager")]
    )
    timestamp_candidates = {
        key: metadata[key] for key in ("created_at", "modified_at", "last_printed_at") if metadata.get(key)
    }
    flags = ["document-metadata-profile"]
    if author_candidates:
        flags.append("document-author-metadata")
    if macro_paths:
        flags.append("document-macro-present")
    if timestamp_candidates:
        flags.append("document-timestamp-metadata")
    if encryption.get("encrypted"):
        flags.append("document-encrypted")
    profile: dict[str, object] = {
        "profile_version": "document-metadata-risk-profile-v2",
        "analysis_status": "parsed" if property_sets or encryption.get("encrypted") or hwp_header else "ole-no-property-set",
        "document_family": family,
        "container_format": container,
        "properties": {key: value for key, value in metadata.items()},
        "normalized_metadata": metadata,
        "property_sets": property_sets,
        "ole_stream_count": len(stream_names),
        "ole_streams": stream_names[:200],
        "ole_streams_truncated": len(stream_names) > 200,
        "encryption": encryption,
        "author_candidates": author_candidates,
        "timestamp_candidates": timestamp_candidates,
        "timestamp_timezone": "UTC (FILETIME)",
        "macro_profile": {
            "macro_present": bool(macro_paths),
            "macro_paths": macro_paths[:20],
            "macro_path_count": len(macro_paths),
            "macro_scan_status": "vba-storage-present" if macro_paths else "not-detected",
        },
        "external_reference_candidates": [],
        "risk_flags": flags,
        "values_are_candidates": True,
        "validation_guidance": "OLE2 요약 정보 속성은 문서 작성 프로그램이 기록한 값입니다. 다른 도구로 교차 검증하세요.",
    }
    if hwp_header:
        profile["hwp_file_header"] = hwp_header
    return profile


HWP_PROPERTY_BITS = (
    (0, "compressed"),
    (1, "password_encrypted"),
    (2, "distribution_document"),
    (3, "script_saved"),
    (4, "drm_protected"),
    (5, "xml_template_storage"),
    (6, "document_history"),
    (7, "digital_signature"),
    (8, "public_key_encrypted"),
    (9, "signature_certificate_saved"),
    (10, "certificate_drm"),
    (11, "ccl_document"),
    (12, "mobile_optimized"),
    (13, "privacy_security_document"),
    (14, "track_changes"),
    (15, "kogl_copyright"),
    (16, "video_control"),
    (17, "toc_field"),
)


def parse_hwp_file_header(data: bytes) -> dict[str, object]:
    if len(data) < 40 or not data.startswith(b"HWP Document File"):
        return {"status": "invalid-file-header"}
    version = struct.unpack_from("<I", data, 32)[0]
    properties = struct.unpack_from("<I", data, 36)[0]
    flags = {name: bool(properties & (1 << bit)) for bit, name in HWP_PROPERTY_BITS}
    encrypted_reasons = [
        f"hwp-{name.replace('_', '-')}"
        for name in ("password_encrypted", "distribution_document", "drm_protected", "public_key_encrypted", "certificate_drm")
        if flags.get(name)
    ]
    return {
        "status": "parsed",
        "version": f"{(version >> 24) & 0xFF}.{(version >> 16) & 0xFF}.{(version >> 8) & 0xFF}.{version & 0xFF}",
        "properties_raw": properties,
        "flags": flags,
        "encrypted_reasons": encrypted_reasons,
    }


def word_fib_encryption(stream: bytes) -> dict[str, object]:
    if len(stream) < 12 or struct.unpack_from("<H", stream, 0)[0] != 0xA5EC:
        return {"encrypted": False, "fib_status": "fib-not-recognized"}
    flags = struct.unpack_from("<H", stream, 0x0A)[0]
    encrypted = bool(flags & 0x0100)
    obfuscated = bool(flags & 0x8000)
    result: dict[str, object] = {"encrypted": encrypted, "fib_flags": flags}
    if encrypted:
        result["encryption_reason"] = "word-fib-fObfuscated-xor" if obfuscated else "word-fib-fEncrypted"
    return result


def biff_filepass_encryption(stream: bytes) -> dict[str, object]:
    position = 0
    records = 0
    while position + 4 <= len(stream) and records < 100_000:
        record_type, length = struct.unpack_from("<HH", stream, position)
        if record_type == 0x002F:
            scheme = struct.unpack_from("<H", stream, position + 4)[0] if length >= 2 else -1
            return {
                "encrypted": True,
                "encryption_reason": "biff-filepass-record",
                "encryption_scheme": "xor-obfuscation" if scheme == 0 else "rc4" if scheme == 1 else "unknown",
            }
        if record_type == 0x000A and records:
            break
        position += 4 + length
        records += 1
    return {"encrypted": False}


PDF_INFO_KEYS = {
    "Title": "title",
    "Author": "author",
    "Subject": "subject",
    "Keywords": "keywords",
    "Creator": "application",
    "Producer": "producer",
    "CreationDate": "created_at",
    "ModDate": "modified_at",
}
PDF_INFO_REF_RE = re.compile(rb"/Info\s+(\d+)\s+(\d+)\s+R")
PDF_ENCRYPT_RE = re.compile(rb"/Encrypt\s*(?:\d+\s+\d+\s+R|<<)")
PDF_DATE_RE = re.compile(
    r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s*(?:([Zz])|([+-])(\d{2})'?(\d{2})?'?)?"
)
PDF_OBJSTM_MAX_BYTES = 64 * 1024 * 1024
PDF_XREF_ROW_RE = re.compile(rb"\d{10} \d{5} [nf]")


def pdf_document_profile(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return pdf_profile_from_bytes(data)
    except (OSError, ValueError) as exc:
        return {
            "profile_version": "document-metadata-risk-profile-v2",
            "analysis_status": "pdf-parse-failed",
            "document_family": "pdf",
            "container_format": "pdf",
            "error": str(exc)[:200],
            "encryption": {"encrypted": False},
            "risk_flags": ["document-metadata-profile", "document-parse-failed"],
        }


def pdf_profile_from_bytes(data: bytes | mmap.mmap) -> dict[str, object]:
    header_index = data.find(b"%PDF-", 0, 1024)
    version = bytes(data[header_index + 5 : header_index + 8]).decode("ascii", errors="replace") if header_index >= 0 else ""
    trailers = pdf_trailer_dictionaries(data)
    encrypted = any(PDF_ENCRYPT_RE.search(trailer) for _source, trailer in trailers)
    info_ref = next(
        (match for _source, trailer in trailers for match in [PDF_INFO_REF_RE.search(trailer)] if match),
        None,
    )
    trailer_source = next((source for source, trailer in trailers if PDF_INFO_REF_RE.search(trailer)), "")
    raw_info: dict[str, str] = {}
    info_source = "not-found"
    if info_ref is not None:
        number, generation = int(info_ref.group(1)), int(info_ref.group(2))
        body, info_source = pdf_find_object(data, number, generation)
        info_source = f"{trailer_source}:{info_source}"
        if body is not None:
            raw_info = pdf_parse_info_dict(body, data, decode_strings=not encrypted)
    metadata: dict[str, object] = {}
    for pdf_key, target in PDF_INFO_KEYS.items():
        value = raw_info.get(pdf_key)
        if not value:
            continue
        if target in {"created_at", "modified_at"}:
            metadata[target] = pdf_date_to_iso(value) or value
            metadata[f"{target}_raw"] = value
        else:
            metadata[target] = value
    naive = [
        key
        for key in ("created_at", "modified_at")
        if isinstance(metadata.get(key), str) and metadata[key] and not W3CDTF_ZONE_RE.search(str(metadata[key]))
    ]
    if naive:
        metadata["timestamps_without_zone"] = naive
    encryption: dict[str, object] = {"encrypted": encrypted}
    if encrypted:
        encryption["encryption_reason"] = "pdf-trailer-encrypt-dictionary"
        encryption["info_strings_encrypted"] = info_ref is not None
    author_candidates = unique_values([str(metadata.get(key) or "") for key in ("author",)])
    timestamp_candidates = {key: metadata[key] for key in ("created_at", "modified_at") if metadata.get(key)}
    flags = ["document-metadata-profile"]
    if author_candidates:
        flags.append("document-author-metadata")
    if timestamp_candidates:
        flags.append("document-timestamp-metadata")
    if encrypted:
        flags.append("document-encrypted")
    return {
        "profile_version": "document-metadata-risk-profile-v2",
        "analysis_status": "parsed" if raw_info or encrypted else "pdf-info-not-found",
        "document_family": "pdf",
        "container_format": "pdf",
        "pdf_version": version,
        "info_source": info_source,
        "properties": raw_info,
        "normalized_metadata": metadata,
        "encryption": encryption,
        "author_candidates": author_candidates,
        "timestamp_candidates": timestamp_candidates,
        "macro_profile": {"macro_present": False, "macro_paths": [], "macro_scan_status": "not-applicable"},
        "external_reference_candidates": [],
        "risk_flags": flags,
        "values_are_candidates": True,
        "validation_guidance": "PDF /Info 사전 값은 생성 프로그램이 기록한 값입니다. XMP 메타데이터와 교차 확인하세요.",
    }


def pdf_dictionary_at(data: bytes | mmap.mmap, start: int, limit: int = 1 << 20) -> bytes:
    """Balanced ``<< ... >>`` dictionary beginning at ``start`` (hex strings skipped)."""
    if data[start : start + 2] != b"<<":
        return b""
    depth = 0
    index = start
    stop = min(len(data), start + limit)
    while index < stop:
        pair = data[index : index + 2]
        if pair == b"<<":
            depth += 1
            index += 2
            continue
        if pair == b">>":
            depth -= 1
            index += 2
            if depth == 0:
                return bytes(data[start:index])
            continue
        lead = data[index : index + 1]
        if lead == b"<":
            close = data.find(b">", index + 1, stop)
            index = close + 1 if close >= 0 else stop
            continue
        if lead == b"(":
            nesting = 0
            while index < stop:
                char = data[index : index + 1]
                if char == b"\\":
                    index += 2
                    continue
                if char == b"(":
                    nesting += 1
                elif char == b")":
                    nesting -= 1
                    if nesting == 0:
                        break
                index += 1
            index += 1
            continue
        index += 1
    return b""


def pdf_trailer_dictionaries(data: bytes | mmap.mmap) -> list[tuple[str, bytes]]:
    """Trailer dictionaries in authority order: the ``startxref`` chain (newest first, then
    ``/Prev``), then the linearized first-page trailer, then any other trailer / XRef stream dict."""
    ordered: list[tuple[str, bytes]] = []
    seen_offsets: set[int] = set()

    def trailer_at(offset: int) -> bytes:
        if offset < 0 or offset >= len(data):
            return b""
        window = data[offset : offset + 32].lstrip()
        if window.startswith(b"xref"):
            keyword = data.find(b"trailer", offset)
            if keyword < 0:
                return b""
            start = data.find(b"<<", keyword)
            return pdf_dictionary_at(data, start) if start >= 0 else b""
        header = re.match(rb"\s*\d+\s+\d+\s+obj\s*", data[offset : offset + 64])
        if header:
            return pdf_dictionary_at(data, offset + header.end())
        return b""

    startxref = data.rfind(b"startxref")
    if startxref >= 0:
        match = re.match(rb"startxref\s+(\d+)", data[startxref : startxref + 40])
        offset = int(match.group(1)) if match else -1
        for _ in range(64):
            if offset < 0 or offset in seen_offsets:
                break
            seen_offsets.add(offset)
            trailer = trailer_at(offset)
            if not trailer:
                break
            ordered.append(("startxref-chain", trailer))
            previous = re.search(rb"/Prev\s+(\d+)", trailer)
            offset = int(previous.group(1)) if previous else -1
    linearized = b"/Linearized" in data[:2048]
    others: list[tuple[int, str, bytes]] = []
    for match in re.finditer(rb"trailer\s*<<", data):
        trailer = pdf_dictionary_at(data, match.end() - 2)
        if trailer:
            others.append((match.start(), "trailer-keyword", trailer))
    for match in re.finditer(rb"/Type\s*/XRef\b", data):
        start = data.rfind(b"<<", max(0, match.start() - 4096), match.start())
        trailer = pdf_dictionary_at(data, start) if start >= 0 else b""
        if trailer:
            others.append((start, "xref-stream", trailer))
    # Linearized: the first-page trailer near the start is authoritative; otherwise newest (last) first.
    others.sort(key=lambda item: item[0], reverse=not linearized)
    ordered.extend((source, trailer) for _offset, source, trailer in others)
    return ordered


def pdf_find_object(data: bytes | mmap.mmap, number: int, generation: int) -> tuple[bytes | None, str]:
    pattern = re.compile(rb"(?<![0-9])%d\s+%d\s+obj\b" % (number, generation))
    last = None
    for match in pattern.finditer(data):
        last = match
    if last is not None:
        end = data.find(b"endobj", last.end())
        stop = end if end >= 0 else min(len(data), last.end() + 65536)
        return bytes(data[last.end() : stop]), "indirect-object"
    for match in re.finditer(rb"/Type\s*/ObjStm", data):
        body = pdf_object_from_stream(data, match.start(), number)
        if body is not None:
            return body, "object-stream"
    return None, "object-not-found"


def pdf_object_from_stream(data: bytes | mmap.mmap, type_offset: int, number: int) -> bytes | None:
    dict_start = data.rfind(b"obj", max(0, type_offset - 4096), type_offset)
    stream_index = data.find(b"stream", type_offset, type_offset + 4096)
    if dict_start < 0 or stream_index < 0:
        return None
    header = bytes(data[dict_start:stream_index])
    count_match = re.search(rb"/N\s+(\d+)", header)
    first_match = re.search(rb"/First\s+(\d+)", header)
    if not count_match or not first_match or b"/FlateDecode" not in header:
        return None
    start = stream_index + len(b"stream")
    if data[start : start + 2] == b"\r\n":
        start += 2
    elif data[start : start + 1] in (b"\n", b"\r"):
        start += 1
    end = data.find(b"endstream", start)
    if end < 0:
        return None
    try:
        decompressor = zlib.decompressobj()
        payload = decompressor.decompress(bytes(data[start:end]), PDF_OBJSTM_MAX_BYTES)
    except zlib.error:
        return None
    first = int(first_match.group(1))
    numbers = [int(value) for value in re.findall(rb"\d+", payload[:first])]
    pairs = list(zip(numbers[0::2], numbers[1::2]))[: int(count_match.group(1))]
    for index, (object_number, offset) in enumerate(pairs):
        if object_number != number:
            continue
        next_offset = pairs[index + 1][1] if index + 1 < len(pairs) else len(payload) - first
        return payload[first + offset : first + next_offset]
    return None


def pdf_parse_info_dict(body: bytes, data: bytes | mmap.mmap, *, decode_strings: bool) -> dict[str, str]:
    start = body.find(b"<<")
    if start < 0:
        return {}
    values: dict[str, str] = {}
    for key in PDF_INFO_KEYS:
        match = re.search(rb"/" + key.encode("ascii") + rb"(?![A-Za-z0-9])\s*", body[start:])
        if not match:
            continue
        position = start + match.end()
        value = pdf_read_value(body, position, data, decode_strings=decode_strings)
        if value:
            values[key] = value
    return values


def pdf_read_value(body: bytes, position: int, data: bytes | mmap.mmap, *, decode_strings: bool, depth: int = 0) -> str:
    if position >= len(body):
        return ""
    lead = body[position : position + 1]
    if lead == b"(":
        raw = pdf_literal_string(body, position)
        if PDF_XREF_ROW_RE.search(raw):
            # A literal that runs into an xref table is a truncated/corrupt object.
            return ""
        return pdf_decode_text(raw) if decode_strings else ""
    if lead == b"<" and body[position : position + 2] != b"<<":
        end = body.find(b">", position)
        hex_text = re.sub(rb"\s+", b"", body[position + 1 : end if end >= 0 else len(body)])
        if len(hex_text) % 2:
            hex_text += b"0"
        try:
            raw = bytes.fromhex(hex_text.decode("ascii"))
        except ValueError:
            return ""
        return pdf_decode_text(raw) if decode_strings else ""
    reference = re.match(rb"(\d+)\s+(\d+)\s+R", body[position : position + 32])
    if reference and depth == 0:
        target, _source = pdf_find_object(data, int(reference.group(1)), int(reference.group(2)))
        if target is None:
            return ""
        stripped = target.lstrip()
        return pdf_read_value(stripped, 0, data, decode_strings=decode_strings, depth=1)
    return ""


def pdf_literal_string(body: bytes, position: int) -> bytes:
    output = bytearray()
    depth = 0
    index = position
    while index < len(body):
        char = body[index]
        if char == 0x5C:  # backslash
            index += 1
            if index >= len(body):
                break
            escaped = body[index]
            mapping = {0x6E: 0x0A, 0x72: 0x0D, 0x74: 0x09, 0x62: 0x08, 0x66: 0x0C, 0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}
            if escaped in mapping:
                output.append(mapping[escaped])
            elif 0x30 <= escaped <= 0x37:
                digits = bytes([escaped])
                while len(digits) < 3 and index + 1 < len(body) and 0x30 <= body[index + 1] <= 0x37:
                    index += 1
                    digits += bytes([body[index]])
                output.append(int(digits, 8) & 0xFF)
            elif escaped in (0x0D, 0x0A):
                if escaped == 0x0D and index + 1 < len(body) and body[index + 1] == 0x0A:
                    index += 1
            else:
                output.append(escaped)
        elif char == 0x28:
            depth += 1
            if depth > 1:
                output.append(char)
        elif char == 0x29:
            depth -= 1
            if depth == 0:
                break
            output.append(char)
        else:
            output.append(char)
        index += 1
    return bytes(output)


def pdf_decode_text(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16-be", errors="replace")
    elif raw.startswith(b"\xff\xfe"):
        text = raw[2:].decode("utf-16-le", errors="replace")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw[3:].decode("utf-8", errors="replace")
    else:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = "".join(PDFDOC_ENCODING.get(byte, chr(byte)) for byte in raw)
    return " ".join(text.replace("\x00", "").split())[:1000]


# PDFDocEncoding differs from latin-1 only in 0x18-0x1F and 0x80-0xA0 (PDF 32000-1 Annex D).
PDFDOC_ENCODING = {
    0x18: "\u02d8", 0x19: "\u02c7", 0x1A: "\u02c6", 0x1B: "\u02d9", 0x1C: "\u02dd", 0x1D: "\u02db",
    0x1E: "\u02da", 0x1F: "\u02dc", 0x80: "\u2022", 0x81: "\u2020", 0x82: "\u2021", 0x83: "\u2026",
    0x84: "\u2014", 0x85: "\u2013", 0x86: "\u0192", 0x87: "\u2044", 0x88: "\u2039", 0x89: "\u203a",
    0x8A: "\u2212", 0x8B: "\u2030", 0x8C: "\u201e", 0x8D: "\u201c", 0x8E: "\u201d", 0x8F: "\u2018",
    0x90: "\u2019", 0x91: "\u201a", 0x92: "\u2122", 0x93: "\ufb01", 0x94: "\ufb02", 0x95: "\u0141",
    0x96: "\u0152", 0x97: "\u0160", 0x98: "\u0178", 0x99: "\u017d", 0x9A: "\u0131", 0x9B: "\u0142",
    0x9C: "\u0153", 0x9D: "\u0161", 0x9E: "\u017e", 0xA0: "\u20ac",
}


def pdf_date_to_iso(value: str) -> str:
    match = PDF_DATE_RE.match(value.strip())
    if not match:
        return ""
    year = int(match.group(1))
    month = int(match.group(2) or 1)
    day = int(match.group(3) or 1)
    hour = int(match.group(4) or 0)
    minute = int(match.group(5) or 0)
    second = int(match.group(6) or 0)
    tzinfo: dt.tzinfo | None = None
    if match.group(7):
        tzinfo = dt.timezone.utc
    elif match.group(8):
        offset = dt.timedelta(hours=int(match.group(9) or 0), minutes=int(match.group(10) or 0))
        tzinfo = dt.timezone(-offset if match.group(8) == "-" else offset)
    try:
        moment = dt.datetime(year, month, day, hour, minute, second, tzinfo=tzinfo)
    except ValueError:
        return ""
    return moment.isoformat()


def document_lock_owner_record(path: Path) -> ArtifactRecord | None:
    data = read_prefix(path, 4096)
    owner = parse_office_lock_owner(data)
    if not owner:
        return None
    stat_result = safe_stat(path)
    target_name = path.name[2:]
    return ArtifactRecord(
        provider=GenericDocumentArtifactProvider.name,
        artifact_type="document-lock-owner",
        path=str(path.resolve()),
        supported=True,
        details={
            "parser": "office-owner-lock-file",
            "parser_version": PARSER_VERSION,
            "source_path": str(path.resolve()),
            "source_hashes": safe_source_hashes(path),
            "source_size": stat_result.get("size", 0),
            "source_file_mtime": stat_result.get("modified_at", ""),
            "lock_format": owner["lock_format"],
            "lock_owner": owner.get("lock_owner", ""),
            "lock_owner_host": owner.get("lock_owner_host", ""),
            "lock_owner_ansi": owner.get("lock_owner_ansi", ""),
            "locked_document_name_hint": target_name,
            "display_label": "문서 잠금 파일(편집 중이던 사용자)",
            "interpretation": (
                "Office/한컴 소유자 잠금 파일(~$)은 문서를 열어 둔 사용자 이름을 기록합니다. 비정상 종료 등으로 남은 "
                "파일이며, 대상 문서 이름은 앞 두 글자가 잘린 형태일 수 있습니다."
            ),
            "coverage_status": "owner-lock-file-parsed",
            "validation_required": True,
            "commercial_grade_ready": False,
            "risk_flags": ["document-lock-owner"],
        },
    )


def parse_office_lock_owner(data: bytes) -> dict[str, str]:
    hancom_magic = "HCellShareFileInfo".encode("utf-16le")
    if data.startswith(hancom_magic) and len(data) >= 0x90:
        host = data[0x50:0x6E].decode("utf-16le", errors="replace").split("\0", 1)[0]
        user = data[0x6E:0x6E + 128].decode("utf-16le", errors="replace").split("\x00", 1)[0]
        if host or user:
            return {"lock_format": "hancom-cell-share-info", "lock_owner": user.strip(), "lock_owner_host": host.strip()}
        return {}
    if len(data) < 2 or not 0 < data[0] <= 54:
        return {}
    length = data[0]
    ansi = decode_ansi_text(data[1 : 1 + length]).strip()
    for offset in range(0x34, 0x3A):
        if offset + 2 + length * 2 > len(data):
            break
        if struct.unpack_from("<H", data, offset)[0] != length:
            continue
        candidate = data[offset + 2 : offset + 2 + length * 2].decode("utf-16le", errors="replace")
        if candidate and "�" not in candidate and candidate.strip("\x00"):
            return {"lock_format": "office-owner-file", "lock_owner": candidate.strip(), "lock_owner_ansi": ansi}
    if ansi and ansi.isprintable():
        return {"lock_format": "office-owner-file-ansi-only", "lock_owner": ansi, "lock_owner_ansi": ansi}
    return {}


def extract_ooxml_properties(archive: zipfile.ZipFile, names: set[str]) -> dict[str, str]:
    props: dict[str, str] = {}
    for name in sorted(OOXML_PROPS_PATHS.intersection(names)):
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        props.update(extract_xml_leaf_text(xml_data))
    return props


def extract_odf_properties(archive: zipfile.ZipFile, names: set[str]) -> dict[str, str]:
    props: dict[str, str] = {}
    for name in sorted(ODF_META_PATHS.intersection(names)):
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        props.update(extract_xml_leaf_text(xml_data))
    return props


def extract_xml_leaf_text(xml_data: bytes) -> dict[str, str]:
    try:
        root = safe_xml_fromstring(xml_data)
    except (ET.ParseError, UnsafeXmlError):
        return {}
    props: dict[str, str] = {}
    for node in root.iter():
        if not node.text or not node.text.strip():
            continue
        tag = node.tag.rsplit("}", 1)[-1]
        props.setdefault(tag, node.text.strip()[:500])
    return props


def extract_ooxml_external_references(archive: zipfile.ZipFile, names: set[str]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for name in sorted(item for item in names if item.endswith(".rels")):
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        try:
            root = safe_xml_fromstring(xml_data)
        except (ET.ParseError, UnsafeXmlError):
            continue
        for node in root.iter():
            target = str(node.attrib.get("Target") or "")
            mode = str(node.attrib.get("TargetMode") or "")
            if mode.lower() == "external" or target.lower().startswith(("http://", "https://", "file://", "\\\\")):
                refs.append(
                    {
                        "relationship_file": name,
                        "target": target[:500],
                        "target_mode": mode,
                        "type": str(node.attrib.get("Type") or "")[:200],
                    }
                )
    return refs


def document_metadata_risk_flags(
    author_candidates: Sequence[str],
    macro_paths: Sequence[str],
    external_refs: Sequence[Mapping[str, str]],
    props: Mapping[str, str],
) -> list[str]:
    flags = ["document-metadata-profile"]
    if author_candidates:
        flags.append("document-author-metadata")
    if macro_paths:
        flags.append("document-macro-present")
    if external_refs:
        flags.append("document-external-reference-candidate")
    if any(str(value).strip() for key, value in props.items() if key.lower() in {"created", "modified"}):
        flags.append("document-timestamp-metadata")
    return flags


def collect_sticky_notes_sqlite(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = safe_source_hashes(path)
    # Evidence SQLite is only ever read from a private snapshot copy
    # (immutable working copy), never opened in place.
    snapshot_stack = contextlib.ExitStack()
    try:
        connection = snapshot_stack.enter_context(open_sqlite_snapshot(path.resolve()))
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        snapshot_stack.close()
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="sticky-note-db-unreadable",
            path=str(path.resolve()),
            supported=False,
            details={
                "parser": "sticky-notes-plum",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "coverage_status": "sqlite-open-failed",
                "error": str(exc)[:300],
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": sticky_notes_blockers(),
            },
        )
        return
    with snapshot_stack:
        tables = sticky_note_candidate_tables(connection)
        schema_profile = sticky_notes_schema_profile(connection, tables)
        emitted = 0
        live_note_hashes: set[str] = set()
        for table_name, columns in tables:
            if emitted >= STICKY_NOTE_ROW_LIMIT:
                break
            text_column = first_matching_column(columns, ("text", "content", "body", "note", "plain", "payload"))
            if not text_column:
                continue
            created_column = first_matching_column(columns, ("createdat", "created", "createtime", "creationtime"))
            updated_column = first_matching_column(columns, ("updatedat", "updated", "modified", "modifiedtime", "lastmodified"))
            deleted_column = first_matching_column(columns, ("isdeleted", "deleted", "trashed"))
            color_column = first_matching_column(columns, ("color", "theme"))
            account_column = first_matching_column(columns, ("account", "user", "userid", "email"))
            sql = f'SELECT rowid, * FROM "{table_name}" LIMIT ?'
            try:
                rows = connection.execute(sql, (STICKY_NOTE_ROW_LIMIT - emitted,)).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                text = optional_text(row[text_column])
                if not text.strip():
                    continue
                text_hash = sha256_text(text)
                live_note_hashes.add(text_hash)
                emitted += 1
                is_deleted = boolish(row[deleted_column]) if deleted_column else False
                account_hint = optional_text(row[account_column]) if account_column else ""
                yield ArtifactRecord(
                    provider=GenericDocumentArtifactProvider.name,
                    artifact_type="sticky-note",
                    path=str(path.resolve()),
                    supported=True,
                    details={
                        "parser": "sticky-notes-plum",
                        "parser_version": PARSER_VERSION,
                        "source_path": str(path.resolve()),
                        "source_hashes": source_hashes,
                        "source_table": table_name,
                        "source_index": emitted - 1,
                        "rowid": row["rowid"],
                        "created_at": normalize_sqlite_time(row[created_column]) if created_column else "",
                        "updated_at": normalize_sqlite_time(row[updated_column]) if updated_column else "",
                        "is_deleted": is_deleted,
                        "account_hint": account_hint,
                        "color_hint": optional_text(row[color_column]) if color_column else "",
                        "text_preview": redact_note_preview(text),
                        "text_sha256": text_hash,
                        "text_length": len(text),
                        "sticky_note_schema_profile": schema_profile,
                        "sticky_note_review_profile": sticky_note_review_profile(
                            text=text,
                            is_deleted=is_deleted,
                            account_hint=account_hint,
                            source_table=table_name,
                            recovered=False,
                        ),
                        "coverage_status": "plum-sqlite-row-normalized",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": sticky_notes_blockers(),
                        "risk_flags": sticky_note_risk_flags(text, is_deleted, account_hint=account_hint),
                    },
                )
        for candidate_index, candidate in enumerate(sticky_note_recovery_candidates(path, live_note_hashes)):
            yield ArtifactRecord(
                provider=GenericDocumentArtifactProvider.name,
                artifact_type="sticky-note-recovery-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "sticky-notes-plum",
                    "parser_version": PARSER_VERSION,
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "source_index": candidate_index,
                    "source_offset": candidate["source_offset"],
                    "encoding": candidate["encoding"],
                    "recovery_method": candidate["recovery_method"],
                    "recovery_reason": candidate["recovery_reason"],
                    "text_preview": redact_note_preview(str(candidate["text"])),
                    "text_sha256": sha256_text(str(candidate["text"])),
                    "text_length": len(str(candidate["text"])),
                    "sticky_note_schema_profile": schema_profile,
                    "sticky_note_review_profile": sticky_note_review_profile(
                        text=str(candidate["text"]),
                        is_deleted=True,
                        account_hint=str(candidate.get("account_hint", "")),
                        source_table="bounded-string-scan",
                        recovered=True,
                    ),
                    "coverage_status": "plum-sqlite-bounded-string-recovery-candidate",
                    "validation_required": True,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": sticky_notes_blockers(),
                    "risk_flags": sticky_note_risk_flags(
                        str(candidate["text"]),
                        True,
                        account_hint=str(candidate.get("account_hint", "")),
                    ),
                },
            )


def sticky_note_candidate_tables(connection: sqlite3.Connection) -> list[tuple[str, list[str]]]:
    try:
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    except sqlite3.Error:
        return []
    candidates: list[tuple[str, list[str]]] = []
    for table_row in table_rows:
        table_name = str(table_row[0])
        try:
            columns = [
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
            ]
        except sqlite3.Error:
            continue
        normalized = {normalize_column(column) for column in columns}
        if normalized.intersection({"text", "content", "body", "note", "plain", "payload"}):
            candidates.append((table_name, columns))
    return candidates


def sticky_notes_schema_profile(
    connection: sqlite3.Connection,
    candidate_tables: Sequence[tuple[str, list[str]]],
) -> dict[str, object]:
    candidate_names = {table_name for table_name, _columns in candidate_tables}
    try:
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    except sqlite3.Error:
        table_rows = []
    table_profiles: list[dict[str, object]] = []
    for table_row in table_rows[:30]:
        table_name = str(table_row[0])
        try:
            columns = [
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
            ]
        except sqlite3.Error:
            columns = []
        table_profiles.append(
            {
                "name": table_name,
                "columns": columns,
                "row_count": sqlite_count_rows(connection, table_name),
                "is_note_candidate": table_name in candidate_names,
                "has_text_column": bool(
                    first_matching_column(columns, ("text", "content", "body", "note", "plain", "payload"))
                ),
                "has_deleted_column": bool(first_matching_column(columns, ("isdeleted", "deleted", "trashed"))),
                "has_account_column": bool(first_matching_column(columns, ("account", "user", "userid", "email"))),
                "has_timestamp_column": bool(
                    first_matching_column(
                        columns,
                        ("createdat", "created", "createtime", "creationtime", "updatedat", "modified", "lastmodified"),
                    )
                ),
            }
        )
    return {
        "profile_version": "sticky-notes-schema-profile-v1",
        "database_open_status": "opened",
        "table_count": len(table_rows),
        "bounded_table_count": len(table_profiles),
        "candidate_note_table_count": len(candidate_tables),
        "candidate_note_tables": [table_name for table_name, _columns in candidate_tables],
        "tables": table_profiles,
        "truncated_tables": len(table_rows) > len(table_profiles),
        "validation_required": True,
        "validation_guidance": (
            "Schema profile identifies plausible Sticky Notes tables and columns. Confirm app version, account/device "
            "attribution, deleted state, and row semantics against a known-answer plum.sqlite fixture before reporting."
        ),
    }


def sticky_note_recovery_candidates(path: Path, live_text_hashes: set[str]) -> list[dict[str, object]]:
    blob = read_prefix(path, STICKY_NOTE_RECOVERY_SCAN_BYTES)
    candidates: list[dict[str, object]] = []
    seen_hashes: set[str] = set(live_text_hashes)
    for encoding, iterator in (
        ("ascii", iter_ascii_strings_with_offsets(blob, minimum=14)),
        ("utf-16le", iter_utf16le_strings_with_offsets(blob, minimum=14)),
    ):
        for offset, text in iterator:
            cleaned = " ".join(text.split())
            text_hash = sha256_text(cleaned)
            if text_hash in seen_hashes or not looks_like_sticky_note_recovery_text(cleaned):
                continue
            seen_hashes.add(text_hash)
            candidates.append(
                {
                    "source_offset": offset,
                    "encoding": encoding,
                    "text": cleaned,
                    "account_hint": first_regex_match(cleaned, EMAIL_RE),
                    "recovery_method": "bounded-sqlite-string-scan",
                    "recovery_reason": "string-fragment-not-present-in-live-note-rows",
                }
            )
            if len(candidates) >= STICKY_NOTE_RECOVERY_LIMIT:
                return candidates
    return candidates


def sticky_note_review_profile(
    *,
    text: str,
    is_deleted: bool,
    account_hint: str,
    source_table: str,
    recovered: bool,
) -> dict[str, object]:
    lowered = text.lower()
    sensitive_terms = [
        term
        for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed", "recovery")
        if term in lowered
    ]
    urls = [match.group(0) for match in URL_RE.finditer(text)][:10]
    emails = [match.group(0) for match in EMAIL_RE.finditer(text)][:10]
    return {
        "profile_version": "sticky-note-review-profile-v1",
        "source_table": source_table,
        "source_kind": "bounded-recovery-candidate" if recovered else "sqlite-live-row",
        "deleted_state": "deleted-or-recovered-candidate" if is_deleted else "live-row",
        "text_length": len(text),
        "sensitive_term_hits": sensitive_terms,
        "url_candidates": urls,
        "email_candidates": emails,
        "account_hint_present": bool(account_hint),
        "values_are_candidates": recovered,
        "source_viewer_hint": "Open plum.sqlite with the SQLite/hex viewer and verify the row or source offset before reporting.",
        "report_blockers": [
            "app-version-schema-fixture-required",
            "deleted-state-trusted-diff-required" if is_deleted or recovered else "row-semantics-trusted-diff-required",
            "account-device-attribution-corroboration-required",
        ],
    }


def looks_like_sticky_note_recovery_text(text: str) -> bool:
    if len(text) < 14 or len(text) > 2000:
        return False
    lowered = text.lower()
    if any(term in lowered for term in ("create table", "sqlite_", "pragma ", "index ", "microsoft.msn", "http://schemas")):
        return False
    if not any(character.isalpha() for character in text):
        return False
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        return True
    if first_regex_match(text, EMAIL_RE) or first_regex_match(text, URL_RE):
        return True
    return " " in text and len(text.split()) >= 3


def iter_ascii_strings_with_offsets(blob: bytes, *, minimum: int) -> Iterable[tuple[int, str]]:
    start: int | None = None
    current = bytearray()
    for index, value in enumerate(blob):
        if 32 <= value <= 126:
            if start is None:
                start = index
            current.append(value)
            continue
        if start is not None and len(current) >= minimum:
            yield start, current.decode("utf-8", errors="replace")
        start = None
        current = bytearray()
    if start is not None and len(current) >= minimum:
        yield start, current.decode("utf-8", errors="replace")


def iter_utf16le_strings_with_offsets(blob: bytes, *, minimum: int) -> Iterable[tuple[int, str]]:
    start: int | None = None
    chars: list[str] = []
    index = 0
    while index + 1 < len(blob):
        value = blob[index]
        null = blob[index + 1]
        if 32 <= value <= 126 and null == 0:
            if start is None:
                start = index
            chars.append(chr(value))
            index += 2
            continue
        if start is not None and len(chars) >= minimum:
            yield start, "".join(chars)
        start = None
        chars = []
        index += 1
    if start is not None and len(chars) >= minimum:
        yield start, "".join(chars)


def collect_local_llm_inventory(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not safe_is_file(path):
            continue
        product = infer_local_llm_product(path)
        suffix = path.suffix.lower()
        if not product and suffix not in LOCAL_LLM_MODEL_SUFFIXES:
            continue
        model_magic = local_llm_model_magic(path) if suffix in LOCAL_LLM_MODEL_SUFFIXES else ""
        if suffix in LOCAL_LLM_MAGIC_REQUIRED_SUFFIXES and not model_magic:
            continue
        if not product and suffix in LOCAL_LLM_MODEL_SUFFIXES:
            product = "Local LLM model file"
        if suffix not in LOCAL_LLM_MODEL_SUFFIXES and suffix not in LOCAL_LLM_CONFIG_SUFFIXES:
            continue
        stat_result = safe_stat(path)
        source_hashes = safe_source_hashes(path)
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="local-llm-artifact",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "local-llm-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "product_hint": product,
                "artifact_role": local_llm_role(path),
                "model_name_hint": local_llm_model_name_hint(path),
                "model_format_magic": model_magic,
                "source_size": stat_result.get("size", 0),
                "source_file_mtime": stat_result.get("modified_at", ""),
                "coverage_status": "local-llm-file-inventory",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "application-version-and-schema-not-verified",
                    "prompt-history-db-parser-not-complete",
                    "model-download-provenance-not-validated",
                ],
                "risk_flags": local_llm_risk_flags(path),
            },
        )
        yield from collect_local_llm_prompt_candidates(path=path, product=product, source_hashes=source_hashes)


def collect_local_llm_prompt_candidates(
    *,
    path: Path,
    product: str,
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    suffix = path.suffix.lower()
    if suffix in LOCAL_LLM_MODEL_SUFFIXES:
        return
    if suffix in {".sqlite", ".db"}:
        yield from collect_local_llm_sqlite_prompt_candidates(path=path, product=product, source_hashes=source_hashes)
        return
    if suffix not in {".json", ".yaml", ".yml", ".toml", ".log", ".txt"}:
        return
    data = read_prefix(path, LOCAL_LLM_PROMPT_SCAN_BYTES)
    if not data:
        return
    text = data.decode("utf-8", errors="replace")
    emitted = 0
    for offset, fragment in local_llm_text_prompt_fragments(text):
        if emitted >= LOCAL_LLM_PROMPT_ROW_LIMIT:
            break
        emitted += 1
        direction = local_llm_prompt_direction(fragment)
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="local-llm-prompt-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "local-llm-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "product_hint": product,
                "source_index": emitted - 1,
                "source_offset": offset,
                "source_kind": "bounded-text-fragment",
                "direction": direction,
                "content_preview": redact_note_preview(fragment),
                "content_sha256": sha256_text(fragment),
                "content_length": len(fragment),
                "local_llm_review_profile": local_llm_review_profile(
                    product=product,
                    direction=direction,
                    content=fragment,
                    source_kind="bounded-text-fragment",
                ),
                "coverage_status": "local-llm-prompt-fragment-candidate",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "local-llm-app-schema-version-not-validated",
                    "prompt-history-format-not-confirmed",
                    "conversation-thread-pairing-not-complete",
                ],
                "risk_flags": local_llm_prompt_risk_flags(direction, fragment),
            },
        )


def collect_local_llm_sqlite_prompt_candidates(
    *,
    path: Path,
    product: str,
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    # Evidence SQLite is only ever read from a private snapshot copy
    # (immutable working copy), never opened in place.
    snapshot_stack = contextlib.ExitStack()
    try:
        connection = snapshot_stack.enter_context(open_sqlite_snapshot(path.resolve()))
        connection.row_factory = sqlite3.Row
    except sqlite3.Error:
        snapshot_stack.close()
        return
    emitted = 0
    with snapshot_stack:
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        except sqlite3.Error:
            return
        for table_row in table_rows[:DESKTOP_AI_TABLE_LIMIT]:
            if emitted >= LOCAL_LLM_PROMPT_ROW_LIMIT:
                break
            table_name = str(table_row["name"])
            try:
                columns = [
                    str(row["name"])
                    for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
                ]
            except sqlite3.Error:
                continue
            content_column = first_matching_column(
                columns,
                ("prompt", "content", "text", "message", "input", "output", "response", "completion"),
            )
            if not content_column:
                continue
            role_column = first_matching_column(columns, ("role", "sender", "speaker", "type"))
            created_column = first_matching_column(
                columns,
                ("createdat", "created_at", "created", "timestamp", "time", "date", "updatedat", "updated_at"),
            )
            selected_columns = ["rowid", content_column]
            for optional_column in (role_column, created_column):
                if optional_column and optional_column not in selected_columns:
                    selected_columns.append(optional_column)
            sql = (
                "SELECT "
                + ", ".join("rowid" if column == "rowid" else quote_sqlite_identifier(column) for column in selected_columns)
                + f" FROM {quote_sqlite_identifier(table_name)} LIMIT ?"
            )
            try:
                rows = connection.execute(sql, (LOCAL_LLM_PROMPT_ROW_LIMIT - emitted,)).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                content = optional_text(row[content_column])
                if not content.strip():
                    continue
                role_hint = optional_text(row[role_column]) if role_column else ""
                direction = local_llm_prompt_direction(role_hint or content_column)
                emitted += 1
                yield ArtifactRecord(
                    provider=GenericDocumentArtifactProvider.name,
                    artifact_type="local-llm-prompt-candidate",
                    path=str(path.resolve()),
                    supported=True,
                    details={
                        "parser": "local-llm-inventory",
                        "parser_version": PARSER_VERSION,
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "product_hint": product,
                        "source_table": table_name,
                        "source_index": emitted - 1,
                        "rowid": row["rowid"],
                        "source_kind": "sqlite-row",
                        "role_hint": role_hint,
                        "direction": direction,
                        "created_at": normalize_sqlite_time(row[created_column]) if created_column else "",
                        "content_preview": redact_note_preview(content),
                        "content_sha256": sha256_text(content),
                        "content_length": len(content),
                        "local_llm_review_profile": local_llm_review_profile(
                            product=product,
                            direction=direction,
                            content=content,
                            source_kind="sqlite-row",
                        ),
                        "coverage_status": "local-llm-sqlite-prompt-row-candidate",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": [
                            "local-llm-app-schema-version-not-validated",
                            "service-or-app-export-diff-required",
                            "conversation-thread-pairing-not-complete",
                        ],
                        "risk_flags": local_llm_prompt_risk_flags(direction, content),
                    },
                )


def collect_desktop_ai_app_inventory(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        if not safe_is_file(path) or path.suffix.lower() not in DESKTOP_AI_APP_SUFFIXES:
            continue
        product = infer_desktop_ai_product(path)
        if not product:
            continue
        stat_result = safe_stat(path)
        sqlite_profile = desktop_ai_sqlite_profile(path)
        message_tables = sqlite_profile.get("message_table_candidates", []) if isinstance(sqlite_profile, Mapping) else []
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="desktop-ai-app-artifact",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "desktop-ai-app-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": safe_source_hashes(path),
                "product_hint": product,
                "artifact_role": desktop_ai_app_role(path),
                "source_size": stat_result.get("size", 0),
                "source_file_mtime": stat_result.get("modified_at", ""),
                "database_profile": sqlite_profile,
                "message_table_candidates": message_tables,
                "coverage_status": "desktop-ai-app-file-inventory",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "desktop-ai-app-schema-version-not-validated",
                    "prompt-history-db-parser-not-complete",
                    "service-export-diff-required",
                ],
                "risk_flags": desktop_ai_app_risk_flags(path, sqlite_profile),
            },
        )
        yield from collect_desktop_ai_conversation_candidates(
            path=path,
            product=product,
            sqlite_profile=sqlite_profile,
            source_hashes=safe_source_hashes(path),
        )


def collect_desktop_ai_conversation_candidates(
    *,
    path: Path,
    product: str,
    sqlite_profile: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    if path.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        return
    message_tables = sqlite_profile.get("message_table_candidates")
    if not isinstance(message_tables, list) or not message_tables:
        return
    # Evidence SQLite is only ever read from a private snapshot copy
    # (immutable working copy), never opened in place.
    snapshot_stack = contextlib.ExitStack()
    try:
        connection = snapshot_stack.enter_context(open_sqlite_snapshot(path.resolve()))
        connection.row_factory = sqlite3.Row
    except sqlite3.Error:
        snapshot_stack.close()
        return
    emitted = 0
    with snapshot_stack:
        for table_profile in message_tables[:DESKTOP_AI_MESSAGE_TABLE_LIMIT]:
            if emitted >= DESKTOP_AI_MESSAGE_ROW_LIMIT or not isinstance(table_profile, Mapping):
                break
            table_name = str(table_profile.get("name") or "")
            columns = [str(column) for column in table_profile.get("columns") or []]
            if not table_name or not columns:
                continue
            content_column = first_matching_column(
                columns,
                ("content", "text", "message", "body", "prompt", "answer", "response", "completion"),
            )
            if not content_column:
                continue
            role_column = first_matching_column(columns, ("role", "author", "sender", "speaker", "type"))
            created_column = first_matching_column(
                columns,
                ("createdat", "created_at", "created", "timestamp", "time", "date", "updatedat", "updated_at"),
            )
            conversation_column = first_matching_column(
                columns,
                ("conversationid", "conversation_id", "chatid", "chat_id", "threadid", "thread_id", "sessionid"),
            )
            selected_columns = ["rowid", content_column]
            for optional_column in (role_column, created_column, conversation_column):
                if optional_column and optional_column not in selected_columns:
                    selected_columns.append(optional_column)
            sql = (
                "SELECT "
                + ", ".join("rowid" if column == "rowid" else quote_sqlite_identifier(column) for column in selected_columns)
                + f" FROM {quote_sqlite_identifier(table_name)} LIMIT ?"
            )
            try:
                rows = connection.execute(sql, (DESKTOP_AI_MESSAGE_ROW_LIMIT - emitted,)).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                content = optional_text(row[content_column])
                if not content.strip():
                    continue
                role_hint = optional_text(row[role_column]) if role_column else ""
                conversation_hint = optional_text(row[conversation_column]) if conversation_column else ""
                created_at = normalize_sqlite_time(row[created_column]) if created_column else ""
                direction = desktop_ai_message_direction(role_hint, content_column)
                emitted += 1
                yield ArtifactRecord(
                    provider=GenericDocumentArtifactProvider.name,
                    artifact_type="desktop-ai-conversation-candidate",
                    path=str(path.resolve()),
                    supported=True,
                    details={
                        "parser": "desktop-ai-app-inventory",
                        "parser_version": PARSER_VERSION,
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "product_hint": product,
                        "source_table": table_name,
                        "source_index": emitted - 1,
                        "rowid": row["rowid"],
                        "role_hint": role_hint,
                        "direction": direction,
                        "conversation_id_hint": conversation_hint,
                        "created_at": created_at,
                        "content_preview": redact_note_preview(content),
                        "content_sha256": sha256_text(content),
                        "content_length": len(content),
                        "desktop_ai_conversation_review_profile": desktop_ai_conversation_review_profile(
                            product=product,
                            table_name=table_name,
                            direction=direction,
                            role_hint=role_hint,
                            created_at=created_at,
                            conversation_hint=conversation_hint,
                            content=content,
                        ),
                        "coverage_status": "desktop-ai-sqlite-message-row-candidate",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": [
                            "desktop-ai-app-schema-version-not-validated",
                            "service-export-diff-required",
                            "conversation-thread-pairing-not-complete",
                        ],
                        "risk_flags": desktop_ai_conversation_risk_flags(direction, content),
                    },
                )


def infer_desktop_ai_product(path: Path) -> str:
    lowered = str(path).lower().replace("\\", "/").replace("_", " ")
    if not any(marker in lowered for marker in DESKTOP_AI_APP_STORAGE_MARKERS):
        return ""
    for term, product in DESKTOP_AI_APP_PATH_TERMS.items():
        if term in lowered:
            return product
    return ""


def desktop_ai_app_role(path: Path) -> str:
    suffix = path.suffix.lower()
    lowered_name = path.name.lower()
    if suffix in {".sqlite", ".sqlite3", ".db"}:
        return "application-database"
    if suffix in {".ldb", ".localstorage"} or "leveldb" in str(path).lower():
        return "browser-engine-storage"
    if suffix == ".log":
        return "application-log"
    if suffix == ".json":
        return "configuration-or-export-fragment"
    if "conversation" in lowered_name or "chat" in lowered_name or "message" in lowered_name:
        return "possible-prompt-history"
    return "application-cache-or-metadata"


def desktop_ai_sqlite_profile(path: Path) -> dict[str, object]:
    if path.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        return {"database_open_status": "not-sqlite-extension"}
    # Evidence SQLite is only ever read from a private snapshot copy
    # (immutable working copy), never opened in place.
    snapshot_stack = contextlib.ExitStack()
    try:
        connection = snapshot_stack.enter_context(open_sqlite_snapshot(path.resolve()))
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        snapshot_stack.close()
        return {"database_open_status": "open-failed", "error": str(exc)}
    tables: list[dict[str, object]] = []
    message_candidates: list[dict[str, object]] = []
    with snapshot_stack:
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        except sqlite3.Error as exc:
            return {"database_open_status": "schema-read-failed", "error": str(exc)}
        for table_row in table_rows[:DESKTOP_AI_TABLE_LIMIT]:
            table_name = str(table_row["name"])
            try:
                columns = [
                    str(row["name"])
                    for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
                ]
            except sqlite3.Error:
                columns = []
            row_count = sqlite_count_rows(connection, table_name)
            table_profile = {"name": table_name, "columns": columns, "row_count": row_count}
            tables.append(table_profile)
            normalized_columns = {normalize_column(column) for column in columns}
            if normalized_columns.intersection({"role", "author", "sender", "content", "text", "message", "prompt", "answer", "response"}):
                message_candidates.append(table_profile)
    return {
        "database_open_status": "opened",
        "table_count": len(table_rows),
        "bounded_table_count": len(tables),
        "tables": tables,
        "message_table_candidates": message_candidates,
        "truncated_tables": len(table_rows) > DESKTOP_AI_TABLE_LIMIT,
    }


def sqlite_count_rows(connection: sqlite3.Connection, table_name: str) -> int | None:
    try:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {quote_sqlite_identifier(table_name)}").fetchone()
    except sqlite3.Error:
        return None
    return int(row["count"] or 0) if row is not None else None


def quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def desktop_ai_app_risk_flags(path: Path, sqlite_profile: Mapping[str, object]) -> list[str]:
    flags = ["desktop-ai-app-artifact", "ai-service-usage"]
    role = desktop_ai_app_role(path)
    if role in {"application-database", "possible-prompt-history"}:
        flags.append("possible-ai-prompt-history")
    if sqlite_profile.get("message_table_candidates"):
        flags.append("ai-message-table-candidate")
    return flags


def desktop_ai_message_direction(role_hint: str, content_column: str) -> str:
    normalized_role = normalize_column(role_hint)
    normalized_column = normalize_column(content_column)
    if normalized_role in {"user", "human", "client", "prompt"} or normalized_column == "prompt":
        return "user-prompt-candidate"
    if normalized_role in {"assistant", "ai", "bot", "model", "system"}:
        return "assistant-response-candidate" if normalized_role != "system" else "system-message-candidate"
    if normalized_column in {"answer", "response", "completion"}:
        return "assistant-response-candidate"
    return "message-candidate"


def desktop_ai_conversation_review_profile(
    *,
    product: str,
    table_name: str,
    direction: str,
    role_hint: str,
    created_at: str,
    conversation_hint: str,
    content: str,
) -> dict[str, object]:
    return {
        "profile_version": "desktop-ai-conversation-review-profile-v1",
        "product_hint": product,
        "source_table": table_name,
        "direction": direction,
        "role_hint": role_hint,
        "created_at_present": bool(created_at),
        "conversation_id_present": bool(conversation_hint),
        "content_length": len(content),
        "url_candidates": [match.group(0) for match in URL_RE.finditer(content)][:10],
        "email_candidates": [match.group(0) for match in EMAIL_RE.finditer(content)][:10],
        "sensitive_term_hits": [
            term
            for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed", "credential")
            if term in content.lower()
        ],
        "values_are_candidates": True,
        "source_viewer_hint": (
            "Open the desktop AI SQLite row and compare it with a service export before reporting prompt/answer content."
        ),
        "not_proof_of": [
            "complete-service-side-transcript",
            "message-delivery-or-read-state",
            "conversation-thread-completeness",
        ],
        "report_blockers": [
            "desktop-app-version-schema-fixture-required",
            "service-export-diff-required",
            "thread-pairing-validation-required",
        ],
    }


def desktop_ai_conversation_risk_flags(direction: str, content: str) -> list[str]:
    lowered = content.lower()
    flags = ["desktop-ai-conversation-candidate", "ai-service-usage"]
    if direction == "user-prompt-candidate":
        flags.append("ai-user-prompt-candidate")
    elif direction == "assistant-response-candidate":
        flags.append("ai-assistant-response-candidate")
    if first_regex_match(content, URL_RE):
        flags.append("ai-message-url-candidate")
    if first_regex_match(content, EMAIL_RE):
        flags.append("ai-message-email-candidate")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        flags.append("possible-sensitive-ai-content")
    return flags


def local_llm_model_magic(path: Path) -> str:
    """Content signature of a local model file: GGUF/GGML magic or a safetensors JSON header."""
    head = read_prefix(path, 64)
    if head.startswith(b"GGUF"):
        return "gguf"
    if head[:4] in (b"ggml", b"ggmf", b"ggjt", b"lmgg", b"fmgg", b"tjgg"):
        return "ggml"
    if len(head) >= 10:
        header_length = int.from_bytes(head[:8], "little")
        if 2 <= header_length <= 100 * 1024 * 1024 and head[8:9] == b"{" and head[9:10] in (b'"', b" ", b"\n", b"}"):
            return "safetensors"
    return ""


def infer_local_llm_product(path: Path) -> str:
    lowered = str(path).lower().replace("_", " ")
    for term, product in LOCAL_LLM_PATH_TERMS.items():
        if term in lowered:
            return product
    return ""


def local_llm_role(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in LOCAL_LLM_MODEL_SUFFIXES:
        return "model-file"
    if suffix in {".sqlite", ".db"}:
        return "application-database"
    if suffix == ".log":
        return "application-log"
    return "configuration-or-metadata"


def local_llm_model_name_hint(path: Path) -> str:
    if path.suffix.lower() in LOCAL_LLM_MODEL_SUFFIXES:
        return path.stem
    parent = path.parent.name
    return parent if parent.lower() not in {"models", "blobs", "manifests"} else path.stem


def local_llm_risk_flags(path: Path) -> list[str]:
    flags = ["local-ai-artifact"]
    if path.suffix.lower() in LOCAL_LLM_MODEL_SUFFIXES:
        flags.append("local-model-file")
    lowered = str(path).lower()
    if any(term in lowered for term in ("history", "prompt", "chat", "conversation")):
        flags.append("possible-prompt-history")
    return flags


def local_llm_text_prompt_fragments(text: str) -> list[tuple[int, str]]:
    fragments: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        cleaned = " ".join(line.split()).strip()
        lowered = cleaned.lower()
        if 12 <= len(cleaned) <= 4000 and any(term in lowered for term in LOCAL_LLM_TEXT_PROMPT_TERMS):
            fragments.append((offset, cleaned[:2000]))
        offset += len(line.encode("utf-8", errors="replace"))
    if fragments:
        return fragments[:LOCAL_LLM_PROMPT_ROW_LIMIT]
    for match in re.finditer(r"(?is)(prompt|response|completion|conversation|chat)[\"'\s:=]{1,12}.{20,800}", text):
        fragments.append((match.start(), " ".join(match.group(0).split())[:2000]))
        if len(fragments) >= LOCAL_LLM_PROMPT_ROW_LIMIT:
            break
    return fragments


def local_llm_prompt_direction(value: str) -> str:
    normalized = normalize_column(value)
    lowered = value.lower()
    if normalized in {"user", "human", "prompt", "input"} or "user:" in lowered or "human:" in lowered:
        return "user-prompt-candidate"
    if normalized in {"assistant", "model", "bot", "response", "completion", "output"} or "assistant:" in lowered:
        return "assistant-response-candidate"
    if normalized == "system" or "system:" in lowered:
        return "system-message-candidate"
    return "local-llm-message-candidate"


def local_llm_review_profile(*, product: str, direction: str, content: str, source_kind: str) -> dict[str, object]:
    return {
        "profile_version": "local-llm-review-profile-v1",
        "product_hint": product,
        "source_kind": source_kind,
        "direction": direction,
        "content_length": len(content),
        "url_candidates": [match.group(0) for match in URL_RE.finditer(content)][:10],
        "email_candidates": [match.group(0) for match in EMAIL_RE.finditer(content)][:10],
        "sensitive_term_hits": [
            term
            for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed", "credential")
            if term in content.lower()
        ],
        "values_are_candidates": True,
        "source_viewer_hint": "Open the local LLM log/database source before using this prompt candidate in a report.",
        "not_proof_of": [
            "complete-conversation-thread",
            "message-delivery",
            "model-output-authenticity",
        ],
        "report_blockers": [
            "local-llm-version-fixture-required",
            "prompt-history-schema-diff-required",
            "thread-pairing-validation-required",
        ],
    }


def local_llm_prompt_risk_flags(direction: str, content: str) -> list[str]:
    flags = ["local-llm-prompt-candidate", "local-ai-artifact"]
    lowered = content.lower()
    if direction == "user-prompt-candidate":
        flags.append("local-llm-user-prompt-candidate")
    elif direction == "assistant-response-candidate":
        flags.append("local-llm-assistant-response-candidate")
    if first_regex_match(content, URL_RE):
        flags.append("local-llm-url-candidate")
    if first_regex_match(content, EMAIL_RE):
        flags.append("local-llm-email-candidate")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        flags.append("possible-sensitive-local-llm-content")
    return flags


def safe_source_hashes(path: Path) -> dict[str, str]:
    stat_result = safe_stat(path)
    size = int(stat_result.get("size", 0) or 0)
    if size and size <= LARGE_FILE_HASH_DEFER_BYTES:
        try:
            hashes = compute_hashes(path)
        except OSError:
            hashes = {}
        if hashes:
            return hashes
    return {
        "md5": "",
        "sha1": "",
        "sha256": "",
        "hash_status": "deferred-large-file" if size > LARGE_FILE_HASH_DEFER_BYTES else "unavailable",
        "path_sha256": sha256_text(str(path.resolve())),
    }


def safe_stat(path: Path) -> dict[str, object]:
    try:
        stat_result = path.stat()
    except OSError:
        return {"size": 0, "modified_at": ""}
    return {
        "size": int(stat_result.st_size),
        "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat(),
    }


def safe_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def first_regex_match(value: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(value)
    return match.group(0) if match else ""


def first_matching_column(columns: Sequence[str], names: Sequence[str]) -> str:
    by_normalized = {normalize_column(column): column for column in columns}
    for name in names:
        column = by_normalized.get(normalize_column(name))
        if column:
            return column
    for normalized_name in names:
        wanted = normalize_column(normalized_name)
        for column in columns:
            if wanted in normalize_column(column):
                return column
    return ""


def normalize_column(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def unique_values(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        cleaned = " ".join(str(value).split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def optional_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "deleted"}


def normalize_sqlite_time(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000_000:
            number = number / 1_000_000
        elif number > 10_000_000_000:
            number = number / 1000
        try:
            return dt.datetime.fromtimestamp(number, dt.timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return str(value)
    return str(value)


def redact_note_preview(text: str) -> str:
    preview = " ".join(text.split())[:1200]
    return preview


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sticky_note_risk_flags(text: str, is_deleted: bool, *, account_hint: str = "") -> list[str]:
    lowered = text.lower()
    flags = ["sticky-note-text"]
    if is_deleted:
        flags.append("deleted-note-row")
    if account_hint or first_regex_match(text, EMAIL_RE):
        flags.append("sticky-note-account-or-email-candidate")
    if first_regex_match(text, URL_RE):
        flags.append("sticky-note-url-candidate")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        flags.append("possible-sensitive-note")
    return flags


def sticky_notes_blockers() -> list[str]:
    return [
        "sticky-notes-schema-version-not-verified",
        "deleted-row-recovery-not-complete",
        "account-and-device-attribution-needs-corroboration",
    ]
