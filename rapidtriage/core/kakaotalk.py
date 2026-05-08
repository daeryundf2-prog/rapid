from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.windows.registry import parse_registry_vk_cell, registry_value_data_preview
from .docs import write_result
from .submission import compute_hashes

KAKAOTALK_DECRYPT_VERSION = "kakaotalk-windows-decrypt-v1"
MAX_ZIP_MEMBER_BYTES = 50 * 1024 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 1000
KAKAOTALK_USERDIR_BRUTEFORCE_VERSION = "kakaotalk-windows-userdir-bruteforce-v1"
KAKAOTALK_MEMORY_CARVE_VERSION = "kakaotalk-windows-memory-carve-v1"
KAKAOTALK_KEY_STORE_VERSION = "kakaotalk-windows-key-store-v1"
KAKAOTALK_POSTPATCH_AUXILIARY_VERSION = "kakaotalk-windows-postpatch-auxiliary-v1"
KAKAOTALK_POSTPATCH_IKM_VERSION = "kakaotalk-windows-postpatch-ikm-v1"
KAKAOTALK_POSTPATCH_V2_DEK_VERSION = "kakaotalk-windows-postpatch-v2-dek-v1"
KAKAOTALK_MEDIA_INVENTORY_VERSION = "kakaotalk-windows-media-inventory-v1"
KAKAOTALK_WINDOWS_COLLECT_VERSION = "kakaotalk-windows-collect-v1"
KAKAOTALK_FUNCTIONAL_EXPANSION_BATCH_ID = "commercial-uplift-051-055"
CHATLOG_PATTERN = re.compile(r"^chatlogs_(?P<chat_id>[0-9]+)\.edb$", re.IGNORECASE)
MESSAGE_TABLE_HINTS = ("chat", "message", "log")
TEXT_COLUMN_HINTS = ("message", "msg", "text", "content", "body")
SENDER_COLUMN_HINTS = ("sender", "author", "user", "member", "account")
TIME_COLUMN_HINTS = ("time", "date", "created", "sent", "timestamp")
SQLITE_HEADER = b"SQLite format 3"
PAGE_SIZE = 4096
BLOCK_SIZE = 16
DEFAULT_MEMORY_SQLITE_MAX_HITS = 200
DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES = 64 * 1024 * 1024
DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT = 200
KEY_MATERIAL_SCAN_LIMIT = 256 * 1024 * 1024
KEY_MATERIAL_CHUNK_SIZE = 1024 * 1024
PK_PATTERN = re.compile(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{86}==)([0-9]{3,20})(?![0-9A-Za-z+/])")
DEVICEINFO_FIELDS = ("sys_uuid", "hdd_model", "hdd_serial")
DEVICEINFO_FIELD_ALIASES = {
    "sys_uuid": ("sys_uuid", "UUID", "MotherboardUUID"),
    "hdd_model": ("hdd_model", "HdModel", "DISKMODEL", "Model"),
    "hdd_serial": ("hdd_serial", "HdSerial", "HdSerial1_NH", "DISKSERIAL", "SerialNumber"),
}
KAKAOTALK_DEVICE_PRAGMA_KEY_HEX = "9FBAE3118FDE5DEAEB8279D08F1D4C79"
USER_ID_FIELD_NAMES = (
    "talk_user_id",
    "user_id",
    "userid",
    "userId",
    "tuid",
    "tuidb",
    "uuid",
    "uuidR",
    "login_id",
    "last_login_id",
)
STORED_PRAGMA_FIELD_NAMES = ("dev_id",)
KAKAOTALK_USERDIR_KEY_SEED = "KAKAOTALK_PC_FOREVER"
USERDIR_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
MEMORY_DUMP_SUFFIXES = (".dmp", ".dump", ".raw", ".mem")
MEMORY_DUMP_NAME_HINTS = ("kakaotalk", "memory", "process")
DEFAULT_MEMORY_REVERSE_INDICATOR_LIMIT = 300
DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT = 300
SQLCIPHER_KEY_LITERAL_PATTERN = re.compile(rb"x'([0-9a-fA-F]{64}|[0-9a-fA-F]{96})'")
KAKAOTALK_POSTPATCH_ENTROPY_PATTERN = re.compile(rb"([A-Za-z0-9+/]{86}==)")
MEMORY_REVERSE_INDICATOR_PATTERNS = (
    "TalkChatDB",
    "TalkChatDB::TalkChatDB_Open",
    "TalkChatDB::_InternalOpen",
    "TalkChatRoom::Read_chatLogs_From_DB_forExport",
    "TalkChatRoom::GetChatLogCountforExport",
    "_CheckTable_chatLogs",
    "_Ensure_chatLogs_indices",
    "TalkChatDB.cpp",
    "RecoverChatDbFile",
    "DbLibraryMigration",
    "sqlite3_key",
    "sqlite3_key_v2",
    "sqlite3_rekey_v2",
    "sqlcipher_export",
    "talk_db_key_store",
    "wrapped_dek_map",
    "ikm-wrap",
    "km-wrap",
    "entropy-bound-kek",
    "Failed to compute HMAC for IKM binding",
    "Failed to compute HMAC for IKM wrapping key",
    "Failed to decrypt IKM",
    "Succeeded to loading the database key store",
    "ATTACH DATABASE",
    "PRAGMA key",
    "PRAGMA kdf_iter",
    "cipher_settings",
    "cipher_page_size",
    "cipher_hmac_algorithm",
    "cipher_kdf_algorithm",
    "Failed to generate new key",
    "Failed to set new key",
    "Failed to set legacy key",
    "Failed to open legacy database",
)
MEMORY_REVERSE_CONTEXT_HINTS = (
    "chatlogs",
    "chatlog",
    "talkchatdb",
    "recoverchatdbfile",
    "read_chatlogs_from_db_forexport",
    "getchatlogcountforexport",
    "checktable_chatlogs",
    "ensure_chatlogs_indices",
    "talkchatdb.cpp",
    "dblibrarymigration",
    "sqlcipher_export",
    "talk_db_key_store",
    "wrapped_dek_map",
    "ikm-wrap",
    "km-wrap",
    "entropy-bound-kek",
    "sqlite3_key",
    "sqlite3_rekey",
    "attach database",
    "pragma",
    "kdf_iter",
    "cipher_page_size",
    "cipher_hmac_algorithm",
    "cipher_kdf_algorithm",
    "tokeninfo",
    "url_image",
    "fci",
    "oci",
    "ocii",
    "mpi",
    ".edb",
    "legacy database",
)
KAKAOTALK_ATTACHMENT_TYPE_LABELS = {
    1: "link",
    2: "image",
    3: "video",
    18: "file",
    26: "reply",
    27: "multi-image",
    72: "alimtalk-link",
    16385: "encrypted-or-unknown",
}
KAKAOTALK_LOCAL_MEDIA_SUFFIXES = {
    ".cng",
    ".gif",
    ".heic",
    ".jpeg",
    ".jpg",
    ".m4a",
    ".m4v",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".wav",
    ".webp",
}


class KakaoTalkDecryptError(ValueError):
    """Raised when KakaoTalk decrypt input is invalid."""


class KakaoTalkKeyStoreParseError(ValueError):
    """Raised when a KakaoTalk key-store sidecar cannot be parsed safely."""


def kakaotalk_windows_split_functional_profile(
    *,
    command: str,
    summary: Mapping[str, object],
    analysis_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Describe the PC KakaoTalk strategy split without overstating decrypt coverage."""

    analysis_summary = analysis_summary or {}
    split_manifest = kakaotalk_windows_split_strategy_manifest(
        command=command,
        summary=summary,
        analysis_summary=analysis_summary,
    )
    chat_database_count = int(summary.get("chat_database_count") or analysis_summary.get("chat_database_count") or 0)
    opened_count = int(
        summary.get("sqlite_open_count")
        or summary.get("opened_database_count")
        or analysis_summary.get("opened_database_count")
        or analysis_summary.get("openable_edb_count")
        or 0
    )
    memory_source_count = int(
        summary.get("memory_source_count") or summary.get("memory_dump_count") or analysis_summary.get("memory_source_count") or 0
    )
    registry_export_count = int(summary.get("registry_export_count") or 0)
    key_store_count = int(
        summary.get("key_store_file_count") or summary.get("parsed_key_store_count") or analysis_summary.get("parsed_key_store_count") or 0
    )
    residue_count = int(
        summary.get("postpatch_message_residue_count")
        or summary.get("postpatch_memory_chat_message_residue_count")
        or analysis_summary.get("postpatch_message_residue_count")
        or 0
    )
    failed_checks: list[str] = []
    if chat_database_count and opened_count == 0:
        failed_checks.append("chatlogs-present-but-not-opened")
    if memory_source_count == 0:
        failed_checks.append("memory-dump-not-attached")
    if registry_export_count == 0:
        failed_checks.append("registry-export-not-attached")
    if key_store_count == 0 and "key-store" in command:
        failed_checks.append("post-bigbang-key-store-not-parsed")
    if not split_manifest.get("manifest_sha256"):
        failed_checks.append("kakaotalk-split-strategy-manifest-not-emitted")
    failed_checks.extend(
        [
            "trusted-kakaotalk-tool-diff-required",
            "known-answer-before-and-after-bigbang-corpus-required",
        ]
    )
    return {
        "batch_id": KAKAOTALK_FUNCTIONAL_EXPANSION_BATCH_ID,
        "item_number": 51,
        "implementation_track": "pc-kakaotalk-split-strategy",
        "command": command,
        "status": "usable-internal-triage-not-commercial-grade",
        "implemented_controls": {
            "legacy_edb_decrypt_workflow": True,
            "post_bigbang_key_store_inventory": key_store_count > 0 or "key-store" in command,
            "memory_sqlcipher_probe_workflow": command in {"kakaotalk-sqlcipher-probe", "kakaotalk-collect-windows"}
            or memory_source_count > 0,
            "registry_windows_edb_correlation_recorded": registry_export_count > 0 or command == "kakaotalk-collect-windows",
            "raw_sensitive_keys_exported": False,
            "separated_modes": [
                "kakaotalk-decrypt",
                "kakaotalk-userdir-bruteforce",
                "kakaotalk-key-store-inspect",
                "kakaotalk-sqlcipher-probe",
                "kakaotalk-memory-carve",
                "kakaotalk-collect-windows",
            ],
            "split_strategy_manifest_hash": split_manifest["manifest_sha256"],
            "split_strategy_manifest_emitted": True,
        },
        "evidence_counts": {
            "chat_database_count": chat_database_count,
            "opened_database_count": opened_count,
            "memory_source_count": memory_source_count,
            "registry_export_count": registry_export_count,
            "key_store_count": key_store_count,
            "message_residue_count": residue_count,
        },
        "split_strategy_manifest": split_manifest,
        "passed_validation_check_ids": [
            "kakaotalk-split-strategy-manifest-emitted",
            "legacy-post-bigbang-mode-separation-recorded",
            "raw-sensitive-key-redaction-recorded",
        ],
        "failed_validation_check_ids": failed_checks,
        "ready_for_court_report": False,
        "next_internal_step": "Attach before/after-BigBang known-answer ZIPs and compare room/message/media counts against a trusted PC KakaoTalk extractor.",
    }


def kakaotalk_windows_split_strategy_manifest(
    *,
    command: str,
    summary: Mapping[str, object],
    analysis_summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    analysis_summary = analysis_summary or {}
    chat_database_count = int(summary.get("chat_database_count") or analysis_summary.get("chat_database_count") or 0)
    opened_count = int(
        summary.get("sqlite_open_count")
        or summary.get("opened_database_count")
        or analysis_summary.get("opened_database_count")
        or analysis_summary.get("openable_edb_count")
        or 0
    )
    registry_export_count = int(summary.get("registry_export_count") or analysis_summary.get("registry_export_count") or 0)
    memory_source_count = int(
        summary.get("memory_source_count") or summary.get("memory_dump_count") or analysis_summary.get("memory_source_count") or 0
    )
    key_store_count = int(
        summary.get("key_store_file_count") or summary.get("parsed_key_store_count") or analysis_summary.get("parsed_key_store_count") or 0
    )
    windows_edb_candidate_count = int(
        summary.get("windows_edb_candidate_count")
        or summary.get("edb_candidate_count")
        or analysis_summary.get("windows_edb_candidate_count")
        or 0
    )
    residue_count = int(
        summary.get("postpatch_message_residue_count")
        or summary.get("postpatch_memory_chat_message_residue_count")
        or analysis_summary.get("postpatch_message_residue_count")
        or 0
    )
    manifest: dict[str, object] = {
        "manifest_version": "kakaotalk-windows-split-strategy-manifest-v1",
        "item_number": 51,
        "batch_id": KAKAOTALK_FUNCTIONAL_EXPANSION_BATCH_ID,
        "command": command,
        "strategy_goal": "Keep legacy EDB decrypt, post-BigBang key-store inventory, memory/registry/Windows.edb correlation, and limitation reporting as separate modes.",
        "mode_statuses": {
            "legacy_edb_decrypt": {
                "implemented": True,
                "active_for_command": command == "kakaotalk-decrypt",
                "chat_database_count": chat_database_count,
                "opened_database_count": opened_count,
                "reporting_boundary": "message content is reportable only after SQLite header validation, source hashes, and trusted extractor/known-answer diff",
            },
            "userdir_bruteforce": {
                "implemented": True,
                "active_for_command": command == "kakaotalk-userdir-bruteforce",
                "reporting_boundary": "UID discovery is an authentication-material candidate and must not be treated as message content",
            },
            "post_bigbang_key_store": {
                "implemented": True,
                "active_for_command": command == "kakaotalk-key-store-inspect",
                "key_store_count": key_store_count,
                "raw_sensitive_keys_exported": False,
                "reporting_boundary": "wrapped DEK/IKM material is inventoried by hash/length only unless a lawful controlled reveal workflow is attached",
            },
            "sqlcipher_probe": {
                "implemented": True,
                "active_for_command": command == "kakaotalk-sqlcipher-probe",
                "opened_database_count": opened_count,
                "residue_count": residue_count,
                "reporting_boundary": "SQLCipher-opened auxiliary stores and memory residues are review pivots until known-answer validated",
            },
            "memory_registry_windows_edb_correlation": {
                "implemented": True,
                "active_for_command": command in {"kakaotalk-memory-carve", "kakaotalk-collect-windows"},
                "memory_source_count": memory_source_count,
                "registry_export_count": registry_export_count,
                "windows_edb_candidate_count": windows_edb_candidate_count,
                "reporting_boundary": "cross-source hits strengthen triage confidence but do not independently decrypt chatLogs",
            },
            "authorized_windows_collection": {
                "implemented": True,
                "active_for_command": command == "kakaotalk-collect-windows",
                "registry_export_count": registry_export_count,
                "memory_source_count": memory_source_count,
                "raw_sensitive_keys_exported": False,
                "reporting_boundary": "collection package preserves source hashes and must be paired with Windows 11 smoke evidence",
            },
        },
        "evidence_counts": {
            "chat_database_count": chat_database_count,
            "opened_database_count": opened_count,
            "registry_export_count": registry_export_count,
            "memory_source_count": memory_source_count,
            "key_store_count": key_store_count,
            "windows_edb_candidate_count": windows_edb_candidate_count,
            "message_residue_count": residue_count,
        },
        "source_viewer_locators": [
            {"section": "summary", "json_pointer": "/summary"},
            {"section": "functional_priority_profile", "json_pointer": "/functional_priority_profile"},
            {"section": "legacy_decrypt_entries", "json_pointer": "/entries"},
            {"section": "post_bigbang_key_store", "json_pointer": "/key_stores"},
            {"section": "sqlcipher_matches", "json_pointer": "/matches"},
            {"section": "memory_carve", "json_pointer": "/postpatch_memory_carve"},
        ],
        "large_case_controls": {
            "zip_member_max_bytes": MAX_ZIP_MEMBER_BYTES,
            "zip_total_uncompressed_max_bytes": MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES,
            "memory_key_material_scan_limit": KEY_MATERIAL_SCAN_LIMIT,
            "memory_message_residue_limit_default": DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
            "raw_values_redacted_by_default": True,
        },
        "commercial_blockers": [
            "before-and-after-bigbang-known-answer-zip-corpus-required",
            "trusted-pc-kakaotalk-extractor-diff-required",
            "windows-11-runtime-smoke-evidence-required",
            "post-bigbang-key-unwrap-and-deleted-store-validation-required",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_kakaotalk_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_kakaotalk_json_sha256(value: Mapping[str, object] | Sequence[object] | str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def run_kakaotalk_windows_collect(
    *,
    output_root: Path,
    kakao_root: Path | None = None,
    include_memory_dump: bool = False,
    analyze: bool = False,
    sqlcipher_bin: str = "sqlcipher",
    timeout_seconds: float = 5.0,
    max_message_residues: int = 1000,
    no_xlsx: bool = False,
) -> dict[str, object]:
    """Collect authorized Windows PC KakaoTalk data into a ZIP and optionally analyze it."""

    output_root = output_root.expanduser().resolve()
    if timeout_seconds <= 0:
        raise KakaoTalkDecryptError("--timeout-seconds must be > 0")
    if max_message_residues < 0:
        raise KakaoTalkDecryptError("--max-message-residues must be >= 0")
    source_root = resolve_windows_kakaotalk_root(kakao_root)
    if not source_root.exists() or not source_root.is_dir():
        raise KakaoTalkDecryptError(f"KakaoTalk root does not exist: {source_root}")

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    case_dir = output_root / f"kakaotalk_collection_{timestamp}"
    collection_dir = case_dir / "collection"
    collected_kakao_root = collection_dir / "KakaoTalk"
    registry_dir = collection_dir / "Registry"
    zip_path = case_dir / f"kakaotalk_collection_{timestamp}.zip"
    report_dir = case_dir / "report"
    output_root.mkdir(parents=True, exist_ok=True)
    collection_dir.mkdir(parents=True, exist_ok=True)

    copy_directory_tree(source_root, collected_kakao_root)
    registry_exports = export_windows_kakaotalk_registry(registry_dir)
    memory_dumps = collect_windows_kakaotalk_memory_dumps(collection_dir) if include_memory_dump else []
    functional_profile = kakaotalk_windows_split_functional_profile(
        command="kakaotalk-collect-windows",
        summary={
            "chat_database_count": len(find_chatlog_databases(source_root)),
            "registry_export_count": len(registry_exports),
            "memory_dump_count": len(memory_dumps),
        },
    )
    metadata = {
        "parser": KAKAOTALK_WINDOWS_COLLECT_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": os.name,
        "source_kakao_root": str(source_root),
        "collected_kakao_root": str(collected_kakao_root),
        "include_memory_dump": include_memory_dump,
        "memory_dump_count": len(memory_dumps),
        "registry_export_count": len(registry_exports),
        "authorization_notice": "Collect only systems and accounts you are authorized to examine.",
        "sensitive_keys_exported": False,
        "functional_priority_profile": functional_profile,
    }
    write_result(metadata, collection_dir / "collection_metadata.json")
    manifest_rows = write_collection_hash_manifest(collection_dir, collection_dir / "hash_manifest.csv")
    create_zip_from_directory(collection_dir, zip_path)

    payload: dict[str, object] = {
        "command": "kakaotalk-collect-windows",
        "parser": KAKAOTALK_WINDOWS_COLLECT_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "summary": {
            "source_kakao_root": str(source_root),
            "case_dir": str(case_dir),
            "collection_dir": str(collection_dir),
            "collection_zip": str(zip_path),
            "hash_manifest_count": len(manifest_rows),
            "registry_export_count": len(registry_exports),
            "memory_dump_count": len(memory_dumps),
            "analyze_requested": analyze,
            "sensitive_keys_exported": False,
            "status": "collected",
        },
        "collection": {
            "zip_path": str(zip_path),
            "metadata_path": str(collection_dir / "collection_metadata.json"),
            "hash_manifest_path": str(collection_dir / "hash_manifest.csv"),
            "registry_exports": registry_exports,
            "memory_dumps": memory_dumps,
        },
        "functional_priority_profile": functional_profile,
    }
    if analyze:
        report_dir.mkdir(parents=True, exist_ok=True)
        export_opened_dir = report_dir / "opened_sqlite"
        analysis = run_kakaotalk_sqlcipher_probe(
            collection_dir,
            output=report_dir / "kakaotalk_probe.json",
            sqlcipher_bin=sqlcipher_bin,
            max_message_residues=max_message_residues,
            include_message_preview=True,
            timeout_seconds=timeout_seconds,
            export_opened_dir=export_opened_dir,
        )
        payload["analysis"] = {
            "report_dir": str(report_dir),
            "probe_json": str(report_dir / "kakaotalk_probe.json"),
            "summary": analysis.get("summary", {}),
            "xlsx_requested": not no_xlsx,
        }
        payload["functional_priority_profile"] = kakaotalk_windows_split_functional_profile(
            command="kakaotalk-collect-windows",
            summary=payload["summary"],
            analysis_summary=analysis.get("summary", {}) if isinstance(analysis.get("summary"), Mapping) else {},
        )
        payload["summary"]["status"] = "collected-and-analyzed"
        payload["summary"]["report_dir"] = str(report_dir)
    return payload


def resolve_windows_kakaotalk_root(kakao_root: Path | None) -> Path:
    if kakao_root is not None:
        return kakao_root.expanduser().resolve()
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return (Path(local_app_data) / "Kakao" / "KakaoTalk").resolve()
    raise KakaoTalkDecryptError("--kakao-root is required outside a Windows user session")


def copy_directory_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob("*"), key=lambda item: str(item).lower()):
        try:
            relative = path.relative_to(source)
        except ValueError:
            continue
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(path, target)
        except OSError:
            continue


def export_windows_kakaotalk_registry(registry_dir: Path) -> list[str]:
    if os.name != "nt":
        return []
    registry_dir.mkdir(parents=True, exist_ok=True)
    exports = []
    for key, filename in (
        (r"HKCU\Software\Kakao\KakaoTalk", "HKCU_Software_Kakao_KakaoTalk.reg"),
        (r"HKCU\Software\Kakao", "HKCU_Software_Kakao.reg"),
    ):
        output = registry_dir / filename
        proc = subprocess.run(
            ["reg.exe", "export", key, str(output), "/y"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode == 0 and output.exists():
            exports.append(str(output.resolve()))
    return exports


def collect_windows_kakaotalk_memory_dumps(destination: Path) -> list[str]:
    if os.name != "nt":
        return []
    tasklist = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq KakaoTalk.exe", "/FO", "CSV", "/NH"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if tasklist.returncode != 0:
        return []
    pids = parse_tasklist_pids(tasklist.stdout)
    dumps = []
    for pid in pids:
        dump_path = destination / f"KakaoTalk_{pid}.DMP"
        proc = subprocess.run(
            ["rundll32.exe", r"C:\Windows\System32\comsvcs.dll,", "MiniDump", str(pid), str(dump_path), "full"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode == 0 and dump_path.exists():
            dumps.append(str(dump_path.resolve()))
    return dumps


def parse_tasklist_pids(output: str) -> list[int]:
    pids = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "INFO:" in line:
            continue
        try:
            row = next(csv.reader([line]))
        except csv.Error:
            continue
        if len(row) < 2:
            continue
        try:
            pids.append(int(str(row[1]).strip()))
        except ValueError:
            continue
    return pids


def write_collection_hash_manifest(root: Path, output: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path == output:
            continue
        try:
            stat = path.stat()
            hashes = compute_hashes(path)
        except OSError:
            continue
        rows.append(
            {
                "relative_path": safe_relative_path(root, path),
                "size": stat.st_size,
                "mtime_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
                "sha256": hashes.get("sha256", ""),
            }
        )
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["relative_path", "size", "mtime_utc", "sha256"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def create_zip_from_directory(source_dir: Path, output_zip: Path) -> None:
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.rglob("*"), key=lambda item: str(item).lower()):
            if path.is_file():
                archive.write(path, path.relative_to(source_dir).as_posix())


class MiniCborDecoder:
    """Small definite-length CBOR decoder for KakaoTalk appstate.dat key stores."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise KakaoTalkKeyStoreParseError("CBOR value is truncated")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def read_length(self, additional_info: int) -> int:
        if additional_info < 24:
            return additional_info
        if additional_info == 24:
            return self.read(1)[0]
        if additional_info == 25:
            return int.from_bytes(self.read(2), "big")
        if additional_info == 26:
            return int.from_bytes(self.read(4), "big")
        if additional_info == 27:
            return int.from_bytes(self.read(8), "big")
        raise KakaoTalkKeyStoreParseError("Indefinite or reserved CBOR length is not supported")

    def decode(self) -> object:
        if self.offset >= len(self.data):
            raise KakaoTalkKeyStoreParseError("CBOR value is missing")
        initial = self.read(1)[0]
        major_type = initial >> 5
        additional_info = initial & 0x1F
        if major_type == 0:
            return self.read_length(additional_info)
        if major_type == 1:
            return -1 - self.read_length(additional_info)
        if major_type == 2:
            return self.read(self.read_length(additional_info))
        if major_type == 3:
            return self.read(self.read_length(additional_info)).decode("utf-8", errors="replace")
        if major_type == 4:
            return [self.decode() for _ in range(self.read_length(additional_info))]
        if major_type == 5:
            return {self.decode(): self.decode() for _ in range(self.read_length(additional_info))}
        if major_type == 7 and additional_info in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[additional_info]
        raise KakaoTalkKeyStoreParseError(f"Unsupported CBOR major type {major_type}")


KAKAOTALK_USERDIR_BRUTEFORCE_C_SOURCE = r"""
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char b64tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64_16(const unsigned char in[16], char out[25]) {
    int j = 0;
    for (int i = 0; i < 15; i += 3) {
        unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[j++] = b64tbl[(v >> 18) & 63];
        out[j++] = b64tbl[(v >> 12) & 63];
        out[j++] = b64tbl[(v >> 6) & 63];
        out[j++] = b64tbl[v & 63];
    }
    unsigned v = in[15] << 16;
    out[j++] = b64tbl[(v >> 18) & 63];
    out[j++] = b64tbl[(v >> 12) & 63];
    out[j++] = '=';
    out[j++] = '=';
    out[j] = 0;
}
static void md5_bytes(const unsigned char *in, size_t len, unsigned char out[16]) {
    CC_MD5(in, (CC_LONG)len, out);
}
static int aes_cbc_pkcs7(
    const unsigned char *plain,
    size_t plain_len,
    const unsigned char key[16],
    const unsigned char iv[16],
    unsigned char *out,
    size_t *out_len
) {
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key,
        16,
        iv,
        plain,
        plain_len,
        out,
        plain_len + 16,
        &moved
    );
    *out_len = moved;
    return st == kCCSuccess;
}
static void hex_lower(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 15];
    }
    out[len * 2] = 0;
}
static int hex_to_bytes20(const char *value, unsigned char out[20]) {
    for (int i = 0; i < 20; i++) {
        char a = value[i * 2];
        char b = value[i * 2 + 1];
        int va = 0;
        int vb = 0;
        if (a >= '0' && a <= '9') va = a - '0';
        else if (a >= 'a' && a <= 'f') va = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') va = a - 'A' + 10;
        else return 0;
        if (b >= '0' && b <= '9') vb = b - '0';
        else if (b >= 'a' && b <= 'f') vb = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') vb = b - 'A' + 10;
        else return 0;
        out[i] = (unsigned char)((va << 4) | vb);
    }
    return 1;
}
int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s pragmas.txt userDirHome targetHex start end\n", argv[0]);
        return 2;
    }
    unsigned char target[20];
    if (!hex_to_bytes20(argv[3], target)) {
        fprintf(stderr, "bad target hex\n");
        return 2;
    }
    uint64_t start = strtoull(argv[4], 0, 10);
    uint64_t end = strtoull(argv[5], 0, 10);
    FILE *pragma_file = fopen(argv[1], "r");
    if (!pragma_file) {
        perror("open pragmas");
        return 2;
    }
    char pragmas[64][256];
    char line[512];
    int pragma_count = 0;
    while (pragma_count < 64 && fgets(line, sizeof(line), pragma_file)) {
        size_t n = strcspn(line, "\r\n");
        line[n] = 0;
        if (n) {
            strncpy(pragmas[pragma_count], line, 255);
            pragmas[pragma_count][255] = 0;
            pragma_count++;
        }
    }
    fclose(pragma_file);
    unsigned char key1[16];
    unsigned char iv1[16];
    char key_b64[25];
    md5_bytes((const unsigned char *)"KAKAOTALK_PC_FOREVER", strlen("KAKAOTALK_PC_FOREVER"), key1);
    b64_16(key1, key_b64);
    md5_bytes((const unsigned char *)key_b64, strlen(key_b64), iv1);
    const char *home = argv[2];
    for (int p = 0; p < pragma_count; p++) {
        unsigned char key2[16];
        unsigned char iv2[16];
        md5_bytes((const unsigned char *)pragmas[p], strlen(pragmas[p]), key2);
        b64_16(key2, key_b64);
        md5_bytes((const unsigned char *)key_b64, strlen(key_b64), iv2);
        for (uint64_t uid = start; uid <= end; uid++) {
            char uid_string[32];
            int uid_len = snprintf(uid_string, sizeof(uid_string), "%llu", (unsigned long long)uid);
            unsigned char encrypted_uid[64];
            size_t encrypted_uid_len = 0;
            if (!aes_cbc_pkcs7((unsigned char *)uid_string, uid_len, key1, iv1, encrypted_uid, &encrypted_uid_len)) {
                return 3;
            }
            char encrypted_uid_hex[129];
            hex_lower(encrypted_uid, encrypted_uid_len, encrypted_uid_hex);
            char second_input[768];
            int second_input_len = snprintf(second_input, sizeof(second_input), "%s\\%s", home, encrypted_uid_hex);
            unsigned char encrypted_second[896];
            size_t encrypted_second_len = 0;
            if (!aes_cbc_pkcs7((unsigned char *)second_input, second_input_len, key2, iv2, encrypted_second, &encrypted_second_len)) {
                return 4;
            }
            unsigned char sha1[20];
            CC_SHA1(encrypted_second, (CC_LONG)encrypted_second_len, sha1);
            if (memcmp(sha1, target, 20) == 0) {
                printf("MATCH pragma_index=%d uid=%llu\n", p, (unsigned long long)uid);
                return 0;
            }
        }
    }
    printf("NO_MATCH %llu %llu pragmas=%d\n", (unsigned long long)start, (unsigned long long)end, pragma_count);
    return 1;
}
"""


def run_kakaotalk_decrypt(
    root: Path,
    *,
    output: Path,
    key_hex: str | None = None,
    iv_hex: str | None = None,
    pragma: str | None = None,
    user_id: str | None = None,
    pragma_key_hex: str | None = None,
    sys_uuid: str | None = None,
    hdd_model: str | None = None,
    hdd_serial: str | None = None,
    key_hex_env: str | None = "RAPIDTRIAGE_KAKAO_KEY_HEX",
    iv_hex_env: str | None = "RAPIDTRIAGE_KAKAO_IV_HEX",
    pragma_env: str | None = "RAPIDTRIAGE_KAKAO_PRAGMA",
    user_id_env: str | None = "RAPIDTRIAGE_KAKAO_USER_ID",
    pragma_key_hex_env: str | None = "RAPIDTRIAGE_KAKAO_PRAGMA_KEY_HEX",
    sys_uuid_env: str | None = "RAPIDTRIAGE_KAKAO_SYS_UUID",
    hdd_model_env: str | None = "RAPIDTRIAGE_KAKAO_HDD_MODEL",
    hdd_serial_env: str | None = "RAPIDTRIAGE_KAKAO_HDD_SERIAL",
    include_message_preview: bool = False,
    write_decrypted: bool = False,
    decrypted_dir: Path | None = None,
    max_databases: int = 0,
    max_messages_per_db: int = 20,
    openssl_bin: str = "openssl",
    postpatch_memory_carve: bool = True,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.exists():
        raise KakaoTalkDecryptError(f"Input root does not exist: {root}")
    if not root.is_dir():
        raise KakaoTalkDecryptError("kakaotalk-decrypt expects an extracted KakaoTalk folder, not a ZIP or image file")
    auth = resolve_decrypt_auth(
        key_hex=key_hex,
        iv_hex=iv_hex,
        pragma=pragma,
        user_id=user_id,
        pragma_key_hex=pragma_key_hex,
        sys_uuid=sys_uuid,
        hdd_model=hdd_model,
        hdd_serial=hdd_serial,
        key_hex_env=key_hex_env,
        iv_hex_env=iv_hex_env,
        pragma_env=pragma_env,
        user_id_env=user_id_env,
        pragma_key_hex_env=pragma_key_hex_env,
        sys_uuid_env=sys_uuid_env,
        hdd_model_env=hdd_model_env,
        hdd_serial_env=hdd_serial_env,
        deviceinfo_root=root,
        openssl_bin=openssl_bin,
    )
    if max_messages_per_db < 0:
        raise KakaoTalkDecryptError("--max-messages-per-db must be >= 0")
    if max_databases < 0:
        raise KakaoTalkDecryptError("--max-databases must be >= 0")

    chat_databases = find_chatlog_databases(root)
    if max_databases:
        chat_databases = chat_databases[:max_databases]
    decrypt_output_dir = (
        decrypted_dir.expanduser().resolve()
        if decrypted_dir is not None
        else output.parent / f"{output.stem}-decrypted"
    )
    if write_decrypted:
        decrypt_output_dir.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, object]] = []
    message_total = 0
    success_count = 0
    sqlite_count = 0
    preview_count = 0
    for db_path in chat_databases:
        entry = analyze_chatlog_database(
            db_path,
            auth=auth,
            include_message_preview=include_message_preview,
            write_decrypted=write_decrypted,
            decrypted_dir=decrypt_output_dir,
            max_messages=max_messages_per_db,
            openssl_bin=openssl_bin,
        )
        entries.append(entry)
        if entry.get("decrypt_status") == "success":
            success_count += 1
        if entry.get("sqlite_status") == "opened":
            sqlite_count += 1
        message_total += int(entry.get("message_row_count") or 0)
        preview_count += len(entry.get("message_previews") or [])

    status_counts = Counter(str(entry.get("decrypt_status") or "unknown") for entry in entries)
    sqlite_status_counts = Counter(str(entry.get("sqlite_status") or "unknown") for entry in entries)
    payload = {
        "command": "kakaotalk-decrypt",
        "parser": KAKAOTALK_DECRYPT_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "output": str(output),
        "authorization_model": {
            "requires_authorized_legal_scope": True,
            "secrets_redacted": True,
            "message_preview_included": include_message_preview,
            "decrypted_sqlite_written": write_decrypted,
            "proprietary_application_key_included": False,
        },
        "auth_material": auth.public_summary(),
        "strategy": {
            "option_1": "legacy-page-aes-cbc",
            "option_1_status": "success" if sqlite_count else "failed",
            "fallback": "postpatch-memory-sqlite-carve",
            "fallback_enabled": postpatch_memory_carve,
        },
        "summary": {
            "chat_database_count": len(chat_databases),
            "decrypt_success_count": success_count,
            "sqlite_open_count": sqlite_count,
            "message_row_count": message_total,
            "message_preview_count": preview_count,
            "decrypt_status_counts": dict(status_counts),
            "sqlite_status_counts": dict(sqlite_status_counts),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": commercial_blockers(auth),
        },
        "entries": entries,
    }
    if postpatch_memory_carve and chat_databases and sqlite_count == 0:
        payload["postpatch_memory_carve"] = build_kakaotalk_memory_carve_payload(
            root=root,
            output=output.parent / f"{output.stem}-memory-carve.json",
            carve_dir=None,
            max_hits=DEFAULT_MEMORY_SQLITE_MAX_HITS,
            max_carve_bytes=DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
            include_row_preview=False,
            max_rows_per_table=0,
            max_message_residues=max_messages_per_db,
            include_message_preview=include_message_preview,
            write_carves=False,
            command="kakaotalk-decrypt-postpatch-memory-carve",
        )
        payload["summary"]["postpatch_memory_carve_sqlite_header_count"] = payload["postpatch_memory_carve"]["summary"][
            "sqlite_header_count"
        ]
        payload["summary"]["postpatch_memory_carve_database_count"] = payload["postpatch_memory_carve"]["summary"][
            "carved_database_count"
        ]
        payload["summary"]["postpatch_memory_carve_chat_relevant_table_count"] = payload["postpatch_memory_carve"][
            "summary"
        ]["chat_relevant_table_count"]
        payload["summary"]["postpatch_memory_chat_message_residue_count"] = payload["postpatch_memory_carve"][
            "summary"
        ]["chat_message_residue_count"]
        payload["summary"]["postpatch_memory_message_content_reportable"] = payload["postpatch_memory_carve"]["summary"][
            "message_content_reportable"
        ]
    payload["functional_priority_profile"] = kakaotalk_windows_split_functional_profile(
        command="kakaotalk-decrypt",
        summary=payload["summary"],
    )
    write_result(payload, output)
    return payload


def run_kakaotalk_memory_carve(
    root: Path,
    *,
    output: Path,
    carve_dir: Path | None = None,
    max_hits: int = DEFAULT_MEMORY_SQLITE_MAX_HITS,
    max_carve_bytes: int = DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
    include_row_preview: bool = False,
    max_rows_per_table: int = 3,
    max_message_residues: int = DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
    include_message_preview: bool | None = None,
    write_carves: bool = False,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.exists():
        raise KakaoTalkDecryptError(f"Input root does not exist: {root}")
    if max_hits < 0:
        raise KakaoTalkDecryptError("--max-hits must be >= 0")
    if max_carve_bytes < PAGE_SIZE:
        raise KakaoTalkDecryptError(f"--max-carve-bytes must be >= {PAGE_SIZE}")
    if max_rows_per_table < 0:
        raise KakaoTalkDecryptError("--max-rows-per-table must be >= 0")
    if max_message_residues < 0:
        raise KakaoTalkDecryptError("--max-message-residues must be >= 0")
    resolved_carve_dir = (
        carve_dir.expanduser().resolve()
        if carve_dir is not None
        else output.parent / f"{output.stem}-carves"
    )
    if root.is_file():
        if root.suffix.lower() != ".zip":
            raise KakaoTalkDecryptError("kakaotalk-memory-carve expects an extracted KakaoTalk folder or ZIP archive")
        with tempfile.TemporaryDirectory(prefix="rapidtriage-kakao-zip-") as tmp_dir:
            extracted_root = extract_zip_archive_safely(root, Path(tmp_dir))
            payload = build_kakaotalk_memory_carve_payload(
                root=extracted_root,
                output=output,
                carve_dir=resolved_carve_dir,
                max_hits=max_hits,
                max_carve_bytes=max_carve_bytes,
                include_row_preview=include_row_preview,
                max_rows_per_table=max_rows_per_table,
                max_message_residues=max_message_residues,
                include_message_preview=include_row_preview if include_message_preview is None else include_message_preview,
                write_carves=write_carves,
                command="kakaotalk-memory-carve",
            )
            payload["input"] = {
                "source_path": str(root),
                "source_type": "zip",
                "temporary_extraction": True,
                "zip_sha256": compute_hashes(root).get("sha256", ""),
            }
            write_result(payload, output)
            return payload
    if not root.is_dir():
        raise KakaoTalkDecryptError("kakaotalk-memory-carve expects an extracted KakaoTalk folder or ZIP archive")
    payload = build_kakaotalk_memory_carve_payload(
        root=root,
        output=output,
        carve_dir=resolved_carve_dir,
        max_hits=max_hits,
        max_carve_bytes=max_carve_bytes,
        include_row_preview=include_row_preview,
        max_rows_per_table=max_rows_per_table,
        max_message_residues=max_message_residues,
        include_message_preview=include_row_preview if include_message_preview is None else include_message_preview,
        write_carves=write_carves,
        command="kakaotalk-memory-carve",
    )
    payload["input"] = {
        "source_path": str(root),
        "source_type": "directory",
        "temporary_extraction": False,
    }
    write_result(payload, output)
    return payload


def extract_zip_archive_safely(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()
    try:
        with zipfile.ZipFile(archive) as zf:
            total_uncompressed = 0
            for member in zf.infolist():
                if member.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise KakaoTalkDecryptError(f"ZIP member is too large: {member.filename}")
                total_uncompressed += member.file_size
                if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
                    raise KakaoTalkDecryptError("ZIP archive expands beyond the safe uncompressed size limit")
                if member.compress_size > 0 and member.file_size / member.compress_size > MAX_ZIP_COMPRESSION_RATIO:
                    raise KakaoTalkDecryptError(f"ZIP member compression ratio is suspicious: {member.filename}")
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise KakaoTalkDecryptError(f"ZIP symbolic links are not extracted: {member.filename}")
                target = (destination_root / member.filename).resolve()
                if target != destination_root and destination_root not in target.parents:
                    raise KakaoTalkDecryptError(f"Unsafe ZIP member path: {member.filename}")
                try:
                    _ = zf.extract(member, destination_root)
                except PermissionError as exc:
                    if _is_ignorable_windows_short_name_alias(member, target):
                        continue
                    raise KakaoTalkDecryptError(f"Could not extract ZIP member: {member.filename}") from exc
    except zipfile.BadZipFile as exc:
        raise KakaoTalkDecryptError(f"Invalid ZIP archive: {archive}") from exc
    return destination_root


def _is_ignorable_windows_short_name_alias(member: zipfile.ZipInfo, target: Path) -> bool:
    if member.is_dir() or member.file_size != 0:
        return False
    name = Path(member.filename).name
    if not re.fullmatch(r"[^./\\]{1,6}~\d+", name):
        return False
    parent = target.parent
    if not parent.exists():
        return False
    prefix = name.split("~", 1)[0].lower()
    return any(child.is_dir() and child.name.lower().startswith(prefix) for child in parent.iterdir())


def run_kakaotalk_sqlcipher_probe(
    root: Path,
    *,
    output: Path,
    sqlcipher_bin: str = "sqlcipher",
    max_keys: int = DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT,
    max_databases: int = 0,
    max_message_residues: int = DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
    include_message_preview: bool = False,
    timeout_seconds: float = 2.0,
    export_opened_dir: Path | None = None,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise KakaoTalkDecryptError("kakaotalk-sqlcipher-probe expects an extracted KakaoTalk folder")
    if max_keys < 0:
        raise KakaoTalkDecryptError("--max-keys must be >= 0")
    if max_databases < 0:
        raise KakaoTalkDecryptError("--max-databases must be >= 0")
    if max_message_residues < 0:
        raise KakaoTalkDecryptError("--max-message-residues must be >= 0")
    if timeout_seconds <= 0:
        raise KakaoTalkDecryptError("--timeout-seconds must be > 0")
    resolved_export_dir = export_opened_dir.expanduser().resolve() if export_opened_dir is not None else None
    if resolved_export_dir is not None:
        resolved_export_dir.mkdir(parents=True, exist_ok=True)

    sqlcipher_path = shutil.which(sqlcipher_bin)
    sources = find_memory_dump_candidates(root)
    chat_databases = find_chatlog_databases(root)
    if max_databases:
        chat_databases = chat_databases[:max_databases]
    key_candidates = collect_sqlcipher_key_literals_from_memory(sources, max_keys=max_keys)
    edb_databases = find_kakaotalk_edb_databases(root)
    payload: dict[str, object] = {
        "command": "kakaotalk-sqlcipher-probe",
        "parser": KAKAOTALK_MEMORY_CARVE_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "output": str(output),
        "authorization_model": {
            "requires_authorized_legal_scope": True,
            "raw_keys_redacted": True,
            "original_edb_untouched": True,
            "plaintext_exports_requested": resolved_export_dir is not None,
        },
        "parameters": {
            "sqlcipher_bin": sqlcipher_bin,
            "max_keys": max_keys,
            "max_databases": max_databases,
            "max_message_residues": max_message_residues,
            "include_message_preview": include_message_preview,
            "timeout_seconds": timeout_seconds,
            "export_opened_dir": str(resolved_export_dir) if resolved_export_dir is not None else "",
        },
        "summary": {
            "memory_source_count": len(sources),
            "chat_database_count": len(chat_databases),
            "edb_database_count": len(edb_databases),
            "key_candidate_count": len(key_candidates),
            "variant_count": 0,
            "probe_attempt_count": 0,
            "opened_database_count": 0,
            "openable_edb_count": 0,
            "exported_edb_count": 0,
            "postpatch_chat_room_preview_count": 0,
            "postpatch_message_residue_count": 0,
            "postpatch_room_evidence_count": 0,
            "postpatch_v2_derived_key_count": 0,
            "postpatch_v2_derived_chat_key_count": 0,
            "postpatch_v2_derived_chat_match_count": 0,
            "postpatch_v2_exported_chat_message_row_count": 0,
            "postpatch_v2_exported_chat_message_preview_count": 0,
            "status": "sqlcipher-not-found" if sqlcipher_path is None else "not-run",
        },
        "key_candidates": [redact_sqlcipher_key_candidate(candidate) for candidate in key_candidates],
        "matches": [],
        "openable_edbs": [],
        "errors": [],
    }
    payload["functional_priority_profile"] = kakaotalk_windows_split_functional_profile(
        command="kakaotalk-sqlcipher-probe",
        summary=payload["summary"],
    )
    if sqlcipher_path is None:
        payload["errors"] = [f"SQLCipher binary was not found: {sqlcipher_bin}"]
        write_result(payload, output)
        return payload

    variants = build_sqlcipher_key_probe_variants(key_candidates)
    payload["summary"]["variant_count"] = len(variants)
    openable_edbs = match_sqlcipher_literals_to_edb_headers(root, edb_databases, variants)
    exported_count = 0
    if resolved_export_dir is not None:
        for match in openable_edbs:
            database = Path(str(match["database"]))
            export_name = safe_export_name(root, database)
            export_path = resolved_export_dir / f"{export_name}.sqlite"
            export_result = export_sqlcipher_database(
                sqlcipher_path,
                database,
                key_hex=str(match["key_hex"]),
                export_path=export_path,
                timeout_seconds=timeout_seconds,
            )
            if export_result["exported"]:
                exported_count += 1
            match["export"] = export_result
        postpatch_chat_rooms = extract_postpatch_chat_room_previews(
            [Path(str(match.get("export", {}).get("export_path", ""))) for match in openable_edbs],
            root=root,
        )
        payload["postpatch_chat_room_previews"] = postpatch_chat_rooms
        payload["summary"]["postpatch_chat_room_preview_count"] = len(postpatch_chat_rooms)
    else:
        postpatch_chat_rooms = []
    postpatch_message_residues = collect_kakaotalk_memory_message_residues(
        sources,
        max_messages=max_message_residues,
        include_message_preview=include_message_preview,
    )
    payload["postpatch_message_residues"] = postpatch_message_residues
    payload["postpatch_room_evidence"] = build_kakaotalk_postpatch_room_evidence(
        room_previews=postpatch_chat_rooms,
        message_residues=postpatch_message_residues,
    )
    payload["summary"]["postpatch_message_residue_count"] = len(postpatch_message_residues)
    payload["summary"]["postpatch_room_evidence_count"] = len(payload["postpatch_room_evidence"])
    payload["summary"]["openable_edb_count"] = len(openable_edbs)
    payload["summary"]["exported_edb_count"] = exported_count
    payload["openable_edbs"] = [redact_openable_edb_match(match) for match in openable_edbs]
    postpatch_v2_derived_keys = derive_kakaotalk_postpatch_v2_dek_candidates(
        root=root,
        memory_sources=sources,
        include_raw=True,
    )
    payload["postpatch_v2_derived_keys"] = [
        redact_postpatch_v2_derived_key(candidate) for candidate in postpatch_v2_derived_keys
    ]
    payload["summary"]["postpatch_v2_derived_key_count"] = len(postpatch_v2_derived_keys)
    payload["summary"]["postpatch_v2_derived_chat_key_count"] = sum(
        1 for candidate in postpatch_v2_derived_keys if candidate.get("role") == "chatlog"
    )
    derived_by_database = {
        str(candidate.get("database") or ""): candidate
        for candidate in postpatch_v2_derived_keys
        if candidate.get("database") and candidate.get("key_hex")
    }
    matches: list[dict[str, object]] = []
    attempt_count = 0
    compat_versions = (4, 3, 2, 1)
    for db_path in chat_databases:
        with tempfile.TemporaryDirectory(prefix="rapidtriage-sqlcipher-probe-") as temp_dir:
            temp_db = Path(temp_dir) / db_path.name
            shutil.copy2(db_path, temp_db)
            derived_candidate = derived_by_database.get(str(db_path.resolve()))
            if derived_candidate is not None:
                derived_key_hex = str(derived_candidate.get("key_hex") or "")
                try:
                    database_salt_hex = db_path.read_bytes()[:16].hex()
                except OSError:
                    database_salt_hex = ""
                if len(derived_key_hex) == 64 and len(database_salt_hex) == 32:
                    for compatibility in compat_versions:
                        attempt_count += 1
                        probe = probe_sqlcipher_database(
                            sqlcipher_path,
                            temp_db,
                            key_hex=derived_key_hex + database_salt_hex,
                            variant="first-32-byte-raw-key-with-salt-pragma",
                            compatibility=compatibility,
                            timeout_seconds=timeout_seconds,
                        )
                        if probe.get("opened"):
                            match: dict[str, object] = {
                                "database": str(db_path.resolve()),
                                "database_name": db_path.name,
                                "compatibility": compatibility,
                                "variant": "postpatch-v2-derived-wrapped-dek",
                                "schema_count": probe["schema_count"],
                                "key_candidate_sha256": derived_candidate.get("derived_key_sha256", ""),
                                "raw_key_sha256": derived_candidate.get("derived_key_sha256", ""),
                                "wrapped_dek_sha256": derived_candidate.get("wrapped_dek_sha256", ""),
                                "validation": {
                                    "source": "kakaotalk-postpatch-v2-derived-dek",
                                    "algorithm": derived_candidate.get("algorithm", ""),
                                    "requires_manual_validation": True,
                                    "raw_key_redacted": True,
                                },
                            }
                            if resolved_export_dir is not None:
                                export_name = safe_export_name(root, db_path)
                                export_path = resolved_export_dir / f"{export_name}.sqlite"
                                match["export"] = export_sqlcipher_database(
                                    sqlcipher_path,
                                    db_path,
                                    key_hex=derived_key_hex + database_salt_hex,
                                    export_path=export_path,
                                    timeout_seconds=timeout_seconds,
                                )
                            matches.append(match)
                            break
                    if any(match["database_name"] == db_path.name for match in matches):
                        continue
            for variant in variants:
                for compatibility in compat_versions:
                    attempt_count += 1
                    probe = probe_sqlcipher_database(
                        sqlcipher_path,
                        temp_db,
                        key_hex=str(variant["key_hex"]),
                        variant=str(variant["variant"]),
                        compatibility=compatibility,
                        timeout_seconds=timeout_seconds,
                    )
                    if probe.get("opened"):
                        matches.append(
                            {
                                "database": str(db_path.resolve()),
                                "database_name": db_path.name,
                                "compatibility": compatibility,
                                "variant": variant["variant"],
                                "schema_count": probe["schema_count"],
                                "key_candidate_sha256": variant["candidate_sha256"],
                                "raw_key_sha256": variant["raw_key_sha256"],
                                "validation": {
                                    "source": "sqlcipher-probe-temp-copy",
                                    "requires_manual_validation": True,
                                    "raw_key_redacted": True,
                                },
                            }
                        )
                        break
                if any(match["database_name"] == db_path.name for match in matches):
                    break
    exported_chat_message_rows = 0
    exported_chat_message_previews = 0
    max_export_preview_messages = min(max_message_residues or DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT, 100)
    for match in matches:
        export_info = match.get("export")
        if not isinstance(export_info, Mapping) or not export_info.get("exported"):
            continue
        export_path = Path(str(export_info.get("export_path") or ""))
        if not export_path.exists():
            continue
        try:
            sqlite_inspection = inspect_decrypted_sqlite(
                export_path,
                include_message_preview=include_message_preview,
                max_messages=max_export_preview_messages,
            )
        except (OSError, sqlite3.DatabaseError):
            continue
        match["sqlite_inspection"] = sqlite_inspection
        exported_chat_message_rows += int(sqlite_inspection.get("message_row_count") or 0)
        exported_chat_message_previews += len(sqlite_inspection.get("message_previews") or [])
    exported_sqlites = [
        Path(str(match.get("export", {}).get("export_path") or ""))
        for match in matches
        if isinstance(match.get("export"), Mapping) and match.get("export", {}).get("exported")
    ]
    media_inventory = build_kakaotalk_media_inventory(
        root=root,
        exported_sqlite_paths=exported_sqlites,
        include_message_preview=include_message_preview,
    )

    payload["summary"]["probe_attempt_count"] = attempt_count
    payload["summary"]["opened_database_count"] = len({match["database_name"] for match in matches})
    payload["summary"]["postpatch_v2_derived_chat_match_count"] = sum(
        1 for match in matches if match.get("variant") == "postpatch-v2-derived-wrapped-dek"
    )
    payload["summary"]["postpatch_v2_exported_chat_message_row_count"] = exported_chat_message_rows
    payload["summary"]["postpatch_v2_exported_chat_message_preview_count"] = exported_chat_message_previews
    payload["summary"]["postpatch_media_attachment_count"] = media_inventory["summary"]["attachment_count"]
    payload["summary"]["postpatch_media_local_file_count"] = media_inventory["summary"]["local_media_file_count"]
    payload["summary"]["postpatch_media_local_match_count"] = media_inventory["summary"]["local_match_count"]
    payload["postpatch_media_inventory"] = media_inventory
    payload["summary"]["status"] = "matched" if matches else "no-chatlog-match"
    payload["matches"] = matches
    payload["functional_priority_profile"] = kakaotalk_windows_split_functional_profile(
        command="kakaotalk-sqlcipher-probe",
        summary=payload["summary"],
    )
    write_result(payload, output)
    return payload


def run_kakaotalk_key_store_inspect(
    root: Path,
    *,
    output: Path,
    max_memory_sources: int = 2,
) -> dict[str, object]:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise KakaoTalkDecryptError("kakaotalk-key-store-inspect expects an extracted KakaoTalk folder")
    if max_memory_sources < 0:
        raise KakaoTalkDecryptError("--max-memory-sources must be >= 0")

    key_store_files = find_kakaotalk_key_store_files(root)
    chat_databases = find_chatlog_databases(root)
    memory_sources = find_memory_dump_candidates(root)
    inspected_memory_sources = memory_sources[:max_memory_sources] if max_memory_sources else []
    sqlcipher_key_candidates = (
        collect_sqlcipher_key_literals_from_memory(inspected_memory_sources, max_keys=0)
        if inspected_memory_sources
        else []
    )
    openable_edbs = (
        match_sqlcipher_literals_to_edb_headers(
            root,
            find_kakaotalk_edb_databases(root),
            build_sqlcipher_key_probe_variants(sqlcipher_key_candidates),
        )
        if sqlcipher_key_candidates
        else []
    )
    entries: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    for key_store_path in key_store_files:
        try:
            entries.append(
                inspect_kakaotalk_key_store_file(
                    key_store_path,
                    root=root,
                    chat_databases=chat_databases,
                    memory_sources=inspected_memory_sources,
                )
            )
        except (OSError, KakaoTalkKeyStoreParseError, ValueError) as exc:
            errors.append(
                {
                    "path": str(key_store_path.resolve()),
                    "error": str(exc),
                    "validation": {
                        "source": "kakaotalk-appstate-key-store-parse",
                        "requires_manual_validation": True,
                    },
                }
            )

    wrapped_entries = [
        wrapped
        for entry in entries
        for wrapped in entry.get("wrapped_dek_entries", [])
        if isinstance(wrapped, Mapping)
    ]
    chatlog_wrapped = [entry for entry in wrapped_entries if entry.get("role") == "chatlog"]
    matched_chatlogs = {str(entry.get("relative_path_normalized") or "") for entry in chatlog_wrapped if entry.get("matched_file")}
    known_answer_pairs = build_kakaotalk_postpatch_known_answer_pairs(
        key_stores=entries,
        openable_edbs=openable_edbs,
    )
    runtime_node_count = sum(
        len(entry.get("runtime_key_store_nodes", []))
        for entry in entries
        if isinstance(entry.get("runtime_key_store_nodes"), list)
    )
    info_prefixes = sorted({str(entry.get("info_prefix") or "") for entry in entries if entry.get("info_prefix")})
    postpatch_ikm_candidates = extract_kakaotalk_postpatch_ikm_candidates(
        root=root,
        memory_sources=inspected_memory_sources,
    )
    payload: dict[str, object] = {
        "command": "kakaotalk-key-store-inspect",
        "parser": KAKAOTALK_KEY_STORE_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "output": str(output),
        "authorization_model": {
            "requires_authorized_legal_scope": True,
            "raw_wrapped_deks_redacted": True,
            "unwrapped_deks_not_exported": True,
            "original_edb_untouched": True,
        },
        "parameters": {
            "max_memory_sources": max_memory_sources,
        },
        "summary": {
            "key_store_file_count": len(key_store_files),
            "parsed_key_store_count": len(entries),
            "parse_error_count": len(errors),
            "wrapped_dek_entry_count": len(wrapped_entries),
            "chatlog_wrapped_dek_entry_count": len(chatlog_wrapped),
            "chat_database_count": len(chat_databases),
            "chat_database_key_store_match_count": len(matched_chatlogs),
            "memory_source_count": len(memory_sources),
            "inspected_memory_source_count": len(inspected_memory_sources),
            "postpatch_sqlcipher_literal_key_count": len(sqlcipher_key_candidates),
            "postpatch_openable_non_chat_edb_count": len(openable_edbs),
            "postpatch_known_answer_pair_count": len(known_answer_pairs),
            "postpatch_runtime_key_store_node_count": runtime_node_count,
            "postpatch_ikm_candidate_count": len(postpatch_ikm_candidates),
            "postpatch_v2_entropy_bound_kek_required": "v2:" in info_prefixes,
            "method_status": "key-store-mapped" if chatlog_wrapped else "key-store-not-found",
            "direct_decryption_ready": False,
            "commercial_grade_ready": False,
            "next_step": "Finish the v2 entropy-bound KEK branch, unwrap per-database DEKs, then validate SQLCipher opening against known-answer chatLogs.",
        },
        "key_stores": entries,
        "postpatch_known_answer_pairs": known_answer_pairs,
        "postpatch_openable_edbs": [redact_openable_edb_match(match) for match in openable_edbs],
        "postpatch_ikm_candidates": postpatch_ikm_candidates,
        "errors": errors,
        "validation": {
            "finding": "Post-BigBang PC KakaoTalk appstate.dat uses a CBOR key store with per-EDB wrapped DEKs.",
            "observed_info_prefixes": info_prefixes,
            "wrapped_dek_length_observed": sorted({int(entry.get("wrapped_dek_length") or 0) for entry in wrapped_entries}),
            "raw_secret_handling": "Only lengths and SHA-256 digests are exported; wrapped key bytes and any recovered DEKs remain redacted.",
            "postpatch_v2_note": "The observed v2: key-store path uses KakaoTalk's entropy-bound KEK branch; legacy pragma/userId AES-CBC derivation is not sufficient for these chatLogs.",
            "blockers": [
                "v2-entropy-bound-kek-derivation-not-yet-implemented",
                "wrapped-dek-unwrapping-not-validated",
                "postpatch-chatlogs-known-answer-corpus-required",
            ],
        },
    }
    payload["functional_priority_profile"] = kakaotalk_windows_split_functional_profile(
        command="kakaotalk-key-store-inspect",
        summary=payload["summary"],
    )
    write_result(payload, output)
    return payload


def find_kakaotalk_key_store_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in sorted(root.rglob("appstate.dat*"), key=lambda item: str(item).lower()):
        if path.is_file() and path.name.lower() in {"appstate.dat", "appstate.dat.backup"}:
            candidates.append(path)
    return candidates


def extract_kakaotalk_postpatch_ikm_candidates(
    *,
    root: Path,
    memory_sources: Sequence[Path],
    max_entropy_hits_per_source: int = 128,
    max_pointer_hits_per_entropy: int = 64,
) -> list[dict[str, object]]:
    """Recover and validate post-BigBang IKM candidates without exporting secrets.

    Current PC KakaoTalk builds an IKM wrapping key from a 32-byte in-memory object
    key and an entropy string, then AES-KW unwraps profile.dat. The resulting IKM
    is an intermediate keying material needed for the newer wrapped-DEK flow, but
    it is sensitive, so this function only reports hashes and provenance.
    """

    profiles = [
        path
        for path in sorted(root.rglob("profile.dat"), key=lambda item: str(item).lower())
        if path.is_file() and path.stat().st_size >= 24 and path.stat().st_size % 8 == 0
    ]
    if not profiles or not memory_sources:
        return []
    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]
    except ImportError:
        return [
            {
                "parser": KAKAOTALK_POSTPATCH_IKM_VERSION,
                "status": "dependency-missing",
                "dependency": "pycryptodome",
                "validation": {
                    "source": "kakaotalk-postpatch-ikm-memory-probe",
                    "requires_manual_validation": True,
                    "raw_secrets_redacted": True,
                },
            }
        ]

    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for source in memory_sources:
        try:
            data = source.read_bytes()
        except OSError:
            continue
        ranges = build_memory_address_ranges(data)
        if not ranges:
            continue
        source_candidates = extract_kakaotalk_postpatch_ikm_candidates_from_blob(
            data,
            source=source,
            profiles=profiles,
            ranges=ranges,
            max_entropy_hits=max_entropy_hits_per_source,
            max_pointer_hits_per_entropy=max_pointer_hits_per_entropy,
            aes_module=AES,
        )
        for candidate in source_candidates:
            key = (
                str(candidate.get("source_path") or ""),
                int(candidate.get("entropy_source_offset") or 0),
                str(candidate.get("object_candidate_va") or ""),
                str(candidate.get("ikm_sha256") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)
    return candidates


def extract_kakaotalk_postpatch_ikm_candidates_from_blob(
    data: bytes,
    *,
    source: Path,
    profiles: Sequence[Path],
    ranges: Sequence[tuple[int, int, int]],
    max_entropy_hits: int,
    max_pointer_hits_per_entropy: int,
    aes_module: object,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    entropy_hits = find_kakaotalk_postpatch_entropy_candidates(data, max_hits=max_entropy_hits)
    pointer_lookup: dict[int, tuple[int, int, bytes]] = {}
    for entropy_offset, entropy in entropy_hits:
        entropy_va = mapped_offset_to_va(entropy_offset, ranges)
        if entropy_va is not None:
            pointer_lookup[entropy_va] = (entropy_offset, entropy_va, entropy)
    if not pointer_lookup:
        return candidates

    pointer_hit_counts: Counter[int] = Counter()
    for pointer_offset, pointed_va in find_aligned_qword_pointer_offsets(data, pointer_lookup.keys()):
        if pointer_hit_counts[pointed_va] >= max_pointer_hits_per_entropy:
            continue
        pointer_hit_counts[pointed_va] += 1
        entropy_offset, entropy_va, entropy = pointer_lookup[pointed_va]
        pointer_va = mapped_offset_to_va(pointer_offset, ranges)
        if pointer_va is None:
            continue
        for object_pointer_delta in (0x88,):
            object_va = pointer_va - object_pointer_delta
            object_key = read_mapped_va(data, ranges, object_va + 0x68, 32)
            if not object_key or object_key == b"\x00" * 32:
                continue
            ikm_wrap_kek = hmac.new(object_key, entropy + b"ikm-wrap", hashlib.sha256).digest()
            for profile in profiles:
                try:
                    wrapped_profile = profile.read_bytes()
                except OSError:
                    continue
                try:
                    ikm = aes_module.new(ikm_wrap_kek, aes_module.MODE_KW).unseal(wrapped_profile)
                except (ValueError, KeyError):
                    continue
                if len(ikm) != 32:
                    continue
                candidates.append(
                    {
                        "parser": KAKAOTALK_POSTPATCH_IKM_VERSION,
                        "status": "ikm-unwrapped",
                        "source_path": str(source.resolve()),
                        "source_size": len(data),
                        "source_sha256": hashlib.sha256(data).hexdigest(),
                        "profile_path": str(profile.resolve()),
                        "profile_sha256": compute_hashes(profile).get("sha256", ""),
                        "entropy_source_offset": entropy_offset,
                        "entropy_va": f"0x{entropy_va:x}",
                        "entropy_length": len(entropy),
                        "entropy_sha256": hashlib.sha256(entropy).hexdigest(),
                        "entropy_pointer_source_offset": pointer_offset,
                        "entropy_pointer_va": f"0x{pointer_va:x}",
                        "object_candidate_va": f"0x{object_va:x}",
                        "object_pointer_delta": object_pointer_delta,
                        "object_key_sha256": hashlib.sha256(object_key).hexdigest(),
                        "ikm_length": len(ikm),
                        "ikm_sha256": hashlib.sha256(ikm).hexdigest(),
                        "validation": {
                            "source": "kakaotalk-postpatch-profile-ikm-aes-key-wrap",
                            "algorithm": "HMAC-SHA256(object_key, entropy || ikm-wrap) then AES-KW unwrap(profile.dat)",
                            "raw_secrets_redacted": True,
                            "requires_manual_validation": True,
                            "direct_chatlog_decryption_ready": False,
                        },
                    }
                )
    return candidates


def derive_kakaotalk_postpatch_v2_dek_candidates(
    *,
    root: Path,
    memory_sources: Sequence[Path],
    include_raw: bool = False,
) -> list[dict[str, object]]:
    """Derive post-BigBang v2 per-database SQLCipher keys from appstate/profile.

    Observed KakaoTalk v2 flow:
    1. HMAC-SHA256(object_key, entropy || "ikm-wrap") unwraps profile.dat to IKM.
    2. HMAC-SHA256(object_key, IKM || "entropy-bound-kek") binds the IKM to the
       runtime object.
    3. HKDF-SHA256(bound_ikm, salt=appstate.salt, info=info_prefix + backslash path)
       derives the AES-KW KEK for each wrapped DEK.
    """

    key_store_files = [path for path in find_kakaotalk_key_store_files(root) if path.name.lower() == "appstate.dat"]
    if not key_store_files or not memory_sources:
        return []
    try:
        from Crypto.Cipher import AES  # type: ignore[import-not-found]
        from Crypto.Hash import SHA256  # type: ignore[import-not-found]
        from Crypto.Protocol.KDF import HKDF  # type: ignore[import-not-found]
    except ImportError:
        return []

    profiles = [
        path
        for path in sorted(root.rglob("profile.dat"), key=lambda item: str(item).lower())
        if path.is_file() and path.stat().st_size >= 24 and path.stat().st_size % 8 == 0
    ]
    if not profiles:
        return []

    file_index = build_kakaotalk_relative_file_index(root)
    chatlog_names = {path.name.lower() for path in find_chatlog_databases(root)}
    materials: list[dict[str, object]] = []
    seen_materials: set[tuple[str, str, str]] = set()
    for source in memory_sources:
        try:
            data = source.read_bytes()
        except OSError:
            continue
        ranges = build_memory_address_ranges(data)
        source_materials = extract_kakaotalk_postpatch_v2_materials_from_blob(
            data,
            source=source,
            profiles=profiles,
            ranges=ranges,
            aes_module=AES,
        )
        for material in source_materials:
            material_key = (
                str(material.get("source_path") or ""),
                str(material.get("object_candidate_va") or ""),
                str(material.get("ikm_sha256") or ""),
            )
            if material_key in seen_materials:
                continue
            seen_materials.add(material_key)
            materials.append(material)

    candidates: list[dict[str, object]] = []
    seen_candidates: set[tuple[str, str, str]] = set()
    for key_store_path in key_store_files:
        try:
            decoded = MiniCborDecoder(key_store_path.read_bytes()).decode()
        except (OSError, KakaoTalkKeyStoreParseError, ValueError):
            continue
        if not isinstance(decoded, dict):
            continue
        info_prefix = cbor_byte_array_to_text(decoded.get("info_prefix"))
        if info_prefix != "v2:":
            continue
        app_salt = cbor_byte_array_to_bytes(decoded.get("salt"))
        if len(app_salt) != 32:
            continue
        wrapped_dek_map = decoded.get("wrapped_dek_map")
        if not isinstance(wrapped_dek_map, list):
            continue
        for material in materials:
            object_key = material.get("object_key")
            ikm = material.get("ikm")
            if not isinstance(object_key, bytes) or not isinstance(ikm, bytes):
                continue
            bound_ikm = hmac.new(object_key, ikm + b"entropy-bound-kek", hashlib.sha256).digest()
            for index, pair in enumerate(wrapped_dek_map):
                if not isinstance(pair, list) or len(pair) != 2:
                    continue
                relative_path = cbor_byte_array_to_text(pair[0])
                wrapped_dek = cbor_byte_array_to_bytes(pair[1])
                if len(wrapped_dek) != 40:
                    continue
                normalized_path = normalize_kakaotalk_relative_path(relative_path)
                backslash_path = normalized_path.replace("/", "\\")
                info = info_prefix.encode("utf-8") + backslash_path.encode("utf-8")
                try:
                    kek = HKDF(bound_ikm, 32, app_salt, SHA256, context=info)
                    derived_key = AES.new(kek, AES.MODE_KW).unseal(wrapped_dek)
                except (ValueError, KeyError):
                    continue
                if len(derived_key) != 32:
                    continue
                matched_file = file_index.get(normalized_path.lower())
                is_chatlog = Path(normalized_path).name.lower() in chatlog_names or bool(
                    CHATLOG_PATTERN.fullmatch(Path(normalized_path).name)
                )
                candidate_key = (
                    str(key_store_path.resolve()),
                    normalized_path.lower(),
                    hashlib.sha256(derived_key).hexdigest(),
                )
                if candidate_key in seen_candidates:
                    continue
                seen_candidates.add(candidate_key)
                candidate: dict[str, object] = {
                    "parser": KAKAOTALK_POSTPATCH_V2_DEK_VERSION,
                    "status": "derived",
                    "key_store_path": str(key_store_path.resolve()),
                    "key_store_sha256": compute_hashes(key_store_path).get("sha256", ""),
                    "entry_index": index,
                    "relative_path": relative_path,
                    "relative_path_normalized": normalized_path,
                    "database": str(matched_file.resolve()) if matched_file else "",
                    "database_name": matched_file.name if matched_file else Path(normalized_path).name,
                    "role": "chatlog" if is_chatlog else classify_kakaotalk_key_store_entry(normalized_path),
                    "wrapped_dek_length": len(wrapped_dek),
                    "wrapped_dek_sha256": hashlib.sha256(wrapped_dek).hexdigest(),
                    "derived_key_sha256": hashlib.sha256(derived_key).hexdigest(),
                    "ikm_sha256": material.get("ikm_sha256", ""),
                    "object_key_sha256": material.get("object_key_sha256", ""),
                    "entropy_sha256": material.get("entropy_sha256", ""),
                    "app_salt_sha256": hashlib.sha256(app_salt).hexdigest(),
                    "info_prefix": info_prefix,
                    "info_path_style": "backslash",
                    "algorithm": "HMAC-SHA256(object_key, IKM || entropy-bound-kek); HKDF-SHA256(bound_ikm, appstate_salt, info_prefix || backslash_path); AES-KW unwrap(wrapped_dek)",
                    "validation": {
                        "source": "kakaotalk-postpatch-v2-dek-derivation",
                        "raw_key_redacted": not include_raw,
                        "requires_manual_validation": True,
                    },
                }
                if include_raw:
                    candidate["key_hex"] = derived_key.hex()
                candidates.append(candidate)
    return candidates


def extract_kakaotalk_postpatch_v2_materials_from_blob(
    data: bytes,
    *,
    source: Path,
    profiles: Sequence[Path],
    ranges: Sequence[tuple[int, int, int]],
    aes_module: object,
    max_entropy_hits: int = 128,
    max_pointer_hits_per_entropy: int = 64,
) -> list[dict[str, object]]:
    materials: list[dict[str, object]] = []
    entropy_hits = find_kakaotalk_postpatch_entropy_candidates(data, max_hits=max_entropy_hits)
    pointer_lookup: dict[int, tuple[int, int, bytes]] = {}
    for entropy_offset, entropy in entropy_hits:
        entropy_va = mapped_offset_to_va(entropy_offset, ranges)
        if entropy_va is not None:
            pointer_lookup[entropy_va] = (entropy_offset, entropy_va, entropy)
    if not pointer_lookup:
        return materials

    pointer_hit_counts: Counter[int] = Counter()
    seen: set[tuple[int, str]] = set()
    for pointer_offset, pointed_va in find_aligned_qword_pointer_offsets(data, pointer_lookup.keys()):
        if pointer_hit_counts[pointed_va] >= max_pointer_hits_per_entropy:
            continue
        pointer_hit_counts[pointed_va] += 1
        entropy_offset, entropy_va, entropy = pointer_lookup[pointed_va]
        pointer_va = mapped_offset_to_va(pointer_offset, ranges)
        if pointer_va is None:
            continue
        object_va = pointer_va - 0x88
        object_key = read_mapped_va(data, ranges, object_va + 0x68, 32)
        if not object_key or object_key == b"\x00" * 32:
            continue
        ikm_wrap_kek = hmac.new(object_key, entropy + b"ikm-wrap", hashlib.sha256).digest()
        for profile in profiles:
            try:
                wrapped_profile = profile.read_bytes()
                ikm = aes_module.new(ikm_wrap_kek, aes_module.MODE_KW).unseal(wrapped_profile)
            except (OSError, ValueError, KeyError):
                continue
            if len(ikm) != 32:
                continue
            material_key = (object_va, hashlib.sha256(ikm).hexdigest())
            if material_key in seen:
                continue
            seen.add(material_key)
            materials.append(
                {
                    "source_path": str(source.resolve()),
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                    "object_candidate_va": f"0x{object_va:x}",
                    "object_key": object_key,
                    "object_key_sha256": hashlib.sha256(object_key).hexdigest(),
                    "entropy_source_offset": entropy_offset,
                    "entropy_va": f"0x{entropy_va:x}",
                    "entropy_sha256": hashlib.sha256(entropy).hexdigest(),
                    "entropy_pointer_source_offset": pointer_offset,
                    "entropy_pointer_va": f"0x{pointer_va:x}",
                    "profile_path": str(profile.resolve()),
                    "profile_sha256": compute_hashes(profile).get("sha256", ""),
                    "ikm": ikm,
                    "ikm_sha256": hashlib.sha256(ikm).hexdigest(),
                }
            )
    return materials


def build_memory_address_ranges(data: bytes) -> list[tuple[int, int, int]]:
    """Return (virtual_address, size, file_offset) ranges for minidumps or raw blobs."""

    if len(data) >= 32 and data[:4] == b"MDMP":
        try:
            _, _, stream_count, directory_rva, _, _, _ = struct.unpack_from("<IIIIIIQ", data, 0)
        except struct.error:
            return [(0, len(data), 0)]
        for index in range(stream_count):
            try:
                stream_type, stream_size, stream_rva = struct.unpack_from("<III", data, directory_rva + index * 12)
            except struct.error:
                break
            if stream_type != 9 or stream_size < 16:
                continue
            try:
                range_count, base_rva = struct.unpack_from("<QQ", data, stream_rva)
            except struct.error:
                continue
            ranges: list[tuple[int, int, int]] = []
            file_offset = base_rva
            for descriptor_index in range(range_count):
                try:
                    start_va, size = struct.unpack_from("<QQ", data, stream_rva + 16 + descriptor_index * 16)
                except struct.error:
                    break
                ranges.append((start_va, size, file_offset))
                file_offset += size
            if ranges:
                return sorted(ranges)
    return [(0, len(data), 0)]


def mapped_offset_to_va(offset: int, ranges: Sequence[tuple[int, int, int]]) -> int | None:
    for start_va, size, file_offset in ranges:
        if file_offset <= offset < file_offset + size:
            return start_va + offset - file_offset
    return None


def mapped_va_to_offset(va: int, ranges: Sequence[tuple[int, int, int]]) -> int | None:
    for start_va, size, file_offset in ranges:
        if start_va <= va < start_va + size:
            return file_offset + va - start_va
    return None


def read_mapped_va(data: bytes, ranges: Sequence[tuple[int, int, int]], va: int, size: int) -> bytes | None:
    offset = mapped_va_to_offset(va, ranges)
    if offset is None or offset < 0 or offset + size > len(data):
        return None
    return data[offset : offset + size]


def find_limited_byte_offsets(data: bytes, needle: bytes, *, max_hits: int) -> list[int]:
    offsets: list[int] = []
    search_from = 0
    while len(offsets) < max_hits:
        found = data.find(needle, search_from)
        if found < 0:
            break
        offsets.append(found)
        search_from = found + 1
    return offsets


def find_aligned_qword_pointer_offsets(data: bytes, targets: Sequence[int]) -> list[tuple[int, int]]:
    if not targets:
        return []
    try:
        import numpy as np
    except ImportError:
        offsets: list[tuple[int, int]] = []
        for target in targets:
            pointer = struct.pack("<Q", target)
            offsets.extend((offset, target) for offset in find_limited_byte_offsets(data, pointer, max_hits=64))
        return sorted(offsets)

    target_values = np.fromiter(targets, dtype=np.uint64)
    offsets: list[tuple[int, int]] = []
    view = memoryview(data)
    for alignment in range(8):
        usable_length = len(data) - alignment
        usable_length -= usable_length % 8
        if usable_length <= 0:
            continue
        values = np.frombuffer(view[alignment : alignment + usable_length], dtype="<u8")
        indexes = np.flatnonzero(np.isin(values, target_values))
        offsets.extend((alignment + int(index) * 8, int(values[index])) for index in indexes)
    return sorted(offsets)


def find_kakaotalk_postpatch_entropy_candidates(data: bytes, *, max_hits: int) -> list[tuple[int, bytes]]:
    candidates: list[tuple[int, bytes]] = []
    valid = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    search_from = 0
    while not max_hits or len(candidates) < max_hits:
        end = data.find(b"==", search_from)
        if end < 0:
            break
        start = end - 86
        if start >= 0:
            value = data[start : end + 2]
            if len(value) == 88 and all(byte in valid for byte in value[:-2]):
                candidates.append((start, value))
        search_from = end + 2
    return candidates


def inspect_kakaotalk_key_store_file(
    path: Path,
    *,
    root: Path,
    chat_databases: Sequence[Path],
    memory_sources: Sequence[Path],
) -> dict[str, object]:
    data = path.read_bytes()
    decoder = MiniCborDecoder(data)
    decoded = decoder.decode()
    if not isinstance(decoded, dict):
        raise KakaoTalkKeyStoreParseError("Top-level key store is not a CBOR map")
    if decoder.offset != len(data):
        raise KakaoTalkKeyStoreParseError("Trailing bytes after CBOR key store")
    info_prefix = cbor_byte_array_to_text(decoded.get("info_prefix"))
    salt = cbor_byte_array_to_bytes(decoded.get("salt"))
    wrapped_dek_map = decoded.get("wrapped_dek_map")
    if not isinstance(wrapped_dek_map, list):
        raise KakaoTalkKeyStoreParseError("wrapped_dek_map is not a CBOR array")

    file_index = build_kakaotalk_relative_file_index(root)
    chatlog_names = {path.name.lower() for path in chat_databases}
    wrapped_entries: list[dict[str, object]] = []
    wrapped_raw_values: list[tuple[str, bytes]] = []
    for index, pair in enumerate(wrapped_dek_map):
        if not isinstance(pair, list) or len(pair) != 2:
            continue
        relative_path = cbor_byte_array_to_text(pair[0])
        wrapped_dek = cbor_byte_array_to_bytes(pair[1])
        normalized_path = normalize_kakaotalk_relative_path(relative_path)
        matched_file = file_index.get(normalized_path.lower())
        is_chatlog = Path(normalized_path).name.lower() in chatlog_names or bool(
            CHATLOG_PATTERN.fullmatch(Path(normalized_path).name)
        )
        wrapped_raw_values.append((normalized_path, wrapped_dek))
        wrapped_entries.append(
            {
                "index": index,
                "relative_path": relative_path,
                "relative_path_normalized": normalized_path,
                "role": "chatlog" if is_chatlog else classify_kakaotalk_key_store_entry(normalized_path),
                "wrapped_dek_length": len(wrapped_dek),
                "wrapped_dek_sha256": hashlib.sha256(wrapped_dek).hexdigest(),
                "wrapped_dek_format_hint": "aes-key-wrap-32-byte-dek" if len(wrapped_dek) == 40 else "unknown",
                "matched_file": str(matched_file.resolve()) if matched_file else "",
                "matched_file_size": matched_file.stat().st_size if matched_file else 0,
                "matched_file_sha256": compute_hashes(matched_file)["sha256"] if matched_file else "",
                "validation": {
                    "source": "appstate.dat-wrapped-dek-map",
                    "raw_wrapped_dek_redacted": True,
                    "requires_unwrap_validation": True,
                },
            }
        )

    memory_hits = inspect_key_store_memory_hits(
        data=data,
        salt=salt,
        wrapped_entries=wrapped_entries,
        wrapped_raw_values=wrapped_raw_values,
        sources=memory_sources,
    )
    runtime_nodes = inspect_key_store_runtime_nodes(
        wrapped_entries=wrapped_entries,
        wrapped_raw_values=wrapped_raw_values,
        sources=memory_sources,
    )
    return {
        "path": str(path.resolve()),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "cbor_consumed_bytes": decoder.offset,
        "info_prefix": info_prefix,
        "salt_length": len(salt),
        "salt_sha256": hashlib.sha256(salt).hexdigest() if salt else "",
        "wrapped_dek_entry_count": len(wrapped_entries),
        "chatlog_wrapped_dek_entry_count": sum(1 for entry in wrapped_entries if entry["role"] == "chatlog"),
        "matched_file_count": sum(1 for entry in wrapped_entries if entry["matched_file"]),
        "wrapped_dek_entries": wrapped_entries,
        "memory_hits": memory_hits,
        "runtime_key_store_nodes": runtime_nodes,
        "validation": {
            "source": "kakaotalk-appstate-cbor-key-store",
            "format": "definite-length-cbor",
            "secrets_redacted": True,
            "direct_edb_decryption_ready": False,
        },
    }


def cbor_byte_array_to_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, list) and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
        return bytes(value)
    return b""


def cbor_byte_array_to_text(value: object) -> str:
    if isinstance(value, str):
        return value
    raw = cbor_byte_array_to_bytes(value)
    if not raw:
        return ""
    for encoding in ("utf-8", "utf-16le"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text and all(ord(char) >= 32 or char in "\r\n\t" for char in text):
            return text.replace("\x00", "")
    return raw.hex()


def normalize_kakaotalk_relative_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip().lstrip("/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized


def build_kakaotalk_relative_file_index(root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        normalized_relative = normalize_kakaotalk_relative_path(str(path.relative_to(root)))
        index.setdefault(normalized_relative.lower(), path)
        parts = normalized_relative.split("/")
        for start in range(1, len(parts)):
            index.setdefault("/".join(parts[start:]).lower(), path)
    return index


def classify_kakaotalk_key_store_entry(relative_path: str) -> str:
    lowered = relative_path.lower()
    if "chat_data/" in lowered:
        return "chat-data"
    if "contact" in lowered:
        return "contacts"
    if "profile" in lowered or "prf" in lowered:
        return "profile"
    if lowered.endswith(".edb"):
        return "edb"
    return "unknown"


def inspect_key_store_memory_hits(
    *,
    data: bytes,
    salt: bytes,
    wrapped_entries: Sequence[Mapping[str, object]],
    wrapped_raw_values: Sequence[tuple[str, bytes]],
    sources: Sequence[Path],
) -> list[dict[str, object]]:
    hits: list[dict[str, object]] = []
    for source in sources:
        try:
            source_data = source.read_bytes()
        except OSError:
            continue
        appstate_offset = source_data.find(data)
        salt_count = source_data.count(salt) if salt else 0
        wrapped_exact_hit_count = sum(1 for _, wrapped_value in wrapped_raw_values if wrapped_value and source_data.find(wrapped_value) >= 0)
        path_string_hit_count = 0
        for entry in wrapped_entries:
            relative_path = str(entry.get("relative_path") or "")
            if relative_path and source_data.find(relative_path.encode("utf-8", errors="ignore")) >= 0:
                path_string_hit_count += 1
        hits.append(
            {
                "source_path": str(source.resolve()),
                "source_size": source.stat().st_size,
                "appstate_blob_offset": appstate_offset,
                "appstate_blob_present": appstate_offset >= 0,
                "salt_occurrence_count": salt_count,
                "wrapped_dek_exact_hit_count": wrapped_exact_hit_count,
                "key_store_path_string_hit_count": path_string_hit_count,
                "validation": {
                    "source": "process-memory-key-store-residency",
                    "raw_memory_redacted": True,
                    "requires_manual_validation": True,
                },
            }
        )
    return hits


def inspect_key_store_runtime_nodes(
    *,
    wrapped_entries: Sequence[Mapping[str, object]],
    wrapped_raw_values: Sequence[tuple[str, bytes]],
    sources: Sequence[Path],
) -> list[dict[str, object]]:
    """Map appstate wrapped-DEK entries back to the in-memory C++ map nodes.

    KakaoTalk v2 keeps a runtime map where the key string is immediately before
    the wrapped DEK value. Recording that layout gives us a redacted known-answer
    corpus for finishing the entropy-bound KEK branch without exporting secrets.
    """

    nodes: list[dict[str, object]] = []
    entry_by_digest = {
        str(entry.get("wrapped_dek_sha256") or ""): entry
        for entry in wrapped_entries
        if entry.get("wrapped_dek_sha256")
    }
    seen: set[tuple[str, int, str]] = set()
    for source in sources:
        try:
            source_data = source.read_bytes()
        except OSError:
            continue
        ranges = build_memory_address_ranges(source_data)
        for expected_path, wrapped_value in wrapped_raw_values:
            if not wrapped_value:
                continue
            digest = hashlib.sha256(wrapped_value).hexdigest()
            search_from = 0
            while True:
                wrapped_offset = source_data.find(wrapped_value, search_from)
                if wrapped_offset < 0:
                    break
                search_from = wrapped_offset + 1
                key = (str(source.resolve()), wrapped_offset, digest)
                if key in seen:
                    continue
                seen.add(key)
                runtime_path, storage, path_source_va = decode_msvc_string_before_wrapped_value(
                    source_data,
                    ranges,
                    wrapped_offset,
                )
                normalized_runtime = normalize_kakaotalk_relative_path(runtime_path)
                normalized_expected = normalize_kakaotalk_relative_path(expected_path)
                entry = entry_by_digest.get(digest, {})
                wrapped_va = mapped_offset_to_va(wrapped_offset, ranges)
                nodes.append(
                    {
                        "source_path": str(source.resolve()),
                        "source_offset": wrapped_offset,
                        "wrapped_dek_va": f"0x{wrapped_va:x}" if wrapped_va is not None else "",
                        "relative_path_normalized": normalized_expected,
                        "runtime_path_normalized": normalized_runtime,
                        "runtime_path_matches_appstate": normalized_runtime.lower() == normalized_expected.lower(),
                        "runtime_path_storage": storage,
                        "runtime_path_length": len(runtime_path.encode("utf-8", errors="ignore")),
                        "runtime_path_sha256": hashlib.sha256(runtime_path.encode("utf-8", errors="ignore")).hexdigest()
                        if runtime_path
                        else "",
                        "runtime_path_source_va": f"0x{path_source_va:x}" if path_source_va is not None else "",
                        "role": entry.get("role", classify_kakaotalk_key_store_entry(normalized_expected)),
                        "wrapped_dek_length": len(wrapped_value),
                        "wrapped_dek_sha256": digest,
                        "validation": {
                            "source": "kakaotalk-runtime-wrapped-dek-map-node",
                            "raw_wrapped_dek_redacted": True,
                            "raw_memory_redacted": True,
                            "requires_manual_validation": True,
                        },
                    }
                )
                break
    return nodes


def decode_msvc_string_before_wrapped_value(
    data: bytes,
    ranges: Sequence[tuple[int, int, int]],
    wrapped_offset: int,
) -> tuple[str, str, int | None]:
    """Decode the MSVC std::string located before an inline 40-byte wrapped DEK."""

    metadata_offset = wrapped_offset - 0x40
    if metadata_offset < 0 or metadata_offset + 0x40 > len(data):
        return "", "unknown", None
    metadata = data[metadata_offset : metadata_offset + 0x40]
    try:
        path_length = struct.unpack_from("<Q", metadata, 0x30)[0]
        path_capacity = struct.unpack_from("<Q", metadata, 0x38)[0]
    except struct.error:
        return "", "unknown", None
    if path_length > 4096 or path_capacity < path_length:
        return "", "unknown", None
    if path_capacity <= 15:
        raw = metadata[0x20 : 0x20 + path_length]
        return raw.decode("utf-8", errors="replace").rstrip("\x00"), "inline-sso", mapped_offset_to_va(
            metadata_offset + 0x20,
            ranges,
        )
    path_va = struct.unpack_from("<Q", metadata, 0x20)[0]
    raw = read_mapped_va(data, ranges, path_va, int(path_length))
    if raw is None:
        return "", "external-pointer-unreadable", path_va
    return raw.decode("utf-8", errors="replace").rstrip("\x00"), "external-pointer", path_va


def build_kakaotalk_postpatch_known_answer_pairs(
    *,
    key_stores: Sequence[Mapping[str, object]],
    openable_edbs: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    openable_by_relative: dict[str, Mapping[str, object]] = {}
    for match in openable_edbs:
        relative = normalize_kakaotalk_relative_path(str(match.get("relative_path") or "")).lower()
        if relative:
            openable_by_relative[relative] = match
            parts = relative.split("/")
            for start in range(1, len(parts)):
                openable_by_relative.setdefault("/".join(parts[start:]), match)

    pairs: list[dict[str, object]] = []
    for key_store in key_stores:
        runtime_nodes = key_store.get("runtime_key_store_nodes", [])
        memory_hits = key_store.get("memory_hits", [])
        has_current_runtime_evidence = bool(runtime_nodes) or any(
            isinstance(hit, Mapping) and int(hit.get("wrapped_dek_exact_hit_count") or 0) > 0
            for hit in memory_hits
            if isinstance(hit, Mapping)
        )
        if not has_current_runtime_evidence:
            continue
        wrapped_entries = key_store.get("wrapped_dek_entries", [])
        if not isinstance(wrapped_entries, Sequence):
            continue
        for entry in wrapped_entries:
            if not isinstance(entry, Mapping):
                continue
            relative = normalize_kakaotalk_relative_path(str(entry.get("relative_path_normalized") or ""))
            match = openable_by_relative.get(relative.lower())
            if match is None:
                continue
            pairs.append(
                {
                    "key_store_path": key_store.get("path", ""),
                    "relative_path_normalized": relative,
                    "database": match.get("database", ""),
                    "database_name": match.get("database_name", ""),
                    "role": entry.get("role", classify_kakaotalk_key_store_entry(relative)),
                    "wrapped_dek_sha256": entry.get("wrapped_dek_sha256", ""),
                    "raw_key_sha256": match.get("raw_key_sha256", ""),
                    "database_sha256": entry.get("matched_file_sha256", ""),
                    "validation": {
                        "source": "postpatch-known-answer-wrapped-dek-to-sqlcipher-key-pair",
                        "raw_wrapped_dek_redacted": True,
                        "raw_key_redacted": True,
                        "purpose": "Use these non-chat pairs to validate the v2 KEK/DEK derivation before applying it to chatLogs.",
                    },
                }
            )
    return pairs


def build_kakaotalk_memory_carve_payload(
    *,
    root: Path,
    output: Path,
    carve_dir: Path | None,
    max_hits: int,
    max_carve_bytes: int,
    include_row_preview: bool,
    max_rows_per_table: int,
    max_message_residues: int,
    include_message_preview: bool,
    write_carves: bool,
    command: str,
) -> dict[str, object]:
    if write_carves and carve_dir is not None:
        carve_dir.mkdir(parents=True, exist_ok=True)
    sources = find_memory_dump_candidates(root)
    entries: list[dict[str, object]] = []
    header_count = 0
    for source in sources:
        for offset in iter_sqlite_header_offsets(source, max_hits=max(0, max_hits - header_count) if max_hits else 0):
            header_count += 1
            entry = analyze_memory_sqlite_carve(
                source,
                offset=offset,
                carve_dir=carve_dir,
                max_carve_bytes=max_carve_bytes,
                include_row_preview=include_row_preview,
                max_rows_per_table=max_rows_per_table,
                write_carves=write_carves,
            )
            entries.append(entry)
            if max_hits and header_count >= max_hits:
                break
        if max_hits and header_count >= max_hits:
            break
    message_residues: list[dict[str, object]] = []
    remaining_message_residues = max_message_residues
    for source in sources:
        if max_message_residues and remaining_message_residues <= 0:
            break
        source_limit = remaining_message_residues if max_message_residues else 0
        source_residues = extract_memory_chat_message_residues(
            source,
            max_messages=source_limit,
            include_message_preview=include_message_preview,
        )
        message_residues.extend(source_residues)
        if max_message_residues:
            remaining_message_residues -= len(source_residues)
    reverse_indicators: list[dict[str, object]] = []
    sqlcipher_key_residues: list[dict[str, object]] = []
    remaining_reverse_indicators = DEFAULT_MEMORY_REVERSE_INDICATOR_LIMIT
    remaining_key_residues = DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT
    for source in sources:
        if remaining_reverse_indicators <= 0 and remaining_key_residues <= 0:
            break
        reverse_evidence = extract_memory_reverse_evidence(
            source,
            max_indicators=max(0, remaining_reverse_indicators),
            max_key_residues=max(0, remaining_key_residues),
        )
        source_indicators = reverse_evidence["reverse_indicators"]
        source_key_residues = reverse_evidence["sqlcipher_key_residues"]
        reverse_indicators.extend(source_indicators)
        sqlcipher_key_residues.extend(source_key_residues)
        remaining_reverse_indicators -= len(source_indicators)
        remaining_key_residues -= len(source_key_residues)

    table_total = sum(len(entry.get("tables") or []) for entry in entries)
    chat_relevant_total = sum(
        1
        for entry in entries
        for table in entry.get("tables") or []
        if bool(table.get("chat_relevant"))
    )
    malformed_total = sum(
        1
        for entry in entries
        if any(str(table.get("row_status") or "").startswith("malformed") for table in entry.get("tables") or [])
    )
    return {
        "command": command,
        "parser": KAKAOTALK_MEMORY_CARVE_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "output": str(output),
        "authorization_model": {
            "requires_authorized_legal_scope": True,
            "secrets_redacted": not include_row_preview,
            "row_preview_included": include_row_preview,
            "carved_sqlite_written": write_carves,
        },
        "parameters": {
            "max_hits": max_hits,
            "max_carve_bytes": max_carve_bytes,
            "include_row_preview": include_row_preview,
            "max_rows_per_table": max_rows_per_table,
            "max_message_residues": max_message_residues,
            "write_carves": write_carves,
            "carve_dir": str(carve_dir) if carve_dir is not None else "",
        },
        "summary": {
            "memory_source_count": len(sources),
            "sqlite_header_count": header_count,
            "carved_database_count": len(entries),
            "table_count": table_total,
            "chat_relevant_table_count": chat_relevant_total,
            "chat_message_residue_count": len(message_residues),
            "reverse_indicator_count": len(reverse_indicators),
            "sqlcipher_key_residue_count": len(sqlcipher_key_residues),
            "malformed_database_count": malformed_total,
            "postpatch_evidence_value": determine_postpatch_evidence_value(
                entries=entries,
                message_residues=message_residues,
                reverse_indicators=reverse_indicators,
                sqlcipher_key_residues=sqlcipher_key_residues,
            ),
            "message_content_reportable": include_message_preview and bool(message_residues),
        },
        "entries": entries,
        "chat_message_residues": message_residues,
        "reverse_indicators": reverse_indicators,
        "sqlcipher_key_residues": sqlcipher_key_residues,
    }


def determine_postpatch_evidence_value(
    *,
    entries: Sequence[Mapping[str, object]],
    message_residues: Sequence[Mapping[str, object]],
    reverse_indicators: Sequence[Mapping[str, object]],
    sqlcipher_key_residues: Sequence[Mapping[str, object]],
) -> str:
    values: list[str] = []
    if entries:
        values.append("sqlite-schema-carves")
    if message_residues:
        values.append("message-json-residue")
    if reverse_indicators:
        values.append("reverse-indicators")
    if sqlcipher_key_residues:
        values.append("sqlcipher-key-residue")
    return "+".join(values) if values else "none"


def find_memory_dump_candidates(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        name = path.name.lower()
        suffix_match = path.suffix.lower() in MEMORY_DUMP_SUFFIXES
        hinted = any(hint in name for hint in MEMORY_DUMP_NAME_HINTS)
        if suffix_match and hinted:
            candidates.append(path)
    return candidates


def iter_sqlite_header_offsets(path: Path, *, max_hits: int = 0) -> list[int]:
    hits: list[int] = []
    overlap = len(SQLITE_HEADER) - 1
    carry = b""
    offset = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(KEY_MATERIAL_CHUNK_SIZE)
            if not chunk:
                break
            data = carry + chunk
            search_from = 0
            while True:
                found = data.find(SQLITE_HEADER, search_from)
                if found < 0:
                    break
                absolute = offset - len(carry) + found
                if absolute >= 0:
                    hits.append(absolute)
                    if max_hits and len(hits) >= max_hits:
                        return hits
                search_from = found + 1
            carry = data[-overlap:] if overlap else b""
            offset += len(chunk)
    return hits


def extract_memory_reverse_evidence(
    path: Path,
    *,
    max_indicators: int,
    max_key_residues: int,
) -> dict[str, list[dict[str, object]]]:
    data = path.read_bytes()
    indicators = extract_memory_reverse_indicators(data, source=path, max_indicators=max_indicators)
    key_residues = extract_memory_sqlcipher_key_residues(data, source=path, max_key_residues=max_key_residues)
    return {
        "reverse_indicators": indicators,
        "sqlcipher_key_residues": key_residues,
    }


def extract_memory_reverse_indicators(
    data: bytes,
    *,
    source: Path,
    max_indicators: int,
) -> list[dict[str, object]]:
    if max_indicators <= 0:
        return []
    indicators: list[dict[str, object]] = []
    seen: set[tuple[str, int, str]] = set()
    for pattern_text in MEMORY_REVERSE_INDICATOR_PATTERNS:
        encoded_patterns = (
            ("ascii", pattern_text.encode("utf-8")),
            ("utf-16le", pattern_text.encode("utf-16le")),
        )
        for encoding, pattern in encoded_patterns:
            search_from = 0
            while len(indicators) < max_indicators:
                found = data.find(pattern, search_from)
                if found < 0:
                    break
                key = (pattern_text, found, encoding)
                if key not in seen:
                    seen.add(key)
                    context = context_window(data, found)
                    indicators.append(
                        {
                            "source_path": str(source.resolve()),
                            "source_offset": found,
                            "indicator": pattern_text,
                            "encoding": encoding,
                            "context_sha256": hashlib.sha256(context).hexdigest(),
                            "context_terms": detect_memory_context_terms(context),
                            "validation": {
                                "source": "process-memory-reverse-indicator",
                                "requires_manual_validation": True,
                                "secrets_redacted": True,
                            },
                        }
                    )
                search_from = found + 1
            if len(indicators) >= max_indicators:
                break
        if len(indicators) >= max_indicators:
            break
    return indicators


def extract_memory_sqlcipher_key_residues(
    data: bytes,
    *,
    source: Path,
    max_key_residues: int,
) -> list[dict[str, object]]:
    if max_key_residues <= 0:
        return []
    residues: list[dict[str, object]] = []
    seen: set[tuple[int, str]] = set()
    for match in SQLCIPHER_KEY_LITERAL_PATTERN.finditer(data):
        if len(residues) >= max_key_residues:
            break
        key_hex = match.group(1).decode("ascii")
        key_bytes = bytes.fromhex(key_hex)
        key = (match.start(), hashlib.sha256(key_bytes).hexdigest())
        if key in seen:
            continue
        seen.add(key)
        context = context_window(data, match.start())
        raw_key = key_bytes[:32]
        salt = key_bytes[32:48] if len(key_bytes) == 48 else b""
        residues.append(
            {
                "source_path": str(source.resolve()),
                "source_offset": match.start(),
                "literal_size": match.end() - match.start(),
                "hex_length": len(key_hex),
                "byte_length": len(key_bytes),
                "raw_key_byte_length": len(raw_key),
                "salt_byte_length": len(salt),
                "candidate_sha256": hashlib.sha256(key_bytes).hexdigest(),
                "raw_key_sha256": hashlib.sha256(raw_key).hexdigest(),
                "salt_sha256": hashlib.sha256(salt).hexdigest() if salt else "",
                "context_sha256": hashlib.sha256(context).hexdigest(),
                "context_terms": detect_memory_context_terms(context),
                "validation": {
                    "source": "process-memory-sqlcipher-key-literal",
                    "requires_manual_validation": True,
                    "raw_key_redacted": True,
                    "sqlcipher_raw_key_format": "64-hex-key+32-hex-salt"
                    if len(key_hex) == 96
                    else "64-hex-key",
                },
            }
        )
    return residues


def collect_sqlcipher_key_literals_from_memory(
    sources: Sequence[Path],
    *,
    max_keys: int,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[str] = set()
    for source in sources:
        data = source.read_bytes()
        for match in SQLCIPHER_KEY_LITERAL_PATTERN.finditer(data):
            if max_keys and len(candidates) >= max_keys:
                return candidates
            key_hex = match.group(1).decode("ascii")
            key_bytes = bytes.fromhex(key_hex)
            digest = hashlib.sha256(key_bytes).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            candidates.append(
                {
                    "source_path": str(source.resolve()),
                    "source_offset": match.start(),
                    "key_hex": key_hex,
                    "candidate_sha256": digest,
                    "raw_key_sha256": hashlib.sha256(key_bytes[:32]).hexdigest(),
                    "salt_sha256": hashlib.sha256(key_bytes[32:48]).hexdigest() if len(key_bytes) == 48 else "",
                    "hex_length": len(key_hex),
                    "byte_length": len(key_bytes),
                }
            )
    return candidates


def find_kakaotalk_edb_databases(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*.edb") if path.is_file()),
        key=lambda item: str(item).lower(),
    )


def match_sqlcipher_literals_to_edb_headers(
    root: Path,
    databases: Sequence[Path],
    variants: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    by_salt: dict[str, list[Path]] = {}
    for database in databases:
        try:
            salt = database.read_bytes()[:16].hex()
        except OSError:
            continue
        if len(salt) == 32:
            by_salt.setdefault(salt, []).append(database)

    matches: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for variant in variants:
        key_hex = str(variant.get("key_hex") or "")
        if len(key_hex) != 96:
            continue
        salt_hex = key_hex[64:96].lower()
        for database in by_salt.get(salt_hex, []):
            key = (str(database.resolve()), str(variant.get("raw_key_sha256") or ""))
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "database": str(database.resolve()),
                    "relative_path": str(database.relative_to(root)) if database.is_relative_to(root) else database.name,
                    "database_name": database.name,
                    "database_size": database.stat().st_size,
                    "key_hex": key_hex,
                    "variant": variant.get("variant", ""),
                    "key_candidate_sha256": variant.get("candidate_sha256", ""),
                    "raw_key_sha256": variant.get("raw_key_sha256", ""),
                    "salt_sha256": hashlib.sha256(bytes.fromhex(salt_hex)).hexdigest(),
                    "validation": {
                        "source": "memory-sqlcipher-literal-salt-match",
                        "raw_key_redacted": True,
                        "salt_redacted": True,
                        "requires_manual_validation": True,
                    },
                }
            )
    return matches


def redact_openable_edb_match(match: Mapping[str, object]) -> dict[str, object]:
    redacted = {
        "database": match.get("database", ""),
        "relative_path": match.get("relative_path", ""),
        "database_name": match.get("database_name", ""),
        "database_size": match.get("database_size", 0),
        "variant": match.get("variant", ""),
        "key_candidate_sha256": match.get("key_candidate_sha256", ""),
        "raw_key_sha256": match.get("raw_key_sha256", ""),
        "salt_sha256": match.get("salt_sha256", ""),
        "validation": match.get("validation", {}),
    }
    if isinstance(match.get("export"), Mapping):
        redacted["export"] = match["export"]
    return redacted


def redact_postpatch_v2_derived_key(candidate: Mapping[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in candidate.items()
        if key not in {"key_hex", "object_key", "ikm"}
    }


def export_sqlcipher_database(
    sqlcipher_path: str,
    database: Path,
    *,
    key_hex: str,
    export_path: Path,
    timeout_seconds: float,
) -> dict[str, object]:
    export_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rapidtriage-sqlcipher-export-") as temp_dir:
        temp_db = Path(temp_dir) / database.name
        shutil.copy2(database, temp_db)
        temp_export = Path(temp_dir) / export_path.name
        commands = [
            f".open {temp_db}",
            "PRAGMA cipher_compatibility = 4;",
            f"PRAGMA key = \"x'{key_hex[:64]}'\";",
            f"PRAGMA cipher_salt = \"x'{key_hex[64:96]}'\";",
            f"ATTACH DATABASE '{temp_export}' AS plaintext KEY '';",
            "SELECT sqlcipher_export('plaintext');",
            "DETACH DATABASE plaintext;",
        ]
        try:
            process = subprocess.run(
                [sqlcipher_path],
                input="\n".join(commands) + "\n",
                text=True,
                capture_output=True,
                timeout=max(timeout_seconds, 5.0),
            )
        except subprocess.TimeoutExpired:
            return {"exported": False, "status": "timeout", "export_path": str(export_path)}
        if process.returncode == 0 and temp_export.exists() and temp_export.stat().st_size > 0:
            shutil.copy2(temp_export, export_path)
            return {
                "exported": True,
                "status": "exported",
                "export_path": str(export_path),
                "export_size": export_path.stat().st_size,
                "export_sha256": compute_hashes(export_path).get("sha256", ""),
            }
    return {
        "exported": False,
        "status": "failed",
        "export_path": str(export_path),
        "stderr_sha256": hashlib.sha256((process.stderr or "").encode("utf-8", errors="ignore")).hexdigest(),
    }


def extract_postpatch_chat_room_previews(
    exported_databases: Sequence[Path],
    *,
    root: Path,
    max_rooms: int = 200,
) -> list[dict[str, object]]:
    """Extract post-BigBang room/message previews from SQLCipher-opened auxiliary EDBs.

    Newer Windows KakaoTalk keeps full chat history in per-room chatLogs_*.edb, but the
    SQLCipher-openable chatListInfo.edb still carries room metadata and the latest
    chat JSON in chatRoomList.lastChatlog. This does not replace full chatLogs
    decryption; it gives analysts a validated, source-cited room triage surface.
    """

    previews: list[dict[str, object]] = []
    for database in exported_databases:
        if not database or not database.exists() or not database.is_file():
            continue
        try:
            connection = sqlite3.connect(sqlite_readonly_uri(database, immutable=True), uri=True)
        except sqlite3.Error:
            continue
        try:
            table_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='chatRoomList' LIMIT 1"
            ).fetchone()
            if not table_exists:
                continue
            columns = {row[1] for row in connection.execute("PRAGMA table_info(chatRoomList)")}
            required = {"chatId", "type", "lastChatMessage", "lastChatlog"}
            if not required.issubset(columns):
                continue
            optional_columns = [
                column
                for column in (
                    "chatRoomTitle",
                    "activeMembersCount",
                    "newMessageCount",
                    "lastUpdatedAt",
                    "lastLogId_ByCHATLOGS",
                    "lastLogId",
                    "directChatMemberId",
                )
                if column in columns
            ]
            select_columns = ["chatId", "type", "lastChatMessage", "lastChatlog", *optional_columns]
            order_clause = " ORDER BY lastUpdatedAt DESC" if "lastUpdatedAt" in columns else ""
            rows = connection.execute(
                f"SELECT {', '.join(select_columns)} FROM chatRoomList{order_clause} LIMIT ?",
                (max_rooms,),
            )
            for row in rows:
                values = dict(zip(select_columns, row))
                last_chatlog = str(values.get("lastChatlog") or "")
                parsed_last_chatlog = parse_kakaotalk_last_chatlog_json(last_chatlog)
                message_text = parsed_last_chatlog.get("message") or str(values.get("lastChatMessage") or "")
                previews.append(
                    {
                        "parser": KAKAOTALK_POSTPATCH_AUXILIARY_VERSION,
                        "source_export_path": str(database.resolve()),
                        "source_export_relative_path": str(database.relative_to(root))
                        if database.is_relative_to(root)
                        else database.name,
                        "source_export_sha256": compute_hashes(database).get("sha256", ""),
                        "chat_id": str(values.get("chatId") or ""),
                        "room_type": values.get("type") or "",
                        "room_title": values.get("chatRoomTitle") or "",
                        "active_members_count": values.get("activeMembersCount"),
                        "new_message_count": values.get("newMessageCount"),
                        "last_updated_at": values.get("lastUpdatedAt"),
                        "last_log_id_by_chatlogs": str(values.get("lastLogId_ByCHATLOGS") or ""),
                        "last_log_id": str(values.get("lastLogId") or ""),
                        "direct_chat_member_id": str(values.get("directChatMemberId") or ""),
                        "message_text": message_text,
                        "message_text_sha256": hashlib.sha256(str(message_text).encode("utf-8")).hexdigest()
                        if message_text
                        else "",
                        "last_chatlog_json_status": parsed_last_chatlog.get("_status", "missing"),
                        "last_chatlog_fields": {
                            key: parsed_last_chatlog[key]
                            for key in (
                                "authorId",
                                "deleted",
                                "logId",
                                "msgId",
                                "prevId",
                                "sendAt",
                                "type",
                            )
                            if key in parsed_last_chatlog
                        },
                        "validation": {
                            "source": "kakaotalk-postpatch-chatListInfo-chatRoomList",
                            "full_history_available": False,
                            "limitation": "chatRoomList.lastChatlog generally preserves the latest room message only; per-room chatLogs_*.edb decryption is still required for complete history.",
                            "requires_manual_validation": True,
                        },
                    }
                )
        finally:
            connection.close()
    return previews


def parse_kakaotalk_last_chatlog_json(value: str) -> dict[str, object]:
    if not value:
        return {"_status": "missing"}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"_status": "invalid-json", "raw_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()}
    if not isinstance(parsed, dict):
        return {"_status": "not-object"}
    parsed["_status"] = "parsed"
    return parsed


def collect_kakaotalk_memory_message_residues(
    sources: Sequence[Path],
    *,
    max_messages: int,
    include_message_preview: bool,
) -> list[dict[str, object]]:
    residues: list[dict[str, object]] = []
    remaining = max_messages
    for source in sources:
        if max_messages and remaining <= 0:
            break
        source_limit = remaining if max_messages else 0
        source_residues = extract_memory_chat_message_residues(
            source,
            max_messages=source_limit,
            include_message_preview=include_message_preview,
        )
        residues.extend(source_residues)
        if max_messages:
            remaining -= len(source_residues)
    return residues


def build_kakaotalk_postpatch_room_evidence(
    *,
    room_previews: Sequence[Mapping[str, object]],
    message_residues: Sequence[Mapping[str, object]],
    max_residue_samples_per_room: int = 5,
) -> list[dict[str, object]]:
    rooms: dict[str, dict[str, object]] = {}
    for preview in room_previews:
        chat_id = str(preview.get("chat_id") or "")
        if not chat_id:
            continue
        room = rooms.setdefault(
            chat_id,
            {
                "chat_id": chat_id,
                "sources": [],
                "preview": {},
                "memory_message_count": 0,
                "memory_message_samples": [],
            },
        )
        room["preview"] = {
            key: preview.get(key)
            for key in (
                "room_title",
                "room_type",
                "active_members_count",
                "new_message_count",
                "last_updated_at",
                "last_log_id_by_chatlogs",
                "last_log_id",
                "direct_chat_member_id",
                "message_text",
                "message_text_sha256",
            )
            if key in preview
        }
        room["sources"] = sorted(set([*room.get("sources", []), "chatListInfo.edb"]))
    for residue in message_residues:
        chat_id = str(residue.get("chat_id") or "")
        if not chat_id:
            continue
        room = rooms.setdefault(
            chat_id,
            {
                "chat_id": chat_id,
                "sources": [],
                "preview": {},
                "memory_message_count": 0,
                "memory_message_samples": [],
            },
        )
        room["memory_message_count"] = int(room.get("memory_message_count") or 0) + 1
        room["sources"] = sorted(set([*room.get("sources", []), "process-memory-json-residue"]))
        samples = room["memory_message_samples"]
        if isinstance(samples, list) and len(samples) < max_residue_samples_per_room:
            sample = {
                key: residue.get(key)
                for key in (
                    "source_path",
                    "source_offset",
                    "chat_id",
                    "log_id",
                    "author_id",
                    "send_at",
                    "send_at_utc",
                    "type",
                    "deleted",
                    "message_text_length",
                    "message_text_sha256",
                    "attachment_length",
                    "attachment_sha256",
                    "message_text",
                    "attachment_preview",
                )
                if key in residue
            }
            samples.append(sample)
    evidence = sorted(
        rooms.values(),
        key=lambda item: (
            -int(item.get("memory_message_count") or 0),
            str(item.get("preview", {}).get("last_updated_at") or ""),
            str(item.get("chat_id") or ""),
        ),
    )
    for room in evidence:
        room["validation"] = {
            "source": "kakaotalk-postpatch-room-evidence-bundle",
            "full_history_available": False,
            "requires_manual_validation": True,
            "limitation": "Combines auxiliary room metadata and process-memory JSON residues; this is triage evidence, not full chatLogs_*.edb history.",
        }
    return evidence


def safe_export_name(root: Path, database: Path) -> str:
    try:
        relative = database.relative_to(root)
    except ValueError:
        relative = Path(database.name)
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", "_".join(relative.parts))


def redact_sqlcipher_key_candidate(candidate: Mapping[str, object]) -> dict[str, object]:
    key_hex = str(candidate.get("key_hex") or "")
    return {
        "source_path": candidate.get("source_path", ""),
        "source_offset": candidate.get("source_offset", 0),
        "hex_length": len(key_hex),
        "byte_length": int(candidate.get("byte_length") or 0),
        "raw_key_byte_length": 32 if len(key_hex) >= 64 else 0,
        "salt_byte_length": 16 if len(key_hex) == 96 else 0,
        "candidate_sha256": candidate.get("candidate_sha256", ""),
        "raw_key_sha256": candidate.get("raw_key_sha256", ""),
        "salt_sha256": candidate.get("salt_sha256", ""),
        "validation": {
            "source": "process-memory-sqlcipher-key-literal",
            "raw_key_redacted": True,
            "requires_manual_validation": True,
        },
    }


def build_sqlcipher_key_probe_variants(candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    variants: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidates:
        key_hex = str(candidate.get("key_hex") or "")
        if len(key_hex) not in (64, 96):
            continue
        for variant_name, variant_hex in sqlcipher_key_variant_hex_values(key_hex):
            key = (variant_name, variant_hex)
            if key in seen:
                continue
            seen.add(key)
            variant_bytes = bytes.fromhex(variant_hex)
            variants.append(
                {
                    "variant": variant_name,
                    "key_hex": variant_hex,
                    "candidate_sha256": candidate.get("candidate_sha256", ""),
                    "raw_key_sha256": hashlib.sha256(variant_bytes[:32]).hexdigest(),
                }
            )
    return variants


def sqlcipher_key_variant_hex_values(key_hex: str) -> list[tuple[str, str]]:
    if len(key_hex) == 96:
        return [
            ("literal-32-byte-key-plus-16-byte-salt", key_hex),
            ("first-32-byte-raw-key", key_hex[:64]),
            ("first-32-byte-raw-key-with-salt-pragma", key_hex),
        ]
    if len(key_hex) == 64:
        return [("literal-32-byte-raw-key", key_hex)]
    return []


def probe_sqlcipher_database(
    sqlcipher_path: str,
    database: Path,
    *,
    key_hex: str,
    variant: str,
    compatibility: int,
    timeout_seconds: float,
) -> dict[str, object]:
    commands = [f"PRAGMA cipher_compatibility = {compatibility};"]
    if variant == "first-32-byte-raw-key-with-salt-pragma" and len(key_hex) == 96:
        commands.append(f"PRAGMA key = \"x'{key_hex[:64]}'\";")
        commands.append(f"PRAGMA cipher_salt = \"x'{key_hex[64:]}'\";")
    else:
        commands.append(f"PRAGMA key = \"x'{key_hex}'\";")
    commands.append("SELECT count(*) FROM sqlite_master;")
    try:
        process = subprocess.run(
            [sqlcipher_path, str(database)],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"opened": False, "status": "timeout"}
    output_lines = [line.strip() for line in (process.stdout or "").splitlines() if line.strip()]
    opened = process.returncode == 0 and bool(output_lines) and output_lines[-1].isdigit()
    return {
        "opened": opened,
        "status": "opened" if opened else "not-opened",
        "schema_count": int(output_lines[-1]) if opened else 0,
    }


def context_window(data: bytes, offset: int, *, radius: int = 512) -> bytes:
    start = max(0, offset - radius)
    end = min(len(data), offset + radius)
    return data[start:end]


def detect_memory_context_terms(context: bytes) -> list[str]:
    ascii_text = context.decode("utf-8", errors="ignore").lower()
    utf16_text = context.decode("utf-16le", errors="ignore").lower()
    combined = ascii_text + "\n" + utf16_text
    return [term for term in MEMORY_REVERSE_CONTEXT_HINTS if term in combined]


def extract_memory_chat_message_residues(
    path: Path,
    *,
    max_messages: int,
    include_message_preview: bool,
) -> list[dict[str, object]]:
    data = path.read_bytes()
    starts: list[int] = []
    for marker in (b'{"attachment"', b'{"authorId"', b'{"chatId"'):
        search_from = 0
        while True:
            found = data.find(marker, search_from)
            if found < 0:
                break
            starts.append(found)
            search_from = found + 1
            if max_messages and len(set(starts)) >= max_messages * 4:
                break
    residues: list[dict[str, object]] = []
    seen: set[tuple[int, int, int]] = set()
    decoder = json.JSONDecoder()
    for offset in sorted(set(starts)):
        if max_messages and len(residues) >= max_messages:
            break
        window = data[offset : offset + 64 * 1024].decode("utf-8", errors="ignore")
        try:
            parsed, consumed = decoder.raw_decode(window)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        if "message" not in parsed or "chatId" not in parsed or "logId" not in parsed:
            continue
        try:
            chat_id = int(parsed.get("chatId") or 0)
            log_id = int(parsed.get("logId") or 0)
            send_at = int(parsed.get("sendAt") or 0)
        except (TypeError, ValueError):
            continue
        key = (chat_id, log_id, offset)
        if key in seen:
            continue
        seen.add(key)
        message_text = str(parsed.get("message") or "")
        attachment_text = str(parsed.get("attachment") or "")
        residue: dict[str, object] = {
            "source_path": str(path.resolve()),
            "source_offset": offset,
            "json_size": consumed,
            "chat_id": chat_id,
            "log_id": log_id,
            "author_id": int(parsed.get("authorId") or 0) if str(parsed.get("authorId") or "").isdigit() else 0,
            "send_at": send_at,
            "send_at_utc": timestamp_to_utc_iso(send_at),
            "type": int(parsed.get("type") or 0) if str(parsed.get("type") or "").lstrip("-").isdigit() else 0,
            "deleted": bool(parsed.get("deleted")),
            "message_text_length": len(message_text),
            "message_text_sha256": hashlib.sha256(message_text.encode("utf-8", errors="ignore")).hexdigest(),
            "attachment_length": len(attachment_text),
            "attachment_sha256": hashlib.sha256(attachment_text.encode("utf-8", errors="ignore")).hexdigest()
            if attachment_text
            else "",
            "validation": {
                "source": "process-memory-json-residue",
                "requires_manual_validation": True,
                "message_content_reportable": include_message_preview and bool(message_text),
            },
        }
        if include_message_preview:
            residue["message_text"] = message_text
            residue["attachment_preview"] = attachment_text[:1000]
        residues.append(residue)
    return residues


def timestamp_to_utc_iso(timestamp: int) -> str:
    if timestamp <= 0:
        return ""
    try:
        return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


def analyze_memory_sqlite_carve(
    source: Path,
    *,
    offset: int,
    carve_dir: Path | None,
    max_carve_bytes: int,
    include_row_preview: bool,
    max_rows_per_table: int,
    write_carves: bool,
) -> dict[str, object]:
    header = read_bytes_at(source, offset, 100)
    page_size, declared_page_count = parse_sqlite_header_geometry(header)
    declared_size = page_size * declared_page_count if page_size and declared_page_count else 0
    carve_size = declared_size if declared_size else max_carve_bytes
    carve_size = min(carve_size, max_carve_bytes)
    carved = read_bytes_at(source, offset, carve_size)
    carved_sha256 = hashlib.sha256(carved).hexdigest()
    entry: dict[str, object] = {
        "source_path": str(source.resolve()),
        "source_offset": offset,
        "page_size": page_size,
        "declared_page_count": declared_page_count,
        "declared_size": declared_size,
        "carved_size": len(carved),
        "truncated": bool(declared_size and len(carved) < declared_size),
        "carved_sha256": carved_sha256,
        "carved_path": "",
        "sqlite_status": "not-opened",
        "tables": [],
        "errors": [],
        "validation": {
            "sqlite_header_confirmed": carved.startswith(SQLITE_HEADER),
            "memory_carve_only": True,
            "requires_manual_validation": True,
        },
    }
    if not carved.startswith(SQLITE_HEADER):
        entry["errors"] = ["SQLite header was not present at the requested offset"]
        return entry

    temp_path: Path | None = None
    try:
        if write_carves and carve_dir is not None:
            carve_dir.mkdir(parents=True, exist_ok=True)
            temp_path = carve_dir / f"{source.stem}-sqlite-{offset}.sqlite"
            temp_path.write_bytes(carved)
            entry["carved_path"] = str(temp_path)
        else:
            temp_file = tempfile.NamedTemporaryFile(prefix=f"{source.stem}-sqlite-{offset}-", suffix=".sqlite", delete=False)
            temp_file.write(carved)
            temp_file.close()
            temp_path = Path(temp_file.name)
        entry["tables"] = inspect_memory_sqlite_tables(
            temp_path,
            include_row_preview=include_row_preview,
            max_rows_per_table=max_rows_per_table,
        )
        entry["sqlite_status"] = "schema-opened" if entry["tables"] else "opened-no-tables"
    except (OSError, sqlite3.DatabaseError) as exc:
        entry["sqlite_status"] = "malformed"
        entry["errors"] = [str(exc)]
    finally:
        if temp_path is not None and not write_carves:
            try:
                temp_path.unlink()
            except OSError:
                pass
    return entry


def parse_sqlite_header_geometry(header: bytes) -> tuple[int, int]:
    if len(header) < 100 or not header.startswith(SQLITE_HEADER):
        return (0, 0)
    page_size = struct.unpack(">H", header[16:18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size not in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}:
        page_size = PAGE_SIZE
    page_count = struct.unpack(">I", header[28:32])[0]
    return (page_size, page_count)


def read_bytes_at(path: Path, offset: int, size: int) -> bytes:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(size)


def inspect_memory_sqlite_tables(
    path: Path,
    *,
    include_row_preview: bool,
    max_rows_per_table: int,
) -> list[dict[str, object]]:
    connection = sqlite3.connect(sqlite_readonly_uri(path, immutable=True), uri=True)
    try:
        rows = connection.execute(
            "select name, sql from sqlite_master where type='table' and name not like 'sqlite_%' order by name"
        ).fetchall()
        tables: list[dict[str, object]] = []
        for table_name, schema_sql in rows:
            table = {
                "name": str(table_name),
                "schema_sql": str(schema_sql or ""),
                "schema_sql_sha256": hashlib.sha256(str(schema_sql or "").encode("utf-8", errors="ignore")).hexdigest(),
                "chat_relevant": any(
                    hint in str(table_name).lower() or hint in str(schema_sql or "").lower()
                    for hint in ("chat", "message", "msg", "log", "token", "room")
                ),
                "row_status": "not-attempted",
                "row_count": 0,
                "row_preview": [],
                "errors": [],
            }
            try:
                table["row_count"] = int(connection.execute(f'select count(*) from "{table_name}"').fetchone()[0])
                table["row_status"] = "counted"
                if include_row_preview and max_rows_per_table > 0:
                    preview_rows = connection.execute(f'select * from "{table_name}" limit ?', (max_rows_per_table,)).fetchall()
                    column_names = [item[1] for item in connection.execute(f'pragma table_info("{table_name}")').fetchall()]
                    table["row_preview"] = [
                        {
                            str(column_names[index] if index < len(column_names) else f"column_{index}"): preview_sqlite_value(value)
                            for index, value in enumerate(row)
                        }
                        for row in preview_rows
                    ]
            except sqlite3.DatabaseError as exc:
                table["row_status"] = "malformed-row-pages"
                table["errors"] = [str(exc)]
            tables.append(table)
        return tables
    finally:
        connection.close()


def preview_sqlite_value(value: object) -> object:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "preview_hex": value[:32].hex(),
        }
    text = str(value)
    return text[:500]


def sqlite_readonly_uri(path: Path, *, immutable: bool = False) -> str:
    suffix = "?mode=ro"
    if immutable:
        # Decrypted KakaoTalk EDBs are evidence copies. Opening as immutable avoids
        # SQLite trying to create WAL/SHM sidecars in read-only or temporary folders.
        suffix += "&immutable=1"
    return f"{path.resolve().as_uri()}{suffix}"


def run_kakaotalk_userdir_bruteforce(
    root: Path,
    *,
    output: Path,
    userdir_home: str | None = None,
    userdir: str | None = None,
    pragma: str | None = None,
    pragma_key_hex: str | None = None,
    sys_uuid: str | None = None,
    hdd_model: str | None = None,
    hdd_serial: str | None = None,
    start_id: int = 1,
    end_id: int = 400_000_000,
    chunk_size: int = 10_000_000,
    compiler: str = "cc",
    openssl_bin: str = "openssl",
) -> dict[str, object]:
    root = root.expanduser().resolve()
    output = output.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise KakaoTalkDecryptError(f"Input root does not exist or is not a directory: {root}")
    if start_id < 0 or end_id < start_id:
        raise KakaoTalkDecryptError("--start-id/--end-id range is invalid")
    if chunk_size <= 0:
        raise KakaoTalkDecryptError("--chunk-size must be > 0")

    resolved_userdir = userdir or infer_kakaotalk_userdir(root)
    if not resolved_userdir or not USERDIR_PATTERN.fullmatch(resolved_userdir):
        raise KakaoTalkDecryptError("Could not infer a 40-hex KakaoTalk userDir; pass --userdir")
    resolved_userdir_home = userdir_home or infer_kakaotalk_userdir_home(root)
    if not resolved_userdir_home:
        raise KakaoTalkDecryptError("Could not infer Windows KakaoTalk users path; pass --userdir-home")

    pragma_candidates = resolve_userdir_pragma_candidates(
        root,
        pragma=pragma,
        pragma_key_hex=pragma_key_hex,
        sys_uuid=sys_uuid,
        hdd_model=hdd_model,
        hdd_serial=hdd_serial,
        openssl_bin=openssl_bin,
    )
    if not pragma_candidates:
        raise KakaoTalkDecryptError("No pragma candidates available; pass --pragma or --pragma-key-hex with DeviceInfo")

    payload: dict[str, object] = {
        "command": "kakaotalk-userdir-bruteforce",
        "parser": KAKAOTALK_USERDIR_BRUTEFORCE_VERSION,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "output": str(output),
        "authorization_model": {
            "requires_authorized_legal_scope": True,
            "secrets_redacted": True,
            "proprietary_application_key_included": False,
        },
        "parameters": {
            "userdir": resolved_userdir,
            "userdir_home": resolved_userdir_home,
            "start_id": start_id,
            "end_id": end_id,
            "chunk_size": chunk_size,
            "pragma_candidate_count": len(pragma_candidates),
            "pragma_candidate_hashes": [
                hashlib.sha256(str(item.get("pragma") or "").encode("utf-8", errors="ignore")).hexdigest()
                for item in pragma_candidates[:20]
            ],
            "compiler": compiler,
        },
        "summary": {
            "status": "running",
            "searched_start_id": start_id,
            "searched_end_id": start_id - 1,
            "searched_count": 0,
            "matched": False,
            "matched_user_id": "",
            "matched_user_id_sha256": "",
            "matched_pragma_variant": "",
            "matched_pragma_index": -1,
            "resume_next_start_id": start_id,
            "engine": "commoncrypto-native-helper",
        },
        "chunks": [],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    write_result(payload, output)

    helper_path = compile_userdir_bruteforce_helper(compiler=compiler)
    with tempfile.TemporaryDirectory(prefix="rapidtriage-kakao-userdir-") as tmp_dir:
        pragma_path = Path(tmp_dir) / "pragma-candidates.txt"
        pragma_path.write_text(
            "\n".join(str(item.get("pragma") or "") for item in pragma_candidates if item.get("pragma")),
            encoding="utf-8",
        )
        current = start_id
        while current <= end_id:
            chunk_end = min(end_id, current + chunk_size - 1)
            chunk_result = run_userdir_bruteforce_chunk(
                helper_path=helper_path,
                pragma_path=pragma_path,
                userdir_home=resolved_userdir_home,
                userdir=resolved_userdir,
                start_id=current,
                end_id=chunk_end,
            )
            chunks = list(payload["chunks"]) if isinstance(payload.get("chunks"), list) else []
            chunks.append(chunk_result)
            payload["chunks"] = chunks
            summary = dict(payload["summary"]) if isinstance(payload.get("summary"), dict) else {}
            summary["searched_end_id"] = chunk_end
            summary["searched_count"] = int(summary.get("searched_count") or 0) + (chunk_end - current + 1)
            summary["resume_next_start_id"] = chunk_end + 1
            if chunk_result.get("matched"):
                matched_user_id = str(chunk_result.get("matched_user_id") or "")
                summary["status"] = "matched"
                summary["matched"] = True
                summary["matched_user_id"] = matched_user_id
                summary["matched_user_id_sha256"] = hashlib.sha256(
                    matched_user_id.encode("utf-8", errors="ignore")
                ).hexdigest()
                pragma_index_value = chunk_result.get("matched_pragma_index")
                pragma_index = int(pragma_index_value) if pragma_index_value is not None else -1
                summary["matched_pragma_index"] = pragma_index
                if 0 <= pragma_index < len(pragma_candidates):
                    summary["matched_pragma_variant"] = str(pragma_candidates[pragma_index].get("variant") or "")
                summary["resume_next_start_id"] = ""
                payload["summary"] = summary
                write_result(payload, output)
                return payload
            payload["summary"] = summary
            write_result(payload, output)
            current = chunk_end + 1
    summary = dict(payload["summary"]) if isinstance(payload.get("summary"), dict) else {}
    summary["status"] = "not-matched"
    summary["matched"] = False
    payload["summary"] = summary
    write_result(payload, output)
    return payload


class DecryptAuth:
    def __init__(
        self,
        *,
        key: bytes | None,
        iv: bytes | None,
        source: str,
        missing: Sequence[str],
        pragma: str = "",
        deviceinfo_fields: Mapping[str, str] | None = None,
        user_id_candidates: Sequence[Mapping[str, object]] | None = None,
        user_id_auto_selected: bool = False,
        candidate_key_materials: Sequence[Mapping[str, object]] | None = None,
        stored_pragma_candidates: Sequence[Mapping[str, object]] | None = None,
    ) -> None:
        self.key = key
        self.iv = iv
        self.source = source
        self.missing = list(missing)
        self.pragma = pragma
        self.deviceinfo_fields = dict(deviceinfo_fields or {})
        self.user_id_candidates = [dict(item) for item in user_id_candidates or []]
        self.user_id_auto_selected = user_id_auto_selected
        self.candidate_key_materials = [dict(item) for item in candidate_key_materials or []]
        self.stored_pragma_candidates = [dict(item) for item in stored_pragma_candidates or []]

    @property
    def ready(self) -> bool:
        return (self.key is not None and self.iv is not None) or bool(self.candidate_key_materials)

    def public_summary(self) -> dict[str, object]:
        return {
            "ready": self.ready,
        "source": self.source,
        "missing": list(self.missing),
            "key_sha256": hashlib.sha256(self.key).hexdigest() if self.key else "",
            "iv_sha256": hashlib.sha256(self.iv).hexdigest() if self.iv else "",
            "pragma_sha256": hashlib.sha256(self.pragma.encode("utf-8", errors="ignore")).hexdigest()
            if self.pragma
            else "",
            "deviceinfo_present_fields": sorted(self.deviceinfo_fields),
            "user_id_candidate_count": len(self.user_id_candidates),
            "user_id_candidate_hashes": sorted(
                {
                    str(item.get("value_sha256") or "")
                    for item in self.user_id_candidates
                    if item.get("value_sha256")
                }
            )[:10],
            "user_id_auto_selected": self.user_id_auto_selected,
            "stored_pragma_candidate_count": len(self.stored_pragma_candidates),
            "stored_pragma_candidate_hashes": sorted(
                {
                    str(item.get("value_sha256") or "")
                    for item in self.stored_pragma_candidates
                    if item.get("value_sha256")
                }
            )[:10],
            "candidate_key_count": len(self.candidate_key_materials),
            "pk_candidate_count": sum(1 for item in self.candidate_key_materials if item.get("source") == "pk-memory-candidate"),
            "pk_candidate_hashes": sorted(
                {
                    str(item.get("pk_sha256") or "")
                    for item in self.candidate_key_materials
                    if item.get("pk_sha256")
                }
            )[:10],
            "key_redacted": True,
            "iv_redacted": True,
            "pragma_redacted": True,
            "deviceinfo_values_redacted": True,
            "user_id_values_redacted": True,
            "stored_pragma_values_redacted": True,
            "pk_values_redacted": True,
        }

    def key_candidates(self) -> list[dict[str, object]]:
        materials: list[dict[str, object]] = []
        if self.key is not None and self.iv is not None:
            materials.append(
                {
                    "key": self.key,
                    "iv": self.iv,
                    "source": self.source,
                    "user_id_sha256": "",
                    "pragma_variant": "",
                    "key_derivation": "direct-key-iv",
                }
            )
        materials.extend(self.candidate_key_materials)
        return materials


def resolve_decrypt_auth(
    *,
    key_hex: str | None,
    iv_hex: str | None,
    pragma: str | None,
    user_id: str | None,
    pragma_key_hex: str | None,
    sys_uuid: str | None,
    hdd_model: str | None,
    hdd_serial: str | None,
    key_hex_env: str | None,
    iv_hex_env: str | None,
    pragma_env: str | None,
    user_id_env: str | None,
    pragma_key_hex_env: str | None,
    sys_uuid_env: str | None,
    hdd_model_env: str | None,
    hdd_serial_env: str | None,
    deviceinfo_root: Path | None,
    openssl_bin: str,
) -> DecryptAuth:
    env_key = os.environ.get(key_hex_env or "") if key_hex_env else None
    env_iv = os.environ.get(iv_hex_env or "") if iv_hex_env else None
    env_pragma = os.environ.get(pragma_env or "") if pragma_env else None
    env_user_id = os.environ.get(user_id_env or "") if user_id_env else None
    env_pragma_key = os.environ.get(pragma_key_hex_env or "") if pragma_key_hex_env else None
    env_sys_uuid = os.environ.get(sys_uuid_env or "") if sys_uuid_env else None
    env_hdd_model = os.environ.get(hdd_model_env or "") if hdd_model_env else None
    env_hdd_serial = os.environ.get(hdd_serial_env or "") if hdd_serial_env else None

    resolved_key_hex = key_hex or env_key
    resolved_iv_hex = iv_hex or env_iv
    if resolved_key_hex or resolved_iv_hex:
        missing = []
        if not resolved_key_hex:
            missing.append("key_hex")
        if not resolved_iv_hex:
            missing.append("iv_hex")
        if missing:
            return DecryptAuth(key=None, iv=None, source="direct-key-iv", missing=missing)
        return DecryptAuth(
            key=parse_hex_bytes(str(resolved_key_hex), expected_len=16, field_name="key_hex"),
            iv=parse_hex_bytes(str(resolved_iv_hex), expected_len=16, field_name="iv_hex"),
            source="direct-key-iv",
            missing=[],
        )

    user_id_candidates = find_user_id_candidates_from_root(deviceinfo_root) if deviceinfo_root is not None else []
    stored_pragma_candidates = find_stored_pragma_candidates_from_root(deviceinfo_root) if deviceinfo_root is not None else []
    auto_user_id = choose_unambiguous_user_id(user_id_candidates)
    resolved_pragma = pragma or env_pragma
    resolved_pragma_key = pragma_key_hex or env_pragma_key
    resolved_user_id = user_id or env_user_id or auto_user_id
    user_id_auto_selected = bool(auto_user_id and not (user_id or env_user_id))
    candidate_user_ids = [
        str(candidate.get("value") or "").strip()
        for candidate in user_id_candidates
        if str(candidate.get("value") or "").strip()
    ]
    stored_pragma_values = [
        {
            "variant": str(candidate.get("variant") or candidate.get("field_name") or "stored-pragma"),
            "pragma": str(candidate.get("value") or "").strip(),
        }
        for candidate in stored_pragma_candidates
        if str(candidate.get("value") or "").strip()
    ]
    pk_candidates = find_pk_candidates_from_root(deviceinfo_root) if deviceinfo_root is not None else []
    pk_key_materials = build_candidate_key_materials_from_pk_candidates(pk_candidates)
    deviceinfo = resolve_deviceinfo_fields(
        deviceinfo_root=deviceinfo_root,
        sys_uuid=sys_uuid or env_sys_uuid,
        hdd_model=hdd_model or env_hdd_model,
        hdd_serial=hdd_serial or env_hdd_serial,
    )
    device_pragma_values: list[dict[str, str]] = []
    if all(deviceinfo.get(field) for field in DEVICEINFO_FIELDS):
        if resolved_pragma_key:
            device_pragma_values.extend(
                derive_pragma_candidates_from_deviceinfo(
                    pragma_key=parse_hex_bytes(str(resolved_pragma_key), expected_len=16, field_name="pragma_key_hex"),
                    sys_uuid=str(deviceinfo["sys_uuid"]),
                    hdd_model=str(deviceinfo["hdd_model"]),
                    hdd_serial=str(deviceinfo["hdd_serial"]),
                    openssl_bin=openssl_bin,
                )
            )
        else:
            device_pragma_values.extend(
                prefix_pragma_candidate_variants(
                    derive_pragma_candidates_from_deviceinfo(
                        pragma_key=bytes.fromhex(KAKAOTALK_DEVICE_PRAGMA_KEY_HEX),
                        sys_uuid=str(deviceinfo["sys_uuid"]),
                        hdd_model=str(deviceinfo["hdd_model"]),
                        hdd_serial=str(deviceinfo["hdd_serial"]),
                        openssl_bin=openssl_bin,
                    ),
                    "builtin-deviceinfo-key",
                )
            )
    if resolved_pragma and resolved_user_id and not user_id_auto_selected:
        return DecryptAuth(
            key=None,
            iv=None,
            source="pragma-user-id-candidates",
            missing=[],
            pragma=str(resolved_pragma),
            user_id_candidates=public_user_id_candidates(user_id_candidates),
            user_id_auto_selected=user_id_auto_selected,
            stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
            candidate_key_materials=[
                *build_candidate_key_materials_from_pragma(str(resolved_pragma), [str(resolved_user_id)]),
                *pk_key_materials,
            ],
        )
    if resolved_pragma and candidate_user_ids:
        return DecryptAuth(
            key=None,
            iv=None,
            source="pragma-user-id-candidates",
            missing=[],
            pragma=str(resolved_pragma),
            user_id_candidates=public_user_id_candidates(user_id_candidates),
            user_id_auto_selected=user_id_auto_selected,
            stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
            candidate_key_materials=[
                *build_candidate_key_materials_from_pragma(str(resolved_pragma), candidate_user_ids),
                *pk_key_materials,
            ],
        )
    derived_pragma_values = [*device_pragma_values, *stored_pragma_values]
    if not resolved_pragma_key and derived_pragma_values and (resolved_user_id or candidate_user_ids):
        users = [str(resolved_user_id)] if resolved_user_id else candidate_user_ids
        return DecryptAuth(
            key=None,
            iv=None,
            source="deviceinfo-stored-pragma-user-id-candidates",
            missing=[],
            pragma=derived_pragma_values[0]["pragma"],
            deviceinfo_fields={field: str(deviceinfo[field]) for field in DEVICEINFO_FIELDS if deviceinfo.get(field)},
            user_id_candidates=public_user_id_candidates(user_id_candidates),
            user_id_auto_selected=user_id_auto_selected,
            stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
            candidate_key_materials=build_candidate_key_materials_from_pragma_candidates(
                derived_pragma_values,
                users,
            )
            + pk_key_materials,
        )

    if resolved_pragma_key or deviceinfo:
        missing = []
        if not resolved_user_id and not candidate_user_ids:
            missing.append("user_id")
        for field in DEVICEINFO_FIELDS:
            if not deviceinfo.get(field):
                missing.append(field)
        if missing:
            return DecryptAuth(
                key=None,
                iv=None,
                source="deviceinfo-pragma-key-user-id",
                missing=missing,
                deviceinfo_fields={key: str(value) for key, value in deviceinfo.items() if value},
                user_id_candidates=public_user_id_candidates(user_id_candidates),
                user_id_auto_selected=user_id_auto_selected,
                stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
            )
        pragma_values = device_pragma_values
        if not resolved_user_id and candidate_user_ids:
            return DecryptAuth(
                key=None,
                iv=None,
                source="deviceinfo-pragma-key-user-id-candidates",
                missing=[],
                pragma=pragma_values[0]["pragma"] if pragma_values else "",
                deviceinfo_fields={field: str(deviceinfo[field]) for field in DEVICEINFO_FIELDS},
                user_id_candidates=public_user_id_candidates(user_id_candidates),
                stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
                candidate_key_materials=build_candidate_key_materials_from_pragma_candidates(
                    [*stored_pragma_values, *pragma_values],
                    candidate_user_ids,
                )
                + pk_key_materials,
            )
        return DecryptAuth(
            key=None,
            iv=None,
            source="deviceinfo-pragma-key-user-id-variants",
            missing=[],
            pragma=pragma_values[0]["pragma"] if pragma_values else "",
            deviceinfo_fields={field: str(deviceinfo[field]) for field in DEVICEINFO_FIELDS},
            user_id_candidates=public_user_id_candidates(user_id_candidates),
            user_id_auto_selected=user_id_auto_selected,
            stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
            candidate_key_materials=build_candidate_key_materials_from_pragma_candidates(
                [*stored_pragma_values, *pragma_values],
                [str(resolved_user_id)],
            )
            + pk_key_materials,
        )

    if pk_key_materials:
        return DecryptAuth(
            key=None,
            iv=None,
            source="pk-memory-candidates",
            missing=[],
            user_id_candidates=public_user_id_candidates(user_id_candidates),
            user_id_auto_selected=user_id_auto_selected,
            stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
            candidate_key_materials=pk_key_materials,
        )

    missing = []
    if not resolved_pragma:
        missing.append("pragma")
    if not resolved_user_id:
        missing.append("user_id")
    if missing:
        return DecryptAuth(
            key=None,
            iv=None,
            source="pragma-user-id",
            missing=missing,
            user_id_candidates=public_user_id_candidates(user_id_candidates),
            user_id_auto_selected=user_id_auto_selected,
            stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
        )
    return DecryptAuth(
        key=None,
        iv=None,
        source="pragma-user-id",
        missing=missing,
        user_id_candidates=public_user_id_candidates(user_id_candidates),
        user_id_auto_selected=user_id_auto_selected,
        stored_pragma_candidates=public_stored_pragma_candidates(stored_pragma_candidates),
    )


def parse_hex_bytes(value: str, *, expected_len: int, field_name: str) -> bytes:
    normalized = value.strip().lower().replace(":", "").replace(" ", "")
    try:
        parsed = bytes.fromhex(normalized)
    except ValueError as exc:
        raise KakaoTalkDecryptError(f"{field_name} must be hex") from exc
    if len(parsed) != expected_len:
        raise KakaoTalkDecryptError(f"{field_name} must decode to {expected_len} bytes")
    return parsed


def derive_kakaotalk_key_iv_from_pk(pk_value: str, *, repeat_to_512: bool = True) -> tuple[bytes, bytes]:
    seed = pk_value.encode("utf-8")
    if repeat_to_512:
        while len(seed) < 512:
            seed += seed
        seed = seed[:512]
    key = hashlib.md5(seed).digest()
    iv = hashlib.md5(base64.b64encode(key)).digest()
    return key, iv


def derive_kakaotalk_key_iv(pragma: str, user_id: str) -> tuple[bytes, bytes]:
    return derive_kakaotalk_key_iv_from_pk(pragma + user_id)


def derive_kakaotalk_userdir(
    *,
    pragma: str,
    userdir_home: str,
    user_id: str,
    openssl_bin: str,
) -> str:
    key1 = hashlib.md5(KAKAOTALK_USERDIR_KEY_SEED.encode("utf-8")).digest()
    iv1 = hashlib.md5(base64.b64encode(key1)).digest()
    encrypted_user_id = openssl_aes_128_cbc(
        pkcs7_pad(user_id.encode("utf-8"), BLOCK_SIZE),
        key=key1,
        iv=iv1,
        openssl_bin=openssl_bin,
        decrypt=False,
    )
    key2 = hashlib.md5(pragma.encode("utf-8")).digest()
    iv2 = hashlib.md5(base64.b64encode(key2)).digest()
    second_input = f"{userdir_home}\\{encrypted_user_id.hex()}".encode("utf-8")
    encrypted_second = openssl_aes_128_cbc(
        pkcs7_pad(second_input, BLOCK_SIZE),
        key=key2,
        iv=iv2,
        openssl_bin=openssl_bin,
        decrypt=False,
    )
    return hashlib.sha1(encrypted_second).hexdigest()


def infer_kakaotalk_userdir(root: Path) -> str:
    candidates: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_dir() or not USERDIR_PATTERN.fullmatch(path.name):
            continue
        if (path / "chat_data").is_dir() or any(child.name.lower().endswith(".edb") for child in path.iterdir() if child.is_file()):
            candidates.append(path.name.lower())
    if len(set(candidates)) == 1:
        return candidates[0]
    return candidates[0] if candidates else ""


def infer_kakaotalk_userdir_home(root: Path) -> str:
    profile = infer_windows_user_profile_from_root(root)
    if not profile:
        return ""
    return f"{profile}\\AppData\\Local\\Kakao\\KakaoTalk\\users"


def infer_windows_user_profile_from_root(root: Path) -> str:
    counts: Counter[str] = Counter()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        if path.name.upper() not in {"NTUSER.DAT", "USRCLASS.DAT", "SOFTWARE", "SYSTEM"} and path.stat().st_size > 32 * 1024 * 1024:
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        for match in re.finditer(rb"C:\\Users\\[A-Za-z0-9._ -]{1,80}", blob):
            value = match.group(0).decode("ascii", errors="ignore").rstrip(" .")
            counts[value] += 1
        try:
            ascii_blob = blob.decode("utf-16le", errors="ignore").encode("ascii", errors="ignore")
        except UnicodeError:
            ascii_blob = b""
        for match in re.finditer(rb"C:\\Users\\[A-Za-z0-9._ -]{1,80}", ascii_blob):
            value = match.group(0).decode("ascii", errors="ignore").rstrip(" .")
            counts[value] += 1
    if not counts:
        return ""
    return counts.most_common(1)[0][0]


def resolve_userdir_pragma_candidates(
    root: Path,
    *,
    pragma: str | None,
    pragma_key_hex: str | None,
    sys_uuid: str | None,
    hdd_model: str | None,
    hdd_serial: str | None,
    openssl_bin: str,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    if pragma:
        candidates.append({"variant": "provided-pragma", "pragma": pragma})
        seen.add(pragma)
    for stored in find_stored_pragma_candidates_from_root(root):
        value = str(stored.get("value") or "")
        if value and value not in seen:
            seen.add(value)
            candidates.append({"variant": str(stored.get("variant") or "stored-pragma"), "pragma": value})
    if pragma_key_hex:
        deviceinfo = resolve_deviceinfo_fields(
            deviceinfo_root=root,
            sys_uuid=sys_uuid,
            hdd_model=hdd_model,
            hdd_serial=hdd_serial,
        )
        missing = [field for field in DEVICEINFO_FIELDS if not deviceinfo.get(field)]
        if missing:
            raise KakaoTalkDecryptError(f"DeviceInfo fields missing for userDir brute force: {', '.join(missing)}")
        for item in derive_pragma_candidates_from_deviceinfo(
            pragma_key=parse_hex_bytes(pragma_key_hex, expected_len=16, field_name="pragma_key_hex"),
            sys_uuid=deviceinfo["sys_uuid"],
            hdd_model=deviceinfo["hdd_model"],
            hdd_serial=deviceinfo["hdd_serial"],
            openssl_bin=openssl_bin,
        ):
            value = str(item.get("pragma") or "")
            if value and value not in seen:
                seen.add(value)
                candidates.append(dict(item))
    return candidates


def compile_userdir_bruteforce_helper(*, compiler: str) -> Path:
    compiler_path = shutil.which(compiler)
    if not compiler_path:
        raise KakaoTalkDecryptError(f"Compiler not found for native userDir brute force helper: {compiler}")
    temp_dir = Path(tempfile.mkdtemp(prefix="rapidtriage-kakao-userdir-helper-"))
    source_path = temp_dir / "kakao_userdir_bruteforce.c"
    binary_path = temp_dir / "kakao_userdir_bruteforce"
    source_path.write_text(KAKAOTALK_USERDIR_BRUTEFORCE_C_SOURCE, encoding="utf-8")
    proc = subprocess.run(
        [compiler_path, "-O3", str(source_path), "-o", str(binary_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise KakaoTalkDecryptError(
            "Failed to compile native userDir brute force helper: "
            + proc.stderr.decode("utf-8", errors="replace")[:2000]
        )
    return binary_path


def run_userdir_bruteforce_chunk(
    *,
    helper_path: Path,
    pragma_path: Path,
    userdir_home: str,
    userdir: str,
    start_id: int,
    end_id: int,
) -> dict[str, object]:
    started_at = dt.datetime.now()
    proc = subprocess.run(
        [str(helper_path), str(pragma_path), userdir_home, userdir, str(start_id), str(end_id)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    finished_at = dt.datetime.now()
    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    result: dict[str, object] = {
        "start_id": start_id,
        "end_id": end_id,
        "searched_count": end_id - start_id + 1,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
        "matched": False,
        "matched_user_id": "",
        "matched_user_id_sha256": "",
        "matched_pragma_index": -1,
        "status": "not-matched" if proc.returncode == 1 else "error",
        "stdout_preview": stdout[:200],
        "stderr_preview": stderr[:500],
    }
    match = re.search(r"^MATCH pragma_index=(?P<pragma_index>\d+) uid=(?P<uid>\d+)", stdout)
    if proc.returncode == 0 and match:
        uid = match.group("uid")
        result.update(
            {
                "matched": True,
                "matched_user_id": uid,
                "matched_user_id_sha256": hashlib.sha256(uid.encode("utf-8", errors="ignore")).hexdigest(),
                "matched_pragma_index": int(match.group("pragma_index")),
                "status": "matched",
            }
        )
        return result
    if proc.returncode not in {0, 1}:
        raise KakaoTalkDecryptError(f"userDir brute force helper failed: {stderr or stdout}")
    return result


def build_candidate_key_materials_from_pragma(pragma: str, user_ids: Sequence[str]) -> list[dict[str, object]]:
    return build_candidate_key_materials_from_pragma_candidates(
        [{"variant": "provided-pragma", "pragma": pragma}],
        user_ids,
    )


def build_candidate_key_materials_from_pragma_candidates(
    pragma_candidates: Sequence[Mapping[str, str]],
    user_ids: Sequence[str],
) -> list[dict[str, object]]:
    materials: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for pragma_candidate in pragma_candidates:
        pragma = str(pragma_candidate.get("pragma") or "")
        variant = str(pragma_candidate.get("variant") or "")
        if not pragma:
            continue
        for user_id in user_ids[:20]:
            normalized = normalize_kakaotalk_user_id_value(user_id)
            if not normalized:
                continue
            for derivation_name, repeat_to_512 in (("repeat512-md5", True), ("direct-md5", False)):
                key_id = (variant, normalized, derivation_name)
                if key_id in seen:
                    continue
                seen.add(key_id)
                key, iv = derive_kakaotalk_key_iv_from_pk(pragma + normalized, repeat_to_512=repeat_to_512)
                materials.append(
                    {
                        "key": key,
                        "iv": iv,
                        "source": "user-id-candidate",
                        "user_id_sha256": hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest(),
                        "pragma_variant": variant,
                        "key_derivation": derivation_name,
                    }
                )
    return materials


def build_candidate_key_materials_from_pk_candidates(pk_candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    materials: list[dict[str, object]] = []
    seen: set[str] = set()
    for candidate in pk_candidates[:40]:
        pk_value = str(candidate.get("pk") or "")
        if not pk_value or pk_value in seen:
            continue
        seen.add(pk_value)
        key, iv = derive_kakaotalk_key_iv_from_pk(pk_value)
        materials.append(
            {
                "key": key,
                "iv": iv,
                "source": "pk-memory-candidate",
                "user_id_sha256": hashlib.sha256(str(candidate.get("uid") or "").encode("utf-8", errors="ignore")).hexdigest()
                if candidate.get("uid")
                else "",
                "pk_sha256": hashlib.sha256(pk_value.encode("utf-8", errors="ignore")).hexdigest(),
                "pragma_variant": "memory-or-file-pk-candidate",
                "key_derivation": "repeat512-md5",
                "source_path": str(candidate.get("source_path") or ""),
                "source_offset": int(candidate.get("source_offset") or -1),
            }
        )
    return materials


def derive_pragma_candidates_from_deviceinfo(
    *,
    pragma_key: bytes,
    sys_uuid: str,
    hdd_model: str,
    hdd_serial: str,
    openssl_bin: str,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    seed_variants = [
        ("pipe", f"{sys_uuid}|{hdd_model}|{hdd_serial}".encode("utf-8")),
        ("concat", f"{sys_uuid}{hdd_model}{hdd_serial}".encode("utf-8")),
    ]
    for seed_name, seed in seed_variants:
        payloads = [(f"{seed_name}-pkcs7", pkcs7_pad(seed, BLOCK_SIZE))]
        if len(seed) % BLOCK_SIZE == 0:
            payloads.append((f"{seed_name}-nopad", seed))
        for payload_name, payload in payloads:
            encrypted = openssl_aes_128_cbc(
                payload,
                key=pragma_key,
                iv=bytes(BLOCK_SIZE),
                openssl_bin=openssl_bin,
                decrypt=False,
            )
            encrypted_b64 = base64.b64encode(encrypted)
            variant_values = [
                (f"{payload_name}-aes-ciphertext-base64", encrypted_b64.decode("ascii")),
                (
                    f"{payload_name}-sha512-ciphertext-base64",
                    base64.b64encode(hashlib.sha512(encrypted).digest()).decode("ascii"),
                ),
                (
                    f"{payload_name}-sha512-base64-ciphertext-base64",
                    base64.b64encode(hashlib.sha512(encrypted_b64).digest()).decode("ascii"),
                ),
            ]
            for variant, pragma in variant_values:
                if pragma in seen:
                    continue
                seen.add(pragma)
                candidates.append({"variant": variant, "pragma": pragma})
    return candidates


def prefix_pragma_candidate_variants(
    candidates: Sequence[Mapping[str, str]],
    prefix: str,
) -> list[dict[str, str]]:
    return [
        {
            "variant": f"{prefix}-{candidate.get('variant', '')}",
            "pragma": str(candidate.get("pragma") or ""),
        }
        for candidate in candidates
        if candidate.get("pragma")
    ]


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def derive_pragma_from_deviceinfo(
    *,
    pragma_key: bytes,
    sys_uuid: str,
    hdd_model: str,
    hdd_serial: str,
    openssl_bin: str,
) -> str:
    return derive_pragma_candidates_from_deviceinfo(
        pragma_key=pragma_key,
        sys_uuid=sys_uuid,
        hdd_model=hdd_model,
        hdd_serial=hdd_serial,
        openssl_bin=openssl_bin,
    )[0]["pragma"]


def resolve_deviceinfo_fields(
    *,
    deviceinfo_root: Path | None,
    sys_uuid: str | None,
    hdd_model: str | None,
    hdd_serial: str | None,
) -> dict[str, str]:
    values = {
        "sys_uuid": sys_uuid or "",
        "hdd_model": hdd_model or "",
        "hdd_serial": hdd_serial or "",
    }
    if all(values.values()) or deviceinfo_root is None:
        return {key: value for key, value in values.items() if value}
    extracted = extract_deviceinfo_from_root(deviceinfo_root)
    for key in DEVICEINFO_FIELDS:
        if not values.get(key) and extracted.get(key):
            values[key] = extracted[key]
    return {key: value for key, value in values.items() if value}


def extract_deviceinfo_from_root(root: Path) -> dict[str, str]:
    for hive_path in sorted(root.rglob("NTUSER.DAT"), key=lambda item: str(item).lower()):
        values = extract_deviceinfo_from_native_hive(hive_path)
        if values:
            return values
    return {}


def extract_deviceinfo_from_native_hive(path: Path) -> dict[str, str]:
    try:
        blob = path.read_bytes()
    except OSError:
        return {}
    values: dict[str, str] = {}
    for field in DEVICEINFO_FIELDS:
        aliases = DEVICEINFO_FIELD_ALIASES.get(field, (field,))
        for alias in aliases:
            matched = False
            for field_bytes in {alias.encode("ascii"), alias.lower().encode("ascii"), alias.upper().encode("ascii")}:
                if not field_bytes:
                    continue
                start = 0
                while True:
                    index = blob.find(field_bytes, start)
                    if index < 0:
                        break
                    candidate = decode_vk_value_at_name_offset(blob, index)
                    if candidate and str(candidate.get("name") or "").lower() == alias.lower():
                        preview = registry_value_data_preview(blob, candidate)
                        if preview:
                            values[field] = preview
                            matched = True
                            break
                    start = index + len(field_bytes)
                if matched:
                    break
            if matched:
                break
    return values


def decode_vk_value_at_name_offset(blob: bytes, name_offset: int) -> dict[str, object] | None:
    signature_offset = name_offset - 20
    cell_offset = signature_offset - 4
    if cell_offset < 0 or blob[signature_offset : signature_offset + 2] != b"vk":
        return None
    cell_size_raw = int.from_bytes(blob[cell_offset:signature_offset], "little", signed=True)
    cell_size = abs(cell_size_raw)
    if cell_size <= 0 or cell_size > 4096:
        return None
    return parse_registry_vk_cell(blob, cell_offset, signature_offset, cell_size, cell_size_raw)


def find_user_id_candidates_from_root(root: Path) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for reg_path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
        candidates.extend(extract_user_id_candidates_from_reg_export(reg_path))
        if len(candidates) >= 20:
            return dedupe_user_id_candidates(candidates)
    for hive_path in sorted(root.rglob("NTUSER.DAT"), key=lambda item: str(item).lower()):
        candidates.extend(extract_user_id_candidates_from_native_hive(hive_path))
        if len(candidates) >= 20:
            return dedupe_user_id_candidates(candidates)
    return dedupe_user_id_candidates(candidates)


def find_stored_pragma_candidates_from_root(root: Path) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for reg_path in sorted(root.rglob("*.reg"), key=lambda item: str(item).lower()):
        candidates.extend(extract_stored_pragma_candidates_from_reg_export(reg_path))
        if len(candidates) >= 20:
            return dedupe_stored_pragma_candidates(candidates)
    for hive_path in sorted(root.rglob("NTUSER.DAT"), key=lambda item: str(item).lower()):
        candidates.extend(extract_stored_pragma_candidates_from_native_hive(hive_path))
        if len(candidates) >= 20:
            return dedupe_stored_pragma_candidates(candidates)
    return dedupe_stored_pragma_candidates(candidates)


def find_pk_candidates_from_root(root: Path) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for path in iter_key_material_scan_paths(root):
        candidates.extend(scan_pk_candidates_from_file(path))
        if len(candidates) >= 40:
            break
    return dedupe_pk_candidates(candidates)


def iter_key_material_scan_paths(root: Path) -> list[Path]:
    weighted: list[tuple[int, str, Path]] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        lowered = str(path).lower()
        name = path.name.lower()
        score = 50
        if any(term in lowered for term in ("memory", "memdump", "process", "kakaotalk", "dump", ".dmp", ".raw")):
            score -= 30
        if name in {"ntuser.dat", "software", "system", "sam", "security"}:
            score -= 5
        if path.suffix.lower() in {".edb", ".sqlite", ".db", ".wal", ".shm"}:
            score += 20
        weighted.append((score, lowered, path))
    return [item[2] for item in sorted(weighted)[:200]]


def scan_pk_candidates_from_file(path: Path) -> list[dict[str, object]]:
    try:
        file_size = path.stat().st_size
    except OSError:
        return []
    limit = min(file_size, KEY_MATERIAL_SCAN_LIMIT)
    candidates: list[dict[str, object]] = []
    tail = b""
    offset = 0
    try:
        with path.open("rb") as handle:
            remaining = limit
            while remaining > 0 and len(candidates) < 20:
                chunk = handle.read(min(KEY_MATERIAL_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                data = tail + chunk
                data_offset = offset - len(tail)
                candidates.extend(pk_candidates_from_bytes(data, data_offset, path, encoding="ascii"))
                try:
                    utf16_text = data.decode("utf-16le", errors="ignore").encode("ascii", errors="ignore")
                except UnicodeError:
                    utf16_text = b""
                if utf16_text:
                    candidates.extend(pk_candidates_from_bytes(utf16_text, data_offset, path, encoding="utf-16le-normalized"))
                tail = data[-256:]
                offset += len(chunk)
                remaining -= len(chunk)
    except OSError:
        return []
    return candidates[:20]


def pk_candidates_from_bytes(data: bytes, data_offset: int, path: Path, *, encoding: str) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for match in PK_PATTERN.finditer(data):
        pragma = match.group(1).decode("ascii", errors="ignore")
        uid = match.group(2).decode("ascii", errors="ignore")
        pk_value = pragma + uid
        candidates.append(
            {
                "pk": pk_value,
                "uid": uid,
                "source_path": str(path.resolve()),
                "source_offset": data_offset + match.start(),
                "encoding": encoding,
                "confidence": 0.78,
            }
        )
    return candidates


def dedupe_pk_candidates(candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    deduped: dict[str, dict[str, object]] = {}
    for candidate in candidates:
        pk_value = str(candidate.get("pk") or "")
        if not pk_value:
            continue
        if pk_value not in deduped or float(candidate.get("confidence") or 0) > float(deduped[pk_value].get("confidence") or 0):
            deduped[pk_value] = dict(candidate)
    return sorted(deduped.values(), key=lambda item: (-float(item.get("confidence") or 0), str(item.get("source_path") or "")))


def extract_user_id_candidates_from_reg_export(path: Path) -> list[dict[str, object]]:
    lines = read_registry_export_lines(path)
    candidates: list[dict[str, object]] = []
    in_kakaotalk = False
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_kakaotalk = r"\software\kakao\kakaotalk" in stripped.lower()
            continue
        if not in_kakaotalk:
            continue
        match = re.match(r'"(?P<name>[^"]+)"=(?:"(?P<string>.*)"|(?P<raw>.+))$', stripped)
        if not match:
            continue
        name = canonical_user_id_field_name(match.group("name"))
        if not name:
            continue
        value = normalize_kakaotalk_user_id_value(
            match.group("string") if match.group("string") is not None else match.group("raw") or ""
        )
        if not looks_like_kakaotalk_user_id(value):
            continue
        candidates.append(
            {
                "value": value,
                "field_name": name,
                "source_path": str(path.resolve()),
                "source_subtype": "reg-export-user-id",
                "line_number": line_number,
                "confidence": 0.7,
            }
        )
    return candidates


def extract_stored_pragma_candidates_from_reg_export(path: Path) -> list[dict[str, object]]:
    lines = read_registry_export_lines(path)
    candidates: list[dict[str, object]] = []
    in_kakaotalk = False
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            lowered = stripped.lower()
            in_kakaotalk = r"\software\kakao\kakaotalk" in lowered and "deviceinfo" in lowered
            continue
        if not in_kakaotalk:
            continue
        match = re.match(r'"(?P<name>[^"]+)"=(?:"(?P<string>.*)"|(?P<raw>.+))$', stripped)
        if not match:
            continue
        name = canonical_stored_pragma_field_name(match.group("name"))
        if not name:
            continue
        value = normalize_kakaotalk_token_value(
            match.group("string") if match.group("string") is not None else match.group("raw") or ""
        )
        if not looks_like_stored_pragma_material(value):
            continue
        candidates.append(
            {
                "value": value,
                "field_name": name,
                "variant": f"registry-{name}-stored-pragma",
                "source_path": str(path.resolve()),
                "source_subtype": "reg-export-stored-pragma",
                "line_number": line_number,
                "confidence": 0.62,
            }
        )
    return candidates


def extract_user_id_candidates_from_native_hive(path: Path) -> list[dict[str, object]]:
    try:
        blob = path.read_bytes()
    except OSError:
        return []
    candidates: list[dict[str, object]] = []
    for field in USER_ID_FIELD_NAMES:
        field_needles = [field.encode("ascii", errors="ignore")]
        if any(ch.isupper() for ch in field):
            field_needles.append(field.lower().encode("ascii", errors="ignore"))
        for field_bytes in field_needles:
            if not field_bytes:
                continue
            start = 0
            while True:
                index = blob.find(field_bytes, start)
                if index < 0:
                    break
                candidate = decode_vk_value_at_name_offset(blob, index)
                if candidate and str(candidate.get("name") or "").lower() == field.lower():
                    preview = registry_value_data_preview(blob, candidate)
                    normalized_preview = normalize_kakaotalk_user_id_value(preview)
                    if preview and looks_like_kakaotalk_user_id(normalized_preview):
                        candidates.append(
                            {
                                "value": normalized_preview,
                                "field_name": field,
                                "source_path": str(path.resolve()),
                                "source_subtype": "native-hive-user-id-value",
                                "source_offset": int(candidate.get("cell_offset") or max(0, index - 24)),
                                "confidence": 0.76,
                            }
                        )
                        break
                start = index + len(field_bytes)
            if any(item.get("field_name") == field for item in candidates):
                break
    return candidates


def extract_stored_pragma_candidates_from_native_hive(path: Path) -> list[dict[str, object]]:
    try:
        blob = path.read_bytes()
    except OSError:
        return []
    candidates: list[dict[str, object]] = []
    for field in STORED_PRAGMA_FIELD_NAMES:
        field_bytes = field.encode("ascii", errors="ignore")
        start = 0
        while True:
            index = blob.find(field_bytes, start)
            if index < 0:
                break
            candidate = decode_vk_value_at_name_offset(blob, index)
            if candidate and str(candidate.get("name") or "").lower() == field.lower():
                preview = registry_value_data_preview(blob, candidate)
                normalized_preview = normalize_kakaotalk_token_value(preview)
                if preview and looks_like_stored_pragma_material(normalized_preview):
                    candidates.append(
                        {
                            "value": normalized_preview,
                            "field_name": field,
                            "variant": f"native-hive-{field}-stored-pragma",
                            "source_path": str(path.resolve()),
                            "source_subtype": "native-hive-stored-pragma-value",
                            "source_offset": int(candidate.get("cell_offset") or max(0, index - 24)),
                            "confidence": 0.68,
                        }
                    )
                    break
            start = index + len(field_bytes)
    return candidates


def read_registry_export_lines(path: Path) -> list[str]:
    for encoding in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            return path.read_text(encoding=encoding).splitlines()
        except (OSError, UnicodeError):
            continue
    return []


def canonical_user_id_field_name(name: str) -> str:
    lowered = name.lower()
    for field in USER_ID_FIELD_NAMES:
        if lowered == field.lower():
            return field
    return ""


def canonical_stored_pragma_field_name(name: str) -> str:
    lowered = name.lower()
    for field in STORED_PRAGMA_FIELD_NAMES:
        if lowered == field.lower():
            return field
    return ""


def looks_like_kakaotalk_user_id(value: str) -> bool:
    stripped = value.strip().strip('"')
    if not stripped or len(stripped) > 160:
        return False
    if stripped.lower().startswith("hex:"):
        return False
    if re.fullmatch(r"[0-9]{3,20}", stripped):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,128}", stripped):
        return True
    if re.fullmatch(r"[A-Za-z0-9+/=_.:-]{8,160}", stripped):
        return True
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", stripped):
        return True
    return False


def looks_like_stored_pragma_material(value: str) -> bool:
    stripped = value.strip().strip('"')
    if not stripped or len(stripped) > 256:
        return False
    if stripped.lower().startswith("hex:"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]{16,256}", stripped))


def normalize_kakaotalk_user_id_value(value: str) -> str:
    return normalize_kakaotalk_token_value(value)


def normalize_kakaotalk_token_value(value: str) -> str:
    stripped = value.strip().strip('"')
    allowed = re.findall(r"[A-Za-z0-9+/=_.:-]+", stripped)
    if not allowed:
        return stripped
    return max(allowed, key=len)


def dedupe_user_id_candidates(candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str], dict[str, object]] = {}
    for candidate in candidates:
        value = str(candidate.get("value") or "").strip()
        field_name = str(candidate.get("field_name") or "")
        if not value:
            continue
        key = (value, field_name.lower())
        if key not in deduped or float(candidate.get("confidence") or 0) > float(deduped[key].get("confidence") or 0):
            deduped[key] = dict(candidate)
    return sorted(deduped.values(), key=lambda item: (-float(item.get("confidence") or 0), str(item.get("field_name") or "")))


def dedupe_stored_pragma_candidates(candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    deduped: dict[tuple[str, str], dict[str, object]] = {}
    for candidate in candidates:
        value = str(candidate.get("value") or "").strip()
        field_name = str(candidate.get("field_name") or "")
        if not value:
            continue
        key = (value, field_name.lower())
        if key not in deduped or float(candidate.get("confidence") or 0) > float(deduped[key].get("confidence") or 0):
            deduped[key] = dict(candidate)
    return sorted(deduped.values(), key=lambda item: (-float(item.get("confidence") or 0), str(item.get("field_name") or "")))


def choose_unambiguous_user_id(candidates: Sequence[Mapping[str, object]]) -> str:
    high_confidence_values = {
        str(candidate.get("value") or "").strip()
        for candidate in candidates
        if float(candidate.get("confidence") or 0) >= 0.68 and looks_like_kakaotalk_user_id(str(candidate.get("value") or ""))
    }
    if len(high_confidence_values) == 1:
        return next(iter(high_confidence_values))
    return ""


def public_user_id_candidates(candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    public: list[dict[str, object]] = []
    for candidate in candidates[:20]:
        value = str(candidate.get("value") or "")
        public.append(
            {
                "field_name": str(candidate.get("field_name") or ""),
                "source_path": str(candidate.get("source_path") or ""),
                "source_subtype": str(candidate.get("source_subtype") or ""),
                "value_sha256": hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest() if value else "",
                "value_shape": classify_user_id_shape(value),
                "confidence": float(candidate.get("confidence") or 0.0),
                "value_redacted": True,
            }
        )
    return public


def public_stored_pragma_candidates(candidates: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    public: list[dict[str, object]] = []
    for candidate in candidates[:20]:
        value = str(candidate.get("value") or "")
        public.append(
            {
                "field_name": str(candidate.get("field_name") or ""),
                "variant": str(candidate.get("variant") or ""),
                "source_path": str(candidate.get("source_path") or ""),
                "source_subtype": str(candidate.get("source_subtype") or ""),
                "value_sha256": hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest() if value else "",
                "value_shape": classify_stored_pragma_shape(value),
                "confidence": float(candidate.get("confidence") or 0.0),
                "value_redacted": True,
            }
        )
    return public


def classify_stored_pragma_shape(value: str) -> str:
    stripped = value.strip().strip('"')
    if re.fullmatch(r"[A-Za-z0-9+/=]{80,128}", stripped):
        return "base64-digest-like"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,79}", stripped):
        return "stored-token-prefix"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{129,256}", stripped):
        return "long-stored-token"
    return "unknown"


def classify_user_id_shape(value: str) -> str:
    stripped = value.strip().strip('"')
    if re.fullmatch(r"[0-9]{3,20}", stripped):
        return "numeric-id"
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", stripped):
        return "uuid-like"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,128}", stripped):
        return "opaque-token"
    if re.fullmatch(r"[A-Za-z0-9+/=_.:-]{8,160}", stripped):
        return "structured-token"
    return "unknown"


def find_chatlog_databases(root: Path) -> list[Path]:
    return [
        path
        for path in sorted(root.rglob("chatLogs_*.edb"), key=lambda item: str(item).lower())
        if path.is_file() and CHATLOG_PATTERN.match(path.name)
    ]


def analyze_chatlog_database(
    path: Path,
    *,
    auth: DecryptAuth,
    include_message_preview: bool,
    write_decrypted: bool,
    decrypted_dir: Path,
    max_messages: int,
    openssl_bin: str,
) -> dict[str, object]:
    stat_size = path.stat().st_size
    chat_id = chat_id_from_path(path)
    entry: dict[str, object] = {
        "source_path": str(path.resolve()),
        "source_hashes": dict(compute_hashes(path)),
        "chat_id": chat_id,
        "source_size": stat_size,
        "source_size_multiple_of_4096": stat_size % PAGE_SIZE == 0,
        "source_header_hex": read_header_hex(path),
        "decrypt_status": "not-attempted-auth-material-missing",
        "sqlite_status": "not-attempted",
        "decrypted_sha256": "",
        "decrypted_path": "",
        "matched_key_source": "",
        "matched_pragma_variant": "",
        "matched_key_derivation": "",
        "matched_user_id_sha256": "",
        "tables": [],
        "message_table_candidates": [],
        "message_row_count": 0,
        "message_previews": [],
        "errors": [],
        "validation": {
            "expected_success_header": SQLITE_HEADER.decode("ascii"),
            "sqlite_header_confirmed": False,
            "message_content_reportable": False,
            "validation_required": True,
            "candidate_key_validated_by_sqlite_header": False,
        },
    }
    if not auth.ready:
        entry["errors"] = [f"missing auth material: {', '.join(auth.missing)}"]
        return entry

    temp_path: Path | None = None
    try:
        decrypted = b""
        matched_material: Mapping[str, object] | None = None
        candidate_errors: list[str] = []
        for material in auth.key_candidates():
            material_key = material.get("key") if isinstance(material.get("key"), bytes) else b""
            material_iv = material.get("iv") if isinstance(material.get("iv"), bytes) else b""
            try:
                candidate_header = decrypt_kakaotalk_header(
                    path,
                    key=material_key,
                    iv=material_iv,
                    openssl_bin=openssl_bin,
                )
            except (KakaoTalkDecryptError, OSError, subprocess.SubprocessError) as exc:
                candidate_errors.append(str(exc))
                continue
            if candidate_header.startswith(SQLITE_HEADER):
                decrypted = decrypt_kakaotalk_edb(path, key=material_key, iv=material_iv, openssl_bin=openssl_bin)
                matched_material = material
                break
        if not decrypted:
            entry["decrypt_status"] = "candidate-keys-tried-sqlite-header-not-found" if auth.key_candidates() else "failed"
            entry["sqlite_status"] = "sqlite-header-not-found"
            entry["errors"] = candidate_errors[:5]
            entry["validation"] = {**dict(entry["validation"]), "sqlite_header_confirmed": False}
            return entry
        entry["decrypt_status"] = "success"
        entry["decrypted_sha256"] = hashlib.sha256(decrypted).hexdigest()
        if matched_material:
            entry["matched_key_source"] = str(matched_material.get("source") or "")
            entry["matched_pragma_variant"] = str(matched_material.get("pragma_variant") or "")
            entry["matched_key_derivation"] = str(matched_material.get("key_derivation") or "")
            entry["matched_user_id_sha256"] = str(matched_material.get("user_id_sha256") or "")

        if write_decrypted:
            decrypted_path = decrypted_dir / f"{path.stem}.sqlite"
            decrypted_path.write_bytes(decrypted)
            temp_path = decrypted_path
            entry["decrypted_path"] = str(decrypted_path)
        else:
            temp_file = tempfile.NamedTemporaryFile(prefix=f"{path.stem}-", suffix=".sqlite", delete=False)
            temp_file.write(decrypted)
            temp_file.close()
            temp_path = Path(temp_file.name)

        sqlite_result = inspect_decrypted_sqlite(
            temp_path,
            include_message_preview=include_message_preview,
            max_messages=max_messages,
        )
        entry.update(sqlite_result)
        entry["sqlite_status"] = "opened"
        entry["validation"] = {
            **dict(entry["validation"]),
            "sqlite_header_confirmed": True,
            "candidate_key_validated_by_sqlite_header": bool(matched_material and matched_material.get("user_id_sha256")),
            "message_content_reportable": include_message_preview and int(sqlite_result.get("message_row_count") or 0) > 0,
        }
    except (KakaoTalkDecryptError, OSError, sqlite3.DatabaseError, subprocess.SubprocessError) as exc:
        entry["decrypt_status"] = "failed"
        entry["errors"] = [str(exc)]
    finally:
        if temp_path is not None and not write_decrypted:
            try:
                temp_path.unlink()
            except OSError:
                pass
    return entry


def decrypt_kakaotalk_edb(path: Path, *, key: bytes, iv: bytes, openssl_bin: str) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise KakaoTalkDecryptError("KakaoTalk legacy decrypt requires a 16-byte AES key and 16-byte IV")
    if shutil.which(openssl_bin) is None:
        raise KakaoTalkDecryptError(f"OpenSSL binary not found: {openssl_bin}")
    output = bytearray()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(PAGE_SIZE)
            if not chunk:
                break
            if len(chunk) % BLOCK_SIZE != 0:
                raise KakaoTalkDecryptError(f"Encrypted page is not {BLOCK_SIZE}-byte aligned: {path}")
            output.extend(openssl_aes_128_cbc(chunk, key=key, iv=iv, openssl_bin=openssl_bin, decrypt=True))
    return bytes(output)


def decrypt_kakaotalk_header(path: Path, *, key: bytes, iv: bytes, openssl_bin: str) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise KakaoTalkDecryptError("KakaoTalk legacy decrypt requires a 16-byte AES key and 16-byte IV")
    if shutil.which(openssl_bin) is None:
        raise KakaoTalkDecryptError(f"OpenSSL binary not found: {openssl_bin}")
    with path.open("rb") as handle:
        chunk = handle.read(PAGE_SIZE)
    if not chunk:
        return b""
    if len(chunk) % BLOCK_SIZE != 0:
        raise KakaoTalkDecryptError(f"Encrypted page is not {BLOCK_SIZE}-byte aligned: {path}")
    return openssl_aes_128_cbc(chunk, key=key, iv=iv, openssl_bin=openssl_bin, decrypt=True)


def openssl_aes_128_cbc(data: bytes, *, key: bytes, iv: bytes, openssl_bin: str, decrypt: bool) -> bytes:
    mode = "-d" if decrypt else "-e"
    proc = subprocess.run(
        [
            openssl_bin,
            "enc",
            "-aes-128-cbc",
            mode,
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
            "-nopad",
        ],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise KakaoTalkDecryptError(proc.stderr.decode("utf-8", errors="replace").strip() or "OpenSSL AES failed")
    return proc.stdout


def inspect_decrypted_sqlite(
    path: Path,
    *,
    include_message_preview: bool,
    max_messages: int,
) -> dict[str, object]:
    connection = sqlite3.connect(sqlite_readonly_uri(path, immutable=True), uri=True)
    try:
        tables = list_tables(connection)
        candidates = []
        previews = []
        total_messages = 0
        for table in tables:
            columns = table_columns(connection, table)
            candidate = build_message_table_candidate(connection, table, columns, max_messages=max_messages)
            if candidate is None:
                continue
            total_messages += int(candidate.get("row_count") or 0)
            if include_message_preview:
                previews.extend(candidate.get("message_previews") or [])
            candidate_without_previews = dict(candidate)
            candidate_without_previews.pop("message_previews", None)
            candidates.append(candidate_without_previews)
        return {
            "tables": tables,
            "message_table_candidates": candidates,
            "message_row_count": total_messages,
            "message_previews": previews[:max_messages] if include_message_preview else [],
        }
    finally:
        connection.close()


def build_kakaotalk_media_inventory(
    *,
    root: Path,
    exported_sqlite_paths: Sequence[Path],
    include_message_preview: bool = False,
    max_attachment_rows: int = 2000,
    max_local_files: int = 20000,
    hash_limit_bytes: int = 100 * 1024 * 1024,
) -> dict[str, object]:
    """Inventory KakaoTalk media attachments and local cache files without rendering them."""

    local_index = build_kakaotalk_local_media_index(root, max_files=max_local_files, hash_limit_bytes=hash_limit_bytes)
    attachments: list[dict[str, object]] = []
    for sqlite_path in exported_sqlite_paths:
        if not sqlite_path.exists() or len(attachments) >= max_attachment_rows:
            continue
        attachments.extend(
            extract_kakaotalk_attachment_rows(
                sqlite_path,
                local_index=local_index,
                include_message_preview=include_message_preview,
                remaining=max_attachment_rows - len(attachments),
            )
        )
    class_counts = Counter(str(row.get("media_class") or "unknown") for row in attachments)
    review_counts = Counter(str(row.get("review_status") or "unknown") for row in attachments)
    return {
        "parser": KAKAOTALK_MEDIA_INVENTORY_VERSION,
        "summary": {
            "attachment_count": len(attachments),
            "attachment_class_counts": dict(class_counts),
            "attachment_review_status_counts": dict(review_counts),
            "local_match_count": sum(1 for row in attachments if int(row.get("local_match_count") or 0) > 0),
            "local_media_file_count": len(local_index["files"]),
            "local_cng_cache_file_count": local_index["summary"]["cng_count"],
            "directly_viewable_local_file_count": local_index["summary"]["direct_viewable_count"],
            "hash_indexed_local_file_count": local_index["summary"]["hash_indexed_count"],
            "truncated": len(attachments) >= max_attachment_rows or local_index["summary"]["truncated"],
        },
        "attachments": attachments,
        "local_media_files": local_index["files"][:500],
        "validation": {
            "original_files_touched": False,
            "active_content_rendered": False,
            "raw_media_embedded": False,
            "matching_methods": ["checksum", "basename", "stem"],
            "limitations": [
                "Expired remote Kakao CDN URLs are preserved as metadata but not downloaded.",
                ".cng cache files are inventoried as opaque Kakao cache candidates until a decoder is independently validated.",
                "Message-to-media matching is evidentiary only when backed by a checksum or direct local file match.",
            ],
        },
    }


def extract_kakaotalk_attachment_rows(
    sqlite_path: Path,
    *,
    local_index: Mapping[str, object],
    include_message_preview: bool,
    remaining: int,
) -> list[dict[str, object]]:
    if remaining <= 0:
        return []
    chat_id = chat_id_from_path(sqlite_path)
    connection = sqlite3.connect(sqlite_readonly_uri(sqlite_path, immutable=True), uri=True)
    connection.row_factory = sqlite3.Row
    rows: list[dict[str, object]] = []
    try:
        if not table_exists(connection, "chatLogs"):
            return []
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(chatLogs)").fetchall()}
        if "attachement" not in columns:
            return []
        selected = ["logId", "authorId", "type", "sendAt", "message", "attachement"]
        selected = [column for column in selected if column in columns]
        sql = (
            f"SELECT {', '.join(quote_identifier(column) for column in selected)} "
            "FROM chatLogs WHERE COALESCE(attachement, '') NOT IN ('', '{}') ORDER BY sendAt, logId LIMIT ?"
        )
        for record in connection.execute(sql, (remaining,)):
            raw_attachment = str(record["attachement"] or "")
            try:
                attachment = json.loads(raw_attachment)
            except json.JSONDecodeError:
                attachment = {"_parse_error": True}
            message_type = int(record["type"] or 0) if "type" in record.keys() else 0
            for item_index, item in enumerate(expand_kakaotalk_attachment_items(attachment)):
                if len(rows) >= remaining:
                    break
                candidates, reasons = match_kakaotalk_local_media(item, local_index)
                media_class = classify_kakaotalk_attachment(message_type, item)
                row = {
                    "source_sqlite": str(sqlite_path.resolve()),
                    "chat_id": chat_id,
                    "log_id": record["logId"] if "logId" in record.keys() else "",
                    "send_at": record["sendAt"] if "sendAt" in record.keys() else "",
                    "author_id": record["authorId"] if "authorId" in record.keys() else "",
                    "message_type": message_type,
                    "media_class": media_class,
                    "item_index": item_index,
                    "display_name": kakao_attachment_display_name(item),
                    "mime": first_attachment_scalar(item, "mt", "mime", "contentType"),
                    "declared_size": first_attachment_scalar(item, "size", "s", "sl"),
                    "width": first_attachment_scalar(item, "w", "wl"),
                    "height": first_attachment_scalar(item, "h", "hl"),
                    "duration": first_attachment_scalar(item, "d", "dh"),
                    "expire": first_attachment_scalar(item, "expire"),
                    "checksum_count": len(kakao_attachment_checksums(item)),
                    "checksum_sha256": hashlib.sha256(";".join(kakao_attachment_checksums(item)).encode()).hexdigest()
                    if kakao_attachment_checksums(item)
                    else "",
                    "basename_candidates": kakao_attachment_basenames(item)[:10],
                    "local_match_count": len(candidates),
                    "local_matches": candidates,
                    "match_reasons": reasons,
                    "review_status": "local-file-present"
                    if candidates
                    else ("remote-or-opaque-cache-only" if media_class in {"image", "video", "file", "multi-image"} else "metadata-only"),
                    "message_text_sha256": hashlib.sha256(str(record["message"] or "").encode("utf-8", errors="ignore")).hexdigest()
                    if "message" in record.keys() and record["message"]
                    else "",
                    "attachment_json_sha256": hashlib.sha256(raw_attachment.encode("utf-8", errors="replace")).hexdigest(),
                }
                if include_message_preview and "message" in record.keys():
                    row["message_preview"] = truncate_text(str(record["message"] or ""), 200)
                rows.append(row)
            if len(rows) >= remaining:
                break
    finally:
        connection.close()
    return rows


def build_kakaotalk_local_media_index(
    root: Path,
    *,
    max_files: int,
    hash_limit_bytes: int,
) -> dict[str, object]:
    files: list[dict[str, object]] = []
    by_name: dict[str, list[dict[str, object]]] = {}
    by_stem: dict[str, list[dict[str, object]]] = {}
    by_hash: dict[str, list[dict[str, object]]] = {}
    truncated = False
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if len(files) >= max_files:
            truncated = True
            break
        if not path.is_file() or path.suffix.lower() not in KAKAOTALK_LOCAL_MEDIA_SUFFIXES:
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        record: dict[str, object] = {
            "path": str(path.resolve()),
            "relative_path": safe_relative_path(root, path),
            "name": path.name,
            "suffix": path.suffix.lower(),
            "size": stat.st_size,
            "mtime_utc": dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
            "signature": detect_file_signature(path),
            "sha256": "",
            "sha1": "",
            "md5": "",
        }
        if stat.st_size <= hash_limit_bytes:
            try:
                hashes = compute_hashes(path)
            except OSError:
                hashes = {}
            for key in ("sha256", "sha1", "md5"):
                record[key] = hashes.get(key, "")
                if record[key]:
                    by_hash.setdefault(str(record[key]).lower(), []).append(record)
        files.append(record)
        by_name.setdefault(path.name.lower(), []).append(record)
        by_stem.setdefault(path.stem.lower(), []).append(record)
    return {
        "files": files,
        "by_name": by_name,
        "by_stem": by_stem,
        "by_hash": by_hash,
        "summary": {
            "cng_count": sum(1 for item in files if item.get("suffix") == ".cng"),
            "direct_viewable_count": sum(
                1 for item in files if item.get("signature") in {"gif", "jpeg", "mp4-or-mov", "pdf", "png", "webp"}
            ),
            "hash_indexed_count": sum(1 for item in files if item.get("sha256")),
            "truncated": truncated,
        },
    }


def match_kakaotalk_local_media(
    attachment: Mapping[str, object],
    local_index: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[str]]:
    matches: list[dict[str, object]] = []
    reasons: list[str] = []
    by_hash = local_index.get("by_hash", {})
    by_name = local_index.get("by_name", {})
    by_stem = local_index.get("by_stem", {})
    if not isinstance(by_hash, Mapping) or not isinstance(by_name, Mapping) or not isinstance(by_stem, Mapping):
        return [], []
    for checksum in kakao_attachment_checksums(attachment):
        for record in by_hash.get(checksum.lower(), []):
            matches.append(minimal_local_media_record(record))
            reasons.append(f"checksum:{checksum[:12]}")
    for basename in kakao_attachment_basenames(attachment):
        lowered = basename.lower()
        for record in by_name.get(lowered, []):
            matches.append(minimal_local_media_record(record))
            reasons.append(f"basename:{basename}")
        stem = Path(basename).stem.lower()
        if stem:
            for record in by_stem.get(stem, []):
                matches.append(minimal_local_media_record(record))
                reasons.append(f"stem:{stem}")
    unique_matches: list[dict[str, object]] = []
    unique_reasons: list[str] = []
    seen: set[str] = set()
    for record, reason in zip(matches, reasons):
        key = str(record.get("relative_path") or record.get("path") or "")
        if key in seen:
            continue
        seen.add(key)
        unique_matches.append(record)
        unique_reasons.append(reason)
    return unique_matches[:10], unique_reasons[:10]


def minimal_local_media_record(record: Mapping[str, object]) -> dict[str, object]:
    return {
        "relative_path": record.get("relative_path", ""),
        "name": record.get("name", ""),
        "size": record.get("size", 0),
        "signature": record.get("signature", ""),
        "sha256": record.get("sha256", ""),
    }


def expand_kakaotalk_attachment_items(attachment: Mapping[str, object]) -> list[dict[str, object]]:
    list_lengths = [
        len(value)
        for value in attachment.values()
        if isinstance(value, list) and value and not all(isinstance(item, dict) for item in value)
    ]
    if not list_lengths:
        return [dict(attachment)]
    count = max(list_lengths)
    items: list[dict[str, object]] = []
    for index in range(count):
        item: dict[str, object] = {}
        for key, value in attachment.items():
            if isinstance(value, list) and value and not all(isinstance(entry, dict) for entry in value):
                item[key] = value[index] if index < len(value) else ""
            else:
                item[key] = value
        items.append(item)
    return items


def classify_kakaotalk_attachment(message_type: int, attachment: Mapping[str, object]) -> str:
    label = KAKAOTALK_ATTACHMENT_TYPE_LABELS.get(message_type, "attachment")
    if label == "attachment":
        mime = str(first_attachment_scalar(attachment, "mt", "mime", "contentType")).lower()
        names = " ".join(kakao_attachment_basenames(attachment)).lower()
        if "image/" in mime or any(ext in names for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic")):
            return "image"
        if "video/" in mime or any(ext in names for ext in (".mp4", ".mov", ".m4v", ".avi")):
            return "video"
    return label


def kakao_attachment_display_name(attachment: Mapping[str, object]) -> str:
    name = first_attachment_scalar(attachment, "name", "fileName", "filename")
    if name:
        return str(name)
    basenames = kakao_attachment_basenames(attachment)
    return basenames[0] if basenames else ""


def first_attachment_scalar(attachment: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        value = attachment.get(key)
        if isinstance(value, (str, int, float)) and value != "":
            return value
    return ""


def kakao_attachment_checksums(attachment: Mapping[str, object]) -> list[str]:
    values: list[str] = []
    for key in ("cs", "csh", "csl"):
        collect_attachment_strings(attachment.get(key), values)
    return sorted({value.lower() for value in values if re.fullmatch(r"[A-Fa-f0-9]{32,64}", value)})


def kakao_attachment_basenames(attachment: Mapping[str, object]) -> list[str]:
    values: list[str] = []
    for key in (
        "name",
        "fileName",
        "filename",
        "k",
        "tk",
        "kl",
        "url",
        "urls",
        "thumbnailUrl",
        "thumbnailUrls",
        "imageUrls",
    ):
        collect_attachment_strings(attachment.get(key), values)
    basenames = []
    for value in values:
        clean_value = value.split("?", 1)[0].replace("\\", "/")
        basename = Path(clean_value).name
        if basename:
            basenames.append(basename)
    return sorted(set(basenames))


def collect_attachment_strings(value: object, output: list[str]) -> None:
    if isinstance(value, str) and value:
        output.append(value)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        for item in value:
            collect_attachment_strings(item, output)
    elif isinstance(value, Mapping):
        for item in value.values():
            collect_attachment_strings(item, output)


def detect_file_signature(path: Path) -> str:
    try:
        header = path.read_bytes()[:16]
    except OSError:
        return "unreadable"
    if header.startswith(b"\x89PNG"):
        return "png"
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header.startswith(b"GIF8"):
        return "gif"
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    if len(header) >= 12 and header[4:8] == b"ftyp":
        return "mp4-or-mov"
    if header.startswith(b"%PDF"):
        return "pdf"
    if path.suffix.lower() == ".cng":
        return "opaque-cng"
    return "data"


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    return (
        connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table_name,)).fetchone()
        is not None
    )


def chat_id_from_path(path: Path) -> str:
    match = re.search(r"chatLogs_(\d+)", path.name, flags=re.IGNORECASE)
    return match.group(1) if match else path.stem


def safe_relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def list_tables(connection: sqlite3.Connection) -> list[dict[str, object]]:
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    tables = []
    for row in rows:
        table = str(row[0])
        try:
            count = connection.execute(f"SELECT COUNT(*) FROM {quote_identifier(table)}").fetchone()
        except sqlite3.DatabaseError:
            count = None
        tables.append({"name": table, "row_count": int(count[0]) if count else None})
    return tables


def table_columns(connection: sqlite3.Connection, table: Mapping[str, object]) -> list[dict[str, object]]:
    table_name = str(table["name"])
    rows = connection.execute(f"PRAGMA table_info({quote_identifier(table_name)})").fetchall()
    return [{"name": str(row[1]), "type": str(row[2] or "")} for row in rows]


def build_message_table_candidate(
    connection: sqlite3.Connection,
    table: Mapping[str, object],
    columns: Sequence[Mapping[str, object]],
    *,
    max_messages: int,
) -> dict[str, object] | None:
    table_name = str(table["name"])
    lowered_table = table_name.lower()
    column_names = [str(column["name"]) for column in columns]
    text_columns = rank_columns(column_names, TEXT_COLUMN_HINTS)
    if not text_columns:
        return None
    table_hint = any(hint in lowered_table for hint in MESSAGE_TABLE_HINTS)
    if not table_hint and len(text_columns) == 0:
        return None
    sender_columns = rank_columns(column_names, SENDER_COLUMN_HINTS)[:3]
    time_columns = rank_columns(column_names, TIME_COLUMN_HINTS)[:3]
    selected_columns = list(dict.fromkeys(text_columns[:3] + sender_columns + time_columns))
    row_count = int(table.get("row_count") or 0)
    previews = fetch_message_previews(
        connection,
        table_name,
        selected_columns=selected_columns,
        text_columns=text_columns[:3],
        max_messages=max_messages,
    )
    if row_count == 0 and not previews:
        return None
    return {
        "table": table_name,
        "row_count": row_count,
        "text_columns": text_columns[:10],
        "sender_columns": sender_columns,
        "time_columns": time_columns,
        "message_previews": previews,
    }


def fetch_message_previews(
    connection: sqlite3.Connection,
    table_name: str,
    *,
    selected_columns: Sequence[str],
    text_columns: Sequence[str],
    max_messages: int,
) -> list[dict[str, object]]:
    if max_messages <= 0 or not selected_columns:
        return []
    where = " OR ".join(
        f"TRIM(CAST({quote_identifier(column)} AS TEXT)) != ''" for column in text_columns
    )
    sql = (
        f"SELECT rowid, {', '.join(quote_identifier(column) for column in selected_columns)} "
        f"FROM {quote_identifier(table_name)} WHERE {where} LIMIT ?"
    )
    try:
        rows = connection.execute(sql, (max_messages,)).fetchall()
    except sqlite3.DatabaseError:
        return []
    previews = []
    for row in rows:
        values = dict(zip(["rowid", *selected_columns], row))
        message_value = first_text_value(values, text_columns)
        previews.append(
            {
                "table": table_name,
                "rowid": values.get("rowid"),
                "message_text": truncate_text(message_value, 500),
                "message_text_sha256": hashlib.sha256(message_value.encode("utf-8", errors="ignore")).hexdigest()
                if message_value
                else "",
                "fields": {
                    key: truncate_text(str(value), 200)
                    for key, value in values.items()
                    if key != "rowid" and key not in text_columns and value is not None
                },
            }
        )
    return previews


def rank_columns(column_names: Sequence[str], hints: Sequence[str]) -> list[str]:
    scored: list[tuple[int, str]] = []
    for column in column_names:
        lowered = column.lower()
        score = 0
        for index, hint in enumerate(hints):
            if hint == lowered:
                score += 50 - index
            elif hint in lowered:
                score += 20 - index
        if score:
            scored.append((score, column))
    return [column for _, column in sorted(scored, key=lambda item: (-item[0], item[1].lower()))]


def first_text_value(values: Mapping[str, object], text_columns: Sequence[str]) -> str:
    for column in text_columns:
        value = values.get(column)
        if value is None:
            continue
        text = str(value)
        if text.strip():
            return text
    return ""


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def truncate_text(value: str, limit: int) -> str:
    return " ".join(value.split())[:limit]


def chat_id_from_path(path: Path) -> str:
    match = CHATLOG_PATTERN.match(path.name)
    if match:
        return match.group("chat_id")
    export_match = re.search(r"chatLogs_(\d+)", path.name, flags=re.IGNORECASE)
    return export_match.group(1) if export_match else ""


def read_header_hex(path: Path) -> str:
    try:
        return path.read_bytes()[:16].hex()
    except OSError:
        return ""


def commercial_blockers(auth: DecryptAuth) -> list[str]:
    blockers = [
        "known-answer-validation-required",
        "schema-specific-message-parser-required",
        "deleted-record-recovery-validation-required",
    ]
    if not auth.ready:
        blockers.insert(0, "authorized-decryption-material-required")
    return blockers
