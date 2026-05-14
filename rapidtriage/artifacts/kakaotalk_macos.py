from __future__ import annotations

import datetime as dt
import base64
import csv
import hashlib
import html
import io
import json
import os
import plistlib
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .windows.common import build_forensic_review, open_sqlite_snapshot
from .kakaotalk_windows import companion_files, inspect_sqlite_database

PARSER_VERSION = "kakaotalk-macos-db-inventory-v2"
KAKAO_MAC_MAX_FILES = 900
KAKAO_MAC_MAX_SCANNED_FILES = 12_000
KAKAO_MAC_MAX_DIRS = 1_500
KAKAO_MAC_MAX_DEPTH = 9
KAKAO_MAC_DB_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".edb", ".dat"}
KAKAO_MAC_CONTAINER_NAMES = (
    "com.kakao.KakaoTalkMac",
    "com.kakao.KakaoTalkMac.ShareExt",
)
KAKAO_MAC_HOME_ROOTS = (
    ("Library", "Application Support", "KakaoTalk"),
    ("Library", "Application Support", "Kakao"),
)
KAKAO_MAC_CONTAINER_RELATIVE_ROOTS = (
    ("Data", "Library", "Application Support", "com.kakao.KakaoTalkMac"),
    ("Data", "Library", "Application Support", "KakaoTalk"),
    ("Data", "Library", "Application Support", "Kakao"),
    ("Data", "Documents"),
)
KAKAO_MAC_CHAT_TABLE_RE = re.compile(r"(?i)(message|messages|chatlogs|chat_messages)")
KAKAO_MAC_KNOWN_MESSAGE_TABLES = {"NTChatMessage", "chatLogs", "messages"}
SAFE_SQL_NAME_RE = re.compile(r"[A-Za-z0-9_.$-]{1,128}")
SHA512_HEX_RE = re.compile(r"^[a-fA-F0-9]{128}$")
SKIP_USERS = {"shared", "guest", "daemon", "nobody"}
KAKAO_MAC_SKIP_DIR_NAMES = {
    ".trash",
    "commonresource",
    "emoticon",
    "fsCachedData".lower(),
    "items",
    "movies",
    "music",
    "pictures",
    "profileresource",
    "webkit",
}
EMPTY_ACCOUNT_SHA512 = (
    "31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99"
)
SQLCIPHER_TIMEOUT_SECONDS = 6
DEFAULT_MACOS_REPORT_MAX_MESSAGES = 100_000
DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS = 100_000
MACOS_REPORT_VERSION = "kakaotalk-macos-report-v1"


class KakaoTalkMacOsReportError(RuntimeError):
    """Raised when a macOS KakaoTalk report cannot be produced safely."""


class KakaoTalkMacOsProvider:
    collector_kind = "kakaotalk-macos"
    name = "kakaotalk-macos-database-inventory"
    description = "macOS KakaoTalk container and database inventory with SQLite openability checks"
    target_platform = "macos"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        candidate_roots = list(iter_kakaotalk_macos_candidate_roots(root))
        records: list[ArtifactRecord] = []
        for db_path in iter_kakaotalk_macos_databases(candidate_roots):
            records.append(collect_kakaotalk_macos_database(db_path, root=root))
        yield from records
        summary = build_kakaotalk_macos_summary(root, candidate_roots, records)
        if summary is not None:
            yield summary


def iter_kakaotalk_macos_candidate_roots(root: Path) -> Iterator[Path]:
    seen: set[Path] = set()

    def emit(path: Path) -> Iterator[Path]:
        if not path.exists() or not path.is_dir():
            return
        try:
            key = path.resolve()
        except OSError:
            key = path.absolute()
        if key in seen:
            return
        seen.add(key)
        yield path

    lowered_root = str(root).lower()
    if "kakao" in lowered_root:
        for container_parts in KAKAO_MAC_CONTAINER_RELATIVE_ROOTS:
            yield from emit(root.joinpath(*container_parts))
        if not is_probably_kakao_container_root(root):
            yield from emit(root)

    for user_root in iter_macos_user_homes(root):
        containers_root = user_root / "Library" / "Containers"
        for container_name in KAKAO_MAC_CONTAINER_NAMES:
            container_root = containers_root / container_name
            for container_parts in KAKAO_MAC_CONTAINER_RELATIVE_ROOTS:
                yield from emit(container_root.joinpath(*container_parts))
        for parts in KAKAO_MAC_HOME_ROOTS:
            yield from emit(user_root.joinpath(*parts))
        group_containers = user_root / "Library" / "Group Containers"
        if group_containers.is_dir():
            for child in iter_child_dirs(group_containers):
                if "kakao" in child.name.lower():
                    yield from emit(child)


def is_probably_kakao_container_root(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered in {name.lower() for name in KAKAO_MAC_CONTAINER_NAMES}:
        return True
    return (path / "Data" / "Library" / "Application Support").is_dir()


def iter_macos_user_homes(root: Path) -> Iterator[Path]:
    users_dir = root / "Users"
    if users_dir.is_dir():
        for candidate in iter_child_dirs(users_dir):
            if candidate.name.lower() not in SKIP_USERS:
                yield candidate
        return
    if (root / "Library").is_dir():
        yield root


def iter_child_dirs(path: Path) -> Iterator[Path]:
    try:
        entries = sorted(os.scandir(path), key=lambda entry: entry.name.lower())
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                yield Path(entry.path)
        except OSError:
            continue


def iter_kakaotalk_macos_databases(candidate_roots: Sequence[Path]) -> Iterator[Path]:
    seen: set[Path] = set()
    for candidate_root in candidate_roots:
        for path in iter_files_bounded(
            candidate_root,
            max_depth=KAKAO_MAC_MAX_DEPTH,
            max_files=KAKAO_MAC_MAX_FILES,
            max_scanned_files=KAKAO_MAC_MAX_SCANNED_FILES,
            max_dirs=KAKAO_MAC_MAX_DIRS,
        ):
            if not is_kakaotalk_macos_database_path(path):
                continue
            try:
                key = path.resolve()
            except OSError:
                key = path.absolute()
            if key in seen:
                continue
            seen.add(key)
            yield path


def iter_files_bounded(
    root: Path,
    *,
    max_depth: int,
    max_files: int,
    max_scanned_files: int,
    max_dirs: int,
) -> Iterator[Path]:
    yielded = 0
    scanned = 0
    visited_dirs = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack and yielded < max_files and scanned < max_scanned_files and visited_dirs < max_dirs:
        current, depth = stack.pop()
        visited_dirs += 1
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name.lower(), reverse=True)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False):
                    scanned += 1
                    if scanned >= max_scanned_files:
                        return
                    if not is_kakaotalk_macos_database_path(Path(entry.path)):
                        continue
                    yielded += 1
                    yield Path(entry.path)
                    if yielded >= max_files:
                        return
                elif depth < max_depth and entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() in KAKAO_MAC_SKIP_DIR_NAMES:
                        continue
                    stack.append((Path(entry.path), depth + 1))
            except OSError:
                continue


def is_kakaotalk_macos_database_path(path: Path) -> bool:
    lowered = str(path).lower()
    if "kakao" not in lowered and "talk" not in lowered and "chat" not in lowered:
        return False
    if path.name.lower().endswith(("-wal", "-shm")):
        return False
    if path.suffix.lower() in KAKAO_MAC_DB_EXTENSIONS:
        return True
    return path.suffix == "" and bool(re.fullmatch(r"[a-fA-F0-9]{40,128}", path.name))


def collect_kakaotalk_macos_database(path: Path, *, root: Path) -> ArtifactRecord:
    sqlite_meta = inspect_sqlite_database(path)
    identity_context = build_kakaotalk_macos_identity_context(path)
    sqlite_analysis = analyze_kakaotalk_macos_sqlite(path, sqlite_meta, identity_context=identity_context)
    role = classify_kakaotalk_macos_db_role(path, sqlite_analysis)
    companions = companion_files(path)
    source_hashes = compute_hashes(path)
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    report_grade = {
        "report_grade_ready": False,
        "status": "macos-kakaotalk-db-inventory-validation-required",
        "blockers": [
            "kakaotalk-macos-schema-version-validation-required",
            "kakaotalk-macos-sqlcipher-known-answer-validation-required",
            "kakaotalk-macos-message-semantics-known-answer-required",
        ],
        "validated_strengths": [
            "source-hash-preserved",
            "sqlite-openability-tested",
            "kakaotalk-macos-db-name-and-key-derivation-probed-without-key-export",
            "wal-shm-companions-recorded",
            "message-table-candidates-counted-without-content-export",
        ],
        "commercial_gap_ids": ["#31"],
        "next_validation_step": "Validate plain SQLite or authorized SQLCipher decoding against a known-answer macOS KakaoTalk corpus before reporting message contents.",
    }
    db_opened = sqlite_meta.get("open_status") == "opened-read-only"
    details = {
        "parser": "kakaotalk-macos-db-inventory",
        "parser_version": PARSER_VERSION,
        "coverage_status": "parsed" if db_opened else "inventory",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_hashes": dict(source_hashes),
        "source_size": size,
        "source_relative_path": safe_relative(path, root),
        "source_family": "kakaotalk-macos-container-db",
        "database_role": role,
        "sqlite_access": sqlite_meta,
        "kakaotalk_macos_identity_context": identity_context,
        "kakaotalk_macos_db_analysis": sqlite_analysis,
        "companion_files": companions,
        "has_wal": any(item["kind"] == "wal" for item in companions),
        "has_shm": any(item["kind"] == "shm" for item in companions),
        "parser_confidence": kakaotalk_macos_confidence(role, sqlite_meta, sqlite_analysis, companions),
        "evidence_strength": "kakaotalk-macos-database-presence-and-openability",
        "validation_required": True,
        "validation_guidance": (
            "This row proves the macOS KakaoTalk DB candidate was found and tested for SQLite openability. "
            "Message content is not exported from encrypted or unvalidated schemas."
        ),
        "forensic_review": build_forensic_review(
            gap_id="#31",
            artifact_goal="macOS KakaoTalk database inventory and DB openability",
            primary_evidence=[
                f"role={role}",
                f"sqlite_open_status={sqlite_meta.get('open_status')}",
                f"message_table_candidates={len(sqlite_analysis.get('message_table_candidates', []))}",
                f"message_row_count_estimate={sqlite_analysis.get('message_row_count_estimate', 0)}",
            ],
            validation_required=True,
            report_grade_assessment=report_grade,
            commercial_grade_ready=False,
            caveats=[
                "Plain SQLite table counts are metadata only; unvalidated message text is not exported.",
                "SQLCipher or custom-codec databases require authorized key material and known-answer validation.",
            ],
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "privacy_legal_warning": "KakaoTalk Mac databases may contain private communications. Preserve hashes and validate authority before decoding or reporting content.",
        "risk_flags": kakaotalk_macos_risk_flags(role, sqlite_meta, sqlite_analysis, companions),
        "risk_score": kakaotalk_macos_risk_score(role, sqlite_meta, sqlite_analysis),
        "raw_preview": "",
    }
    return ArtifactRecord(
        provider=KakaoTalkMacOsProvider.name,
        artifact_type="kakaotalk-macos-database",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def analyze_kakaotalk_macos_sqlite(
    path: Path,
    sqlite_meta: Mapping[str, object],
    *,
    identity_context: Mapping[str, object] | None = None,
) -> dict[str, object]:
    analysis: dict[str, object] = {
        "db_opened": sqlite_meta.get("open_status") == "opened-read-only",
        "db_access_status": sqlite_meta.get("open_status") or "unknown",
        "plain_sqlite_header": bool(sqlite_meta.get("sqlite_header")),
        "requires_sqlcipher_or_custom_decoder": not bool(sqlite_meta.get("sqlite_header")),
        "sqlcipher_probe": build_sqlcipher_probe_summary(None),
        "message_table_candidates": [],
        "message_row_count_estimate": 0,
        "schema_samples": [],
        "content_exported": False,
        "safe_message_content_status": "not-exported",
    }
    if sqlite_meta.get("open_status") != "opened-read-only":
        if not sqlite_meta.get("sqlite_header"):
            analysis["db_access_status"] = "encrypted-or-custom-store-validation-required"
            probe = probe_kakaotalk_macos_sqlcipher(path, identity_context or {})
            analysis["sqlcipher_probe"] = build_sqlcipher_probe_summary(probe)
            if probe.get("opened"):
                analysis["db_opened"] = True
                analysis["db_access_status"] = "sqlcipher-opened-read-only"
                analysis["requires_sqlcipher_or_custom_decoder"] = False
                analysis["message_table_candidates"] = probe.get("message_table_candidates") or []
                analysis["message_row_count_estimate"] = int(probe.get("message_row_count_estimate") or 0)
                analysis["schema_samples"] = probe.get("schema_samples") or []
        return analysis
    try:
        with open_sqlite_snapshot(path) as connection:
            table_names = [
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            ]
            candidates: list[dict[str, object]] = []
            row_total = 0
            for table_name in table_names:
                if not SAFE_SQL_NAME_RE.fullmatch(table_name):
                    continue
                columns = sqlite_columns(connection, table_name)
                schema_row = {"table": table_name, "columns": columns[:24]}
                if len(analysis["schema_samples"]) < 20:
                    analysis["schema_samples"].append(schema_row)
                if not is_kakaotalk_message_table_candidate(table_name, columns):
                    continue
                row_count = sqlite_count(connection, table_name)
                row_total += row_count
                candidates.append(
                    {
                        "table": table_name,
                        "row_count": row_count,
                        "columns": columns[:24],
                        "content_columns_detected": [
                            column
                            for column in columns
                            if column.lower() in {"message", "msg", "text", "content", "attachment", "data"}
                        ],
                    }
                )
            analysis["message_table_candidates"] = candidates[:30]
            analysis["message_row_count_estimate"] = row_total
            analysis["db_access_status"] = "plain-sqlite-opened"
    except (sqlite3.DatabaseError, OSError) as exc:
        analysis["db_access_status"] = "sqlite-analysis-failed"
        analysis["error"] = str(exc)[:200]
    return analysis


def build_sqlcipher_probe_summary(probe: Mapping[str, object] | None) -> dict[str, object]:
    if not probe:
        return {
            "attempted": False,
            "opened": False,
            "tool": "",
            "tool_available": bool(shutil.which("sqlcipher")),
            "compatibility_mode": None,
            "candidate_count": 0,
            "derived_database_name_match_count": 0,
            "matched_user_id_sha256": "",
            "key_sha256": "",
            "message": "not-attempted",
        }
    return {
        "attempted": bool(probe.get("attempted")),
        "opened": bool(probe.get("opened")),
        "tool": str(probe.get("tool") or ""),
        "tool_available": bool(probe.get("tool_available")),
        "compatibility_mode": probe.get("compatibility_mode"),
        "candidate_count": int(probe.get("candidate_count") or 0),
        "derived_database_name_match_count": int(probe.get("derived_database_name_match_count") or 0),
        "matched_user_id_sha256": str(probe.get("matched_user_id_sha256") or ""),
        "key_sha256": str(probe.get("key_sha256") or ""),
        "message": str(probe.get("message") or ""),
    }


def build_kakaotalk_macos_identity_context(path: Path) -> dict[str, object]:
    home_root = find_macos_home_for_path(path)
    plist_paths = list(iter_kakaotalk_macos_plists(home_root)) if home_root else []
    user_directory_hashes = discover_kakaotalk_macos_user_directory_hashes(home_root) if home_root else []
    user_id_candidates, active_hashes, direct_sources = extract_kakaotalk_macos_user_id_candidates(
        plist_paths,
        user_directory_hashes=user_directory_hashes,
    )
    uuid = kakao_macos_uuid_for_path(path, home_root)
    derived_names: list[dict[str, object]] = []
    for candidate in user_id_candidates[:12]:
        if not uuid:
            continue
        derived_name = derive_kakaotalk_macos_database_name(candidate, uuid)
        derived_names.append(
            {
                "database_name": derived_name,
                "source_user_id_sha256": redact_number(candidate),
                "matches_source_file": path.name.lower() in {derived_name, f"{derived_name}.db"},
            }
        )
    return {
        "home_root": str(home_root) if home_root else "",
        "plist_paths": [str(item) for item in plist_paths[:8]],
        "platform_uuid_available": bool(uuid),
        "platform_uuid_source": "env-or-live" if uuid else "",
        "user_id_candidate_count": len(user_id_candidates),
        "user_id_candidate_sources": sorted(direct_sources),
        "user_id_candidate_sha256": [redact_number(candidate) for candidate in user_id_candidates[:20]],
        "active_account_hash_count": len(active_hashes),
        "active_account_hash_sha256": [hash_text(item) for item in active_hashes[:12]],
        "user_directory_hash_count": len(user_directory_hashes),
        "user_directory_hash_sha256": [hash_text(item) for item in user_directory_hashes[:12]],
        "derived_database_name_candidates": derived_names[:12],
        "derived_database_name_match_count": sum(1 for item in derived_names if item["matches_source_file"]),
        "sqlcipher_key_derivation_supported": bool(uuid and user_id_candidates),
        "sqlcipher_key_material_exported": False,
        "external_user_id_override_supported": True,
        "external_uuid_override_supported": True,
        "override_env": {
            "user_ids": "RAPIDTRIAGE_KAKAO_MAC_USER_ID or RAPIDTRIAGE_KAKAO_MAC_USER_IDS",
            "uuid": "RAPIDTRIAGE_KAKAO_MAC_UUID",
        },
    }


def find_macos_home_for_path(path: Path) -> Path | None:
    parts = path.resolve().parts
    for index, part in enumerate(parts):
        if part == "Library" and index > 0:
            return Path(*parts[:index])
    return None


def iter_kakaotalk_macos_plists(home_root: Path) -> Iterator[Path]:
    candidates: list[Path] = []
    container_preferences = home_root / "Library" / "Containers" / "com.kakao.KakaoTalkMac" / "Data" / "Library" / "Preferences"
    if container_preferences.is_dir():
        try:
            entries = sorted(container_preferences.iterdir(), key=lambda item: (item.name == "com.kakao.KakaoTalkMac.plist", item.name))
        except OSError:
            entries = []
        for entry in entries:
            if entry.name.startswith("com.kakao.KakaoTalkMac") and entry.suffix == ".plist":
                candidates.append(entry)
    candidates.append(home_root / "Library" / "Preferences" / "com.kakao.KakaoTalkMac.plist")
    seen: set[Path] = set()
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            key = candidate.resolve()
        except OSError:
            key = candidate.absolute()
        if key in seen:
            continue
        seen.add(key)
        yield candidate


def extract_kakaotalk_macos_user_id_candidates(
    plist_paths: Sequence[Path],
    *,
    user_directory_hashes: Sequence[str] = (),
) -> tuple[list[int], list[str], set[str]]:
    candidates: list[int] = []
    active_hashes: list[str] = []
    sources: set[str] = set()

    def add_candidate(value: object, source: str) -> None:
        parsed = parse_positive_int(value)
        if parsed is None:
            return
        candidates.append(parsed)
        sources.add(source)

    for plist_path in plist_paths:
        plist = read_plist(plist_path)
        if not isinstance(plist, dict):
            continue
        alert_ids = plist.get("AlertKakaoIDsList")
        if isinstance(alert_ids, list):
            for item in alert_ids:
                add_candidate(item, "AlertKakaoIDsList")
        for key in ("userId", "user_id", "KAKAO_USER_ID", "userID"):
            if key in plist:
                add_candidate(plist.get(key), key)
        for prefix, source in (
            ("FSChatWindowTransparency", "FSChatWindowTransparency-common-suffix"),
            ("NSWindow Frame FSChatWindowFrame_", "FSChatWindowFrame-common-suffix"),
        ):
            suffix = longest_common_suffix([str(key)[len(prefix) :] for key in plist if str(key).startswith(prefix)])
            if suffix:
                add_candidate(suffix, source)
        for key, value in plist.items():
            key_text = str(key)
            if ":" not in key_text:
                continue
            suffix = key_text.rsplit(":", 1)[-1]
            if not SHA512_HEX_RE.fullmatch(suffix) or suffix.lower() == EMPTY_ACCOUNT_SHA512:
                continue
            if not plist_revision_value_is_active(value):
                continue
            active_hashes.append(suffix.lower())
            recovered = recover_user_id_from_sha512_hash(suffix)
            if recovered is not None:
                add_candidate(recovered, "active-revision-sha512-bruteforce")
    for directory_hash in user_directory_hashes:
        recovered = recover_user_id_from_sha512_directory_hash(directory_hash)
        if recovered is not None:
            add_candidate(recovered, "user-directory-sha512-slice-bruteforce")
    return dedupe_ints(candidates), sorted(set(active_hashes)), sources


def discover_kakaotalk_macos_user_directory_hashes(home_root: Path) -> list[str]:
    container_root = home_root / "Library" / "Containers" / "com.kakao.KakaoTalkMac" / "Data" / "Library" / "Application Support" / "com.kakao.KakaoTalkMac"
    if not container_root.is_dir():
        return []
    hashes: list[str] = []
    for child in iter_child_dirs(container_root):
        if re.fullmatch(r"[a-fA-F0-9]{40}", child.name):
            hashes.append(child.name.lower())
    return sorted(set(hashes))


def read_plist(path: Path) -> object | None:
    try:
        with path.open("rb") as handle:
            return plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def parse_positive_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return None
        return parsed if parsed > 0 else None
    return None


def plist_revision_value_is_active(value: object) -> bool:
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, (int, float)):
        return int(value) != 0
    return value not in (None, "", b"")


def longest_common_suffix(values: Sequence[str]) -> str:
    if len(values) < 2:
        return ""
    reversed_values = [value[::-1] for value in values if value]
    if len(reversed_values) < 2:
        return ""
    common = []
    for chars in zip(*reversed_values):
        if len(set(chars)) != 1:
            break
        common.append(chars[0])
    return "".join(common)[::-1]


def recover_user_id_from_sha512_hash(hex_hash: str) -> int | None:
    max_id_text = os.environ.get("RAPIDTRIAGE_KAKAO_MAC_SHA512_BRUTE_MAX", "0").strip()
    try:
        max_id = int(max_id_text)
    except ValueError:
        max_id = 0
    if max_id <= 0 or not SHA512_HEX_RE.fullmatch(hex_hash):
        return None
    target = bytes.fromhex(hex_hash)
    for value in range(max_id + 1):
        if hashlib.sha512(str(value).encode("utf-8")).digest() == target:
            return value
    return None


def recover_user_id_from_sha512_directory_hash(directory_hash: str) -> int | None:
    max_id_text = os.environ.get("RAPIDTRIAGE_KAKAO_MAC_SHA512_BRUTE_MAX", "0").strip()
    try:
        max_id = int(max_id_text)
    except ValueError:
        max_id = 0
    if max_id <= 0 or not re.fullmatch(r"[a-fA-F0-9]{40}", directory_hash):
        return None
    target = bytes.fromhex(directory_hash)
    for value in range(max_id + 1):
        digest = hashlib.sha512(str(value).encode("utf-8")).digest()
        if digest[20:40] == target:
            return value
    return None


def dedupe_ints(values: Sequence[int]) -> list[int]:
    seen: set[int] = set()
    deduped: list[int] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    for value in env_user_id_overrides():
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def env_user_id_overrides() -> list[int]:
    values: list[int] = []
    raw = ",".join(
        item
        for item in (
            os.environ.get("RAPIDTRIAGE_KAKAO_MAC_USER_ID", ""),
            os.environ.get("RAPIDTRIAGE_KAKAO_MAC_USER_IDS", ""),
        )
        if item
    )
    for item in re.split(r"[\s,;]+", raw):
        parsed = parse_positive_int(item)
        if parsed is not None:
            values.append(parsed)
    raw_files = ",".join(
        item
        for item in (
            os.environ.get("RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILE", ""),
            os.environ.get("RAPIDTRIAGE_KAKAO_MAC_USER_ID_FILES", ""),
        )
        if item
    )
    for item in re.split(r"[\s,;]+", raw_files):
        if not item:
            continue
        try:
            file_text = Path(item).expanduser().read_bytes().decode("utf-8", errors="ignore")
        except OSError:
            continue
        for token in re.split(r"[\s,;]+", file_text):
            parsed = parse_positive_int(token)
            if parsed is not None:
                values.append(parsed)
    return values


def kakao_macos_uuid_for_path(path: Path, home_root: Path | None) -> str:
    env_uuid = os.environ.get("RAPIDTRIAGE_KAKAO_MAC_UUID", "").strip()
    if env_uuid:
        return env_uuid
    if home_root and same_or_descendant(home_root, Path.home()):
        return live_macos_platform_uuid()
    if same_or_descendant(path, Path.home()):
        return live_macos_platform_uuid()
    return ""


def same_or_descendant(path: Path, possible_parent: Path) -> bool:
    try:
        path.resolve().relative_to(possible_parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def live_macos_platform_uuid() -> str:
    try:
        completed = subprocess.run(
            ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', completed.stdout)
    return match.group(1) if match else ""


def hashed_macos_device_uuid(uuid: str) -> str:
    data = uuid.encode("utf-8")
    return base64.b64encode(hashlib.sha1(data).digest() + hashlib.sha256(data).digest()).decode("ascii")


def derive_kakaotalk_macos_database_name(user_id: int, uuid: str) -> str:
    hawawa = ".".join([".", "F", str(user_id), "A", "F", "".join(reversed(uuid)), ".", "|"])
    salt = "".join(reversed(hashed_macos_device_uuid(uuid)))
    derived = hashlib.pbkdf2_hmac("sha256", hawawa.encode("utf-8"), salt.encode("utf-8"), 100_000, 128)
    return derived.hex()[28:106]


def derive_kakaotalk_macos_secure_key(user_id: int, uuid: str) -> str:
    hashed = hashed_macos_device_uuid(uuid)
    parts = ["A", hashed, "|", "F", uuid[:5], "H", str(user_id), "|", uuid[7:]]
    hawawa = "F".join(parts)
    salt = uuid[int(len(uuid) * 0.3) :]
    derived = hashlib.pbkdf2_hmac("sha256", hawawa[::-1].encode("utf-8"), salt.encode("utf-8"), 100_000, 128)
    return derived.hex()


def probe_kakaotalk_macos_sqlcipher(path: Path, identity_context: Mapping[str, object]) -> dict[str, object]:
    tool = shutil.which("sqlcipher") or ""
    candidates = sqlcipher_key_candidates(path, identity_context)
    match_count = int(identity_context.get("derived_database_name_match_count") or 0)
    probe: dict[str, object] = {
        "attempted": bool(tool and candidates),
        "opened": False,
        "tool": tool,
        "tool_available": bool(tool),
        "candidate_count": len(candidates),
        "derived_database_name_match_count": match_count,
        "compatibility_mode": None,
        "message": "",
    }
    if not tool:
        probe["message"] = "sqlcipher-not-installed"
        return probe
    if not candidates:
        probe["message"] = "missing-platform-uuid-or-user-id-candidate"
        return probe
    for candidate in candidates:
        for compatibility in (3, 4):
            table_names = sqlcipher_table_names(tool, path, candidate["key"], compatibility)
            if table_names is None:
                continue
            schema_samples, message_candidates, row_total = sqlcipher_schema_and_message_counts(
                tool,
                path,
                candidate["key"],
                compatibility,
                table_names,
            )
            probe.update(
                {
                    "opened": True,
                    "compatibility_mode": compatibility,
                    "matched_user_id_sha256": candidate["user_id_sha256"],
                    "key_sha256": hash_text(candidate["key"]),
                    "schema_samples": schema_samples,
                    "message_table_candidates": message_candidates,
                    "message_row_count_estimate": row_total,
                    "message": "sqlcipher-opened-read-only",
                }
            )
            return probe
    probe["message"] = "candidate-keys-did-not-open-database"
    return probe


def sqlcipher_key_candidates(path: Path, identity_context: Mapping[str, object]) -> list[dict[str, str]]:
    if not identity_context.get("platform_uuid_available"):
        return []
    uuid = os.environ.get("RAPIDTRIAGE_KAKAO_MAC_UUID", "").strip()
    if not uuid:
        uuid = live_macos_platform_uuid()
    if not uuid:
        return []
    candidates: list[dict[str, str]] = []
    for user_id in env_user_id_overrides():
        candidates.append({"key": derive_kakaotalk_macos_secure_key(user_id, uuid), "user_id_sha256": redact_number(user_id)})
    for item in identity_context.get("derived_database_name_candidates") or []:
        if not isinstance(item, Mapping):
            continue
        user_hash = str(item.get("source_user_id_sha256") or "")
        # The raw user id is intentionally unavailable here unless supplied through the environment;
        # candidate keys are generated earlier only for in-memory probing and never serialized.
        if user_hash:
            continue
    # Re-read plist candidates locally so raw IDs exist only inside this process.
    home_root = find_macos_home_for_path(path)
    plist_paths = list(iter_kakaotalk_macos_plists(home_root)) if home_root else []
    directory_hashes = discover_kakaotalk_macos_user_directory_hashes(home_root) if home_root else []
    raw_ids, _, _ = extract_kakaotalk_macos_user_id_candidates(plist_paths, user_directory_hashes=directory_hashes)
    for user_id in raw_ids[:12]:
        key = derive_kakaotalk_macos_secure_key(user_id, uuid)
        hashed = redact_number(user_id)
        if all(item["user_id_sha256"] != hashed for item in candidates):
            candidates.append({"key": key, "user_id_sha256": hashed})
    return candidates[:16]


def sqlcipher_table_names(tool: str, path: Path, key: str, compatibility: int) -> list[str] | None:
    sql = (
        f"PRAGMA cipher_default_compatibility = {compatibility};\n"
        f"PRAGMA key = '{key}';\n"
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 120;\n"
    )
    completed = run_sqlcipher(tool, path, sql)
    if completed is None or completed.returncode != 0:
        return None
    names = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip().lower() != "ok" and SAFE_SQL_NAME_RE.fullmatch(line.strip())
    ]
    return names or None


def sqlcipher_schema_and_message_counts(
    tool: str,
    path: Path,
    key: str,
    compatibility: int,
    table_names: Sequence[str],
) -> tuple[list[dict[str, object]], list[dict[str, object]], int]:
    schema_samples: list[dict[str, object]] = []
    message_candidates: list[dict[str, object]] = []
    row_total = 0
    for table_name in table_names[:40]:
        columns = sqlcipher_table_columns(tool, path, key, compatibility, table_name)
        if len(schema_samples) < 20:
            schema_samples.append({"table": table_name, "columns": columns[:24]})
        if not is_kakaotalk_message_table_candidate(table_name, columns):
            continue
        row_count = sqlcipher_count_rows(tool, path, key, compatibility, table_name)
        row_total += row_count
        message_candidates.append(
            {
                "table": table_name,
                "row_count": row_count,
                "columns": columns[:24],
                "content_columns_detected": [
                    column
                    for column in columns
                    if column.lower() in {"message", "msg", "text", "content", "attachment", "data", "localfilepath"}
                ],
            }
        )
    return schema_samples, message_candidates[:30], row_total


def sqlcipher_table_columns(tool: str, path: Path, key: str, compatibility: int, table_name: str) -> list[str]:
    if not SAFE_SQL_NAME_RE.fullmatch(table_name):
        return []
    sql = (
        f"PRAGMA cipher_default_compatibility = {compatibility};\n"
        f"PRAGMA key = '{key}';\n"
        f'PRAGMA table_info("{table_name}");\n'
    )
    completed = run_sqlcipher(tool, path, sql)
    if completed is None or completed.returncode != 0:
        return []
    columns: list[str] = []
    for line in completed.stdout.splitlines():
        parts = line.split("|")
        if len(parts) >= 2 and SAFE_SQL_NAME_RE.fullmatch(parts[1]):
            columns.append(parts[1])
    return columns


def sqlcipher_count_rows(tool: str, path: Path, key: str, compatibility: int, table_name: str) -> int:
    if not SAFE_SQL_NAME_RE.fullmatch(table_name):
        return 0
    sql = (
        f"PRAGMA cipher_default_compatibility = {compatibility};\n"
        f"PRAGMA key = '{key}';\n"
        f'SELECT COUNT(*) FROM "{table_name}";\n'
    )
    completed = run_sqlcipher(tool, path, sql)
    if completed is None or completed.returncode != 0:
        return 0
    try:
        return int(completed.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        return 0


def run_sqlcipher(tool: str, path: Path, sql: str) -> subprocess.CompletedProcess[str] | None:
    if not path.exists():
        return None
    try:
        return subprocess.run(
            [tool, "-readonly", "-ifexists", "-batch", "-noheader", str(path)],
            input=sql,
            text=True,
            capture_output=True,
            timeout=SQLCIPHER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def is_kakaotalk_message_table_candidate(table_name: str, columns: Sequence[str]) -> bool:
    if table_name in KAKAO_MAC_KNOWN_MESSAGE_TABLES:
        return True
    return bool(KAKAO_MAC_CHAT_TABLE_RE.search(table_name))


def redact_number(value: int) -> str:
    return hash_text(str(value))


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sqlite_columns(connection: sqlite3.Connection, table_name: str) -> list[str]:
    try:
        return [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table_name}")').fetchall()]
    except sqlite3.DatabaseError:
        return []


def sqlite_count(connection: sqlite3.Connection, table_name: str) -> int:
    try:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()
        return int(row[0]) if row else 0
    except (sqlite3.DatabaseError, TypeError, ValueError):
        return 0


def classify_kakaotalk_macos_db_role(path: Path, analysis: Mapping[str, object]) -> str:
    lowered = str(path).lower()
    name = path.name.lower()
    if analysis.get("message_table_candidates"):
        return "conversation-database"
    if "chat" in lowered or "message" in lowered or name.startswith("talk"):
        return "conversation-store-candidate"
    if "friend" in lowered or "contact" in lowered or "profile" in lowered:
        return "contact-profile-database"
    if "media" in lowered or "image" in lowered or "thumb" in lowered or "cache" in lowered:
        return "media-cache-database"
    if name.endswith(".dat") and not analysis.get("plain_sqlite_header"):
        return "encrypted-or-custom-state"
    return "kakaotalk-macos-database"


def build_kakaotalk_macos_summary(
    root: Path,
    candidate_roots: Sequence[Path],
    records: Sequence[ArtifactRecord],
) -> ArtifactRecord | None:
    if not candidate_roots and not records:
        return None
    opened = 0
    plain_opened = 0
    sqlcipher_opened = 0
    encrypted_or_custom = 0
    message_candidates = 0
    message_rows = 0
    for record in records:
        details = record.details
        analysis = details.get("kakaotalk_macos_db_analysis") if isinstance(details, dict) else {}
        if not isinstance(analysis, Mapping):
            analysis = {}
        if analysis.get("db_opened"):
            opened += 1
        if analysis.get("db_access_status") == "plain-sqlite-opened":
            plain_opened += 1
        if analysis.get("db_access_status") == "sqlcipher-opened-read-only":
            sqlcipher_opened += 1
        if analysis.get("requires_sqlcipher_or_custom_decoder"):
            encrypted_or_custom += 1
        table_candidates = analysis.get("message_table_candidates") or []
        if table_candidates:
            message_candidates += 1
        try:
            message_rows += int(analysis.get("message_row_count_estimate") or 0)
        except (TypeError, ValueError):
            pass
    source_paths = [str(path.resolve()) for path in candidate_roots[:20]]
    details = {
        "parser": "kakaotalk-macos-summary",
        "parser_version": PARSER_VERSION,
        "coverage_status": "summary",
        "reportability": "triage",
        "source_path": str(root.resolve()),
        "candidate_root_count": len(candidate_roots),
        "candidate_roots": source_paths,
        "database_count": len(records),
        "opened_database_count": opened,
        "plain_sqlite_opened_count": plain_opened,
        "sqlcipher_opened_count": sqlcipher_opened,
        "encrypted_or_custom_store_count": encrypted_or_custom,
        "message_database_candidate_count": message_candidates,
        "message_row_count_estimate": message_rows,
        "content_exported": False,
        "db_analysis_supported": True,
        "validation_required": True,
        "validation_guidance": "Use this summary to decide whether Mac KakaoTalk DBs are plain SQLite, encrypted/custom, or need authorized SQLCipher/native validation.",
        "forensic_review": build_forensic_review(
            gap_id="#31",
            artifact_goal="macOS KakaoTalk database coverage summary",
            primary_evidence=[
                f"database_count={len(records)}",
                f"plain_sqlite_opened_count={plain_opened}",
                f"sqlcipher_opened_count={sqlcipher_opened}",
                f"encrypted_or_custom_store_count={encrypted_or_custom}",
                f"message_row_count_estimate={message_rows}",
            ],
            validation_required=True,
            report_grade_assessment={
                "report_grade_ready": False,
                "status": "macos-kakaotalk-summary-validation-required",
                "blockers": [
                    "known-answer-macos-kakaotalk-corpus-required",
                    "authorized-decryption-validation-required-for-encrypted-dbs",
                ],
                "validated_strengths": [
                    "candidate-roots-enumerated",
                    "db-openability-summarized",
                    "message-row-counts-estimated-without-content-export",
                ],
                "commercial_gap_ids": ["#31"],
                "next_validation_step": "Attach a known-answer Mac KakaoTalk fixture and trusted parser/export diff before claiming message completeness.",
            },
            commercial_grade_ready=False,
            caveats=[
                "This is a triage summary, not a complete decrypted-message report.",
                "macOS sandbox/container layouts vary by KakaoTalk version and distribution channel.",
            ],
        ),
        "commercial_grade_ready": False,
        "privacy_legal_warning": "KakaoTalk Mac data can include private communications; only analyze within authorized scope.",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    return ArtifactRecord(
        provider=KakaoTalkMacOsProvider.name,
        artifact_type="kakaotalk-macos-summary",
        path=str(root.resolve()),
        supported=True,
        details=details,
    )


def run_kakaotalk_macos_report(
    root: Path,
    *,
    output_dir: Path,
    include_message_text: bool = False,
    max_messages: int = DEFAULT_MACOS_REPORT_MAX_MESSAGES,
    max_context_rows: int = DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS,
    sqlcipher_bin: str = "sqlcipher",
) -> dict[str, object]:
    """Write a reviewable macOS KakaoTalk report package.

    The regular artifact collector intentionally avoids message body export. This
    report path is the explicit analyst-controlled workflow for turning an
    authorized macOS KakaoTalk SQLCipher/plain SQLite store into CSV/HTML review
    outputs. Raw SQLCipher keys and raw Kakao UserID values never leave memory.
    """

    root = root.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate_roots = list(iter_kakaotalk_macos_candidate_roots(root))
    database_paths = list(iter_kakaotalk_macos_databases(candidate_roots))
    sqlcipher_tool = resolve_sqlcipher_tool(sqlcipher_bin)
    messages: list[dict[str, object]] = []
    rooms: list[dict[str, object]] = []
    media: list[dict[str, object]] = []
    databases: list[dict[str, object]] = []
    context_row_coverage: list[dict[str, object]] = []
    remaining = max_messages if max_messages > 0 else 0

    for db_path in database_paths:
        sqlite_meta = inspect_sqlite_database(db_path)
        identity_context = build_kakaotalk_macos_identity_context(db_path)
        analysis = analyze_kakaotalk_macos_sqlite(db_path, sqlite_meta, identity_context=identity_context)
        source_hashes = compute_hashes(db_path)
        db_entry: dict[str, object] = {
            "source_path": str(db_path.resolve()),
            "source_size": safe_file_size(db_path),
            "source_hashes": dict(source_hashes),
            "db_access_status": analysis.get("db_access_status"),
            "message_row_count_estimate": analysis.get("message_row_count_estimate"),
            "sqlcipher_opened": False,
            "plain_sqlite_opened": analysis.get("db_access_status") == "plain-sqlite-opened",
            "compatibility_mode": None,
            "message_table": "",
            "message_export_status": "not-attempted",
        }
        exported_rows: list[dict[str, object]] = []
        table_name = ""

        db_access_status = str(analysis.get("db_access_status") or "")
        requires_sqlcipher = bool(analysis.get("requires_sqlcipher_or_custom_decoder")) or db_access_status == "sqlcipher-opened-read-only"
        if requires_sqlcipher and db_access_status != "plain-sqlite-opened":
            if not sqlcipher_tool:
                db_entry["message_export_status"] = "sqlcipher-not-installed"
            else:
                context = open_kakaotalk_macos_sqlcipher_context(db_path, identity_context, tool=sqlcipher_tool)
                if context is None:
                    db_entry["message_export_status"] = "sqlcipher-context-not-reopened"
                else:
                    db_entry["sqlcipher_opened"] = True
                    db_entry["db_access_status"] = "sqlcipher-opened-read-only"
                    db_entry["compatibility_mode"] = context["compatibility"]
                    exported_rows, table_name = read_kakaotalk_macos_sqlcipher_messages(
                        db_path,
                        key=str(context["key"]),
                        compatibility=int(context["compatibility"]),
                        table_names=list(context["table_names"]),
                        max_rows=remaining,
                        include_message_text=include_message_text,
                        tool=sqlcipher_tool,
                        source_hash=str(source_hashes.get("sha256", "")),
                    )
                    context_rows, context_coverage = read_kakaotalk_macos_sqlcipher_context_rows(
                        db_path,
                        key=str(context["key"]),
                        compatibility=int(context["compatibility"]),
                        table_names=list(context["table_names"]),
                        tool=sqlcipher_tool,
                        include_text=include_message_text,
                        source_hash=str(source_hashes.get("sha256", "")),
                        max_rows=max_context_rows,
                    )
                    rooms.extend(context_rows)
                    context_row_coverage.extend(context_coverage)
        elif db_access_status == "plain-sqlite-opened":
            exported_rows, table_name = read_kakaotalk_macos_plain_messages(
                db_path,
                max_rows=remaining,
                include_message_text=include_message_text,
                source_hash=str(source_hashes.get("sha256", "")),
            )
            context_rows, context_coverage = read_kakaotalk_macos_plain_context_rows(
                db_path,
                include_text=include_message_text,
                source_hash=str(source_hashes.get("sha256", "")),
                max_rows=max_context_rows,
            )
            rooms.extend(context_rows)
            context_row_coverage.extend(context_coverage)

        if exported_rows:
            db_entry["message_export_status"] = "exported"
            db_entry["message_table"] = table_name
            messages.extend(exported_rows)
            media.extend(extract_kakaotalk_macos_media_rows(exported_rows, source_hash=str(source_hashes.get("sha256", ""))))
            if max_messages > 0:
                remaining = max(max_messages - len(messages), 0)
        elif db_entry["message_export_status"] == "not-attempted":
            db_entry["message_export_status"] = "no-readable-message-table"
        databases.append(db_entry)
        if max_messages > 0 and remaining <= 0:
            break

    messages_csv = output_dir / "kakaotalk_macos_messages.csv"
    rooms_csv = output_dir / "kakaotalk_macos_rooms.csv"
    media_csv = output_dir / "kakaotalk_macos_media.csv"
    viewer_html = output_dir / "kakaotalk_macos_viewer.html"
    report_json = output_dir / "kakaotalk_macos_report.json"
    summary_json = output_dir / "kakaotalk_macos_summary.json"
    write_dict_csv(messages_csv, messages, message_csv_fields(include_message_text=include_message_text))
    write_dict_csv(rooms_csv, rooms, room_csv_fields(include_text=include_message_text))
    write_dict_csv(media_csv, media, media_csv_fields(include_text=include_message_text))
    render_kakaotalk_macos_viewer(
        viewer_html,
        messages=messages,
        rooms=rooms,
        media=media,
        context_row_coverage=context_row_coverage,
        include_message_text=include_message_text,
        root=root,
        max_messages=max_messages,
        max_context_rows=max_context_rows,
    )
    context_truncated_tables = [item for item in context_row_coverage if item.get("truncated")]

    payload: dict[str, object] = {
        "parser": "kakaotalk-macos-report",
        "parser_version": MACOS_REPORT_VERSION,
        "source_root": str(root),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "privacy": {
            "message_text_exported": include_message_text,
            "raw_user_id_exported": False,
            "sqlcipher_key_exported": False,
            "sqlcipher_invocation": "read-only",
        },
        "summary": {
            "database_count": len(database_paths),
            "processed_database_count": len(databases),
            "sqlcipher_opened_count": sum(1 for item in databases if item.get("sqlcipher_opened")),
            "plain_sqlite_opened_count": sum(1 for item in databases if item.get("plain_sqlite_opened")),
            "message_count": len(messages),
            "room_context_row_count": len(rooms),
            "room_context_row_estimate": sum(int(item.get("row_count") or 0) for item in context_row_coverage),
            "context_row_limit": max_context_rows,
            "context_limit_reached": bool(context_truncated_tables),
            "context_truncated_table_count": len(context_truncated_tables),
            "media_reference_count": len(media),
            "max_messages": max_messages,
            "message_limit_reached": bool(max_messages > 0 and len(messages) >= max_messages),
            "candidate_root_count": len(candidate_roots),
        },
        "databases": databases,
        "context_row_coverage": context_row_coverage,
        "outputs": {
            "report_json": str(report_json),
            "summary_json": str(summary_json),
            "messages_csv": str(messages_csv),
            "rooms_csv": str(rooms_csv),
            "media_csv": str(media_csv),
            "viewer_html": str(viewer_html),
        },
        "validation_required": True,
        "validation_guidance": (
            "Message bodies are exported only when explicitly requested. Validate row semantics and "
            "known-answer counts before using as court-ready message testimony."
        ),
    }
    report_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_json.write_text(json.dumps(payload["summary"], ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def resolve_sqlcipher_tool(sqlcipher_bin: str) -> str:
    resolved = shutil.which(sqlcipher_bin)
    if resolved:
        return resolved
    candidate = Path(sqlcipher_bin).expanduser()
    return str(candidate) if candidate.is_file() else ""


def safe_file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def open_kakaotalk_macos_sqlcipher_context(
    path: Path,
    identity_context: Mapping[str, object],
    *,
    tool: str,
) -> dict[str, object] | None:
    for candidate in sqlcipher_key_candidates(path, identity_context):
        for compatibility in (3, 4):
            table_names = sqlcipher_table_names(tool, path, candidate["key"], compatibility)
            if table_names is None:
                continue
            return {
                "key": candidate["key"],
                "user_id_sha256": candidate["user_id_sha256"],
                "compatibility": compatibility,
                "table_names": table_names,
            }
    return None


def read_kakaotalk_macos_sqlcipher_messages(
    path: Path,
    *,
    key: str,
    compatibility: int,
    table_names: Sequence[str],
    max_rows: int,
    include_message_text: bool,
    tool: str,
    source_hash: str,
) -> tuple[list[dict[str, object]], str]:
    table_name = select_kakaotalk_macos_message_table(table_names)
    if not table_name:
        return [], ""
    columns = sqlcipher_table_columns(tool, path, key, compatibility, table_name)
    if not columns:
        return [], table_name
    rows = run_sqlcipher_select_dicts(
        tool,
        path,
        key=key,
        compatibility=compatibility,
        table_name=table_name,
        columns=columns,
        order_columns=message_order_columns(columns),
        max_rows=max_rows,
    )
    return [
        normalize_kakaotalk_macos_message_row(
            row,
            source_path=path,
            source_hash=source_hash,
            table_name=table_name,
            row_index=index,
            include_message_text=include_message_text,
        )
        for index, row in enumerate(rows, start=1)
    ], table_name


def read_kakaotalk_macos_plain_messages(
    path: Path,
    *,
    max_rows: int,
    include_message_text: bool,
    source_hash: str,
) -> tuple[list[dict[str, object]], str]:
    try:
        with open_sqlite_snapshot(path) as connection:
            table_names = [
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            ]
            table_name = select_kakaotalk_macos_message_table(table_names)
            if not table_name:
                return [], ""
            columns = sqlite_columns(connection, table_name)
            order_clause = sqlite_order_clause(message_order_columns(columns))
            limit_clause = f" LIMIT {int(max_rows)}" if max_rows > 0 else ""
            selected = ", ".join(f'"{column}"' for column in columns if SAFE_SQL_NAME_RE.fullmatch(column))
            if not selected:
                return [], table_name
            rows = [
                dict(zip([column for column in columns if SAFE_SQL_NAME_RE.fullmatch(column)], row))
                for row in connection.execute(f'SELECT {selected} FROM "{table_name}"{order_clause}{limit_clause}').fetchall()
            ]
    except (sqlite3.DatabaseError, OSError):
        return [], ""
    return [
        normalize_kakaotalk_macos_message_row(
            row,
            source_path=path,
            source_hash=source_hash,
            table_name=table_name,
            row_index=index,
            include_message_text=include_message_text,
        )
        for index, row in enumerate(rows, start=1)
    ], table_name


def read_kakaotalk_macos_sqlcipher_context_rows(
    path: Path,
    *,
    key: str,
    compatibility: int,
    table_names: Sequence[str],
    tool: str,
    include_text: bool,
    source_hash: str,
    max_rows: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    coverage: list[dict[str, object]] = []
    for table_name in ("NTChatRoom", "NTUser"):
        if table_name not in table_names:
            continue
        columns = sqlcipher_table_columns(tool, path, key, compatibility, table_name)
        table_rows = run_sqlcipher_select_dicts(
            tool,
            path,
            key=key,
            compatibility=compatibility,
            table_name=table_name,
            columns=columns,
            order_columns=message_order_columns(columns),
            max_rows=max_rows,
        )
        row_count = sqlcipher_count_rows(tool, path, key, compatibility, table_name)
        for index, row in enumerate(table_rows, start=1):
            rows.append(normalize_kakaotalk_macos_context_row(row, table_name, index, path, source_hash, include_text))
        coverage.append(build_kakaotalk_macos_context_coverage(path, source_hash, table_name, row_count, len(table_rows), max_rows))
    return rows, coverage


def read_kakaotalk_macos_plain_context_rows(
    path: Path,
    *,
    include_text: bool,
    source_hash: str,
    max_rows: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    coverage: list[dict[str, object]] = []
    try:
        with open_sqlite_snapshot(path) as connection:
            table_names = [
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            ]
            for table_name in ("rooms", "chat_rooms", "NTChatRoom", "users", "NTUser"):
                if table_name not in table_names or not SAFE_SQL_NAME_RE.fullmatch(table_name):
                    continue
                columns = sqlite_columns(connection, table_name)
                selected_columns = [column for column in columns if SAFE_SQL_NAME_RE.fullmatch(column)]
                if not selected_columns:
                    continue
                selected = ", ".join(f'"{column}"' for column in selected_columns)
                row_count = sqlite_count(connection, table_name)
                limit_clause = f" LIMIT {int(max_rows)}" if max_rows > 0 else ""
                exported_for_table = 0
                for index, row in enumerate(connection.execute(f'SELECT {selected} FROM "{table_name}"{limit_clause}'), start=1):
                    exported_for_table += 1
                    rows.append(
                        normalize_kakaotalk_macos_context_row(
                            dict(zip(selected_columns, row)),
                            table_name,
                            index,
                            path,
                            source_hash,
                            include_text,
                        )
                    )
                coverage.append(
                    build_kakaotalk_macos_context_coverage(
                        path,
                        source_hash,
                        table_name,
                        row_count,
                        exported_for_table,
                        max_rows,
                    )
                )
    except (sqlite3.DatabaseError, OSError):
        return rows, coverage
    return rows, coverage


def build_kakaotalk_macos_context_coverage(
    path: Path,
    source_hash: str,
    table_name: str,
    row_count: int,
    exported_rows: int,
    max_rows: int,
) -> dict[str, object]:
    truncated = bool(max_rows > 0 and row_count > exported_rows)
    return {
        "source_database": str(path.resolve()),
        "source_database_sha256": source_hash,
        "source_table": table_name,
        "row_count": row_count,
        "exported_rows": exported_rows,
        "row_limit": max_rows,
        "truncated": truncated,
        "status": "truncated-context-export" if truncated else "complete",
    }


def select_kakaotalk_macos_message_table(table_names: Sequence[str]) -> str:
    for preferred in ("NTChatMessage", "messages", "chatLogs", "chat_messages"):
        if preferred in table_names:
            return preferred
    for table_name in table_names:
        if KAKAO_MAC_CHAT_TABLE_RE.search(table_name):
            return table_name
    return ""


def message_order_columns(columns: Sequence[str]) -> list[str]:
    ordered: list[str] = []
    for column in ("sentAt", "created_at", "createdAt", "sendAt", "timestamp", "logId", "id"):
        if column in columns:
            ordered.append(column)
    return ordered


def sqlite_order_clause(order_columns: Sequence[str]) -> str:
    safe = [column for column in order_columns if SAFE_SQL_NAME_RE.fullmatch(column)]
    return " ORDER BY " + ", ".join(f'"{column}"' for column in safe) if safe else ""


def run_sqlcipher_select_dicts(
    tool: str,
    path: Path,
    *,
    key: str,
    compatibility: int,
    table_name: str,
    columns: Sequence[str],
    order_columns: Sequence[str],
    max_rows: int,
) -> list[dict[str, object]]:
    if not SAFE_SQL_NAME_RE.fullmatch(table_name):
        return []
    selected_columns = [column for column in columns if SAFE_SQL_NAME_RE.fullmatch(column)]
    if not selected_columns:
        return []
    selected = ", ".join(f'"{column}"' for column in selected_columns)
    order_clause = sqlite_order_clause(order_columns)
    limit_clause = f" LIMIT {int(max_rows)}" if max_rows > 0 else ""
    sql = (
        f"PRAGMA cipher_default_compatibility = {compatibility};\n"
        f"PRAGMA key = '{key}';\n"
        f'SELECT {selected} FROM "{table_name}"{order_clause}{limit_clause};\n'
    )
    completed = run_sqlcipher_csv(tool, path, sql)
    if completed is None or completed.returncode != 0 or not completed.stdout.strip():
        return []
    reader = csv.DictReader(io.StringIO(completed.stdout))
    return [dict(row) for row in reader]


def run_sqlcipher_csv(tool: str, path: Path, sql: str) -> subprocess.CompletedProcess[str] | None:
    if not path.exists():
        return None
    try:
        completed = subprocess.run(
            [tool, "-readonly", "-ifexists", "-batch", "-header", "-csv", str(path)],
            input=sql.encode("utf-8"),
            capture_output=True,
            timeout=SQLCIPHER_TIMEOUT_SECONDS,
            check=False,
        )
        return subprocess.CompletedProcess(
            completed.args,
            completed.returncode,
            completed.stdout.decode("utf-8", errors="replace"),
            completed.stderr.decode("utf-8", errors="replace"),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def normalize_kakaotalk_macos_message_row(
    row: Mapping[str, object],
    *,
    source_path: Path,
    source_hash: str,
    table_name: str,
    row_index: int,
    include_message_text: bool,
) -> dict[str, object]:
    message_text = first_text(row, "message", "msg", "text", "content")
    attachment = first_text(row, "attachment")
    local_path = first_text(row, "localFilePath", "local_file_path", "path")
    normalized: dict[str, object] = {
        "row_index": row_index,
        "source_database": str(source_path.resolve()),
        "source_database_sha256": source_hash,
        "source_table": table_name,
        "chat_id": first_text(row, "chatId", "chat_id", "roomId", "room_id"),
        "log_id": first_text(row, "logId", "id"),
        "message_id": first_text(row, "msgId", "message_id"),
        "author_id": first_text(row, "authorId", "sender", "sender_id", "user_id"),
        "message_type": first_text(row, "type"),
        "status": first_text(row, "status"),
        "sent_at_raw": first_text(row, "sentAt", "sendAt", "created_at", "createdAt", "timestamp"),
        "sent_at_iso_guess": timestamp_iso_guess(first_text(row, "sentAt", "sendAt", "created_at", "createdAt", "timestamp")),
        "message_text_sha256": hash_text(message_text) if message_text else "",
        "message_text_length": len(message_text),
        "message_text_redacted": not include_message_text,
        "attachment_sha256": hash_text(attachment) if attachment else "",
        "attachment_length": len(attachment),
        "local_file_path": local_path,
        "local_file_path_sha256": hash_text(local_path) if local_path else "",
        "content_exported": include_message_text,
    }
    if include_message_text:
        normalized["message_text"] = message_text
        normalized["attachment"] = attachment
    else:
        normalized["message_text"] = ""
        normalized["attachment"] = ""
    return normalized


def normalize_kakaotalk_macos_context_row(
    row: Mapping[str, object],
    table_name: str,
    row_index: int,
    source_path: Path,
    source_hash: str,
    include_text: bool,
) -> dict[str, object]:
    display = first_text(row, "title", "name", "nickName", "displayName", "member", "members")
    row_json = json.dumps({str(k): stringify_scalar(v) for k, v in row.items()}, ensure_ascii=False, sort_keys=True)
    item: dict[str, object] = {
        "row_index": row_index,
        "source_database": str(source_path.resolve()),
        "source_database_sha256": source_hash,
        "source_table": table_name,
        "entity_id": first_text(row, "chatId", "userId", "id", "roomId"),
        "display_text_sha256": hash_text(display) if display else "",
        "display_text_length": len(display),
        "row_json_sha256": hash_text(row_json),
        "content_exported": include_text,
    }
    item["display_text"] = display if include_text else ""
    item["row_json"] = row_json if include_text else ""
    return item


def first_text(row: Mapping[str, object], *keys: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for key in keys:
        value = row.get(key)
        if value in (None, ""):
            value = lowered.get(key.lower())
        if value not in (None, ""):
            return stringify_scalar(value)
    return ""


def stringify_scalar(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def timestamp_iso_guess(value: str) -> str:
    if not value:
        return ""
    try:
        numeric = float(value)
    except ValueError:
        return ""
    candidates = [numeric]
    if numeric > 10_000_000_000:
        candidates.append(numeric / 1000.0)
    for candidate in candidates:
        if 946684800 <= candidate <= 4102444800:
            return dt.datetime.fromtimestamp(candidate, tz=dt.timezone.utc).isoformat()
    return ""


def extract_kakaotalk_macos_media_rows(messages: Sequence[Mapping[str, object]], *, source_hash: str) -> list[dict[str, object]]:
    media_rows: list[dict[str, object]] = []
    for message in messages:
        attachment = str(message.get("attachment") or "")
        local_path = str(message.get("local_file_path") or "")
        if not attachment and not local_path:
            continue
        parsed = parse_attachment_summary(attachment)
        media_rows.append(
            {
                "message_row_index": message.get("row_index"),
                "chat_id": message.get("chat_id"),
                "log_id": message.get("log_id"),
                "source_database_sha256": source_hash,
                "local_file_path": local_path,
                "local_file_path_sha256": hash_text(local_path) if local_path else "",
                "attachment_sha256": hash_text(attachment) if attachment else "",
                "attachment_length": len(attachment),
                "attachment_kind": parsed.get("kind", ""),
                "attachment_name": parsed.get("name", ""),
                "attachment_url_present": parsed.get("url_present", False),
            }
        )
    return media_rows


def parse_attachment_summary(attachment: str) -> dict[str, object]:
    if not attachment:
        return {}
    try:
        parsed = json.loads(attachment)
    except json.JSONDecodeError:
        return {"kind": "raw-text", "name": "", "url_present": "http" in attachment.lower()}
    if not isinstance(parsed, Mapping):
        return {"kind": type(parsed).__name__, "name": "", "url_present": False}
    name = ""
    for key in ("name", "fileName", "filename", "title"):
        if parsed.get(key):
            name = str(parsed[key])
            break
    return {
        "kind": str(parsed.get("type") or parsed.get("kind") or "json-object"),
        "name": name,
        "url_present": any("url" in str(key).lower() and bool(value) for key, value in parsed.items()),
    }


def message_csv_fields(*, include_message_text: bool) -> list[str]:
    fields = [
        "row_index",
        "chat_id",
        "log_id",
        "message_id",
        "author_id",
        "message_type",
        "status",
        "sent_at_raw",
        "sent_at_iso_guess",
        "message_text_sha256",
        "message_text_length",
        "message_text_redacted",
        "attachment_sha256",
        "attachment_length",
        "local_file_path",
        "local_file_path_sha256",
        "source_table",
        "source_database_sha256",
        "content_exported",
    ]
    if include_message_text:
        fields.insert(9, "message_text")
        fields.insert(15, "attachment")
    return fields


def room_csv_fields(*, include_text: bool) -> list[str]:
    fields = [
        "row_index",
        "source_table",
        "entity_id",
        "display_text_sha256",
        "display_text_length",
        "row_json_sha256",
        "source_database_sha256",
        "content_exported",
    ]
    if include_text:
        fields.insert(3, "display_text")
        fields.insert(7, "row_json")
    return fields


def media_csv_fields(*, include_text: bool) -> list[str]:
    return [
        "message_row_index",
        "chat_id",
        "log_id",
        "local_file_path",
        "local_file_path_sha256",
        "attachment_sha256",
        "attachment_length",
        "attachment_kind",
        "attachment_name",
        "attachment_url_present",
        "source_database_sha256",
    ]


def write_dict_csv(path: Path, rows: Sequence[Mapping[str, object]], fieldnames: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def render_kakaotalk_macos_viewer(
    path: Path,
    *,
    messages: Sequence[Mapping[str, object]],
    rooms: Sequence[Mapping[str, object]],
    media: Sequence[Mapping[str, object]],
    context_row_coverage: Sequence[Mapping[str, object]],
    include_message_text: bool,
    root: Path,
    max_messages: int,
    max_context_rows: int,
) -> None:
    rendered_messages = []
    for message in messages[:5_000]:
        text = str(message.get("message_text") or "")
        if not include_message_text:
            text = f"[redacted] sha256={message.get('message_text_sha256', '')}"
        rendered_messages.append(
            "\n".join(
                [
                    '<article class="bubble">',
                    f'<div class="meta">chat {escape_html(message.get("chat_id"))} · author {escape_html(message.get("author_id"))} · {escape_html(message.get("sent_at_raw"))}</div>',
                    f'<div class="body">{escape_html(text)}</div>',
                    f'<div class="cite">table {escape_html(message.get("source_table"))} · row {escape_html(message.get("row_index"))} · db {escape_html(str(message.get("source_database_sha256", ""))[:16])}</div>',
                    "</article>",
                ]
            )
        )
    context_warnings = [item for item in context_row_coverage if item.get("truncated")]
    rendered_context_warnings = []
    for item in context_warnings[:20]:
        rendered_context_warnings.append(
            "\n".join(
                [
                    '<div class="context-warning">',
                    f'<strong>{escape_html(item.get("source_table"))}</strong>',
                    (
                        f' exported {escape_html(item.get("exported_rows"))}/'
                        f'{escape_html(item.get("row_count"))} rows '
                        f'(limit {escape_html(item.get("row_limit"))})'
                    ),
                    f'<br><small>db {escape_html(str(item.get("source_database_sha256", ""))[:16])}</small>',
                    "</div>",
                ]
            )
        )
    html_text = "\n".join(
        [
            "<!doctype html>",
            '<html lang="ko">',
            "<head>",
            '<meta charset="utf-8">',
            "<title>RapidTriage macOS KakaoTalk Viewer</title>",
            "<style>",
            "body{margin:0;background:#f3efe7;color:#1f2933;font-family:-apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo','Malgun Gothic',sans-serif}",
            "header{position:sticky;top:0;background:#2f2518;color:#fff;padding:16px 22px;box-shadow:0 2px 12px #0002}",
            "main{display:grid;grid-template-columns:280px minmax(0,1fr);gap:20px;padding:20px}",
            ".panel{background:#fffdf9;border:1px solid #e5d8c2;border-radius:18px;padding:16px;box-shadow:0 8px 28px #8b6f4733}",
            ".stat{display:flex;justify-content:space-between;border-bottom:1px solid #eee0cc;padding:9px 0;font-size:14px}",
            ".timeline{max-width:920px;margin:0 auto;display:flex;flex-direction:column;gap:12px}",
            ".bubble{background:#fff;border:1px solid #eadcc8;border-radius:18px 18px 18px 4px;padding:12px 14px;box-shadow:0 4px 18px #8b6f4722}",
            ".meta,.cite{color:#7c6b5a;font-size:12px}.body{white-space:pre-wrap;line-height:1.55;margin:8px 0;font-size:15px}",
            ".warning{background:#fff2cc;border-color:#f0c36a}",
            ".context-warning{margin-top:10px;padding:10px;border-radius:12px;background:#fff7ed;border:1px solid #fed7aa;font-size:13px;line-height:1.45}",
            "</style>",
            "</head><body>",
            "<header><strong>RapidTriage macOS KakaoTalk Viewer</strong><br><small>정적 HTML 뷰어 · 외부 네트워크/스크립트 없음</small></header>",
            "<main>",
            '<aside class="panel">',
            "<h2>Case Summary</h2>",
            f'<div class="stat"><span>Source</span><span>{escape_html(root)}</span></div>',
            f'<div class="stat"><span>Messages</span><span>{len(messages)}</span></div>',
            f'<div class="stat"><span>Rooms/users</span><span>{len(rooms)}</span></div>',
            f'<div class="stat"><span>Context row limit</span><span>{max_context_rows}</span></div>',
            f'<div class="stat"><span>Media refs</span><span>{len(media)}</span></div>',
            f'<div class="stat"><span>Text exported</span><span>{include_message_text}</span></div>',
            f'<div class="stat"><span>Max messages</span><span>{max_messages}</span></div>',
            '<section class="panel warning"><strong>주의</strong><br>본문은 명시적으로 요청한 경우에만 포함됩니다. 법정 제출 전 known-answer 검증이 필요합니다.</section>',
            (
                '<section class="panel warning"><strong>Context export warning</strong>'
                '<br>대화방/사용자 context가 제한값을 넘어 일부만 CSV/HTML에 포함됐습니다.'
                + "".join(rendered_context_warnings)
                + "</section>"
                if context_warnings
                else ""
            ),
            "</aside>",
            '<section class="timeline">',
            *rendered_messages,
            "</section>",
            "</main></body></html>",
        ]
    )
    path.write_text(html_text, encoding="utf-8")


def escape_html(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def kakaotalk_macos_confidence(
    role: str,
    sqlite_meta: Mapping[str, object],
    analysis: Mapping[str, object],
    companions: Sequence[Mapping[str, object]],
) -> float:
    score = 0.45
    if "conversation" in role:
        score += 0.18
    if sqlite_meta.get("open_status") == "opened-read-only":
        score += 0.18
    if analysis.get("message_table_candidates"):
        score += 0.14
    if companions:
        score += 0.05
    return min(score, 0.9)


def kakaotalk_macos_risk_flags(
    role: str,
    sqlite_meta: Mapping[str, object],
    analysis: Mapping[str, object],
    companions: Sequence[Mapping[str, object]],
) -> list[str]:
    flags = ["kakaotalk-macos"]
    if "conversation" in role:
        flags.append("conversation-store-candidate")
    if sqlite_meta.get("open_status") == "opened-read-only":
        flags.append("plain-sqlite-opened")
    if analysis.get("requires_sqlcipher_or_custom_decoder"):
        flags.append("encrypted-or-custom-db")
    if analysis.get("message_table_candidates"):
        flags.append("message-table-candidate")
    if companions:
        flags.append("wal-shm-companions-present")
    return flags


def kakaotalk_macos_risk_score(
    role: str,
    sqlite_meta: Mapping[str, object],
    analysis: Mapping[str, object],
) -> int:
    score = 35
    if "conversation" in role:
        score += 25
    if sqlite_meta.get("open_status") == "opened-read-only":
        score += 10
    if analysis.get("message_table_candidates"):
        score += 20
    return min(score, 95)


def safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return path.name
