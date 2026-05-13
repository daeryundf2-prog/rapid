from __future__ import annotations

import datetime as dt
import os
import re
import sqlite3
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .windows.common import build_forensic_review, open_sqlite_snapshot
from .kakaotalk_windows import companion_files, inspect_sqlite_database

PARSER_VERSION = "kakaotalk-macos-db-inventory-v1"
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
KAKAO_MAC_CHAT_TABLE_RE = re.compile(r"(?i)(chat|message|talk|log|channel|room)")
SAFE_SQL_NAME_RE = re.compile(r"[A-Za-z0-9_.$-]{1,128}")
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
    sqlite_analysis = analyze_kakaotalk_macos_sqlite(path, sqlite_meta)
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
            "kakaotalk-macos-encryption-or-sqlcipher-validation-required",
            "kakaotalk-macos-message-semantics-known-answer-required",
        ],
        "validated_strengths": [
            "source-hash-preserved",
            "sqlite-openability-tested",
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


def analyze_kakaotalk_macos_sqlite(path: Path, sqlite_meta: Mapping[str, object]) -> dict[str, object]:
    analysis: dict[str, object] = {
        "db_opened": sqlite_meta.get("open_status") == "opened-read-only",
        "db_access_status": sqlite_meta.get("open_status") or "unknown",
        "plain_sqlite_header": bool(sqlite_meta.get("sqlite_header")),
        "requires_sqlcipher_or_custom_decoder": not bool(sqlite_meta.get("sqlite_header")),
        "message_table_candidates": [],
        "message_row_count_estimate": 0,
        "schema_samples": [],
        "content_exported": False,
        "safe_message_content_status": "not-exported",
    }
    if sqlite_meta.get("open_status") != "opened-read-only":
        if not sqlite_meta.get("sqlite_header"):
            analysis["db_access_status"] = "encrypted-or-custom-store-validation-required"
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
                is_message_candidate = bool(KAKAO_MAC_CHAT_TABLE_RE.search(table_name)) or any(
                    KAKAO_MAC_CHAT_TABLE_RE.search(column) for column in columns
                )
                schema_row = {"table": table_name, "columns": columns[:24]}
                if len(analysis["schema_samples"]) < 20:
                    analysis["schema_samples"].append(schema_row)
                if not is_message_candidate:
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
        "plain_sqlite_opened_count": opened,
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
                f"plain_sqlite_opened_count={opened}",
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
