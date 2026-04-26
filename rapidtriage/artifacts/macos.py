from __future__ import annotations

import datetime as dt
import hashlib
import plistlib
import sqlite3
from pathlib import Path
from typing import Iterable

from ..core.models import ArtifactRecord
from .windows.browser import (
    build_browser_artifacts,
    build_browser_storage_only_artifacts,
    extract_chromium_history_and_downloads,
    extract_firefox_history,
    sqlite_table_exists,
)
from .windows.common import open_sqlite_snapshot

PARSER_VERSION = "macos-system-v1"
MACOS_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)
SKIP_USERS = {"shared", "guest", "daemon", "nobody"}
CHROMIUM_BROWSER_ROOTS = (
    ("chrome", ("Library", "Application Support", "Google", "Chrome")),
    ("edge", ("Library", "Application Support", "Microsoft Edge")),
    ("brave", ("Library", "Application Support", "BraveSoftware", "Brave-Browser")),
)
FIREFOX_PROFILE_ROOT = ("Library", "Application Support", "Firefox", "Profiles")
SAFARI_HISTORY = ("Library", "Safari", "History.db")
QUARANTINE_DB = ("Library", "Preferences", "com.apple.LaunchServices.QuarantineEventsV2")
LAUNCH_AGENT_DIRS = (
    ("Library", "LaunchAgents"),
    ("Library", "LaunchDaemons"),
)


class MacOsSystemArtifactsProvider:
    name = "macos-system-artifacts"
    collector_kind = "macos-system"
    description = "macOS user, browser, quarantine, and LaunchAgent triage artifacts"
    target_platform = "macos"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        if not looks_like_macos_evidence(root):
            return
        for user_root in iter_macos_user_homes(root):
            yield user_profile_record(user_root)
            yield from collect_macos_browsers(user_root)
            yield from collect_quarantine_events(user_root)
            yield from collect_launch_agents(user_root)
        yield from collect_system_launch_agents(root)


def looks_like_macos_evidence(root: Path) -> bool:
    if (root / "System" / "Library").is_dir() or (root / "private" / "var" / "db").is_dir():
        return True
    return any((candidate / "Library").is_dir() for candidate in iter_macos_user_homes(root))


def iter_macos_user_homes(root: Path) -> Iterable[Path]:
    users_dir = root / "Users"
    if users_dir.is_dir():
        for candidate in sorted(users_dir.iterdir(), key=lambda item: item.name.lower()):
            if candidate.is_dir() and candidate.name.lower() not in SKIP_USERS:
                yield candidate
        return
    if (root / "Library").is_dir():
        yield root


def user_profile_record(user_root: Path) -> ArtifactRecord:
    details = {
        "parser": "macos-user-profile",
        "parser_version": PARSER_VERSION,
        "coverage_status": "inventory",
        "reportability": "triage",
        "user_name": user_root.name,
        "home_path": str(user_root.resolve()),
        "source_path": str(user_root.resolve()),
        "modified_at": path_modified_at(user_root),
    }
    return ArtifactRecord(
        provider=MacOsSystemArtifactsProvider.name,
        artifact_type="macos-user-profile",
        path=str(user_root.resolve()),
        supported=True,
        details=details,
    )


def collect_macos_browsers(user_root: Path) -> Iterable[ArtifactRecord]:
    for browser_name, relative_parts in CHROMIUM_BROWSER_ROOTS:
        browser_root = user_root.joinpath(*relative_parts)
        if not browser_root.is_dir():
            continue
        for profile_dir in sorted(browser_root.iterdir(), key=lambda item: item.name.lower()):
            if not profile_dir.is_dir():
                continue
            history_path = profile_dir / "History"
            if not history_path.is_file():
                yield from build_browser_storage_only_artifacts(
                    provider=MacOsSystemArtifactsProvider.name,
                    user=user_root.name,
                    browser=browser_name,
                    profile=profile_dir.name,
                    profile_dir=profile_dir,
                    parser_version=PARSER_VERSION,
                    ai_conversation_artifact_type="macos-browser-ai-conversation",
                )
                continue
            history_rows, download_rows = extract_chromium_history_and_downloads(history_path)
            if history_rows or download_rows:
                yield from browser_records(user_root, browser_name, profile_dir.name, history_path, history_rows, download_rows)

    firefox_root = user_root.joinpath(*FIREFOX_PROFILE_ROOT)
    if firefox_root.is_dir():
        for profile_dir in sorted(firefox_root.iterdir(), key=lambda item: item.name.lower()):
            places_path = profile_dir / "places.sqlite"
            if not places_path.is_file():
                continue
            history_rows = extract_firefox_history(places_path)
            if history_rows:
                yield from browser_records(user_root, "firefox", profile_dir.name, places_path, history_rows, [])

    safari_path = user_root.joinpath(*SAFARI_HISTORY)
    if safari_path.is_file():
        history_rows = extract_safari_history(safari_path)
        if history_rows:
            yield from browser_records(user_root, "safari", "Default", safari_path, history_rows, [])


def browser_records(
    user_root: Path,
    browser: str,
    profile: str,
    path: Path,
    history_rows: list[dict[str, object]],
    download_rows: list[dict[str, object]],
) -> list[ArtifactRecord]:
    return build_browser_artifacts(
        provider=MacOsSystemArtifactsProvider.name,
        artifact_type="macos-browser-history-downloads",
        user=user_root.name,
        browser=browser,
        profile=profile,
        source_path=path,
        history_rows=history_rows,
        download_rows=download_rows,
        parser="macos-browser-history",
        parser_version=PARSER_VERSION,
        ai_artifact_type="macos-browser-ai-usage",
        ai_conversation_artifact_type="macos-browser-ai-conversation",
    )


def extract_safari_history(history_db: Path) -> list[dict[str, object]]:
    try:
        with open_sqlite_snapshot(history_db) as connection:
            if not sqlite_table_exists(connection, "history_items") or not sqlite_table_exists(connection, "history_visits"):
                return []
            rows = []
            for row in connection.execute(
                """
                SELECT
                    history_items.url AS url,
                    history_items.title AS title,
                    COUNT(history_visits.id) AS visit_count,
                    MAX(history_visits.visit_time) AS last_visit_time
                FROM history_items
                LEFT JOIN history_visits ON history_visits.history_item = history_items.id
                WHERE history_items.url IS NOT NULL AND history_items.url != ''
                GROUP BY history_items.id, history_items.url, history_items.title
                ORDER BY last_visit_time DESC, history_items.url ASC
                """
            ):
                rows.append(
                    {
                        "url": row["url"],
                        "title": row["title"] or "",
                        "visit_count": int(row["visit_count"] or 0),
                        "last_visited_at": isoformat_from_macos_absolute(row["last_visit_time"]),
                    }
                )
            return rows
    except (sqlite3.DatabaseError, OSError):
        return []


def collect_quarantine_events(user_root: Path) -> Iterable[ArtifactRecord]:
    path = user_root.joinpath(*QUARANTINE_DB)
    if not path.is_file():
        return
    source_hashes = file_hashes(path)
    for index, row in enumerate(extract_quarantine_rows(path)):
        yield ArtifactRecord(
            provider=MacOsSystemArtifactsProvider.name,
            artifact_type="macos-quarantine-event",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "macos-quarantine-events",
                "parser_version": PARSER_VERSION,
                "coverage_status": "parsed",
                "reportability": "triage",
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "source_index": index,
                "user": user_root.name,
                **row,
            },
        )


def extract_quarantine_rows(path: Path) -> list[dict[str, object]]:
    try:
        with open_sqlite_snapshot(path) as connection:
            if not sqlite_table_exists(connection, "LSQuarantineEvent"):
                return []
            rows = []
            for row in connection.execute(
                """
                SELECT
                    LSQuarantineTimeStamp AS timestamp,
                    LSQuarantineAgentName AS agent_name,
                    LSQuarantineDataURLString AS data_url,
                    LSQuarantineOriginURLString AS origin_url,
                    LSQuarantineSenderName AS sender_name
                FROM LSQuarantineEvent
                ORDER BY LSQuarantineTimeStamp DESC
                """
            ):
                rows.append(
                    {
                        "timestamp": isoformat_from_macos_absolute(row["timestamp"]),
                        "agent_name": row["agent_name"] or "",
                        "data_url": row["data_url"] or "",
                        "origin_url": row["origin_url"] or "",
                        "sender_name": row["sender_name"] or "",
                    }
                )
            return rows
    except (sqlite3.DatabaseError, OSError):
        return []


def collect_launch_agents(user_root: Path) -> Iterable[ArtifactRecord]:
    for relative_parts in LAUNCH_AGENT_DIRS[:1]:
        yield from collect_launch_agent_dir(user_root.joinpath(*relative_parts), owner=user_root.name)


def collect_system_launch_agents(root: Path) -> Iterable[ArtifactRecord]:
    for relative_parts in LAUNCH_AGENT_DIRS:
        yield from collect_launch_agent_dir(root.joinpath(*relative_parts), owner="system")


def collect_launch_agent_dir(path: Path, *, owner: str) -> Iterable[ArtifactRecord]:
    if not path.is_dir():
        return
    for plist_path in sorted(path.glob("*.plist"), key=lambda item: str(item).lower()):
        details = parse_launch_agent_plist(plist_path)
        yield ArtifactRecord(
            provider=MacOsSystemArtifactsProvider.name,
            artifact_type="macos-launch-agent",
            path=str(plist_path.resolve()),
            supported=True,
            details={
                "parser": "macos-launch-agent-plist",
                "parser_version": PARSER_VERSION,
                "coverage_status": "parsed" if details else "inventory",
                "reportability": "triage",
                "source_path": str(plist_path.resolve()),
                "source_hashes": file_hashes(plist_path),
                "owner": owner,
                "label": str(details.get("Label") or plist_path.stem),
                "program": str(details.get("Program") or ""),
                "program_arguments": list_strings(details.get("ProgramArguments")),
                "run_at_load": bool(details.get("RunAtLoad", False)),
                "modified_at": path_modified_at(plist_path),
            },
        )


def parse_launch_agent_plist(path: Path) -> dict[str, object]:
    try:
        payload = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def list_strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if value:
        return [str(value)]
    return []


def isoformat_from_macos_absolute(value: object) -> str:
    if value in (None, ""):
        return ""
    try:
        return (MACOS_EPOCH + dt.timedelta(seconds=float(value))).isoformat()
    except (TypeError, ValueError, OverflowError):
        return ""


def path_modified_at(path: Path) -> str:
    try:
        return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc).isoformat()
    except OSError:
        return ""


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
