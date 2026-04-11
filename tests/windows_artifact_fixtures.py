from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class ChromiumVisit:
    url: str
    title: str
    visited_at: datetime


@dataclass(frozen=True)
class ChromiumDownload:
    url: str
    target_path: str
    started_at: datetime
    total_bytes: int


@dataclass(frozen=True)
class RecentShortcut:
    name: str
    modified_at: datetime


@dataclass(frozen=True)
class WindowsArtifactFixture:
    root: Path
    chrome_visit: ChromiumVisit
    edge_visit: ChromiumVisit
    download: ChromiumDownload
    recent_shortcut: RecentShortcut


def build_windows_artifact_fixture(root: Path) -> WindowsArtifactFixture:
    chrome_visit = ChromiumVisit(
        url="https://example.com/browser-history",
        title="Browser History Fixture",
        visited_at=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    edge_visit = ChromiumVisit(
        url="https://contoso.example/downloads",
        title="Edge Download Portal",
        visited_at=datetime(2024, 2, 3, 4, 5, 6, tzinfo=timezone.utc),
    )
    download = ChromiumDownload(
        url="https://download.example/tools/installer.exe",
        target_path=r"C:\Users\alice\Downloads\installer.exe",
        started_at=datetime(2024, 2, 4, 5, 6, 7, tzinfo=timezone.utc),
        total_bytes=424242,
    )
    recent_shortcut = RecentShortcut(
        name="Incident Notes.docx.lnk",
        modified_at=datetime(2024, 3, 5, 6, 7, 8, tzinfo=timezone.utc),
    )

    chrome_history = root / "Users" / "alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "History"
    edge_history = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "History"
    recent_dir = root / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"

    _write_chromium_history(
        chrome_history,
        visits=[chrome_visit],
        downloads=[],
    )
    _write_chromium_history(
        edge_history,
        visits=[edge_visit],
        downloads=[download],
    )
    _write_recent_shortcuts(recent_dir, [recent_shortcut])

    return WindowsArtifactFixture(
        root=root,
        chrome_visit=chrome_visit,
        edge_visit=edge_visit,
        download=download,
        recent_shortcut=recent_shortcut,
    )


def _write_chromium_history(
    path: Path,
    *,
    visits: list[ChromiumVisit],
    downloads: list[ChromiumDownload],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        cursor = conn.cursor()
        cursor.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                visit_count INTEGER DEFAULT 0,
                typed_count INTEGER DEFAULT 0,
                last_visit_time INTEGER DEFAULT 0,
                hidden INTEGER DEFAULT 0
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER NOT NULL,
                visit_time INTEGER NOT NULL,
                from_visit INTEGER DEFAULT 0,
                transition INTEGER DEFAULT 0,
                segment_id INTEGER DEFAULT 0,
                visit_duration INTEGER DEFAULT 0
            );
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                guid TEXT,
                current_path TEXT,
                target_path TEXT,
                tab_url TEXT,
                tab_referrer_url TEXT,
                start_time INTEGER,
                end_time INTEGER,
                total_bytes INTEGER DEFAULT 0,
                mime_type TEXT,
                state INTEGER DEFAULT 1
            );
            """
        )
        for index, visit in enumerate(visits, start=1):
            chrome_time = _to_chrome_time(visit.visited_at)
            cursor.execute(
                "INSERT INTO urls (id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
                (index, visit.url, visit.title, 1, chrome_time),
            )
            cursor.execute(
                "INSERT INTO visits (id, url, visit_time) VALUES (?, ?, ?)",
                (index, index, chrome_time),
            )
        for index, download in enumerate(downloads, start=1):
            chrome_time = _to_chrome_time(download.started_at)
            cursor.execute(
                """
                INSERT INTO downloads (
                    id,
                    guid,
                    current_path,
                    target_path,
                    tab_url,
                    start_time,
                    end_time,
                    total_bytes,
                    state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    index,
                    f"fixture-{index}",
                    download.target_path,
                    download.target_path,
                    download.url,
                    chrome_time,
                    chrome_time,
                    download.total_bytes,
                    1,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _write_recent_shortcuts(path: Path, shortcuts: list[RecentShortcut]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for shortcut in shortcuts:
        shortcut_path = path / shortcut.name
        shortcut_path.write_bytes(b"LNK")
        ts = shortcut.modified_at.timestamp()
        os.utime(shortcut_path, (ts, ts))


def _to_chrome_time(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - CHROME_EPOCH
    return int(delta.total_seconds() * 1_000_000)
