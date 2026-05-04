from __future__ import annotations

import os
import sqlite3
import struct
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


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
    ai_visit: ChromiumVisit
    ai_storage_log: Path
    edge_visit: ChromiumVisit
    download: ChromiumDownload
    recent_shortcut: RecentShortcut
    eventlog_xml: Path
    hayabusa_jsonl: Path
    evtx_file: Path
    user_profile: Path
    execution_reg: Path
    powershell_history: Path
    amcache_hive: Path
    prefetch_file: Path
    srum_csv: Path
    srum_db: Path
    mft_csv: Path
    mft_native: Path
    usn_jsonl: Path
    usn_journal: Path
    windows_search_csv: Path
    windows_edb: Path
    default_rdp: Path
    rdp_cache_file: Path
    rdp_reg: Path
    task_file: Path
    wmi_objects: Path


def build_windows_artifact_fixture(root: Path) -> WindowsArtifactFixture:
    chrome_visit = ChromiumVisit(
        url="https://example.com/browser-history",
        title="Browser History Fixture",
        visited_at=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )
    ai_visit = ChromiumVisit(
        url="https://chatgpt.com/?q=timeline%20analysis%20for%20evtx",
        title="ChatGPT - timeline analysis for evtx",
        visited_at=datetime(2024, 1, 2, 4, 5, 6, tzinfo=timezone.utc),
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
    ai_storage_log = (
        root
        / "Users"
        / "alice"
        / "AppData"
        / "Local"
        / "Google"
        / "Chrome"
        / "User Data"
        / "Default"
        / "Local Storage"
        / "leveldb"
        / "000003.log"
    )
    edge_history = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "History"
    recent_dir = root / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    logs_dir = root / "Windows" / "System32" / "winevt" / "Logs"
    eventlog_xml = logs_dir / "Security.xml"
    hayabusa_jsonl = root / "analysis" / "hayabusa-results.jsonl"
    evtx_file = logs_dir / "System.evtx"
    user_profile = root / "Users" / "alice"
    execution_reg = root / "Windows" / "System32" / "config" / "execution.reg"
    powershell_history = root / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
    amcache_hive = root / "Windows" / "AppCompat" / "Programs" / "Amcache.hve"
    prefetch_file = root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf"
    srum_csv = root / "analysis" / "srum.csv"
    srum_db = root / "Windows" / "System32" / "sru" / "SRUDB.dat"
    mft_csv = root / "analysis" / "mft.csv"
    mft_native = root / "$MFT"
    usn_jsonl = root / "analysis" / "usn.jsonl"
    usn_journal = root / "$Extend" / "$UsnJrnl" / "$J"
    windows_search_csv = root / "analysis" / "windows-search-index.csv"
    windows_edb = root / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows" / "Windows.edb"
    default_rdp = root / "Users" / "alice" / "Documents" / "Default.rdp"
    rdp_cache_file = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Terminal Server Client" / "Cache" / "Cache0000.bin"
    rdp_reg = root / "Windows" / "System32" / "config" / "rdp.reg"
    task_file = root / "Windows" / "System32" / "Tasks" / "Microsoft" / "Windows" / "UpdateOrchestrator" / "SecurityUpdater"
    wmi_objects = root / "Windows" / "System32" / "wbem" / "Repository" / "OBJECTS.DATA"

    _write_chromium_history(
        chrome_history,
        visits=[chrome_visit, ai_visit],
        downloads=[],
    )
    _write_ai_storage_fixture(ai_storage_log)
    _write_browser_storage_inventory_fixture(chrome_history.parent)
    _write_chromium_history(
        edge_history,
        visits=[edge_visit],
        downloads=[download],
    )
    _write_recent_shortcuts(recent_dir, [recent_shortcut])
    _write_eventlog_fixtures(eventlog_xml, hayabusa_jsonl, evtx_file)
    _write_user_profile_fixtures(user_profile, root / "Windows" / "System32" / "config" / "SYSTEM.reg")
    _write_execution_fixtures(execution_reg, powershell_history, amcache_hive)
    _write_prefetch_fixture(prefetch_file)
    _write_srum_fixture(srum_csv)
    _write_srum_database_fixture(srum_db)
    _write_filesystem_fixtures(mft_csv, usn_jsonl, mft_native, usn_journal)
    _write_windows_search_fixture(windows_search_csv, windows_edb)
    _write_remote_access_fixtures(default_rdp, rdp_cache_file, rdp_reg)
    _write_task_scheduler_fixture(task_file)
    _write_wmi_repository_fixture(wmi_objects)

    return WindowsArtifactFixture(
        root=root,
        chrome_visit=chrome_visit,
        ai_visit=ai_visit,
        ai_storage_log=ai_storage_log,
        edge_visit=edge_visit,
        download=download,
        recent_shortcut=recent_shortcut,
        eventlog_xml=eventlog_xml,
        hayabusa_jsonl=hayabusa_jsonl,
        evtx_file=evtx_file,
        user_profile=user_profile,
        execution_reg=execution_reg,
        powershell_history=powershell_history,
        amcache_hive=amcache_hive,
        prefetch_file=prefetch_file,
        srum_csv=srum_csv,
        srum_db=srum_db,
        mft_csv=mft_csv,
        mft_native=mft_native,
        usn_jsonl=usn_jsonl,
        usn_journal=usn_journal,
        windows_search_csv=windows_search_csv,
        windows_edb=windows_edb,
        default_rdp=default_rdp,
        rdp_cache_file=rdp_cache_file,
        rdp_reg=rdp_reg,
        task_file=task_file,
        wmi_objects=wmi_objects,
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


def _write_ai_storage_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"\x00chatgpt.com\x00"
        b'{"role":"user","content":"How do I build an EVTX forensic timeline?"}\n'
        b'{"role":"assistant","content":"Correlate EventRecordID, TimeCreated, channel, user, source IP, and process fields."}\n'
        b'{"prompt":"Find AI usage in browser artifacts","answer":"Check History plus Local Storage, IndexedDB, Session Storage, and Cache."}\n'
    )


def _write_browser_storage_inventory_fixture(profile_dir: Path) -> None:
    cache_entry = profile_dir / "Cache" / "Cache_Data" / "f_000001"
    session_entry = profile_dir / "Session Storage" / "000004.log"
    extension_manifest = profile_dir / "Extensions" / "abcdefghijklmnopabcdefghijklmnop" / "1.0.0" / "manifest.json"
    sync_metadata = profile_dir / "Sync Data" / "LevelDB" / "000005.ldb"
    cookies_db = profile_dir / "Network" / "Cookies"
    cache_entry.parent.mkdir(parents=True, exist_ok=True)
    session_entry.parent.mkdir(parents=True, exist_ok=True)
    extension_manifest.parent.mkdir(parents=True, exist_ok=True)
    sync_metadata.parent.mkdir(parents=True, exist_ok=True)
    cookies_db.parent.mkdir(parents=True, exist_ok=True)
    cache_entry.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\ncached browser response")
    session_entry.write_bytes(b'{"session":"chatgpt-tab","last_url":"https://chatgpt.com/c/fixture"}')
    extension_manifest.write_text(
        '{"name":"Fixture Extension","version":"1.0.0","permissions":["storage"]}',
        encoding="utf-8",
    )
    sync_metadata.write_bytes(b"sync_metadata\x00account_id_redacted\x00")
    cookies_db.write_bytes(b"SQLite format 3\x00fixture cookie store placeholder")


def _write_recent_shortcuts(path: Path, shortcuts: list[RecentShortcut]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    timestamp = shortcuts[0].modified_at if shortcuts else datetime(2024, 1, 1, tzinfo=timezone.utc)
    for shortcut in shortcuts:
        shortcut_path = path / shortcut.name
        target_path = rf"C:\Users\alice\Documents\{shortcut.name.removesuffix('.lnk')}"
        shortcut_path.write_bytes(build_minimal_lnk(target_path, shortcut.modified_at))
        ts = shortcut.modified_at.timestamp()
        os.utime(shortcut_path, (ts, ts))
    automatic = path / "AutomaticDestinations" / "5f7b5f1e01b83767.automaticDestinations-ms"
    custom = path / "CustomDestinations" / "9b9cdc69c1c24e2b.customDestinations-ms"
    automatic.parent.mkdir(parents=True, exist_ok=True)
    custom.parent.mkdir(parents=True, exist_ok=True)
    automatic.write_bytes(
        build_minimal_ole_jumplist_streams(
            [
                (
                    "DestList",
                    build_minimal_destlist(
                        1,
                        r"C:\Users\alice\Documents\Incident Notes.docx",
                        timestamp,
                    ),
                ),
                (
                    "1",
                    build_minimal_lnk(r"C:\Users\alice\Documents\Incident Notes.docx", timestamp),
                ),
            ]
        )
    )
    custom.write_bytes(
        b"JUMPLIST:CUSTOM\x00"
        + build_minimal_lnk(r"C:\Users\alice\Downloads\installer.exe", timestamp)
    )


def build_minimal_lnk(target_path: str, timestamp: datetime) -> bytes:
    link_flags = 0x00000008 | 0x00000010 | 0x00000020 | 0x00000080
    header = bytearray(0x4C)
    header[0:4] = (0x4C).to_bytes(4, "little")
    header[4:20] = LNK_CLSID
    header[0x14:0x18] = link_flags.to_bytes(4, "little")
    header[0x18:0x1C] = (0x20).to_bytes(4, "little")
    filetime = datetime_to_filetime(timestamp)
    header[0x1C:0x24] = filetime.to_bytes(8, "little")
    header[0x24:0x2C] = filetime.to_bytes(8, "little")
    header[0x2C:0x34] = filetime.to_bytes(8, "little")
    header[0x34:0x38] = (4096).to_bytes(4, "little")
    header[0x3C:0x40] = (1).to_bytes(4, "little")
    return (
        bytes(header)
        + lnk_unicode_string(target_path)
        + lnk_unicode_string(r"C:\Users\alice\Documents")
        + lnk_unicode_string("")
        + build_lnk_tracker_block("ALICE-PC")
        + b"\x00\x00\x00\x00"
    )


def build_lnk_tracker_block(machine_id: str) -> bytes:
    block = bytearray(0x60)
    block[0:4] = (0x60).to_bytes(4, "little")
    block[4:8] = (0xA0000003).to_bytes(4, "little")
    block[8:12] = (0x58).to_bytes(4, "little")
    block[12:16] = (0).to_bytes(4, "little")
    block[0x10:0x20] = machine_id.encode("cp1252")[:15].ljust(16, b"\x00")
    block[0x20:0x30] = bytes.fromhex("785634123412785690abcdef12345678")
    block[0x30:0x40] = bytes.fromhex("21436587ba09fedc1032547698badcfe")
    block[0x40:0x50] = bytes.fromhex("efcdab89674523011032547698badcfe")
    block[0x50:0x60] = bytes.fromhex("0badf00d34127856aabbccddeeff0011")
    return bytes(block)


def build_minimal_ole_jumplist(stream_name: str, stream_payload: bytes) -> bytes:
    return build_minimal_ole_jumplist_streams([(stream_name, stream_payload)])


def build_minimal_ole_jumplist_streams(streams: list[tuple[str, bytes]]) -> bytes:
    sector_size = 512
    header = bytearray(sector_size)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    header[24:26] = (0x003E).to_bytes(2, "little")
    header[26:28] = (0x0003).to_bytes(2, "little")
    header[28:30] = (0xFFFE).to_bytes(2, "little")
    header[30:32] = (9).to_bytes(2, "little")
    header[32:34] = (6).to_bytes(2, "little")
    header[44:48] = (1).to_bytes(4, "little")
    header[48:52] = (1).to_bytes(4, "little")
    header[56:60] = (4096).to_bytes(4, "little")
    header[60:64] = (0xFFFFFFFF).to_bytes(4, "little")
    header[64:68] = (0).to_bytes(4, "little")
    header[68:72] = (0xFFFFFFFF).to_bytes(4, "little")
    header[72:76] = (0).to_bytes(4, "little")
    header[76:80] = (0).to_bytes(4, "little")
    for offset in range(80, 512, 4):
        header[offset : offset + 4] = (0xFFFFFFFF).to_bytes(4, "little")

    stream_sector_ranges: list[tuple[int, int]] = []
    next_sector_id = 2
    for _, stream_payload in streams:
        stream_sector_count = max(1, (len(stream_payload) + sector_size - 1) // sector_size)
        stream_sector_ranges.append((next_sector_id, stream_sector_count))
        next_sector_id += stream_sector_count
    fat_entries = [0xFFFFFFFF for _ in range(next_sector_id)]
    fat_entries[0] = 0xFFFFFFFD
    fat_entries[1] = 0xFFFFFFFE
    for start_sector, stream_sector_count in stream_sector_ranges:
        for index in range(stream_sector_count):
            sector_id = start_sector + index
            is_last = index == stream_sector_count - 1
            fat_entries[sector_id] = 0xFFFFFFFE if is_last else sector_id + 1
    fat_sector = bytearray(sector_size)
    for index in range(sector_size // 4):
        value = fat_entries[index] if index < len(fat_entries) else 0xFFFFFFFF
        fat_sector[index * 4 : index * 4 + 4] = value.to_bytes(4, "little")

    directory_sector = bytearray(sector_size)
    directory_sector[0:128] = cfb_directory_entry("Root Entry", 5, child_id=1)
    for index, ((stream_name, stream_payload), (start_sector, _)) in enumerate(zip(streams, stream_sector_ranges), start=1):
        right_id = index + 1 if index < len(streams) else 0xFFFFFFFF
        directory_sector[index * 128 : (index + 1) * 128] = cfb_directory_entry(
            stream_name,
            2,
            right_id=right_id,
            start_sector=start_sector,
            stream_size=len(stream_payload),
        )
    stream_bytes = b"".join(
        stream_payload.ljust(stream_sector_count * sector_size, b"\x00")
        for (_, stream_payload), (_, stream_sector_count) in zip(streams, stream_sector_ranges)
    )
    return bytes(header) + bytes(fat_sector) + bytes(directory_sector) + stream_bytes


def cfb_directory_entry(
    name: str,
    object_type: int,
    *,
    right_id: int = 0xFFFFFFFF,
    child_id: int = 0xFFFFFFFF,
    start_sector: int = 0xFFFFFFFF,
    stream_size: int = 0,
) -> bytes:
    entry = bytearray(128)
    encoded_name = (name + "\x00").encode("utf-16le")[:64]
    entry[: len(encoded_name)] = encoded_name
    entry[64:66] = len(encoded_name).to_bytes(2, "little")
    entry[66] = object_type
    entry[67] = 1
    entry[68:72] = (0xFFFFFFFF).to_bytes(4, "little")
    entry[72:76] = right_id.to_bytes(4, "little")
    entry[76:80] = child_id.to_bytes(4, "little")
    entry[116:120] = start_sector.to_bytes(4, "little")
    entry[120:128] = stream_size.to_bytes(8, "little")
    return bytes(entry)


def build_minimal_destlist(stream_id: int, target_path: str, timestamp: datetime) -> bytes:
    header = bytearray(32)
    header[0:4] = (3).to_bytes(4, "little")
    header[4:8] = (1).to_bytes(4, "little")
    header[16:24] = stream_id.to_bytes(8, "little")

    entry = bytearray(114)
    guid_values = (
        "11111111-2222-3333-4444-555555555555",
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
        "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
        "12345678-1234-5678-9abc-def012345678",
    )
    for index, value in enumerate(guid_values):
        entry[index * 16 : index * 16 + 16] = uuid.UUID(value).bytes_le
    entry[64:80] = "ALICEPC".encode("utf-16le").ljust(16, b"\x00")
    entry[80:84] = stream_id.to_bytes(4, "little")
    entry[88:96] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    entry[96:100] = (3).to_bytes(4, "little")
    entry[100:104] = stream_id.to_bytes(4, "little")
    entry[112:114] = len(target_path).to_bytes(2, "little")
    return bytes(header) + bytes(entry) + target_path.encode("utf-16le")


def lnk_unicode_string(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    return (len(value)).to_bytes(2, "little") + encoded


def datetime_to_filetime(value: datetime) -> int:
    return int((value.astimezone(timezone.utc) - CHROME_EPOCH).total_seconds() * 10_000_000)


def filetime_reg_hex(value: datetime) -> str:
    raw = datetime_to_filetime(value).to_bytes(8, "little")
    return ",".join(f"{byte:02x}" for byte in raw)


def reg_hex_from_bytes(raw: bytes) -> str:
    return ",".join(f"{byte:02x}" for byte in raw)


def sam_f_reg_hex(*, last_logon: datetime, password_last_set: datetime, rid: int, uac: int) -> str:
    raw = bytearray(0x44)
    raw[0x08:0x10] = datetime_to_filetime(last_logon).to_bytes(8, "little")
    raw[0x18:0x20] = datetime_to_filetime(password_last_set).to_bytes(8, "little")
    raw[0x30:0x34] = rid.to_bytes(4, "little")
    raw[0x34:0x38] = (513).to_bytes(4, "little")
    raw[0x38:0x3C] = uac.to_bytes(4, "little")
    raw[0x42:0x44] = (7).to_bytes(2, "little")
    return reg_hex_from_bytes(bytes(raw))


def sam_v_reg_hex(*strings: str) -> str:
    return reg_hex_from_bytes(("\x00".join(strings) + "\x00").encode("utf-16le"))


def build_minimal_evtx(record_id: int, timestamp: datetime, strings: list[str]) -> bytes:
    payload = build_minimal_binxml_fragment(strings) + b"".join(
        value.encode("utf-16le") + b"\x00\x00" for value in strings
    )
    size = 28 + len(payload)
    record = (
        b"**\x00\x00"
        + size.to_bytes(4, "little")
        + record_id.to_bytes(8, "little")
        + datetime_to_filetime(timestamp).to_bytes(8, "little")
        + payload
        + size.to_bytes(4, "little")
    )
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    header[24:32] = (record_id + 1).to_bytes(8, "little")
    header[32:36] = (4096).to_bytes(4, "little")
    header[36:38] = (1).to_bytes(2, "little")
    header[38:40] = (3).to_bytes(2, "little")
    header[40:42] = (4096).to_bytes(2, "little")
    header[42:44] = (1).to_bytes(2, "little")
    return bytes(header) + record


def build_template_evtx(record_id: int, timestamp: datetime, command: str) -> bytes:
    payload = b"\x0f\x01\x01\x00" + build_minimal_binxml_template_instance(command)
    size = 28 + len(payload)
    record = (
        b"**\x00\x00"
        + size.to_bytes(4, "little")
        + record_id.to_bytes(8, "little")
        + datetime_to_filetime(timestamp).to_bytes(8, "little")
        + payload
        + size.to_bytes(4, "little")
    )
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    header[24:32] = (record_id + 1).to_bytes(8, "little")
    header[32:36] = (4096).to_bytes(4, "little")
    header[36:38] = (1).to_bytes(2, "little")
    header[38:40] = (3).to_bytes(2, "little")
    header[40:42] = (4096).to_bytes(2, "little")
    header[42:44] = (1).to_bytes(2, "little")
    return bytes(header) + record


def build_evtx_with_slack_record(record_id: int, timestamp: datetime, strings: list[str]) -> bytes:
    source = build_minimal_evtx(record_id, timestamp, strings)
    record = source[4096:]
    header = bytearray(source[:4096])
    chunk = bytearray(512)
    chunk[0:8] = b"ElfChnk\x00"
    chunk[8:16] = record_id.to_bytes(8, "little")
    chunk[16:24] = record_id.to_bytes(8, "little")
    chunk[24:32] = record_id.to_bytes(8, "little")
    chunk[32:40] = record_id.to_bytes(8, "little")
    chunk[40:44] = (512).to_bytes(4, "little")
    chunk[44:48] = (512).to_bytes(4, "little")
    return bytes(header) + bytes(chunk) + (b"\x00" * 128) + record


def build_evtx_with_checked_chunk(record_id: int, timestamp: datetime, strings: list[str]) -> bytes:
    source = build_minimal_evtx(record_id, timestamp, strings)
    record = source[4096:]
    header = bytearray(source[:4096])
    chunk = bytearray(65536)
    chunk[0:8] = b"ElfChnk\x00"
    chunk[8:16] = record_id.to_bytes(8, "little")
    chunk[16:24] = record_id.to_bytes(8, "little")
    chunk[24:32] = record_id.to_bytes(8, "little")
    chunk[32:40] = record_id.to_bytes(8, "little")
    free_space_offset = 512 + len(record)
    chunk[40:44] = (512).to_bytes(4, "little")
    chunk[44:48] = free_space_offset.to_bytes(4, "little")
    chunk[48:52] = free_space_offset.to_bytes(4, "little")
    chunk[512:free_space_offset] = record
    chunk[52:56] = _fixture_crc32(chunk[512:free_space_offset]).to_bytes(4, "little")
    chunk[124:128] = _fixture_crc32(chunk[:120]).to_bytes(4, "little")
    return bytes(header) + bytes(chunk)


def _fixture_crc32(value: bytes) -> int:
    return zlib.crc32(value) & 0xFFFFFFFF


def build_corrupt_evtx_record_candidate(record_id: int, timestamp: datetime, strings: list[str]) -> bytes:
    blob = bytearray(build_minimal_evtx(record_id, timestamp, strings))
    declared_size = len(blob) - 4096 + 2048
    blob[4096 + 4 : 4096 + 8] = declared_size.to_bytes(4, "little")
    return bytes(blob)


def build_minimal_binxml_template_instance(command: str) -> bytes:
    template_body = (
        b"\x0f\x01\x01\x00"
        + _binxml_element(
            "Event",
            [
                _binxml_element(
                    "System",
                    [
                        _binxml_element_with_attributes(
                            "Provider",
                            [("Name", "Microsoft-Windows-PowerShell")],
                            [],
                        ),
                        _binxml_element("EventID", [_binxml_value("4104")]),
                        _binxml_element("Level", [_binxml_value("3")]),
                        _binxml_element("Channel", [_binxml_value("Microsoft-Windows-PowerShell/Operational")]),
                        _binxml_element("Computer", [_binxml_value("WIN-TEMPLATE")]),
                    ],
                ),
                _binxml_element(
                    "EventData",
                    [
                        _binxml_element_with_attributes(
                            "Data",
                            [("Name", "CommandLine")],
                            [_binxml_substitution(0, 0x01)],
                        )
                    ],
                )
            ],
        )
        + b"\x00"
    )
    encoded_command = command.encode("utf-16le")
    value_spec = (
        (1).to_bytes(4, "little")
        + len(encoded_command).to_bytes(2, "little")
        + b"\x01\x00"
        + encoded_command
    )
    template_id = bytes.fromhex("00112233445566778899aabbccddeeff")
    return b"\x0c\xb0" + template_id + len(template_body).to_bytes(4, "little") + template_body + value_spec


def build_minimal_binxml_fragment(strings: list[str]) -> bytes:
    provider = strings[0] if len(strings) > 0 else "Provider"
    channel = strings[1] if len(strings) > 1 else "System"
    computer = strings[2] if len(strings) > 2 else "WIN-FIXTURE"
    command = strings[3] if len(strings) > 3 else "cmd.exe /c whoami"
    event = (
        _binxml_element(
            "Event",
            [
                _binxml_element(
                    "System",
                    [
                        _binxml_element_with_attributes("Provider", [("Name", provider)], []),
                        _binxml_element("EventID", [_binxml_value("4104")]),
                        _binxml_element("Level", [_binxml_value("3")]),
                        _binxml_element_with_raw_attributes(
                            "TimeCreated",
                            [("SystemTime", _binxml_filetime(datetime(2024, 4, 1, 3, 4, 5, tzinfo=timezone.utc)))],
                            [],
                        ),
                        _binxml_element_with_raw_attributes(
                            "Execution",
                            [("ProcessID", _binxml_uint32(4321)), ("ThreadID", _binxml_uint32(8765))],
                            [],
                        ),
                        _binxml_element("Channel", [_binxml_value(channel)]),
                        _binxml_element("Computer", [_binxml_value(computer)]),
                        _binxml_element_with_raw_attributes(
                            "Security",
                            [("UserID", _binxml_sid(5, [21, 111, 222, 333, 1001]))],
                            [],
                        ),
                    ],
                ),
                _binxml_element(
                    "EventData",
                    [
                        _binxml_element("CommandLine", [_binxml_value(command)]),
                        _binxml_element("SubjectUserSid", [_binxml_sid(5, [21, 111, 222, 333, 1001])]),
                        _binxml_element("ProcessId", [_binxml_uint32(4321)]),
                        _binxml_element("IsElevated", [_binxml_bool(True)]),
                        _binxml_element("CpuSeconds", [_binxml_float64(12.5)]),
                        _binxml_element("RiskRatio", [_binxml_float32(0.25)]),
                        _binxml_element("ActivityGuid", [_binxml_guid(bytes.fromhex("00112233445566778899aabbccddeeff"))]),
                        _binxml_element("PayloadHash", [_binxml_binary(bytes.fromhex("feedface"))]),
                    ],
                ),
            ],
        )
    )
    return b"\x0f\x01\x01\x00" + event + b"\x00"


def _binxml_element(name: str, children: list[bytes]) -> bytes:
    return b"\x01\xff\xff\x00\x00\x00\x00" + _binxml_name(name) + b"\x02" + b"".join(children) + b"\x04"


def _binxml_element_with_attributes(name: str, attributes: list[tuple[str, str]], children: list[bytes]) -> bytes:
    return _binxml_element_with_raw_attributes(
        name,
        [(attribute_name, _binxml_value(value)) for attribute_name, value in attributes],
        children,
    )


def _binxml_element_with_raw_attributes(name: str, attributes: list[tuple[str, bytes]], children: list[bytes]) -> bytes:
    return (
        b"\x41\xff\xff\x00\x00\x00\x00"
        + _binxml_name(name)
        + b"".join(_binxml_attribute_raw(attribute_name, value) for attribute_name, value in attributes)
        + b"\x02"
        + b"".join(children)
        + b"\x04"
    )


def _binxml_attribute(name: str, value: str) -> bytes:
    return _binxml_attribute_raw(name, _binxml_value(value))


def _binxml_attribute_raw(name: str, value: bytes) -> bytes:
    return b"\x06" + _binxml_name(name) + value


def _binxml_value(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    return b"\x05\x01" + len(value).to_bytes(2, "little") + encoded


def _binxml_uint32(value: int) -> bytes:
    return b"\x05\x08" + value.to_bytes(4, "little")


def _binxml_bool(value: bool) -> bytes:
    return b"\x05\x0d" + (1 if value else 0).to_bytes(4, "little")


def _binxml_float32(value: float) -> bytes:
    return b"\x05\x0b" + struct.pack("<f", value)


def _binxml_float64(value: float) -> bytes:
    return b"\x05\x0c" + struct.pack("<d", value)


def _binxml_filetime(value: datetime) -> bytes:
    return b"\x05\x11" + datetime_to_filetime(value).to_bytes(8, "little")


def _binxml_guid(value: bytes) -> bytes:
    return b"\x05\x0f" + value[:16].ljust(16, b"\x00")


def _binxml_sid(identifier_authority: int, sub_authorities: list[int]) -> bytes:
    sid = (
        b"\x01"
        + len(sub_authorities).to_bytes(1, "little")
        + identifier_authority.to_bytes(6, "big")
        + b"".join(value.to_bytes(4, "little") for value in sub_authorities)
    )
    return b"\x05\x13" + sid


def _binxml_binary(value: bytes) -> bytes:
    return b"\x05\x0e" + len(value).to_bytes(2, "little") + value


def _binxml_substitution(index: int, value_type: int) -> bytes:
    return b"\x0d" + index.to_bytes(2, "little") + bytes([value_type])


def _binxml_name(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    return (0).to_bytes(2, "little") + len(value).to_bytes(2, "little") + encoded + b"\x00\x00"


def build_minimal_registry_hive(timestamp: datetime, embedded_name: str, strings: list[str]) -> bytes:
    header = bytearray(4096)
    header[0:4] = b"regf"
    header[4:8] = (7).to_bytes(4, "little")
    header[8:12] = (7).to_bytes(4, "little")
    header[12:20] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[24:28] = (5).to_bytes(4, "little")
    header[36:40] = (32).to_bytes(4, "little")
    header[40:44] = (4096).to_bytes(4, "little")
    header[44:48] = (1).to_bytes(4, "little")
    header[48:112] = embedded_name.encode("utf-16le")[:64].ljust(64, b"\x00")
    header[508:512] = (0x12345678).to_bytes(4, "little")
    has_run_string = any("Run" in value for value in strings)
    root_name = "Software" if has_run_string else embedded_name
    child_name = "Run" if has_run_string else f"{embedded_name[:16]}Key"
    deleted_key_name = "DeletedRun" if has_run_string else f"Deleted{embedded_name[:16]}"
    value_name = "SecurityUpdater" if any("SecurityUpdater" in value for value in strings) else "SampleValue"
    root_relative_offset = 32
    root_size = _registry_cell_size(0x4C + len(root_name.encode("latin-1", errors="ignore")))
    subkey_list_relative_offset = root_relative_offset + root_size
    subkey_list_size = _registry_cell_size(12)
    child_relative_offset = subkey_list_relative_offset + subkey_list_size
    child_size = _registry_cell_size(0x4C + len(child_name.encode("latin-1", errors="ignore")))
    value_list_cell_relative_offset = child_relative_offset + child_size
    value_list_data_relative_offset = value_list_cell_relative_offset + 4
    value_list_size = _registry_cell_size(4)
    value_relative_offset = value_list_cell_relative_offset + value_list_size
    cell_payload = b"".join(
        [
            build_registry_nk_cell(
                root_name,
                timestamp,
                allocated=True,
                stable_subkey_count=1,
                stable_subkey_list_relative_offset=subkey_list_relative_offset,
            ),
            build_registry_subkey_list_cell([child_relative_offset]),
            build_registry_nk_cell(
                child_name,
                timestamp,
                allocated=True,
                parent_relative_offset=root_relative_offset,
                value_count=1,
                value_list_relative_offset=value_list_data_relative_offset,
            ),
            build_registry_value_list_cell([value_relative_offset]),
            build_registry_vk_cell(
                value_name,
                allocated=False,
                value_type=4,
                inline_data=(1).to_bytes(4, "little"),
            ),
            build_registry_nk_cell(
                deleted_key_name,
                timestamp,
                allocated=False,
                parent_relative_offset=child_relative_offset,
            ),
        ]
    )
    payload = cell_payload + b"".join(value.encode("utf-16le") + b"\x00\x00" for value in strings)
    hbin = bytearray(4096)
    hbin[0:4] = b"hbin"
    hbin[4:8] = (0).to_bytes(4, "little")
    hbin[8:12] = len(hbin).to_bytes(4, "little")
    hbin[32 : 32 + min(len(payload), len(hbin) - 32)] = payload[: len(hbin) - 32]
    return bytes(header) + bytes(hbin)


def build_minimal_shellbags_registry_hive(timestamp: datetime, embedded_name: str = "UsrClass.dat") -> bytes:
    header = bytearray(4096)
    header[0:4] = b"regf"
    header[4:8] = (11).to_bytes(4, "little")
    header[8:12] = (11).to_bytes(4, "little")
    header[12:20] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    header[20:24] = (1).to_bytes(4, "little")
    header[24:28] = (5).to_bytes(4, "little")
    header[36:40] = (32).to_bytes(4, "little")
    header[40:44] = (4096).to_bytes(4, "little")
    header[44:48] = (1).to_bytes(4, "little")
    header[48:112] = embedded_name.encode("utf-16le")[:64].ljust(64, b"\x00")
    header[508:512] = (0x12345678).to_bytes(4, "little")

    root_relative_offset = 32
    root_size = _registry_cell_size(0x4C + len(b"Shell"))
    subkey_list_relative_offset = root_relative_offset + root_size
    subkey_list_size = _registry_cell_size(12)
    bagmru_relative_offset = subkey_list_relative_offset + subkey_list_size
    bagmru_size = _registry_cell_size(0x4C + len(b"BagMRU"))
    value_list_cell_relative_offset = bagmru_relative_offset + bagmru_size
    value_list_data_relative_offset = value_list_cell_relative_offset + 4
    value_list_size = _registry_cell_size(8)
    shell_item_value_relative_offset = value_list_cell_relative_offset + value_list_size
    shell_item_value_size = _registry_cell_size(20 + len(b"0"))
    node_slot_value_relative_offset = shell_item_value_relative_offset + shell_item_value_size

    cell_payload = b"".join(
        [
            build_registry_nk_cell(
                "Shell",
                timestamp,
                allocated=True,
                stable_subkey_count=1,
                stable_subkey_list_relative_offset=subkey_list_relative_offset,
            ),
            build_registry_subkey_list_cell([bagmru_relative_offset]),
            build_registry_nk_cell(
                "BagMRU",
                timestamp,
                allocated=True,
                parent_relative_offset=root_relative_offset,
                value_count=2,
                value_list_relative_offset=value_list_data_relative_offset,
            ),
            build_registry_value_list_cell([shell_item_value_relative_offset, node_slot_value_relative_offset]),
            build_registry_vk_cell("0", allocated=True, value_type=3, inline_data=b"\x14\x00\x1fP"),
            build_registry_vk_cell("NodeSlot", allocated=True, value_type=4, inline_data=(42).to_bytes(4, "little")),
        ]
    )
    payload = cell_payload + r"Software\Microsoft\Windows\Shell\BagMRU\0".encode("utf-16le") + b"\x00\x00"
    hbin = bytearray(4096)
    hbin[0:4] = b"hbin"
    hbin[4:8] = (0).to_bytes(4, "little")
    hbin[8:12] = len(hbin).to_bytes(4, "little")
    hbin[32 : 32 + min(len(payload), len(hbin) - 32)] = payload[: len(hbin) - 32]
    return bytes(header) + bytes(hbin)


def build_registry_nk_cell(
    name: str,
    timestamp: datetime,
    *,
    allocated: bool,
    parent_relative_offset: int = 0,
    stable_subkey_count: int = 0,
    stable_subkey_list_relative_offset: int = 0,
    value_count: int = 0,
    value_list_relative_offset: int = 0,
) -> bytes:
    name_bytes = name.encode("latin-1", errors="ignore")
    body = bytearray(0x4C + len(name_bytes))
    body[0:2] = b"nk"
    body[2:4] = (0x0020).to_bytes(2, "little")
    body[4:12] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    body[0x10:0x14] = parent_relative_offset.to_bytes(4, "little")
    body[0x14:0x18] = stable_subkey_count.to_bytes(4, "little")
    body[0x1C:0x20] = stable_subkey_list_relative_offset.to_bytes(4, "little")
    body[0x24:0x28] = value_count.to_bytes(4, "little")
    body[0x28:0x2C] = value_list_relative_offset.to_bytes(4, "little")
    body[0x48:0x4A] = len(name_bytes).to_bytes(2, "little")
    body[0x4C : 0x4C + len(name_bytes)] = name_bytes
    return _registry_cell(bytes(body), allocated=allocated)


def build_registry_vk_cell(
    name: str,
    *,
    allocated: bool,
    value_type: int = 1,
    inline_data: bytes = b"",
) -> bytes:
    name_bytes = name.encode("latin-1", errors="ignore")
    body = bytearray(20 + len(name_bytes))
    body[0:2] = b"vk"
    body[2:4] = len(name_bytes).to_bytes(2, "little")
    if inline_data:
        body[4:8] = (0x80000000 | len(inline_data)).to_bytes(4, "little")
        body[8:12] = inline_data[:4].ljust(4, b"\x00")
    else:
        body[4:8] = (4).to_bytes(4, "little")
        body[8:12] = (0).to_bytes(4, "little")
    body[12:16] = value_type.to_bytes(4, "little")
    body[16:18] = (1).to_bytes(2, "little")
    body[20 : 20 + len(name_bytes)] = name_bytes
    return _registry_cell(bytes(body), allocated=allocated)


def build_registry_subkey_list_cell(child_relative_offsets: list[int]) -> bytes:
    body = bytearray(4 + len(child_relative_offsets) * 8)
    body[0:2] = b"lf"
    body[2:4] = len(child_relative_offsets).to_bytes(2, "little")
    cursor = 4
    for child_relative_offset in child_relative_offsets:
        body[cursor : cursor + 4] = child_relative_offset.to_bytes(4, "little")
        cursor += 8
    return _registry_cell(bytes(body), allocated=True)


def build_registry_value_list_cell(value_relative_offsets: list[int]) -> bytes:
    body = bytearray(len(value_relative_offsets) * 4)
    for index, value_relative_offset in enumerate(value_relative_offsets):
        body[index * 4 : index * 4 + 4] = value_relative_offset.to_bytes(4, "little")
    return _registry_cell(bytes(body), allocated=True)


def _registry_cell_size(body_size: int) -> int:
    unpadded_size = body_size + 4
    return unpadded_size + ((8 - (unpadded_size % 8)) % 8)


def _registry_cell(body: bytes, *, allocated: bool) -> bytes:
    unpadded_size = len(body) + 4
    cell_size = _registry_cell_size(len(body))
    signed_size = -cell_size if allocated else cell_size
    return signed_size.to_bytes(4, "little", signed=True) + body + (b"\x00" * (cell_size - unpadded_size))


def _write_eventlog_fixtures(xml_path: Path, hayabusa_path: Path, evtx_path: Path) -> None:
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(
        """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4624</EventID>
      <Level>0</Level>
      <Task>12544</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8020000000000000</Keywords>
      <TimeCreated SystemTime="2024-04-01T01:02:03.0000000Z"/>
      <EventRecordID>101</EventRecordID>
      <Channel>Security</Channel>
      <Computer>WIN-FIXTURE</Computer>
      <Security UserID="S-1-5-18"/>
      <Execution ProcessID="612" ThreadID="616"/>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="TargetUserName">alice</Data>
      <Data Name="LogonType">10</Data>
      <Data Name="IpAddress">10.0.0.5</Data>
    </EventData>
    <RenderingInfo>
      <Message>An account was successfully logged on.</Message>
    </RenderingInfo>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-PowerShell"/>
      <EventID>4104</EventID>
      <Level>3</Level>
      <TimeCreated SystemTime="2024-04-01T02:03:04.0000000Z"/>
      <EventRecordID>202</EventRecordID>
      <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
      <Computer>WIN-FIXTURE</Computer>
    </System>
    <EventData>
      <Data Name="ScriptBlockText">powershell -enc SQBFAFgA</Data>
    </EventData>
  </Event>
</Events>
""",
        encoding="utf-8",
    )
    hayabusa_path.parent.mkdir(parents=True, exist_ok=True)
    hayabusa_path.write_text(
        '{"Timestamp":"2024-04-01T02:03:04Z","Computer":"WIN-FIXTURE","Channel":"Microsoft-Windows-PowerShell/Operational","EventID":4104,"Level":"high","RecordID":205,"RuleTitle":"Suspicious Encoded PowerShell","RuleID":"RT-PS-001","MitreTags":"attack.t1059.001","CommandLine":"powershell -enc SQBFAFgA"}\n',
        encoding="utf-8",
    )
    evtx_path.write_bytes(
        build_minimal_evtx(
            record_id=300,
            timestamp=datetime(2024, 4, 1, 3, 4, 5, tzinfo=timezone.utc),
            strings=[
                "Microsoft-Windows-PowerShell",
                "Microsoft-Windows-PowerShell/Operational",
                "WIN-FIXTURE",
                "powershell -enc NativeFixture",
            ],
        )
    )


def _write_user_profile_fixtures(profile_path: Path, reg_path: Path) -> None:
    profile_path.mkdir(parents=True, exist_ok=True)
    (profile_path / "NTUSER.DAT").write_bytes(
        build_minimal_registry_hive(
            datetime(2024, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
            "NTUSER.DAT",
            [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"C:\Users\alice\AppData\Roaming\SecurityUpdater.exe",
                "https://example.test/payload",
            ],
        )
    )
    usrclass = profile_path / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
    usrclass.parent.mkdir(parents=True, exist_ok=True)
    usrclass.write_bytes(
        build_minimal_registry_hive(
            datetime(2024, 4, 1, 5, 6, 7, tzinfo=timezone.utc),
            "UsrClass.dat",
            [r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"],
        )
    )
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    sam_path = reg_path.with_name("SAM")
    sam_path.write_bytes(
        build_minimal_registry_hive(
            datetime(2024, 4, 1, 6, 7, 8, tzinfo=timezone.utc),
            "SAM",
            [r"SAM\Domains\Account\Users\Names\alice"],
        )
        + build_registry_nk_cell("alice", datetime(2024, 3, 1, 0, 0, 0, tzinfo=timezone.utc), allocated=True)
        + build_registry_nk_cell("000003E9", datetime(2024, 3, 1, 0, 0, 1, tzinfo=timezone.utc), allocated=True)
        + build_registry_nk_cell("Administrators", datetime(2024, 3, 1, 0, 0, 2, tzinfo=timezone.utc), allocated=True)
        + build_registry_nk_cell("00000220", datetime(2024, 3, 1, 0, 0, 3, tzinfo=timezone.utc), allocated=True)
    )
    reg_path.write_text(
        f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName]
"ComputerName"="WIN-FIXTURE"

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation]
"TimeZoneKeyName"="Korea Standard Time"

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows]
"ShutdownTime"=hex(b):{filetime_reg_hex(datetime(2024, 4, 1, 0, 55, 1, tzinfo=timezone.utc))}

[HKEY_LOCAL_MACHINE\\SYSTEM\\Select]
"Current"=dword:00000001
"Default"=dword:00000001

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SecurityUpdater]
"ImagePath"="C:\\Users\\alice\\AppData\\Roaming\\SecurityUpdater.exe"
"DisplayName"="Security Updater"
"ObjectName"="LocalSystem"
"Start"=dword:00000002
"Type"=dword:00000010

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\MountedDevices]
"\\DosDevices\\E:"=hex:01,02,03,04

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_Test&Prod_USB&Rev_1.00\\1234567890]
"FriendlyName"="Test USB Device"

[HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets\\_SC_SecurityUpdater]
"CurrVal"=hex:00,01
"CupdTime"=hex(b):{filetime_reg_hex(datetime(2024, 4, 1, 1, 23, 45, tzinfo=timezone.utc))}
"SecDesc"=hex:01,00,04,80

[HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\PolPrDmN\\Privilege Rights]
"SeDebugPrivilege"="S-1-5-32-544"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion]
"LastBootUpTime"="2024-04-01T01:02:03Z"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1000]
"ProfileImagePath"="C:\\Users\\alice"

[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\alice]
@=dword:000003e9

[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Builtin\\Aliases\\Names\\Administrators]
"Members"="S-1-5-21-111-222-333-1001"
"MemberNames"="alice"

[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\000003E9]
"UserName"="alice"
"AccountCreated"="2024-03-01T00:00:00Z"
"LastLogon"=hex(b):{filetime_reg_hex(datetime(2024, 4, 1, 1, 2, 3, tzinfo=timezone.utc))}
"PasswordLastSet"="2024-03-15T12:34:56Z"
"UserAccountControl"=dword:00000200
"AdminCount"=dword:00000001
"F"=hex:{sam_f_reg_hex(last_logon=datetime(2024, 4, 1, 1, 2, 3, tzinfo=timezone.utc), password_last_set=datetime(2024, 3, 15, 12, 34, 56, tzinfo=timezone.utc), rid=1001, uac=0x0200)}
"V"=hex:{sam_v_reg_hex("alice", "Alice Example")}
""",
        encoding="utf-16",
    )


def _write_execution_fixtures(reg_path: Path, powershell_history: Path, amcache_hive: Path) -> None:
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(
        f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1000]
"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Roaming\\evil.exe"=hex(b):{filetime_reg_hex(datetime(2024, 4, 1, 6, 7, 8, tzinfo=timezone.utc))}

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count]
"P:\\Hfref\\nyvpr\\NccQngn\\Ebnzvat\\rivy.rkr"=hex:01,00,00,00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache]
"C:\\Users\\alice\\AppData\\Roaming\\legacy.exe"="LastModified=2024-04-01T03:04:05Z"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store]
"C:\\Users\\alice\\AppData\\Roaming\\compat.exe"=hex:01,02,03,04

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Amcache\\InventoryApplicationFile\\app.exe]
"Path"="C:\\Program Files\\Example\\app.exe"
"Name"="Example App"
"Publisher"="Example Publisher"
"SHA1"="0123456789abcdef0123456789abcdef01234567"
"FileDescription"="Example Application Binary"
"ProductName"="Example Suite"
"LinkDate"="2024-04-01T02:03:04Z"
""",
        encoding="utf-16",
    )
    powershell_history.parent.mkdir(parents=True, exist_ok=True)
    powershell_history.write_text(
        "Get-Process\npowershell -enc SQBFAFgA\nvssadmin delete shadows /all /quiet\n",
        encoding="utf-8",
    )
    amcache_hive.parent.mkdir(parents=True, exist_ok=True)
    amcache_hive.write_bytes(
        build_minimal_registry_hive(
            datetime(2024, 4, 1, 2, 3, 4, tzinfo=timezone.utc),
            "Amcache.hve",
            [
                r"C:\Program Files\Example\app.exe",
                "0123456789abcdef0123456789abcdef01234567",
                "Example Publisher",
            ],
        )
    )


def _write_prefetch_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(512)
    header[0:4] = (30).to_bytes(4, "little")
    header[4:8] = b"SCCA"
    header[0x0C:0x10] = (len(header)).to_bytes(4, "little")
    header[16 : 16 + len("POWERSHELL.EXE".encode("utf-16le"))] = "POWERSHELL.EXE".encode("utf-16le")
    header[0x80:0x88] = datetime_to_filetime(datetime(2024, 4, 1, 9, 10, 11, tzinfo=timezone.utc)).to_bytes(8, "little")
    header[0x88:0x90] = datetime_to_filetime(datetime(2024, 3, 30, 8, 9, 10, tzinfo=timezone.utc)).to_bytes(8, "little")
    header[0xD0:0xD4] = (3).to_bytes(4, "little")
    referenced_path = r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE".encode("utf-16le")
    header[0x120 : 0x120 + len(referenced_path)] = referenced_path
    path.write_bytes(bytes(header))


def _write_srum_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Timestamp,Application,User,BytesSent,BytesReceived,EnergyUsage,InterfaceLuid,NetworkProfile\n"
        "2024-04-01T05:06:07Z,powershell.exe,alice,512,2048,3,12,CorpWiFi\n",
        encoding="utf-8",
    )


def _write_srum_database_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        _minimal_ese_database(
            [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "NetworkUsage",
                "bytes received from https://download.example/tools/installer.exe",
                (
                    "SruDbTable=NetworkUsage Application=powershell.exe UserSid=S-1-5-21-1000 "
                    "Timestamp=2024-04-01T05:06:07Z BytesSent=512 BytesReceived=2048 "
                    "InterfaceLuid=12 NetworkProfile=CorpWiFi Url=https://download.example/tools/installer.exe"
                ),
            ]
        )
    )


def _write_filesystem_fixtures(mft_csv: Path, usn_jsonl: Path, mft_native: Path, usn_journal: Path) -> None:
    mft_csv.parent.mkdir(parents=True, exist_ok=True)
    mft_csv.write_text(
        "EntryNumber,FullPath,Deleted,Created0x10\n"
        "42,C:\\\\Users\\\\alice\\\\Desktop\\\\deleted.txt,True,2024-04-01T04:05:06Z\n",
        encoding="utf-8",
    )
    usn_jsonl.write_text(
        '{"FRN":"42","ParentFRN":"5","Name":"deleted.txt","Reason":"FILE_DELETE","Timestamp":"2024-04-01T04:06:07Z"}\n',
        encoding="utf-8",
    )
    mft_native.parent.mkdir(parents=True, exist_ok=True)
    mft_native.write_bytes(build_minimal_mft())
    usn_journal.parent.mkdir(parents=True, exist_ok=True)
    usn_journal.write_bytes(
        (b"\x00" * 16)
        + build_minimal_usn_journal(
            file_name="deleted.txt",
            timestamp=datetime(2024, 4, 1, 4, 6, 7, tzinfo=timezone.utc),
            reason=0x00000200,
        )
        + build_minimal_usn_journal_v3(
            file_name="renamed.txt",
            timestamp=datetime(2024, 4, 1, 4, 7, 8, tzinfo=timezone.utc),
            reason=0x00002000 | 0x80000000,
        )
        + build_minimal_usn_journal(
            file_name=f"large_{'x' * 260}.bin",
            timestamp=datetime(2024, 4, 1, 4, 8, 9, tzinfo=timezone.utc),
            reason=0x00000002 | 0x80000000,
        )
    )


def build_minimal_mft() -> bytes:
    record = bytearray(1024)
    record[0:4] = b"FILE"
    record[0x04:0x06] = (0x30).to_bytes(2, "little")
    record[0x06:0x08] = (3).to_bytes(2, "little")
    record[0x10:0x12] = (3).to_bytes(2, "little")
    record[0x12:0x14] = (1).to_bytes(2, "little")
    record[0x14:0x16] = (0x38).to_bytes(2, "little")
    record[0x16:0x18] = (0x01).to_bytes(2, "little")
    record[0x1C:0x20] = (1024).to_bytes(4, "little")
    record[0x28:0x2A] = (1).to_bytes(2, "little")
    record[0x2C:0x30] = (4).to_bytes(4, "little")
    record[0x30:0x32] = b"\xaa\xbb"
    record[0x32:0x34] = b"\x11\x22"
    record[0x34:0x36] = b"\x33\x44"
    timestamp = datetime(2024, 4, 1, 4, 5, 6, tzinfo=timezone.utc)
    timestamp_filetime = datetime_to_filetime(timestamp)
    standard_information = bytearray(48)
    for offset in (0, 8, 16, 24):
        standard_information[offset : offset + 8] = timestamp_filetime.to_bytes(8, "little")
    standard_information[32:36] = (0x20).to_bytes(4, "little")

    file_name = "deleted.txt"
    encoded_name = file_name.encode("utf-16le")
    file_name_value = bytearray(66 + len(encoded_name))
    file_name_value[0:8] = ((1 << 48) | 5).to_bytes(8, "little")
    for offset in (8, 16, 24, 32):
        file_name_value[offset : offset + 8] = timestamp_filetime.to_bytes(8, "little")
    file_name_value[40:48] = (128).to_bytes(8, "little")
    file_name_value[48:56] = (32).to_bytes(8, "little")
    file_name_value[56:60] = (0x20).to_bytes(4, "little")
    file_name_value[64] = len(file_name)
    file_name_value[65] = 1
    file_name_value[66 : 66 + len(encoded_name)] = encoded_name

    cursor = 0x38
    for attribute in (
        build_mft_resident_attribute(0x10, bytes(standard_information), attribute_id=1),
        build_mft_resident_attribute(0x30, bytes(file_name_value), attribute_id=2),
        build_mft_resident_attribute(0x80, b"triage fixture data", attribute_id=3),
    ):
        record[cursor : cursor + len(attribute)] = attribute
        cursor += len(attribute)
    record[cursor : cursor + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    cursor += 8
    record[0x18:0x1C] = cursor.to_bytes(4, "little")
    path = r"C:\Users\alice\Desktop\deleted.txt".encode("utf-16le")
    record[0x300 : 0x300 + len(path)] = path
    record[510:512] = b"\xaa\xbb"
    record[1022:1024] = b"\xaa\xbb"
    return bytes(record)


def build_mft_resident_attribute(attribute_type: int, value: bytes, *, attribute_id: int) -> bytes:
    value_offset = 0x18
    length = align8(value_offset + len(value))
    attribute = bytearray(length)
    attribute[0:4] = attribute_type.to_bytes(4, "little")
    attribute[4:8] = length.to_bytes(4, "little")
    attribute[8] = 0
    attribute[12:14] = (0).to_bytes(2, "little")
    attribute[14:16] = attribute_id.to_bytes(2, "little")
    attribute[16:20] = len(value).to_bytes(4, "little")
    attribute[20:22] = value_offset.to_bytes(2, "little")
    attribute[value_offset : value_offset + len(value)] = value
    return bytes(attribute)


def build_minimal_usn_journal(file_name: str, timestamp: datetime, reason: int) -> bytes:
    encoded_name = file_name.encode("utf-16le")
    name_offset = 60
    length = align8(name_offset + len(encoded_name))
    record = bytearray(length)
    record[0:4] = length.to_bytes(4, "little")
    record[4:6] = (2).to_bytes(2, "little")
    record[6:8] = (0).to_bytes(2, "little")
    record[8:16] = (42).to_bytes(8, "little")
    record[16:24] = (5).to_bytes(8, "little")
    record[24:32] = (9001).to_bytes(8, "little")
    record[32:40] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    record[40:44] = reason.to_bytes(4, "little")
    record[48:52] = (100).to_bytes(4, "little")
    record[52:56] = (0x20).to_bytes(4, "little")
    record[56:58] = len(encoded_name).to_bytes(2, "little")
    record[58:60] = name_offset.to_bytes(2, "little")
    record[name_offset : name_offset + len(encoded_name)] = encoded_name
    return bytes(record)


def build_minimal_usn_journal_v3(file_name: str, timestamp: datetime, reason: int) -> bytes:
    encoded_name = file_name.encode("utf-16le")
    name_offset = 76
    length = align8(name_offset + len(encoded_name))
    record = bytearray(length)
    record[0:4] = length.to_bytes(4, "little")
    record[4:6] = (3).to_bytes(2, "little")
    record[6:8] = (0).to_bytes(2, "little")
    record[8:24] = (43).to_bytes(16, "little")
    record[24:40] = (5).to_bytes(16, "little")
    record[40:48] = (9002).to_bytes(8, "little")
    record[48:56] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    record[56:60] = reason.to_bytes(4, "little")
    record[64:68] = (101).to_bytes(4, "little")
    record[68:72] = (0x20).to_bytes(4, "little")
    record[72:74] = len(encoded_name).to_bytes(2, "little")
    record[74:76] = name_offset.to_bytes(2, "little")
    record[name_offset : name_offset + len(encoded_name)] = encoded_name
    return bytes(record)


def align8(value: int) -> int:
    return (value + 7) & ~7


def _write_windows_search_fixture(csv_path: Path, edb_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.write_text(
        "DocID,System.ItemPathDisplay,System.FileName,System.Title,System.Search.Contents,System.DateModified,System.Size\n"
        '7,C:\\Users\\alice\\Documents\\Incident Notes.docx,Incident Notes.docx,Incident Notes,"encoded powershell investigation notes",2024-04-01T08:09:10Z,12345\n',
        encoding="utf-8",
    )
    edb_path.parent.mkdir(parents=True, exist_ok=True)
    edb_path.write_bytes(
        _minimal_ese_database(
            [
                "SystemIndex_GthrPth WorkID ItemUrl",
                "SystemIndex_PropertyStore System.ItemPathDisplay System.FileName System.DateModified",
                "System.Search.Contents IsDeleted CrawlStatus",
                r"C:\Users\alice\Documents\Incident Notes.docx",
                "encoded powershell investigation notes",
                "https://example.com/browser-history",
            ]
        )
    )


def _minimal_ese_database(strings: list[str]) -> bytes:
    page_size = 8192
    header = bytearray(8192)
    header[4:8] = bytes.fromhex("efcdab89")
    header[8:12] = (0x620).to_bytes(4, "little")
    header[12:16] = (1).to_bytes(4, "little")
    header[0xEC:0xF0] = page_size.to_bytes(4, "little")
    payload = b"\x00\x00".join(value.encode("utf-16le") for value in strings)
    database = bytes(header) + payload
    padding = (page_size - (len(database) % page_size)) % page_size
    return database + (b"\x00" * padding)


def _write_remote_access_fixtures(default_rdp: Path, cache_file: Path, reg_path: Path) -> None:
    default_rdp.parent.mkdir(parents=True, exist_ok=True)
    default_rdp.write_text(
        "full address:s:10.0.0.50\n"
        "username:s:CORP\\alice\n"
        "gatewayhostname:s:rd-gateway.example\n"
        "screen mode id:i:2\n",
        encoding="utf-8",
    )
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_bytes(
        b"fixture rdp cache"
        + b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + (320).to_bytes(4, "big")
        + (200).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
        + b"\x00\x00\x00\x00"
    )
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(
        """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\\10.0.0.50]
"MRU0"="10.0.0.50"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\\rdp-target.example]
"UsernameHint"="CORP\\alice"
""",
        encoding="utf-16",
    )


def _write_task_scheduler_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """<?xml version="1.0" encoding="utf-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>alice</Author>
    <URI>\\Microsoft\\Windows\\UpdateOrchestrator\\SecurityUpdater</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <StartBoundary>2024-04-01T09:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-21-1000</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File C:\\Users\\alice\\AppData\\Roaming\\updater.ps1</Arguments>
      <WorkingDirectory>C:\\Users\\alice\\AppData\\Roaming</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
""",
        encoding="utf-8",
    )


def _write_wmi_repository_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"fixture wmi repository objects\x00"
        + "__EventFilter".encode("utf-16le")
        + b"\x00\x00"
        + "CommandLineEventConsumer".encode("utf-16le")
        + b"\x00\x00"
        + r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc SQBFAFgA".encode("utf-16le")
        + b"\x00\x00"
        + b"https://example.test/wmi-payload"
    )


def _to_chrome_time(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - CHROME_EPOCH
    return int(delta.total_seconds() * 1_000_000)
