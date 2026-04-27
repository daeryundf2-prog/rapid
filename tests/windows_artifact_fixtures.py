from __future__ import annotations

import os
import sqlite3
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
    _write_chromium_history(
        edge_history,
        visits=[edge_visit],
        downloads=[download],
    )
    _write_recent_shortcuts(recent_dir, [recent_shortcut])
    _write_eventlog_fixtures(eventlog_xml, hayabusa_jsonl, evtx_file)
    _write_user_profile_fixtures(user_profile, root / "Windows" / "System32" / "config" / "SYSTEM.reg")
    _write_execution_fixtures(execution_reg, powershell_history)
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
        build_minimal_ole_jumplist(
            "1",
            build_minimal_lnk(r"C:\Users\alice\Documents\Incident Notes.docx", timestamp),
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
    return bytes(header) + lnk_unicode_string(target_path) + lnk_unicode_string(r"C:\Users\alice\Documents") + lnk_unicode_string("")


def build_minimal_ole_jumplist(stream_name: str, stream_payload: bytes) -> bytes:
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

    stream_sector_count = max(1, (len(stream_payload) + sector_size - 1) // sector_size)
    stream_sector_ids = list(range(2, 2 + stream_sector_count))
    fat_entries = [0xFFFFFFFD, 0xFFFFFFFE]
    for index, sector_id in enumerate(stream_sector_ids):
        is_last = index == len(stream_sector_ids) - 1
        fat_entries.append(0xFFFFFFFE if is_last else sector_id + 1)
    fat_sector = bytearray(sector_size)
    for index in range(sector_size // 4):
        value = fat_entries[index] if index < len(fat_entries) else 0xFFFFFFFF
        fat_sector[index * 4 : index * 4 + 4] = value.to_bytes(4, "little")

    directory_sector = bytearray(sector_size)
    directory_sector[0:128] = cfb_directory_entry("Root Entry", 5, child_id=1)
    directory_sector[128:256] = cfb_directory_entry(
        stream_name,
        2,
        start_sector=stream_sector_ids[0],
        stream_size=len(stream_payload),
    )
    stream_bytes = stream_payload.ljust(stream_sector_count * sector_size, b"\x00")
    return bytes(header) + bytes(fat_sector) + bytes(directory_sector) + stream_bytes


def cfb_directory_entry(
    name: str,
    object_type: int,
    *,
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
    entry[72:76] = (0xFFFFFFFF).to_bytes(4, "little")
    entry[76:80] = child_id.to_bytes(4, "little")
    entry[116:120] = start_sector.to_bytes(4, "little")
    entry[120:128] = stream_size.to_bytes(8, "little")
    return bytes(entry)


def lnk_unicode_string(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    return (len(value)).to_bytes(2, "little") + encoded


def datetime_to_filetime(value: datetime) -> int:
    return int((value.astimezone(timezone.utc) - CHROME_EPOCH).total_seconds() * 10_000_000)


def filetime_reg_hex(value: datetime) -> str:
    raw = datetime_to_filetime(value).to_bytes(8, "little")
    return ",".join(f"{byte:02x}" for byte in raw)


def build_minimal_evtx(record_id: int, timestamp: datetime, strings: list[str]) -> bytes:
    payload = b"".join(value.encode("utf-16le") + b"\x00\x00" for value in strings)
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
    return bytes(header) + record


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
    header[48:112] = embedded_name.encode("utf-16le")[:64]
    header[508:512] = (0x12345678).to_bytes(4, "little")
    cell_payload = b"".join(
        [
            build_registry_nk_cell(
                "Run" if any("Run" in value for value in strings) else embedded_name,
                timestamp,
                allocated=True,
            ),
            build_registry_vk_cell(
                "SecurityUpdater" if any("SecurityUpdater" in value for value in strings) else "SampleValue",
                allocated=False,
            ),
        ]
    )
    payload = cell_payload + b"".join(value.encode("utf-16le") + b"\x00\x00" for value in strings)
    return bytes(header) + payload


def build_registry_nk_cell(name: str, timestamp: datetime, *, allocated: bool) -> bytes:
    name_bytes = name.encode("latin-1", errors="ignore")
    body = bytearray(0x4C + len(name_bytes))
    body[0:2] = b"nk"
    body[2:4] = (0x0020).to_bytes(2, "little")
    body[4:12] = datetime_to_filetime(timestamp).to_bytes(8, "little")
    body[0x48:0x4A] = len(name_bytes).to_bytes(2, "little")
    body[0x4C : 0x4C + len(name_bytes)] = name_bytes
    return _registry_cell(bytes(body), allocated=allocated)


def build_registry_vk_cell(name: str, *, allocated: bool) -> bytes:
    name_bytes = name.encode("latin-1", errors="ignore")
    body = bytearray(20 + len(name_bytes))
    body[0:2] = b"vk"
    body[2:4] = len(name_bytes).to_bytes(2, "little")
    body[4:8] = (4).to_bytes(4, "little")
    body[8:12] = (0).to_bytes(4, "little")
    body[12:16] = (1).to_bytes(4, "little")
    body[16:18] = (1).to_bytes(2, "little")
    body[20 : 20 + len(name_bytes)] = name_bytes
    return _registry_cell(bytes(body), allocated=allocated)


def _registry_cell(body: bytes, *, allocated: bool) -> bytes:
    cell_size = len(body) + 4
    signed_size = -cell_size if allocated else cell_size
    return signed_size.to_bytes(4, "little", signed=True) + body


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
    )
    reg_path.write_text(
        f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName]
"ComputerName"="WIN-FIXTURE"

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation]
"TimeZoneKeyName"="Korea Standard Time"

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Windows]
"ShutdownTime"=hex(b):{filetime_reg_hex(datetime(2024, 4, 1, 0, 55, 1, tzinfo=timezone.utc))}

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion]
"LastBootUpTime"="2024-04-01T01:02:03Z"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1000]
"ProfileImagePath"="C:\\Users\\alice"

[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\Names\\alice]
@=dword:000003e9

[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\000003E9]
"UserName"="alice"
"AccountCreated"="2024-03-01T00:00:00Z"
"LastLogon"=hex(b):{filetime_reg_hex(datetime(2024, 4, 1, 1, 2, 3, tzinfo=timezone.utc))}
"PasswordLastSet"="2024-03-15T12:34:56Z"
"UserAccountControl"=dword:00000200
"AdminCount"=dword:00000001
""",
        encoding="utf-16",
    )


def _write_execution_fixtures(reg_path: Path, powershell_history: Path) -> None:
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(
        """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-1000]
"\\Device\\HarddiskVolume3\\Users\\alice\\AppData\\Roaming\\evil.exe"=hex(b):00,00,00,00,00,00,00,00

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count]
"P:\\Hfref\\nyvpr\\NccQngn\\Ebnzvat\\rivy.rkr"=hex:01,00,00,00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache]
"C:\\Users\\alice\\AppData\\Roaming\\legacy.exe"="LastModified=2024-04-01T03:04:05Z"
""",
        encoding="utf-16",
    )
    powershell_history.parent.mkdir(parents=True, exist_ok=True)
    powershell_history.write_text(
        "Get-Process\npowershell -enc SQBFAFgA\nvssadmin delete shadows /all /quiet\n",
        encoding="utf-8",
    )


def _write_prefetch_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = bytearray(512)
    header[0:4] = (30).to_bytes(4, "little")
    header[4:8] = b"SCCA"
    header[16 : 16 + len("POWERSHELL.EXE".encode("utf-16le"))] = "POWERSHELL.EXE".encode("utf-16le")
    header[0x80:0x88] = datetime_to_filetime(datetime(2024, 4, 1, 9, 10, 11, tzinfo=timezone.utc)).to_bytes(8, "little")
    header[0xD0:0xD4] = (3).to_bytes(4, "little")
    referenced_path = r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE".encode("utf-16le")
    header[0x120 : 0x120 + len(referenced_path)] = referenced_path
    path.write_bytes(bytes(header))


def _write_srum_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Timestamp,Application,User,BytesSent,BytesReceived,EnergyUsage\n"
        "2024-04-01T05:06:07Z,powershell.exe,alice,512,2048,3\n",
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
        build_minimal_usn_journal(
            file_name="deleted.txt",
            timestamp=datetime(2024, 4, 1, 4, 6, 7, tzinfo=timezone.utc),
            reason=0x00000200,
        )
        + build_minimal_usn_journal_v3(
            file_name="renamed.txt",
            timestamp=datetime(2024, 4, 1, 4, 7, 8, tzinfo=timezone.utc),
            reason=0x00002000 | 0x80000000,
        )
    )


def build_minimal_mft() -> bytes:
    record = bytearray(1024)
    record[0:4] = b"FILE"
    record[0x10:0x12] = (3).to_bytes(2, "little")
    record[0x12:0x14] = (1).to_bytes(2, "little")
    record[0x14:0x16] = (0x38).to_bytes(2, "little")
    record[0x16:0x18] = (0x01).to_bytes(2, "little")
    record[0x18:0x1C] = (512).to_bytes(4, "little")
    record[0x1C:0x20] = (1024).to_bytes(4, "little")
    path = r"C:\Users\alice\Desktop\deleted.txt".encode("utf-16le")
    record[0x100 : 0x100 + len(path)] = path
    return bytes(record)


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
                r"C:\Users\alice\Documents\Incident Notes.docx",
                "encoded powershell investigation notes",
                "https://example.com/browser-history",
            ]
        )
    )


def _minimal_ese_database(strings: list[str]) -> bytes:
    header = bytearray(8192)
    header[4:8] = bytes.fromhex("efcdab89")
    header[8:12] = (0x620).to_bytes(4, "little")
    header[12:16] = (1).to_bytes(4, "little")
    header[0xEC:0xF0] = (8192).to_bytes(4, "little")
    payload = b"\x00\x00".join(value.encode("utf-16le") for value in strings)
    return bytes(header) + payload


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
