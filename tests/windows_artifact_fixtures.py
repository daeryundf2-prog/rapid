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
    mft_csv: Path
    usn_jsonl: Path


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
    logs_dir = root / "Windows" / "System32" / "winevt" / "Logs"
    eventlog_xml = logs_dir / "Security.xml"
    hayabusa_jsonl = root / "analysis" / "hayabusa-results.jsonl"
    evtx_file = logs_dir / "System.evtx"
    user_profile = root / "Users" / "alice"
    execution_reg = root / "Windows" / "System32" / "config" / "execution.reg"
    powershell_history = root / "Users" / "alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
    prefetch_file = root / "Windows" / "Prefetch" / "POWERSHELL.EXE-12345678.pf"
    srum_csv = root / "analysis" / "srum.csv"
    mft_csv = root / "analysis" / "mft.csv"
    usn_jsonl = root / "analysis" / "usn.jsonl"

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
    _write_eventlog_fixtures(eventlog_xml, hayabusa_jsonl, evtx_file)
    _write_user_profile_fixtures(user_profile, root / "Windows" / "System32" / "config" / "SYSTEM.reg")
    _write_execution_fixtures(execution_reg, powershell_history)
    _write_prefetch_fixture(prefetch_file)
    _write_srum_fixture(srum_csv)
    _write_filesystem_fixtures(mft_csv, usn_jsonl)

    return WindowsArtifactFixture(
        root=root,
        chrome_visit=chrome_visit,
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
        mft_csv=mft_csv,
        usn_jsonl=usn_jsonl,
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
        target_path = rf"C:\Users\alice\Documents\{shortcut.name.removesuffix('.lnk')}"
        shortcut_path.write_bytes(build_minimal_lnk(target_path, shortcut.modified_at))
        ts = shortcut.modified_at.timestamp()
        os.utime(shortcut_path, (ts, ts))


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


def lnk_unicode_string(value: str) -> bytes:
    encoded = value.encode("utf-16le")
    return (len(value)).to_bytes(2, "little") + encoded


def datetime_to_filetime(value: datetime) -> int:
    return int((value.astimezone(timezone.utc) - CHROME_EPOCH).total_seconds() * 10_000_000)


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
    evtx_path.write_bytes(b"ElfFile fixture evtx placeholder")


def _write_user_profile_fixtures(profile_path: Path, reg_path: Path) -> None:
    profile_path.mkdir(parents=True, exist_ok=True)
    (profile_path / "NTUSER.DAT").write_bytes(b"fixture ntuser")
    usrclass = profile_path / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
    usrclass.parent.mkdir(parents=True, exist_ok=True)
    usrclass.write_bytes(b"fixture usrclass")
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(
        """Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName]
"ComputerName"="WIN-FIXTURE"

[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\TimeZoneInformation]
"TimeZoneKeyName"="Korea Standard Time"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1000]
"ProfileImagePath"="C:\\Users\\alice"
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
    header = bytearray(256)
    header[0:4] = (30).to_bytes(4, "little")
    header[4:8] = b"SCCA"
    header[16 : 16 + len("POWERSHELL.EXE".encode("utf-16le"))] = "POWERSHELL.EXE".encode("utf-16le")
    path.write_bytes(bytes(header))


def _write_srum_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "Timestamp,Application,User,BytesSent,BytesReceived,EnergyUsage\n"
        "2024-04-01T05:06:07Z,powershell.exe,alice,512,2048,3\n",
        encoding="utf-8",
    )


def _write_filesystem_fixtures(mft_csv: Path, usn_jsonl: Path) -> None:
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


def _to_chrome_time(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - CHROME_EPOCH
    return int(delta.total_seconds() * 1_000_000)
