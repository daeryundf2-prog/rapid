"""Synthetic desktop cloud sync client fixtures (R2 M4): schemas built in code, no real client data or PII.

Each builder writes the client's on-disk layout under a Windows-like evidence root
(``Users\\<user>\\AppData\\...``) with values a test can assert on.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import sqlite3
import struct
from collections.abc import Sequence
from pathlib import Path

ODL_SIGNATURE = b"\xcc\xdd\xee\xff\x00\x00\x00\x00"
BASE_MS = int(dt.datetime(2024, 5, 1, 9, 0, tzinfo=dt.timezone.utc).timestamp() * 1000)


def appdata_local(root: Path, user: str = "alice") -> Path:
    return root / "Users" / user / "AppData" / "Local"


def appdata_roaming(root: Path, user: str = "alice") -> Path:
    return root / "Users" / user / "AppData" / "Roaming"


def sqlite_db(path: Path, statements: Sequence[str], rows: Sequence[tuple[str, Sequence[object]]] = ()) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        for statement in statements:
            connection.execute(statement)
        for sql, values in rows:
            connection.execute(sql, tuple(values))
        connection.commit()
    finally:
        connection.close()
    return path


def utf16_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
    return path


def lp(text: str) -> bytes:
    raw = text.encode("ascii")
    return struct.pack("<I", len(raw)) + raw


def odl_record(ms: int, code_file: str, function: str, params: Sequence[str] = (), utf16_param: str = "") -> bytes:
    """One ODL v2-style record: signature, Unix-ms time at +8, zeroed header to +56, then the data block."""
    data = lp(code_file) + struct.pack("<I", 1) + lp(function)
    for value in params:
        data += lp(value)
    if utf16_param:
        encoded = utf16_param.encode("utf-16-le")
        data += struct.pack("<I", len(encoded)) + encoded
    header = ODL_SIGNATURE + struct.pack("<Q", ms) + bytes(32) + struct.pack("<I", len(data)) + bytes(4)
    return header + data


def odl_file(records: Sequence[bytes], *, compressed: bool) -> bytes:
    header = b"EBFGONED" + struct.pack("<I", 2) + bytes(0x100 - 12)
    body = b"".join(records)
    return header + (gzip.compress(body) if compressed else body)


def build_onedrive(root: Path, *, user: str = "alice", uploads: int = 3, corrupt_log: bool = False) -> dict[str, Path]:
    base = appdata_local(root, user) / "Microsoft" / "OneDrive"
    settings = base / "settings" / "Personal"
    paths: dict[str, Path] = {}
    paths["global_ini"] = utf16_text(settings / "global.ini", "cid = 1a2b3c4d5e6f7788\r\nUserEmail = alice@example.com\r\n")
    paths["cid_ini"] = utf16_text(
        settings / "1a2b3c4d5e6f7788.ini",
        'library = 14 4 1A2B3C4D5E6F7788!101 1717000000 "SkyDrive" "Personal" 0 "D:\\Sync\\OneDrive" 1 6\r\n',
    )
    (settings / "1a2b3c4d5e6f7788.dat").write_bytes(b"\x02\x00legacy-binary-onedrive-dat" + bytes(64))
    paths["sync_db"] = sqlite_db(
        settings / "SyncEngineDatabase.db",
        [
            "CREATE TABLE od_ClientFolder_Records (resourceID TEXT PRIMARY KEY, parentResourceID TEXT, folderName TEXT, folderStatus INTEGER)",
            "CREATE TABLE od_ClientFile_Records (resourceID TEXT PRIMARY KEY, parentResourceID TEXT, fileName TEXT, size INTEGER, "
            "lastChange INTEGER, fileStatus INTEGER, sharedItem INTEGER, localHashDigest BLOB, eTag TEXT)",
            "CREATE TABLE od_ScopeInfo_Records (scopeID TEXT PRIMARY KEY, webURL TEXT, remotePath TEXT, tenantID TEXT)",
        ],
        [
            ("INSERT INTO od_ScopeInfo_Records VALUES (?, ?, ?, ?)", ("SCOPE1", "https://onedrive.live.com/?cid=1a2b3c4d5e6f7788", "/", "")),
            ("INSERT INTO od_ClientFolder_Records VALUES (?, ?, ?, ?)", ("F1", "SCOPE1", "Projects", 1)),
            ("INSERT INTO od_ClientFolder_Records VALUES (?, ?, ?, ?)", ("F2", "F1", "2024", 1)),
            ("INSERT INTO od_ClientFolder_Records VALUES (?, ?, ?, ?)", ("LOOP1", "LOOP2", "a", 1)),
            ("INSERT INTO od_ClientFolder_Records VALUES (?, ?, ?, ?)", ("LOOP2", "LOOP1", "b", 1)),
            (
                "INSERT INTO od_ClientFile_Records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("I1", "F2", "budget.xlsx", 48213, 1714554000, 2, 1, b"\x01\x02\x03", "etag-1"),
            ),
            (
                "INSERT INTO od_ClientFile_Records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("I2", "SCOPE1", "readme.txt", 120, 1714550000, 2, 0, None, "etag-2"),
            ),
            (
                "INSERT INTO od_ClientFile_Records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("I3", "LOOP1", "cycle.bin", 1, 1714550001, 2, 0, None, "etag-3"),
            ),
        ],
    )
    logs = base / "logs" / "Personal"
    logs.mkdir(parents=True, exist_ok=True)
    utf16_text(logs / "ObfuscationStringMap.txt", "Qx7Lm2Pa\tcontract_final.pdf\r\n")
    records = [
        odl_record(BASE_MS + index * 1000, "SyncEngineUpload.cpp", "UploadFileComplete", [f"C:\\Users\\{user}\\OneDrive\\Projects\\file{index:02d}.docx"])
        for index in range(uploads)
    ]
    records.append(odl_record(BASE_MS + 60_000, "SyncEngine.cpp", "DeleteItemLocal", ["Qx7Lm2Pa"]))
    records.append(odl_record(BASE_MS + 61_000, "SyncEngine.cpp", "HeartbeatTick", ["noise"]))
    records.append(odl_record(BASE_MS + 62_000, "Telemetry.cpp", "Flush", ["UploadThrottleConfig"]))
    records.append(odl_record(BASE_MS + 63_000, "SyncEngine.cpp", "RenameItem", [], utf16_param=f"C:\\Users\\{user}\\OneDrive\\보고서.hwp"))
    paths["odlgz"] = logs / "SyncEngine-2024-05-01.0900.1.odlgz"
    paths["odlgz"].write_bytes(odl_file(records, compressed=True))
    paths["odl"] = logs / "SyncEngine-2024-05-01.1000.2.odl"
    paths["odl"].write_bytes(odl_file([odl_record(BASE_MS + 3_600_000, "SyncEngine.cpp", "DownloadFileComplete", ["C:\\Users\\alice\\OneDrive\\plan.pptx"])], compressed=False))
    if corrupt_log:
        paths["corrupt_log"] = logs / "SyncEngine-2024-05-02.odlgz"
        paths["corrupt_log"].write_bytes(b"EBFGONED" + bytes(0x100 - 8) + b"\x1f\x8b\x08\x00garbage-not-deflate")
    return paths


def build_dropbox(root: Path, *, user: str = "alice", uploads: int = 3, upload_step_seconds: int = 30) -> dict[str, Path]:
    local = appdata_local(root, user) / "Dropbox"
    local.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    paths["info"] = local / "info.json"
    paths["info"].write_text(
        json.dumps({"personal": {"path": "E:\\Dropbox", "host": 4242, "is_team": False, "subscription_type": "Basic"}}),
        encoding="utf-8",
    )

    paths["host"] = local / "host.db"
    paths["host"].write_text("0" * 40 + "\n" + base64.b64encode(b"E:\\Dropbox").decode() + "\n", encoding="utf-8")
    instance = appdata_roaming(root, user) / "Dropbox" / "instance1"
    instance.mkdir(parents=True, exist_ok=True)
    (instance / "config.dbx").write_bytes(b"\x8a\x13encrypted-see-page" + bytes(512))
    (instance / "filecache.dbx").write_bytes(b"\x01\x02" + bytes(256))
    rows = [
        (
            "INSERT INTO sync_history (file_event_type, direction, local_path, timestamp, other_user, is_dir, file_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("add", "upload", f"E:\\Dropbox\\out\\doc{index:03d}.pdf", 1714554000 + index * upload_step_seconds, None, 0, f"id:{index}"),
        )
        for index in range(uploads)
    ]
    rows.append(
        (
            "INSERT INTO sync_history (file_event_type, direction, local_path, timestamp, other_user, is_dir, file_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("delete", "download", "E:\\Dropbox\\out\\old.pdf", 1714560000, "bob@example.net", 0, "id:old"),
        )
    )
    rows.append(
        (
            "INSERT INTO sync_history (file_event_type, direction, local_path, timestamp, other_user, is_dir, file_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("add", "upload", "E:\\Dropbox\\out\\folder", 1714560100, None, 1, "id:dir"),
        )
    )
    paths["sync_history"] = sqlite_db(
        instance / "sync_history.db",
        [
            "CREATE TABLE sync_history (id INTEGER PRIMARY KEY, file_event_type TEXT, direction TEXT, local_path TEXT, "
            "timestamp INTEGER, other_user TEXT, is_dir INTEGER, file_id TEXT)"
        ],
        rows,
    )
    return paths


def build_drivefs(root: Path, *, user: str = "alice", account_id: str = "117000000000000000001") -> dict[str, Path]:
    drivefs = appdata_local(root, user) / "Google" / "DriveFS"
    account = drivefs / account_id
    paths: dict[str, Path] = {}
    paths["metadata"] = sqlite_db(
        account / "metadata_sqlite_db",
        [
            "CREATE TABLE items (stable_id INTEGER PRIMARY KEY, id TEXT, trashed INTEGER, is_folder INTEGER, local_title TEXT, "
            "mime_type TEXT, file_size INTEGER, modified_date INTEGER, viewed_by_me_date INTEGER, shared_with_me_date INTEGER, is_owner INTEGER)",
            "CREATE TABLE stable_parents (item_stable_id INTEGER, parent_stable_id INTEGER)",
            "CREATE TABLE properties (property TEXT, value TEXT)",
        ],
        [
            ("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?)", (1, "root", 0, 1, "My Drive", "application/vnd.google-apps.folder", 0, 0, 0, 0, 1)),
            ("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?)", (2, "fold2", 0, 1, "인사", "application/vnd.google-apps.folder", 0, 0, 0, 0, 1)),
            ("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?)", (3, "doc3", 0, 0, "salary.xlsx", "application/vnd.ms-excel", 9000, 1714554000000, 1714555000000, 0, 1)),
            ("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?)", (4, "doc4", 1, 0, "deleted.docx", "application/msword", 100, 1714554100000, 0, 0, 1)),
            ("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?)", (5, "doc5", 0, 0, "from-partner.pdf", "application/pdf", 300, 1714554200000, 0, 1714554300000, 0)),
            ("INSERT INTO stable_parents VALUES (?, ?)", (2, 1)),
            ("INSERT INTO stable_parents VALUES (?, ?)", (3, 2)),
            ("INSERT INTO stable_parents VALUES (?, ?)", (4, 1)),
            ("INSERT INTO stable_parents VALUES (?, ?)", (5, 1)),
            ("INSERT INTO properties VALUES (?, ?)", ("driveway_account_email", "alice.drive@example.com")),
        ],
    )
    paths["mirror"] = sqlite_db(
        account / "mirror_sqlite_db",
        ["CREATE TABLE mirror_item (local_stable_id INTEGER PRIMARY KEY, cloud_id TEXT, local_filename TEXT, size INTEGER, local_mtime INTEGER, is_folder INTEGER)"],
        [
            ("INSERT INTO mirror_item VALUES (?,?,?,?,?,?)", (10, "doc3", "salary.xlsx", 9000, 1714554000, 0)),
            ("INSERT INTO mirror_item VALUES (?,?,?,?,?,?)", (11, "fold2", "인사", 0, 1714554000, 1)),
        ],
    )
    cache = account / "content_cache" / "d1" / "d2"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "1234").write_bytes(b"x" * 100)
    (cache / "5678").write_bytes(b"y" * 50)
    paths["root_preference"] = sqlite_db(
        drivefs / "root_preference_sqlite.db",
        ["CREATE TABLE roots (media_id TEXT, title TEXT, root_path TEXT, account_token TEXT, sync_type INTEGER)"],
        [("INSERT INTO roots VALUES (?,?,?,?,?)", ("m1", "Desktop", "\\\\?\\C:\\Users\\alice\\Desktop", "alice.drive@example.com", 1))],
    )
    return paths


def build_mybox(root: Path, *, user: str = "alice") -> dict[str, Path]:
    base = appdata_local(root, user) / "NAVER" / "MYBOX"
    paths = {
        "db": sqlite_db(base / "data" / "sync.db", ["CREATE TABLE sync_item (path TEXT, state INTEGER)"], [("INSERT INTO sync_item VALUES (?, ?)", ("/내 폴더/a.txt", 1))]),
    }
    (base / "config.ini").parent.mkdir(parents=True, exist_ok=True)
    (base / "config.ini").write_text("[sync]\nenabled=1\n", encoding="utf-8")
    # A browser IndexedDB origin of the MYBOX *website* is not the sync client.
    browser = appdata_local(root, user) / "Microsoft" / "Edge" / "User Data" / "Default" / "IndexedDB" / "https_mybox.naver.com_0.indexeddb.leveldb"
    browser.mkdir(parents=True, exist_ok=True)
    (browser / "000003.log").write_bytes(b"mybox upload")
    return paths


def build_icloud(root: Path, *, user: str = "alice") -> dict[str, Path]:
    drive = root / "Users" / user / "iCloudDrive"
    drive.mkdir(parents=True, exist_ok=True)
    (drive / "notes.txt").write_text("synthetic", encoding="utf-8")
    package = appdata_local(root, user) / "Packages" / "AppleInc.iCloud_nzyj5cx40ttqa" / "LocalState"
    db = sqlite_db(package / "cloudkit.db", ["CREATE TABLE zones (name TEXT)"], [("INSERT INTO zones VALUES (?)", ("com.apple.CloudDocs",))])
    return {"drive": drive, "db": db}


def build_prefetch_only(root: Path) -> Path:
    prefetch = root / "Windows" / "Prefetch"
    prefetch.mkdir(parents=True, exist_ok=True)
    path = prefetch / "ONEDRIVE.EXE-26111395.pf"
    path.write_bytes(b"MAM\x04" + bytes(64))
    return path
