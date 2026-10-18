"""Synthetic Windows desktop-messenger fixtures (plan r2-communication Q-R2-1).

Everything here is generated in code: LevelDB ``.log``/``.ldb`` files with
V8-serialized or JSON values (a minimal Snappy compressor included), Chromium
cache bodies, SQLite DBs and encrypted-looking stores. Names, addresses and
texts are invented (``example.com``/``example.org``); no real app data.

The SQLite layouts for Skype ``main.db`` follow the widely documented legacy
schema (Accounts/Contacts/Conversations/Messages/Transfers). The Zoom table
(``chat_messages``) is a *generic* layout exercising the alias mapping, not a
claim about Zoom's real schema.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
import struct
from pathlib import Path

from rapidtriage.artifacts.windows.leveldb import (
    LOG_BLOCK_SIZE,
    TABLE_MAGIC,
    crc32c,
    mask_crc,
)

# --- encoders -------------------------------------------------------------------------------


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _v8_string(text: str) -> bytes:
    try:
        raw = text.encode("latin-1")
        return b'"' + varint(len(raw)) + raw
    except UnicodeEncodeError:
        raw = text.encode("utf-16-le")
        return b"\x00c" + varint(len(raw)) + raw  # padding byte before a two-byte string


def v8_value(value: object) -> bytes:
    if isinstance(value, bool):
        return b"T" if value else b"F"
    if value is None:
        return b"0"
    if isinstance(value, int):
        return b"I" + varint((value << 1) ^ (value >> 63))
    if isinstance(value, float):
        return b"N" + struct.pack("<d", value)
    if isinstance(value, str):
        return _v8_string(value)
    if isinstance(value, dict):
        body = b"".join(_v8_string(str(key)) + v8_value(item) for key, item in value.items())
        return b"o" + body + b"{" + varint(len(value))
    if isinstance(value, list):
        body = b"".join(v8_value(item) for item in value)
        return b"A" + varint(len(value)) + body + b"$" + varint(0) + varint(len(value))
    raise TypeError(type(value))


def v8_serialize(value: object) -> bytes:
    """Blink envelope (``0xFF 0x11``) + V8 header (``0xFF 0x0F``) + value."""
    return b"\xff\x11\xff\x0f" + v8_value(value)


def snappy_compress(data: bytes) -> bytes:
    """Greedy Snappy encoder (literals + 2-byte-offset copies): enough to exercise every decoder path."""
    out = bytearray(varint(len(data)))
    table: dict[bytes, int] = {}
    position = literal_start = 0

    def literal(chunk: bytes) -> None:
        while chunk:
            piece, chunk = chunk[:65536], chunk[65536:]
            length = len(piece) - 1
            if length < 60:
                out.append(length << 2)
            elif length < 256:
                out.extend((60 << 2, length))
            else:
                out.append(61 << 2)
                out.extend(length.to_bytes(2, "little"))
            out.extend(piece)

    while position + 4 <= len(data):
        key = data[position : position + 4]
        candidate = table.get(key)
        table[key] = position
        if candidate is not None and 0 < position - candidate < 65536:
            length = 4
            while position + length < len(data) and length < 64 and data[candidate + length] == data[position + length]:
                length += 1
            literal(data[literal_start:position])
            out.append(((length - 1) << 2) | 2)
            out.extend((position - candidate).to_bytes(2, "little"))
            position += length
            literal_start = position
        else:
            position += 1
    literal(data[literal_start:])
    return bytes(out)


def write_batch(sequence: int, entries: list[tuple[bytes, bytes | None]]) -> bytes:
    body = bytearray(struct.pack("<QI", sequence, len(entries)))
    for key, value in entries:
        if value is None:
            body += b"\x00" + varint(len(key)) + key
        else:
            body += b"\x01" + varint(len(key)) + key + varint(len(value)) + value
    return bytes(body)


def leveldb_log(batches: list[bytes]) -> bytes:
    """A ``.log`` file: batches split into FULL/FIRST/MIDDLE/LAST fragments across 32 KiB blocks."""
    out = bytearray()
    for batch in batches:
        remaining = batch
        first = True
        while True:
            left_in_block = LOG_BLOCK_SIZE - (len(out) % LOG_BLOCK_SIZE)
            if left_in_block < 7:
                out += b"\x00" * left_in_block
                left_in_block = LOG_BLOCK_SIZE
            room = left_in_block - 7
            fragment, remaining = remaining[:room], remaining[room:]
            if first and not remaining:
                record_type = 1
            elif first:
                record_type = 2
            elif remaining:
                record_type = 3
            else:
                record_type = 4
            crc = mask_crc(crc32c(fragment, crc32c(bytes([record_type]))))
            out += struct.pack("<IHB", crc, len(fragment), record_type) + fragment
            first = False
            if not remaining:
                break
    return bytes(out)


def _block(entries: list[tuple[bytes, bytes]]) -> bytes:
    body = bytearray()
    restarts = []
    last = b""
    for index, (key, value) in enumerate(entries):
        if index % 16 == 0:
            restarts.append(len(body))
            shared = 0
        else:
            shared = 0
            while shared < min(len(last), len(key)) and last[shared] == key[shared]:
                shared += 1
        body += varint(shared) + varint(len(key) - shared) + varint(len(value)) + key[shared:] + value
        last = key
    if not restarts:
        restarts.append(0)
    for restart in restarts:
        body += struct.pack("<I", restart)
    body += struct.pack("<I", len(restarts))
    return bytes(body)


def leveldb_table(records: list[tuple[bytes, int, bytes | None]], *, compress: bool = True, per_block: int = 4) -> bytes:
    """An ``.ldb`` table of ``(user_key, sequence, value|None=deletion)`` (sorted by key)."""
    out = bytearray()
    index_entries: list[tuple[bytes, bytes]] = []

    def put_block(raw: bytes, use_snappy: bool) -> tuple[int, int]:
        payload = snappy_compress(raw) if use_snappy else raw
        kind = 1 if use_snappy else 0
        offset = len(out)
        out.extend(payload)
        out.append(kind)
        out.extend(struct.pack("<I", mask_crc(crc32c(payload + bytes([kind])))))
        return offset, len(payload)

    ordered = sorted(records, key=lambda item: (item[0], -item[1]))
    for start in range(0, len(ordered), per_block):
        chunk = ordered[start : start + per_block]
        entries = [
            (key + struct.pack("<Q", (sequence << 8) | (0 if value is None else 1)), value or b"")
            for key, sequence, value in chunk
        ]
        offset, size = put_block(_block(entries), compress)
        index_entries.append((entries[-1][0], varint(offset) + varint(size)))
    meta_offset, meta_size = put_block(struct.pack("<II", 0, 1), False)  # empty metaindex block
    index_offset, index_size = put_block(_block(index_entries), False)
    footer = varint(meta_offset) + varint(meta_size) + varint(index_offset) + varint(index_size)
    footer += b"\x00" * (40 - len(footer))
    out.extend(footer + struct.pack("<Q", TABLE_MAGIC))
    return bytes(out)


def pseudo_random(size: int, seed: int = 7) -> bytes:
    """Deterministic high-entropy bytes (encrypted-store stand-in)."""
    state = seed
    out = bytearray()
    while len(out) < size:
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out += state.to_bytes(8, "little")
    return bytes(out[:size])


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return path


# --- per-app fixtures -------------------------------------------------------------------------

ROAMING = ("AppData", "Roaming")
LOCAL = ("AppData", "Local")
PACKAGES = ("AppData", "Local", "Packages")

TEAMS_FILES = json.dumps(
    [{"@type": "http://schema.skype.com/File", "fileName": "q3_budget.xlsx", "fileType": "xlsx", "objectUrl": "https://example.sharepoint.com/sites/fin/q3_budget.xlsx"}]
)


def teams_message(index: int, content: str, minute: int, **extra: object) -> dict[str, object]:
    return {
        "clientmessageid": f"1700000000{index:04d}",
        "conversationId": "19:meeting_abc@thread.v2",
        "messagetype": "RichText/Html",
        "content": content,
        "imdisplayname": extra.pop("imdisplayname", "김민수"),
        "composetime": f"2024-03-01T01:{minute:02d}:00.000Z",
        **extra,
    }


def build_teams_classic(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "Microsoft", "Teams")
    store = root / "IndexedDB" / "https_teams.microsoft.com_0.indexeddb.leveldb"
    messages = [
        teams_message(1, "<div>견적서 검토 부탁드립니다</div>", 1),
        teams_message(2, "<p>첨부 확인 &amp; 회신</p>", 2, properties={"files": TEAMS_FILES}),
    ]
    contact = {"mri": "8:orgid:11111111-2222-3333-4444-555555555555", "displayName": "이영희", "email": "younghee.lee@example.com"}
    log = leveldb_log(
        [write_batch(10 + index, [(f"\x00\x01\x02msg{index}".encode(), v8_serialize(message))]) for index, message in enumerate(messages)]
        + [write_batch(20, [(b"\x00\x01\x03people", v8_serialize(contact))])]
    )
    write(store / "000003.log", log)
    table = leveldb_table([(b"\x00\x01\x02msg9", 5, v8_serialize(teams_message(9, "작년 회의록 공유", 30)))])
    write(store / "000005.ldb", table)
    write(store / "CURRENT", b"MANIFEST-000001\n")
    return root


def build_teams_new(home: Path) -> Path:
    root = home.joinpath(*PACKAGES, "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams")
    store = root / "EBWebView" / "WV2Profile_tfw" / "IndexedDB" / "https_teams.microsoft.com_0.indexeddb.leveldb"
    records = [
        (b"\x00\x02\x01m1", 30, v8_serialize(teams_message(31, "신규 Teams 첫 메시지", 10, isSentByMe=True))),
        (b"\x00\x02\x01m2", 31, v8_serialize(teams_message(32, "신규 Teams 두 번째 메시지", 11, imdisplayname="박지훈"))),
        (b"\x00\x02\x01p1", 32, v8_serialize({"mri": "8:orgid:aaaa", "displayName": "박지훈", "userPrincipalName": "jihoon.park@example.com"})),
        (b"\x00\x02\x01f1", 33, v8_serialize({"fileName": "design_spec.pdf", "fileSize": 48213, "objectUrl": "https://example.sharepoint.com/design_spec.pdf"})),
    ]
    write(store / "000007.ldb", leveldb_table(records, compress=True, per_block=2))
    return root


def build_slack(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "Slack")
    state = {
        "messages": {
            "C024BE91L": [
                {"type": "message", "user": "U012AB3CD", "text": "고객 명단 보내드립니다", "ts": "1709251200.000100", "channel": "C024BE91L",
                 "files": [{"name": "customers.csv", "title": "customers.csv", "size": 20480, "mimetype": "text/csv", "url_private": "https://files.slack.com/files-pri/T0-F0/customers.csv"}]},
                {"type": "message", "user": "U045ZZ9XY", "text": "받았습니다", "ts": "1709251260.000200", "channel": "C024BE91L"},
            ]
        },
        "members": [{"id": "U045ZZ9XY", "name": "jdoe", "real_name": "John Doe", "profile": {"email": "jdoe@example.org"}}],
        "token": "xoxc-should-never-be-copied",
    }
    value = b"\x01" + json.dumps(state, ensure_ascii=False).encode("latin-1", errors="ignore")
    # Korean text needs UTF-16: Chromium stores non-Latin-1 Local Storage values as 0x00 + UTF-16LE.
    value = b"\x00" + json.dumps(state, ensure_ascii=False).encode("utf-16-le")
    log = leveldb_log([write_batch(1, [(b"_https://app.slack.com\x00\x01localConfig_v2", value)])])
    write(root / "Local Storage" / "leveldb" / "000003.log", log)
    write(home.joinpath(*LOCAL, "slack", "app-4.36.140", "slack.exe"), b"MZ")
    return root


def build_discord(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "discord")
    messages = [
        {"id": "1210000000000000001", "channel_id": "1100000000000000001", "content": "자료 올렸어", "timestamp": "2024-03-01T02:10:00.000000+00:00",
         "author": {"id": "900000000000000001", "username": "minsu_k", "global_name": "민수"},
         "attachments": [{"id": "1", "filename": "plan.docx", "size": 33000, "url": "https://cdn.discordapp.com/attachments/1/1/plan.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}]},
        {"id": "1210000000000000002", "channel_id": "1100000000000000001", "content": "확인", "timestamp": "2024-03-01T02:11:00.000000+00:00",
         "author": {"id": "900000000000000002", "username": "yh_lee"}, "attachments": []},
    ]
    body = gzip.compress(json.dumps(messages, ensure_ascii=False).encode("utf-8"))
    write(root / "Cache" / "Cache_Data" / "f_000001", b"\x30\x5c\x72\xa7\x1b\x6d\xfb\xfc" + b"https://discord.com/api/v9/channels/1/messages" + b"\x00" * 8 + body)
    token_log = leveldb_log([write_batch(1, [(b"_https://discord.com\x00\x01token", b"\x01\"mfa.SECRETSECRET\"")])])
    write(root / "Local Storage" / "leveldb" / "000003.log", token_log)
    write(home.joinpath(*LOCAL, "Discord", "app-1.0.9030", "Discord.exe"), b"MZ")
    return root


def build_telegram(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "Telegram Desktop")
    write(root / "Telegram.exe", b"MZ")
    write(root / "tdata" / "key_datas", pseudo_random(380, 1))
    write(root / "tdata" / "settingss", pseudo_random(200, 2))
    write(root / "tdata" / "D877F783D5D3EF8C" / "maps", pseudo_random(120, 3))
    write(root / "tdata" / "user_data" / "cache" / "0" / "A1B2C3D4", pseudo_random(4096, 4))
    write(root / "tdata" / "user_data" / "media_cache" / "0" / "B1", pseudo_random(2048, 5))
    write(home / "Downloads" / "Telegram Desktop" / "invoice_2024.pdf", b"%PDF-1.7\n" + b"0" * 64)
    return root


def build_whatsapp(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "WhatsApp")
    store = root / "IndexedDB" / "file__0.indexeddb.leveldb"
    msgs = [
        {"id": "true_821012345678@c.us_3EB0AAA1", "body": "계약서 보냈어요", "t": 1709254800, "from": "821099990000@c.us", "to": "821012345678@c.us", "type": "chat"},
        {"id": "false_821012345678@c.us_3EB0AAA2", "body": "네 받았습니다", "t": 1709254860, "from": "821012345678@c.us", "to": "821099990000@c.us", "notifyName": "홍길동", "type": "chat"},
    ]
    log = leveldb_log([write_batch(5 + index, [(f"\x00\x05\x01{index}".encode(), v8_serialize(item))]) for index, item in enumerate(msgs)])
    write(store / "000004.log", log)
    new_root = home.joinpath(*PACKAGES, "5319275A.WhatsAppDesktop_cv1g1gvanyjgm", "LocalState")
    write(new_root / "sessions" / "0A1B2C" / "nativeSettings.db", pseudo_random(8192, 9))
    return root


def build_skype(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "Skype")
    db_path = root / "live#3aalice.kim" / "main.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE Accounts (id INTEGER PRIMARY KEY, skypename TEXT, fullname TEXT);
            CREATE TABLE Contacts (id INTEGER PRIMARY KEY, skypename TEXT, fullname TEXT, displayname TEXT, emails TEXT, phone_mobile TEXT);
            CREATE TABLE Conversations (id INTEGER PRIMARY KEY, identity TEXT, displayname TEXT, type INTEGER);
            CREATE TABLE Messages (id INTEGER PRIMARY KEY, convo_id INTEGER, chatname TEXT, author TEXT, from_dispname TEXT,
                                   dialog_partner TEXT, timestamp INTEGER, edited_timestamp INTEGER, type INTEGER, body_xml TEXT);
            CREATE TABLE Transfers (id INTEGER PRIMARY KEY, partner_handle TEXT, partner_dispname TEXT, status INTEGER, starttime INTEGER,
                                    finishtime INTEGER, filepath TEXT, filename TEXT, filesize TEXT, type INTEGER, convo_id INTEGER);
            """
        )
        connection.execute("INSERT INTO Accounts VALUES (1, 'live:alice.kim', 'Alice Kim')")
        connection.execute("INSERT INTO Contacts VALUES (1, 'live:bob.partner', 'Bob Partner', 'Bob', 'bob@partner.example.org', '+82-10-0000-1111')")
        connection.execute("INSERT INTO Conversations VALUES (1, 'live:bob.partner', 'Bob', 1)")
        connection.executemany(
            "INSERT INTO Messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (1, 1, '#live:alice.kim/$live:bob.partner;1', 'live:alice.kim', 'Alice Kim', 'live:bob.partner', 1709200000, None, 61, '견적 보내요'),
                (2, 1, '#live:alice.kim/$live:bob.partner;1', 'live:bob.partner', 'Bob', 'live:bob.partner', 1709200060, None, 61, '<ss type="smile">:)</ss> 고마워요'),
                (3, 1, '#live:alice.kim/$live:bob.partner;1', 'live:alice.kim', 'Alice Kim', 'live:bob.partner', 1709200120, 1709200200, 61, ''),
            ],
        )
        connection.execute(
            "INSERT INTO Transfers VALUES (1, 'live:bob.partner', 'Bob', 8, 1709200150, 1709200160, 'C:\\\\Users\\\\alice\\\\Documents\\\\price_list.xlsx', 'price_list.xlsx', '51200', 2, 1)"
        )
        connection.commit()
    finally:
        connection.close()
    return root


def build_line(home: Path) -> Path:
    root = home.joinpath(*LOCAL, "LINE")
    write(root / "bin" / "LineLauncher.exe", b"MZ")
    write(root / "Data" / "8f3c2a.edb", pseudo_random(16384, 11))
    write(root / "Data" / "Sticker" / "1" / "sticker.png", b"\x89PNG\r\n\x1a\n" + b"0" * 16)
    return root


def build_wechat(home: Path) -> Path:
    root = home / "Documents" / "WeChat Files"
    account = root / "wxid_abc123def456"
    write(account / "Msg" / "MSG0.db", pseudo_random(8192, 21))
    write(account / "Msg" / "MicroMsg.db", pseudo_random(8192, 22))
    write(account / "Msg" / "Multi" / "MSG0.db", pseudo_random(4096, 23))
    write(account / "FileStorage" / "File" / "2024-03" / "contract_final.docx", b"PK\x03\x04" + b"0" * 64)
    write(account / "FileStorage" / "File" / "2024-03" / "photo.jpg", b"\xff\xd8\xff\xe0" + b"0" * 64)
    return root


ZOOM_CHAT = (
    "10:01:02 From 김민수 to Everyone:\n\t안녕하세요\n"
    "10:02:10 From 이영희 to Everyone:\n\t자료는 https://wetransfer.com/downloads/abc 에 있습니다\n"
    "10:03:00 From Me to 김민수(Direct Message):\n\t확인했습니다\n"
)


def build_zoom(home: Path) -> Path:
    root = home.joinpath(*ROAMING, "Zoom")
    db_path = root / "data" / "zoomus.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE zoom_kv (key TEXT, value TEXT, section TEXT);
            CREATE TABLE chat_messages (id INTEGER PRIMARY KEY, session_id TEXT, sender TEXT, body TEXT, timestamp INTEGER);
            CREATE TABLE contacts (jid TEXT, display_name TEXT, email TEXT);
            """
        )
        connection.execute("INSERT INTO zoom_kv VALUES ('com.zoom.client.theme', 'light', 'ui')")
        connection.executemany(
            "INSERT INTO chat_messages VALUES (?, ?, ?, ?, ?)",
            [(1, "s1@xmpp.zoom.us", "minsu@example.com", "회의 링크 공유", 1709254800000), (2, "s1@xmpp.zoom.us", "younghee@example.com", "감사합니다", 1709254860000)],
        )
        connection.execute("INSERT INTO contacts VALUES ('abc@xmpp.zoom.us', 'Lee Younghee', 'younghee@example.com')")
        connection.commit()
    finally:
        connection.close()
    write(root / "data" / "zoomus.enc.db", pseudo_random(4096, 31))
    write(home / "Documents" / "Zoom" / "2024-03-01 10.00.00 Weekly Sync 81234567890" / "meeting_saved_chat.txt", ZOOM_CHAT)
    return root


BUILDERS = {
    "teams-classic": build_teams_classic,
    "teams-new": build_teams_new,
    "slack": build_slack,
    "discord": build_discord,
    "telegram-desktop": build_telegram,
    "whatsapp-desktop": build_whatsapp,
    "skype": build_skype,
    "line": build_line,
    "wechat": build_wechat,
    "zoom": build_zoom,
}


def build_all(root: Path, user: str = "analyst") -> Path:
    home = root / "Users" / user
    for builder in BUILDERS.values():
        builder(home)
    return home


def corrupt_stores(home: Path) -> dict[str, Path]:
    """Damaged inputs next to good ones: truncated table, garbage log, broken SQLite."""
    teams = home.joinpath(*ROAMING, "Microsoft", "Teams", "IndexedDB", "https_teams.microsoft.com_0.indexeddb.leveldb")
    good = (teams / "000005.ldb").read_bytes()
    truncated = write(teams / "000006.ldb", good[: len(good) - 30])
    garbage_log = write(teams / "000009.log", b"\xff" * 64 + b"\x00\x00\x00\x00\xff\xff\x09garbage")
    skype_bad = home.joinpath(*ROAMING, "Skype", "live#3abroken", "main.db")
    write(skype_bad, b"SQLite format 3\x00" + b"\xde\xad" * 2000)
    return {"truncated_table": truncated, "garbage_log": garbage_log, "broken_sqlite": skype_bad}


# --- hostile LevelDB shapes (review repros exp1-exp4) ---------------------------------------------


def prefix_bomb_block(key_size: int, entries: int, *, tail: bytes = b"") -> bytes:
    """A block whose first key is ``key_size`` bytes and every later entry re-shares it (prefix amplification)."""
    body = bytearray(varint(0) + varint(key_size) + varint(0) + b"A" * key_size)
    for _ in range(entries):
        body += varint(key_size - len(tail)) + varint(len(tail)) + varint(0) + tail
    return bytes(body + struct.pack("<I", 0) + struct.pack("<I", 1))


def snappy_run(length: int) -> bytes:
    """A tiny Snappy stream that expands to ``length`` bytes (one literal + 64-byte copies)."""
    out = bytearray(varint(length)) + bytes([0]) + b"x"
    count, rest = divmod(length - 1, 64)
    out += bytes([((64 - 1) << 2) | 2, 1, 0]) * count
    if rest:
        out += bytes([((rest - 1) << 2) | 2, 1, 0])
    return bytes(out)


def table_with_blocks(payloads: list[tuple[bytes, int]], *, repeat_first_handle: int = 1) -> bytes:
    """A table of already-encoded data blocks ``(payload, compression)``; the first handle may repeat in the index."""
    out = bytearray()
    handles: list[bytes] = []
    for payload, kind in payloads:
        handles.append(varint(len(out)) + varint(len(payload)))
        out += payload + bytes([kind]) + b"\x00" * 4
    handles = [handles[0]] * repeat_first_handle + handles[1:]
    index_entries = [(b"k%06d" % number, handle) for number, handle in enumerate(handles)]
    index_raw = _block(index_entries)
    index_offset = len(out)
    out += index_raw + b"\x00" * 5
    meta_offset = len(out)
    out += struct.pack("<II", 0, 1) + b"\x00" * 5
    footer = varint(meta_offset) + varint(8) + varint(index_offset) + varint(len(index_raw))
    out += footer + b"\x00" * (40 - len(footer)) + struct.pack("<Q", TABLE_MAGIC)
    return bytes(out)


def log_fragment(record_type: int, data: bytes) -> bytes:
    crc = mask_crc(crc32c(data, crc32c(bytes([record_type]))))
    return struct.pack("<IHB", crc, len(data), record_type) + data
