"""Synthetic KakaoTalk PC chat database fixtures (legacy page cipher, r2 M2).

The schema mirrors the PC ``chatLogs`` table the existing media inventory reads
(``logId, chatId, authorId, type, sendAt, message, attachement``); every value is synthetic.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from rapidtriage.artifacts.kakaotalk_messages import derive_deviceinfo_pragmas
from rapidtriage.core.aes_cbc import aes_cbc_encrypt
from rapidtriage.core.kakaotalk import derive_kakaotalk_key_iv

PAGE_SIZE = 4096
DEVICEINFO = {"sys_uuid": "550e8400-e29b-41d4-a716-446655440000", "hdd_model": "Sample SSD", "hdd_serial": "SERIAL1234"}
USER_ID = "12345"
PEER_ID = "67890"


def fixture_key_iv(user_id: str = USER_ID) -> tuple[bytes, bytes]:
    """Key/IV the run derives from the fixture's registry DeviceInfo + talk_user_id."""
    pragma = derive_deviceinfo_pragmas(DEVICEINFO)[0]["pragma"]
    return derive_kakaotalk_key_iv(pragma, user_id)


def build_chatlogs_sqlite(path: Path, *, picture_sha1: str = "", rows: int = 0) -> bytes:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE chatLogs (logId INTEGER PRIMARY KEY, chatId INTEGER, authorId INTEGER, type INTEGER, "
            "sendAt INTEGER, message TEXT, attachement TEXT)"
        )
        base = [
            (101, 42, int(USER_ID), 1, 1710000000, "견적서 보내드립니다", ""),
            (102, 42, int(PEER_ID), 1, 1710000060, "확인했습니다", ""),
            (
                103,
                42,
                int(PEER_ID),
                2,
                1710000120,
                "사진",
                json.dumps({"k": "remote/path/i_sample.jpg", "mt": "image/jpeg", "s": 20, "cs": picture_sha1}),
            ),
            (104, 42, int(USER_ID), 16385, 1710000180, "", ""),
        ]
        connection.executemany("INSERT INTO chatLogs VALUES (?, ?, ?, ?, ?, ?, ?)", base)
        connection.executemany(
            "INSERT INTO chatLogs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(1000 + index, 42, int(PEER_ID), 1, 1710001000 + index, f"메시지 {index}", "") for index in range(rows)],
        )
        connection.commit()
    finally:
        connection.close()
    data = path.read_bytes()
    return data + b"\x00" * ((PAGE_SIZE - len(data) % PAGE_SIZE) % PAGE_SIZE)


def encrypt_pagewise(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return b"".join(
        aes_cbc_encrypt(key, iv, plaintext[offset : offset + PAGE_SIZE]) for offset in range(0, len(plaintext), PAGE_SIZE)
    )


def write_registry_export(root: Path, *, deviceinfo: bool = True, user_id: bool = True) -> Path:
    reg_path = root / "Users" / "alice" / "NTUSER-kakao.reg"
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["Windows Registry Editor Version 5.00", "", r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk]"]
    if user_id:
        lines.append(f'"talk_user_id"="{USER_ID}"')
    if deviceinfo:
        lines.append(r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk\DeviceInfo]")
        lines.extend(f'"{name}"="{value}"' for name, value in DEVICEINFO.items())
    reg_path.write_text("\n".join(lines) + "\n", encoding="utf-16")
    return reg_path


def write_kakaotalk_pc_profile(root: Path, *, encrypt: bool = True, rows: int = 0) -> dict[str, Path]:
    """KakaoTalk PC profile: encrypted chatLogs_42.edb, an app-cache thumbnail and a saved picture."""
    profile = root / "Users" / "alice" / "AppData" / "Local" / "Kakao" / "KakaoTalk" / "users" / "abc123"
    chat_dir = profile / "chat_data"
    chat_dir.mkdir(parents=True, exist_ok=True)
    saved = root / "Users" / "alice" / "Documents" / "카카오톡 받은 파일" / "KakaoTalk_20240309_160200123.jpg"
    saved.parent.mkdir(parents=True, exist_ok=True)
    saved.write_bytes(b"\xff\xd8\xff\xe0" + b"synthetic-saved-picture")
    thumb = profile / "cache" / "thumb" / "i_sample.jpg"
    thumb.parent.mkdir(parents=True, exist_ok=True)
    thumb.write_bytes(b"\x89PNG\r\n\x1a\n" + b"synthetic-thumbnail")
    scratch = root / "plain-chatlogs.sqlite"
    plaintext = build_chatlogs_sqlite(scratch, picture_sha1=hashlib.sha1(saved.read_bytes()).hexdigest(), rows=rows)
    scratch.unlink()
    key, iv = fixture_key_iv()
    database = chat_dir / "chatLogs_42.edb"
    database.write_bytes(encrypt_pagewise(plaintext, key, iv) if encrypt else b"\x11" * len(plaintext))
    return {"database": database, "saved": saved, "thumb": thumb, "profile": profile}
