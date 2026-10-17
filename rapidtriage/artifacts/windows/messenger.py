"""Windows desktop messengers (plan r2-communication §3.1 M1): ``windows-messenger`` provider.

Path signatures under each user profile (``AppData\\Roaming|Local``, ``Packages``,
``Documents``, ``Downloads``) for Microsoft Teams (classic and the new
WebView2 client), Slack, Discord, Telegram Desktop, WhatsApp Desktop, Skype,
LINE PC, WeChat PC and Zoom. Rows:

* ``chat-message`` — app, conversation, sender, recipient, time, body,
  direction, deleted state.
* ``chat-attachment`` — file name, size, path/URL, hash, transfer direction.
* ``chat-contact`` — display name, account id, e-mail/phone.
* ``chat-app-inventory`` — one row per app root: presence, version, file
  count/bytes, store list, encryption state and (Korean) why the app is
  inventory-only when its stores are encrypted.
* ``chat-parse-error`` — a store that could not be read (``parser_error``);
  the provider continues with the next store.

Recovery methods (``recovery_method``):

* ``sqlite-table`` — plaintext SQLite rows (Skype ``main.db``, Zoom, any
  plaintext LINE/WhatsApp DB), mapped through the shared column aliases and
  the mobile chat profiles (``artifacts/mobile`` ``CHAT_APP_PROFILES``).
* ``carved`` — LevelDB (IndexedDB / Local Storage) values read by the bounded
  pure-Python reader in ``leveldb.py`` (``.log`` batches, ``.ldb`` blocks with
  Snappy) and Chromium cache bodies, from which V8-serialized key/value runs
  and JSON fragments are recovered as message/contact/file candidates. These
  are *candidates*: the record structure (object store, schema version) is
  not decoded, so values are attributed by field names only.
* ``app-file-store`` — files the app saved (WeChat ``FileStorage``, Telegram
  ``Downloads``), hashed within a byte cap.
* ``text-log`` — Zoom ``meeting_saved_chat.txt`` lines.
* ``filesystem-inventory`` — presence/size/count only (encrypted stores).

Nothing is decrypted: Telegram ``tdata``, WeChat SQLCipher DBs, LINE and the
new WhatsApp client's encrypted DBs, and Zoom ``*.enc.db`` are inventoried
with the reason; no key material or token values are emitted (secret-named
fields are never copied).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import sqlite3
import struct
import zlib
from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ...core.models import ArtifactRecord
from ..mobile.helpers import (
    chat_table_is_message_candidate,
    safe_sqlite_identifier,
    sqlite_columns,
    sqlite_table_names,
)
from ..mobile.messengers import chat_app_profile
from .common import (
    isoformat_from_timestamp,
    iter_windows_user_homes,
    open_sqlite_snapshot,
)
from .leveldb import LevelDBError, ReadStats, iter_log_records, iter_table_records

PARSER = "windows-messenger"
PARSER_VERSION = "windows-messenger-v1"
SQLITE_HEADER = b"SQLite format 3\x00"
GZIP_MAGIC = b"\x1f\x8b\x08"
MAX_GZIP_MEMBERS_PER_CACHE_FILE = 64  # Chromium blockfile data_N files hold many bodies


@dataclass(frozen=True)
class MessengerLimits:
    """Caps of one collect (per app root unless noted)."""

    max_store_files: int = 400  # LevelDB/cache/db files read per store directory
    max_file_bytes: int = 64 * 1024 * 1024  # bytes read from one file
    max_app_bytes: int = 768 * 1024 * 1024  # bytes read for carving per app root
    max_rows_per_app: int = 50_000  # message/attachment/contact rows per app root
    max_sqlite_rows: int = 20_000  # rows read per SQLite table
    max_sqlite_tables: int = 200
    max_inventory_files: int = 20_000  # files walked for the inventory counts
    max_attachment_files: int = 2_000  # file-store files per app root
    max_hash_bytes: int = 64 * 1024 * 1024  # files above this are listed without a hash
    max_json_attempts: int = 300  # JSON decode attempts per blob
    max_json_window: int = 1024 * 1024  # characters one JSON fragment may span
    max_text_chars: int = 8_000  # stored message text
    max_store_list: int = 50  # stores listed on the inventory row


DEFAULT_LIMITS = MessengerLimits()


@dataclass(frozen=True)
class AppSpec:
    app_id: str
    service: str
    label_ko: str
    # App roots relative to the user home (first existing ones are used).
    roots: tuple[tuple[str, ...], ...]
    leveldb: tuple[str, ...] = ()  # globs (relative to an app root) of LevelDB directories
    caches: tuple[str, ...] = ()  # globs of Chromium cache directories (JSON bodies)
    sqlite: tuple[str, ...] = ()  # globs of database files (plaintext → rows, else inventory)
    encrypted: tuple[str, ...] = ()  # globs of stores known to be encrypted (inventory only)
    file_stores: tuple[str, ...] = ()  # globs of directories holding files the app saved
    home_file_stores: tuple[tuple[str, ...], ...] = ()  # same, relative to the user home
    chat_logs: tuple[tuple[str, ...], ...] = ()  # home-relative dirs with Zoom saved chat logs
    version_dirs: tuple[tuple[str, ...], ...] = ()  # home-relative dirs whose ``app-x.y.z`` children name versions
    encryption_state: str = "plaintext-or-unknown"
    # ``CHAT_APP_PROFILES`` service whose message-table names drive SQLite table selection.
    profile_service: str = ""
    inventory_reason_ko: str = ""


_ROAMING = ("AppData", "Roaming")
_LOCAL = ("AppData", "Local")
_PACKAGES = ("AppData", "Local", "Packages")
_CHROMIUM_LEVELDB = ("IndexedDB/*.leveldb", "Local Storage/leveldb")
_CHROMIUM_CACHE = ("Cache/Cache_Data", "Cache")

APPS: tuple[AppSpec, ...] = (
    AppSpec(
        app_id="teams-classic",
        profile_service="Microsoft Teams",
        service="Microsoft Teams (classic)",
        label_ko="Teams(클래식)",
        roots=((*_ROAMING, "Microsoft", "Teams"),),
        leveldb=_CHROMIUM_LEVELDB,
        caches=_CHROMIUM_CACHE,
        encryption_state="leveldb-plaintext",
    ),
    AppSpec(
        app_id="teams-new",
        profile_service="Microsoft Teams",
        service="Microsoft Teams (new)",
        label_ko="Teams(신규)",
        roots=((*_PACKAGES, "MSTeams_8wekyb3d8bbwe", "LocalCache", "Microsoft", "MSTeams"),),
        leveldb=("EBWebView/*/IndexedDB/*.leveldb", "EBWebView/*/Local Storage/leveldb"),
        caches=("EBWebView/*/Cache/Cache_Data",),
        encryption_state="leveldb-plaintext",
    ),
    AppSpec(
        app_id="slack",
        profile_service="Slack",
        service="Slack",
        label_ko="Slack",
        roots=((*_ROAMING, "Slack"), (*_PACKAGES, "91750D7E.Slack_8she8kybcnzg4", "LocalCache", "Roaming", "Slack")),
        leveldb=_CHROMIUM_LEVELDB,
        caches=_CHROMIUM_CACHE,
        version_dirs=((*_LOCAL, "slack"),),
        encryption_state="leveldb-plaintext",
    ),
    AppSpec(
        app_id="discord",
        profile_service="Discord",
        service="Discord",
        label_ko="Discord",
        roots=((*_ROAMING, "discord"), (*_ROAMING, "discordptb"), (*_ROAMING, "discordcanary")),
        leveldb=_CHROMIUM_LEVELDB,
        caches=_CHROMIUM_CACHE,
        version_dirs=((*_LOCAL, "Discord"),),
        encryption_state="leveldb-plaintext",
    ),
    AppSpec(
        app_id="telegram-desktop",
        profile_service="Telegram",
        service="Telegram Desktop",
        label_ko="Telegram Desktop",
        roots=(
            (*_ROAMING, "Telegram Desktop"),
            (*_PACKAGES, "TelegramMessengerLLP.TelegramDesktop_t4vj0pshhgkwm", "LocalCache", "Roaming", "Telegram Desktop UWP"),
        ),
        encrypted=("tdata",),
        file_stores=("tdata/user_data/cache", "tdata/user_data/media_cache"),
        home_file_stores=(("Downloads", "Telegram Desktop"),),
        encryption_state="encrypted-tdata",
        inventory_reason_ko=(
            "Telegram Desktop의 tdata(대화·캐시)는 로컬 키(key_datas)로 암호화되어 있어 본문을 읽지 않습니다"
            "(복호·암호 크래킹은 정책상 하지 않음). 계정 폴더·세션·캐시 파일 목록과 Downloads 저장 파일만 제공합니다."
        ),
    ),
    AppSpec(
        app_id="whatsapp-desktop",
        profile_service="WhatsApp",
        service="WhatsApp Desktop",
        label_ko="WhatsApp Desktop",
        roots=((*_ROAMING, "WhatsApp"), (*_PACKAGES, "5319275A.WhatsAppDesktop_cv1g1gvanyjgm", "LocalState")),
        leveldb=_CHROMIUM_LEVELDB,
        caches=_CHROMIUM_CACHE,
        sqlite=("*.db", "sessions/*/*.db", "sessions/*/*/*.db"),
        version_dirs=((*_LOCAL, "WhatsApp"),),
        encryption_state="mixed",
        inventory_reason_ko=(
            "WhatsApp Desktop은 msgstore.db가 없습니다. Electron판은 IndexedDB(LevelDB)에서 메시지 후보를 복구하고, "
            "신규(Store)판 세션 DB는 암호화되어 있어 존재·크기만 목록화합니다."
        ),
    ),
    AppSpec(
        app_id="skype",
        profile_service="Skype",
        service="Skype",
        label_ko="Skype",
        roots=(
            (*_ROAMING, "Microsoft", "Skype for Desktop"),
            (*_ROAMING, "Skype"),
            (*_PACKAGES, "Microsoft.SkypeApp_kzf8qxf38zg5c", "LocalState"),
        ),
        leveldb=_CHROMIUM_LEVELDB,
        sqlite=("*/main.db",),
        encryption_state="mixed",
    ),
    AppSpec(
        app_id="line",
        profile_service="LINE",
        service="LINE",
        label_ko="LINE PC",
        roots=((*_LOCAL, "LINE"),),
        sqlite=("Data/*.db", "Data/*.edb", "Data/*/*.db", "Data/*/*.edb"),
        encryption_state="encrypted-or-unknown",
        inventory_reason_ko=(
            "LINE PC 대화 DB는 암호화되어 있어 본문을 읽지 않습니다. 평문 SQLite가 있으면 행으로, 아니면 존재·크기만 목록화합니다."
        ),
    ),
    AppSpec(
        app_id="wechat",
        profile_service="WeChat",
        service="WeChat",
        label_ko="WeChat PC",
        # 3.x: Documents\WeChat Files\<wxid>\Msg; 4.x: Documents\xwechat_files\<wxid>\db_storage (both SQLCipher).
        roots=(("Documents", "WeChat Files"), ("Documents", "xwechat_files"), (*_ROAMING, "Tencent", "WeChat")),
        encrypted=("*/Msg/*.db", "*/Msg/Multi/*.db", "*/db_storage/*/*.db"),
        file_stores=("*/FileStorage/File/*", "*/msg/file/*"),
        encryption_state="encrypted-sqlcipher",
        inventory_reason_ko=(
            "WeChat PC의 Msg\\*.db는 SQLCipher로 암호화되어 있어 본문을 읽지 않습니다(키 추출·복호는 정책상 하지 않음). "
            "DB 목록과 FileStorage\\File에 저장된 주고받은 파일만 제공합니다."
        ),
    ),
    AppSpec(
        app_id="zoom",
        service="Zoom",
        label_ko="Zoom",
        roots=((*_ROAMING, "Zoom"),),
        sqlite=("data/*.db", "data/*/*.db"),
        chat_logs=(("Documents", "Zoom"),),
        encryption_state="mixed",
        inventory_reason_ko=(
            "Zoom 신규 버전의 *.enc.db는 암호화되어 있어 존재·크기만 목록화합니다. 평문 zoomus.db/zoommeeting.db 표와 "
            "Documents\\Zoom의 저장된 회의 채팅(meeting_saved_chat.txt)은 행으로 읽습니다."
        ),
    ),
)

# --- field vocabularies (JSON objects, V8 runs, SQLite columns) -----------------------

TEXT_KEYS = ("content", "text", "body", "body_xml", "message", "messagebody", "msg", "caption", "plaintext")
TIME_KEYS = (
    "composetime", "originalarrivaltime", "clientarrivaltime", "createdtime", "created_at", "createdat", "timestamp",
    "ts", "t", "time", "sent_at", "sendtime", "send_time", "date", "msgtime", "msg_time", "datetime",
)
SENDER_KEYS = (
    "imdisplayname", "author", "from_dispname", "fromdisplayname", "sendername", "sender_name", "sender", "from",
    "creator", "user", "username", "user_name", "notifyname", "global_name", "speaker",
)
RECIPIENT_KEYS = ("to", "recipient", "dialog_partner", "partner_handle", "receiver", "peer")
CONVERSATION_KEYS = (
    "conversationid", "conversation_id", "convo_id", "channel_id", "channel", "chatid", "chat_id", "chatname",
    "threadid", "thread_id", "thread_ts", "roomid", "room_id", "sessionid", "session_id", "remote_jid", "id_remote",
)
CONVERSATION_TITLE_KEYS = ("topic", "chattitle", "threadtopic", "conversation_name", "displayname_conversation", "channel_name")
MESSAGE_ID_KEYS = ("clientmessageid", "client_msg_id", "messageid", "message_id", "msg_id", "msgid", "server_id", "id")
EDIT_KEYS = ("edittime", "edited_timestamp", "edited_at", "lasteditedtime", "edited")
DELETE_KEYS = ("deletetime", "deleted", "isdeleted", "is_deleted", "deletedtime")
OUTGOING_FLAG_KEYS = ("isfromme", "is_from_me", "fromme", "from_me", "issentbyme", "issentbycurrentuser", "outgoing", "is_sent")
MESSAGE_TYPE_KEYS = ("messagetype", "message_type", "msgtype", "type", "subtype")
FILE_LIST_KEYS = ("files", "attachments", "file", "attachment", "amsreferences", "media")
FILE_NAME_KEYS = ("filename", "file_name", "name", "title", "original_name", "fullname_file")
FILE_SIZE_KEYS = ("size", "filesize", "file_size", "bytes", "bytestransferred")
FILE_URL_KEYS = ("url_private", "url", "objecturl", "proxy_url", "shareurl", "permalink", "downloadurl", "fileurl")
FILE_PATH_KEYS = ("filepath", "file_path", "localpath", "local_path", "savepath")
FILE_MIME_KEYS = ("mimetype", "mime_type", "content_type", "filetype", "file_type")
CONTACT_NAME_KEYS = (
    "displayname", "display_name", "real_name", "fullname", "full_name", "global_name", "username", "nickname", "name", "pushname",
)
CONTACT_ID_KEYS = ("mri", "skypename", "userprincipalname", "email", "jid", "user_id", "userid", "id")
CONTACT_STRONG_KEYS = frozenset(
    {"mri", "skypename", "userprincipalname", "email", "real_name", "global_name", "discriminator", "jid", "phone", "phone_mobile", "pushname", "ismycontact"}
)
EMAIL_KEYS = ("email", "emails", "userprincipalname", "mail")
PHONE_KEYS = ("phone", "phone_mobile", "phonenumber", "phone_number", "msisdn")
_ANCHOR_KEYS = frozenset({*TEXT_KEYS, "composetime", "originalarrivaltime", "ts", "timestamp", "conversationid", "channel_id"})
_SECRET_MARKERS = ("token", "password", "passwd", "secret", "cookie", "authorization", "credential", "session_key", "private_key")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TAG_RE = re.compile(r"<[^>]{0,2000}>")
_WS_RE = re.compile(r"\s+")
_JSON_START_RE = re.compile(r"\[\s*\{\s*\"|[\[{]\s*\"")  # arrays of objects first, then objects/string arrays
_WHATSAPP_MSG_ID = re.compile(r"^(true|false)_([^_\s]+@[a-z.]+)_")
_APP_VERSION_RE = re.compile(r"^app-(\d+(?:\.\d+){1,3})$", re.IGNORECASE)
_KNOWN_KEYS = frozenset(
    {
        *TEXT_KEYS, *TIME_KEYS, *SENDER_KEYS, *RECIPIENT_KEYS, *CONVERSATION_KEYS, *CONVERSATION_TITLE_KEYS,
        *MESSAGE_ID_KEYS, *EDIT_KEYS, *DELETE_KEYS, *OUTGOING_FLAG_KEYS, *MESSAGE_TYPE_KEYS, *FILE_NAME_KEYS,
        *FILE_SIZE_KEYS, *FILE_URL_KEYS, *FILE_PATH_KEYS, *FILE_MIME_KEYS, *CONTACT_NAME_KEYS, *CONTACT_ID_KEYS,
        *EMAIL_KEYS, *PHONE_KEYS, "discriminator", "status", "ismycontact",
    }
)
# V8 needles: case-preserving spellings as the apps write them (the vocabulary above is lowercase).
V8_KEY_SPELLINGS = (
    "content", "text", "body", "message", "caption", "messagetype", "messageType", "imdisplayname", "composetime",
    "originalarrivaltime", "clientArrivalTime", "createdTime", "conversationId", "conversationid", "clientmessageid",
    "clientMessageId", "id", "ts", "t", "timestamp", "user", "username", "author", "from", "to", "creator",
    "channel", "channel_id", "displayName", "real_name", "global_name", "mri", "email", "userPrincipalName",
    "notifyName", "type", "isFromMe", "fromMe", "isSentByMe", "deletetime", "edittime", "files", "properties",
    "fileName", "filename", "name", "size", "fileSize", "url_private", "objectUrl", "url", "mimetype", "fileType",
    "title", "jid", "skypename", "threadId", "chatId", "subject", "topic", "pushname", "isMyContact",
)

SECONDS_2000 = 946_684_800
SECONDS_2100 = 4_102_444_800


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


_V8_NEEDLES = tuple((key, b'"' + _varint(len(key)) + key.encode("latin-1")) for key in V8_KEY_SPELLINGS)
_MISSING = object()


# --- value helpers ---------------------------------------------------------------------------


def parse_chat_time(value: object) -> tuple[str, str]:
    """``(ISO-8601 UTC, raw text)`` of an epoch (s/ms/µs, Slack ``"1700000000.000100"``) or ISO value; ``("", raw)`` when unusable."""
    if value is None or isinstance(value, bool):
        return "", ""
    raw = str(value).strip()
    number: float | None = None
    if isinstance(value, (int, float)):
        number = float(value)
    elif re.fullmatch(r"\d{9,17}(?:\.\d+)?", raw):
        number = float(raw)
    if number is not None:
        if number > 1e14:
            number /= 1e6
        elif number > 1e11:
            number /= 1e3
        if not SECONDS_2000 <= number <= SECONDS_2100:
            return "", raw
        return dt.datetime.fromtimestamp(number, dt.timezone.utc).isoformat(), raw
    text = raw.replace("Z", "+00:00").replace(" ", "T", 1) if raw else ""
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        moment = dt.datetime.fromisoformat(text)
    except ValueError:
        return "", raw
    if moment.tzinfo is None:
        return "", raw  # no offset: never guess an instant
    if not 2000 <= moment.year < 2100:
        return "", raw
    return moment.astimezone(dt.timezone.utc).isoformat(), raw


def _lower_map(record: Mapping[object, object]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in record.items():
        if isinstance(key, str):
            out.setdefault(key.lower(), value)
    return out


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in _SECRET_MARKERS)


def _first(lower: Mapping[str, object], keys: Iterable[str]) -> tuple[str, object]:
    for key in keys:
        value = lower.get(key)
        if value not in (None, "", [], {}):
            return key, value
    return "", None


def _scalar_text(value: object, *, limit: int = 512) -> str:
    if value is None or isinstance(value, (list, tuple)):
        return ""
    if isinstance(value, Mapping):
        lower = _lower_map(value)
        _key, nested = _first(lower, ("displayname", "display_name", "global_name", "username", "name", "real_name", "id"))
        return _scalar_text(nested, limit=limit) if not isinstance(nested, Mapping) else ""
    text = str(value).strip()
    return text[:limit]


def clean_message_text(value: object, limit: int) -> tuple[str, str, bool]:
    """``(plain text, format, truncated)``: HTML (Teams ``RichText/Html``, Skype ``body_xml``) reduced to text."""
    text = str(value)
    text_format = "text"
    if "<" in text and ">" in text and _TAG_RE.search(text):
        text_format = "html"
        text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", html.unescape(text)).strip()
    return text[:limit], text_format, len(text) > limit


def _bool_flag(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "y", "out", "outgoing", "sent"}:
        return True
    if text in {"false", "0", "no", "n", "in", "incoming", "received"}:
        return False
    return None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _email_of(*values: object) -> str:
    for value in values:
        match = _EMAIL_RE.search(str(value or ""))
        if match:
            return match.group(0).lower()
    return ""


# --- carving: V8 key/value runs and JSON fragments --------------------------------------------


def decode_v8_value(blob: bytes, position: int) -> tuple[object, int]:
    """One V8-serialized scalar at ``position`` (padding skipped): string/int/double/bool/null, else ``_MISSING``."""
    size = len(blob)
    padding = 0
    while position < size and blob[position] == 0 and padding < 4:
        position += 1
        padding += 1
    if position >= size:
        return _MISSING, position
    tag = blob[position]
    position += 1
    try:
        if tag in (0x22, 0x63, 0x53):  # '"' one-byte, 'c' two-byte, 'S' UTF-8 string
            length, _shift, cursor = 0, 0, position
            while cursor < size:
                byte = blob[cursor]
                cursor += 1
                length |= (byte & 0x7F) << _shift
                if not byte & 0x80:
                    break
                _shift += 7
                if _shift > 35:
                    return _MISSING, position
            else:
                return _MISSING, position
            if length > 1_048_576 or cursor + length > size:
                return _MISSING, position
            raw = blob[cursor : cursor + length]
            if tag == 0x22:
                text = raw.decode("latin-1")
            elif tag == 0x63:
                if length % 2:
                    return _MISSING, position
                text = raw.decode("utf-16-le")
            else:
                text = raw.decode("utf-8")
            if text and sum(1 for char in text[:256] if char.isprintable() or char in "\r\n\t") < min(len(text), 256) * 0.85:
                return _MISSING, position
            return text, cursor + length
        if tag in (0x49, 0x55):  # 'I' zigzag int32, 'U' uint32
            value, shift, cursor = 0, 0, position
            while cursor < size:
                byte = blob[cursor]
                cursor += 1
                value |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
                if shift > 35:
                    return _MISSING, position
            if tag == 0x49:
                value = (value >> 1) ^ -(value & 1)
            return value, cursor
        if tag in (0x4E, 0x44):  # 'N' double, 'D' date (ms)
            if position + 8 > size:
                return _MISSING, position
            number = struct.unpack("<d", blob[position : position + 8])[0]
            if not math.isfinite(number):
                return _MISSING, position
            return number, position + 8
        if tag == 0x54:
            return True, position
        if tag == 0x46:
            return False, position
    except (UnicodeDecodeError, struct.error):
        return _MISSING, position
    return _MISSING, position


def v8_key_objects(blob: bytes, *, max_pairs: int = 20_000) -> list[tuple[int, dict[str, object]]]:
    """Objects rebuilt from V8 ``"key" value`` runs: known keys found by needle, grouped by proximity.

    A new object starts when an anchor key (body, send time, conversation)
    repeats or after a 4 KiB gap; other repeated keys (nested ``id``) keep
    their first value. Positions are offsets of the first key in ``blob``.
    """
    hits: list[tuple[int, str, object]] = []
    for key, needle in _V8_NEEDLES:
        start = 0
        while len(hits) < max_pairs:
            position = blob.find(needle, start)
            if position < 0:
                break
            value, _end = decode_v8_value(blob, position + len(needle))
            if value is not _MISSING:
                hits.append((position, key, value))
            start = position + 1
    hits.sort(key=lambda item: item[0])
    groups: list[tuple[int, dict[str, object]]] = []
    current: dict[str, object] = {}
    lowered: set[str] = set()
    group_start = last = -1
    for position, key, value in hits:
        lower = key.lower()
        if current and ((lower in lowered and lower in _ANCHOR_KEYS) or position - last > 4096):
            groups.append((group_start, current))
            current, lowered = {}, set()
        if not current:
            group_start = position
        if lower not in lowered:
            current[key] = value
            lowered.add(lower)
        last = position
    if current:
        groups.append((group_start, current))
    return groups


def json_fragments(text: str, *, max_attempts: int, max_window: int) -> list[tuple[int, object]]:
    """``(offset, value)`` of JSON objects/arrays embedded in ``text`` (bounded decode attempts)."""
    decoder = json.JSONDecoder()
    found: list[tuple[int, object]] = []
    consumed = 0
    attempts = 0
    for match in _JSON_START_RE.finditer(text):
        position = match.start()
        if position < consumed:
            continue
        attempts += 1
        if attempts > max_attempts:
            break
        window = text[position : position + max_window]
        try:
            value, end = decoder.raw_decode(window)
        except (ValueError, RecursionError):
            continue
        found.append((position, value))
        consumed = position + end
    return found


def walk_dicts(value: object, *, max_nodes: int = 20_000) -> Iterator[dict[str, object]]:
    """Every mapping inside a JSON value (breadth-first, bounded); JSON-in-string values are expanded once."""
    queue: deque[tuple[object, int]] = deque([(value, 0)])
    seen = 0
    while queue and seen < max_nodes:
        item, depth = queue.popleft()
        seen += 1
        if isinstance(item, dict):
            yield item
            if depth < 12:
                for child in item.values():
                    if isinstance(child, (dict, list)):
                        queue.append((child, depth + 1))
                    elif isinstance(child, str) and len(child) <= 1_048_576 and child[:1] in ("[", "{"):
                        parsed = _maybe_json(child)
                        if parsed is not None:
                            queue.append((parsed, depth + 1))
        elif isinstance(item, list) and depth < 12:
            queue.extend((child, depth + 1) for child in item[:5000] if isinstance(child, (dict, list)))


def _maybe_json(text: str) -> object | None:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def localstorage_text(value: bytes) -> str:
    """Chromium Local Storage value text: ``0x00`` + UTF-16LE or ``0x01`` + Latin-1 (else Latin-1 of the bytes)."""
    if value[:1] == b"\x00" and len(value) > 1 and (len(value) - 1) % 2 == 0:
        try:
            return value[1:].decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    if value[:1] == b"\x01":
        return value[1:].decode("latin-1")
    return value.decode("latin-1")


# --- classification -------------------------------------------------------------------------


@dataclass
class Candidate:
    """A message/attachment/contact recovered from one source object."""

    artifact_type: str
    fields: dict[str, object]


def _file_fields(lower: Mapping[str, object]) -> dict[str, object] | None:
    _name_key, name = _first(lower, FILE_NAME_KEYS)
    _size_key, size = _first(lower, FILE_SIZE_KEYS)
    _url_key, url = _first(lower, FILE_URL_KEYS)
    _path_key, local_path = _first(lower, FILE_PATH_KEYS)
    name_text = _scalar_text(name, limit=300)
    if not name_text and local_path:
        name_text = re.split(r"[\\/]", str(local_path))[-1][:300]
    if not name_text or not (size not in (None, "") or url or local_path or _first(lower, FILE_MIME_KEYS)[1]):
        return None
    if "." not in name_text and not size:
        return None  # a bare "name" with a URL is usually a channel/link, not a file
    try:
        size_value: int | None = int(float(str(size))) if size not in (None, "") else None
    except ValueError:
        size_value = None
    url_text = _scalar_text(url, limit=1000)
    return {
        "file_name": name_text,
        "attachment_name": name_text,
        "file_size": size_value,
        "url": url_text if url_text.lower().startswith(("http://", "https://")) else "",
        "file_path": _scalar_text(local_path, limit=1000),
        "mime_type": _scalar_text(_first(lower, FILE_MIME_KEYS)[1], limit=120),
    }


def _direction(lower: Mapping[str, object], owner: str = "") -> str:
    key, value = _first(lower, OUTGOING_FLAG_KEYS)
    if key:
        flag = _bool_flag(value)
        if flag is not None:
            return "outgoing" if flag else "incoming"
    message_id = str(lower.get("id") or lower.get("_serialized") or "")
    if message_id.startswith("true_"):
        return "outgoing"
    if message_id.startswith("false_"):
        return "incoming"
    if owner:
        sender = _scalar_text(_first(lower, ("author", "sender", "from", "creator", "user"))[1])
        if sender and sender.lower() == owner.lower():
            return "outgoing"
        if sender:
            return "incoming"
    return "unknown"


def classify_object(record: Mapping[object, object], *, max_text_chars: int, owner: str = "") -> list[Candidate]:
    """Message / attachment / contact candidates of one object (JSON dict, V8 run group or SQLite row)."""
    lower = _lower_map(record)
    candidates: list[Candidate] = []
    text_key, text_value = _first(lower, TEXT_KEYS)
    text_value = text_value if isinstance(text_value, str) else None
    delete_key, delete_value = _first(lower, DELETE_KEYS)
    deleted = bool(delete_key) and (_bool_flag(delete_value) is True or bool(parse_chat_time(delete_value)[0]))
    if text_value is None and deleted:
        # A message deleted in the app keeps its row with an emptied body (Skype ``body_xml = ''``).
        text_key = next((key for key in TEXT_KEYS if isinstance(lower.get(key), str)), "")
        text_value = "" if text_key else None
    time_key = ""
    iso = raw_time = ""
    for key in TIME_KEYS:
        if key in lower and lower[key] not in (None, ""):
            candidate_iso, candidate_raw = parse_chat_time(lower[key])
            if candidate_iso:
                time_key, iso, raw_time = key, candidate_iso, candidate_raw
                break
    sender_key, sender_value = _first(lower, SENDER_KEYS)
    sender = _scalar_text(sender_value)
    conversation = _scalar_text(_first(lower, CONVERSATION_KEYS)[1])
    if not conversation:
        whatsapp_id = _WHATSAPP_MSG_ID.match(str(lower.get("id") or ""))
        if whatsapp_id:
            conversation = whatsapp_id.group(2)  # WhatsApp Web ids: ``<fromMe>_<chat jid>_<id>``
    files: list[dict[str, object]] = []
    for key in FILE_LIST_KEYS:
        value = lower.get(key)
        if isinstance(value, str) and value[:1] in ("[", "{"):
            value = _maybe_json(value)
        items = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
        for item in items[:200]:
            if isinstance(item, Mapping):
                found = _file_fields(_lower_map(item))
                if found:
                    files.append(found)
    properties = lower.get("properties")
    if isinstance(properties, str) and properties[:1] == "{":
        properties = _maybe_json(properties)
    if isinstance(properties, Mapping):
        for item in classify_object(properties, max_text_chars=max_text_chars, owner=owner):
            if item.artifact_type == "chat-attachment":
                files.append(item.fields)
    message_like = text_value is not None and (bool(text_value.strip()) or deleted) and bool(iso or sender or conversation)
    if message_like and text_value is not None:
        text, text_format, truncated = clean_message_text(text_value, max_text_chars)
        direction = _direction(lower, owner)
        recipient = _scalar_text(_first(lower, RECIPIENT_KEYS)[1])
        if owner and direction == "incoming" and (not recipient or recipient == sender):
            recipient = owner  # 1:1 partner field names the other side; an incoming message was sent to the owner
        message_id = _scalar_text(_first(lower, MESSAGE_ID_KEYS)[1], limit=200)
        edit_iso = parse_chat_time(_first(lower, EDIT_KEYS)[1])[0]
        fields: dict[str, object] = {
            "timestamp": iso,
            "timestamp_raw": raw_time,
            "timestamp_source": f"field:{time_key}" if time_key else "none-no-message-time",
            "timestamp_kind": "sent" if time_key else "",
            "conversation_id": conversation,
            "conversation_title": _scalar_text(_first(lower, CONVERSATION_TITLE_KEYS)[1]),
            "sender": sender,
            "sender_field": sender_key,
            "recipient": recipient,
            "direction": direction,
            "message_text": text,
            "message_text_preview": text[:240],
            "message_text_sha256": _sha256_text(text) if text else "",
            "message_text_truncated": truncated,
            "message_format": text_format,
            "message_id": message_id,
            "message_type": _scalar_text(_first(lower, MESSAGE_TYPE_KEYS)[1], limit=120),
            "attachment_name": str(files[0]["file_name"]) if files else "",
            "attachment_count": len(files),
            "edited_at": edit_iso,
            "deleted_state": "deleted-in-app" if deleted else "",
            "text_field": text_key,
        }
        candidates.append(Candidate("chat-message", fields))
    if not message_like:
        own_file = _file_fields(lower)
        if own_file:
            files.append(own_file)
    for item in files:
        candidates.append(
            Candidate(
                "chat-attachment",
                {
                    **item,
                    "timestamp": iso,
                    "timestamp_raw": raw_time,
                    "timestamp_source": f"field:{time_key}" if time_key else "none-no-transfer-time",
                    "sender": sender,
                    "recipient": _scalar_text(_first(lower, RECIPIENT_KEYS)[1]),
                    "conversation_id": conversation,
                    "direction": _direction(lower, owner),
                },
            )
        )
    if not message_like and not files:
        contact = _contact_fields(lower)
        if contact:
            candidates.append(Candidate("chat-contact", contact))
    return candidates


def _looks_like_message_table(columns: set[str]) -> bool:
    return bool(columns & set(TEXT_KEYS)) and bool(columns & (set(TIME_KEYS) | set(SENDER_KEYS)))


def _contact_fields(lower: Mapping[str, object]) -> dict[str, object] | None:
    if not CONTACT_STRONG_KEYS.intersection(key for key, value in lower.items() if value not in (None, "", [], {})):
        profile = lower.get("profile")
        if not isinstance(profile, Mapping) or not _email_of(*_lower_map(profile).values()):
            return None
    _name_key, name = _first(lower, CONTACT_NAME_KEYS)
    _id_key, contact_id = _first(lower, CONTACT_ID_KEYS)
    profile = lower.get("profile")
    profile_lower = _lower_map(profile) if isinstance(profile, Mapping) else {}
    email = _email_of(*(lower.get(key) for key in EMAIL_KEYS), *(profile_lower.get(key) for key in EMAIL_KEYS))
    name_text = _scalar_text(name, limit=200) or _scalar_text(profile_lower.get("real_name") or profile_lower.get("display_name"), limit=200)
    id_text = _scalar_text(contact_id, limit=200)
    if not name_text or not (id_text or email):
        return None
    phone = _scalar_text(_first(lower, PHONE_KEYS)[1] or profile_lower.get("phone"), limit=60)
    return {
        "contact_name": name_text,
        "display_name": name_text,
        "contact_id": id_text,
        "email": email,
        "phone": phone,
        "account": email or id_text,
    }


def raw_field_sample(record: Mapping[object, object], limit: int = 24) -> dict[str, object]:
    """Known, non-secret scalar fields of the source object (provenance; values ≤ 200 chars)."""
    sample: dict[str, object] = {}
    for key, value in record.items():
        if len(sample) >= limit:
            break
        if not isinstance(key, str) or _is_secret_key(key) or key.lower() not in _KNOWN_KEYS:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            sample[key] = value[:200] if isinstance(value, str) else value
    return sample


# --- provider ---------------------------------------------------------------------------------


@dataclass
class _AppRun:
    """Per app-root state: rows, dedupe, budgets and counts."""

    spec: AppSpec
    user: str
    root: Path
    limits: MessengerLimits
    owner: str = ""
    rows: list[ArtifactRecord] = field(default_factory=list)
    seen: dict[str, int] = field(default_factory=dict)
    bytes_read: int = 0
    attachment_files: int = 0
    capped: list[str] = field(default_factory=list)
    stores: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    parse_errors: int = 0
    duplicates: int = 0

    def cap(self, reason: str) -> None:
        if reason not in self.capped:
            self.capped.append(reason)

    def can_read(self, size: int) -> bool:
        if self.bytes_read + size > self.limits.max_app_bytes:
            self.cap("app-byte-cap")
            return False
        return True

    def add(self, record: ArtifactRecord, fingerprint: str | None = None) -> bool:
        if fingerprint is not None:
            if fingerprint in self.seen:
                self.duplicates += 1
                index = self.seen[fingerprint]
                details = self.rows[index].details
                details["duplicate_count"] = int(details.get("duplicate_count") or 0) + 1
                return True
        data_rows = sum(self.counts.get(kind, 0) for kind in ("chat-message", "chat-attachment", "chat-contact"))
        if record.artifact_type != "chat-parse-error" and data_rows >= self.limits.max_rows_per_app:
            self.cap("row-cap")
            return False
        if fingerprint is not None:
            self.seen[fingerprint] = len(self.rows)
        self.rows.append(record)
        self.counts[record.artifact_type] = self.counts.get(record.artifact_type, 0) + 1
        return True


class WindowsMessengerProvider:
    name = "windows-messenger"
    collector_kind = "windows-messenger"
    description = "Windows desktop messengers: Teams, Slack, Discord, Telegram Desktop, WhatsApp Desktop, Skype, LINE, WeChat, Zoom"
    target_platform = "windows"

    def __init__(self, limits: MessengerLimits | None = None) -> None:
        self.limits = limits or DEFAULT_LIMITS
        self.collection_notes: list[str] = []
        if limits is not None and limits != DEFAULT_LIMITS:
            self.options_key = "limits:" + hashlib.sha256(repr(dataclasses.astuple(limits)).encode()).hexdigest()[:12]

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        self.collection_notes = []
        found_any = False
        for user_home in iter_windows_user_homes(root):
            for spec in APPS:
                for index, app_root in enumerate(_existing_roots(user_home, spec)):
                    found_any = True
                    # Home-relative stores (Downloads, Documents\Zoom) belong to the user, not to one app root:
                    # read them with the first root only so a second root (Store build) never repeats them.
                    yield from self._collect_app(user_home, spec, app_root, home_stores=index == 0)
        if not found_any:
            self.collection_notes.append(
                "데스크톱 메신저(Teams·Slack·Discord·Telegram·WhatsApp·Skype·LINE·WeChat·Zoom) 앱 폴더가 사용자 프로필에서 발견되지 않았습니다."
            )

    # -- one app root ------------------------------------------------------------------------

    def _collect_app(self, user_home: Path, spec: AppSpec, app_root: Path, *, home_stores: bool = True) -> Iterator[ArtifactRecord]:
        run = _AppRun(spec=spec, user=user_home.name, root=app_root, limits=self.limits)
        inventory = _inventory_counts(app_root, self.limits.max_inventory_files)
        for pattern in spec.sqlite:
            for path in _glob_files(app_root, pattern, self.limits.max_store_files):
                self._guarded(run, path, "sqlite", lambda p=path: self._sqlite_store(run, p))
        for pattern in spec.leveldb:
            for directory in _glob_dirs(app_root, pattern):
                self._guarded(run, directory, "leveldb", lambda d=directory: self._leveldb_store(run, d))
        for pattern in spec.caches:
            for directory in _glob_dirs(app_root, pattern):
                self._guarded(run, directory, "chromium-cache", lambda d=directory: self._cache_store(run, d))
        for pattern in spec.encrypted:
            for path in sorted(app_root.glob(pattern), key=lambda item: str(item).lower())[: self.limits.max_store_files]:
                self._guarded(run, path, "encrypted", lambda p=path: self._encrypted_store(run, p))
        for pattern in spec.file_stores:
            for directory in _glob_dirs(app_root, pattern):
                self._guarded(run, directory, "file-store", lambda d=directory: self._file_store(run, d))
        for parts in spec.home_file_stores if home_stores else ():
            directory = user_home.joinpath(*parts)
            if directory.is_dir():
                self._guarded(run, directory, "file-store", lambda d=directory: self._file_store(run, d, saved_by_user=True))
        for parts in spec.chat_logs if home_stores else ():
            directory = user_home.joinpath(*parts)
            if directory.is_dir():
                self._guarded(run, directory, "text-log", lambda d=directory: self._zoom_chat_logs(run, d))
        yield self._inventory_row(run, user_home, inventory)
        yield from run.rows
        if run.capped:
            self.collection_notes.append(f"{spec.label_ko}({run.user}): 상한 도달 — {', '.join(run.capped)}")

    def _guarded(self, run: _AppRun, path: Path, store_kind: str, action) -> None:
        """Run one store reader; any exception becomes a ``chat-parse-error`` row (the collect continues)."""
        try:
            action()
        except Exception as exc:
            run.parse_errors += 1
            run.stores.append({"path": str(path), "kind": store_kind, "status": "parse-error"})
            run.add(
                ArtifactRecord(
                    provider=self.name,
                    artifact_type="chat-parse-error",
                    path=str(path),
                    supported=True,
                    details={
                        **self._base(run, path, store_kind, recovery_method="none", offset=None),
                        "parser_error": True,
                        "coverage_status": "parser-error",
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:500],
                        "reason_ko": f"{run.spec.label_ko} 저장소를 읽지 못해 건너뜀({type(exc).__name__}); 나머지 저장소는 계속 처리",
                        "timestamp": "",
                        "timestamp_source": "none-parse-error",
                    },
                )
            )

    def _base(self, run: _AppRun, path: Path, source_format: str, *, recovery_method: str, offset: int | None) -> dict[str, object]:
        return {
            "parser": PARSER,
            "parser_version": PARSER_VERSION,
            "service": run.spec.service,
            "app": run.spec.service,
            "app_id": run.spec.app_id,
            "app_label_ko": run.spec.label_ko,
            "user": run.user,
            "recovery_method": recovery_method,
            "source_path": str(path),
            "source_offset": offset,
            "source_format": source_format,
            "store_path": str(path),
            "reportability": "triage",
            "validation_required": True,
        }

    def _emit(self, run: _AppRun, candidate: Candidate, path: Path, source_format: str, *, recovery_method: str,
              offset: int | None, extra: Mapping[str, object] | None = None, raw: Mapping[object, object] | None = None) -> bool:
        details = {
            **self._base(run, path, source_format, recovery_method=recovery_method, offset=offset),
            **candidate.fields,
            **(dict(extra) if extra else {}),
        }
        details.setdefault("deleted_state", "")
        if candidate.artifact_type == "chat-message" and not details.get("deleted_state"):
            details["deleted_state"] = "unknown" if recovery_method == "carved" else "live"
        details["coverage_status"] = "carved-candidate" if recovery_method == "carved" else "mapped"
        details["confidence"] = "low" if recovery_method == "carved" else "medium"
        if raw is not None:
            details["raw_fields"] = raw_field_sample(raw)
        if source_format in ("leveldb-log", "leveldb-table", "leveldb-raw", "chromium-cache"):
            details["store_path"] = str(path.parent)
        fingerprint = _fingerprint(run.spec.app_id, run.user, candidate)
        return run.add(
            ArtifactRecord(provider=self.name, artifact_type=candidate.artifact_type, path=str(path), supported=True, details=details),
            fingerprint,
        )

    # -- LevelDB (IndexedDB / Local Storage) ------------------------------------------------------

    def _leveldb_store(self, run: _AppRun, directory: Path) -> None:
        files = sorted(
            (item for item in directory.iterdir() if item.is_file() and item.suffix.lower() in (".log", ".ldb", ".sst")),
            key=lambda item: item.name.lower(),
        )
        if len(files) > self.limits.max_store_files:
            run.cap("store-file-cap")
            files = files[: self.limits.max_store_files]
        store_entry: dict[str, object] = {"path": str(directory), "kind": "leveldb", "files": len(files), "status": "read"}
        run.stores.append(store_entry)
        deleted_keys: dict[bytes, int] = {}
        pending: list[tuple[Path, str, object]] = []
        for path in files:
            data = self._read_bounded(run, path)
            if data is None:
                continue
            stats = ReadStats()
            source_format = "leveldb-log" if path.suffix.lower() == ".log" else "leveldb-table"
            try:
                reader = iter_log_records(data, stats) if source_format == "leveldb-log" else iter_table_records(data, stats)
                records = list(reader)
            except LevelDBError as exc:
                # Structure unreadable (truncated table, bad footer): record the error, carve the raw bytes.
                self._parse_error(run, path, source_format, exc)
                self._carve_blob(run, path, "leveldb-raw", data, offset=0, deleted=False, extra={"carve_scope": "raw-file-after-parse-error"})
                continue
            for record in records:
                if record.deleted and record.sequence is not None:
                    deleted_keys[record.user_key] = max(record.sequence, deleted_keys.get(record.user_key, -1))
            pending.append((path, source_format, (records, stats)))
        for path, source_format, payload in pending:
            records, stats = payload  # type: ignore[misc]
            if stats.corrupt_fragments or stats.corrupt_blocks:
                store_entry.setdefault("damaged_files", []).append(  # type: ignore[union-attr]
                    {"file": path.name, **{key: value for key, value in stats.as_dict().items() if key != "errors"}}
                )
            for record in records:
                if record.deleted or not record.value:
                    continue
                tombstoned = record.sequence is not None and deleted_keys.get(record.user_key, -1) > record.sequence
                self._carve_blob(
                    run,
                    path,
                    source_format,
                    record.value,
                    offset=record.file_offset,
                    deleted=tombstoned,
                    extra={
                        "leveldb_origin": record.origin,
                        "leveldb_sequence": record.sequence,
                        "leveldb_entry_offset": record.entry_offset,
                        "leveldb_checksum_ok": record.checksum_ok,
                        "leveldb_key_preview": _key_preview(record.user_key),
                    },
                    local_storage=directory.name.lower() == "leveldb" and directory.parent.name.lower() == "local storage",
                )

    def _carve_blob(self, run: _AppRun, path: Path, source_format: str, blob: bytes, *, offset: int | None, deleted: bool,
                    extra: Mapping[str, object], local_storage: bool = False) -> None:
        limits = self.limits
        objects: list[tuple[int, Mapping[object, object], str]] = []
        for position, group in v8_key_objects(blob):
            objects.append((position, group, "v8-key-run"))
        if local_storage:
            text = localstorage_text(blob)
        elif source_format == "chromium-cache" or blob[:1] != b"\xff":
            # HTTP bodies and plain values are UTF-8; V8 (``0xFF`` envelope) one-byte strings are Latin-1.
            text = blob.decode("utf-8", errors="replace")
        else:
            text = blob.decode("latin-1")
        if "\"" in text:
            for position, value in json_fragments(text, max_attempts=limits.max_json_attempts, max_window=limits.max_json_window):
                for record in walk_dicts(value):
                    objects.append((position, record, "json-fragment"))
        for position, record, method in objects:
            for candidate in classify_object(record, max_text_chars=limits.max_text_chars, owner=run.owner):
                if deleted and candidate.artifact_type == "chat-message":
                    candidate.fields["deleted_state"] = "deleted"
                    candidate.fields["deleted_basis"] = "leveldb-tombstone-newer-than-value"
                self._emit(
                    run,
                    candidate,
                    path,
                    source_format,
                    recovery_method="carved",
                    offset=offset,
                    extra={**extra, "carve_method": method, "carve_value_offset": position},
                    raw=record,
                )

    # -- Chromium cache bodies (Discord/Slack API responses) -----------------------------------

    def _cache_store(self, run: _AppRun, directory: Path) -> None:
        files = sorted((item for item in directory.iterdir() if item.is_file()), key=lambda item: item.name.lower())
        if len(files) > self.limits.max_store_files:
            run.cap("store-file-cap")
            files = files[: self.limits.max_store_files]
        run.stores.append({"path": str(directory), "kind": "chromium-cache", "files": len(files), "status": "read"})
        for path in files:
            data = self._read_bounded(run, path)
            if not data:
                continue
            blobs: list[tuple[int, bytes]] = [(0, data)]
            view = memoryview(data)
            start = 0
            while len(blobs) <= MAX_GZIP_MEMBERS_PER_CACHE_FILE:
                position = data.find(GZIP_MAGIC, start)
                if position < 0:
                    break
                try:
                    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    inflated = inflater.decompress(view[position:], self.limits.max_json_window * 4)
                    if inflated:
                        blobs.append((position, inflated))
                except zlib.error:
                    pass
                start = position + 3
            for position, blob in blobs:
                if b"\"" not in blob:
                    continue
                self._carve_blob(run, path, "chromium-cache", blob, offset=position, deleted=False,
                                 extra={"cache_body": "gzip" if position else "raw"})

    # -- SQLite ---------------------------------------------------------------------------------

    def _sqlite_store(self, run: _AppRun, path: Path) -> None:
        header = _read_head(path, 16)
        if header != SQLITE_HEADER:
            self._encrypted_store(run, path)
            return
        provenance: dict[str, object] = {}
        tables_read = 0
        run.owner = ""  # the account owner is per database (one Skype main.db per account)
        with open_sqlite_snapshot(path, provenance=provenance) as connection:
            # Probe the schema outside the helpers (which swallow errors): a damaged DB must become a parse-error row.
            connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
            tables = sqlite_table_names(connection)[: self.limits.max_sqlite_tables]
            lowered = {table.lower(): table for table in tables}
            if "accounts" in lowered:
                owner_row = _select(connection, lowered["accounts"], ("skypename", "fullname"), 1)
                if owner_row:
                    run.owner = str(owner_row[0].get("skypename") or "")
            conversations = {}
            if "conversations" in lowered:
                for item in _select(connection, lowered["conversations"], ("id", "displayname", "identity"), self.limits.max_sqlite_rows):
                    conversations[str(item.get("id"))] = str(item.get("displayname") or item.get("identity") or "")
            profile = chat_app_profile(run.spec.profile_service) or {}
            profile_tables = tuple(str(item) for item in profile.get("message_tables", ()))  # type: ignore[union-attr]
            for table in tables:
                columns = sqlite_columns(connection, table)
                if not columns or not safe_sqlite_identifier(table):
                    continue
                lowered_columns = {column.lower() for column in columns}
                skype_transfer = table.lower() == "transfers" and {"filename", "partner_handle"} <= lowered_columns
                interesting = (
                    skype_transfer
                    or chat_table_is_message_candidate(table, columns, profile_tables)
                    or _looks_like_message_table(lowered_columns)
                    or bool(lowered_columns & set(CONTACT_STRONG_KEYS))
                    or bool(lowered_columns & {"filename", "file_name", "filepath"})
                )
                if not interesting:
                    continue
                tables_read += 1
                rows = _select(connection, table, tuple(columns), self.limits.max_sqlite_rows + 1)
                if len(rows) > self.limits.max_sqlite_rows:
                    run.cap("sqlite-row-cap")
                    rows = rows[: self.limits.max_sqlite_rows]
                for index, row in enumerate(rows):
                    record = dict(row)
                    if table.lower() == "messages" and record.get("body_xml") == "" and record.get("edited_timestamp"):
                        record["deleted"] = True  # Skype empties body_xml and stamps edited_timestamp on delete
                    if skype_transfer:
                        transfer_type = str(record.get("type") or "")
                        record["outgoing"] = {"1": False, "2": True}.get(transfer_type)
                        record.setdefault("to", record.get("partner_handle"))
                    for candidate in classify_object(record, max_text_chars=self.limits.max_text_chars, owner=run.owner):
                        if skype_transfer and candidate.artifact_type == "chat-attachment":
                            candidate.fields["recipient"] = str(record.get("partner_handle") or "")
                            candidate.fields["transfer_status"] = str(record.get("status") or "")
                            start_iso = parse_chat_time(record.get("starttime"))[0]
                            if start_iso:
                                candidate.fields.update({"timestamp": start_iso, "timestamp_source": "field:starttime"})
                        if conversations and candidate.artifact_type in ("chat-message", "chat-attachment"):
                            title = conversations.get(str(record.get("convo_id")))
                            if title:
                                candidate.fields["conversation_title"] = title
                        self._emit(
                            run,
                            candidate,
                            path,
                            "sqlite",
                            recovery_method="sqlite-table",
                            offset=None,
                            extra={
                                "source_table": table,
                                "source_row": index,
                                "sqlite_snapshot": provenance.get("profile_version", ""),
                                **({"contact_role": "account-owner"} if table.lower() == "accounts" else {}),
                            },
                            raw=record,
                        )
        run.stores.append(
            {"path": str(path), "kind": "sqlite", "encryption_state": "plaintext-sqlite", "tables": len(tables), "tables_read": tables_read, "status": "read"}
        )

    # -- inventory-only stores --------------------------------------------------------------------

    def _encrypted_store(self, run: _AppRun, path: Path) -> None:
        if path.is_dir():
            count, total, truncated = 0, 0, False
            names: set[str] = set()
            for file_path in _walk_files(path, self.limits.max_inventory_files):
                count += 1
                try:
                    total += file_path.stat().st_size
                except OSError:
                    continue
                if file_path.parent == path:
                    names.add(file_path.name)
            if count >= self.limits.max_inventory_files:
                truncated = True
            account_dirs = sorted(
                item.name for item in path.iterdir() if item.is_dir() and re.fullmatch(r"[0-9A-F]{16}", item.name)
            )[:20]
            run.stores.append(
                {
                    "path": str(path),
                    "kind": "encrypted-directory",
                    "encryption_state": run.spec.encryption_state,
                    "files": count,
                    "bytes": total,
                    "files_truncated": truncated,
                    "key_file_present": "key_datas" in names,
                    "account_dir_candidates": account_dirs,
                    "status": "inventory-only",
                }
            )
            return
        header = _read_head(path, 16)
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        state = "plaintext-sqlite" if header == SQLITE_HEADER else (
            "encrypted-sqlcipher" if run.spec.encryption_state == "encrypted-sqlcipher" else "encrypted-or-unknown"
        )
        if not header:
            state = "empty"
        run.stores.append(
            {
                "path": str(path),
                "kind": "database",
                "encryption_state": state,
                "bytes": size,
                "header_hex": header[:16].hex(),
                "sha256": _bounded_sha256(path, self.limits.max_hash_bytes),
                "status": "inventory-only",
            }
        )

    def _file_store(self, run: _AppRun, directory: Path, *, saved_by_user: bool = False) -> None:
        listed = 0
        for path in _walk_files(directory, self.limits.max_inventory_files):
            if run.attachment_files >= self.limits.max_attachment_files:
                run.cap("attachment-file-cap")
                break
            run.attachment_files += 1
            listed += 1
            try:
                stat_result = path.stat()
            except OSError:
                continue
            signature = _signature(_read_head(path, 16))
            cache_entry = "user_data" in {part.lower() for part in path.parts}
            if cache_entry and signature == "unknown":
                # Telegram cache entries are encrypted: counted on the store, not listed as attachments.
                continue
            candidate = Candidate(
                "chat-attachment",
                {
                    "file_name": path.name,
                    "attachment_name": path.name,
                    "file_size": stat_result.st_size,
                    "file_path": str(path),
                    "url": "",
                    "mime_type": "",
                    "signature_type": signature,
                    "sha256": _bounded_sha256(path, self.limits.max_hash_bytes),
                    "direction": "incoming" if saved_by_user else "unknown",
                    "direction_basis": "saved-to-downloads-by-app" if saved_by_user else "app-file-store-mixed-sent-and-received",
                    "sender": "",
                    "recipient": "",
                    "conversation_id": "",
                    "timestamp": "",
                    "timestamp_source": "none-file-store-mtime-is-not-transfer-time",
                    "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
                },
            )
            self._emit(run, candidate, path, "file", recovery_method="app-file-store", offset=None)
        run.stores.append({"path": str(directory), "kind": "file-store", "files": listed, "status": "read"})

    def _zoom_chat_logs(self, run: _AppRun, directory: Path) -> None:
        logs = [
            path
            for path in _walk_files(directory, self.limits.max_inventory_files)
            if path.name.lower() in ("meeting_saved_chat.txt", "chat.txt")
        ][: self.limits.max_store_files]
        for path in logs:
            data = self._read_bounded(run, path)
            if data is None:
                continue
            text = data.decode("utf-8-sig", errors="replace")
            meeting_date = _zoom_folder_date(path.parent.name)
            for message in parse_zoom_chat_log(text):
                local_time = f"{meeting_date}T{message['time']}" if meeting_date else message["time"]
                body, _fmt, truncated = clean_message_text(message["text"], self.limits.max_text_chars)
                sender = message["sender"]
                candidate = Candidate(
                    "chat-message",
                    {
                        # Saved chat logs carry local wall-clock time without an offset: never stored as an instant.
                        "timestamp": "",
                        "local_timestamp": local_time,
                        "timestamp_source": "zoom-chat-log-local-time-no-offset",
                        "timezone": "local-unknown",
                        "conversation_id": path.parent.name,
                        "conversation_title": path.parent.name,
                        "sender": sender,
                        "recipient": message["recipient"],
                        "direction": "outgoing" if sender.lower() in ("me", "나") else "unknown",
                        "message_text": body,
                        "message_text_preview": body[:240],
                        "message_text_sha256": _sha256_text(body) if body else "",
                        "message_text_truncated": truncated,
                        "message_format": "text",
                        "message_id": f"line-{message['line']}",
                        "message_type": "zoom-meeting-chat",
                        "attachment_name": "",
                        "attachment_count": 0,
                        "edited_at": "",
                        "deleted_state": "live",
                    },
                )
                self._emit(run, candidate, path, "text", recovery_method="text-log", offset=message["offset"], extra={"source_line": message["line"]})
            run.stores.append({"path": str(path), "kind": "zoom-chat-log", "status": "read"})

    # -- helpers ------------------------------------------------------------------------------------

    def _read_bounded(self, run: _AppRun, path: Path) -> bytes | None:
        try:
            size = path.stat().st_size
        except OSError:
            return None
        to_read = min(size, self.limits.max_file_bytes)
        if size > self.limits.max_file_bytes:
            run.cap("file-byte-cap")
        if not run.can_read(to_read):
            return None
        with path.open("rb") as handle:
            data = handle.read(to_read)
        run.bytes_read += len(data)
        return data

    def _parse_error(self, run: _AppRun, path: Path, source_format: str, exc: BaseException) -> None:
        run.parse_errors += 1
        run.add(
            ArtifactRecord(
                provider=self.name,
                artifact_type="chat-parse-error",
                path=str(path),
                supported=True,
                details={
                    **self._base(run, path, source_format, recovery_method="none", offset=None),
                    "parser_error": True,
                    "coverage_status": "parser-error",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                    "reason_ko": "LevelDB 구조가 손상되어 레코드 단위로 읽지 못함 — 원시 바이트에서 문자열 후보만 복구",
                    "timestamp": "",
                    "timestamp_source": "none-parse-error",
                },
            )
        )

    def _inventory_row(self, run: _AppRun, user_home: Path, inventory: Mapping[str, object]) -> ArtifactRecord:
        spec = run.spec
        message_rows = run.counts.get("chat-message", 0)
        encrypted_stores = [store for store in run.stores if str(store.get("status")) == "inventory-only"]
        inventory_only = message_rows == 0
        if inventory_only and spec.inventory_reason_ko:
            reason = spec.inventory_reason_ko
        elif inventory_only:
            reason = f"{spec.label_ko}: 앱 폴더는 있으나 읽을 수 있는 메시지 후보가 없습니다(저장소 없음·비어 있음·미지원 구조)."
        else:
            reason = ""
        versions = _app_versions(user_home, spec)
        details = {
            **self._base(run, run.root, "directory", recovery_method="filesystem-inventory", offset=None),
            "store_path": str(run.root),
            "app_root": str(run.root),
            "present": True,
            "app_version": versions[0] if versions else "",
            "app_version_candidates": versions,
            "app_version_source": "app-x.y.z-folder" if versions else "",
            "encryption_state": spec.encryption_state,
            "file_count": inventory["file_count"],
            "total_bytes": inventory["total_bytes"],
            "files_truncated": inventory["truncated"],
            "last_file_modified": inventory["last_modified"],
            "last_file_modified_source": "max-file-mtime-in-app-folder (acquisition copies may reset it)",
            "stores": run.stores[: self.limits.max_store_list],
            "store_count": len(run.stores),
            "encrypted_store_count": len(encrypted_stores),
            "message_rows": message_rows,
            "attachment_rows": run.counts.get("chat-attachment", 0),
            "contact_rows": run.counts.get("chat-contact", 0),
            "parse_error_count": run.parse_errors,
            "duplicate_candidates_merged": run.duplicates,
            "bytes_read": run.bytes_read,
            "caps_hit": list(run.capped),
            "inventory_only": inventory_only,
            "reason_ko": reason,
            "coverage_status": "inventory-only" if inventory_only else "rows-recovered",
            "timestamp": "",
            "timestamp_source": "none-inventory-row",
        }
        return ArtifactRecord(provider=self.name, artifact_type="chat-app-inventory", path=str(run.root), supported=True, details=details)


# --- module helpers ----------------------------------------------------------------------------------


def _existing_roots(user_home: Path, spec: AppSpec) -> list[Path]:
    roots: list[Path] = []
    for parts in spec.roots:
        candidate = user_home.joinpath(*parts)
        try:
            if candidate.is_dir():
                roots.append(candidate)
        except OSError:
            continue
    return roots


def _glob_dirs(root: Path, pattern: str) -> list[Path]:
    try:
        return sorted((item for item in root.glob(pattern) if item.is_dir()), key=lambda item: str(item).lower())
    except OSError:
        return []


def _glob_files(root: Path, pattern: str, limit: int) -> list[Path]:
    try:
        return sorted((item for item in root.glob(pattern) if item.is_file()), key=lambda item: str(item).lower())[:limit]
    except OSError:
        return []


def _walk_files(root: Path, limit: int) -> Iterator[Path]:
    count = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort(key=str.lower)
        for name in sorted(filenames, key=str.lower):
            yield Path(directory) / name
            count += 1
            if count >= limit:
                return


def _inventory_counts(root: Path, limit: int) -> dict[str, object]:
    count, total, latest = 0, 0, 0.0
    for path in _walk_files(root, limit):
        count += 1
        try:
            stat_result = path.stat()
        except OSError:
            continue
        total += stat_result.st_size
        latest = max(latest, stat_result.st_mtime)
    return {
        "file_count": count,
        "total_bytes": total,
        "truncated": count >= limit,
        "last_modified": isoformat_from_timestamp(latest) if latest else "",
    }


def _app_versions(user_home: Path, spec: AppSpec) -> list[str]:
    versions: list[str] = []
    for parts in spec.version_dirs:
        directory = user_home.joinpath(*parts)
        try:
            children = list(directory.iterdir()) if directory.is_dir() else []
        except OSError:
            children = []
        for child in children:
            match = _APP_VERSION_RE.match(child.name)
            if match and child.is_dir():
                versions.append(match.group(1))
    return sorted(set(versions), key=lambda value: tuple(int(part) for part in value.split(".")), reverse=True)


def _read_head(path: Path, size: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def _bounded_sha256(path: Path, limit: int) -> str:
    try:
        if path.stat().st_size > limit:
            return ""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip-or-office"),
    (b"\xd0\xcf\x11\xe0", "ole-office"),
    (b"RIFF", "riff"),
    (b"\x1aE\xdf\xa3", "webm-mkv"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"7z\xbc\xaf", "7z"),
    (b"Rar!", "rar"),
    (b"MZ", "pe-executable"),
)


def _signature(head: bytes) -> str:
    for magic, name in _SIGNATURES:
        if head.startswith(magic):
            return name
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "mp4-or-heic"
    return "unknown"


def _key_preview(key: bytes) -> str:
    text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in key[:80])
    return text


def _fingerprint(app_id: str, user: str, candidate: Candidate) -> str:
    fields = candidate.fields
    if candidate.artifact_type == "chat-message":
        parts = (fields.get("conversation_id"), fields.get("timestamp") or fields.get("local_timestamp"), fields.get("sender"),
                 fields.get("message_text_sha256"), fields.get("message_id") if fields.get("message_type") == "zoom-meeting-chat" else "")
    elif candidate.artifact_type == "chat-attachment":
        parts = (fields.get("file_name"), fields.get("file_size"), fields.get("url"), fields.get("file_path"))
    else:
        parts = (fields.get("contact_id"), fields.get("email"), fields.get("contact_name"))
    material = json.dumps([app_id, user, candidate.artifact_type, *[str(item or "") for item in parts]], ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _select(connection: sqlite3.Connection, table: str, columns: tuple[str, ...], limit: int) -> list[dict[str, object]]:
    if not safe_sqlite_identifier(table):
        return []
    available = {column.lower(): column for column in sqlite_columns(connection, table)}
    chosen = [available[column.lower()] for column in columns if column.lower() in available and safe_sqlite_identifier(available[column.lower()])]
    if not chosen:
        return []
    quoted = ", ".join(f'"{column}"' for column in chosen)
    try:
        cursor = connection.execute(f'SELECT {quoted} FROM "{table}" LIMIT ?', (int(limit),))
        rows = cursor.fetchall()
    except sqlite3.Error:
        return []
    out: list[dict[str, object]] = []
    for row in rows:
        record: dict[str, object] = {}
        for column, value in zip(chosen, row):
            if isinstance(value, bytes):
                continue  # BLOBs (thumbnails, encrypted columns) are not message text
            record[column] = value
        out.append(record)
    return out


_ZOOM_FOLDER_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_ZOOM_NEW = re.compile(r"^(\d{1,2}:\d{2}:\d{2})\s+From\s+(.+?)\s+[Tt]o\s+(.+?)\s*:\s*(.*)$")
_ZOOM_OLD = re.compile(r"^(\d{1,2}:\d{2}:\d{2})\s+From\s+(.+?)\s*:\s?(.*)$")


def _zoom_folder_date(name: str) -> str:
    match = _ZOOM_FOLDER_DATE.match(name)
    return match.group(1) if match else ""


def parse_zoom_chat_log(text: str, *, max_messages: int = 20_000) -> list[dict[str, object]]:
    """Zoom saved meeting chat: ``HH:MM:SS From A to B:`` + tab-indented body lines, or the older ``HH:MM:SS From A : body``."""
    messages: list[dict[str, object]] = []
    offset = 0
    current: dict[str, object] | None = None
    for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
        stripped = line.rstrip("\r\n")
        match = _ZOOM_NEW.match(stripped.strip())
        if match:
            current = {"time": match.group(1).zfill(8), "sender": match.group(2).strip(), "recipient": match.group(3).strip(),
                       "text": match.group(4).strip(), "line": line_number, "offset": offset}
            messages.append(current)
        else:
            old = _ZOOM_OLD.match(stripped.strip())
            if old:
                current = {"time": old.group(1).zfill(8), "sender": old.group(2).strip(), "recipient": "",
                           "text": old.group(3).strip(), "line": line_number, "offset": offset}
                messages.append(current)
            elif current is not None and stripped[:1] in ("\t", " ") and stripped.strip():
                current["text"] = (str(current["text"]) + "\n" + stripped.strip()).strip()
        offset += len(line.encode("utf-8"))
        if len(messages) >= max_messages:
            break
    return [message for message in messages if str(message["text"]).strip()]


__all__ = [
    "APPS",
    "DEFAULT_LIMITS",
    "MessengerLimits",
    "WindowsMessengerProvider",
    "classify_object",
    "decode_v8_value",
    "json_fragments",
    "parse_chat_time",
    "parse_zoom_chat_log",
    "v8_key_objects",
]
