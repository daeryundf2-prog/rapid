"""KakaoTalk PC message rows, app inventory and shared-picture rows (plan r2 §3.2 M2).

Runs inside the ``kakaotalk-windows`` provider. Decryption only uses key material the
parser already recovers from the evidence (registry ``DeviceInfo`` + user-id candidates,
stored pragma values, PK strings in collected memory dumps) or that the operator supplies
through the ``RAPIDTRIAGE_KAKAO_*`` environment variables of ``kakaotalk-decrypt``. There is
no password cracking and no key search: every candidate is a deterministic derivation of
recovered material, validated by the SQLite header of the first page.

Legacy (pre-2025-08) chat databases are SQLite pages encrypted with AES-128-CBC per 4 KiB
page (same key and IV for every page). Post-patch SQLCipher stores need a runtime key and
are reported as ``kakaotalk-app-inventory`` with the reason.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..core.aes_cbc import aes_cbc_decrypt, aes_cbc_encrypt, decrypt_round_keys
from ..core.kakaotalk import (
    CHATLOG_PATTERN,
    DEVICEINFO_FIELDS,
    KAKAOTALK_DEVICE_PRAGMA_KEY_HEX,
    build_candidate_key_materials_from_pk_candidates,
    build_candidate_key_materials_from_pragma_candidates,
    classify_kakaotalk_attachment,
    expand_kakaotalk_attachment_items,
    extract_deviceinfo_from_native_hive,
    extract_stored_pragma_candidates_from_native_hive,
    extract_stored_pragma_candidates_from_reg_export,
    extract_user_id_candidates_from_native_hive,
    extract_user_id_candidates_from_reg_export,
    first_attachment_scalar,
    kakao_attachment_basenames,
    kakao_attachment_checksums,
    kakao_attachment_display_name,
    pkcs7_pad,
    scan_pk_candidates_from_file,
)
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from ._walk import iter_evidence_paths

PARSER_VERSION = "kakaotalk-windows-messages-v1"
PROVIDER_NAME = "kakaotalk-windows-correlation"
SQLITE_HEADER = b"SQLite format 3\x00"
PAGE_SIZE = 4096
# Bounds (plan §3 common rules): candidate keys, decrypted bytes, rows.
KEY_CANDIDATE_LIMIT = 512
USER_ID_LIMIT = 20
PK_SCAN_FILE_LIMIT = 2
PURE_PYTHON_DECRYPT_LIMIT = 32 * 1024 * 1024
OPENSSL_DECRYPT_LIMIT = 1024 * 1024 * 1024
OPENSSL_CHUNK = 16 * 1024 * 1024
MESSAGE_ROW_LIMIT = 100_000
MESSAGE_TEXT_LIMIT = 4000
PREVIEW_LIMIT = 300
PICTURE_ROW_LIMIT = 20_000
PICTURE_HASH_LIMIT = 64 * 1024 * 1024
INVENTORY_DB_LIST_LIMIT = 50
DELETED_TYPE_FLAG = 0x4000

PICTURE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".mp4", ".mov", ".m4v", ".cng"}
# "KakaoTalk_20250131_203825506_01.jpg": PC "save"/download name = local save time (ms) + sequence.
SAVED_NAME_RE = re.compile(
    r"^KakaoTalk_(?P<date>\d{8})_(?P<time>\d{6})(?P<ms>\d{3})?(?:_(?P<seq>\d{1,3}))?\.[A-Za-z0-9]+$",
    re.IGNORECASE,
)
RECEIVED_FOLDER_NAMES = {"카카오톡 받은 파일", "kakaotalk downloads", "kakaotalk received files"}
MAGIC_MIME = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG", "image/png"),
    (b"GIF8", "image/gif"),
    (b"BM", "image/bmp"),
)
STATUS_LABELS = {
    "decrypted": "복호 완료",
    "no-chat-database": "대화 DB 없음",
    "no-key-material": "복호 키 없음",
    "key-mismatch": "복호 키 없음",
    "size-cap": "크기 상한 초과",
    "error": "복호 오류",
}
TABLE_HINTS = ("chatlogs", "chat_logs", "chatlog", "messages", "message")
COLUMN_HINTS: dict[str, tuple[str, ...]] = {
    "id": ("logid", "log_id", "msgid", "msg_id", "id", "_id"),
    "chat": ("chatid", "chat_id", "roomid", "room_id"),
    "author": ("authorid", "author_id", "userid", "user_id", "sender", "senderid"),
    "type": ("type", "msgtype", "message_type"),
    "time": ("sendat", "send_at", "created_at", "createdat", "timestamp", "sent_at"),
    "text": ("message", "msg", "text", "body", "content"),
    "attachment": ("attachement", "attachment", "attachments"),
    "deleted": ("deleted", "isdeleted", "is_deleted", "deletedat", "deleted_at"),
}


@dataclass
class KeyMaterial:
    """Recovered key material (values stay in memory; rows only carry counts and hashes)."""

    user_ids: list[str] = field(default_factory=list)
    stored_pragmas: list[dict[str, str]] = field(default_factory=list)
    deviceinfo: dict[str, str] = field(default_factory=dict)
    pk_candidates: list[dict[str, object]] = field(default_factory=list)
    sources: list[Path] = field(default_factory=list)
    operator_supplied: bool = False
    candidates: list[dict[str, object]] = field(default_factory=list)

    def public_summary(self) -> dict[str, object]:
        return {
            "user_id_candidate_count": len(self.user_ids),
            "user_id_hashes": sorted({sha256_text(value) for value in self.user_ids})[:10],
            "deviceinfo_fields_present": sorted(self.deviceinfo),
            "stored_pragma_candidate_count": len(self.stored_pragmas),
            "pk_candidate_count": len(self.pk_candidates),
            "operator_supplied": self.operator_supplied,
            "key_candidate_count": len(self.candidates),
            "values_redacted": True,
        }


@dataclass
class DatabaseResult:
    path: Path
    status: str
    reason: str = ""
    messages: list[dict[str, object]] = field(default_factory=list)
    matched: Mapping[str, object] | None = None
    decrypted_sha256: str = ""
    tried: int = 0
    truncated: bool = False


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


# --- key material -------------------------------------------------------------------


def derive_deviceinfo_pragmas(deviceinfo: Mapping[str, str], *, pragma_key: bytes | None = None) -> list[dict[str, str]]:
    """Same pragma variants as ``core.kakaotalk.derive_pragma_candidates_from_deviceinfo`` (pure-Python AES)."""
    if not all(deviceinfo.get(name) for name in DEVICEINFO_FIELDS):
        return []
    key = pragma_key if pragma_key is not None else bytes.fromhex(KAKAOTALK_DEVICE_PRAGMA_KEY_HEX)
    prefix = "" if pragma_key is not None else "builtin-deviceinfo-key-"
    sys_uuid, hdd_model, hdd_serial = (deviceinfo[name] for name in DEVICEINFO_FIELDS)
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    for seed_name, seed in (
        ("pipe", f"{sys_uuid}|{hdd_model}|{hdd_serial}".encode()),
        ("concat", f"{sys_uuid}{hdd_model}{hdd_serial}".encode()),
    ):
        payloads = [(f"{seed_name}-pkcs7", pkcs7_pad(seed, 16))]
        if len(seed) % 16 == 0:
            payloads.append((f"{seed_name}-nopad", seed))
        for payload_name, payload in payloads:
            encrypted = aes_cbc_encrypt(key, bytes(16), payload)
            encrypted_b64 = base64.b64encode(encrypted)
            for variant, pragma in (
                (f"{payload_name}-aes-ciphertext-base64", encrypted_b64.decode("ascii")),
                (f"{payload_name}-sha512-ciphertext-base64", base64.b64encode(hashlib.sha512(encrypted).digest()).decode("ascii")),
                (
                    f"{payload_name}-sha512-base64-ciphertext-base64",
                    base64.b64encode(hashlib.sha512(encrypted_b64).digest()).decode("ascii"),
                ),
            ):
                if pragma not in seen:
                    seen.add(pragma)
                    candidates.append({"variant": prefix + variant, "pragma": pragma})
    return candidates


def read_reg_export_deviceinfo(path: Path) -> dict[str, str]:
    from .kakaotalk_windows import extract_deviceinfo_values, read_registry_export_lines

    return extract_deviceinfo_values(read_registry_export_lines(path))


def gather_key_material(
    registry_paths: Sequence[Path],
    memory_paths: Sequence[Path],
    *,
    environ: Mapping[str, str] | None = None,
) -> KeyMaterial:
    env = os.environ if environ is None else environ
    material = KeyMaterial()
    user_ids: list[str] = []
    pragmas: list[dict[str, str]] = []
    for path in registry_paths:
        is_export = path.suffix.lower() == ".reg"
        if not is_export and path.name.upper() != "NTUSER.DAT":
            continue  # KakaoTalk keys live under HKCU.
        try:
            ids = extract_user_id_candidates_from_reg_export(path) if is_export else extract_user_id_candidates_from_native_hive(path)
            stored = (
                extract_stored_pragma_candidates_from_reg_export(path)
                if is_export
                else extract_stored_pragma_candidates_from_native_hive(path)
            )
            deviceinfo = read_reg_export_deviceinfo(path) if is_export else extract_deviceinfo_from_native_hive(path)
        except (OSError, ValueError, UnicodeError):
            continue
        if ids or stored or deviceinfo:
            material.sources.append(path)
        user_ids.extend(str(item.get("value") or "").strip() for item in ids)
        pragmas.extend(
            {"variant": str(item.get("variant") or "stored-pragma"), "pragma": str(item.get("value") or "").strip()}
            for item in stored
        )
        if all(deviceinfo.get(name) for name in DEVICEINFO_FIELDS):
            if not material.deviceinfo:
                material.deviceinfo = {name: str(deviceinfo[name]) for name in DEVICEINFO_FIELDS}
            pragmas.extend(derive_deviceinfo_pragmas(deviceinfo))
    operator_user = str(env.get("RAPIDTRIAGE_KAKAO_USER_ID") or "").strip()
    if operator_user:
        user_ids.insert(0, operator_user)
    operator_pragma = str(env.get("RAPIDTRIAGE_KAKAO_PRAGMA") or "").strip()
    if operator_pragma:
        pragmas.insert(0, {"variant": "operator-pragma", "pragma": operator_pragma})
    material.user_ids = list(dict.fromkeys(value for value in user_ids if value))[:USER_ID_LIMIT]
    material.stored_pragmas = [item for item in pragmas if item["variant"].startswith(("registry-", "stored"))]
    candidates: list[dict[str, object]] = []
    key_hex = str(env.get("RAPIDTRIAGE_KAKAO_KEY_HEX") or "").strip()
    iv_hex = str(env.get("RAPIDTRIAGE_KAKAO_IV_HEX") or "").strip()
    if key_hex and iv_hex:
        try:
            key, iv = bytes.fromhex(key_hex), bytes.fromhex(iv_hex)
        except ValueError:
            key = iv = b""
        if len(key) == 16 and len(iv) == 16:
            candidates.append(
                {"key": key, "iv": iv, "source": "operator-key-iv", "user_id_sha256": "", "pragma_variant": "", "key_derivation": "direct-key-iv"}
            )
    material.operator_supplied = bool(operator_user or operator_pragma or candidates)
    unique_pragmas = list({item["pragma"]: item for item in pragmas if item["pragma"]}.values())
    if unique_pragmas and material.user_ids:
        candidates.extend(build_candidate_key_materials_from_pragma_candidates(unique_pragmas, material.user_ids))
    for path in list(memory_paths)[:PK_SCAN_FILE_LIMIT]:
        material.pk_candidates.extend(scan_pk_candidates_from_file(path))
    candidates.extend(build_candidate_key_materials_from_pk_candidates(material.pk_candidates))
    material.candidates = candidates[:KEY_CANDIDATE_LIMIT]
    return material


# --- decryption ---------------------------------------------------------------------


def first_block_matches(first_block: bytes, key: bytes, iv: bytes) -> bool:
    return len(first_block) == 16 and aes_cbc_decrypt(key, iv, first_block) == SQLITE_HEADER


def find_matching_key(path: Path, candidates: Sequence[Mapping[str, object]]) -> Mapping[str, object] | None:
    try:
        with path.open("rb") as handle:
            first_block = handle.read(16)
    except OSError:
        return None
    for candidate in candidates:
        key, iv = candidate.get("key"), candidate.get("iv")
        if isinstance(key, bytes) and isinstance(iv, bytes) and first_block_matches(first_block, key, iv):
            return candidate
    return None


def openssl_binary() -> str | None:
    return shutil.which("openssl")


def decrypt_pages_to_file(path: Path, key: bytes, iv: bytes, destination: Path, *, openssl_bin: str | None) -> str:
    """Decrypt every 4 KiB page into ``destination``; returns the plaintext SHA-256."""
    digest = hashlib.sha256()
    round_keys = decrypt_round_keys(key)
    iv_int = int.from_bytes(iv, "big")
    chunk_size = OPENSSL_CHUNK if openssl_bin else PAGE_SIZE * 64
    with path.open("rb") as source, destination.open("wb") as target:
        while True:
            chunk = source.read(chunk_size)
            if not chunk:
                break
            usable = len(chunk) - len(chunk) % 16
            chunk = chunk[:usable]
            if not chunk:
                break
            if openssl_bin:
                plain = bytearray(openssl_cbc_decrypt(chunk, key, iv, openssl_bin))
                # One CBC chain over the chunk: re-key every page start to the fixed IV
                # (P = D(C) ^ C_prev  ->  D(C) ^ IV).
                for offset in range(PAGE_SIZE, len(chunk), PAGE_SIZE):
                    previous = int.from_bytes(chunk[offset - 16 : offset], "big")
                    fixed = int.from_bytes(plain[offset : offset + 16], "big") ^ previous ^ iv_int
                    plain[offset : offset + 16] = fixed.to_bytes(16, "big")
                output = bytes(plain)
            else:
                output = b"".join(
                    aes_cbc_decrypt(key, iv, chunk[offset : offset + PAGE_SIZE], round_keys=round_keys)
                    for offset in range(0, len(chunk), PAGE_SIZE)
                )
            digest.update(output)
            target.write(output)
    return digest.hexdigest()


def openssl_cbc_decrypt(data: bytes, key: bytes, iv: bytes, openssl_bin: str) -> bytes:
    completed = subprocess.run(
        [openssl_bin, "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nopad"],
        input=data,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode != 0 or len(completed.stdout) != len(data):
        raise OSError("openssl AES-128-CBC 복호 실패")
    return completed.stdout


def decrypt_chat_database(path: Path, material: KeyMaterial, *, remaining_rows: int) -> DatabaseResult:
    if not material.candidates:
        return DatabaseResult(path, "no-key-material")
    matched = find_matching_key(path, material.candidates)
    if matched is None:
        return DatabaseResult(path, "key-mismatch", tried=len(material.candidates))
    try:
        size = path.stat().st_size
    except OSError as exc:
        return DatabaseResult(path, "error", reason=str(exc), matched=matched)
    openssl_bin = openssl_binary()
    limit = OPENSSL_DECRYPT_LIMIT if openssl_bin else PURE_PYTHON_DECRYPT_LIMIT
    if size > limit:
        return DatabaseResult(path, "size-cap", matched=matched, reason=f"{size} > {limit} bytes")
    handle, temp_name = tempfile.mkstemp(prefix="rt-kakao-", suffix=".sqlite")
    os.close(handle)
    temp_path = Path(temp_name)
    try:
        plain_sha256 = decrypt_pages_to_file(path, matched["key"], matched["iv"], temp_path, openssl_bin=openssl_bin)  # type: ignore[arg-type]
        messages, truncated = read_chat_messages(temp_path, remaining_rows=remaining_rows)
    except (OSError, sqlite3.DatabaseError, subprocess.SubprocessError, ValueError) as exc:
        return DatabaseResult(path, "error", reason=str(exc)[:300], matched=matched)
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass
    return DatabaseResult(path, "decrypted", messages=messages, matched=matched, decrypted_sha256=plain_sha256, truncated=truncated)


# --- decrypted SQLite -> message dicts -------------------------------------------------


def pick_column(columns: Sequence[str], role: str) -> str:
    lowered = {column.lower(): column for column in columns}
    for hint in COLUMN_HINTS[role]:
        if hint in lowered:
            return lowered[hint]
    return ""


def pick_message_table(connection: sqlite3.Connection) -> tuple[str, list[str]]:
    tables = [str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    ranked = sorted(
        tables,
        key=lambda name: next((index for index, hint in enumerate(TABLE_HINTS) if hint == name.lower()), len(TABLE_HINTS)),
    )
    for table in ranked:
        columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({quote(table)})")]
        if pick_column(columns, "text") and (pick_column(columns, "time") or pick_column(columns, "author")):
            return table, columns
    return "", []


def quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def epoch_to_iso(value: object) -> str:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value or "")
    if number <= 0:
        return ""
    if number > 1e14:
        number /= 1_000_000
    elif number > 1e11:
        number /= 1000
    try:
        return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return ""


def read_chat_messages(sqlite_path: Path, *, remaining_rows: int) -> tuple[list[dict[str, object]], bool]:
    connection = sqlite3.connect(f"{sqlite_path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
    try:
        table, columns = pick_message_table(connection)
        if not table:
            return [], False
        mapping = {role: pick_column(columns, role) for role in COLUMN_HINTS}
        selected = ["rowid", *dict.fromkeys(column for column in mapping.values() if column)]
        order = mapping["time"] or "rowid"
        sql = f"SELECT {', '.join(quote(c) if c != 'rowid' else c for c in selected)} FROM {quote(table)} ORDER BY {quote(order) if order != 'rowid' else order}, rowid LIMIT ?"
        rows = connection.execute(sql, (max(remaining_rows, 0) + 1,)).fetchall()
    finally:
        connection.close()
    truncated = len(rows) > remaining_rows
    messages: list[dict[str, object]] = []
    for values in rows[:remaining_rows]:
        record = dict(zip(selected, values))
        messages.append({"table": table, **{role: record.get(column) for role, column in mapping.items() if column}, "rowid": record["rowid"]})
    return messages, truncated


def message_attachments(raw: object, message_type: int) -> list[dict[str, object]]:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw or "")
    if text.strip() in ("", "{}", "[]", "null"):
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return [{"parse_error": True, "attachment_json_sha256": sha256_text(text)}]
    items = parsed if isinstance(parsed, list) else [parsed]
    out: list[dict[str, object]] = []
    for entry in items:
        if not isinstance(entry, Mapping):
            continue
        for item in expand_kakaotalk_attachment_items(entry):
            out.append(
                {
                    "name": kakao_attachment_display_name(item),
                    "media_class": classify_kakaotalk_attachment(message_type, item),
                    "mime": str(first_attachment_scalar(item, "mt", "mime", "contentType") or ""),
                    "declared_size": first_attachment_scalar(item, "size", "s", "sl"),
                    "checksums": kakao_attachment_checksums(item),
                    "basenames": kakao_attachment_basenames(item)[:10],
                }
            )
    return out[:50]


def deleted_state(message: Mapping[str, object], message_type: int) -> str:
    flag = message.get("deleted")
    if flag not in (None, "", 0, "0", False):
        return "deleted"
    if message_type >= DELETED_TYPE_FLAG:
        return "확인 필요(type ≥ 16384 표식)"
    return ""


# --- shared pictures -----------------------------------------------------------------


def classify_picture(path: Path) -> str:
    """``saved-file`` (KakaoTalk_<time>.ext), ``received-folder`` or ``app-cache``; "" = not a KakaoTalk picture."""
    if path.suffix.lower() not in PICTURE_SUFFIXES:
        return ""
    if SAVED_NAME_RE.match(path.name):
        return "saved-file"
    parents = [part.lower() for part in path.parent.parts]
    if any(part in RECEIVED_FOLDER_NAMES for part in parents):
        return "received-folder"
    if "appdata" in parents and any("kakaotalk" in part or part == "kakao" for part in parents):
        return "app-cache"
    return ""


def find_picture_paths(root: Path) -> Iterable[tuple[Path, str]]:
    count = 0
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        kind = classify_picture(path)
        if not kind or not path.is_file():
            continue
        yield path, kind
        count += 1
        if count >= PICTURE_ROW_LIMIT:
            return


def sniff_mime(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            header = handle.read(16)
    except OSError:
        return ""
    for magic, mime in MAGIC_MIME:
        if header.startswith(magic):
            return mime
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp"
    if header[4:8] == b"ftyp":
        brand = header[8:12]
        return "image/heic" if brand in (b"heic", b"heix", b"mif1") else "video/mp4"
    if path.suffix.lower() == ".cng":
        return "application/octet-stream"
    return ""


def saved_name_time(name: str) -> str:
    match = SAVED_NAME_RE.match(name)
    if not match:
        return ""
    try:
        moment = dt.datetime.strptime(match.group("date") + match.group("time"), "%Y%m%d%H%M%S")
    except ValueError:
        return ""
    if match.group("ms"):
        moment = moment.replace(microsecond=int(match.group("ms")) * 1000)
    return moment.isoformat(timespec="milliseconds")


def build_picture_entry(path: Path, kind: str) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    hashes = compute_hashes(path) if 0 < size <= PICTURE_HASH_LIMIT else {}
    lowered = str(path).lower()
    return {
        "path": path,
        "kind": kind,
        "size": size,
        "hashes": {key: str(value).lower() for key, value in hashes.items()},
        "mime": sniff_mime(path),
        "is_thumbnail": "thumb" in lowered or path.suffix.lower() == ".cng",
        "download_time": saved_name_time(path.name),
        "link": None,
    }


def link_pictures(pictures: Sequence[dict[str, object]], messages: Sequence[Mapping[str, object]]) -> None:
    by_hash: dict[str, list[dict[str, object]]] = {}
    by_name: dict[str, list[dict[str, object]]] = {}
    for picture in pictures:
        for value in dict(picture["hashes"]).values():  # type: ignore[arg-type]
            by_hash.setdefault(str(value), []).append(picture)
        by_name.setdefault(Path(str(picture["path"])).name.lower(), []).append(picture)
    for message in messages:
        for attachment in message.get("attachments") or []:
            if not isinstance(attachment, Mapping):
                continue
            hits: list[tuple[dict[str, object], str]] = []
            for checksum in attachment.get("checksums") or []:
                hits.extend((picture, "checksum") for picture in by_hash.get(str(checksum).lower(), []))
            matched_ids = {id(picture) for picture, _method in hits}
            for name in attachment.get("basenames") or []:
                hits.extend(
                    (picture, "basename") for picture in by_name.get(str(name).lower(), []) if id(picture) not in matched_ids
                )
            for picture, method in hits:
                if picture["link"] is None or (method == "checksum" and picture["link"]["method"] != "checksum"):  # type: ignore[index]
                    picture["link"] = {
                        "message_id": message.get("message_id"),
                        "conversation_id": message.get("conversation_id"),
                        "sender": message.get("sender"),
                        "timestamp": message.get("timestamp"),
                        "method": method,
                    }
                local = message.setdefault("attachment_local_paths", [])
                if isinstance(local, list) and str(picture["path"]) not in local and len(local) < 10:
                    local.append(str(picture["path"]))


# --- rows ------------------------------------------------------------------------------


def chat_profile_root(path: Path) -> Path:
    """``…\\users\\<userdir>`` for ``…\\users\\<userdir>\\chat_data\\chatLogs_1.edb``."""
    return path.parent.parent if path.parent.name.lower() == "chat_data" else path.parent


def message_details(
    message: Mapping[str, object],
    *,
    result: DatabaseResult,
    source_sha256: str,
) -> dict[str, object]:
    matched = result.matched or {}
    user_hash = str(matched.get("user_id_sha256") or "")
    raw_type = message.get("type")
    try:
        message_type = int(raw_type)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        message_type = 0
    text_raw = message.get("text")
    text = text_raw.decode("utf-8", errors="replace") if isinstance(text_raw, bytes) else str(text_raw or "")
    author = str(message.get("author") if message.get("author") is not None else "")
    chat_match = CHATLOG_PATTERN.match(result.path.name)
    chat_id = str(message.get("chat") or (chat_match.group("chat_id") if chat_match else ""))
    attachments = message_attachments(message.get("attachment"), message_type)
    direction = ""
    if user_hash and author:
        direction = "발신" if sha256_text(author) == user_hash else "수신"
    return {
        "service": "KakaoTalk PC",
        "conversation_id": chat_id,
        "sender": author,
        "direction": direction,
        "timestamp": epoch_to_iso(message.get("time")),
        "message_id": str(message.get("id") if message.get("id") is not None else message.get("rowid")),
        "message_type": message_type,
        "message_text": text[:MESSAGE_TEXT_LIMIT],
        "message_text_preview": " ".join(text.split())[:PREVIEW_LIMIT],
        "message_text_truncated": len(text) > MESSAGE_TEXT_LIMIT,
        "message_text_sha256": sha256_text(text) if text else "",
        "attachment_name": ", ".join(str(item.get("name") or "") for item in attachments if item.get("name"))[:500],
        "attachments": attachments,
        "deleted_state": deleted_state(message, message_type),
        "source_table": str(message.get("table") or ""),
        "source_rowid": message.get("rowid"),
        "source_path": str(result.path.resolve()),
        "source_sha256": source_sha256,
        "source_offset": None,
        "decrypted_sha256": result.decrypted_sha256,
        "key_source": str(matched.get("source") or ""),
        "key_derivation": str(matched.get("key_derivation") or ""),
        "pragma_variant": str(matched.get("pragma_variant") or ""),
        "matched_user_id_sha256": user_hash,
        "recovery_method": "decrypted-legacy-page-aes",
        "parser": "kakaotalk-windows-messages",
        "parser_version": PARSER_VERSION,
        "validation_required": True,
        "privacy_legal_warning": "카카오톡 대화 본문입니다. 법적 권한 범위 안에서만 열람·보고하십시오.",
    }


def inventory_reason(status: str, *, material: KeyMaterial, db_count: int, results: Sequence[DatabaseResult]) -> str:
    summary = material.public_summary()
    found = (
        f"사용자 ID 후보 {summary['user_id_candidate_count']}개, DeviceInfo {'있음' if material.deviceinfo else '없음'}, "
        f"저장 pragma 후보 {summary['stored_pragma_candidate_count']}개, PK 후보 {summary['pk_candidate_count']}개"
    )
    if status == "decrypted":
        done = sum(1 for result in results if result.status == "decrypted")
        return f"복호 완료 — 대화 DB {db_count}개 중 {done}개를 복구된 키 재료로 복호"
    if status == "no-chat-database":
        return f"대화 DB 없음 — 카카오톡 흔적은 있으나 chatLogs_*.edb가 증거에 없음 ({found})"
    if status == "no-key-material":
        return f"복호 키 없음 — 키 재료 후보로 키를 만들 수 없음 ({found}; 사용자 ID와 DeviceInfo 또는 pragma가 함께 필요)"
    if status == "key-mismatch":
        tried = max((result.tried for result in results), default=0)
        return (
            f"복호 키 없음 — 키 후보 {tried}개가 모두 첫 페이지 SQLite 헤더와 맞지 않음 "
            f"({found}; 2025-08 이후 SQLCipher 형식이면 실행 중 메모리의 키가 필요)"
        )
    if status == "size-cap":
        return "크기 상한 초과 — 키는 맞았으나 DB가 복호 상한보다 큼(OpenSSL 없으면 32 MB, 있으면 1 GB)"
    errors = "; ".join(result.reason for result in results if result.reason)[:300]
    return f"복호 오류 — {errors}"


def overall_status(results: Sequence[DatabaseResult]) -> str:
    statuses = {result.status for result in results}
    for status in ("decrypted", "size-cap", "key-mismatch", "error", "no-key-material"):
        if status in statuses:
            return status
    return "no-chat-database"


def inventory_record(
    profile: Path,
    results: Sequence[DatabaseResult],
    *,
    material: KeyMaterial,
    db_hashes: Mapping[Path, str],
) -> ArtifactRecord:
    status = overall_status(results)
    # The row path is a file (first chat DB of the profile, else the registry source with key material).
    anchor = results[0].path if results else profile
    return ArtifactRecord(
        provider=PROVIDER_NAME,
        artifact_type="kakaotalk-app-inventory",
        path=str(anchor),
        supported=True,
        details={
            "service": "KakaoTalk PC",
            "profile_path": str(profile),
            "decryption_status": status,
            "status_label": STATUS_LABELS.get(status, status),
            "reason": inventory_reason(status, material=material, db_count=len(results), results=results),
            "chat_database_count": len(results),
            "decrypted_database_count": sum(1 for result in results if result.status == "decrypted"),
            "message_row_count": sum(len(result.messages) for result in results),
            "message_rows_truncated": any(result.truncated for result in results),
            "chat_databases": [
                {
                    "path": str(result.path),
                    "sha256": db_hashes.get(result.path, ""),
                    "status": result.status,
                    "status_label": STATUS_LABELS.get(result.status, result.status),
                    "message_row_count": len(result.messages),
                }
                for result in results[:INVENTORY_DB_LIST_LIMIT]
            ],
            "chat_databases_truncated": len(results) > INVENTORY_DB_LIST_LIMIT,
            "key_material": material.public_summary(),
            "openssl_available": openssl_binary() is not None,
            "policy": "복구된 키 재료의 결정적 유도만 시도(암호 크래킹·키 전수 탐색 없음)",
            "source_path": str(anchor),
            "source_offset": None,
            "recovery_method": "inventory",
            "parser": "kakaotalk-windows-messages",
            "parser_version": PARSER_VERSION,
        },
    )


def picture_record(picture: Mapping[str, object]) -> ArtifactRecord:
    path = Path(str(picture["path"]))
    hashes = dict(picture["hashes"])  # type: ignore[arg-type]
    link = picture.get("link") or {}
    kind = str(picture["kind"])
    location_label = {"saved-file": "저장·다운로드 파일", "received-folder": "받은 파일 폴더", "app-cache": "앱 캐시"}[kind]
    return ArtifactRecord(
        provider=PROVIDER_NAME,
        artifact_type="kakaotalk-shared-picture",
        path=str(path.resolve()),
        supported=True,
        details={
            "service": "KakaoTalk PC",
            "file_name": path.name,
            "download_location": str(path.parent),
            "location_kind": kind,
            "location_label": location_label,
            "download_time": picture.get("download_time") or "",
            "download_time_source": "파일 이름(현지 시각, 시간대 미상)" if picture.get("download_time") else "",
            "mime": picture.get("mime") or "",
            "size": picture.get("size"),
            "sha256": hashes.get("sha256", ""),
            "sha1": hashes.get("sha1", ""),
            "md5": hashes.get("md5", ""),
            "is_thumbnail": bool(picture.get("is_thumbnail")),
            "linked_message_id": link.get("message_id") or "",  # type: ignore[union-attr]
            "conversation_id": link.get("conversation_id") or "",  # type: ignore[union-attr]
            "sender": link.get("sender") or "",  # type: ignore[union-attr]
            "message_time": link.get("timestamp") or "",  # type: ignore[union-attr]
            "link_method": link.get("method") or "",  # type: ignore[union-attr]
            "link_status": "메시지 연결됨" if link else "메시지 연결 없음",
            "source_path": str(path.resolve()),
            "source_offset": 0,
            "recovery_method": "file-inventory",
            "parser": "kakaotalk-windows-shared-pictures",
            "parser_version": PARSER_VERSION,
        },
    )


def collect_kakaotalk_message_rows(
    root: Path,
    *,
    app_databases: Sequence[Path],
    registry_paths: Sequence[Path],
    memory_paths: Sequence[Path],
    has_traces: bool,
) -> list[ArtifactRecord]:
    """Message, app-inventory and shared-picture rows for one evidence root."""
    chat_dbs = [path for path in app_databases if CHATLOG_PATTERN.match(path.name)]
    pictures = [build_picture_entry(path, kind) for path, kind in find_picture_paths(root)]
    if not chat_dbs and not has_traces and not pictures:
        return []
    material = gather_key_material(registry_paths, memory_paths) if (chat_dbs or has_traces) else KeyMaterial()
    results: list[DatabaseResult] = []
    db_hashes: dict[Path, str] = {}
    remaining = MESSAGE_ROW_LIMIT
    for db_path in chat_dbs:
        db_hashes[db_path] = str(compute_hashes(db_path).get("sha256", ""))
        result = decrypt_chat_database(db_path, material, remaining_rows=remaining)
        remaining -= len(result.messages)
        results.append(result)
    message_rows: list[dict[str, object]] = []
    for result in results:
        for message in result.messages:
            message_rows.append(message_details(message, result=result, source_sha256=db_hashes.get(result.path, "")))
    link_pictures(pictures, message_rows)
    records: list[ArtifactRecord] = [
        ArtifactRecord(
            provider=PROVIDER_NAME,
            artifact_type="kakaotalk-message",
            path=str(details["source_path"]),
            supported=True,
            details=details,
        )
        for details in message_rows
    ]
    by_profile: dict[Path, list[DatabaseResult]] = {}
    for result in results:
        by_profile.setdefault(chat_profile_root(result.path), []).append(result)
    for profile, profile_results in sorted(by_profile.items(), key=lambda item: str(item[0]).lower()):
        records.append(inventory_record(profile, profile_results, material=material, db_hashes=db_hashes))
    if not results and has_traces:
        anchor = material.sources[0] if material.sources else root
        records.append(inventory_record(anchor, [], material=material, db_hashes=db_hashes))
    records.extend(picture_record(picture) for picture in pictures)
    return records
