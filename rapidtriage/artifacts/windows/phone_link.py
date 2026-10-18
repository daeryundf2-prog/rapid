"""Phone Link / Your Phone (휴대폰과 연결; plan r5-residual L1, re-audit §3 item 3): ``windows-phone-link``.

Per user profile, every device folder
``AppData\\Local\\Packages\\Microsoft.YourPhone_8wekyb3d8bbwe\\LocalCache\\Indexed\\<GUID>``
is read. Its ``System\\Database\\*.db`` files (``phone.db``, ``contacts.db``,
``calling.db``, ``photos.db``, ``settings.db`` …) are plaintext SQLite whose
columns change between app versions, so tables are recognised by *name and
columns* (alias lists), never by a fixed schema:

* ``phone-link-message`` — ``message`` / ``mms`` (+ ``mms_part`` text and
  attachment names) rows: thread, counterpart (``conversation.recipient_list``),
  direction, body, status, time.
* ``phone-link-call`` — ``call_history``-like rows: number, name, type, duration, start.
* ``phone-link-contact`` — ``contact`` rows joined with ``phonenumber`` /
  ``emailaddress`` by contact id.
* ``phone-link-photo`` — ``photo`` / ``media`` rows: name, taken/updated time,
  size, URI (metadata only — the synced image bytes are not read here; the
  file walk lists any cached files).
* ``phone-link-device`` — one per device folder: device GUID, database list
  (size, tables, rows), counts, caps and any device name/model column found.
* ``phone-link-parse-error`` — a database that could not be read (the
  collect continues with the next one).

Times: integer columns are decoded by magnitude (Windows FILETIME, Unix
s/ms/µs) and the chosen encoding is kept (``timestamp_encoding``); a text
time without an offset is never turned into an instant. Message/call type
codes follow the Android ``Telephony.Sms`` / ``CallLog.Calls`` constants the
app mirrors (``direction_source``); the raw code is always kept.
"""

from __future__ import annotations

import datetime as dt
import re
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ...core.models import ArtifactRecord
from .common import iter_windows_user_homes, open_sqlite_snapshot

PARSER = "windows-phone-link"
PARSER_VERSION = "windows-phone-link-v1"
SQLITE_HEADER = b"SQLite format 3\x00"
PACKAGE_DIRS = ("Microsoft.YourPhone_8wekyb3d8bbwe",)
MAX_DB_BYTES = 512 * 1024 * 1024
MAX_DBS_PER_DEVICE = 64
MAX_TABLES = 200
MAX_ROWS_PER_TABLE = 50_000
MAX_ROWS_PER_DEVICE = 200_000
MAX_TEXT_CHARS = 8_000
MAX_INVENTORY_FILES = 20_000

FILETIME_EPOCH_OFFSET = 11_644_473_600
SECONDS_2000 = 946_684_800
SECONDS_2100 = 4_102_444_800

MESSAGE_TABLES = frozenset({"message", "messages", "sms"})
MMS_TABLES = frozenset({"mms"})
MMS_PART_TABLES = frozenset({"mms_part", "mmspart", "part"})
CONVERSATION_TABLES = frozenset({"conversation", "conversations", "thread", "threads"})
CONTACT_TABLES = frozenset({"contact", "contacts"})
PHONE_TABLES = frozenset({"phonenumber", "phone_number", "phonenumbers"})
EMAIL_TABLES = frozenset({"emailaddress", "email_address", "emailaddresses"})
PHOTO_TABLES = frozenset({"photo", "photos", "media", "mediaitem", "media_item"})

TIME_ALIASES = ("timestamp", "date", "time", "datetime", "sent_time", "received_time", "last_updated_time", "creation_time")
BODY_ALIASES = ("body", "text", "message_body", "content", "subject")
FROM_ALIASES = ("from_address", "address", "sender", "from", "sender_address")
TO_ALIASES = ("recipient_list", "recipients", "to", "to_address")
TYPE_ALIASES = ("type", "msg_box", "message_type", "box", "direction")
THREAD_ALIASES = ("thread_id", "conversation_id", "threadid")
ID_ALIASES = ("message_id", "id", "_id", "msg_id")
STATUS_ALIASES = ("status", "delivery_status")
READ_ALIASES = ("read", "is_read", "seen")
CALL_NUMBER_ALIASES = ("phone_number", "number", "address", "phonenumber", "display_phone_number")
CALL_NAME_ALIASES = ("display_name", "name", "contact_name", "cached_name")
CALL_TIME_ALIASES = ("start_time", "timestamp", "date", "call_time", "time")
CALL_TYPE_ALIASES = ("call_type", "type")
DURATION_ALIASES = ("duration", "duration_seconds", "call_duration")
CONTACT_ID_ALIASES = ("contact_id", "id", "_id")
CONTACT_NAME_ALIASES = ("display_name", "name", "full_name", "nickname")
PHONE_VALUE_ALIASES = ("display_phone_number", "phone_number", "number", "normalized_number")
EMAIL_VALUE_ALIASES = ("address", "email_address", "email", "value")
PHOTO_NAME_ALIASES = ("name", "file_name", "filename", "display_name", "title")
PHOTO_TAKEN_ALIASES = ("taken_time", "date_taken", "datetaken", "taken_at", "capture_time")
PHOTO_UPDATED_ALIASES = ("last_updated_time", "last_modified_time", "date_modified", "modified_time", "last_seen_time")
PHOTO_SIZE_ALIASES = ("size", "file_size", "size_bytes")
PHOTO_URI_ALIASES = ("uri", "media_uri", "path", "file_path", "content_uri")
PHOTO_MIME_ALIASES = ("mime_type", "mimetype", "content_type")
PHOTO_ID_ALIASES = ("media_id", "photo_id", "id", "_id")
DEVICE_FIELD_ALIASES = ("device_name", "friendly_name", "model", "manufacturer", "os_version", "android_version", "brand")

SMS_TYPE_LABELS = {1: ("incoming", "수신"), 2: ("outgoing", "발신"), 3: ("draft", "임시 저장"), 4: ("outgoing", "발신 대기"),
                   5: ("outgoing", "발신 실패"), 6: ("outgoing", "발신 대기열")}
CALL_TYPE_LABELS = {1: "수신", 2: "발신", 3: "부재중", 4: "음성사서함", 5: "거절", 6: "차단", 7: "다른 기기에서 받음"}
_SECRET_MARKERS = ("token", "password", "secret", "key", "credential", "auth")


def decode_phone_time(value: object) -> tuple[str, str]:
    """``(ISO-8601 UTC, encoding)``; ``("", "")`` when the value is not a plausible 2000–2099 instant."""
    if value is None or isinstance(value, bool) or value == "":
        return "", ""
    number: float | None = None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        if re.fullmatch(r"-?\d{9,19}(?:\.\d+)?", text):
            number = float(text)
        else:
            candidate = text.replace("Z", "+00:00").replace(" ", "T", 1)
            candidate = re.sub(r"(\.\d{6})\d+", r"\1", candidate)
            try:
                moment = dt.datetime.fromisoformat(candidate)
            except ValueError:
                return "", ""
            if moment.tzinfo is None or not 2000 <= moment.year < 2100:
                return "", ""
            return moment.astimezone(dt.timezone.utc).isoformat(), "iso-8601"
    if number is None or number <= 0:
        return "", ""
    for encoding, seconds in (
        ("windows-filetime", number / 10_000_000 - FILETIME_EPOCH_OFFSET if number > 1e17 else None),
        ("unix-us", number / 1e6 if 1e14 < number < 1e17 else None),
        ("unix-ms", number / 1e3 if 1e11 < number <= 1e14 else None),
        ("unix-s", number if number <= 1e11 else None),
    ):
        if seconds is not None and SECONDS_2000 <= seconds <= SECONDS_2100:
            return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat(), encoding
    return "", ""


def _lower(row: Mapping[str, object]) -> dict[str, object]:
    return {str(key).lower(): value for key, value in row.items()}


def _pick(row: Mapping[str, object], aliases: Sequence[str]) -> tuple[str, object]:
    for alias in aliases:
        value = row.get(alias)
        if value not in (None, ""):
            return alias, value
    return "", None


def _text(value: object, limit: int = 512) -> str:
    if value is None or isinstance(value, (bytes, bytearray)):
        return ""
    return str(value).strip()[:limit]


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _raw_sample(row: Mapping[str, object], limit: int = 24) -> dict[str, object]:
    sample: dict[str, object] = {}
    for key, value in row.items():
        if len(sample) >= limit:
            break
        if any(marker in str(key).lower() for marker in _SECRET_MARKERS):
            continue
        if isinstance(value, (bytes, bytearray)):
            sample[key] = f"<{len(value)} bytes>"
        elif isinstance(value, str):
            sample[key] = value[:200]
        elif isinstance(value, (int, float)) or value is None:
            sample[key] = value
    return sample


@dataclass
class _DeviceRun:
    user: str
    device_dir: Path
    rows: list[ArtifactRecord] = field(default_factory=list)
    errors: list[ArtifactRecord] = field(default_factory=list)
    databases: list[dict[str, object]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    device_fields: dict[str, str] = field(default_factory=dict)
    capped: list[str] = field(default_factory=list)

    def cap(self, reason: str) -> None:
        if reason not in self.capped:
            self.capped.append(reason)

    @property
    def device_id(self) -> str:
        return self.device_dir.name


class WindowsPhoneLinkProvider:
    name = "windows-phone-link"
    collector_kind = "windows-phone-link"
    description = "Phone Link / Your Phone (휴대폰과 연결): synced messages, calls, contacts, photos and device folders"
    target_platform = "windows"

    def __init__(self) -> None:
        self.collection_notes: list[str] = []

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        self.collection_notes = []
        found = False
        for user_home in iter_windows_user_homes(root):
            for package in PACKAGE_DIRS:
                indexed = user_home / "AppData" / "Local" / "Packages" / package / "LocalCache" / "Indexed"
                try:
                    devices = sorted((item for item in indexed.iterdir() if item.is_dir()), key=lambda item: item.name.lower())
                except OSError:
                    continue
                for device_dir in devices:
                    found = True
                    run = _DeviceRun(user=user_home.name, device_dir=device_dir)
                    self._collect_device(run)
                    yield self._device_row(run)
                    yield from run.rows
                    yield from run.errors
                    if run.capped:
                        self.collection_notes.append(f"휴대폰과 연결({run.user}, {run.device_id}): 상한 도달 — {', '.join(run.capped)}")
        if not found:
            self.collection_notes.append("휴대폰과 연결(Phone Link/Your Phone) 기기 폴더(LocalCache\\Indexed\\<GUID>)가 사용자 프로필에서 발견되지 않았습니다.")

    # -- one device folder -------------------------------------------------------------------

    def _collect_device(self, run: _DeviceRun) -> None:
        candidates: list[Path] = []
        for pattern in ("System/Database/*.db", "System/*.db", "*.db"):
            try:
                candidates.extend(item for item in run.device_dir.glob(pattern) if item.is_file())
            except OSError:
                continue
        seen: set[str] = set()
        ordered = []
        for path in sorted(candidates, key=lambda item: str(item).lower()):
            if str(path).lower() not in seen:
                seen.add(str(path).lower())
                ordered.append(path)
        if len(ordered) > MAX_DBS_PER_DEVICE:
            run.cap("database-count-cap")
            ordered = ordered[:MAX_DBS_PER_DEVICE]
        for path in ordered:
            try:
                self._database(run, path)
            except Exception as exc:  # a damaged database never stops the device
                run.databases.append({"path": str(path), "name": path.name, "status": "parse-error"})
                run.errors.append(
                    ArtifactRecord(
                        provider=self.name,
                        artifact_type="phone-link-parse-error",
                        path=str(path),
                        supported=True,
                        details={
                            **self._base(run, path, "none", table=""),
                            "parser_error": True,
                            "coverage_status": "parser-error",
                            "error_type": type(exc).__name__,
                            "error": str(exc)[:500],
                            "reason_ko": f"휴대폰과 연결 DB({path.name})를 읽지 못해 건너뜀({type(exc).__name__}); 다른 DB는 계속 처리",
                            "timestamp": "",
                            "timestamp_source": "none-parse-error",
                        },
                    )
                )

    def _base(self, run: _DeviceRun, path: Path, recovery_method: str, *, table: str) -> dict[str, object]:
        return {
            "parser": PARSER,
            "parser_version": PARSER_VERSION,
            "app": "Phone Link",
            "app_label_ko": "휴대폰과 연결",
            "user": run.user,
            "device_id": run.device_id,
            "recovery_method": recovery_method,
            "source_path": str(path),
            "source_table": table,
            "source_format": "sqlite",
            "reportability": "triage",
            "validation_required": True,
        }

    def _add(self, run: _DeviceRun, artifact_type: str, path: Path, details: dict[str, object]) -> bool:
        data_rows = sum(run.counts.values())
        if data_rows >= MAX_ROWS_PER_DEVICE:
            run.cap("device-row-cap")
            return False
        run.rows.append(ArtifactRecord(provider=self.name, artifact_type=artifact_type, path=str(path), supported=True, details=details))
        run.counts[artifact_type] = run.counts.get(artifact_type, 0) + 1
        return True

    def _database(self, run: _DeviceRun, path: Path) -> None:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(16)
        entry: dict[str, object] = {"path": str(path), "name": path.name, "bytes": size}
        if header != SQLITE_HEADER:
            entry["status"] = "not-sqlite" if header else "empty"
            run.databases.append(entry)
            return
        if size > MAX_DB_BYTES:
            entry["status"] = "skipped-size-cap"
            run.cap("database-size-cap")
            run.databases.append(entry)
            return
        with open_sqlite_snapshot(path) as connection:
            connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
            names = [str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
            names = names[:MAX_TABLES]
            tables = {name.lower(): name for name in names if re.fullmatch(r"[A-Za-z0-9_]+", name)}
            table_rows: dict[str, list[dict[str, object]]] = {}

            def rows_of(lowered: str) -> list[dict[str, object]]:
                if lowered not in table_rows:
                    table_rows[lowered] = self._select(run, connection, tables[lowered])
                return table_rows[lowered]

            threads: dict[str, str] = {}
            for lowered in tables:
                if lowered in CONVERSATION_TABLES:
                    for row in rows_of(lowered):
                        thread_key, thread = _pick(row, THREAD_ALIASES + ("id", "_id"))
                        _rk, recipients = _pick(row, TO_ALIASES + ("display_name", "name"))
                        if thread is not None and recipients is not None:
                            threads[str(thread)] = _text(recipients)
            parts: dict[str, dict[str, list[str]]] = {}
            for lowered in tables:
                if lowered in MMS_PART_TABLES:
                    for row in rows_of(lowered):
                        _ik, message_id = _pick(row, ("message_id", "mms_id", "msg_id", "mid"))
                        if message_id is None:
                            continue
                        bucket = parts.setdefault(str(message_id), {"text": [], "files": []})
                        content_type = _text(row.get("content_type") or row.get("ct"))
                        _tk, text = _pick(row, ("text", "body", "content"))
                        if text is not None and (not content_type or content_type.startswith("text/")):
                            bucket["text"].append(_text(text, MAX_TEXT_CHARS))
                        elif content_type and not content_type.startswith(("text/", "application/smil")):
                            _nk, file_name = _pick(row, ("name", "file_name", "filename", "cl", "fn"))
                            bucket["files"].append(_text(file_name) or content_type)
            read_tables: list[str] = []
            for lowered, original in tables.items():
                columns = {str(item[1]).lower() for item in connection.execute(f'PRAGMA table_info("{original}")').fetchall()}
                if lowered in MESSAGE_TABLES and columns & set(BODY_ALIASES):
                    self._messages(run, path, original, rows_of(lowered), threads, {}, mms=False)
                elif lowered in MMS_TABLES:
                    self._messages(run, path, original, rows_of(lowered), threads, parts, mms=True)
                elif "call" in lowered and columns & set(CALL_NUMBER_ALIASES):
                    self._calls(run, path, original, rows_of(lowered))
                elif lowered in CONTACT_TABLES and columns & set(CONTACT_NAME_ALIASES):
                    phones = self._contact_values(rows_of, tables, PHONE_TABLES, PHONE_VALUE_ALIASES)
                    emails = self._contact_values(rows_of, tables, EMAIL_TABLES, EMAIL_VALUE_ALIASES)
                    self._contacts(run, path, original, rows_of(lowered), phones, emails)
                elif lowered in PHOTO_TABLES and columns & set(PHOTO_NAME_ALIASES + PHOTO_URI_ALIASES):
                    self._photos(run, path, original, rows_of(lowered))
                elif "device" in lowered and columns & set(DEVICE_FIELD_ALIASES) and rows_of(lowered):
                    for key in DEVICE_FIELD_ALIASES:
                        value = _text(rows_of(lowered)[0].get(key), 200)
                        if value and key not in run.device_fields:
                            run.device_fields[key] = value
                else:
                    continue
                read_tables.append(original)
            entry.update(
                {
                    "status": "read",
                    "tables": names[:60],
                    "table_count": len(names),
                    "tables_mapped": read_tables,
                    "rows_read": {tables[key]: len(value) for key, value in table_rows.items()},
                }
            )
        run.databases.append(entry)

    def _select(self, run: _DeviceRun, connection: sqlite3.Connection, table: str) -> list[dict[str, object]]:
        cursor = connection.execute(f'SELECT * FROM "{table}" LIMIT ?', (MAX_ROWS_PER_TABLE + 1,))
        names = [str(item[0]).lower() for item in cursor.description or ()]
        rows = [dict(zip(names, row, strict=False)) for row in cursor.fetchall()]
        if len(rows) > MAX_ROWS_PER_TABLE:
            run.cap(f"table-row-cap:{table}")
            rows = rows[:MAX_ROWS_PER_TABLE]
        return rows

    @staticmethod
    def _contact_values(rows_of, tables: Mapping[str, str], names: frozenset[str], aliases: Sequence[str]) -> dict[str, list[str]]:
        values: dict[str, list[str]] = {}
        for lowered in tables:
            if lowered not in names:
                continue
            for row in rows_of(lowered):
                _ck, contact = _pick(row, ("contact_id", "raw_contact_id"))
                _vk, value = _pick(row, aliases)
                if contact is not None and value is not None:
                    bucket = values.setdefault(str(contact), [])
                    if _text(value) not in bucket and len(bucket) < 20:
                        bucket.append(_text(value))
        return values

    # -- row mappers -------------------------------------------------------------------------

    def _messages(self, run: _DeviceRun, path: Path, table: str, rows: list[dict[str, object]], threads: Mapping[str, str],
                  parts: Mapping[str, Mapping[str, list[str]]], *, mms: bool) -> None:
        for index, row in enumerate(rows):
            _id_key, message_id = _pick(row, ID_ALIASES)
            body_key, body = _pick(row, BODY_ALIASES)
            part = parts.get(str(message_id)) if message_id is not None else None
            text = _text(body, MAX_TEXT_CHARS)
            if part and part.get("text"):
                text = " ".join([text, *part["text"]]).strip()[:MAX_TEXT_CHARS]
            attachments = list(part.get("files", [])) if part else []
            time_key, time_value = _pick(row, TIME_ALIASES)
            iso, encoding = decode_phone_time(time_value)
            type_key, type_value = _pick(row, TYPE_ALIASES)
            code = _int(type_value)
            direction, direction_ko = SMS_TYPE_LABELS.get(code, ("unknown", "불명")) if code is not None else ("unknown", "불명")
            _tk, thread = _pick(row, THREAD_ALIASES)
            _fk, sender = _pick(row, FROM_ALIASES)
            _rk, recipients = _pick(row, TO_ALIASES)
            counterpart = _text(recipients) or (threads.get(str(thread), "") if thread is not None else "") or _text(sender)
            _sk, status = _pick(row, STATUS_ALIASES)
            _rd, read = _pick(row, READ_ALIASES)
            details = {
                **self._base(run, path, "sqlite-table", table=table),
                "source_row": index,
                "message_kind": "mms" if mms else "sms",
                "message_id": _text(message_id, 120),
                "thread_id": _text(thread, 120),
                "conversation_title": threads.get(str(thread), "") if thread is not None else "",
                "counterpart": counterpart,
                "sender": "" if direction == "outgoing" else (_text(sender) or counterpart),
                "recipient": counterpart if direction == "outgoing" else "",
                "direction": direction,
                "direction_ko": direction_ko,
                "direction_code": code,
                "direction_source": f"column:{type_key} (Android Telephony.Sms 상수)" if type_key else "",
                "message_text": text,
                "message_text_preview": text[:500],
                "body_column": body_key,
                "attachments": attachments,
                "attachment_count": len(attachments),
                "status": _text(status, 60),
                "read_state": "" if read is None else ("읽음" if _int(read) else "읽지 않음"),
                "timestamp": iso,
                "timestamp_kind": "message" if iso else "",
                "timestamp_source": f"column:{time_key}" if iso else ("unparsed:" + time_key if time_key else "none"),
                "timestamp_encoding": encoding,
                "timestamp_raw": _text(time_value, 60),
                "deleted_state": "live",
                "coverage_status": "mapped",
                "raw_fields": _raw_sample(row),
            }
            if not self._add(run, "phone-link-message", path, details):
                return

    def _calls(self, run: _DeviceRun, path: Path, table: str, rows: list[dict[str, object]]) -> None:
        for index, row in enumerate(rows):
            _nk, number = _pick(row, CALL_NUMBER_ALIASES)
            _dk, name = _pick(row, CALL_NAME_ALIASES)
            time_key, time_value = _pick(row, CALL_TIME_ALIASES)
            iso, encoding = decode_phone_time(time_value)
            type_key, type_value = _pick(row, CALL_TYPE_ALIASES)
            code = _int(type_value)
            _durk, duration = _pick(row, DURATION_ALIASES)
            details = {
                **self._base(run, path, "sqlite-table", table=table),
                "source_row": index,
                "phone_number": _text(number, 80),
                "contact_name": _text(name, 200),
                "call_type": CALL_TYPE_LABELS.get(code, "불명") if code is not None else "불명",
                "call_type_code": code,
                "call_type_source": f"column:{type_key} (Android CallLog.Calls 상수)" if type_key else "",
                "duration_seconds": _int(duration),
                "timestamp": iso,
                "timestamp_kind": "call-start" if iso else "",
                "timestamp_source": f"column:{time_key}" if iso else ("unparsed:" + time_key if time_key else "none"),
                "timestamp_encoding": encoding,
                "timestamp_raw": _text(time_value, 60),
                "coverage_status": "mapped",
                "raw_fields": _raw_sample(row),
            }
            if not self._add(run, "phone-link-call", path, details):
                return

    def _contacts(self, run: _DeviceRun, path: Path, table: str, rows: list[dict[str, object]],
                  phones: Mapping[str, list[str]], emails: Mapping[str, list[str]]) -> None:
        for index, row in enumerate(rows):
            _ik, contact_id = _pick(row, CONTACT_ID_ALIASES)
            _nk, name = _pick(row, CONTACT_NAME_ALIASES)
            numbers = list(phones.get(str(contact_id), [])) if contact_id is not None else []
            mails = list(emails.get(str(contact_id), [])) if contact_id is not None else []
            for key in ("phone_number", "number"):
                if not numbers and _text(row.get(key)):
                    numbers.append(_text(row.get(key)))
            details = {
                **self._base(run, path, "sqlite-table", table=table),
                "source_row": index,
                "contact_id": _text(contact_id, 120),
                "contact_name": _text(name, 200),
                "display_name": _text(name, 200),
                "phone": numbers[0] if numbers else "",
                "phones": numbers,
                "email": mails[0] if mails else "",
                "emails": mails,
                "timestamp": "",
                "timestamp_source": "none-contact-row",
                "coverage_status": "mapped",
                "raw_fields": _raw_sample(row),
            }
            if not self._add(run, "phone-link-contact", path, details):
                return

    def _photos(self, run: _DeviceRun, path: Path, table: str, rows: list[dict[str, object]]) -> None:
        for index, row in enumerate(rows):
            _nk, name = _pick(row, PHOTO_NAME_ALIASES)
            taken_key, taken = _pick(row, PHOTO_TAKEN_ALIASES)
            updated_key, updated = _pick(row, PHOTO_UPDATED_ALIASES)
            taken_iso, taken_encoding = decode_phone_time(taken)
            updated_iso, updated_encoding = decode_phone_time(updated)
            _sk, size = _pick(row, PHOTO_SIZE_ALIASES)
            _uk, uri = _pick(row, PHOTO_URI_ALIASES)
            _mk, mime = _pick(row, PHOTO_MIME_ALIASES)
            _ik, media_id = _pick(row, PHOTO_ID_ALIASES)
            if taken_iso:
                timestamp, kind, source, encoding = taken_iso, "photo-taken", f"column:{taken_key}", taken_encoding
            elif updated_iso:
                timestamp, kind, source, encoding = updated_iso, "photo-synced", f"column:{updated_key}", updated_encoding
            else:
                timestamp, kind, source, encoding = "", "", "none", ""
            details = {
                **self._base(run, path, "sqlite-table", table=table),
                "source_row": index,
                "media_id": _text(media_id, 120),
                "file_name": _text(name, 260),
                "media_uri": _text(uri, 1024),
                "mime_type": _text(mime, 80),
                "file_size": _int(size),
                "taken_at": taken_iso,
                "updated_at": updated_iso,
                "width": _int(row.get("width")),
                "height": _int(row.get("height")),
                "timestamp": timestamp,
                "timestamp_kind": kind,
                "timestamp_source": source,
                "timestamp_encoding": encoding,
                "coverage_status": "mapped",
                "raw_fields": _raw_sample(row),
            }
            if not self._add(run, "phone-link-photo", path, details):
                return

    def _device_row(self, run: _DeviceRun) -> ArtifactRecord:
        file_count, total, truncated = 0, 0, False
        try:
            for item in run.device_dir.rglob("*"):
                if file_count >= MAX_INVENTORY_FILES:
                    truncated = True
                    break
                if item.is_file():
                    file_count += 1
                    try:
                        total += item.stat().st_size
                    except OSError:
                        continue
        except OSError:
            truncated = True
        data_rows = sum(run.counts.values())
        details = {
            **self._base(run, run.device_dir, "filesystem-inventory", table=""),
            "source_format": "directory",
            "device_name": run.device_fields.get("device_name") or run.device_fields.get("friendly_name", ""),
            "device_model": run.device_fields.get("model", ""),
            "device_manufacturer": run.device_fields.get("manufacturer") or run.device_fields.get("brand", ""),
            "device_os_version": run.device_fields.get("os_version") or run.device_fields.get("android_version", ""),
            "databases": run.databases,
            "database_count": len(run.databases),
            "message_rows": run.counts.get("phone-link-message", 0),
            "call_rows": run.counts.get("phone-link-call", 0),
            "contact_rows": run.counts.get("phone-link-contact", 0),
            "photo_rows": run.counts.get("phone-link-photo", 0),
            "parse_error_count": len(run.errors),
            "file_count": file_count,
            "total_bytes": total,
            "files_truncated": truncated,
            "caps_hit": list(run.capped),
            "reason_ko": "" if data_rows else "기기 폴더는 있으나 메시지·통화·연락처·사진 행으로 해석된 표가 없습니다(동기화 안 함·삭제·미확인 스키마).",
            "coverage_status": "rows-recovered" if data_rows else "inventory-only",
            "timestamp": "",
            "timestamp_source": "none-device-row",
        }
        return ArtifactRecord(provider=self.name, artifact_type="phone-link-device", path=str(run.device_dir), supported=True, details=details)
