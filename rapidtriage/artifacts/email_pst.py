"""Outlook PST/OST rows via pffexport/readpst output, plus ICS and vCard parsing (plan r2 §3.2 M2).

``email_external.run_email_external_parse`` runs libpff ``pffexport`` or libpst ``readpst``
(when one is on PATH) into a temporary folder; this module normalises that export tree into
``email-message``, ``email-attachment``, ``calendar-event`` and ``contact`` rows and always
adds one ``email-container-inventory`` row per container with the tool status. Without a
tool the inventory row carries the Korean reason and ``/doctor`` shows ``tools:email-pst``.

``.ics`` files are parsed in pure Python (RFC 5545 VEVENT) into ``calendar-event`` rows.
The pffexport text-file labels (``OutlookHeaders.txt``, ``Recipients.txt``, ``Appointment.txt``,
``Contact.txt``) are matched by lower-cased label aliases; parsing is bounded and a damaged
item is skipped with a counted error instead of stopping the run.
"""

from __future__ import annotations

import datetime as dt
import email
import hashlib
import mimetypes
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from email import policy
from email.message import EmailMessage
from email.parser import HeaderParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from ..core.triage_rules.email import folder_is_deleted

PARSER_VERSION = "email-pst-normalizer-v1"
ICS_PARSER_VERSION = "ics-vevent-v1"
PROVIDER_NAME = "email-artifacts"
ICS_MAX_BYTES = 32 * 1024 * 1024
ICS_EVENT_LIMIT = 20_000
EXPORT_ITEM_LIMIT = 100_000
EXPORT_TEXT_LIMIT = 4 * 1024 * 1024
MBOX_MAX_BYTES = 512 * 1024 * 1024
BODY_PREVIEW_CHARS = 500
ATTACHMENT_HASH_LIMIT = 256 * 1024 * 1024
DEFAULT_TOOL_TIMEOUT = 900
MAX_TOOL_TIMEOUT = 4 * 3600
ITEM_DIR_RE = re.compile(
    r"^(?P<kind>Message|Email|Appointment|Meeting|Contact|Task|Note|Activity|DistributionList|Document|Item)(?P<number>\d{5})$",
    re.IGNORECASE,
)
# Deleted folders: ``folder_is_deleted`` / ``DELETED_FOLDER_NAMES`` live in core.triage_rules.email (shared with the rules).
# Outlook exports name Windows time zones in TZID; map the common ones to IANA names.
WINDOWS_TZ_NAMES = {
    "Korea Standard Time": "Asia/Seoul",
    "Tokyo Standard Time": "Asia/Tokyo",
    "China Standard Time": "Asia/Shanghai",
    "Taipei Standard Time": "Asia/Taipei",
    "Singapore Standard Time": "Asia/Singapore",
    "UTC": "UTC",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Warsaw",
    "Romance Standard Time": "Europe/Paris",
    "Greenwich Standard Time": "Atlantic/Reykjavik",
    "Eastern Standard Time": "America/New_York",
    "US Eastern Standard Time": "America/Indiana/Indianapolis",
    "Central Standard Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver",
    "US Mountain Standard Time": "America/Phoenix",
    "Pacific Standard Time": "America/Los_Angeles",
    "India Standard Time": "Asia/Kolkata",
    "SE Asia Standard Time": "Asia/Bangkok",
    "Arabian Standard Time": "Asia/Dubai",
}
# Fallback when the zoneinfo database is missing (Windows Python without the ``tzdata`` package):
# zones without daylight saving -> fixed UTC offset in minutes.
FIXED_TZ_OFFSETS = {
    "Asia/Seoul": 540,
    "Asia/Tokyo": 540,
    "Asia/Shanghai": 480,
    "Asia/Hong_Kong": 480,
    "Asia/Taipei": 480,
    "Asia/Singapore": 480,
    "Asia/Kolkata": 330,
    "Asia/Bangkok": 420,
    "Asia/Dubai": 240,
    "UTC": 0,
    "Etc/UTC": 0,
    "GMT": 0,
    "Etc/GMT": 0,
    "Atlantic/Reykjavik": 0,
    "America/Phoenix": -420,
}
# Zones with daylight saving: (standard offset minutes, rule). "us" = US rule since 2007, "eu" = EU rule
# since 1996; other years are left unconverted (``timezone_status: unconverted``).
DST_TZ_RULES = {
    "America/New_York": (-300, "us"),
    "America/Indiana/Indianapolis": (-300, "us"),
    "America/Chicago": (-360, "us"),
    "America/Denver": (-420, "us"),
    "America/Los_Angeles": (-480, "us"),
    "Europe/London": (0, "eu"),
    "Europe/Berlin": (60, "eu"),
    "Europe/Paris": (60, "eu"),
    "Europe/Budapest": (60, "eu"),
    "Europe/Warsaw": (60, "eu"),
    "Europe/Amsterdam": (60, "eu"),
    "Europe/Madrid": (60, "eu"),
    "Europe/Rome": (60, "eu"),
    "Europe/Vienna": (60, "eu"),
    "Europe/Prague": (60, "eu"),
    "Europe/Zurich": (60, "eu"),
}
TOOL_REASON_MISSING = "외부 도구 없음 — pffexport(libpff)·readpst(libpst)가 PATH에 없어 메시지·약속·연락처를 풀지 않음(/doctor의 tools:email-pst 참고)"
ToolResolver = Callable[[str], str | None]
CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


# --- shared text helpers ---------------------------------------------------------------


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def read_text_bounded(path: Path, limit: int = EXPORT_TEXT_LIMIT) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit)
    except OSError:
        return ""
    for encoding in ("utf-8-sig", "utf-16") if data[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8-sig", "cp949", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def normalise_label(label: str) -> str:
    return " ".join(label.strip().strip(":").lower().split())


def parse_label_lines(text: str) -> list[tuple[str, str]]:
    """``Label:<tabs>value`` lines of a pffexport text file, in order."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _sep, value = line.partition(":")
        if not label.strip() or len(label) > 80:
            continue
        pairs.append((normalise_label(label), value.strip()))
    return pairs


def first_value(fields: Mapping[str, str], *labels: str) -> str:
    for label in labels:
        value = fields.get(label)
        if value:
            return value
    return ""


TOOL_TIME_FORMATS = (
    "%b %d, %Y %H:%M:%S.%f",
    "%b %d, %Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_tool_time(value: str) -> str:
    """pffexport ``Jan 02, 2024 10:00:00.123456789 UTC`` (or ISO / RFC 2822) -> ISO-8601 UTC."""
    text = value.strip()
    if not text or text.lower() in {"not set", "(null)", "0"}:
        return ""
    utc = text.upper().endswith(" UTC") or text.endswith("Z")
    core = re.sub(r"\s*(UTC|Z)$", "", text, flags=re.IGNORECASE)
    core = re.sub(r"(\.\d{6})\d+", r"\1", core)
    for pattern in TOOL_TIME_FORMATS:
        try:
            moment = dt.datetime.strptime(core, pattern)
        except ValueError:
            continue
        if utc:
            moment = moment.replace(tzinfo=dt.timezone.utc)
        return iso(moment)
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return ""
    return iso(moment) if moment is not None else ""


def iso(moment: dt.datetime) -> str:
    if moment.tzinfo is not None:
        return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return moment.isoformat()


def safe_folder(parts: Sequence[str]) -> str:
    """Export folder path; ``.`` / ``..`` segments (a PST folder can be named so) are neutralised."""
    return "/".join("\uff0e" * len(part) if part and set(part) == {"."} else part for part in parts)


# --- RFC 5545 / RFC 6350 content lines ------------------------------------------------------


def unfold_content_lines(text: str) -> list[tuple[str, int]]:
    """Unfolded logical lines with the character offset of their first physical line."""
    lines: list[tuple[str, int]] = []
    offset = 0
    for physical in text.splitlines(keepends=True):
        stripped = physical.rstrip("\r\n")
        if stripped[:1] in (" ", "\t") and lines:
            previous, start = lines[-1]
            lines[-1] = (previous + stripped[1:], start)
        elif stripped:
            lines.append((stripped, offset))
        offset += len(physical)
    return lines


def split_content_line(line: str) -> tuple[str, dict[str, str], str]:
    """``NAME;PARAM=a;PARAM2="b:c":value`` -> (NAME, params, value); colons inside quotes kept."""
    in_quotes = False
    split_at = -1
    for index, char in enumerate(line):
        if char == '"':
            in_quotes = not in_quotes
        elif char == ":" and not in_quotes:
            split_at = index
            break
    if split_at < 0:
        return "", {}, ""
    head, value = line[:split_at], line[split_at + 1 :]
    parts = re.split(r';(?=(?:[^"]*"[^"]*")*[^"]*$)', head)
    name = parts[0].strip().upper()
    if "." in name:  # vCard group prefix (item1.EMAIL)
        name = name.rsplit(".", 1)[1]
    params: dict[str, str] = {}
    for part in parts[1:]:
        key, _eq, raw = part.partition("=")
        params[key.strip().upper()] = raw.strip().strip('"')
    return name, params, value


def unescape_text(value: str) -> str:
    return re.sub(r"\\([\\;,nN])", lambda match: "\n" if match.group(1) in "nN" else match.group(1), value)


def _nth_sunday(year: int, month: int, nth: int) -> dt.date:
    first = dt.date(year, month, 1)
    return first + dt.timedelta(days=(6 - first.weekday()) % 7 + 7 * (nth - 1))


def _last_sunday(year: int, month: int) -> dt.date:
    last = (dt.date(year + 1, 1, 1) if month == 12 else dt.date(year, month + 1, 1)) - dt.timedelta(days=1)
    return last - dt.timedelta(days=(last.weekday() + 1) % 7)


def fallback_utc_offset(zone: str, wall: dt.datetime) -> dt.timedelta | None:
    """UTC offset of local wall time ``wall`` in ``zone`` without tzdata; ``None`` = cannot tell.

    Ambiguous / skipped hours resolve like ``zoneinfo`` with ``fold=0``.
    """
    if zone in FIXED_TZ_OFFSETS:
        return dt.timedelta(minutes=FIXED_TZ_OFFSETS[zone])
    rule = DST_TZ_RULES.get(zone)
    if rule is None:
        return None
    standard = dt.timedelta(minutes=rule[0])
    hour = dt.timedelta(hours=1)
    if rule[1] == "us":
        if wall.year < 2007:
            return None
        start = dt.datetime.combine(_nth_sunday(wall.year, 3, 2), dt.time(3))
        end = dt.datetime.combine(_nth_sunday(wall.year, 11, 1), dt.time(2))
    else:
        if wall.year < 1996:
            return None
        start = dt.datetime.combine(_last_sunday(wall.year, 3), dt.time(1)) + standard + hour
        end = dt.datetime.combine(_last_sunday(wall.year, 10), dt.time(1)) + standard + hour
    return standard + hour if start <= wall < end else standard


def parse_ics_time(value: str, params: Mapping[str, str]) -> tuple[str, bool, str, str]:
    """(ISO time, all-day, time-zone label, ``timezone_status``).

    UTC ``Z`` -> ISO Z; TZID -> UTC via zoneinfo, else via the built-in offset table; a TZID that
    cannot be converted keeps the local wall time (no ``Z``) with status ``unconverted``.
    """
    text = value.strip()
    if params.get("VALUE", "").upper() == "DATE" or re.fullmatch(r"\d{8}", text):
        try:
            return dt.datetime.strptime(text[:8], "%Y%m%d").date().isoformat(), True, "", "all-day"
        except ValueError:
            return "", True, "", ""
    match = re.fullmatch(r"(\d{8})T(\d{6})(Z?)", text)
    if not match:
        return "", False, "", ""
    try:
        moment = dt.datetime.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M%S")
    except ValueError:
        return "", False, "", ""
    if match.group(3):
        return iso(moment.replace(tzinfo=dt.timezone.utc)), False, "UTC", "utc"
    tzid = params.get("TZID", "")
    if not tzid:
        return moment.isoformat(), False, "floating(시간대 없음)", "floating"
    zone = WINDOWS_TZ_NAMES.get(tzid, tzid)
    try:
        from zoneinfo import ZoneInfo

        return iso(moment.replace(tzinfo=ZoneInfo(zone))), False, tzid, "converted"
    except (ImportError, ValueError, KeyError, OSError):
        pass
    offset = fallback_utc_offset(zone, moment)
    if offset is not None:
        return iso(moment.replace(tzinfo=dt.timezone(offset))), False, tzid, "converted-offset-table"
    return moment.isoformat(), False, f"{tzid} (변환 안 함)", "unconverted"


def mail_address(value: str, params: Mapping[str, str]) -> str:
    address = re.sub(r"^mailto:", "", value.strip(), flags=re.IGNORECASE)
    name = params.get("CN", "")
    return f"{name} <{address}>" if name and address else (address or name)


def parse_ics_events(text: str, *, limit: int = ICS_EVENT_LIMIT) -> tuple[list[dict[str, object]], int]:
    """VEVENT dicts (bounded) and the number of malformed/unterminated components."""
    events: list[dict[str, object]] = []
    errors = 0
    stack: list[str] = []
    current: dict[str, object] | None = None
    for line, offset in unfold_content_lines(text):
        name, params, value = split_content_line(line)
        if not name:
            errors += 1
            continue
        if name == "BEGIN":
            component = value.strip().upper()
            stack.append(component)
            if component == "VEVENT":
                if current is not None:
                    errors += 1
                current = {"source_char_offset": offset, "attendees": [], "attachments": []}
            continue
        if name == "END":
            component = value.strip().upper()
            if stack and stack[-1] == component:
                stack.pop()
            if component == "VEVENT" and current is not None:
                events.append(current)
                current = None
                if len(events) >= limit:
                    break
            continue
        if current is None or (stack and stack[-1] != "VEVENT"):
            continue  # VCALENDAR properties, VALARM / VTIMEZONE sub-components
        if name in ("DTSTART", "DTEND", "CREATED", "LAST-MODIFIED", "DTSTAMP"):
            moment, all_day, tz_label, tz_status = parse_ics_time(value, params)
            current[name.lower().replace("-", "_")] = moment
            if name == "DTSTART":
                current["all_day"] = all_day
                current["timezone"] = tz_label
                current["timezone_status"] = tz_status
        elif name == "ATTENDEE":
            current["attendees"].append(mail_address(value, params))  # type: ignore[union-attr]
        elif name == "ORGANIZER":
            current["organizer"] = mail_address(value, params)
        elif name == "ATTACH":
            current["attachments"].append(params.get("FILENAME") or params.get("X-FILENAME") or value[:200])  # type: ignore[union-attr]
        elif name in ("SUMMARY", "LOCATION", "DESCRIPTION", "UID", "STATUS", "RRULE", "DURATION", "CLASS", "URL", "SEQUENCE"):
            current[name.lower()] = unescape_text(value)
    if current is not None:
        errors += 1  # unterminated VEVENT: not emitted
    return events, errors


def parse_vcards(text: str, *, limit: int = EXPORT_ITEM_LIMIT) -> list[dict[str, object]]:
    cards: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line, _offset in unfold_content_lines(text):
        name, params, value = split_content_line(line)
        if name == "BEGIN" and value.strip().upper() == "VCARD":
            current = {"emails": [], "phones": []}
        elif name == "END" and value.strip().upper() == "VCARD" and current is not None:
            cards.append(current)
            current = None
            if len(cards) >= limit:
                break
        elif current is not None:
            if name == "FN":
                current["display_name"] = unescape_text(value)
            elif name == "N" and not current.get("display_name"):
                parts = [unescape_text(part) for part in value.split(";")]
                current["display_name"] = " ".join(part for part in (parts[1:2] + parts[:1]) if part)
            elif name == "EMAIL":
                current["emails"].append(value.strip())  # type: ignore[union-attr]
            elif name == "TEL":
                current["phones"].append(re.sub(r"^tel:", "", value.strip(), flags=re.IGNORECASE))  # type: ignore[union-attr]
            elif name == "ORG":
                current["organization"] = unescape_text(value).replace(";", " ").strip()
            elif name == "TITLE":
                current["title"] = unescape_text(value)
    return cards


# --- row builders ------------------------------------------------------------------------------


def base_details(
    *, source_path: Path, source_sha256: str, source_format: str, recovery_method: str, parser_version: str = PARSER_VERSION
) -> dict[str, object]:
    return {
        "source_path": str(source_path),
        "source_sha256": source_sha256,
        "source_format": source_format,
        "source_offset": None,
        "recovery_method": recovery_method,
        "parser_version": parser_version,
        "validation_required": True,
    }


def calendar_record(event: Mapping[str, object], *, base: Mapping[str, object], folder: str = "", item: str = "") -> ArtifactRecord:
    attendees = [str(item) for item in event.get("attendees") or [] if item]
    description = str(event.get("description") or "")
    details = {
        **base,
        "title": str(event.get("summary") or ""),
        "start": str(event.get("dtstart") or ""),
        "end": str(event.get("dtend") or ""),
        "all_day": bool(event.get("all_day")),
        "timezone": str(event.get("timezone") or ""),
        "timezone_status": str(event.get("timezone_status") or ""),
        "duration": str(event.get("duration") or ""),
        "location": str(event.get("location") or ""),
        "organizer": str(event.get("organizer") or ""),
        "attendees": attendees,
        "attendee_count": len(attendees),
        "uid": str(event.get("uid") or ""),
        "status": str(event.get("status") or ""),
        "recurrence_rule": str(event.get("rrule") or ""),
        "created": str(event.get("created") or ""),
        "last_modified": str(event.get("last_modified") or ""),
        "description_preview": " ".join(description.split())[:BODY_PREVIEW_CHARS],
        "description_sha256": sha256_text(description) if description else "",
        "attachment_names": [str(name) for name in event.get("attachments") or []][:20],
        "folder": folder,
        "export_item": item,
    }
    if "source_char_offset" in event:
        details["source_char_offset"] = event["source_char_offset"]
    return ArtifactRecord(
        provider=PROVIDER_NAME,
        artifact_type="calendar-event",
        path=str(base["source_path"]),
        supported=True,
        details=details,
    )


def contact_record(card: Mapping[str, object], *, base: Mapping[str, object], folder: str = "", item: str = "") -> ArtifactRecord:
    emails = [str(value) for value in card.get("emails") or [] if value]
    phones = [str(value) for value in card.get("phones") or [] if value]
    return ArtifactRecord(
        provider=PROVIDER_NAME,
        artifact_type="contact",
        path=str(base["source_path"]),
        supported=True,
        details={
            **base,
            "display_name": str(card.get("display_name") or ""),
            "email": emails[0] if emails else "",
            "emails": emails[:10],
            "phone": phones[0] if phones else "",
            "phones": phones[:10],
            "organization": str(card.get("organization") or ""),
            "title": str(card.get("title") or ""),
            "folder": folder,
            "export_item": item,
        },
    )


def attachment_record(attachment: Mapping[str, object], message: Mapping[str, object], *, base: Mapping[str, object]) -> ArtifactRecord:
    return ArtifactRecord(
        provider=PROVIDER_NAME,
        artifact_type="email-attachment",
        path=str(base["source_path"]),
        supported=True,
        details={
            **base,
            "filename": attachment.get("filename", ""),
            "size": attachment.get("size"),
            "sha256": attachment.get("sha256", ""),
            "content_type": attachment.get("content_type", ""),
            "inline": bool(attachment.get("inline")),
            "message_id": message.get("message_id", ""),
            "message_subject": message.get("subject", ""),
            "message_date": message.get("date", ""),
            "from": message.get("from", ""),
            "to": message.get("to", ""),
            "folder": message.get("folder", ""),
            "deleted_state": message.get("deleted_state", ""),
            "export_item": message.get("export_item", ""),
        },
    )


def message_records(message: Mapping[str, object], *, base: Mapping[str, object]) -> list[ArtifactRecord]:
    details = {**base, **message}
    records = [
        ArtifactRecord(
            provider=PROVIDER_NAME,
            artifact_type="email-message",
            path=str(base["source_path"]),
            supported=True,
            details=details,
        )
    ]
    records.extend(attachment_record(item, message, base=base) for item in message.get("attachments") or [])  # type: ignore[union-attr]
    return records


def body_fields(text: str) -> dict[str, object]:
    clean = " ".join(re.sub(r"<[^>]+>", " ", text).split())
    return {"body_preview": clean[:BODY_PREVIEW_CHARS], "body_sha256": sha256_text(text) if text else ""}


# Outlook names embedded (signature / pasted) images image001.png, image002.jpg, ...; pffexport has no
# Content-ID for them, so the name is the only hint (``inline_reason`` discloses it).
OUTLOOK_INLINE_IMAGE_RE = re.compile(r"^image\d{3}\.(?:png|jpe?g|gif|bmp)$", re.IGNORECASE)


def file_attachment(path: Path) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    sha256 = str(compute_hashes(path).get("sha256", "")) if 0 < size <= ATTACHMENT_HASH_LIMIT else ""
    inline = OUTLOOK_INLINE_IMAGE_RE.match(path.name) is not None
    return {
        "filename": path.name,
        "size": size,
        "sha256": sha256,
        "content_type": mimetypes.guess_type(path.name)[0] or "",
        "inline": inline,
        **({"inline_reason": "outlook-inline-image-name"} if inline else {}),
    }


def attachment_counts(attachments: Sequence[Mapping[str, object]]) -> dict[str, int]:
    """``attachment_count`` excludes inline parts (signature images); they are counted separately."""
    inline = sum(1 for item in attachments if item.get("inline"))
    return {"attachment_count": len(attachments) - inline, "inline_attachment_count": inline}


# --- pffexport -------------------------------------------------------------------------------


def recipient_blocks(text: str) -> list[dict[str, str]]:
    """``Recipients.txt`` blocks: a ``Recipient: n`` header line or a repeated label starts a new one."""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for label, value in parse_label_lines(text):
        header = label == "recipient" or re.fullmatch(r"recipient \d+", label) is not None
        if header or label in current:
            if current:
                blocks.append(current)
            current = {}
            if header:
                continue
        current[label] = value
    if current:
        blocks.append(current)
    return blocks


def recipient_lists(text: str) -> dict[str, list[str]]:
    lists: dict[str, list[str]] = {"to": [], "cc": [], "bcc": []}
    for block in recipient_blocks(text):
        candidates = [block.get(label, "") for label in ("smtp address", "email address", "recipient email address", "recipient smtp address")]
        address = next((value for value in candidates if "@" in value), "") or next((value for value in candidates if value), "")
        name = first_value(block, "display name", "recipient display name")
        entry = f"{name} <{address}>" if name and address and name != address else (address or name)
        if not entry:
            continue
        kind = first_value(block, "recipient type", "type").lower()
        key = "cc" if kind in ("cc", "2") else "bcc" if kind in ("bcc", "3") else "to"
        lists[key].append(entry)
    return lists


def read_flag_state(flags: str) -> str:
    if not flags:
        return ""
    match = re.search(r"0x([0-9a-fA-F]+)", flags)
    if match:
        return "읽음" if int(match.group(1), 16) & 0x1 else "읽지 않음"
    lowered = flags.lower()
    if "unread" in lowered:
        return "읽지 않음"
    return "읽음" if "read" in lowered else ""


def header_text(headers: EmailMessage, name: str) -> str:
    """Decoded header value; a malformed header reads as its raw text instead of raising."""
    try:
        value = headers.get(name)
    except (ValueError, LookupError, IndexError, AttributeError):
        return ""
    return str(value or "")


def pffexport_message(item_dir: Path, *, folder: str, deleted: str) -> dict[str, object]:
    fields = dict(parse_label_lines(read_text_bounded(item_dir / "OutlookHeaders.txt")))
    headers = HeaderParser(policy=policy.default).parsestr(read_text_bounded(item_dir / "InternetHeaders.txt"))
    recipients = recipient_lists(read_text_bounded(item_dir / "Recipients.txt"))
    sender_name = first_value(fields, "sender name", "sent representing name")
    sender_address = first_value(fields, "sender email address", "sent representing email address")
    sender_smtp = first_value(fields, "sender smtp address", "sender smtp email address", "sent representing smtp address")
    address_type = first_value(fields, "sender address type", "sender email address type", "sent representing address type").upper()
    if not address_type:
        address_type = "EX" if sender_address.upper().startswith("/O=") else ("SMTP" if "@" in sender_address else "")
    # Exchange senders carry an X.500 DN (/O=EXCHANGELABS/...); prefer the SMTP sender property.
    best_address = sender_smtp if "@" in sender_smtp else sender_address
    header_from = header_text(headers, "From")
    sender = header_from or (f"{sender_name} <{best_address}>" if sender_name and best_address else best_address or sender_name)
    body = ""
    for name in ("Message.txt", "Message.html", "Message.rtf"):
        if (item_dir / name).is_file():
            body = read_text_bounded(item_dir / name)
            break
    attachments_dir = item_dir / "Attachments"
    attachments = (
        [file_attachment(path) for path in sorted(attachments_dir.iterdir(), key=lambda p: p.name.lower()) if path.is_file()][:200]
        if attachments_dir.is_dir()
        else []
    )
    submit = parse_tool_time(first_value(fields, "client submit time", "submit time"))
    delivery = parse_tool_time(first_value(fields, "delivery time", "message delivery time"))
    thread = read_text_bounded(item_dir / "ConversationIndex.txt").strip() or header_text(headers, "Thread-Index") or first_value(fields, "conversation index")
    return {
        "from": str(sender or ""),
        "to": str(header_text(headers, "To") or ", ".join(recipients["to"]) or first_value(fields, "display to")),
        "cc": str(header_text(headers, "Cc") or ", ".join(recipients["cc"]) or first_value(fields, "display cc")),
        "bcc": str(header_text(headers, "Bcc") or ", ".join(recipients["bcc"]) or first_value(fields, "display bcc")),
        "subject": str(header_text(headers, "Subject") or first_value(fields, "subject", "conversation topic")),
        "date": submit or delivery or parse_tool_time(str(header_text(headers, "Date") or "")),
        "submit_time": submit,
        "delivery_time": delivery,
        "folder": folder,
        "read_state": read_flag_state(first_value(fields, "flags", "message flags")),
        "thread_id": " ".join(str(thread).split())[:200],
        "conversation_topic": first_value(fields, "conversation topic"),
        "message_id": str(header_text(headers, "Message-ID") or first_value(fields, "internet message identifier", "message identifier")),
        "in_reply_to": str(header_text(headers, "In-Reply-To") or ""),
        "reply_to": str(header_text(headers, "Reply-To") or ""),
        "return_path": str(header_text(headers, "Return-Path") or ""),
        "authentication_results": str(header_text(headers, "Authentication-Results") or ""),
        "received": "\n".join(str(value) for value in headers.get_all("Received") or [])[:4000],
        "address_type": "SMTP" if header_from and address_type != "EX" else address_type,
        "sender_smtp_address": sender_smtp if "@" in sender_smtp else (sender_address if "@" in sender_address else ""),
        "sender_x500_address": sender_address if sender_address.upper().startswith("/O=") else "",
        **attachment_counts(attachments),
        "attachments": attachments,
        "deleted_state": deleted,
        **body_fields(body),
    }


def pffexport_appointment(item_dir: Path) -> dict[str, object]:
    headers = dict(parse_label_lines(read_text_bounded(item_dir / "OutlookHeaders.txt")))
    fields = dict(parse_label_lines(read_text_bounded(item_dir / "Appointment.txt")))
    fields.update({key: value for key, value in parse_label_lines(read_text_bounded(item_dir / "Meeting.txt")) if key not in fields})
    attendees = [value for values in recipient_lists(read_text_bounded(item_dir / "Recipients.txt")).values() for value in values]
    body = read_text_bounded(item_dir / "Message.txt")
    return {
        "summary": first_value(fields, "subject") or first_value(headers, "subject", "conversation topic"),
        "dtstart": parse_tool_time(first_value(fields, "start time", "appointment start time", "start date")),
        "dtend": parse_tool_time(first_value(fields, "end time", "appointment end time", "end date")),
        "location": first_value(fields, "location", "appointment location"),
        "duration": first_value(fields, "duration"),
        "rrule": first_value(fields, "recurrence pattern", "recurrence"),
        "organizer": first_value(headers, "sender name", "sent representing name"),
        "attendees": attendees,
        "description": body,
    }


def pffexport_contact(item_dir: Path) -> dict[str, object]:
    pairs = parse_label_lines(read_text_bounded(item_dir / "Contact.txt"))
    fields = dict(pairs)
    given, surname = first_value(fields, "given name"), first_value(fields, "surname")
    return {
        "display_name": first_value(fields, "display name", "file under") or " ".join(part for part in (surname, given) if part),
        "emails": [value for label, value in pairs if "email" in label and "@" in value],
        "phones": [value for label, value in pairs if ("phone" in label or "mobile" in label) and any(ch.isdigit() for ch in value)],
        "organization": first_value(fields, "company name", "company"),
        "title": first_value(fields, "title", "job title"),
    }


def iter_item_dirs(root: Path, counts: dict[str, int] | None = None) -> Iterable[Path]:
    """Item folders (bounded by ``EXPORT_ITEM_LIMIT`` across calls sharing ``counts``; ``counts["truncated"]`` = 1 when cut)."""
    counts = {} if counts is None else counts
    for current, dirs, _files in os.walk(root):
        dirs.sort(key=str.lower)
        current_path = Path(current)
        if ITEM_DIR_RE.match(current_path.name):
            dirs[:] = [name for name in dirs if name.lower() != "attachments"]
            if counts.get("items", 0) >= EXPORT_ITEM_LIMIT:
                counts["truncated"] = 1
                return
            counts["items"] = counts.get("items", 0) + 1
            yield current_path


def export_tree_state(tree_name: str) -> str:
    lowered = tree_name.lower()
    if lowered.endswith(".recovered"):
        return "recovered"
    if lowered.endswith(".orphans"):
        return "orphan"
    return ""


def normalize_pffexport_tree(export_dir: Path, *, base: Mapping[str, object]) -> tuple[list[ArtifactRecord], dict[str, int]]:
    """Rows from a ``pffexport -f all`` output folder (``<target>.export`` / ``.recovered`` / ``.orphans``)."""
    records: list[ArtifactRecord] = []
    counts = {"messages": 0, "attachments": 0, "events": 0, "contacts": 0, "skipped": 0, "errors": 0, "items": 0, "truncated": 0}
    trees = sorted((path for path in export_dir.iterdir() if path.is_dir()), key=lambda p: p.name.lower()) if export_dir.is_dir() else []
    for tree in trees:
        if counts["truncated"]:
            break
        state = export_tree_state(tree.name)
        for item_dir in iter_item_dirs(tree, counts):
            relative = item_dir.relative_to(tree)
            folder = safe_folder(relative.parts[:-1])
            deleted = state or ("deleted-folder" if folder_is_deleted(folder) else "")
            kind = ITEM_DIR_RE.match(item_dir.name).group("kind").lower()  # type: ignore[union-attr]
            item = f"{tree.name}/{safe_folder(relative.parts)}"
            try:
                if kind in ("message", "email", "item"):
                    message = pffexport_message(item_dir, folder=folder, deleted=deleted)
                    if not any(message.get(key) for key in ("from", "to", "subject", "date", "body_sha256", "attachments")):
                        counts["errors"] += 1  # unreadable item folder: nothing to report
                        continue
                    message["export_item"] = item
                    message["item_kind"] = kind
                    rows = message_records(message, base=base)
                    counts["messages"] += 1
                    counts["attachments"] += len(rows) - 1
                    records.extend(rows)
                elif kind in ("appointment", "meeting"):
                    records.append(calendar_record(pffexport_appointment(item_dir), base=base, folder=folder, item=item))
                    counts["events"] += 1
                elif kind == "contact":
                    records.append(contact_record(pffexport_contact(item_dir), base=base, folder=folder, item=item))
                    counts["contacts"] += 1
                else:
                    counts["skipped"] += 1
            except (OSError, ValueError, UnicodeError, LookupError):
                counts["errors"] += 1
    return records, counts


# --- readpst -----------------------------------------------------------------------------------


def mime_attachments(message: EmailMessage) -> list[dict[str, object]]:
    """Attachment parts; inline parts (``Content-Disposition: inline``, or an image with a Content-ID) are marked ``inline``."""
    attachments: list[dict[str, object]] = []
    for part in message.iter_attachments():
        try:
            payload = part.get_payload(decode=True) or b""
        except (LookupError, ValueError):
            payload = b""
        try:
            disposition = str(part.get_content_disposition() or "")
            filename = part.get_filename() or ""
        except (LookupError, ValueError, IndexError, AttributeError):
            disposition, filename = "", ""
        content_type = part.get_content_type()
        content_id = header_text(part, "Content-ID").strip()  # type: ignore[arg-type]
        attachments.append(
            {
                "filename": filename,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                "content_type": content_type,
                "content_id": content_id,
                "content_disposition": disposition,
                "inline": disposition == "inline" or (bool(content_id) and content_type.startswith("image/")),
            }
        )
        if len(attachments) >= 200:
            break
    return attachments


def mbox_message(message: EmailMessage, *, folder: str, deleted: str) -> dict[str, object]:
    try:
        body_part = message.get_body(preferencelist=("plain", "html"))
        body = body_part.get_content() if body_part is not None else ""
    except (LookupError, ValueError, AttributeError):
        body = ""
    attachments = mime_attachments(message)
    date_text = str(header_text(message, "Date") or "")
    status = str(header_text(message, "Status") or "") + str(header_text(message, "X-Status") or "")
    try:
        parsed = parsedate_to_datetime(date_text) if date_text else None
    except (TypeError, ValueError, IndexError):
        parsed = None
    sender = str(header_text(message, "From") or "")
    return {
        "from": sender,
        "address_type": "EX" if "/o=" in sender.lower() and "@" not in sender else ("SMTP" if "@" in sender else ""),
        "to": str(header_text(message, "To") or ""),
        "cc": str(header_text(message, "Cc") or ""),
        "bcc": str(header_text(message, "Bcc") or ""),
        "subject": str(header_text(message, "Subject") or ""),
        "date": iso(parsed) if parsed else "",
        "submit_time": iso(parsed) if parsed else "",
        "delivery_time": "",
        "folder": folder,
        "read_state": ("읽음" if "R" in status else "읽지 않음") if status else "",
        "thread_id": str(header_text(message, "Thread-Index") or ""),
        "message_id": str(header_text(message, "Message-ID") or ""),
        "in_reply_to": str(header_text(message, "In-Reply-To") or ""),
        "reply_to": str(header_text(message, "Reply-To") or ""),
        "return_path": str(header_text(message, "Return-Path") or ""),
        "authentication_results": str(header_text(message, "Authentication-Results") or ""),
        "received": "\n".join(str(value) for value in message.get_all("Received") or [])[:4000],
        **attachment_counts(attachments),
        "attachments": attachments,
        "deleted_state": deleted,
        **body_fields(str(body)),
    }


def split_mbox(data: bytes) -> list[bytes]:
    chunks = re.split(rb"(?:^|\n)From [^\n]*\n", data)
    return [chunk for chunk in chunks if chunk.strip()]


def normalize_readpst_tree(export_dir: Path, *, base: Mapping[str, object]) -> tuple[list[ArtifactRecord], dict[str, int]]:
    """Rows from ``readpst -r`` output: per folder ``mbox`` (or numbered files), ``calendar`` (ICS), ``contacts`` (vCard)."""
    records: list[ArtifactRecord] = []
    counts = {"messages": 0, "attachments": 0, "events": 0, "contacts": 0, "skipped": 0, "errors": 0, "items": 0, "truncated": 0}
    for current, dirs, files in os.walk(export_dir):
        dirs.sort(key=str.lower)
        folder = safe_folder([part for part in Path(current).relative_to(export_dir).parts if part != "."])
        deleted = "deleted-folder" if folder_is_deleted(folder) else ""
        for name in sorted(files, key=str.lower):
            path = Path(current) / name
            lowered = name.lower()
            item = f"{folder}/{name}".lstrip("/")
            try:
                if lowered in ("calendar", "calendar.ics") or lowered.endswith(".ics"):
                    events, errors = parse_ics_events(read_text_bounded(path, ICS_MAX_BYTES))
                    counts["errors"] += errors
                    for event in events:
                        records.append(calendar_record(event, base=base, folder=folder, item=item))
                    counts["events"] += len(events)
                elif lowered in ("contacts", "contacts.vcf") or lowered.endswith(".vcf"):
                    cards = parse_vcards(read_text_bounded(path, ICS_MAX_BYTES))
                    for card in cards:
                        records.append(contact_record(card, base=base, folder=folder, item=item))
                    counts["contacts"] += len(cards)
                elif lowered in ("mbox", "mbox.mbox") or lowered.endswith((".mbox", ".eml")) or lowered.isdigit():
                    if path.stat().st_size > MBOX_MAX_BYTES:
                        counts["skipped"] += 1
                        continue
                    data = path.read_bytes()
                    chunks = [data] if lowered.endswith(".eml") or lowered.isdigit() and not data.startswith(b"From ") else split_mbox(data)
                    for index, chunk in enumerate(chunks):
                        if counts["messages"] >= EXPORT_ITEM_LIMIT:
                            counts["truncated"] = 1
                            break
                        parsed = email.message_from_bytes(chunk, policy=policy.default)
                        message = mbox_message(parsed, folder=folder, deleted=deleted)  # type: ignore[arg-type]
                        message["export_item"] = f"{item}#{index + 1}"
                        rows = message_records(message, base=base)
                        counts["messages"] += 1
                        counts["attachments"] += len(rows) - 1
                        records.extend(rows)
                else:
                    counts["skipped"] += 1
            except (OSError, ValueError, UnicodeError, LookupError):
                counts["errors"] += 1
    return records, counts


# --- containers and ICS files ----------------------------------------------------------------


def external_tools_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Running pffexport/readpst during a run is opt-in (project policy: no external programs by default).

    Set ``RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1`` (or ``on``/``true``/``yes``) to let the run export
    PST/OST containers with an installed tool; otherwise each container gets an inventory row.
    """
    env = os.environ if environ is None else environ
    return str(env.get("RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS", "")).strip().lower() in {"1", "on", "true", "yes"}


def tool_timeout(environ: Mapping[str, str] | None = None) -> int:
    """``RAPIDTRIAGE_EMAIL_TOOL_TIMEOUT`` seconds, clamped to 30 s .. 4 h."""
    env = os.environ if environ is None else environ
    try:
        return min(MAX_TOOL_TIMEOUT, max(30, int(str(env.get("RAPIDTRIAGE_EMAIL_TOOL_TIMEOUT", DEFAULT_TOOL_TIMEOUT)))))
    except ValueError:
        return DEFAULT_TOOL_TIMEOUT


def export_byte_cap(environ: Mapping[str, str] | None = None) -> int | None:
    """Operator override ``RAPIDTRIAGE_EMAIL_EXPORT_MAX_BYTES`` (else the wrapper's 2x-container / 8 GiB cap)."""
    env = os.environ if environ is None else environ
    try:
        value = int(str(env.get("RAPIDTRIAGE_EMAIL_EXPORT_MAX_BYTES", "") or 0))
    except ValueError:
        return None
    return value if value > 0 else None


def container_inventory(
    path: Path,
    *,
    source_sha256: str,
    status: str,
    reason: str,
    tool: str = "",
    tools_checked: Sequence[Mapping[str, object]] = (),
    counts: Mapping[str, object] | None = None,
) -> ArtifactRecord:
    counts = dict(counts or {})
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return ArtifactRecord(
        provider=PROVIDER_NAME,
        artifact_type="email-container-inventory",
        path=str(path.resolve()),
        supported=True,
        details={
            **base_details(
                source_path=path.resolve(),
                source_sha256=source_sha256,
                source_format=path.suffix.lower().lstrip("."),
                recovery_method="inventory",
            ),
            "container_name": path.name,
            "size": size,
            "status": status,
            "status_label": {"normalized": "정규화 완료", "tool-missing": "도구 없음", "failed": "도구 실행 실패", "blocked": "헤더 불일치", "disabled": "외부 도구 꺼짐"}.get(status, status),
            "reason": reason,
            "tool": tool,
            "tools_checked": [dict(item) for item in tools_checked],
            "message_count": counts.get("messages", 0),
            "attachment_count": counts.get("attachments", 0),
            "calendar_event_count": counts.get("events", 0),
            "contact_count": counts.get("contacts", 0),
            "item_error_count": counts.get("errors", 0),
            "export_item_limit": EXPORT_ITEM_LIMIT,
            "export_truncated": bool(counts.get("truncated")),
            "export_limit_exceeded": str(counts.get("limit_exceeded") or ""),
        },
    )


def collect_outlook_container(
    path: Path,
    *,
    tool_resolver: ToolResolver | None = None,
    command_runner: CommandRunner | None = None,
    environ: Mapping[str, str] | None = None,
    source_hashes: Mapping[str, str] | None = None,
) -> list[ArtifactRecord]:
    """PST/OST: normalised rows when pffexport/readpst ran, plus one ``email-container-inventory`` row.

    ``source_hashes`` (from the caller's hashing of the same file) avoid reading the container again.
    ``command_runner`` is for tests; the default runs the tool under the export-size / output guard.
    """
    tool_resolver = tool_resolver or shutil.which
    from .email_external import (
        EmailExternalParserError,
        email_external_tool_availability_matrix,
        run_email_external_parse,
    )

    hashes = dict(source_hashes) if source_hashes and source_hashes.get("sha256") else compute_hashes(path)
    source_sha256 = str(hashes.get("sha256", ""))
    suffix = path.suffix.lower().lstrip(".")
    matrix = email_external_tool_availability_matrix(suffix, preferred_tool=None, tool_resolver=tool_resolver)
    tools_checked = [{"tool": row["tool"], "available": row["available"]} for row in matrix]
    if not any(row["available"] for row in matrix):
        return [container_inventory(path, source_sha256=source_sha256, status="tool-missing", reason=TOOL_REASON_MISSING, tools_checked=tools_checked)]
    if not external_tools_enabled(environ):
        return [
            container_inventory(
                path,
                source_sha256=source_sha256,
                status="disabled",
                reason="외부 도구 실행 꺼짐(기본값) — RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1로 켜면 설치된 pffexport/readpst로 내보냅니다",
                tools_checked=tools_checked,
            )
        ]
    work = Path(tempfile.mkdtemp(prefix="rt-pst-"))
    try:
        try:
            payload = run_email_external_parse(
                source_path=path,
                output_dir=work / "out",
                timeout_seconds=tool_timeout(environ),
                tool_resolver=tool_resolver,
                command_runner=command_runner,
                source_hashes=hashes,
                max_export_bytes=export_byte_cap(environ),
            )
        except (EmailExternalParserError, OSError) as exc:
            return [container_inventory(path, source_sha256=source_sha256, status="failed", reason=f"도구 실행 실패 — {exc}"[:400], tools_checked=tools_checked)]
        selected = payload.get("selected_tool") if isinstance(payload.get("selected_tool"), Mapping) else {}
        tool = str(selected.get("tool") or "")  # type: ignore[union-attr]
        status = str(payload.get("status") or "")
        export_dir = work / "out" / "export"
        family = Path(tool).name.lower()
        base = base_details(
            source_path=path.resolve(),
            source_sha256=source_sha256,
            source_format=suffix,
            recovery_method=f"external-tool:{family or 'unknown'}",
        )
        execution = payload.get("execution") if isinstance(payload.get("execution"), Mapping) else {}
        limit = str(execution.get("limit_exceeded") or "")  # type: ignore[union-attr]
        if family == "readpst":
            records, counts = normalize_readpst_tree(export_dir, base=base)
        else:
            records, counts = normalize_pffexport_tree(export_dir, base=base)
        counts_out: dict[str, object] = {**counts, "limit_exceeded": limit}
        if status == "blocked":
            reason = f"헤더 불일치 — {payload.get('source', {}).get('header_profile', {}).get('reason', '')}"  # type: ignore[union-attr]
        elif status != "complete" and not records:
            stderr = str(execution.get("stderr_tail", ""))[-300:]  # type: ignore[union-attr]
            error = str(execution.get("error", ""))[:200]  # type: ignore[union-attr]
            reason = f"도구 실행 실패 — {tool} 종료 코드 {execution.get('returncode')} {error} {stderr}".strip()  # type: ignore[union-attr]
        else:
            reason = f"{tool} 출력 정규화 — 메시지 {counts['messages']}·첨부 {counts['attachments']}·약속 {counts['events']}·연락처 {counts['contacts']}"
            if limit:
                reason += f" — 도구 중단({limit}), 일부만 정규화"
        if counts.get("truncated"):
            reason += f" — 항목 상한 {EXPORT_ITEM_LIMIT:,}개에서 잘림"
        inventory_status = "normalized" if records or status == "complete" else ("blocked" if status == "blocked" else "failed")
        records.append(
            container_inventory(
                path,
                source_sha256=source_sha256,
                status=inventory_status,
                reason=reason,
                tool=tool,
                tools_checked=tools_checked,
                counts=counts_out,
            )
        )
        return records
    finally:
        shutil.rmtree(work, ignore_errors=True)


def collect_ics_file(path: Path) -> list[ArtifactRecord]:
    try:
        if path.stat().st_size > ICS_MAX_BYTES:
            return []
    except OSError:
        return []
    events, _errors = parse_ics_events(read_text_bounded(path, ICS_MAX_BYTES))
    if not events:
        return []
    base = base_details(
        source_path=path.resolve(),
        source_sha256=str(compute_hashes(path).get("sha256", "")),
        source_format="ics",
        recovery_method="parsed",
        parser_version=ICS_PARSER_VERSION,
    )
    return [calendar_record(event, base=base) for event in events]
