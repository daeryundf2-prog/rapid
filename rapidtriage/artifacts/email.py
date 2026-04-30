from __future__ import annotations

import email
import hashlib
import re
from email.message import EmailMessage
from email import policy
from pathlib import Path
from typing import Iterable

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "email-artifacts-v2"
EMAIL_SUFFIXES = {".eml", ".emlx", ".mbox", ".msg", ".pst", ".ost"}
MAX_MBOX_MESSAGES = 200
CONTAINER_SCAN_LIMIT = 16 * 1024 * 1024
MAX_CONTAINER_CANDIDATES = 200
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SUBJECT_RE = re.compile(rb"(?:Subject|SUBJECT)\s*:\s*([^\r\n]{1,240})")
EMAIL_NATIVE_CAPABILITIES = {
    "eml_header_body_attachment_metadata": True,
    "mbox_bounded_message_parse": True,
    "pst_ost_msg_bounded_string_inventory": True,
    "source_hashing": True,
    "native_pst_ost_msg_object_decode": False,
    "folder_hierarchy_decode": False,
    "deleted_item_recovery": False,
    "conversation_thread_reconstruction": False,
    "broad_mailbox_known_answer_corpus": False,
}
EMAIL_REPORT_GRADE_BLOCKERS = [
    "native-pst-ost-msg-object-decoding-not-implemented",
    "folder-hierarchy-and-message-flags-not-implemented",
    "deleted-item-recovery-not-implemented",
    "conversation-threading-and-dedup-validation-required",
    "broad-mailbox-known-answer-corpus-required",
]
EMAIL_FORMAT_PROFILES = {
    "eml": {
        "family": "internet-message",
        "support_tier": "parsed-triage",
        "native_decode": True,
        "known_gaps": ["mime-edge-cases", "dkim-arc-smime-openpgp-validation", "thread-graph-validation"],
    },
    "emlx": {
        "family": "apple-mail-message",
        "support_tier": "parsed-triage",
        "native_decode": True,
        "known_gaps": ["apple-envelope-index-correlation", "attachment-folder-correlation", "thread-graph-validation"],
    },
    "mbox": {
        "family": "unix-mailbox",
        "support_tier": "bounded-parse",
        "native_decode": True,
        "known_gaps": ["message-boundary-edge-cases", "large-mailbox-pagination", "thread-graph-validation"],
    },
    "maildir": {
        "family": "maildir-message",
        "support_tier": "parsed-triage",
        "native_decode": True,
        "known_gaps": ["maildir-flag-semantics", "folder-state-correlation", "thread-graph-validation"],
    },
    "pst": {
        "family": "mapi-container",
        "support_tier": "bounded-string-inventory",
        "native_decode": False,
        "known_gaps": ["folder-tree", "message-flags", "deleted-items", "corrupt-store-recovery", "attachments"],
    },
    "ost": {
        "family": "exchange-cache",
        "support_tier": "bounded-string-inventory",
        "native_decode": False,
        "known_gaps": ["server-sync-state", "folder-tree", "deleted-items", "conversion-differences", "attachments"],
    },
    "msg": {
        "family": "mapi-message",
        "support_tier": "bounded-string-inventory",
        "native_decode": False,
        "known_gaps": ["mapi-properties", "embedded-attachments", "rtf-body", "recipient-tables"],
    },
}


class EmailArtifactsProvider:
    collector_kind = "email"
    name = "email-artifacts"
    description = "Email EML/MBOX parsing and PST/OST/MSG bounded mailbox inventory"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
            if path.is_file() and path.suffix.lower() in EMAIL_SUFFIXES:
                yield from collect_email_path(path)
            elif path.is_file() and is_maildir_message(path):
                yield from collect_maildir_message(path)


def collect_email_path(path: Path) -> Iterable[ArtifactRecord]:
    suffix = path.suffix.lower()
    if suffix == ".eml":
        yield from collect_eml(path)
    elif suffix == ".emlx":
        yield from collect_emlx(path)
    elif suffix == ".mbox":
        yield from collect_mbox(path)
    else:
        yield collect_mail_container(path)


def collect_eml(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    try:
        message = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    except OSError:
        return
    yield build_message_record(path, source_hashes, 0, message, source_format="eml")


def collect_emlx(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    try:
        data = strip_emlx_length_prefix(path.read_bytes())
        message = email.message_from_bytes(data, policy=policy.default)
    except OSError:
        return
    yield build_message_record(path, source_hashes, 0, message, source_format="emlx")


def collect_maildir_message(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    try:
        message = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    except OSError:
        return
    yield build_message_record(path, source_hashes, 0, message, source_format="maildir")


def collect_mbox(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = compute_hashes(path)
    try:
        data = path.read_bytes()
    except OSError:
        return
    chunks = re.split(rb"\n(?=From [^\n]+\n)", data)
    emitted = 0
    for chunk in chunks[:MAX_MBOX_MESSAGES]:
        if chunk.startswith(b"From "):
            chunk = chunk.split(b"\n", 1)[1] if b"\n" in chunk else b""
        if not chunk.strip():
            continue
        message = email.message_from_bytes(chunk, policy=policy.default)
        yield build_message_record(path, source_hashes, emitted, message, source_format="mbox")
        emitted += 1
    yield build_mailbox_record(
        path,
        source_hashes,
        source_format="mbox",
        message_count=emitted,
        validation_checks={
            "parsed_message_count": emitted,
            "message_limit": MAX_MBOX_MESSAGES,
            "container_decoder": "python-email-bounded-mbox",
            "commercial_parser_validated": False,
        },
    )


def collect_mail_container(path: Path) -> ArtifactRecord:
    source_hashes = compute_hashes(path)
    blob = read_prefix(path, CONTAINER_SCAN_LIMIT)
    emails = sorted({item.decode("ascii", errors="ignore") for item in EMAIL_RE.findall(blob)})[:MAX_CONTAINER_CANDIDATES]
    subjects = sorted({decode_bytes(item) for item in SUBJECT_RE.findall(blob) if decode_bytes(item)})[:MAX_CONTAINER_CANDIDATES]
    strings = bounded_strings(blob)[:MAX_CONTAINER_CANDIDATES]
    return build_mailbox_record(
        path,
        source_hashes,
        source_format=path.suffix.lower().lstrip("."),
        message_count=0,
        validation_checks={
            "bounded_scan_bytes": min(len(blob), CONTAINER_SCAN_LIMIT),
            "email_candidate_count": len(emails),
            "subject_candidate_count": len(subjects),
            "native_mailbox_decoding_available": False,
            "commercial_parser_validated": False,
        },
        extra_details={
            "email_candidates": emails,
            "subject_candidates": subjects,
            "string_candidates": strings,
            "risk_flags": ["mailbox-container-candidate"] + (["email-address-candidates"] if emails else []),
        },
    )


def build_message_record(
    path: Path,
    source_hashes: dict[str, str],
    source_index: int,
    message: EmailMessage,
    *,
    source_format: str,
) -> ArtifactRecord:
    body_preview, body_hash, body_truncated = message_body_summary(message)
    attachments = attachment_summaries(message)
    details = {
        "parser": "email-artifacts",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_index": source_index,
        "source_hashes": source_hashes,
        "message_id": header_value(message, "Message-ID"),
        "thread_parent_id": header_value(message, "In-Reply-To"),
        "subject": header_value(message, "Subject"),
        "from": header_value(message, "From"),
        "to": header_value(message, "To"),
        "cc": header_value(message, "Cc"),
        "date": header_value(message, "Date"),
        "body_preview": body_preview,
        "body_sha256": body_hash,
        "body_truncated": body_truncated,
        "attachment_count": len(attachments),
        "attachments": attachments,
        "validation_checks": {
            "headers_parsed": True,
            "body_present": bool(body_preview),
            "attachment_metadata_only": True,
            "commercial_parser_validated": False,
        },
        "email_validation_matrix": email_validation_matrix(source_format, {"headers_parsed": True, "body_present": bool(body_preview)}),
        "email_report_grade_assessment": email_report_grade_assessment(source_format),
        "email_native_capabilities": dict(EMAIL_NATIVE_CAPABILITIES),
        "email_format_profile": email_format_profile(source_format),
        "email_issue_matrix": email_issue_matrix(source_format),
        "forensic_review": email_forensic_review(
            source_format=source_format,
            primary_evidence=[
                f"message_id={header_value(message, 'Message-ID')}",
                f"subject={header_value(message, 'Subject')}",
                f"from={header_value(message, 'From')}",
                f"attachments={len(attachments)}",
            ],
        ),
        "commercial_gap_ids": ["#36"],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": email_blockers(source_format),
        "risk_flags": email_risk_flags(header_value(message, "Subject"), body_preview, attachments),
    }
    return ArtifactRecord(
        provider=EmailArtifactsProvider.name,
        artifact_type="email-message",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def build_mailbox_record(
    path: Path,
    source_hashes: dict[str, str],
    *,
    source_format: str,
    message_count: int,
    validation_checks: dict[str, object],
    extra_details: dict[str, object] | None = None,
) -> ArtifactRecord:
    details = {
        "parser": "email-artifacts",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_hashes": source_hashes,
        "mailbox_name": path.name,
        "message_count": message_count,
        "validation_checks": validation_checks,
        "email_validation_matrix": email_validation_matrix(source_format, validation_checks),
        "email_report_grade_assessment": email_report_grade_assessment(source_format),
        "email_native_capabilities": dict(EMAIL_NATIVE_CAPABILITIES),
        "email_format_profile": email_format_profile(source_format),
        "email_issue_matrix": email_issue_matrix(source_format),
        "forensic_review": email_forensic_review(
            source_format=source_format,
            primary_evidence=[
                f"mailbox={path.name}",
                f"message_count={message_count}",
                f"source_format={source_format}",
            ],
        ),
        "commercial_gap_ids": ["#36"],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": email_blockers(source_format),
        "legal_warning": "Mailbox artifacts may contain privileged or personal communications. Review authorization and scope before analysis or export.",
        "reporting_guidance": "Use bounded container candidates as triage pivots; validate PST/OST/MSG content with a dedicated mailbox parser before testimony.",
    }
    if extra_details:
        details.update(extra_details)
    return ArtifactRecord(
        provider=EmailArtifactsProvider.name,
        artifact_type="email-mailbox",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )


def message_body_summary(message: EmailMessage) -> tuple[str, str, bool]:
    parts: list[str] = []
    for part in message.walk() if message.is_multipart() else [message]:
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            text = part.get_content()
        except (LookupError, UnicodeDecodeError, AttributeError):
            continue
        if isinstance(text, str):
            parts.append(strip_html(text) if content_type == "text/html" else text)
    body = "\n".join(item.strip() for item in parts if item.strip())
    preview = " ".join(body.split())[:4000]
    return preview, sha256_text(body) if body else "", len(body) > len(preview)


def attachment_summaries(message: EmailMessage) -> list[dict[str, object]]:
    attachments: list[dict[str, object]] = []
    for part in message.walk() if message.is_multipart() else []:
        if part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": part.get_filename() or "",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            }
        )
    return attachments[:100]


def strip_emlx_length_prefix(data: bytes) -> bytes:
    first_line, separator, rest = data.partition(b"\n")
    if separator and first_line.strip().isdigit():
        return rest
    return data


def is_maildir_message(path: Path) -> bool:
    if path.parent.name not in {"cur", "new"}:
        return False
    return bool(path.parent.parent.name)


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def bounded_strings(blob: bytes) -> list[str]:
    ascii_strings = [item.decode("latin-1", errors="ignore") for item in re.findall(rb"[\x20-\x7e]{6,240}", blob)]
    utf16_strings = [
        item.decode("utf-16le", errors="ignore")
        for item in re.findall(rb"(?:[\x20-\x7e]\x00){6,240}", blob)
    ]
    seen: set[str] = set()
    result: list[str] = []
    for item in [*ascii_strings, *utf16_strings]:
        text = " ".join(item.split())
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def strip_html(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", value)


def header_value(message: EmailMessage, name: str) -> str:
    value = message.get(name)
    return str(value or "")


def decode_bytes(value: bytes) -> str:
    for encoding in ("utf-8", "utf-16le", "latin-1"):
        try:
            return value.decode(encoding, errors="ignore").strip()
        except UnicodeDecodeError:
            continue
    return ""


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def email_risk_flags(subject: str, body: str, attachments: list[dict[str, object]]) -> list[str]:
    lowered = f"{subject} {body}".lower()
    flags: list[str] = []
    if any(token in lowered for token in ("password", "otp", "invoice", "wire", "payment", "credential")):
        flags.append("sensitive-email-content")
    if attachments:
        flags.append("email-attachments")
    return flags


def email_validation_matrix(source_format: str, checks: dict[str, object]) -> list[dict[str, object]]:
    native_container = source_format in {"pst", "ost", "msg"}
    return [
        {
            "id": "source-hash-and-basic-parse",
            "label": "Source is hashed and basic email/mailbox fields are extracted",
            "passed": True,
            "severity": "critical",
        },
        {
            "id": "message-content-present",
            "label": "Message headers/body or mailbox candidates are present",
            "passed": bool(
                checks.get("headers_parsed")
                or checks.get("parsed_message_count")
                or checks.get("email_candidate_count")
                or checks.get("subject_candidate_count")
            ),
            "severity": "high",
        },
        {
            "id": "native-container-object-decode",
            "label": "PST/OST/MSG folder/message/deleted object model decoded",
            "passed": not native_container,
            "severity": "critical",
        },
        {
            "id": "thread-dedup-validation",
            "label": "Conversation threading, duplicates, timezone, and attachment behavior validated",
            "passed": False,
            "severity": "critical",
        },
    ]


def email_report_grade_assessment(source_format: str) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#36"],
        "source_format": source_format,
        "blockers": list(EMAIL_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Validate PST/OST/MSG content with a dedicated mailbox parser before report-grade conclusions.",
            "Review privilege/scope, threading, duplicate handling, and attachment extraction against known-answer mailboxes.",
        ],
    }


def email_format_profile(source_format: str) -> dict[str, object]:
    profile = EMAIL_FORMAT_PROFILES.get(source_format, {})
    return {
        "source_format": source_format,
        "family": profile.get("family", "unknown-mail-format"),
        "support_tier": profile.get("support_tier", "candidate-inventory"),
        "native_decode": bool(profile.get("native_decode")),
        "known_gaps": list(profile.get("known_gaps", ["format-specific-validation-required"])),
        "reporting_boundary": "triage-candidate-until-known-answer-validated",
    }


def email_issue_matrix(source_format: str) -> list[dict[str, object]]:
    profile = EMAIL_FORMAT_PROFILES.get(source_format, {})
    native_decode = bool(profile.get("native_decode"))
    is_mapi = source_format in {"pst", "ost", "msg"}
    return [
        {
            "id": "mime-structure-and-trace",
            "label": "MIME structure, headers, trace fields, and hidden timestamps are reviewed",
            "passed": source_format in {"eml", "emlx", "mbox", "maildir"},
            "severity": "critical",
        },
        {
            "id": "mapi-native-object-decode",
            "label": "PST/OST/MSG MAPI objects are natively decoded",
            "passed": False if is_mapi else native_decode,
            "severity": "critical" if is_mapi else "medium",
        },
        {
            "id": "corrupt-store-recovery",
            "label": "Corrupt/orphaned mailbox data is recovered and compared against alternate tools",
            "passed": False,
            "severity": "critical" if source_format in {"pst", "ost"} else "high",
        },
        {
            "id": "thread-and-dedup",
            "label": "Message-ID/In-Reply-To conversation graph and duplicate handling are validated",
            "passed": False,
            "severity": "high",
        },
        {
            "id": "auth-signature-crypto",
            "label": "DKIM/ARC/SPF plus S/MIME/OpenPGP state are validated where present",
            "passed": False,
            "severity": "high",
        },
        {
            "id": "attachment-extraction",
            "label": "Attachment bytes, hashes, nested messages, and privilege scope are validated",
            "passed": False,
            "severity": "critical",
        },
    ]


def email_forensic_review(*, source_format: str, primary_evidence: list[str]) -> dict[str, object]:
    return build_forensic_review(
        gap_id="#36",
        artifact_goal="Email mailbox/message parsing, attachment metadata, threading, and report-grade mailbox validation",
        primary_evidence=primary_evidence,
        validation_required=True,
        report_grade_assessment=email_report_grade_assessment(source_format),
        blockers=EMAIL_REPORT_GRADE_BLOCKERS,
        caveats=[
            "EML/MBOX rows are parsed for triage and require broad corpus validation for testimony.",
            "PST/OST/MSG rows are bounded candidate inventory until native mailbox object decoding is implemented.",
        ],
    )


def email_blockers(source_format: str) -> list[str]:
    if source_format in {"pst", "ost", "msg"}:
        return [
            f"{source_format.upper()} support is bounded string/candidate inventory only, not full mailbox object decoding.",
            "Folder hierarchy, message flags, deleted items, embedded attachments, and conversation threading require a dedicated validated parser.",
            "Privilege/scope review is required before exporting or reporting mailbox content.",
        ]
    return [
        "EML/MBOX parsing is fixture-backed but not independently validated against a broad mailbox corpus.",
        "Message threading, duplicate suppression, timezone normalization, and attachment content analysis require further validation.",
    ]
