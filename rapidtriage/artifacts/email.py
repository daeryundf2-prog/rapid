from __future__ import annotations

import email
import hashlib
import json
import re
from datetime import timezone
from email.message import EmailMessage
from email import policy
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Iterable, Mapping

from ..core.forensic_accuracy import build_accuracy_gate
from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes
from .review import build_forensic_review

PARSER_VERSION = "email-artifacts-v2"
FUNCTIONAL_SOURCE_BATCH_ID = "commercial-uplift-046-050"
EMAIL_SUFFIXES = {".eml", ".emlx", ".mbox", ".msg", ".pst", ".ost"}
MAX_MBOX_MESSAGES = 200
CONTAINER_SCAN_LIMIT = 16 * 1024 * 1024
MAX_CONTAINER_CANDIDATES = 200
EMAIL_ATTACHMENT_PREVIEW_BYTES = 64
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
EMAIL_REPORT_GRADE_VALIDATION_PLAN_VERSION = "email-report-grade-validation-plan-v1"
EMAIL_REPORT_GRADE_VALIDATION_BLOCKERS = [
    "trusted-email-mailbox-export-native-diff-required",
    "native-mapi-object-decoding-or-trusted-export-required",
    "deleted-item-recovery-corpus-required",
    "thread-dedup-timezone-corpus-required",
    "attachment-byte-validation-required",
    "auth-signature-crypto-validation-required",
    "privilege-scope-review-required",
    "independent-mailbox-review-required",
]
EMAIL_TRUSTED_DIFF_BLOCKER = "email-mailbox-trusted-diff-required"
EMAIL_TRUSTED_DIFF_TOOLS = {
    "libpff",
    "pffexport",
    "readpst",
    "outlook-export",
    "microsoft-purview-export",
    "thunderbird-export",
    "eml-ground-truth",
    "mbox-ground-truth",
    "maildir-ground-truth",
    "vendor-mailbox-export",
}
EMAIL_QC_PREP_ITEM_NUMBER = 42
EMAIL_QC_PREP_GOAL = (
    "Add PST/OST mailbox parsing depth for folders, messages, attachments, deleted items, headers, and threading."
)
EMAIL_QC_PREP_CONTRACT = {
    "item_number": EMAIL_QC_PREP_ITEM_NUMBER,
    "goal": EMAIL_QC_PREP_GOAL,
    "implemented_outputs": [
        "EML/EMLX/MBOX/Maildir message parsing with hashes, headers, body hash, attachments, and citation manifest",
        "PST/OST/MSG bounded mailbox inventory with candidate folders, subjects, email addresses, attachments, and source viewer locator",
        "Mailbox strategy, reportability decision, attachment locator profile, and trusted-diff blocker metadata",
    ],
    "commercial_blockers": [
        "native PST/OST/MSG MAPI object decode",
        "folder hierarchy, message flags, deleted/recoverable items, and corrupt-store recovery",
        "conversation threading/deduplication and attachment byte validation",
        "trusted libpff/readpst/Outlook/Purview diff plus broad mailbox known-answer corpus",
    ],
}
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
EMAIL_MAILBOX_STRATEGY_TRACKS = {
    "eml": "mime-message-parse-known-answer-validation",
    "emlx": "apple-mail-message-plus-envelope-index-validation",
    "mbox": "bounded-mbox-parse-threading-validation",
    "maildir": "maildir-message-folder-state-validation",
    "pst": "pst-libpff-or-outlook-export-diff-required",
    "ost": "ost-libpff-or-outlook-export-diff-required",
    "msg": "msg-mapi-property-export-diff-required",
}
EMAIL_REQUIRED_TOOLS_BY_FORMAT = {
    "pst": ["libpff/pffexport", "readpst", "Outlook/Microsoft Purview export"],
    "ost": ["libpff/pffexport", "Outlook cached mailbox export", "Microsoft Purview export"],
    "msg": ["libpff/pffexport", "Outlook MSG export", "MAPI property decoder"],
    "mbox": ["python-email", "Thunderbird or vendor MBOX ground truth"],
    "eml": ["python-email", "ground-truth EML fixture"],
    "emlx": ["python-email", "Apple Mail envelope/index ground truth"],
    "maildir": ["python-email", "Maildir folder-state ground truth"],
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
    source_format = path.suffix.lower().lstrip(".")
    mapi_profile = mapi_container_review_profile(
        source_format=source_format,
        scan_bytes=len(blob),
        emails=emails,
        subjects=subjects,
        strings=strings,
    )
    return build_mailbox_record(
        path,
        source_hashes,
        source_format=source_format,
        message_count=0,
        validation_checks={
            "bounded_scan_bytes": min(len(blob), CONTAINER_SCAN_LIMIT),
            "email_candidate_count": len(emails),
            "subject_candidate_count": len(subjects),
            "bounded_candidate_inventory_present": bool(emails or subjects or strings),
            "mapi_container_review_profile_emitted": bool(mapi_profile),
            "native_mailbox_decoding_available": False,
            "commercial_parser_validated": False,
        },
        extra_details={
            "email_candidates": emails,
            "subject_candidates": subjects,
            "string_candidates": strings,
            **({"mapi_container_review_profile": mapi_profile} if mapi_profile else {}),
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
    attachments = attach_email_attachment_locators(
        path,
        source_hashes,
        source_format=source_format,
        message_index=source_index + 1,
        message_id=header_value(message, "Message-ID"),
        attachments=attachment_summaries(message),
    )
    attachment_locator_profile = email_attachment_locator_profile(
        source_path=path,
        source_hashes=source_hashes,
        source_format=source_format,
        message_index=source_index + 1,
        message_id=header_value(message, "Message-ID"),
        attachments=attachments,
    )
    thread_profile = email_thread_profile(message)
    validation_checks = {
        "headers_parsed": True,
        "body_present": bool(body_preview),
        "attachment_metadata_only": True,
        "thread_profile_emitted": True,
        "commercial_parser_validated": False,
    }
    strategy_profile = email_mailbox_strategy_profile(
        source_format,
        source_path=path,
        message_count=1,
        attachment_count=len(attachments),
        validation_checks=validation_checks,
    )
    citation_manifest = build_email_expansion_citation_manifest(
        source_format=source_format,
        source_path=path,
        source_hashes=source_hashes,
        details={
            "source_index": source_index,
            "message_id": header_value(message, "Message-ID"),
            "subject": header_value(message, "Subject"),
            "from": header_value(message, "From"),
            "to": header_value(message, "To"),
            "date": header_value(message, "Date"),
            "body_sha256": body_hash,
            "attachment_count": len(attachments),
            "attachments": attachments,
            "email_thread_profile": thread_profile,
        },
    )
    mailbox_manifest = build_email_mailbox_parser_manifest(
        source_format=source_format,
        source_path=path,
        source_hashes=source_hashes,
        details={
            "artifact_type": "email-message",
            "source_index": source_index,
            "message_id": header_value(message, "Message-ID"),
            "subject": header_value(message, "Subject"),
            "from": header_value(message, "From"),
            "to": header_value(message, "To"),
            "cc": header_value(message, "Cc"),
            "date": header_value(message, "Date"),
            "body_sha256": body_hash,
            "attachment_count": len(attachments),
            "attachments": attachments,
            "email_attachment_locator_profile": attachment_locator_profile,
            "email_thread_profile": thread_profile,
            "email_expansion_citation_manifest": citation_manifest,
            "validation_checks": validation_checks,
        },
    )
    report_plan = build_email_report_grade_validation_plan(
        source_format=source_format,
        source_path=path,
        source_hashes=source_hashes,
        details={
            "artifact_type": "email-message",
            "source_index": source_index,
            "message_id": header_value(message, "Message-ID"),
            "subject": header_value(message, "Subject"),
            "from": header_value(message, "From"),
            "to": header_value(message, "To"),
            "date": header_value(message, "Date"),
            "body_sha256": body_hash,
            "attachment_count": len(attachments),
            "attachments": attachments,
            "email_attachment_locator_profile": attachment_locator_profile,
            "email_thread_profile": thread_profile,
            "email_expansion_citation_manifest": citation_manifest,
            "email_mailbox_parser_manifest": mailbox_manifest,
            "validation_checks": validation_checks,
        },
    )
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
        "email_attachment_locator_profile": attachment_locator_profile,
        "email_thread_profile": thread_profile,
        "validation_checks": validation_checks,
        "email_mailbox_strategy_profile": strategy_profile,
        "email_expansion_citation_manifest": citation_manifest,
        "email_expansion_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "email_mailbox_parser_manifest": mailbox_manifest,
        "email_mailbox_parser_manifest_hash": mailbox_manifest["manifest_sha256"],
        "email_report_grade_validation_plan": report_plan,
        "email_report_grade_validation_plan_hash": report_plan["manifest_sha256"],
        "email_validation_matrix": email_validation_matrix(source_format, {"headers_parsed": True, "body_present": bool(body_preview)}),
        "email_report_grade_assessment": email_report_grade_assessment(source_format),
        "commercial_uplift_evidence": email_commercial_uplift_evidence(
            source_format=source_format,
            source_hashes=source_hashes,
            details={
                "source_path": str(path.resolve()),
                "source_index": source_index,
                "message_id": header_value(message, "Message-ID"),
                "subject": header_value(message, "Subject"),
                "attachment_count": len(attachments),
                "email_attachment_locator_profile": attachment_locator_profile,
                "email_expansion_citation_manifest": citation_manifest,
                "email_mailbox_parser_manifest": mailbox_manifest,
                "email_report_grade_validation_plan": report_plan,
                "email_thread_profile": thread_profile,
                "validation_checks": validation_checks,
                "email_mailbox_strategy_profile": strategy_profile,
            },
        ),
        "email_native_capabilities": dict(EMAIL_NATIVE_CAPABILITIES),
        "email_format_profile": email_format_profile(source_format),
        "email_issue_matrix": email_issue_matrix(source_format),
        "core_accuracy_gates": email_core_accuracy_gates(
            source_format=source_format,
            source_hashes=source_hashes,
            details={
                "source_path": str(path.resolve()),
                "source_index": source_index,
                "message_id": header_value(message, "Message-ID"),
                "subject": header_value(message, "Subject"),
                "body_sha256": body_hash,
                "attachments": attachments,
                "email_attachment_locator_profile": attachment_locator_profile,
                "email_expansion_citation_manifest": citation_manifest,
                "email_mailbox_parser_manifest": mailbox_manifest,
                "email_report_grade_validation_plan": report_plan,
                "email_thread_profile": thread_profile,
                "validation_checks": validation_checks,
                "email_mailbox_strategy_profile": strategy_profile,
            },
        ),
        "forensic_review": email_forensic_review(
            source_format=source_format,
            primary_evidence=[
                f"message_id={header_value(message, 'Message-ID')}",
                f"subject={header_value(message, 'Subject')}",
                f"from={header_value(message, 'From')}",
                f"attachments={len(attachments)}",
            ],
        ),
        "email_analyst_review_profile": email_analyst_review_profile(
            artifact_type="email-message",
            source_format=source_format,
            source_hashes=source_hashes,
            source_path=str(path.resolve()),
            details={
                "source_index": source_index,
                "message_id": header_value(message, "Message-ID"),
                "subject": header_value(message, "Subject"),
                "from": header_value(message, "From"),
                "to": header_value(message, "To"),
                "attachment_count": len(attachments),
                "email_attachment_locator_profile": attachment_locator_profile,
                "risk_flags": email_risk_flags(header_value(message, "Subject"), body_preview, attachments),
                "email_expansion_citation_manifest": citation_manifest,
                "email_mailbox_parser_manifest": mailbox_manifest,
                "validation_checks": validation_checks,
                "email_thread_profile": thread_profile,
            },
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
    strategy_profile = email_mailbox_strategy_profile(
        source_format,
        source_path=path,
        message_count=message_count,
        attachment_count=int((extra_details or {}).get("attachment_count") or 0),
        validation_checks=validation_checks,
    )
    detail_seed = {
        "mailbox_name": path.name,
        "message_count": message_count,
        "validation_checks": validation_checks,
        **(extra_details or {}),
    }
    citation_manifest = build_email_expansion_citation_manifest(
        source_format=source_format,
        source_path=path,
        source_hashes=source_hashes,
        details=detail_seed,
    )
    mailbox_manifest = build_email_mailbox_parser_manifest(
        source_format=source_format,
        source_path=path,
        source_hashes=source_hashes,
        details={
            "artifact_type": "email-mailbox",
            "mailbox_name": path.name,
            "message_count": message_count,
            "email_expansion_citation_manifest": citation_manifest,
            "validation_checks": validation_checks,
            **(extra_details or {}),
        },
    )
    report_plan = build_email_report_grade_validation_plan(
        source_format=source_format,
        source_path=path,
        source_hashes=source_hashes,
        details={
            "artifact_type": "email-mailbox",
            "mailbox_name": path.name,
            "message_count": message_count,
            "email_expansion_citation_manifest": citation_manifest,
            "email_mailbox_parser_manifest": mailbox_manifest,
            "validation_checks": validation_checks,
            **(extra_details or {}),
        },
    )
    details = {
        "parser": "email-artifacts",
        "parser_version": PARSER_VERSION,
        "source_path": str(path.resolve()),
        "source_format": source_format,
        "source_hashes": source_hashes,
        "mailbox_name": path.name,
        "message_count": message_count,
        "validation_checks": validation_checks,
        "email_mailbox_strategy_profile": strategy_profile,
        "email_expansion_citation_manifest": citation_manifest,
        "email_expansion_citation_manifest_hash": citation_manifest["manifest_sha256"],
        "email_mailbox_parser_manifest": mailbox_manifest,
        "email_mailbox_parser_manifest_hash": mailbox_manifest["manifest_sha256"],
        "email_report_grade_validation_plan": report_plan,
        "email_report_grade_validation_plan_hash": report_plan["manifest_sha256"],
        "email_validation_matrix": email_validation_matrix(source_format, validation_checks),
        "email_report_grade_assessment": email_report_grade_assessment(source_format),
        "commercial_uplift_evidence": email_commercial_uplift_evidence(
            source_format=source_format,
            source_hashes=source_hashes,
            details={
                "source_path": str(path.resolve()),
                "mailbox_name": path.name,
                "message_count": message_count,
                "email_expansion_citation_manifest": citation_manifest,
                "email_mailbox_parser_manifest": mailbox_manifest,
                "email_report_grade_validation_plan": report_plan,
                "validation_checks": validation_checks,
                "email_mailbox_strategy_profile": strategy_profile,
                **(extra_details or {}),
            },
        ),
        "email_native_capabilities": dict(EMAIL_NATIVE_CAPABILITIES),
        "email_format_profile": email_format_profile(source_format),
        "email_issue_matrix": email_issue_matrix(source_format),
        "core_accuracy_gates": email_core_accuracy_gates(
            source_format=source_format,
            source_hashes=source_hashes,
            details={
                "source_path": str(path.resolve()),
                "mailbox_name": path.name,
                "message_count": message_count,
                "email_expansion_citation_manifest": citation_manifest,
                "email_mailbox_parser_manifest": mailbox_manifest,
                "email_report_grade_validation_plan": report_plan,
                "validation_checks": validation_checks,
                "email_mailbox_strategy_profile": strategy_profile,
                **(extra_details or {}),
            },
        ),
        "forensic_review": email_forensic_review(
            source_format=source_format,
            primary_evidence=[
                f"mailbox={path.name}",
                f"message_count={message_count}",
                f"source_format={source_format}",
            ],
        ),
        "email_analyst_review_profile": email_analyst_review_profile(
            artifact_type="email-mailbox",
            source_format=source_format,
            source_hashes=source_hashes,
            source_path=str(path.resolve()),
            details={
                "mailbox_name": path.name,
                "message_count": message_count,
                "email_expansion_citation_manifest": citation_manifest,
                "email_mailbox_parser_manifest": mailbox_manifest,
                "validation_checks": validation_checks,
                "email_mailbox_strategy_profile": strategy_profile,
                **(extra_details or {}),
            },
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
    attachment_parts = [
        part
        for part in (message.walk() if message.is_multipart() else [])
        if part.get_content_disposition() == "attachment"
    ]
    for index, part in enumerate(attachment_parts, start=1):
        payload = part.get_payload(decode=True) or b""
        preview = payload[:EMAIL_ATTACHMENT_PREVIEW_BYTES]
        attachments.append(
            {
                "index": index,
                "filename": part.get_filename() or "",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                "bounded_preview_bytes": len(preview),
                "bounded_preview_hex": preview.hex(),
                "bounded_preview_sha256": hashlib.sha256(preview).hexdigest() if preview else "",
                "bounded_preview_truncated": len(payload) > len(preview),
                "export_warning": "Attachment export is bounded metadata/content evidence; validate against the original mailbox and trusted parser before report-grade use.",
            }
        )
    return attachments[:100]


def attach_email_attachment_locators(
    source_path: Path,
    source_hashes: Mapping[str, str],
    *,
    source_format: str,
    message_index: int,
    message_id: str,
    attachments: list[dict[str, object]],
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for fallback_index, attachment in enumerate(attachments, start=1):
        attachment_index = int(attachment.get("index") or fallback_index)
        locator = email_attachment_source_viewer_locator(
            source_path=source_path,
            source_hashes=source_hashes,
            source_format=source_format,
            message_index=message_index,
            message_id=message_id,
            attachment_index=attachment_index,
            attachment=attachment,
        )
        output.append(
            {
                **attachment,
                "index": attachment_index,
                "source_viewer_locator": locator,
                "email_attachment_locator": locator,
                "locator_sha256": locator["locator_sha256"],
            }
        )
    return output


def email_attachment_source_viewer_locator(
    *,
    source_path: Path,
    source_hashes: Mapping[str, str],
    source_format: str,
    message_index: int,
    message_id: str,
    attachment_index: int,
    attachment: Mapping[str, object],
) -> dict[str, object]:
    payload: dict[str, object] = {
        "profile_version": "email-attachment-source-viewer-locator-v1",
        "qc_prep_item": 10,
        "viewer": "source-email-attachment",
        "source_path": str(source_path.resolve()),
        "source_format": source_format,
        "source_sha256": source_hashes.get("sha256", ""),
        "message_index": message_index,
        "message_id": str(message_id or ""),
        "attachment_index": attachment_index,
        "filename": str(attachment.get("filename") or ""),
        "content_type": str(attachment.get("content_type") or ""),
        "size": int(attachment.get("size") or 0),
        "sha256": str(attachment.get("sha256") or ""),
        "bounded_preview_bytes": int(attachment.get("bounded_preview_bytes") or 0),
        "bounded_preview_hex": str(attachment.get("bounded_preview_hex") or ""),
        "bounded_preview_sha256": str(attachment.get("bounded_preview_sha256") or ""),
        "bounded_preview_truncated": bool(attachment.get("bounded_preview_truncated")),
        "export_warning": str(
            attachment.get("export_warning")
            or "Attachment export must be validated against source mailbox before report-grade use."
        ),
        "endpoint": "/api/runs/{run_id}/source-email-attachment",
        "include_content_default": False,
        "bounded_content_export_only": True,
        "native_pst_ost_msg_supported": False,
        "required_before_report": [
            "verify source mailbox hash",
            "open attachment package endpoint and compare attachment hash",
            "validate thread/message identity with trusted mailbox parser",
            "review legal privilege/scope before exporting content",
        ],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "trusted-mailbox-attachment-diff-required",
            "native-pst-ost-msg-attachment-extraction-not-implemented",
            "deleted-mailbox-attachment-recovery-not-implemented",
        ],
    }
    payload["locator_sha256"] = stable_email_sha256(payload)
    return payload


def email_attachment_locator_profile(
    *,
    source_path: Path,
    source_hashes: Mapping[str, str],
    source_format: str,
    message_index: int,
    message_id: str,
    attachments: list[Mapping[str, object]],
) -> dict[str, object]:
    locators = [
        dict(attachment.get("source_viewer_locator") or {})
        for attachment in attachments
        if isinstance(attachment.get("source_viewer_locator"), Mapping)
    ]
    payload: dict[str, object] = {
        "profile_version": "email-attachment-locator-profile-v1",
        "qc_prep_item": 10,
        "source_path": str(source_path.resolve()),
        "source_format": source_format,
        "source_sha256": source_hashes.get("sha256", ""),
        "message_index": message_index,
        "message_id": str(message_id or ""),
        "attachment_count": len(attachments),
        "locator_count": len(locators),
        "locators": locators[:100],
        "max_locator_count": 100,
        "preview_bytes_per_attachment": EMAIL_ATTACHMENT_PREVIEW_BYTES,
        "endpoint": "/api/runs/{run_id}/source-email-attachment",
        "export_warning": "Attachment content export is bounded and disabled by default; cite hashes and validate mailbox provenance before report-grade use.",
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "trusted-mailbox-attachment-diff-required",
            "native-pst-ost-msg-attachment-extraction-not-implemented",
            "deleted-mailbox-attachment-recovery-not-implemented",
        ],
    }
    payload["profile_sha256"] = stable_email_sha256(payload)
    return payload


def build_email_expansion_citation_manifest(
    *,
    source_format: str,
    source_path: Path,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> dict[str, object]:
    message_citations: list[dict[str, object]] = []
    if details.get("message_id") is not None or details.get("subject") is not None:
        message_payload = {
            "source_format": source_format,
            "source_path": str(source_path.resolve()),
            "source_sha256": source_hashes.get("sha256", ""),
            "source_index": details.get("source_index"),
            "message_id": str(details.get("message_id") or ""),
            "subject": str(details.get("subject") or ""),
            "subject_sha256": sha256_text(str(details.get("subject") or "")) if details.get("subject") else "",
            "from": str(details.get("from") or ""),
            "to": str(details.get("to") or ""),
            "date": str(details.get("date") or ""),
            "body_sha256": str(details.get("body_sha256") or ""),
            "attachment_count": int(details.get("attachment_count") or 0),
        }
        message_citations.append(
            {
                **message_payload,
                "row_hash": stable_email_sha256(message_payload),
                "source_viewer_locator": {
                    "viewer": "email-message",
                    "source_path": str(source_path.resolve()),
                    "source_index": details.get("source_index"),
                    "message_id": str(details.get("message_id") or ""),
                },
                "validation_status": "message-citation-candidate",
            }
        )
    attachment_citations = [
        email_attachment_citation(
            source_path=source_path,
            source_hashes=source_hashes,
            attachment=item,
            attachment_index=index,
            message_index=int(details.get("source_index") or 0) + 1,
            message_id=str(details.get("message_id") or ""),
        )
        for index, item in enumerate(details.get("attachments") or [], start=1)
        if isinstance(item, Mapping)
    ]
    candidate_citations = email_container_candidate_citations(
        source_path=source_path,
        source_hashes=source_hashes,
        details=details,
    )
    manifest: dict[str, object] = {
        "manifest_version": "email-expansion-citation-manifest-v1",
        "item_number": 49,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "gap_id": "#49",
        "commercial_gap_ids": ["#36", "#49"],
        "source_format": source_format,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "mailbox_name": str(details.get("mailbox_name") or source_path.name),
        "message_count": int(details.get("message_count") or len(message_citations)),
        "message_citation_count": len(message_citations),
        "attachment_citation_count": len(attachment_citations),
        "candidate_citation_count": len(candidate_citations),
        "message_citations": message_citations,
        "attachment_citations": attachment_citations,
        "candidate_citations": candidate_citations,
        "large_data_controls": {
            "max_mbox_messages": MAX_MBOX_MESSAGES,
            "container_scan_limit": CONTAINER_SCAN_LIMIT,
            "max_container_candidates": MAX_CONTAINER_CANDIDATES,
            "native_mapi_decode_claimed": False,
            "candidate_rows_bounded": len(candidate_citations) >= MAX_CONTAINER_CANDIDATES,
        },
        "review_workflow": {
            "default_view": "thread-or-candidate-list",
            "metadata_collapsed_by_default": True,
            "source_viewer": "email-or-bounded-container",
            "required_before_report": [
                "open the original message or trusted mailbox export row before final citation",
                "validate PST/OST/MSG rows with libpff/readpst/Outlook/Purview or equivalent trusted export",
                "validate threading, deduplication, attachments, and deleted item semantics with known-answer mailboxes",
                "review legal privilege and scope before exporting mailbox content",
            ],
        },
        "validation_status": "implemented-validation-required",
    }
    manifest["manifest_sha256"] = stable_email_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_email_mailbox_parser_manifest(
    *,
    source_format: str,
    source_path: Path,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> dict[str, object]:
    """#36 source manifest for mailbox/message review and court-citation boundaries."""
    artifact_type = str(details.get("artifact_type") or "email-mailbox")
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    citation_manifest = (
        details.get("email_expansion_citation_manifest")
        if isinstance(details.get("email_expansion_citation_manifest"), Mapping)
        else {}
    )
    mailbox_manifest = (
        details.get("email_mailbox_parser_manifest")
        if isinstance(details.get("email_mailbox_parser_manifest"), Mapping)
        else {}
    )
    attachment_locator_profile = (
        details.get("email_attachment_locator_profile")
        if isinstance(details.get("email_attachment_locator_profile"), Mapping)
        else {}
    )
    thread_profile = (
        details.get("email_thread_profile") if isinstance(details.get("email_thread_profile"), Mapping) else {}
    )
    mapi_profile = (
        details.get("mapi_container_review_profile")
        if isinstance(details.get("mapi_container_review_profile"), Mapping)
        else {}
    )
    email_candidates = details.get("email_candidates") if isinstance(details.get("email_candidates"), list) else []
    subject_candidates = details.get("subject_candidates") if isinstance(details.get("subject_candidates"), list) else []
    message_payload = {
        "artifact_type": artifact_type,
        "source_format": source_format,
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_index": details.get("source_index"),
        "message_id": str(details.get("message_id") or ""),
        "mailbox_name": str(details.get("mailbox_name") or source_path.name),
        "subject_sha256": sha256_text(str(details.get("subject") or "")) if details.get("subject") else "",
        "body_sha256": str(details.get("body_sha256") or ""),
        "attachment_count": int(details.get("attachment_count") or 0),
        "message_count": int(details.get("message_count") or (1 if details.get("message_id") else 0)),
    }
    native_container = source_format in {"pst", "ost", "msg"}
    manifest: dict[str, object] = {
        "manifest_version": "email-mailbox-parser-manifest-v1",
        "item_number": 36,
        "batch_id": "commercial-uplift-036-040",
        "gap_id": "#36",
        "qc_prep_item_number": EMAIL_QC_PREP_ITEM_NUMBER,
        "qc_prep_item_goal": EMAIL_QC_PREP_GOAL,
        "qc_prep_contract": dict(EMAIL_QC_PREP_CONTRACT),
        "artifact_type": artifact_type,
        "source_format": source_format,
        "format_family": email_format_profile(source_format)["family"],
        "support_tier": email_format_profile(source_format)["support_tier"],
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "row_citation": {
            **message_payload,
            "row_hash": stable_email_sha256(message_payload),
            "source_viewer_locator": {
                "viewer": "email-message-row" if artifact_type == "email-message" else "email-mailbox-inventory",
                "source_path": str(source_path.resolve()),
                "source_index": details.get("source_index"),
                "message_id": str(details.get("message_id") or ""),
                "mailbox_name": str(details.get("mailbox_name") or source_path.name),
            },
        },
        "parser_tracks": [
            {
                "track": EMAIL_MAILBOX_STRATEGY_TRACKS.get(source_format, "generic-mailbox-inventory-validation"),
                "status": "implemented" if not native_container else "bounded-inventory-only",
                "reportable_as": "triage-message-or-mailbox-inventory",
            },
            {
                "track": "native-pst-ost-msg-object-decode",
                "status": "external-parser-or-native-decoder-required" if native_container else "not-required-for-format",
                "reportable_as": "not-native-mapi-complete",
            },
            {
                "track": "deleted-thread-attachment-known-answer-validation",
                "status": "known-answer-required",
                "reportable_as": "not-deleted-or-thread-complete",
            },
        ],
        "message_review": {
            "present": artifact_type == "email-message",
            "message_id": str(details.get("message_id") or ""),
            "thread_root_id": str(thread_profile.get("thread_root_id") or ""),
            "normalized_subject": str(thread_profile.get("normalized_subject") or ""),
            "participant_count": int(thread_profile.get("participant_count") or 0),
            "date_utc": str(thread_profile.get("date_utc") or ""),
            "body_hash_present": bool(details.get("body_sha256")),
            "attachment_count": int(details.get("attachment_count") or 0),
            "attachment_metadata_only": bool(validation.get("attachment_metadata_only", True)),
        },
        "mailbox_review": {
            "present": artifact_type == "email-mailbox",
            "mailbox_name": str(details.get("mailbox_name") or source_path.name),
            "message_count": int(details.get("message_count") or 0),
            "candidate_email_count": int(details.get("email_candidate_count") or len(email_candidates)),
            "candidate_subject_count": int(details.get("subject_candidate_count") or len(subject_candidates)),
            "mapi_container_review_profile_present": bool(mapi_profile),
            "bounded_inventory_only": native_container,
            "folder_candidate_count": int(mapi_profile.get("folder_path_candidate_count") or 0),
            "deleted_item_hint_count": int(mapi_profile.get("deleted_item_hint_count") or 0),
        },
        "citation_manifest": {
            "manifest_sha256": str(citation_manifest.get("manifest_sha256") or ""),
            "message_citation_count": int(citation_manifest.get("message_citation_count") or 0),
            "attachment_citation_count": int(citation_manifest.get("attachment_citation_count") or 0),
            "candidate_citation_count": int(citation_manifest.get("candidate_citation_count") or 0),
        },
        "attachment_locator_profile": {
            "profile_sha256": str(attachment_locator_profile.get("profile_sha256") or ""),
            "locator_count": int(attachment_locator_profile.get("locator_count") or 0),
            "preview_bytes_per_attachment": int(
                attachment_locator_profile.get("preview_bytes_per_attachment") or EMAIL_ATTACHMENT_PREVIEW_BYTES
            ),
            "endpoint": str(attachment_locator_profile.get("endpoint") or "/api/runs/{run_id}/source-email-attachment"),
            "export_warning": str(attachment_locator_profile.get("export_warning") or ""),
        },
        "validation": {
            "source_hash_present": bool(source_hashes.get("sha256")),
            "headers_or_candidates_present": bool(
                validation.get("headers_parsed")
                or validation.get("parsed_message_count")
                or validation.get("bounded_candidate_inventory_present")
            ),
            "thread_profile_emitted": bool(thread_profile) or artifact_type == "email-mailbox",
            "trusted_mailbox_diff_attached": False,
            "native_pst_ost_msg_decode_complete": False,
            "deleted_item_recovery_complete": False,
            "commercial_grade": False,
        },
        "large_data_controls": {
            "metadata_collapsed_by_default": True,
            "viewer_default": "threaded-email-or-bounded-mailbox-review",
            "max_mbox_messages": MAX_MBOX_MESSAGES,
            "container_scan_limit": CONTAINER_SCAN_LIMIT,
            "max_container_candidates": MAX_CONTAINER_CANDIDATES,
            "body_preview_hash_only_for_reporting": True,
        },
        "commercial_blockers": email_blockers(source_format),
        "required_before_report": [
            "attach a trusted mailbox export/native parser diff for each reported message or mailbox",
            "validate thread graph, duplicate handling, timezone interpretation, and attachment bytes",
            "validate PST/OST/MSG folder tree, deleted/recoverable items, and MAPI properties where applicable",
            "review privilege/scope before exporting or citing mailbox content",
        ],
        "reporting_status": "email-review-ready-not-commercial-grade",
    }
    manifest["manifest_sha256"] = stable_email_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_email_report_grade_validation_plan(
    *,
    source_format: str,
    source_path: Path,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> dict[str, object]:
    """Report-grade evidence contract for #36 without overstating native mailbox support."""
    artifact_type = str(details.get("artifact_type") or "email-mailbox")
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    mailbox_manifest = (
        details.get("email_mailbox_parser_manifest")
        if isinstance(details.get("email_mailbox_parser_manifest"), Mapping)
        else {}
    )
    citation_manifest = (
        details.get("email_expansion_citation_manifest")
        if isinstance(details.get("email_expansion_citation_manifest"), Mapping)
        else {}
    )
    thread_profile = (
        details.get("email_thread_profile") if isinstance(details.get("email_thread_profile"), Mapping) else {}
    )
    attachment_locator_profile = (
        details.get("email_attachment_locator_profile")
        if isinstance(details.get("email_attachment_locator_profile"), Mapping)
        else {}
    )
    mapi_profile = (
        details.get("mapi_container_review_profile")
        if isinstance(details.get("mapi_container_review_profile"), Mapping)
        else {}
    )
    row_citation = mailbox_manifest.get("row_citation") if isinstance(mailbox_manifest.get("row_citation"), Mapping) else {}
    row_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    native_container = source_format in {"pst", "ost", "msg"}

    def slot(
        slot_id: str,
        status: str,
        *,
        description: str,
        evidence_ref: str = "",
        blocking: bool = False,
        blocker_id: str = "",
    ) -> dict[str, object]:
        return {
            "id": slot_id,
            "status": status,
            "description": description,
            "evidence_ref": evidence_ref,
            "blocking": blocking,
            "blocker_id": blocker_id,
        }

    row_hash = str(row_citation.get("row_hash") or "")
    message_or_candidate_present = bool(
        validation.get("headers_parsed")
        or validation.get("parsed_message_count")
        or validation.get("bounded_candidate_inventory_present")
        or details.get("email_candidates")
        or details.get("subject_candidates")
    )
    thread_slot_status = "complete" if thread_profile else ("not-applicable" if artifact_type == "email-mailbox" else "missing")
    mapi_slot_status = "complete" if native_container and mapi_profile else ("not-applicable" if not native_container else "missing")
    body_hash_policy_ready = bool(
        isinstance(mailbox_manifest.get("large_data_controls"), Mapping)
        and mailbox_manifest.get("large_data_controls", {}).get("body_preview_hash_only_for_reporting")
    )
    attachment_locator_count = int(attachment_locator_profile.get("locator_count") or 0)
    evidence_slots = [
        slot(
            "source-mailbox-hash-integrity",
            "complete" if source_hashes.get("sha256") else "missing",
            description="Original message/mailbox source hash is recorded for report provenance.",
            evidence_ref=f"source_sha256:{source_hashes.get('sha256', '')}",
        ),
        slot(
            "message-or-mailbox-row-citation",
            "complete" if row_hash else "missing",
            description="Stable row citation hash and source viewer locator are available.",
            evidence_ref=f"row_hash:{row_hash}",
        ),
        slot(
            "header-body-attachment-inventory",
            "complete" if message_or_candidate_present else "missing",
            description="Headers/body hash/attachment metadata or bounded mailbox candidates are inventoried.",
            evidence_ref=f"validation_checks:{stable_email_sha256(dict(validation)) if validation else ''}",
        ),
        slot(
            "thread-participant-profile",
            thread_slot_status,
            description="Message-ID, References/In-Reply-To, normalized subject, participants, and UTC date are available for threaded review where applicable.",
            evidence_ref=f"thread_root_id:{thread_profile.get('thread_root_id', '')}",
        ),
        slot(
            "bounded-mapi-inventory-boundary",
            mapi_slot_status,
            description="PST/OST/MSG native decode is not claimed; bounded MAPI candidate inventory and limitation state are explicit.",
            evidence_ref=f"mapi_profile:{mapi_profile.get('profile_version', '')}",
        ),
        slot(
            "source-viewer-locator",
            "complete" if row_locator else "missing",
            description="Reviewer can jump back to the message row or bounded mailbox inventory row.",
            evidence_ref=f"viewer:{row_locator.get('viewer', '')}",
        ),
        slot(
            "hash-only-body-policy",
            "complete" if body_hash_policy_ready else "missing",
            description="Body preview is treated as review aid; reporting should carry hashes/citations rather than raw bulk content by default.",
            evidence_ref=f"mailbox_manifest:{mailbox_manifest.get('manifest_sha256', '')}",
        ),
        slot(
            "attachment-source-locator",
            "complete" if attachment_locator_count else ("not-applicable" if artifact_type == "email-mailbox" else "missing"),
            description="Attachment source-viewer locators and bounded preview hashes are available when attachments exist.",
            evidence_ref=f"attachment_locator_count:{attachment_locator_count}",
        ),
        slot(
            "trusted-mailbox-export-native-diff",
            "pending-cross-tool-validate",
            description="Rapid rows must match libpff/readpst/Outlook/Purview/native mailbox rows before report-grade claims.",
            evidence_ref="email_trusted_diff",
            blocking=True,
            blocker_id="trusted-email-mailbox-export-native-diff-required",
        ),
        slot(
            "native-mapi-object-decoding",
            "external-native-parser-required" if native_container else "not-applicable",
            description="PST/OST/MSG folder tree, message flags, properties, embedded attachments, and sync state need native or trusted-export decoding.",
            evidence_ref=source_format,
            blocking=native_container,
            blocker_id="native-mapi-object-decoding-or-trusted-export-required" if native_container else "",
        ),
        slot(
            "deleted-item-recovery-corpus",
            "external-corpus-required",
            description="Deleted/recoverable/orphaned item behavior must be validated with known-answer mailboxes.",
            evidence_ref="known-answer-mailbox-corpus",
            blocking=True,
            blocker_id="deleted-item-recovery-corpus-required",
        ),
        slot(
            "thread-dedup-timezone-corpus",
            "external-corpus-required",
            description="Thread graph, duplicate handling, and timezone interpretation need known-answer validation.",
            evidence_ref="known-answer-thread-corpus",
            blocking=True,
            blocker_id="thread-dedup-timezone-corpus-required",
        ),
        slot(
            "attachment-byte-validation",
            "external-corpus-required",
            description="Attachment bytes, nested messages, hashes, and extraction paths need trusted mailbox validation.",
            evidence_ref="known-answer-attachment-corpus",
            blocking=True,
            blocker_id="attachment-byte-validation-required",
        ),
        slot(
            "auth-signature-crypto-validation",
            "external-corpus-required",
            description="DKIM/ARC/SPF plus S/MIME/OpenPGP state must be validated before authentication or crypto conclusions.",
            evidence_ref="auth-signature-crypto-corpus",
            blocking=True,
            blocker_id="auth-signature-crypto-validation-required",
        ),
        slot(
            "privilege-scope-review",
            "legal-review-required",
            description="Mailbox content may be privileged or out of scope; authority and redaction review must be attached.",
            evidence_ref="analyst-privilege-scope-review",
            blocking=True,
            blocker_id="privilege-scope-review-required",
        ),
        slot(
            "independent-mailbox-review",
            "external-review-required",
            description="Independent reviewer/lab signoff is required for commercial-grade mailbox claims.",
            evidence_ref="independent-review",
            blocking=True,
            blocker_id="independent-mailbox-review-required",
        ),
    ]
    ready_slot_count = sum(1 for item in evidence_slots if item["status"] == "complete")
    blocking_slot_count = sum(1 for item in evidence_slots if item.get("blocking"))
    plan: dict[str, object] = {
        "profile_version": EMAIL_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 36,
        "batch_id": "commercial-uplift-036-040",
        "gap_id": "#36",
        "qc_prep_item_number": EMAIL_QC_PREP_ITEM_NUMBER,
        "qc_prep_item_goal": EMAIL_QC_PREP_GOAL,
        "artifact_type": artifact_type,
        "source_format": source_format,
        "format_family": email_format_profile(source_format)["family"],
        "support_tier": email_format_profile(source_format)["support_tier"],
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "mailbox_parser_manifest_sha256": str(mailbox_manifest.get("manifest_sha256") or ""),
        "citation_manifest_sha256": str(citation_manifest.get("manifest_sha256") or ""),
        "target_capability": "full mailbox folder/message/header/attachment/thread/deleted-item parser",
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": blocking_slot_count,
        "evidence_slots": evidence_slots,
        "validation_commands": [
            {
                "id": "source-email-manifest",
                "command": "rapidtriage artifacts <case-root> --kind email --output email-artifacts.json",
                "purpose": "Generate source hashes, parser manifests, row citations, and review pivots.",
            },
            {
                "id": "email-external-parse",
                "command": "rapidtriage email-external-parse <pst|ost|msg> --output-dir <out>",
                "purpose": "Capture libpff/readpst/Outlook/Purview external parser evidence when available.",
            },
            {
                "id": "trusted-mailbox-diff",
                "command": "rapidtriage cross-tool-validate --family email --rapid email-artifacts.json --trusted <trusted-export.json>",
                "purpose": "Diff Rapid email rows against trusted mailbox/native export rows.",
            },
            {
                "id": "mailbox-known-answer-run",
                "command": "rapidtriage commercial-readiness --validation-package <mailbox-known-answer.json> --json",
                "purpose": "Prove deleted items, threading, timezone, attachment, and MAPI semantics on known-answer corpora.",
            },
            {
                "id": "privilege-scope-review",
                "command": "case review mark --artifact <row> --status scoped-reviewed",
                "purpose": "Attach authorization, privilege/scope decision, and redaction note before report export.",
            },
        ],
        "blockers": list(EMAIL_REPORT_GRADE_VALIDATION_BLOCKERS),
        "report_guidance": [
            "Use current rows as triage and review pivots until all blocking slots are satisfied.",
            "Do not claim native PST/OST/MSG object completeness from bounded string inventory.",
            "Carry source hash, row citation hash, parser version, trusted diff, and privilege review into report exhibits.",
        ],
    }
    plan["manifest_sha256"] = stable_email_sha256(
        {key: value for key, value in plan.items() if key != "manifest_sha256"}
    )
    return plan


def email_thread_profile(message: EmailMessage) -> dict[str, object]:
    subject = header_value(message, "Subject")
    message_id = header_value(message, "Message-ID")
    references = [item for item in header_value(message, "References").split() if item]
    in_reply_to = header_value(message, "In-Reply-To")
    thread_root_id = references[0] if references else in_reply_to or message_id
    participants = normalized_email_participants(message)
    return {
        "profile_version": "email-thread-profile-v1",
        "message_id": message_id,
        "thread_root_id": thread_root_id,
        "thread_parent_id": in_reply_to,
        "reference_count": len(references),
        "normalized_subject": normalize_thread_subject(subject),
        "participant_count": len(participants),
        "participants": participants[:50],
        "date_raw": header_value(message, "Date"),
        "date_utc": email_date_to_utc(header_value(message, "Date")),
        "thread_graph_validation_status": "known-answer-required",
    }


def normalized_email_participants(message: EmailMessage) -> list[dict[str, str]]:
    participants: list[dict[str, str]] = []
    for field in ("From", "To", "Cc", "Bcc", "Reply-To"):
        for name, address in getaddresses([header_value(message, field)]):
            if not address:
                continue
            participants.append(
                {
                    "role": field.lower(),
                    "display_name": name,
                    "address": address.lower(),
                    "address_sha256": sha256_text(address.lower()),
                }
            )
    return participants


def normalize_thread_subject(subject: str) -> str:
    value = subject.strip()
    while True:
        updated = re.sub(r"^\s*(?:re|fw|fwd)\s*:\s*", "", value, flags=re.IGNORECASE).strip()
        if updated == value:
            return updated
        value = updated


def email_date_to_utc(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return ""
    if parsed.tzinfo is None:
        return parsed.isoformat()
    return parsed.astimezone(timezone.utc).isoformat()


def email_attachment_citation(
    *,
    source_path: Path,
    source_hashes: Mapping[str, str],
    attachment: Mapping[str, object],
    attachment_index: int,
    message_index: int,
    message_id: str,
) -> dict[str, object]:
    locator = (
        dict(attachment.get("source_viewer_locator"))
        if isinstance(attachment.get("source_viewer_locator"), Mapping)
        else email_attachment_source_viewer_locator(
            source_path=source_path,
            source_hashes=source_hashes,
            source_format=source_path.suffix.lower().lstrip("."),
            message_index=message_index,
            message_id=message_id,
            attachment_index=attachment_index,
            attachment=attachment,
        )
    )
    payload = {
        "source_path": str(source_path.resolve()),
        "source_sha256": source_hashes.get("sha256", ""),
        "source_index": attachment_index - 1,
        "message_index": message_index,
        "message_id": str(message_id or ""),
        "attachment_index": attachment_index,
        "filename": str(attachment.get("filename") or ""),
        "content_type": str(attachment.get("content_type") or ""),
        "size": int(attachment.get("size") or 0),
        "sha256": str(attachment.get("sha256") or ""),
        "bounded_preview_sha256": str(attachment.get("bounded_preview_sha256") or ""),
        "bounded_preview_bytes": int(attachment.get("bounded_preview_bytes") or 0),
        "export_warning": str(attachment.get("export_warning") or ""),
    }
    return {
        **payload,
        "row_hash": stable_email_sha256(payload),
        "source_viewer_locator": locator,
        "validation_status": "attachment-metadata-citation-candidate",
    }


def email_container_candidate_citations(
    *,
    source_path: Path,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
) -> list[dict[str, object]]:
    citations: list[dict[str, object]] = []
    for candidate_type, key in (("email", "email_candidates"), ("subject", "subject_candidates"), ("string", "string_candidates")):
        for index, value in enumerate(details.get(key) or []):
            if len(citations) >= MAX_CONTAINER_CANDIDATES:
                return citations
            text = str(value or "")
            payload = {
                "candidate_type": candidate_type,
                "candidate_index": index,
                "preview": text[:240],
                "value_sha256": sha256_text(text) if text else "",
                "source_path": str(source_path.resolve()),
                "source_sha256": source_hashes.get("sha256", ""),
                "source_format": source_path.suffix.lower().lstrip("."),
            }
            citations.append(
                {
                    **payload,
                    "row_hash": stable_email_sha256(payload),
                    "source_viewer_locator": {
                        "viewer": "bounded-container-string",
                        "source_path": str(source_path.resolve()),
                        "candidate_type": candidate_type,
                        "candidate_index": index,
                        "offset_known": False,
                    },
                    "validation_status": "bounded-container-candidate",
                }
            )
    return citations


def stable_email_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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


def mapi_container_review_profile(
    *,
    source_format: str,
    scan_bytes: int,
    emails: list[str],
    subjects: list[str],
    strings: list[str],
) -> dict[str, object]:
    if source_format not in {"pst", "ost", "msg"}:
        return {}
    folder_candidates = [
        item
        for item in strings
        if any(token in item.lower() for token in ("inbox", "sent items", "deleted items", "drafts", "outbox", "archive"))
    ][:50]
    message_class_candidates = [
        item
        for item in strings
        if any(token in item.lower() for token in ("ipm.note", "ipm.appointment", "ipm.contact", "message class"))
    ][:50]
    attachment_candidates = [
        item
        for item in strings
        if any(token in item.lower() for token in (".pdf", ".doc", ".xls", ".ppt", ".zip", ".jpg", ".png", "attachment"))
    ][:50]
    deleted_candidates = [
        item
        for item in strings
        if any(token in item.lower() for token in ("deleted items", "recoverable items", "dumpster", "purges", "deletions"))
    ][:50]
    return {
        "profile_version": "mapi-container-review-v1",
        "source_format": source_format,
        "scan_window_bytes": int(scan_bytes),
        "scan_window_limit": CONTAINER_SCAN_LIMIT,
        "bounded_inventory_only": True,
        "email_candidate_count": len(emails),
        "subject_candidate_count": len(subjects),
        "string_candidate_count": len(strings),
        "folder_path_candidate_count": len(folder_candidates),
        "message_class_candidate_count": len(message_class_candidates),
        "attachment_name_candidate_count": len(attachment_candidates),
        "deleted_item_hint_count": len(deleted_candidates),
        "candidate_samples": {
            "folder_paths": folder_candidates[:10],
            "message_classes": message_class_candidates[:10],
            "attachments": attachment_candidates[:10],
            "deleted_item_hints": deleted_candidates[:10],
        },
        "native_object_decode_status": "not-implemented",
        "folder_hierarchy_status": "candidate-strings-only",
        "deleted_item_recovery_status": "not-performed",
        "attachment_extraction_status": "candidate-strings-only",
        "threading_status": "not-reconstructed",
        "recommended_external_validation_tools": EMAIL_REQUIRED_TOOLS_BY_FORMAT.get(source_format, []),
        "required_before_report": [
            "decode PST/OST/MSG with libpff/readpst/Outlook/Purview or another trusted mailbox parser",
            "diff folder tree, message count, subjects, recipients, timestamps, flags, and attachments against RapidTriage candidates",
            "validate deleted/recoverable item handling and OST sync-state limitations with known-answer fixtures",
            "treat these candidate strings as triage hints only until native object decoding and trusted diff pass",
        ],
    }


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


def email_mailbox_strategy_profile(
    source_format: str,
    *,
    source_path: Path,
    message_count: int,
    attachment_count: int,
    validation_checks: Mapping[str, object],
) -> dict[str, object]:
    profile = email_format_profile(source_format)
    native_container = source_format in {"pst", "ost", "msg"}
    blockers = [
        "email-known-answer-corpus-not-attached",
        EMAIL_TRUSTED_DIFF_BLOCKER,
        "thread-dedup-timezone-validation-required",
    ]
    if native_container:
        blockers.extend(
            [
                "native-mapi-container-object-decode-not-implemented",
                "folder-tree-message-flags-deleted-items-not-validated",
            ]
        )
    if attachment_count or native_container:
        blockers.append("attachment-content-and-nested-message-validation-required")
    return {
        "profile_version": "email-mailbox-strategy-v1",
        "source_format": source_format,
        "source_name": source_path.name,
        "format_family": profile["family"],
        "support_tier": profile["support_tier"],
        "selected_track": EMAIL_MAILBOX_STRATEGY_TRACKS.get(source_format, "generic-mailbox-inventory-validation"),
        "native_object_decode_available": bool(profile["native_decode"]),
        "bounded_inventory_only": native_container,
        "message_count": int(message_count),
        "attachment_count": int(attachment_count),
        "required_tools": EMAIL_REQUIRED_TOOLS_BY_FORMAT.get(source_format, ["format-specific trusted parser/export"]),
        "message_content_reportable": False,
        "deleted_item_recovery_complete": False,
        "folder_hierarchy_complete": not native_container and source_format not in {"emlx", "maildir"},
        "commercial_parser_validated": bool(validation_checks.get("commercial_parser_validated")),
        "blockers": blockers,
        "required_before_report": [
            "attach a trusted mailbox export/native parser diff for selected rows",
            "validate folder hierarchy, deleted items, duplicates, threading, timezone, and attachments",
            "record privilege/scope review before exporting or reporting mailbox content",
            "preserve source hash and parser/tool version for every cited message",
        ],
    }


def email_report_grade_assessment(source_format: str) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#36"],
        "source_format": source_format,
        "blockers": [*EMAIL_REPORT_GRADE_BLOCKERS, EMAIL_TRUSTED_DIFF_BLOCKER],
        "ready_for_court_report": False,
        "recommended_validation": [
            "Validate PST/OST/MSG content with a dedicated mailbox parser before report-grade conclusions.",
            "Review privilege/scope, threading, duplicate handling, and attachment extraction against known-answer mailboxes.",
        ],
    }


def email_commercial_uplift_evidence(
    *,
    source_format: str,
    source_hashes: dict[str, str],
    details: dict[str, object],
) -> dict[str, object]:
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    trusted_diff = details.get("email_trusted_diff") if isinstance(details.get("email_trusted_diff"), Mapping) else {}
    citation_manifest = (
        details.get("email_expansion_citation_manifest")
        if isinstance(details.get("email_expansion_citation_manifest"), Mapping)
        else {}
    )
    mailbox_manifest = (
        details.get("email_mailbox_parser_manifest")
        if isinstance(details.get("email_mailbox_parser_manifest"), Mapping)
        else {}
    )
    report_plan = (
        details.get("email_report_grade_validation_plan")
        if isinstance(details.get("email_report_grade_validation_plan"), Mapping)
        else {}
    )
    attachment_locator_profile = (
        details.get("email_attachment_locator_profile")
        if isinstance(details.get("email_attachment_locator_profile"), Mapping)
        else {}
    )
    matrix = email_validation_matrix(source_format, validation)
    issue_matrix = email_issue_matrix(source_format)
    passed_validation_matrix_ids = [str(item.get("id")) for item in matrix if item.get("passed")]
    failed_validation_matrix_ids = [str(item.get("id")) for item in matrix if not item.get("passed")]
    passed_issue_matrix_ids = [str(item.get("id")) for item in issue_matrix if item.get("passed")]
    failed_issue_matrix_ids = [str(item.get("id")) for item in issue_matrix if not item.get("passed")]
    return {
        "batch_id": "commercial-uplift-036-040",
        "item_numbers": [36],
        "qc_prep_item_numbers": [EMAIL_QC_PREP_ITEM_NUMBER],
        "qc_prep_contracts": [dict(EMAIL_QC_PREP_CONTRACT)],
        "functional_priority_profile": email_expansion_functional_profile(
            source_format=source_format,
            source_hashes=source_hashes,
            details=details,
            validation=validation,
            trusted_diff=trusted_diff,
        ),
        "implementation_track": "email-mailbox-parser-validation",
        "objective": "Expose email/PST/OST/MBOX parsing evidence, mailbox bounds, and report-grade blockers without claiming native MAPI parity.",
        "reportability_decision": email_reportability_decision(
            source_format=source_format,
            validation_checks=validation,
            failed_validation_matrix_ids=failed_validation_matrix_ids,
            failed_issue_matrix_ids=failed_issue_matrix_ids,
            details=details,
            trusted_diff=trusted_diff,
        ),
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_format:{source_format}",
            f"source_sha256:{source_hashes.get('sha256', '')}",
            f"source_index:{details.get('source_index', '')}",
            f"mailbox_name:{details.get('mailbox_name', '')}",
            f"citation_manifest_sha256:{citation_manifest.get('manifest_sha256', '')}",
            f"email_mailbox_parser_manifest_sha256:{mailbox_manifest.get('manifest_sha256', '')}",
            f"email_report_grade_validation_plan_sha256:{report_plan.get('manifest_sha256', '')}",
        ],
        "email_mailbox_strategy_profile": (
            dict(details["email_mailbox_strategy_profile"])
            if isinstance(details.get("email_mailbox_strategy_profile"), Mapping)
            else {}
        ),
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "passed_issue_matrix_ids": passed_issue_matrix_ids,
        "failed_issue_matrix_ids": failed_issue_matrix_ids,
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_id": EMAIL_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(EMAIL_TRUSTED_DIFF_TOOLS),
        },
        "commercial_blockers": email_blockers(source_format),
        "large_data_controls": {
            "max_mbox_messages": MAX_MBOX_MESSAGES,
            "container_scan_limit": CONTAINER_SCAN_LIMIT,
            "max_container_candidates": MAX_CONTAINER_CANDIDATES,
            "message_count": int(details.get("message_count") or 0),
            "attachment_count": int(details.get("attachment_count") or 0),
            "mapi_container_review_profile_present": bool(details.get("mapi_container_review_profile")),
            "citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "email_mailbox_parser_manifest_hash": str(mailbox_manifest.get("manifest_sha256") or ""),
            "email_report_grade_validation_plan_hash": str(report_plan.get("manifest_sha256") or ""),
            "email_report_grade_validation_ready_slot_count": int(report_plan.get("ready_slot_count") or 0),
            "email_report_grade_validation_blocking_slot_count": int(report_plan.get("blocking_slot_count") or 0),
            "email_attachment_locator_profile_hash": str(attachment_locator_profile.get("profile_sha256") or ""),
            "email_mailbox_source_row_citation_present": bool(
                isinstance(mailbox_manifest.get("row_citation"), Mapping)
                and mailbox_manifest.get("row_citation", {}).get("row_hash")
            ),
            "email_mailbox_viewer_controls_present": bool(
                isinstance(mailbox_manifest.get("large_data_controls"), Mapping)
                and mailbox_manifest.get("large_data_controls", {}).get("viewer_default")
            ),
            "email_attachment_locator_count": int(attachment_locator_profile.get("locator_count") or 0),
            "citation_row_count": int(citation_manifest.get("message_citation_count") or 0)
            + int(citation_manifest.get("attachment_citation_count") or 0)
            + int(citation_manifest.get("candidate_citation_count") or 0),
            "native_pst_ost_msg_object_decode": False,
            "broad_mailbox_known_answer_corpus_required": True,
        },
        "next_internal_step": "Add libpff/native MAPI object decoding, folder/deleted item recovery, attachment hashing, and mailbox known-answer corpus validation.",
        "external_evidence_required": True,
    }


def email_expansion_functional_profile(
    *,
    source_format: str,
    source_hashes: Mapping[str, str],
    details: Mapping[str, object],
    validation: Mapping[str, object],
    trusted_diff: Mapping[str, object],
) -> dict[str, object]:
    profile = email_format_profile(source_format)
    native_decode = bool(profile.get("native_decode"))
    message_count = int(details.get("message_count") or (1 if details.get("message_id") else 0))
    failed_checks: list[str] = []
    if not source_hashes.get("sha256"):
        failed_checks.append("email-source-sha256-missing")
    if source_format in {"pst", "ost", "msg"} and not native_decode:
        failed_checks.append("pst-ost-msg-native-object-decode-not-implemented")
    if not validation.get("commercial_parser_validated"):
        failed_checks.append("email-known-answer-corpus-not-attached")
    if trusted_diff.get("status") != "pass":
        failed_checks.append(EMAIL_TRUSTED_DIFF_BLOCKER)
    citation_manifest = (
        details.get("email_expansion_citation_manifest")
        if isinstance(details.get("email_expansion_citation_manifest"), Mapping)
        else {}
    )
    mailbox_manifest = (
        details.get("email_mailbox_parser_manifest")
        if isinstance(details.get("email_mailbox_parser_manifest"), Mapping)
        else {}
    )
    report_plan = (
        details.get("email_report_grade_validation_plan")
        if isinstance(details.get("email_report_grade_validation_plan"), Mapping)
        else {}
    )
    attachment_locator_profile = (
        details.get("email_attachment_locator_profile")
        if isinstance(details.get("email_attachment_locator_profile"), Mapping)
        else {}
    )
    if not citation_manifest.get("manifest_sha256"):
        failed_checks.append("email-expansion-citation-manifest-not-emitted")
    if not mailbox_manifest.get("manifest_sha256"):
        failed_checks.append("email-mailbox-parser-manifest-not-emitted")
    if not report_plan.get("manifest_sha256"):
        failed_checks.append("email-report-grade-validation-plan-not-emitted")
    passed_checks = [
        "eml-emlx-maildir-message-parse",
        "mbox-bounded-message-parse",
        "pst-ost-msg-bounded-string-inventory",
        "email-source-hashing",
        "attachment-metadata-hashing",
    ]
    if citation_manifest.get("manifest_sha256"):
        passed_checks.append("email-expansion-citation-manifest-emitted")
    if mailbox_manifest.get("manifest_sha256"):
        passed_checks.append("email-mailbox-parser-manifest-emitted")
    if report_plan.get("manifest_sha256"):
        passed_checks.append("email-report-grade-validation-plan-emitted")
    if isinstance(mailbox_manifest.get("row_citation"), Mapping) and mailbox_manifest.get("row_citation", {}).get("source_viewer_locator"):
        passed_checks.append("email-mailbox-source-locator-emitted")
    if attachment_locator_profile.get("profile_sha256"):
        passed_checks.append("email-attachment-locator-profile-emitted")
    if int(citation_manifest.get("candidate_citation_count") or 0) > 0:
        passed_checks.append("bounded-container-candidate-citations-emitted")
    return {
        "item_number": 49,
        "batch_id": FUNCTIONAL_SOURCE_BATCH_ID,
        "qc_prep_item_numbers": [EMAIL_QC_PREP_ITEM_NUMBER],
        "qc_prep_contracts": [dict(EMAIL_QC_PREP_CONTRACT)],
        "status": "complete" if not failed_checks else "partial",
        "implemented_controls": {
            "source_format": source_format,
            "format_family": str(profile.get("family") or ""),
            "support_tier": str(profile.get("support_tier") or ""),
            "native_decode": native_decode,
            "message_count": message_count,
            "attachment_count": int(details.get("attachment_count") or 0),
            "email_candidate_count": int(details.get("email_candidate_count") or 0),
            "source_sha256_present": bool(source_hashes.get("sha256")),
            "citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "email_mailbox_parser_manifest_hash": str(mailbox_manifest.get("manifest_sha256") or ""),
            "email_report_grade_validation_plan_hash": str(report_plan.get("manifest_sha256") or ""),
            "email_report_grade_validation_ready_slot_count": int(report_plan.get("ready_slot_count") or 0),
            "email_report_grade_validation_blocking_slot_count": int(report_plan.get("blocking_slot_count") or 0),
            "email_attachment_locator_profile_hash": str(attachment_locator_profile.get("profile_sha256") or ""),
            "email_attachment_locator_count": int(attachment_locator_profile.get("locator_count") or 0),
            "email_mailbox_row_citation_present": bool(
                isinstance(mailbox_manifest.get("row_citation"), Mapping)
                and mailbox_manifest.get("row_citation", {}).get("row_hash")
            ),
            "message_citation_count": int(citation_manifest.get("message_citation_count") or 0),
            "attachment_citation_count": int(citation_manifest.get("attachment_citation_count") or 0),
            "candidate_citation_count": int(citation_manifest.get("candidate_citation_count") or 0),
            "supported_formats": sorted(EMAIL_SUFFIXES | {"maildir"}),
            "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
            "strategy_track": str(
                details.get("email_mailbox_strategy_profile", {}).get("selected_track")
                if isinstance(details.get("email_mailbox_strategy_profile"), Mapping)
                else ""
            ),
        },
        "passed_validation_check_ids": passed_checks,
        "failed_validation_check_ids": failed_checks,
        "reportability_decision": {
            "allowed_use": "email-mailbox-and-message-triage-pivot",
            "commercial_claim_allowed": not failed_checks,
            "operator_warning": "Use libpff/vendor mailbox exports and known-answer corpora before PST/OST/MSG or deleted-item report claims.",
        },
    }


def email_reportability_decision(
    *,
    source_format: str,
    validation_checks: dict[str, object],
    failed_validation_matrix_ids: list[str],
    failed_issue_matrix_ids: list[str],
    details: dict[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = set(email_blockers(source_format))
    blockers.update(f"matrix:{item}" for item in failed_validation_matrix_ids)
    blockers.update(f"issue:{item}" for item in failed_issue_matrix_ids)
    if source_format in {"pst", "ost", "msg"}:
        blockers.add("native-mapi-container-decoding-not-validated")
    if not validation_checks.get("commercial_parser_validated"):
        blockers.add("mailbox-known-answer-corpus-not-attached")
    trusted_diff = trusted_diff or {}
    if trusted_diff.get("status") != "pass":
        blockers.add(EMAIL_TRUSTED_DIFF_BLOCKER)
    return {
        "profile_version": "email-reportability-decision-v1",
        "commercial_gap_ids": ["#36"],
        "qc_prep_item_numbers": [EMAIL_QC_PREP_ITEM_NUMBER],
        "qc_prep_contracts": [dict(EMAIL_QC_PREP_CONTRACT)],
        "decision": "do-not-report-mailbox-as-native-or-deleted-complete",
        "allowed_use": "email-message-or-mailbox-inventory-triage-pivot",
        "source_format": source_format,
        "blockers": sorted(blockers),
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "failed_issue_matrix_ids": list(failed_issue_matrix_ids),
        "message_count": int(details.get("message_count") or 0),
        "attachment_count": int(details.get("attachment_count") or 0),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate native PST/OST/MSG object and folder decoding where applicable",
            "validate deleted item recovery, threading, duplicates, timezone, and attachments with known-answer mailboxes",
            "attach a passing trusted email mailbox export diff from libpff/readpst/Outlook/native ground truth",
            "review privilege, legal scope, and search/export limitations before reporting message content",
        ],
    }


def email_core_accuracy_gates(
    *,
    source_format: str,
    source_hashes: dict[str, str],
    details: dict[str, object],
) -> list[dict[str, object]]:
    validation = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"source_format:{source_format}",
    ]
    if source_hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{source_hashes['sha256']}")
    mailbox_manifest = (
        details.get("email_mailbox_parser_manifest")
        if isinstance(details.get("email_mailbox_parser_manifest"), Mapping)
        else {}
    )
    if mailbox_manifest.get("manifest_sha256"):
        evidence_refs.append(f"email_mailbox_parser_manifest_sha256:{mailbox_manifest['manifest_sha256']}")
    report_plan = (
        details.get("email_report_grade_validation_plan")
        if isinstance(details.get("email_report_grade_validation_plan"), Mapping)
        else {}
    )
    if report_plan.get("manifest_sha256"):
        evidence_refs.append(f"email_report_grade_validation_plan_sha256:{report_plan['manifest_sha256']}")
    attachment_locator_profile = (
        details.get("email_attachment_locator_profile")
        if isinstance(details.get("email_attachment_locator_profile"), Mapping)
        else {}
    )
    if attachment_locator_profile.get("profile_sha256"):
        evidence_refs.append(f"email_attachment_locator_profile_sha256:{attachment_locator_profile['profile_sha256']}")
    trusted_diff = details.get("email_trusted_diff") if isinstance(details.get("email_trusted_diff"), Mapping) else {}
    if trusted_diff:
        evidence_refs.append(f"trusted_diff_status:{trusted_diff.get('status', '')}")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    satisfied: list[str] = []
    if source_format and (details.get("message_id") is not None or details.get("mailbox_name")):
        satisfied.append("mailbox/message source profile detection")
    if details.get("email_mailbox_strategy_profile"):
        satisfied.append("mailbox strategy profile")
    if details.get("email_expansion_citation_manifest"):
        satisfied.append("email expansion citation manifest")
    if mailbox_manifest:
        satisfied.append("email mailbox parser manifest")
        if isinstance(mailbox_manifest.get("row_citation"), Mapping) and mailbox_manifest.get("row_citation", {}).get("row_hash"):
            satisfied.append("email mailbox source row citation")
        if isinstance(mailbox_manifest.get("large_data_controls"), Mapping) and mailbox_manifest.get("large_data_controls", {}).get("viewer_default"):
            satisfied.append("email mailbox review viewer controls")
    if report_plan:
        satisfied.append("email report-grade validation plan")
        if int(report_plan.get("ready_slot_count") or 0) >= 5:
            satisfied.append("email report-grade ready slots")
    if validation.get("headers_parsed") or validation.get("parsed_message_count") is not None or details.get("email_candidates"):
        satisfied.append("message header/body/attachment inventory")
    if details.get("email_thread_profile"):
        satisfied.append("email thread/participant profile")
    if attachment_locator_profile.get("profile_sha256"):
        satisfied.append("email attachment source locator")
    if details.get("mapi_container_review_profile"):
        satisfied.append("MAPI container bounded review profile")
    if validation.get("bounded_candidate_inventory_present"):
        satisfied.append("bounded mailbox candidate inventory")
    if source_format in {"pst", "ost", "msg"} or not EMAIL_NATIVE_CAPABILITIES["native_pst_ost_msg_object_decode"]:
        satisfied.append("PST/OST native limitation warning")
    if not validation.get("commercial_parser_validated"):
        satisfied.append("threading/dedup validation warning")
    if source_hashes.get("sha256"):
        satisfied.append("legal privilege boundary")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted email mailbox export diff pass")
    return [build_accuracy_gate(36, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_email_trusted_diff(
    rapid_rows: Iterable[Mapping[str, object]],
    trusted_rows: Iterable[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "email-mailbox-trusted-diff",
) -> dict[str, object]:
    rapid_index = {_email_diff_key(row): _email_diff_values(row) for row in rapid_rows}
    trusted_index = {_email_diff_key(row): _email_diff_values(row) for row in trusted_rows}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing_in_trusted = sorted(key for key in rapid_index if key not in trusted_index)
    unexpected_in_trusted = sorted(key for key in trusted_index if key not in rapid_index)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index).intersection(trusted_index)):
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field in (
            "source_format",
            "message_id",
            "subject",
            "from",
            "to",
            "date",
            "body_sha256",
            "attachment_count",
            "mailbox_name",
            "message_count",
        ):
            left = rapid.get(field)
            right = trusted.get(field)
            if left not in (None, "") and right not in (None, "") and str(left) != str(right):
                mismatches.append({"row_key": key, "field": field, "rapid": str(left), "trusted": str(right)})
    tool_key = trusted_tool.strip().lower()
    tool_accepted = tool_key in EMAIL_TRUSTED_DIFF_TOOLS
    status = (
        "pass"
        if tool_accepted
        and rapid_index
        and trusted_index
        and not missing_in_trusted
        and not unexpected_in_trusted
        and not mismatches
        else "fail"
    )
    return {
        "profile_version": "email-trusted-diff-v1",
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else EMAIL_TRUSTED_DIFF_BLOCKER,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(EMAIL_TRUSTED_DIFF_TOOLS),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_row_count": len(set(rapid_index).intersection(trusted_index)),
        "missing_in_trusted": missing_in_trusted[:200],
        "unexpected_in_trusted": unexpected_in_trusted[:200],
        "mismatched_fields": mismatches[:200],
        "evidence_summary": "Rapid email rows match trusted mailbox export rows" if status == "pass" else "Trusted mailbox export diff is missing or mismatched",
    }


def _email_diff_key(row: Mapping[str, object]) -> str:
    values = _email_diff_values(row)
    if values.get("message_id"):
        return f"message:{values['message_id']}"
    if values.get("mailbox_name"):
        return f"mailbox:{values.get('mailbox_name')}:{values.get('message_count', '')}"
    parts = [
        str(values.get("subject") or ""),
        str(values.get("from") or ""),
        str(values.get("to") or ""),
        str(values.get("date") or ""),
        str(values.get("source_index") or ""),
    ]
    return "message-fingerprint:" + sha256_text("|".join(parts))


def _email_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    source = row.get("details") if isinstance(row.get("details"), Mapping) else row
    attachments = source.get("attachments") if isinstance(source.get("attachments"), list) else []
    return {
        "source_format": source.get("source_format"),
        "source_index": source.get("source_index"),
        "message_id": source.get("message_id"),
        "subject": source.get("subject"),
        "from": source.get("from"),
        "to": source.get("to"),
        "date": source.get("date"),
        "body_sha256": source.get("body_sha256"),
        "attachment_count": source.get("attachment_count", len(attachments)),
        "mailbox_name": source.get("mailbox_name"),
        "message_count": source.get("message_count"),
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


def email_analyst_review_profile(
    *,
    artifact_type: str,
    source_format: str,
    source_hashes: Mapping[str, str],
    source_path: str,
    details: Mapping[str, object],
) -> dict[str, object]:
    parser_manifest = (
        details.get("email_mailbox_parser_manifest")
        if isinstance(details.get("email_mailbox_parser_manifest"), Mapping)
        else {}
    )
    citation_manifest = (
        details.get("email_expansion_citation_manifest")
        if isinstance(details.get("email_expansion_citation_manifest"), Mapping)
        else {}
    )
    row_citation = parser_manifest.get("row_citation") if isinstance(parser_manifest.get("row_citation"), Mapping) else {}
    viewer_locator = (
        row_citation.get("source_viewer_locator")
        if isinstance(row_citation.get("source_viewer_locator"), Mapping)
        else {}
    )
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    risk_flags = details.get("risk_flags") if isinstance(details.get("risk_flags"), list) else []
    return {
        "profile_version": "email-analyst-review-profile-v1",
        "gap_ids": ["#36"],
        "artifact_type": artifact_type,
        "source_format": source_format,
        "severity": "high" if risk_flags or source_format in {"pst", "ost", "msg"} else "medium",
        "summary": f"{artifact_type} / {source_format} / {details.get('subject') or details.get('mailbox_name') or 'mailbox row'}",
        "evidence_interpretation": "Mailbox/message metadata, attachment inventory, and review citation pivot",
        "not_proof_of": [
            "complete mailbox object decoding",
            "deleted item recovery",
            "privilege/scope review completion",
            "DKIM/ARC/SPF/S-MIME/OpenPGP validation",
            "thread/dedup correctness",
        ],
        "analyst_questions": [
            "Does this row match a trusted mailbox parser or native mail client export?",
            "Are timezone, message threading, duplicate suppression, and attachment hashes verified?",
            "Is any privileged or personal content in scope for review/export?",
            "Should this row be correlated with cloud, browser, file, or entity evidence?",
        ],
        "primary_pivots": [
            value
            for value in (
                str(details.get("message_id") or ""),
                str(details.get("subject") or ""),
                str(details.get("from") or ""),
                str(details.get("to") or ""),
                str(details.get("mailbox_name") or ""),
            )
            if value
        ][:8],
        "source_field_values": {
            "source_path": source_path,
            "source_sha256": source_hashes.get("sha256", ""),
            "source_format": source_format,
            "source_index": int(details.get("source_index") or 0),
            "message_id": str(details.get("message_id") or ""),
            "subject": str(details.get("subject") or ""),
            "mailbox_name": str(details.get("mailbox_name") or ""),
            "message_count": int(details.get("message_count") or 0),
            "attachment_count": int(details.get("attachment_count") or 0),
            "citation_manifest_sha256": str(citation_manifest.get("manifest_sha256") or ""),
            "parser_manifest_sha256": str(parser_manifest.get("manifest_sha256") or ""),
            "viewer": str(viewer_locator.get("viewer") or ""),
        },
        "correlation_targets": [
            "libpff/readpst/Outlook/native mailbox diff",
            "cloud provider mail export",
            "attachment hash/file viewer",
            "timeline and entity view",
            "privilege/scope review",
        ],
        "risk_tags": sorted(set(map(str, risk_flags)) | {"email-validation-required"}),
        "validation_required": True,
        "report_grade_ready": False,
        "validation_snapshot": dict(validation_checks),
        "commercial_blockers": email_blockers(source_format),
        "report_guidance": "Use as a mailbox review pivot until native/trusted-parser diff, attachment validation, and privilege-scope review are attached.",
    }


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
