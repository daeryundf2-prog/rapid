from __future__ import annotations
import base64
import binascii
import contextlib
import datetime as dt
import email
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import struct
import wave
from collections.abc import Mapping, MutableMapping, Sequence
from email import policy
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree as ET
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from ...core.audit import audit_path_for, write_audit_record
from ...core.bundle import BundleError, build_submission_bundle
from ...core.case import (
    CaseBookmarkError,
    create_or_update_case_payload,
    load_case_payload,
    save_case_payload,
)
from ...core.case_catalog import CaseCatalog, CaseCatalogError, default_case_catalog_path
from ...core.case_db import CaseDatabaseError, open_case_database
from ...core.case_report import (
    build_case_report_markdown,
    case_report_export_paths,
    write_case_report_exports,
)
from ...core.collect_plan import (
    CollectPlanError,
    build_collect_plan,
    supported_collect_profiles,
)
from ...core.columnar_store import query_columnar_artifact_records
from ...core.commercial_readiness import (
    CommercialReadinessError,
    build_commercial_readiness_report,
)
from ...core.crash import (
    export_crash_report_bundle,
    list_crash_reports,
    read_crash_report,
    write_crash_report,
)
from ...core.docs import SUPPORTED_DOC_EXTS, TEXT_EXTS, extract_text, query_docs_index
from ...core.doctor import run_doctor
from ...core.enterprise import build_enterprise_policy
from ...core.evidence import identify_evidence, supported_evidence_formats
from ...core.files import DEFAULT_KNOWN_GOOD_MAX_HASH_BYTES
from ...core.forensic_accuracy import build_accuracy_gate
from ...core.hash_cache import hash_cache_assessment
from ...core.indicators import (
    IndicatorSummaryError,
    build_indicator_ti_enrichment_package,
)
from ...core.jobs import (
    RunJobStore,
    RunRequest,
    default_job_store,
    is_relative_to,
    run_output_dir,
)
from ...core.keyword_packs import (
    KeywordPackError,
    keyword_pack_library_assessment,
    keyword_pack_selection_profile,
    list_keyword_packs,
    resolve_keyword_packs,
)
from ...core.large_case_controls import build_source_search_full_cursor_contract
from ...core.ocr_queue import (
    OcrQueueError,
    build_ocr_queue,
    build_ocr_queue_report_grade_validation_plan,
)
from ...core.run import RunModeError
from ...core.safe_xml import UnsafeXmlError, safe_xml_fromstring
from ...core.sample_case import DEFAULT_SAMPLE_MODE, SampleCaseError, run_sample_workflow
from ...core.search import SearchError, run_unified_search
from ...core.source_paths import (
    candidate_source_paths,
    source_path_resolution_diagnostics,
)
from ...core.source_reader import (
    SourceReadError,
    build_source_locator,
    parse_archived_source_request,
)
from ...core.source_reader import (
    build_archived_source_preview as build_archived_source_read_preview,
)
from ...core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview
from ...core.submission import build_submission_manifest, compute_hashes
from ...core.visible_capabilities import build_visible_capability_response

from .constants import (
    EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
    EMAIL_BODY_PREVIEW_CHARS,
    EMAIL_PREVIEW_MAX_BYTES,
    EMAIL_PREVIEW_MESSAGE_LIMIT,
    EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
    EMAIL_VIEWER_REPORT_GRADE_BLOCKERS,
    EMAIL_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
    EMAIL_VIEWER_TRUSTED_TOOLS,
    VIEWER_WORKFLOW_GAP_IDS,
)
from .helpers import (
    _email_thread_diff_key,
    _email_thread_diff_values,
    compute_hashes_for_bytes,
    optional_int_for_api,
    stable_payload_sha256,
)
from .viewer_core import (
    build_viewer_trusted_diff_result,
    source_viewer_component_assessment,
    structured_viewer_metadata,
    viewer_workflow_commercial_uplift_evidence,
    viewer_workflow_reportability_decision,
)


def first_email_attachment_count(source_path: Path) -> int:
    suffix = source_path.suffix.lower()
    if suffix not in {".eml", ".mbox"}:
        return 0
    try:
        messages = read_email_messages(source_path, suffix)
    except (OSError, LookupError, UnicodeDecodeError, ValueError):
        return 0
    for index, message in enumerate(messages[:1], start=1):
        summary = summarize_email_message(message, index)
        return int(summary.get("attachment_count") or 0)
    return 0


def build_email_preview(source_path: Path, suffix: str, *, run_id: str | None = None) -> dict[str, object]:
    try:
        messages, diagnostics = read_email_messages_with_diagnostics(source_path, suffix)
    except OSError as exc:
        return {
            "preview_type": "binary",
            "message": f"Email preview failed: {exc}",
            "viewer_metadata": structured_viewer_metadata("email", "bounded-email-parse", "parse-failed"),
            "email": {"error": str(exc)},
        }
    summaries = [summarize_email_message(message, index) for index, message in enumerate(messages, start=1)]
    threads = build_email_threads(summaries)
    conversation = build_email_conversation_viewer(summaries, threads)
    attachment_profile = email_attachment_package_profile(
        run_id=run_id,
        source_path=source_path,
        messages=summaries,
    )
    conversation_manifest = build_email_conversation_manifest(
        source_path=source_path,
        messages=summaries,
        conversation=conversation,
        attachment_profile=attachment_profile,
    )
    text = "\n\n".join(item["body_preview"] for item in summaries if item.get("body_preview"))
    parse_truncated = bool(
        diagnostics.get("source_truncated")
        or diagnostics.get("message_limit_reached")
        or diagnostics.get("message_size_truncated_count")
    )
    validation_plan = build_email_viewer_report_grade_validation_plan(
        context="email-preview",
        source_path=source_path,
        messages=summaries,
        conversation=conversation,
        conversation_manifest=conversation_manifest,
        attachment_profile=attachment_profile,
        parse_truncated=parse_truncated,
    )
    core_accuracy_gates = email_viewer_core_accuracy_gates(
        source_path=source_path,
        messages=summaries,
        conversation=conversation,
        conversation_manifest=conversation_manifest,
        validation_plan=validation_plan,
    )
    return {
        "preview_type": "email",
        "message": (
            "Email structured preview is partial because bounded parsing limits were reached."
            if parse_truncated
            else "Email structured preview is available."
        ),
        "text": text[:20000],
        "truncated": parse_truncated or len(text) > 20000,
        "viewer_metadata": structured_viewer_metadata(
            "email",
            "bounded-email-parse",
            "partial" if parse_truncated else "available",
        ),
        "email": {
            "message_count": len(summaries),
            "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
            "parse_diagnostics": diagnostics,
            "max_input_bytes": EMAIL_PREVIEW_MAX_BYTES,
            "max_message_bytes": EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
            "messages": summaries,
            "attachment_package_profile": attachment_profile,
            "threads": threads,
            "conversation_view": conversation,
            "email_conversation_manifest": conversation_manifest,
            "email_conversation_manifest_hash": conversation_manifest["manifest_hash"],
            "email_viewer_report_grade_validation_plan": validation_plan,
            "email_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
            "thread_count": len(threads),
            "truncated": parse_truncated,
            "email_conversation_viewer_assessment": source_viewer_component_assessment(
                VIEWER_WORKFLOW_GAP_IDS["email"],
                "email-conversation-viewer",
                [
                    "pst-ost-native-folder-flag-deleted-item-threading-not-implemented-in-viewer",
                    "conversation-threading-is-header-based-and-needs-mailbox-known-answer-validation",
                    "attachment-body-rendering-is-bounded-and-inventory-oriented",
                ],
            ),
            "core_accuracy_gates": core_accuracy_gates,
            "trusted_email_conversation_diff": {
                "status": "missing",
                "blocker_id": EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
                "required_tools": sorted(EMAIL_VIEWER_TRUSTED_TOOLS),
            },
            "commercial_uplift_evidence": viewer_workflow_commercial_uplift_evidence(
                item_number=55,
                component="email-conversation-viewer",
                core_accuracy_gates=core_accuracy_gates,
                blockers=[
                    "native-pst-ost-msg-conversation-view-not-implemented",
                    "deleted-mailbox-item-recovery-not-implemented",
                    "attachment-content-export-is-bounded-and-needs-trusted-mailbox-validation",
                    *(
                        ["email-source-preview-is-partial-requires-resume-or-mailbox-export-validation"]
                        if parse_truncated
                        else []
                    ),
                    "message-id-graph-validation-required",
                    EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
                ],
                source_refs=[
                    f"source_path:{source_path}",
                    f"message_count:{len(summaries)}",
                    f"thread_count:{len(threads)}",
                    f"email_viewer_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                ],
                controls={
                    "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
                    "body_preview_chars": EMAIL_BODY_PREVIEW_CHARS,
                    "thread_count": len(threads),
                    "header_threading": True,
                    "native_pst_ost_msg": False,
                    "attachment_inventory": True,
                    "attachment_package_endpoint": True,
                    "attachment_content_export_max_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                    "email_parse_diagnostics": diagnostics,
                    "email_conversation_manifest_hash": conversation_manifest["manifest_hash"],
                    "email_viewer_report_grade_validation_plan_present": True,
                    "email_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                    "email_viewer_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                    "email_viewer_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
                    "email_thread_hash_count": conversation_manifest["thread_hash_count"],
                    "email_message_hash_count": conversation_manifest["message_hash_count"],
                },
            ),
        },
    }


def build_email_viewer_report_grade_validation_plan(
    *,
    context: str,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
    conversation: Mapping[str, object],
    conversation_manifest: Mapping[str, object] | None = None,
    attachment_manifest: Mapping[str, object] | None = None,
    attachment_profile: Mapping[str, object] | None = None,
    parse_truncated: bool = False,
    content_status: str = "",
    copy_safe_citation_ready: bool = False,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    conversation_manifest = conversation_manifest if isinstance(conversation_manifest, Mapping) else {}
    attachment_manifest = attachment_manifest if isinstance(attachment_manifest, Mapping) else {}
    attachment_profile = attachment_profile if isinstance(attachment_profile, Mapping) else {}
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    threads = conversation.get("threads") if isinstance(conversation.get("threads"), list) else []

    def slot(
        slot_id: str,
        *,
        ready: bool,
        evidence: str,
        blocker_id: str | None = None,
        operator_action: str = "",
    ) -> dict[str, object]:
        row: dict[str, object] = {
            "slot_id": slot_id,
            "status": "complete" if ready else "external-required",
            "evidence": evidence,
        }
        if blocker_id and not ready:
            row["blocker_id"] = blocker_id
        if operator_action:
            row["operator_action"] = operator_action
        return row

    message_count = len(messages)
    thread_count = len(threads)
    attachment_count = int(attachment_profile.get("attachment_count") or 0)
    message_hash_count = int(conversation_manifest.get("message_hash_count") or 0)
    thread_hash_count = int(conversation_manifest.get("thread_hash_count") or 0)
    conversation_manifest_hash = str(conversation_manifest.get("manifest_hash") or "")
    attachment_manifest_hash = str(attachment_manifest.get("manifest_hash") or "")
    validation_slots = [
        slot(
            "email-bounded-message-parse",
            ready=message_count > 0,
            evidence=f"context={context} message_count={message_count} parse_truncated={parse_truncated}",
            blocker_id="email-bounded-message-parse-required",
            operator_action="Parse bounded message/header/body metadata before conversation review.",
        ),
        slot(
            "email-thread-or-attachment-context",
            ready=thread_count > 0 or bool(attachment_manifest_hash),
            evidence=f"thread_count={thread_count} attachment_manifest_hash={attachment_manifest_hash}",
            blocker_id="email-thread-or-attachment-context-required",
            operator_action="Emit thread context or an attachment-specific source package.",
        ),
        slot(
            "email-participant-header-preservation",
            ready=bool(messages)
            and all(message.get("from") is not None and message.get("subject") is not None for message in messages),
            evidence=f"message_count={message_count}",
            blocker_id="email-participant-header-preservation-required",
            operator_action="Preserve From/Subject and core headers for each bounded message.",
        ),
        slot(
            "email-attachment-inventory-or-proof",
            ready=attachment_count >= 0 and (bool(attachment_profile) or bool(attachment_manifest_hash)),
            evidence=f"attachment_count={attachment_count} attachment_proof={bool(attachment_manifest_hash)}",
            blocker_id="email-attachment-inventory-or-proof-required",
            operator_action="Emit attachment inventory, hashes, or a bounded attachment proof package.",
        ),
        slot(
            "email-conversation-or-attachment-manifest-hashes",
            ready=(
                bool(conversation_manifest_hash)
                and (message_hash_count > 0 or thread_hash_count > 0)
            )
            or bool(attachment_manifest_hash),
            evidence=(
                f"conversation_manifest_hash={conversation_manifest_hash} message_hash_count={message_hash_count} "
                f"thread_hash_count={thread_hash_count} attachment_manifest_hash={attachment_manifest_hash}"
            ),
            blocker_id="email-conversation-or-attachment-manifest-hashes-required",
            operator_action="Attach conversation or attachment manifest hashes and row hashes.",
        ),
        slot(
            "email-copy-safe-citation-or-package-endpoint",
            ready=copy_safe_citation_ready or bool(attachment_profile.get("endpoint")) or bool(attachment_manifest_hash),
            evidence=(
                f"copy_safe_citation_ready={copy_safe_citation_ready} endpoint={attachment_profile.get('endpoint', '')} "
                f"content_status={content_status}"
            ),
            blocker_id="email-copy-safe-citation-or-package-endpoint-required",
            operator_action="Expose a bounded package endpoint or copy-safe citation before report note handoff.",
        ),
        slot(
            "email-native-pst-ost-msg-conversation-view",
            ready=False,
            evidence="native_pst_ost_msg_conversation_view=false",
            blocker_id="native-pst-ost-msg-conversation-view-required",
            operator_action="Add native MAPI/PST/OST/MSG folder, flag, body, and thread decoding.",
        ),
        slot(
            "email-deleted-mailbox-item-recovery",
            ready=False,
            evidence="deleted_mailbox_item_recovery=false",
            blocker_id="deleted-mailbox-item-recovery-required",
            operator_action="Validate deleted item/folder recovery against mailbox known-answer corpora.",
        ),
        slot(
            "email-native-mailbox-attachment-extraction",
            ready=False,
            evidence="native_mailbox_attachment_extraction=false",
            blocker_id="native-mailbox-attachment-extraction-required",
            operator_action="Extract native mailbox attachments with source offsets/properties and byte hashes.",
        ),
        slot(
            "email-message-id-graph-validation",
            ready=False,
            evidence="message_id_graph_validation=false",
            blocker_id="message-id-graph-validation-required",
            operator_action="Validate Message-ID/In-Reply-To/References graph reconstruction against known-answer threads.",
        ),
        slot(
            "email-trusted-thread-export",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
            operator_action="Attach a passing trusted mail-client or vendor mailbox thread export diff.",
        ),
        slot(
            "email-mailbox-corpus-validation",
            ready=False,
            evidence="mailbox_corpus_validation=false",
            blocker_id="mailbox-corpus-validation-required",
            operator_action="Run corrupt/large/PST/OST/MBOX/MSG fixture corpus validation with expected thread and attachment counts.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": EMAIL_VIEWER_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 55,
        "gap_id": VIEWER_WORKFLOW_GAP_IDS["email"],
        "batch_id": "commercial-uplift-051-055",
        "selected_track": "email-conversation-viewer-report-validation",
        "context": context,
        "path": str(source_path),
        "message_count": message_count,
        "thread_count": thread_count,
        "attachment_count": attachment_count,
        "parse_truncated": parse_truncated,
        "content_status": content_status,
        "conversation_manifest_hash": conversation_manifest_hash,
        "attachment_manifest_hash": attachment_manifest_hash,
        "message_hash_count": message_hash_count,
        "thread_hash_count": thread_hash_count,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(EMAIL_VIEWER_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage web -> source-preview for an EML/MBOX source",
            "GET /api/runs/<run_id>/source-email-attachment?path=<path>&message_index=<n>&attachment_index=<n>",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 55 --json",
        ],
        "report_guidance": {
            "allowed_use": "bounded-email-conversation-triage-pivot",
            "forbidden_claim": "native mailbox thread/deleted-item/attachment-complete analysis",
            "required_disclaimer": (
                "Email viewer output is bounded EML/MBOX-style conversation or attachment evidence until native "
                "PST/OST/MSG decoding, deleted-item recovery, native attachment extraction, Message-ID graph "
                "validation, trusted mailbox thread diffs, and mailbox corpus validation are attached."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def email_viewer_core_accuracy_gates(
    *,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
    conversation: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
    conversation_manifest: Mapping[str, object] | None = None,
    attachment_manifest: Mapping[str, object] | None = None,
    validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    threads = conversation.get("threads") if isinstance(conversation.get("threads"), list) else []
    satisfied = []
    if threads:
        satisfied.append("thread grouping")
    if any(isinstance(thread, Mapping) and thread.get("message_order") is not None for thread in threads):
        satisfied.append("message order")
    if messages and all(message.get("from") is not None and message.get("subject") is not None for message in messages):
        satisfied.append("participant/header preservation")
    if any(int(message.get("attachment_count") or 0) >= 0 for message in messages):
        satisfied.append("attachment inventory")
    conversation_manifest = conversation_manifest if isinstance(conversation_manifest, Mapping) else {}
    attachment_manifest = attachment_manifest if isinstance(attachment_manifest, Mapping) else {}
    if conversation_manifest.get("manifest_hash"):
        satisfied.append("email conversation source manifest")
    if int(conversation_manifest.get("message_hash_count") or 0) > 0:
        satisfied.append("email message hashes")
    if int(conversation_manifest.get("thread_hash_count") or 0) > 0:
        satisfied.append("email thread hashes")
    if attachment_manifest.get("manifest_hash"):
        satisfied.append("email attachment proof manifest")
    validation_plan = validation_plan if isinstance(validation_plan, Mapping) else {}
    if validation_plan.get("validation_plan_sha256"):
        satisfied.append("email viewer report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("email viewer report-grade ready slots")
    satisfied.append("mailbox threading limitation warning")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted email thread/export diff pass")
    return [
        build_accuracy_gate(
            55,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"source_path:{source_path}",
                f"message_count:{len(messages)}",
                f"thread_count:{len(threads)}",
                f"email_conversation_manifest_hash:{conversation_manifest.get('manifest_hash', '')}",
                f"email_attachment_manifest_hash:{attachment_manifest.get('manifest_hash', '')}",
                f"email_viewer_report_grade_validation_plan_sha256:{validation_plan.get('validation_plan_sha256', '')}",
                f"email_viewer_report_grade_ready_slot_count:{validation_plan.get('ready_slot_count', 0)}",
                f"email_viewer_report_grade_blocking_slot_count:{validation_plan.get('blocking_slot_count', 0)}",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
            ],
        )
    ]


def build_email_conversation_trusted_diff(
    rapid_threads: Sequence[Mapping[str, object]],
    trusted_threads: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "email-viewer-trusted-thread-export",
) -> dict[str, object]:
    rapid_index = {_email_thread_diff_key(row): _email_thread_diff_values(row) for row in rapid_threads}
    trusted_index = {_email_thread_diff_key(row): _email_thread_diff_values(row) for row in trusted_threads}
    return build_viewer_trusted_diff_result(
        profile_version="email-viewer-trusted-thread-export-v1",
        comparison_id=comparison_id,
        rapid_index=rapid_index,
        trusted_index=trusted_index,
        trusted_tool=trusted_tool,
        accepted_tools=EMAIL_VIEWER_TRUSTED_TOOLS,
        blocker_id=EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
        compare_fields=("subject", "message_count", "participants_sha256", "message_order_sha256", "attachment_count"),
    )


def read_bounded_email_bytes(source_path: Path, *, max_bytes: int | None = None) -> tuple[bytes, dict[str, object]]:
    max_bytes = EMAIL_PREVIEW_MAX_BYTES if max_bytes is None else max_bytes
    stat = source_path.stat()
    with source_path.open("rb") as handle:
        raw = handle.read(max_bytes + 1)
    source_truncated = len(raw) > max_bytes or stat.st_size > max_bytes
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    diagnostics = {
        "source_size": stat.st_size,
        "max_input_bytes": max_bytes,
        "source_truncated": source_truncated,
        "bytes_read": len(raw),
    }
    return raw, diagnostics


def parse_mbox_messages(source_path: Path) -> list[email.message.EmailMessage]:
    messages, _diagnostics = parse_mbox_messages_with_diagnostics(source_path)
    return messages


def parse_mbox_messages_with_diagnostics(source_path: Path) -> tuple[list[email.message.EmailMessage], dict[str, object]]:
    raw, diagnostics = read_bounded_email_bytes(source_path)
    chunks = re.split(rb"(?m)^From .*$", raw)
    messages = []
    message_size_truncated_count = 0
    for chunk in chunks:
        if not chunk.strip():
            continue
        parse_chunk = chunk.lstrip(b"\r\n")
        if len(parse_chunk) > EMAIL_PREVIEW_MESSAGE_MAX_BYTES:
            parse_chunk = parse_chunk[:EMAIL_PREVIEW_MESSAGE_MAX_BYTES]
            message_size_truncated_count += 1
        messages.append(email.message_from_bytes(parse_chunk, policy=policy.default))
        if len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT:
            break
    diagnostics.update(
        {
            "parse_mode": "bounded-mbox",
            "message_limit": EMAIL_PREVIEW_MESSAGE_LIMIT,
            "message_limit_reached": len(messages) >= EMAIL_PREVIEW_MESSAGE_LIMIT,
            "max_message_bytes": EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
            "message_size_truncated_count": message_size_truncated_count,
            "parsed_message_count": len(messages),
        }
    )
    return messages, diagnostics


def read_email_messages_with_diagnostics(source_path: Path, suffix: str) -> tuple[list[email.message.EmailMessage], dict[str, object]]:
    if suffix == ".eml":
        raw, diagnostics = read_bounded_email_bytes(source_path)
        parse_raw = raw
        message_truncated = False
        if len(parse_raw) > EMAIL_PREVIEW_MESSAGE_MAX_BYTES:
            parse_raw = parse_raw[:EMAIL_PREVIEW_MESSAGE_MAX_BYTES]
            message_truncated = True
        diagnostics.update(
            {
                "parse_mode": "bounded-eml",
                "message_limit": 1,
                "message_limit_reached": False,
                "max_message_bytes": EMAIL_PREVIEW_MESSAGE_MAX_BYTES,
                "message_size_truncated_count": 1 if diagnostics.get("source_truncated") or message_truncated else 0,
                "parsed_message_count": 1,
            }
        )
        return [email.message_from_bytes(parse_raw, policy=policy.default)], diagnostics
    return parse_mbox_messages_with_diagnostics(source_path)


def read_email_messages(source_path: Path, suffix: str) -> list[email.message.EmailMessage]:
    messages, _diagnostics = read_email_messages_with_diagnostics(source_path, suffix)
    return messages


def summarize_email_message(message: email.message.EmailMessage, index: int) -> dict[str, object]:
    attachments = []
    body_parts = []
    attachment_index = 0
    for part in message.walk():
        content_disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        content_type = part.get_content_type()
        if content_disposition == "attachment" or filename:
            attachment_index += 1
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                {
                    "index": attachment_index,
                    "filename": filename or "",
                    "content_type": content_type,
                    "content_id": str(part.get("content-id") or ""),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                    "exportable": len(payload) <= EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                    "export_limit": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                }
            )
            continue
        if content_type in {"text/plain", "text/html"}:
            try:
                body_parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                continue
    body = "\n".join(str(part) for part in body_parts)
    return {
        "index": index,
        "subject": str(message.get("subject") or ""),
        "from": str(message.get("from") or ""),
        "to": str(message.get("to") or ""),
        "cc": str(message.get("cc") or ""),
        "date": str(message.get("date") or ""),
        "message_id": str(message.get("message-id") or ""),
        "in_reply_to": str(message.get("in-reply-to") or ""),
        "references": str(message.get("references") or ""),
        "attachments": attachments[:20],
        "attachment_count": len(attachments),
        "body_preview": body[:EMAIL_BODY_PREVIEW_CHARS],
        "body_truncated": len(body) > EMAIL_BODY_PREVIEW_CHARS,
    }


def email_attachment_package_profile(
    *,
    run_id: str | None,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    quoted_path = quote(str(source_path))
    links = []
    for message in messages:
        message_index = optional_int_for_api(message.get("index")) or 0
        attachments = message.get("attachments") if isinstance(message.get("attachments"), Sequence) else []
        for attachment in attachments:
            if not isinstance(attachment, Mapping):
                continue
            attachment_index = optional_int_for_api(attachment.get("index")) or 0
            links.append(
                {
                    "message_index": message_index,
                    "attachment_index": attachment_index,
                    "filename": str(attachment.get("filename") or ""),
                    "size": optional_int_for_api(attachment.get("size")) or 0,
                    "sha256": str(attachment.get("sha256") or ""),
                    "package_url": (
                        f"/api/runs/{run_id}/source-email-attachment?path={quoted_path}&message_index={message_index}&attachment_index={attachment_index}"
                        if run_id and message_index and attachment_index
                        else None
                    ),
                }
            )
    return {
        "profile_version": "email-attachment-package-profile-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "endpoint": "/api/runs/{run_id}/source-email-attachment",
        "attachment_count": len(links),
        "links": links[:50],
        "max_inline_content_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
        "supports_hash_inventory": True,
        "supports_bounded_content_export": True,
        "native_pst_ost_msg_supported": False,
        "report_use_warning": "Validate attachment hashes and mailbox/thread reconstruction with a trusted mailbox parser before report-grade use.",
    }


def build_email_attachment_package(
    *,
    run_id: str,
    source_path: Path,
    suffix: str,
    message_index: int,
    attachment_index: int,
    include_content: bool,
) -> dict[str, object]:
    try:
        messages, diagnostics = read_email_messages_with_diagnostics(source_path, suffix)
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f"Email attachment package failed: {exc}") from exc
    if message_index > len(messages):
        detail = (
            "message_index not found within bounded email parse"
            if diagnostics.get("source_truncated") or diagnostics.get("message_limit_reached")
            else "message_index not found"
        )
        raise HTTPException(status_code=404, detail=detail)
    message = messages[message_index - 1]
    attachments: list[tuple[email.message.EmailMessage, bytes]] = []
    for part in message.walk():
        if str(part.get_content_disposition() or "") == "attachment" or part.get_filename():
            attachments.append((part, part.get_payload(decode=True) or b""))
    if attachment_index > len(attachments):
        raise HTTPException(status_code=404, detail="attachment_index not found")
    part, payload = attachments[attachment_index - 1]
    hashes = compute_hashes_for_bytes(payload)
    content_b64 = ""
    content_status = "not-requested"
    if include_content:
        if len(payload) > EMAIL_ATTACHMENT_EXPORT_MAX_BYTES:
            content_status = "too-large"
        else:
            content_b64 = base64.b64encode(payload).decode("ascii")
            content_status = "included-base64"
    citation_id = hashlib.sha256(
        f"{run_id}|{source_path}|{message_index}|{attachment_index}|{hashes['sha256']}".encode()
    ).hexdigest()[:16]
    proof_manifest = build_email_attachment_proof_manifest(
        source_path=source_path,
        message_index=message_index,
        attachment_index=attachment_index,
        filename=part.get_filename() or "",
        content_type=part.get_content_type(),
        size=len(payload),
        hashes=hashes,
        content_status=content_status,
        citation_id=citation_id,
    )
    validation_plan = build_email_viewer_report_grade_validation_plan(
        context="email-attachment-package",
        source_path=source_path,
        messages=[
            {
                "index": message_index,
                "from": str(message.get("from") or ""),
                "subject": str(message.get("subject") or ""),
                "attachment_count": 1,
            }
        ],
        conversation={"threads": []},
        attachment_manifest=proof_manifest,
        content_status=content_status,
        copy_safe_citation_ready=True,
    )
    core_accuracy_gates = email_viewer_core_accuracy_gates(
        source_path=source_path,
        messages=[
            {
                "index": message_index,
                "from": str(message.get("from") or ""),
                "subject": str(message.get("subject") or ""),
                "attachment_count": 1,
            }
        ],
        conversation={"threads": []},
        attachment_manifest=proof_manifest,
        validation_plan=validation_plan,
    )
    return {
        "command": "source-email-attachment",
        "profile_version": "email-attachment-package-v1",
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "name": source_path.name,
        "message_index": message_index,
        "attachment_index": attachment_index,
        "filename": part.get_filename() or "",
        "content_type": part.get_content_type(),
        "content_id": str(part.get("content-id") or ""),
        "size": len(payload),
        "hashes": hashes,
        "content_status": content_status,
        "content_base64": content_b64,
        "max_inline_content_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
        "email_parse_diagnostics": diagnostics,
        "email_attachment_proof_manifest": proof_manifest,
        "email_attachment_proof_manifest_hash": proof_manifest["manifest_hash"],
        "email_viewer_report_grade_validation_plan": validation_plan,
        "email_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "copy_safe_citation": {
            "text": (
                f"Source={source_path.name}; message_index={message_index}; attachment_index={attachment_index}; "
                f"filename={part.get_filename() or ''}; size={len(payload)}; sha256={hashes['sha256']}; citation_id={citation_id}"
            ),
            "redacts_full_path": True,
        },
        "reportability_decision": viewer_workflow_reportability_decision(
            item_number=55,
            component="email-attachment-package",
            blockers=[
                "trusted-mailbox-thread-export-required-before-court-use",
                "native-pst-ost-msg-attachment-extraction-not-implemented",
                "deleted-mailbox-item-recovery-not-implemented",
            ],
            controls={
                "hashes": True,
                "bounded_content_export": include_content and content_status == "included-base64",
                "max_inline_content_bytes": EMAIL_ATTACHMENT_EXPORT_MAX_BYTES,
                "native_pst_ost_msg": False,
                "email_parse_diagnostics": diagnostics,
                "email_viewer_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "email_viewer_report_grade_ready_slot_count": validation_plan["ready_slot_count"],
                "email_viewer_report_grade_blocking_slot_count": validation_plan["blocking_slot_count"],
            },
        ),
        "core_accuracy_gates": core_accuracy_gates,
    }


def build_email_attachment_proof_manifest(
    *,
    source_path: Path,
    message_index: int,
    attachment_index: int,
    filename: str,
    content_type: str,
    size: int,
    hashes: Mapping[str, str],
    content_status: str,
    citation_id: str,
) -> dict[str, object]:
    attachment_core = {
        "message_index": message_index,
        "attachment_index": attachment_index,
        "filename": filename,
        "content_type": content_type,
        "size": size,
        "sha256": str(hashes.get("sha256") or ""),
        "content_status": content_status,
    }
    manifest_core: dict[str, object] = {
        "manifest_version": "email-attachment-proof-manifest-v1",
        "item_number": 55,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "citation_id": citation_id,
        "path": str(source_path),
        "attachment": attachment_core,
        "attachment_hash": stable_payload_sha256(attachment_core),
        "source_viewer_locator": {
            "viewer": "source-email-attachment",
            "path": str(source_path),
            "message_index": message_index,
            "attachment_index": attachment_index,
            "open_action": "open-email-attachment-citation-package",
        },
        "blockers": [
            "trusted-mailbox-thread-export-required-before-court-use",
            "native-pst-ost-msg-attachment-extraction-not-implemented",
            "deleted-mailbox-item-recovery-not-implemented",
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def build_email_threads(messages: list[dict[str, object]]) -> list[dict[str, object]]:
    buckets: dict[str, list[dict[str, object]]] = {}
    for message in messages:
        buckets.setdefault(email_thread_key(message), []).append(message)
    threads = []
    for key, rows in sorted(buckets.items(), key=lambda item: (thread_sort_date(item[1]), item[0])):
        threads.append(
            {
                "thread_id": hashlib.sha256(key.encode("utf-8")).hexdigest()[:16],
                "subject": rows[0].get("subject") or "(no subject)",
                "message_count": len(rows),
                "participants": sorted(
                    {
                        value
                        for row in rows
                        for value in (
                            str(row.get("from") or ""),
                            str(row.get("to") or ""),
                            str(row.get("cc") or ""),
                        )
                        if value
                    }
                )[:20],
                "message_indices": [int(row["index"]) for row in rows if isinstance(row.get("index"), int)],
                "first_date": rows[0].get("date") or "",
                "last_date": rows[-1].get("date") or "",
                "attachment_count": sum(int(row.get("attachment_count") or 0) for row in rows),
            }
        )
    return threads


def build_email_conversation_viewer(
    messages: list[dict[str, object]],
    threads: list[dict[str, object]],
) -> dict[str, object]:
    message_by_index = {int(message["index"]): message for message in messages if isinstance(message.get("index"), int)}
    thread_rows = []
    for thread in threads:
        indices = [int(index) for index in thread.get("message_indices", []) if isinstance(index, int)]
        rows = [message_by_index[index] for index in indices if index in message_by_index]
        thread_rows.append(
            {
                "thread_id": thread.get("thread_id"),
                "subject": thread.get("subject"),
                "message_count": len(rows),
                "participants": thread.get("participants", []),
                "first_date": thread.get("first_date", ""),
                "last_date": thread.get("last_date", ""),
                "attachment_count": thread.get("attachment_count", 0),
                "message_order": [
                    {
                        "index": row.get("index"),
                        "date": row.get("date", ""),
                        "from": row.get("from", ""),
                        "to": row.get("to", ""),
                        "subject": row.get("subject", ""),
                        "message_id": row.get("message_id", ""),
                        "reply_to": row.get("in_reply_to", ""),
                    }
                    for row in rows
                ],
                "validation_checks": {
                    "message_id_present": all(bool(row.get("message_id")) for row in rows) if rows else False,
                    "reply_headers_present": any(bool(row.get("in_reply_to") or row.get("references")) for row in rows),
                    "body_preview_present": any(bool(row.get("body_preview")) for row in rows),
                    "attachment_inventory_present": any(int(row.get("attachment_count") or 0) > 0 for row in rows),
                    "mailbox_known_answer_validated": False,
                },
            }
        )
    return {
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "thread_count": len(thread_rows),
        "threads": thread_rows,
        "review_hint": "Review thread order, participants, attachments, and source message headers before reporting email conversation conclusions.",
    }


def build_email_conversation_manifest(
    *,
    source_path: Path,
    messages: Sequence[Mapping[str, object]],
    conversation: Mapping[str, object],
    attachment_profile: Mapping[str, object],
) -> dict[str, object]:
    message_entries: list[dict[str, object]] = []
    for message in messages[:EMAIL_PREVIEW_MESSAGE_LIMIT]:
        body_preview = str(message.get("body_preview") or "")
        attachments = message.get("attachments") if isinstance(message.get("attachments"), Sequence) else []
        attachment_rows = [
            {
                "index": attachment.get("index"),
                "filename": str(attachment.get("filename") or ""),
                "content_type": str(attachment.get("content_type") or ""),
                "size": attachment.get("size"),
                "sha256": str(attachment.get("sha256") or ""),
            }
            for attachment in attachments
            if isinstance(attachment, Mapping)
        ]
        message_core = {
            "index": message.get("index"),
            "subject": str(message.get("subject") or ""),
            "from": str(message.get("from") or ""),
            "to": str(message.get("to") or ""),
            "cc": str(message.get("cc") or ""),
            "date": str(message.get("date") or ""),
            "message_id": str(message.get("message_id") or ""),
            "in_reply_to": str(message.get("in_reply_to") or ""),
            "references_sha256": hashlib.sha256(str(message.get("references") or "").encode("utf-8", errors="replace")).hexdigest(),
            "body_preview_sha256": hashlib.sha256(body_preview.encode("utf-8", errors="replace")).hexdigest() if body_preview else "",
            "attachment_count": int(message.get("attachment_count") or 0),
            "attachments": attachment_rows,
        }
        message_entries.append({**message_core, "message_hash": stable_payload_sha256(message_core)})
    thread_entries: list[dict[str, object]] = []
    threads = conversation.get("threads") if isinstance(conversation.get("threads"), Sequence) else []
    for thread in threads:
        if not isinstance(thread, Mapping):
            continue
        thread_core = {
            "thread_id": str(thread.get("thread_id") or ""),
            "subject": str(thread.get("subject") or ""),
            "message_count": int(thread.get("message_count") or 0),
            "participants": list(thread.get("participants") or []),
            "first_date": str(thread.get("first_date") or ""),
            "last_date": str(thread.get("last_date") or ""),
            "attachment_count": int(thread.get("attachment_count") or 0),
            "message_order": [
                {
                    "index": row.get("index"),
                    "date": str(row.get("date") or ""),
                    "message_id": str(row.get("message_id") or ""),
                    "reply_to": str(row.get("reply_to") or ""),
                }
                for row in thread.get("message_order", [])
                if isinstance(row, Mapping)
            ],
        }
        thread_entries.append({**thread_core, "thread_hash": stable_payload_sha256(thread_core)})
    manifest_core: dict[str, object] = {
        "manifest_version": "email-conversation-source-manifest-v1",
        "item_number": 55,
        "commercial_gap_ids": [VIEWER_WORKFLOW_GAP_IDS["email"]],
        "path": str(source_path),
        "name": source_path.name,
        "message_count": len(messages),
        "bounded_message_count": len(message_entries),
        "thread_count": len(thread_entries),
        "message_hash_count": sum(1 for message in message_entries if message.get("message_hash")),
        "thread_hash_count": sum(1 for thread in thread_entries if thread.get("thread_hash")),
        "attachment_package_count": int(attachment_profile.get("attachment_count") or 0),
        "source_viewer_locator": {
            "viewer": "source-email-conversation",
            "path": str(source_path),
            "open_action": "open-email-conversation-thread-view",
        },
        "messages": message_entries,
        "threads": thread_entries,
        "blockers": [
            "native-pst-ost-msg-conversation-view-not-implemented",
            "deleted-mailbox-item-recovery-not-implemented",
            EMAIL_VIEWER_TRUSTED_DIFF_BLOCKER,
        ],
        "commercial_claim_allowed": False,
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def email_thread_key(message: Mapping[str, object]) -> str:
    references = str(message.get("references") or "").strip()
    in_reply_to = str(message.get("in_reply_to") or "").strip()
    if references:
        return references.split()[0]
    if in_reply_to:
        return in_reply_to
    subject = re.sub(r"^(re|fw|fwd):\s*", "", str(message.get("subject") or ""), flags=re.IGNORECASE).strip().lower()
    participants = "|".join(
        sorted(
            value.lower()
            for value in (str(message.get("from") or ""), str(message.get("to") or ""))
            if value
        )
    )
    return f"{subject}|{participants}"


def thread_sort_date(messages: list[dict[str, object]]) -> str:
    return str(messages[0].get("date") or "") if messages else ""
