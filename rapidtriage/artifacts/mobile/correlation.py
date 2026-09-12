from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..review import build_forensic_review
from .constants import (
    MAX_CHAT_DB_SAMPLE_ROWS,
    MAX_MOBILE_CORRELATION_TIMELINE_ROWS,
    MAX_ROWS_PER_SOURCE,
    MOBILE_ACTOR_REPORT_GRADE_BLOCKERS,
    MOBILE_ACTOR_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS,
    MOBILE_CORRELATION_TRUSTED_TOOLS,
    MOBILE_TIMELINE_REPORT_GRADE_BLOCKERS,
    MOBILE_TIMELINE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
)
from .detect import (
    first_mobile_alias,
)
from .helpers import (
    normalized_mobile_diff_value,
    optional_text,
    sha256_text,
    stable_mobile_sha256,
    unique_non_empty,
)
from .vendor import (
    build_mobile_schema_compatibility_profile,
    build_mobile_schema_report_grade_validation_plan,
    build_mobile_schema_version_manifest,
    build_schema_version_registry,
)


def build_mobile_correlation_summary(rows: list[Mapping[str, object]]) -> dict[str, object]:
    message_rows = [row for row in rows if row.get("artifact_type") == "mobile-message"]
    media_rows = [row for row in rows if row.get("artifact_type") == "mobile-media"]
    contact_rows = [row for row in rows if row.get("artifact_type") == "mobile-contact"]
    call_rows = [row for row in rows if row.get("artifact_type") == "mobile-call"]
    app_rows = [row for row in rows if row.get("artifact_type") == "mobile-app"]
    services = sorted({optional_text(row.get("service")) for row in rows if optional_text(row.get("service"))})
    participants = sorted(
        {
            participant
            for row in message_rows
            for participant in row.get("participants", [])
            if isinstance(participant, str) and participant
        }
    )
    schema_versions = sorted(
        {
            f"{optional_text(row.get('service') or 'unknown')}:{optional_text(row.get('schema_version'))}"
            for row in message_rows
            if optional_text(row.get("schema_version"))
        }
    )
    message_media_links = build_message_media_links(message_rows, media_rows)
    unified_actor_view = build_unified_contact_call_sms_view(message_rows, contact_rows, call_rows)
    schema_version_registry = build_schema_version_registry([*message_rows, *app_rows])
    timeline_profile = build_mobile_timeline_correlation_profile(
        message_rows=message_rows,
        media_rows=media_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        message_media_links=message_media_links,
    )
    correlation_citation_manifest = build_mobile_correlation_citation_manifest(
        message_rows=message_rows,
        media_rows=media_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        message_media_links=message_media_links,
        timeline_profile=timeline_profile,
    )
    timeline_report_grade_validation_plan = build_mobile_timeline_report_grade_validation_plan(
        message_rows=message_rows,
        media_rows=media_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        message_media_links=message_media_links,
        timeline_profile=timeline_profile,
        citation_manifest=correlation_citation_manifest,
    )
    actor_review_profile = build_mobile_actor_review_profile(unified_actor_view)
    actor_citation_manifest = build_mobile_actor_citation_manifest(
        actor_rows=unified_actor_view,
        message_rows=message_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
    )
    actor_report_grade_validation_plan = build_mobile_actor_report_grade_validation_plan(
        actor_rows=unified_actor_view,
        message_rows=message_rows,
        contact_rows=contact_rows,
        call_rows=call_rows,
        actor_review_profile=actor_review_profile,
        actor_citation_manifest=actor_citation_manifest,
    )
    schema_compatibility_profile = build_mobile_schema_compatibility_profile(schema_version_registry)
    schema_version_manifest = build_mobile_schema_version_manifest(
        registry=schema_version_registry,
        source_rows=[*message_rows, *app_rows],
    )
    schema_report_grade_validation_plan = build_mobile_schema_report_grade_validation_plan(
        registry=schema_version_registry,
        source_rows=[*message_rows, *app_rows],
        schema_compatibility_profile=schema_compatibility_profile,
        schema_version_manifest=schema_version_manifest,
    )
    validation_checks = {
        "message_media_correlation_available": bool(message_rows and media_rows),
        "media_message_links_built": bool(message_media_links),
        "contact_message_correlation_available": bool(contact_rows and message_rows),
        "call_message_correlation_available": bool(call_rows and message_rows),
        "unified_contact_call_sms_view_built": bool(unified_actor_view),
        "actor_review_profile_built": bool(actor_review_profile.get("actor_count")),
        "timeline_correlation_profile_built": bool(timeline_profile.get("event_count")),
        "app_specific_schema_versions_tracked": bool(schema_versions),
        "schema_version_registry_built": bool(schema_version_registry),
        "schema_compatibility_profile_built": bool(schema_compatibility_profile.get("entry_count")),
        "schema_version_manifest_built": bool(schema_version_manifest.get("schema_entry_count")),
        "schema_version_registry_known_answer_validated": False,
        "correlation_validated_against_known_answer": False,
    }
    return {
        "event_type": "mobile-correlation-summary",
        "timestamp": "",
        "message_count": len(message_rows),
        "media_count": len(media_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "service_count": len(services),
        "services": services,
        "participants": participants[:200],
        "participant_count": len(participants),
        "schema_versions": schema_versions,
        "schema_version_registry": schema_version_registry,
        "schema_version_registry_count": len(schema_version_registry),
        "mobile_schema_compatibility_profile": schema_compatibility_profile,
        "mobile_schema_version_manifest": schema_version_manifest,
        "mobile_schema_version_manifest_hash": schema_version_manifest["manifest_sha256"],
        "mobile_schema_report_grade_validation_plan": schema_report_grade_validation_plan,
        "mobile_schema_report_grade_validation_plan_hash": schema_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "message_media_links": message_media_links,
        "media_message_link_count": len(message_media_links),
        "mobile_timeline_correlation_profile": timeline_profile,
        "mobile_correlation_citation_manifest": correlation_citation_manifest,
        "mobile_correlation_citation_manifest_hash": correlation_citation_manifest["manifest_sha256"],
        "mobile_timeline_report_grade_validation_plan": timeline_report_grade_validation_plan,
        "mobile_timeline_report_grade_validation_plan_hash": timeline_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "unified_contact_call_sms_view": unified_actor_view,
        "unified_contact_call_sms_view_count": len(unified_actor_view),
        "mobile_actor_review_profile": actor_review_profile,
        "mobile_actor_citation_manifest": actor_citation_manifest,
        "mobile_actor_citation_manifest_hash": actor_citation_manifest["manifest_sha256"],
        "mobile_actor_report_grade_validation_plan": actor_report_grade_validation_plan,
        "mobile_actor_report_grade_validation_plan_hash": actor_report_grade_validation_plan[
            "validation_plan_sha256"
        ],
        "timeline_correlation_ready": bool(message_rows or media_rows or call_rows),
        "validation_checks": validation_checks,
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "mobile_correlation_report_grade_assessment": mobile_correlation_report_grade_assessment(),
        "mobile_correlation_commercial_uplift_evidence": mobile_correlation_commercial_uplift_evidence(
            message_count=len(message_rows),
            media_count=len(media_rows),
            contact_count=len(contact_rows),
            call_count=len(call_rows),
            services=services,
            participant_count=len(participants),
            message_media_link_count=len(message_media_links),
            unified_actor_count=len(unified_actor_view),
            schema_version_count=len(schema_version_registry),
            validation_checks=validation_checks,
            timeline_profile=timeline_profile,
            citation_manifest=correlation_citation_manifest,
            timeline_validation_plan=timeline_report_grade_validation_plan,
            actor_review_profile=actor_review_profile,
            actor_citation_manifest=actor_citation_manifest,
            actor_validation_plan=actor_report_grade_validation_plan,
            schema_compatibility_profile=schema_compatibility_profile,
            schema_version_manifest=schema_version_manifest,
            schema_validation_plan=schema_report_grade_validation_plan,
        ),
        "forensic_review": mobile_correlation_forensic_review(
            message_count=len(message_rows),
            media_count=len(media_rows),
            contact_count=len(contact_rows),
            call_count=len(call_rows),
            services=services,
            message_media_link_count=len(message_media_links),
            unified_actor_count=len(unified_actor_view),
            schema_version_count=len(schema_version_registry),
        ),
        "commercial_grade_blockers": [
            "Correlation is source-export scoped and does not prove device-wide completeness.",
            "App-specific schema versions, timezone semantics, deleted rows, and media attachment recovery need known-answer validation.",
        ],
        "risk_flags": ["mobile-correlation-summary"],
        "reporting_guidance": "Use this summary to pivot between messages, contacts, calls, media, and app rows before building a report timeline.",
    }


def build_message_media_links(
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    links: list[dict[str, object]] = []
    for message in message_rows:
        reference = optional_text(message.get("media_reference") or message.get("attachment_name"))
        reference_hash = optional_text(message.get("media_reference_sha256"))
        if not reference and not reference_hash:
            continue
        reference_name = Path(reference).name.lower() if reference else ""
        matched = False
        for media in media_rows:
            media_path = optional_text(media.get("media_path"))
            media_name = optional_text(media.get("file_name") or (Path(media_path).name if media_path else ""))
            media_hashes = {
                optional_text(media.get("md5")).lower(),
                optional_text(media.get("sha1")).lower(),
                optional_text(media.get("sha256")).lower(),
            }
            matched_by: list[str] = []
            haystack = f"{media_path} {media_name}".lower()
            if reference and reference.lower() in haystack:
                matched_by.append("path-reference")
            elif reference_name and reference_name in haystack:
                matched_by.append("filename-reference")
            if reference_hash and reference_hash.lower() in media_hashes:
                matched_by.append("hash-reference")
            if not matched_by:
                continue
            matched = True
            links.append(
                {
                    "message_id": optional_text(message.get("message_id")),
                    "message_timestamp": optional_text(message.get("timestamp")),
                    "service": optional_text(message.get("service")),
                    "media_reference": reference,
                    "media_path": media_path,
                    "media_sha256": optional_text(media.get("sha256")),
                    "matched_by": matched_by,
                    "validation_status": "candidate",
                }
            )
            if len(links) >= limit:
                return links
        if not matched:
            links.append(
                {
                    "message_id": optional_text(message.get("message_id")),
                    "message_timestamp": optional_text(message.get("timestamp")),
                    "service": optional_text(message.get("service")),
                    "media_reference": reference,
                    "media_path": "",
                    "media_sha256": "",
                    "matched_by": ["unresolved-message-reference"],
                    "validation_status": "unresolved-candidate",
                }
            )
            if len(links) >= limit:
                return links
    return links


def build_mobile_timeline_correlation_profile(
    *,
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    message_media_links: list[Mapping[str, object]],
    limit: int = MAX_MOBILE_CORRELATION_TIMELINE_ROWS,
) -> dict[str, object]:
    media_link_by_message = {
        optional_text(link.get("message_id")): link
        for link in message_media_links
        if optional_text(link.get("message_id"))
    }
    events: list[dict[str, object]] = []
    missing_timestamp_count = 0

    def append_event(row: Mapping[str, object], event_type: str, actor: str, summary: str) -> None:
        nonlocal missing_timestamp_count
        timestamp = optional_text(row.get("timestamp"))
        if not timestamp:
            missing_timestamp_count += 1
        events.append(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "service": optional_text(row.get("service")),
                "actor": actor,
                "summary": summary[:240],
                "source_record_id": optional_text(row.get("source_record_id") or row.get("message_id")),
                "message_id": optional_text(row.get("message_id")),
                "media_reference": optional_text(row.get("media_reference") or row.get("attachment_name")),
                "media_link_status": mobile_media_link_status(row, media_link_by_message),
                "validation_status": "candidate",
            }
        )

    for message in message_rows:
        actor = optional_text(message.get("sender") or message.get("recipient") or "")
        append_event(message, "message", actor, optional_text(message.get("text") or message.get("message_text_sha256")))
    for media in media_rows:
        append_event(
            media,
            "media",
            optional_text(media.get("owner") or media.get("account") or ""),
            optional_text(media.get("media_path") or media.get("file_name") or media.get("sha256")),
        )
    for call in call_rows:
        append_event(
            call,
            "call",
            optional_text(call.get("phone_number") or call.get("contact_name") or ""),
            optional_text(call.get("call_type") or "call"),
        )

    events.sort(key=lambda event: (not bool(event.get("timestamp")), str(event.get("timestamp")), str(event.get("event_type"))))
    unresolved_link_count = sum(
        1 for link in message_media_links if link.get("validation_status") == "unresolved-candidate"
    )
    linked_count = sum(1 for link in message_media_links if link.get("validation_status") == "candidate")
    return {
        "profile_version": "mobile-timeline-correlation-v1",
        "selected_track": "source-export-bounded-message-media-call-timeline",
        "event_count": len(events),
        "events": events[:limit],
        "event_cap": limit,
        "event_truncated": len(events) > limit,
        "message_event_count": len(message_rows),
        "media_event_count": len(media_rows),
        "call_event_count": len(call_rows),
        "contact_record_count": len(contact_rows),
        "missing_timestamp_count": missing_timestamp_count,
        "message_media_link_count": len(message_media_links),
        "resolved_media_link_count": linked_count,
        "unresolved_media_link_count": unresolved_link_count,
        "device_wide_timeline_ready": False,
        "known_answer_correlation_required": True,
        "timezone_validation_required": True,
        "reporting_status": "candidate-timeline-correlation-validation-required",
        "required_before_report": [
            "validate message/media/call ordering against a known-answer device or trusted vendor timeline",
            "verify attachment bytes and hashes before treating media metadata as recovered media",
            "record timezone assumptions and device clock skew before report-grade chronology claims",
        ],
    }


def build_mobile_correlation_citation_manifest(
    *,
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    message_media_links: list[Mapping[str, object]],
    timeline_profile: Mapping[str, object],
    limit: int = MAX_MOBILE_CORRELATION_TIMELINE_ROWS,
) -> dict[str, object]:
    source_rows = [*message_rows, *media_rows, *contact_rows, *call_rows]
    row_citations: list[dict[str, object]] = []
    for index, row in enumerate(source_rows[:limit], start=1):
        row_type = optional_text(row.get("artifact_type") or row.get("event_type") or "mobile-row")
        citation_payload = {
            "citation_index": index,
            "row_type": row_type,
            "source_index": int(row.get("source_index") or 0),
            "source_record_id": optional_text(row.get("source_record_id") or row.get("message_id")),
            "timestamp": optional_text(row.get("timestamp")),
            "service": optional_text(row.get("service")),
            "message_id": optional_text(row.get("message_id")),
            "media_reference_sha256": optional_text(row.get("media_reference_sha256")),
            "media_sha256": optional_text(row.get("sha256")),
            "actor_hash": sha256_text(
                optional_text(
                    row.get("sender")
                    or row.get("recipient")
                    or row.get("phone_number")
                    or row.get("contact_name")
                    or row.get("account_identifier")
                )
            )
            if optional_text(
                row.get("sender")
                or row.get("recipient")
                or row.get("phone_number")
                or row.get("contact_name")
                or row.get("account_identifier")
            )
            else "",
        }
        row_citations.append(
            {
                **citation_payload,
                "row_hash": stable_mobile_sha256(citation_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-export-row",
                    "source_index": citation_payload["source_index"],
                    "source_record_id": citation_payload["source_record_id"],
                    "row_type": row_type,
                    "open_requires_authority": False,
                },
            }
        )

    link_citations: list[dict[str, object]] = []
    for index, link in enumerate(message_media_links[:limit], start=1):
        link_payload = {
            "link_index": index,
            "message_id": optional_text(link.get("message_id")),
            "message_timestamp": optional_text(link.get("message_timestamp")),
            "service": optional_text(link.get("service")),
            "media_reference_sha256": sha256_text(optional_text(link.get("media_reference")))
            if optional_text(link.get("media_reference"))
            else "",
            "media_sha256": optional_text(link.get("media_sha256")),
            "validation_status": optional_text(link.get("validation_status")),
            "matched_by": list(link.get("matched_by") or []),
        }
        link_citations.append(
            {
                **link_payload,
                "link_hash": stable_mobile_sha256(link_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-message-media-link",
                    "message_id": link_payload["message_id"],
                    "validation_status": link_payload["validation_status"],
                    "open_requires_attachment_validation": link_payload["validation_status"] != "candidate",
                },
            }
        )

    timeline_events = [
        event for event in timeline_profile.get("events", []) if isinstance(event, Mapping)
    ]
    timeline_citations: list[dict[str, object]] = []
    for index, event in enumerate(timeline_events[:limit], start=1):
        event_payload = {
            "event_index": index,
            "timestamp": optional_text(event.get("timestamp")),
            "event_type": optional_text(event.get("event_type")),
            "service": optional_text(event.get("service")),
            "source_record_id": optional_text(event.get("source_record_id")),
            "message_id": optional_text(event.get("message_id")),
            "media_link_status": optional_text(event.get("media_link_status")),
            "validation_status": optional_text(event.get("validation_status")),
        }
        timeline_citations.append(
            {
                **event_payload,
                "event_hash": stable_mobile_sha256(event_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-correlation-timeline-event",
                    "event_index": index,
                    "source_record_id": event_payload["source_record_id"],
                    "message_id": event_payload["message_id"],
                },
            }
        )

    manifest: dict[str, object] = {
        "manifest_version": "mobile-correlation-citation-manifest-v1",
        "item_number": 43,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-message-media-call-timeline-citations",
        "row_citation_count": len(row_citations),
        "row_citation_cap": limit,
        "row_citations_truncated": len(source_rows) > limit,
        "row_citations": row_citations,
        "message_media_link_citation_count": len(link_citations),
        "message_media_link_citations": link_citations,
        "timeline_event_citation_count": len(timeline_citations),
        "timeline_event_citations": timeline_citations,
        "event_count": int(timeline_profile.get("event_count") or 0),
        "event_cap": int(timeline_profile.get("event_cap") or limit),
        "timeline_event_truncated": bool(timeline_profile.get("event_truncated")),
        "resolved_media_link_count": int(timeline_profile.get("resolved_media_link_count") or 0),
        "unresolved_media_link_count": int(timeline_profile.get("unresolved_media_link_count") or 0),
        "device_wide_timeline_ready": False,
        "timezone_validation_required": True,
        "known_answer_correlation_required": True,
        "passed_validation_check_ids": [
            "mobile-correlation-citation-manifest-emitted",
            "mobile-source-row-citations-built",
            "mobile-timeline-event-citations-built",
        ],
        "failed_validation_check_ids": [
            "device-wide-timeline-not-validated",
            "timezone-clock-skew-not-validated",
            "attachment-byte-recovery-not-validated",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[43],
        ],
        "commercial_blockers": [
            "device-wide-timeline-not-validated",
            "timezone-clock-skew-not-validated",
            "attachment-byte-recovery-not-validated",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[43],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_timeline_report_grade_validation_plan(
    *,
    message_rows: list[Mapping[str, object]],
    media_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    message_media_links: list[Mapping[str, object]],
    timeline_profile: Mapping[str, object],
    citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    timeline_profile_hash = stable_mobile_sha256(timeline_profile)
    citation_manifest_hash = optional_text(citation_manifest.get("manifest_sha256"))
    timeline_event_citation_count = int(citation_manifest.get("timeline_event_citation_count") or 0)
    message_media_link_citation_count = int(citation_manifest.get("message_media_link_citation_count") or 0)
    event_count = int(timeline_profile.get("event_count") or 0)
    event_cap = int(timeline_profile.get("event_cap") or MAX_MOBILE_CORRELATION_TIMELINE_ROWS)

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

    validation_slots = [
        slot(
            "mobile-timeline-source-row-counts-preserved",
            ready=True,
            evidence=(
                f"messages={len(message_rows)} media={len(media_rows)} "
                f"contacts={len(contact_rows)} calls={len(call_rows)}"
            ),
        ),
        slot(
            "mobile-timeline-profile-emitted",
            ready=timeline_profile.get("profile_version") == "mobile-timeline-correlation-v1",
            evidence=f"timeline_profile_sha256={timeline_profile_hash}",
            blocker_id="mobile-timeline-profile-required",
            operator_action="Regenerate the mobile export so the bounded timeline correlation profile is emitted.",
        ),
        slot(
            "mobile-correlation-citation-manifest-emitted",
            ready=bool(citation_manifest_hash),
            evidence=f"citation_manifest_sha256={citation_manifest_hash}",
            blocker_id="mobile-correlation-citation-manifest-required",
            operator_action="Regenerate the mobile export so row, link, and timeline citations are hashable.",
        ),
        slot(
            "mobile-timeline-event-source-citations",
            ready=timeline_event_citation_count > 0,
            evidence=f"timeline_event_citation_count={timeline_event_citation_count}",
            blocker_id="mobile-timeline-event-source-citations-required",
            operator_action="Attach source row locators for every report-selected timeline event.",
        ),
        slot(
            "mobile-message-media-link-citations",
            ready=message_media_link_citation_count > 0,
            evidence=f"message_media_link_citation_count={message_media_link_citation_count}",
            blocker_id="mobile-message-media-link-citations-required",
            operator_action="Attach source locators for message-to-media links before reporting attachment correlation.",
        ),
        slot(
            "mobile-timeline-row-cap-and-truncation-disclosed",
            ready=event_cap > 0,
            evidence=(
                f"event_count={event_count} event_cap={event_cap} "
                f"event_truncated={bool(timeline_profile.get('event_truncated'))}"
            ),
            blocker_id="mobile-timeline-row-cap-disclosure-required",
            operator_action="Record row caps and truncation status before reviewing large mobile timelines.",
        ),
        slot(
            "mobile-correlation-device-wide-timeline",
            ready=False,
            evidence="device_wide_timeline_ready=false",
            blocker_id="mobile-correlation-device-wide-timeline-required",
            operator_action="Join app export rows with filesystem, acquisition, and device metadata timelines.",
        ),
        slot(
            "mobile-correlation-timezone-skew-validation",
            ready=False,
            evidence="timezone_and_clock_skew_validated=false",
            blocker_id="mobile-correlation-timezone-skew-validation-required",
            operator_action="Validate source timezone semantics and device clock skew against acquisition metadata.",
        ),
        slot(
            "mobile-correlation-attachment-byte-recovery",
            ready=False,
            evidence=(
                f"resolved_media_link_count={int(timeline_profile.get('resolved_media_link_count') or 0)} "
                f"unresolved_media_link_count={int(timeline_profile.get('unresolved_media_link_count') or 0)}"
            ),
            blocker_id="mobile-correlation-attachment-byte-recovery-required",
            operator_action="Recover attachment bytes and hash them before claiming media was recovered.",
        ),
        slot(
            "mobile-correlation-vendor-timeline-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[43],
            operator_action="Attach a passing Cellebrite/XRY/GrayKey/AXIOM/iLEAPP/native timeline diff.",
        ),
        slot(
            "mobile-correlation-known-answer-corpus",
            ready=False,
            evidence="known_answer_corpus_attached=false",
            blocker_id="mobile-correlation-known-answer-corpus-required",
            operator_action="Validate message/media/call chronology against a known-answer mobile corpus.",
        ),
        slot(
            "mobile-correlation-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="mobile-correlation-independent-review-required",
            operator_action="Attach independent reviewer signoff before device-wide timeline wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": MOBILE_TIMELINE_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 43,
        "gap_id": "#43",
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-message-media-call-timeline-report-validation",
        "message_count": len(message_rows),
        "media_count": len(media_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "message_media_link_count": len(message_media_links),
        "timeline_event_count": event_count,
        "timeline_event_cap": event_cap,
        "timeline_event_truncated": bool(timeline_profile.get("event_truncated")),
        "timeline_profile_sha256": timeline_profile_hash,
        "citation_manifest_sha256": citation_manifest_hash,
        "timeline_event_citation_count": timeline_event_citation_count,
        "message_media_link_citation_count": message_media_link_citation_count,
        "resolved_media_link_count": int(timeline_profile.get("resolved_media_link_count") or 0),
        "unresolved_media_link_count": int(timeline_profile.get("unresolved_media_link_count") or 0),
        "missing_timestamp_count": int(timeline_profile.get("missing_timestamp_count") or 0),
        "device_wide_timeline_ready": False,
        "timezone_validation_required": True,
        "known_answer_correlation_required": True,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MOBILE_TIMELINE_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapidtriage-mobile-export.json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-mobile-export.json --reference-output <trusted-mobile-timeline> --backlog-item 43 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 45 --json",
        ],
        "report_guidance": {
            "allowed_use": "mobile-message-media-call-timeline-triage-pivot",
            "forbidden_claims": [
                "complete device-wide mobile timeline",
                "all attachments recovered",
                "timezone-normalized chronology is report-defensible",
                "deleted or hidden app events are fully recovered",
            ],
            "required_disclaimer": (
                "Mobile correlation is bounded to imported source rows. Treat it as a review pivot until "
                "device-wide joins, timezone/skew checks, attachment byte recovery, trusted diffs, known-answer "
                "fixtures, and independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def mobile_media_link_status(
    message: Mapping[str, object],
    media_link_by_message: Mapping[str, Mapping[str, object]],
) -> str:
    message_id = optional_text(message.get("message_id"))
    if message_id and message_id in media_link_by_message:
        return optional_text(media_link_by_message[message_id].get("validation_status")) or "candidate"
    if optional_text(message.get("media_reference") or message.get("attachment_name")):
        return "unresolved-candidate"
    return "not-applicable"


def build_unified_contact_call_sms_view(
    message_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    *,
    limit: int = 200,
) -> list[dict[str, object]]:
    actors: dict[str, dict[str, object]] = {}

    def actor_for(identifier: str) -> dict[str, object]:
        actor = actors.setdefault(
            identifier,
            {
                "actor": identifier,
                "contact_names": set(),
                "phones": set(),
                "emails": set(),
                "message_count": 0,
                "call_count": 0,
                "contact_record_count": 0,
                "services": set(),
                "first_seen_at": "",
                "last_seen_at": "",
            },
        )
        return actor

    def update_seen(actor: dict[str, object], timestamp: str) -> None:
        if not timestamp:
            return
        first = optional_text(actor.get("first_seen_at"))
        last = optional_text(actor.get("last_seen_at"))
        actor["first_seen_at"] = min(first, timestamp) if first else timestamp
        actor["last_seen_at"] = max(last, timestamp) if last else timestamp

    for contact in contact_rows:
        identifiers = unique_non_empty(
            [
                optional_text(contact.get("phone_number")),
                optional_text(contact.get("email")),
                optional_text(contact.get("contact_name")),
            ]
        )
        for identifier in identifiers:
            actor = actor_for(identifier)
            actor["contact_record_count"] = int(actor["contact_record_count"]) + 1
            if contact.get("contact_name"):
                actor["contact_names"].add(optional_text(contact.get("contact_name")))
            if contact.get("phone_number"):
                actor["phones"].add(optional_text(contact.get("phone_number")))
            if contact.get("email"):
                actor["emails"].add(optional_text(contact.get("email")))
            update_seen(actor, optional_text(contact.get("timestamp")))

    for message in message_rows:
        for participant in message.get("participants", []):
            if not isinstance(participant, str) or not participant:
                continue
            actor = actor_for(participant)
            actor["message_count"] = int(actor["message_count"]) + 1
            if "@" in participant:
                actor["emails"].add(participant)
            else:
                actor["phones"].add(participant)
            if message.get("service"):
                actor["services"].add(optional_text(message.get("service")))
            update_seen(actor, optional_text(message.get("timestamp")))

    for call in call_rows:
        identifier = optional_text(call.get("phone_number") or call.get("contact_name"))
        if not identifier:
            continue
        actor = actor_for(identifier)
        actor["call_count"] = int(actor["call_count"]) + 1
        actor["phones"].add(identifier)
        if call.get("contact_name"):
            actor["contact_names"].add(optional_text(call.get("contact_name")))
        update_seen(actor, optional_text(call.get("timestamp")))

    normalized: list[dict[str, object]] = []
    for actor in actors.values():
        normalized.append(
            {
                "actor": optional_text(actor.get("actor")),
                "contact_names": sorted(actor["contact_names"])[:10],
                "phones": sorted(actor["phones"])[:10],
                "emails": sorted(actor["emails"])[:10],
                "message_count": int(actor["message_count"]),
                "call_count": int(actor["call_count"]),
                "contact_record_count": int(actor["contact_record_count"]),
                "services": sorted(actor["services"])[:10],
                "first_seen_at": optional_text(actor.get("first_seen_at")),
                "last_seen_at": optional_text(actor.get("last_seen_at")),
                "validation_status": "candidate",
            }
        )
    normalized.sort(key=lambda item: (-(int(item["message_count"]) + int(item["call_count"])), str(item["actor"])))
    return normalized[:limit]


def build_mobile_actor_review_profile(actor_rows: list[Mapping[str, object]], *, limit: int = 100) -> dict[str, object]:
    review_queue: list[dict[str, object]] = []
    multi_identifier_count = 0
    named_actor_count = 0
    for actor in actor_rows:
        phone_count = len(actor.get("phones") or [])
        email_count = len(actor.get("emails") or [])
        name_count = len(actor.get("contact_names") or [])
        if phone_count + email_count > 1 or name_count > 1:
            multi_identifier_count += 1
        if name_count:
            named_actor_count += 1
        score = int(actor.get("message_count") or 0) + int(actor.get("call_count") or 0) + int(actor.get("contact_record_count") or 0)
        review_queue.append(
            {
                "actor": optional_text(actor.get("actor")),
                "message_count": int(actor.get("message_count") or 0),
                "call_count": int(actor.get("call_count") or 0),
                "contact_record_count": int(actor.get("contact_record_count") or 0),
                "phone_count": phone_count,
                "email_count": email_count,
                "contact_name_count": name_count,
                "services": list(actor.get("services") or [])[:10],
                "first_seen_at": optional_text(actor.get("first_seen_at")),
                "last_seen_at": optional_text(actor.get("last_seen_at")),
                "review_priority": "high" if score >= 3 or phone_count + email_count > 1 else "normal",
                "merge_split_review_required": phone_count + email_count > 1 or name_count > 1,
                "validation_status": "candidate",
            }
        )
    review_queue.sort(
        key=lambda item: (
            item["review_priority"] != "high",
            -(int(item["message_count"]) + int(item["call_count"]) + int(item["contact_record_count"])),
            str(item["actor"]),
        )
    )
    return {
        "profile_version": "mobile-actor-review-v1",
        "selected_track": "source-export-contact-call-sms-actor-review",
        "actor_count": len(actor_rows),
        "named_actor_count": named_actor_count,
        "multi_identifier_actor_count": multi_identifier_count,
        "review_queue": review_queue[:limit],
        "review_queue_count": min(len(review_queue), limit),
        "review_queue_truncated": len(review_queue) > limit,
        "device_wide_identity_resolution_ready": False,
        "merge_split_review_required": bool(actor_rows),
        "known_answer_actor_diff_required": True,
        "reporting_status": "candidate-actor-view-validation-required",
        "required_before_report": [
            "review actor merge/split decisions for shared devices, recycled numbers, aliases, and group chats",
            "validate contact/call/SMS actor counts against a trusted vendor report or hand-labeled fixture",
            "preserve analyst review state before using actor groupings in a report narrative",
        ],
    }


def build_mobile_actor_citation_manifest(
    *,
    actor_rows: list[Mapping[str, object]],
    message_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    limit: int = 200,
) -> dict[str, object]:
    actor_entries: list[dict[str, object]] = []
    for index, actor in enumerate(actor_rows[:limit], start=1):
        actor_value = optional_text(actor.get("actor"))
        actor_hash = sha256_text(actor_value) if actor_value else ""
        linked_message_count = sum(
            1
            for row in message_rows
            if actor_value
            and actor_value in [participant for participant in row.get("participants", []) if isinstance(participant, str)]
        )
        linked_contact_count = sum(
            1
            for row in contact_rows
            if actor_value
            and actor_value
            in {
                optional_text(row.get("phone_number")),
                optional_text(row.get("email")),
                optional_text(row.get("contact_name")),
            }
        )
        linked_call_count = sum(
            1
            for row in call_rows
            if actor_value
            and actor_value
            in {
                optional_text(row.get("phone_number")),
                optional_text(row.get("contact_name")),
            }
        )
        entry_payload = {
            "entry_index": index,
            "actor_sha256": actor_hash,
            "message_count": int(actor.get("message_count") or 0),
            "call_count": int(actor.get("call_count") or 0),
            "contact_record_count": int(actor.get("contact_record_count") or 0),
            "linked_message_count": linked_message_count,
            "linked_contact_count": linked_contact_count,
            "linked_call_count": linked_call_count,
            "first_seen_at": optional_text(actor.get("first_seen_at")),
            "last_seen_at": optional_text(actor.get("last_seen_at")),
            "service_count": len(actor.get("services") or []),
            "phone_count": len(actor.get("phones") or []),
            "email_count": len(actor.get("emails") or []),
            "contact_name_count": len(actor.get("contact_names") or []),
            "merge_split_review_required": len(actor.get("phones") or []) + len(actor.get("emails") or []) > 1
            or len(actor.get("contact_names") or []) > 1,
        }
        actor_entries.append(
            {
                **entry_payload,
                "entry_hash": stable_mobile_sha256(entry_payload),
                "source_viewer_locator": {
                    "viewer": "mobile-actor-review",
                    "actor_sha256": actor_hash,
                    "open_requires_merge_split_review": entry_payload["merge_split_review_required"],
                },
                "validation_status": "candidate-actor-citation",
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "mobile-actor-citation-manifest-v1",
        "item_number": 44,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-contact-call-sms-actor-citations",
        "actor_entry_count": len(actor_entries),
        "actor_entry_cap": limit,
        "actor_entries_truncated": len(actor_rows) > limit,
        "actor_entries": actor_entries,
        "message_count": len(message_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "raw_actor_values_serialized": False,
        "device_wide_identity_resolution_ready": False,
        "merge_split_review_required": bool(actor_rows),
        "known_answer_actor_diff_required": True,
        "passed_validation_check_ids": [
            "mobile-actor-citation-manifest-emitted",
            "actor-source-viewer-locators-built",
            "actor-values-hashed-in-manifest",
        ],
        "failed_validation_check_ids": [
            "device-wide-identity-resolution-not-validated",
            "actor-merge-split-review-not-persisted",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[44],
        ],
        "commercial_blockers": [
            "device-wide-identity-resolution-not-validated",
            "actor-merge-split-review-not-persisted",
            MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[44],
        ],
        "ready_for_court_report": False,
    }
    manifest["manifest_sha256"] = stable_mobile_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def build_mobile_actor_report_grade_validation_plan(
    *,
    actor_rows: list[Mapping[str, object]],
    message_rows: list[Mapping[str, object]],
    contact_rows: list[Mapping[str, object]],
    call_rows: list[Mapping[str, object]],
    actor_review_profile: Mapping[str, object],
    actor_citation_manifest: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff or {}
    actor_review_profile_hash = stable_mobile_sha256(actor_review_profile)
    actor_manifest_hash = optional_text(actor_citation_manifest.get("manifest_sha256"))
    actor_entries = actor_citation_manifest.get("actor_entries")
    if not isinstance(actor_entries, list):
        actor_entries = []
    locators_present = all(
        isinstance(entry, Mapping) and isinstance(entry.get("source_viewer_locator"), Mapping)
        for entry in actor_entries
    )

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

    validation_slots = [
        slot(
            "mobile-actor-view-built",
            ready=bool(actor_rows),
            evidence=f"actor_count={len(actor_rows)}",
            blocker_id="mobile-actor-view-required",
            operator_action="Regenerate mobile correlation so contact/call/SMS/message actor pivots are present.",
        ),
        slot(
            "mobile-actor-review-profile-emitted",
            ready=actor_review_profile.get("profile_version") == "mobile-actor-review-v1",
            evidence=f"actor_review_profile_sha256={actor_review_profile_hash}",
            blocker_id="mobile-actor-review-profile-required",
            operator_action="Regenerate mobile correlation so the actor review queue is emitted.",
        ),
        slot(
            "mobile-actor-citation-manifest-emitted",
            ready=bool(actor_manifest_hash),
            evidence=f"actor_citation_manifest_sha256={actor_manifest_hash}",
            blocker_id="mobile-actor-citation-manifest-required",
            operator_action="Generate hashable actor citations before report review.",
        ),
        slot(
            "mobile-actor-values-hashed",
            ready=actor_citation_manifest.get("raw_actor_values_serialized") is False,
            evidence=f"raw_actor_values_serialized={bool(actor_citation_manifest.get('raw_actor_values_serialized'))}",
            blocker_id="mobile-actor-raw-value-serialization-blocked",
            operator_action="Regenerate actor citations with hash-only actor values.",
        ),
        slot(
            "mobile-actor-source-viewer-locators",
            ready=locators_present and bool(actor_entries),
            evidence=f"actor_entry_count={len(actor_entries)} locators_present={locators_present}",
            blocker_id="mobile-actor-source-viewer-locator-required",
            operator_action="Attach source viewer locators for every actor selected for review.",
        ),
        slot(
            "mobile-actor-review-queue-cap-disclosed",
            ready=int(actor_review_profile.get("review_queue_count") or 0) >= 0,
            evidence=(
                f"review_queue_count={int(actor_review_profile.get('review_queue_count') or 0)} "
                f"review_queue_truncated={bool(actor_review_profile.get('review_queue_truncated'))}"
            ),
            blocker_id="mobile-actor-review-queue-cap-disclosure-required",
            operator_action="Record review queue caps and truncation before large-case actor review.",
        ),
        slot(
            "mobile-actor-device-wide-identity-resolution",
            ready=False,
            evidence="device_wide_identity_resolution_ready=false",
            blocker_id="mobile-actor-device-wide-identity-resolution-required",
            operator_action="Merge actor pivots with device accounts, address books, SIM/account metadata, and app-native IDs.",
        ),
        slot(
            "mobile-actor-merge-split-review-history",
            ready=False,
            evidence="merge_split_review_history_persisted=false",
            blocker_id="mobile-actor-merge-split-review-history-required",
            operator_action="Persist analyst merge/split decisions with reviewer identity, rationale, and source citations.",
        ),
        slot(
            "mobile-actor-cross-app-dedupe",
            ready=False,
            evidence="cross_app_dedupe_validated=false",
            blocker_id="mobile-actor-cross-app-dedupe-required",
            operator_action="Validate cross-app entity deduplication before identity-complete claims.",
        ),
        slot(
            "mobile-actor-vendor-identity-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[44],
            operator_action="Attach a passing vendor/native actor identity diff.",
        ),
        slot(
            "mobile-actor-known-answer-corpus",
            ready=False,
            evidence="known_answer_actor_corpus_attached=false",
            blocker_id="mobile-actor-known-answer-corpus-required",
            operator_action="Validate shared devices, aliases, recycled numbers, group chats, and app IDs against known-answer data.",
        ),
        slot(
            "mobile-actor-independent-review",
            ready=False,
            evidence="independent_review_signoff_present=false",
            blocker_id="mobile-actor-independent-review-required",
            operator_action="Attach independent reviewer signoff before identity-complete actor wording.",
        ),
    ]
    blockers = sorted(
        {
            str(item.get("blocker_id"))
            for item in validation_slots
            if item.get("status") != "complete" and item.get("blocker_id")
        }
    )
    plan: dict[str, object] = {
        "profile_version": MOBILE_ACTOR_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 44,
        "gap_id": "#44",
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "bounded-contact-call-sms-actor-report-validation",
        "actor_count": len(actor_rows),
        "message_count": len(message_rows),
        "contact_count": len(contact_rows),
        "call_count": len(call_rows),
        "actor_review_profile_sha256": actor_review_profile_hash,
        "actor_citation_manifest_sha256": actor_manifest_hash,
        "actor_entry_count": int(actor_citation_manifest.get("actor_entry_count") or 0),
        "review_queue_count": int(actor_review_profile.get("review_queue_count") or 0),
        "review_queue_truncated": bool(actor_review_profile.get("review_queue_truncated")),
        "multi_identifier_actor_count": int(actor_review_profile.get("multi_identifier_actor_count") or 0),
        "raw_actor_values_serialized": bool(actor_citation_manifest.get("raw_actor_values_serialized")),
        "device_wide_identity_resolution_ready": False,
        "merge_split_review_required": bool(actor_review_profile.get("merge_split_review_required")),
        "known_answer_actor_diff_required": True,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": sum(1 for item in validation_slots if item.get("status") == "complete"),
        "blocking_slot_count": sum(1 for item in validation_slots if item.get("status") != "complete"),
        "validation_status": "report-validation-blocked" if blockers else "ready-for-report-review",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(MOBILE_ACTOR_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage artifacts <mobile-export-root> --kind mobile-export --output rapidtriage-mobile-export.json",
            "rapidtriage cross-tool-validate --rapid-output rapidtriage-mobile-export.json --reference-output <trusted-mobile-actor-report> --backlog-item 44 --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-041-050-known-answer.json --limit 45 --json",
        ],
        "report_guidance": {
            "allowed_use": "mobile-contact-call-sms-actor-review-pivot",
            "forbidden_claims": [
                "device-wide identity resolution complete",
                "all accounts for this person are merged",
                "actor deduplication is report-defensible",
                "shared-device or recycled-number ambiguity has been eliminated",
            ],
            "required_disclaimer": (
                "Mobile actor views are source-export review pivots. Treat identity grouping as candidate-only until "
                "merge/split review history, cross-app dedupe validation, trusted diffs, known-answer fixtures, and "
                "independent review are attached."
            ),
        },
    }
    plan["validation_plan_sha256"] = stable_mobile_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def build_mobile_correlation_trusted_diff(
    rapid_rows: list[Mapping[str, object]],
    trusted_rows: list[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    rapid_index = index_mobile_correlation_rows(rapid_rows)
    trusted_index = index_mobile_correlation_rows(trusted_rows)
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in MOBILE_CORRELATION_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        "mobile_correlation_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "mobile-correlation-trusted-diff-v1",
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(common) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-mobile-correlation-output-as-final",
            "blockers": [] if status == "pass" else list(MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS.values()),
        },
    }


def index_mobile_correlation_rows(rows: list[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        kind = normalized_mobile_diff_value(first_mobile_alias(row, "kind", "artifact_type", "event_type", "type"))
        service = normalized_mobile_diff_value(first_mobile_alias(row, "service", "app_identifier", "app"))
        message_id = normalized_mobile_diff_value(first_mobile_alias(row, "message_id", "msg_id", "id"))
        actor = normalized_mobile_diff_value(first_mobile_alias(row, "actor", "participant", "phone", "email"))
        media_sha256 = normalized_mobile_diff_value(first_mobile_alias(row, "media_sha256", "sha256", "attachment_sha256"))
        schema_version = normalized_mobile_diff_value(first_mobile_alias(row, "schema_or_app_version", "schema_version", "app_version", "version"))
        timestamp = normalized_mobile_diff_value(first_mobile_alias(row, "timestamp", "message_timestamp", "date"))
        key = "|".join(item for item in (kind, service, message_id, actor, media_sha256, schema_version, timestamp) if item)
        if not key:
            continue
        indexed[key] = {
            "kind": kind,
            "service": service,
            "message_id": message_id,
            "actor": actor,
            "media_sha256": media_sha256,
            "schema_or_app_version": schema_version,
            "timestamp": timestamp,
        }
    return indexed


def mobile_correlation_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "ready_for_court_report": False,
        "blockers": [
            "media-message-links-are-candidate-matches-not-app-native-attachment-resolution",
            "contact-call-sms-view-is-export-scoped-not-device-wide-entity-resolution",
            "app-schema-version-registry-needs-known-answer-validation",
            *MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS.values(),
        ],
        "recommended_validation": [
            "Validate message/media links against app-native databases and attachment tables for each supported service.",
            "Validate contact/call/SMS identity resolution with known-answer mobile images before report-grade conclusions.",
        ],
    }


def mobile_correlation_forensic_review(
    *,
    message_count: int,
    media_count: int,
    contact_count: int,
    call_count: int,
    services: list[str],
    message_media_link_count: int,
    unified_actor_count: int,
    schema_version_count: int,
) -> dict[str, object]:
    report_grade = mobile_correlation_report_grade_assessment()
    return build_forensic_review(
        gap_id="#43",
        artifact_goal="Mobile message-media-contact-call correlation, unified actor view, and app schema version tracking",
        primary_evidence=[
            f"messages={message_count}",
            f"media={media_count}",
            f"contacts={contact_count}",
            f"calls={call_count}",
            f"services={','.join(services[:8])}",
            f"message_media_links={message_media_link_count}",
            f"unified_actors={unified_actor_count}",
            f"schema_versions={schema_version_count}",
        ],
        validation_required=True,
        report_grade_assessment=report_grade,
        blockers=report_grade["blockers"],
        caveats=[
            "Correlation is export-scoped and candidate-level, not a complete device-wide timeline.",
            "Known-answer validation is required for attachment resolution, contact identity merging, and schema-version semantics.",
        ],
    )


def mobile_correlation_commercial_uplift_evidence(
    *,
    message_count: int,
    media_count: int,
    contact_count: int,
    call_count: int,
    services: list[str],
    participant_count: int,
    message_media_link_count: int,
    unified_actor_count: int,
    schema_version_count: int,
    validation_checks: Mapping[str, object],
    timeline_profile: Mapping[str, object] | None = None,
    citation_manifest: Mapping[str, object] | None = None,
    timeline_validation_plan: Mapping[str, object] | None = None,
    actor_review_profile: Mapping[str, object] | None = None,
    actor_citation_manifest: Mapping[str, object] | None = None,
    actor_validation_plan: Mapping[str, object] | None = None,
    schema_compatibility_profile: Mapping[str, object] | None = None,
    schema_version_manifest: Mapping[str, object] | None = None,
    schema_validation_plan: Mapping[str, object] | None = None,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    report_grade = mobile_correlation_report_grade_assessment()
    timeline_profile = timeline_profile or {}
    citation_manifest = citation_manifest or {}
    timeline_validation_plan = timeline_validation_plan or {}
    actor_review_profile = actor_review_profile or {}
    actor_citation_manifest = actor_citation_manifest or {}
    actor_validation_plan = actor_validation_plan or {}
    schema_compatibility_profile = schema_compatibility_profile or {}
    schema_version_manifest = schema_version_manifest or {}
    schema_validation_plan = schema_validation_plan or {}
    trusted_diff = trusted_diff or {}
    passed_validation_check_ids = [
        str(check_id)
        for check_id, passed in validation_checks.items()
        if passed and not str(check_id).endswith("_known_answer_validated")
    ]
    failed_validation_check_ids = [
        str(check_id)
        for check_id, passed in validation_checks.items()
        if not passed and str(check_id).endswith("_known_answer_validated")
    ]
    if not validation_checks.get("correlation_validated_against_known_answer"):
        failed_validation_check_ids.append("correlation_validated_against_known_answer")
    if timeline_validation_plan:
        passed_validation_check_ids.append("mobile_timeline_report_grade_validation_plan_present")
        if int(timeline_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_validation_check_ids.append("mobile_timeline_report_grade_ready_slots")
    if actor_validation_plan:
        passed_validation_check_ids.append("mobile_actor_report_grade_validation_plan_present")
        if int(actor_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_validation_check_ids.append("mobile_actor_report_grade_ready_slots")
    if schema_validation_plan:
        passed_validation_check_ids.append("mobile_schema_report_grade_validation_plan_present")
        if int(schema_validation_plan.get("ready_slot_count") or 0) >= 6:
            passed_validation_check_ids.append("mobile_schema_report_grade_ready_slots")
    return {
        "batch_id": "commercial-uplift-041-045",
        "item_numbers": [43, 44, 45],
        "implementation_track": "mobile-correlation-schema-gate",
        "reportability_decision": mobile_correlation_reportability_decision(
            validation_checks=validation_checks,
            failed_validation_check_ids=sorted(set(failed_validation_check_ids)),
            report_grade=report_grade,
            message_count=message_count,
            media_count=media_count,
            unified_actor_count=unified_actor_count,
            schema_version_count=schema_version_count,
            trusted_diff=trusted_diff,
            timeline_validation_plan=timeline_validation_plan,
            actor_validation_plan=actor_validation_plan,
            schema_validation_plan=schema_validation_plan,
        ),
        "source_refs": [
            f"service:{service}" for service in services[:20]
        ] + [
            f"mobile_correlation_citation_manifest_sha256:{citation_manifest.get('manifest_sha256', '')}"
        ] + [
            "mobile_timeline_report_grade_validation_plan_sha256:"
            f"{timeline_validation_plan.get('validation_plan_sha256', '')}"
        ] + [
            f"mobile_actor_citation_manifest_sha256:{actor_citation_manifest.get('manifest_sha256', '')}"
        ] + [
            f"mobile_actor_report_grade_validation_plan_sha256:{actor_validation_plan.get('validation_plan_sha256', '')}"
        ] + [
            f"mobile_schema_version_manifest_sha256:{schema_version_manifest.get('manifest_sha256', '')}"
        ] + [
            "mobile_schema_report_grade_validation_plan_sha256:"
            f"{schema_validation_plan.get('validation_plan_sha256', '')}"
        ],
        "passed_validation_check_ids": sorted(set(passed_validation_check_ids)),
        "failed_validation_check_ids": sorted(set(failed_validation_check_ids)),
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_ids": [MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS[number] for number in (43, 44, 45)],
            "required_tools": sorted(MOBILE_CORRELATION_TRUSTED_TOOLS),
        },
        "commercial_blockers": list(report_grade["blockers"]),
        "large_data_controls": {
            "max_rows_per_source": MAX_ROWS_PER_SOURCE,
            "max_chat_db_sample_rows": MAX_CHAT_DB_SAMPLE_ROWS,
            "message_count": message_count,
            "media_count": media_count,
            "contact_count": contact_count,
            "call_count": call_count,
            "participant_count": participant_count,
            "message_media_link_count": message_media_link_count,
            "unified_actor_count": unified_actor_count,
            "schema_version_count": schema_version_count,
            "timeline_event_count": int(timeline_profile.get("event_count") or 0),
            "timeline_event_truncated": bool(timeline_profile.get("event_truncated")),
            "timeline_profile_present": bool(timeline_profile),
            "citation_manifest_present": bool(citation_manifest),
            "citation_manifest_hash": str(citation_manifest.get("manifest_sha256") or ""),
            "timeline_report_grade_validation_plan_present": bool(timeline_validation_plan),
            "timeline_report_grade_validation_plan_hash": str(
                timeline_validation_plan.get("validation_plan_sha256") or ""
            ),
            "timeline_report_grade_ready_slot_count": int(
                timeline_validation_plan.get("ready_slot_count") or 0
            ),
            "timeline_report_grade_blocking_slot_count": int(
                timeline_validation_plan.get("blocking_slot_count") or 0
            ),
            "timeline_event_citation_count": int(citation_manifest.get("timeline_event_citation_count") or 0),
            "message_media_link_citation_count": int(
                citation_manifest.get("message_media_link_citation_count") or 0
            ),
            "timeline_missing_timestamp_count": int(timeline_profile.get("missing_timestamp_count") or 0),
            "unresolved_media_link_count": int(timeline_profile.get("unresolved_media_link_count") or 0),
            "actor_review_profile_present": bool(actor_review_profile),
            "actor_citation_manifest_present": bool(actor_citation_manifest),
            "actor_citation_manifest_hash": str(actor_citation_manifest.get("manifest_sha256") or ""),
            "actor_report_grade_validation_plan_present": bool(actor_validation_plan),
            "actor_report_grade_validation_plan_hash": str(actor_validation_plan.get("validation_plan_sha256") or ""),
            "actor_report_grade_ready_slot_count": int(actor_validation_plan.get("ready_slot_count") or 0),
            "actor_report_grade_blocking_slot_count": int(actor_validation_plan.get("blocking_slot_count") or 0),
            "actor_citation_entry_count": int(actor_citation_manifest.get("actor_entry_count") or 0),
            "raw_actor_values_serialized": bool(actor_citation_manifest.get("raw_actor_values_serialized")),
            "actor_review_queue_count": int(actor_review_profile.get("review_queue_count") or 0),
            "multi_identifier_actor_count": int(actor_review_profile.get("multi_identifier_actor_count") or 0),
            "device_wide_identity_resolution_ready": False,
            "schema_compatibility_profile_present": bool(schema_compatibility_profile),
            "schema_compatibility_entry_count": int(schema_compatibility_profile.get("entry_count") or 0),
            "schema_unvalidated_entry_count": int(schema_compatibility_profile.get("unvalidated_entry_count") or 0),
            "schema_release_gate_blocked": bool(schema_compatibility_profile.get("commercial_release_blocked")),
            "schema_version_manifest_present": bool(schema_version_manifest),
            "schema_version_manifest_hash": str(schema_version_manifest.get("manifest_sha256") or ""),
            "schema_version_manifest_entry_count": int(schema_version_manifest.get("schema_entry_count") or 0),
            "schema_version_manifest_release_gate_blocked": bool(schema_version_manifest.get("release_gate_blocked")),
            "schema_report_grade_validation_plan_present": bool(schema_validation_plan),
            "schema_report_grade_validation_plan_hash": str(
                schema_validation_plan.get("validation_plan_sha256") or ""
            ),
            "schema_report_grade_ready_slot_count": int(schema_validation_plan.get("ready_slot_count") or 0),
            "schema_report_grade_blocking_slot_count": int(schema_validation_plan.get("blocking_slot_count") or 0),
            "device_wide_timeline_ready": False,
            "known_answer_correlation_required": True,
        },
        "reporting_status": "candidate-correlation-validation-required",
    }


def mobile_correlation_reportability_decision(
    *,
    validation_checks: Mapping[str, object],
    failed_validation_check_ids: list[str],
    report_grade: Mapping[str, object],
    message_count: int,
    media_count: int,
    unified_actor_count: int,
    schema_version_count: int,
    trusted_diff: Mapping[str, object] | None = None,
    timeline_validation_plan: Mapping[str, object] | None = None,
    actor_validation_plan: Mapping[str, object] | None = None,
    schema_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade["blockers"] if str(item)}
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    if not validation_checks.get("device_wide_timeline_validated"):
        blockers.add("device-wide-timeline-not-validated")
    if not validation_checks.get("schema_version_registry_known_answer_validated"):
        blockers.add("schema-version-registry-known-answer-not-attached")
    trusted_diff = trusted_diff or {}
    timeline_validation_plan = timeline_validation_plan or {}
    actor_validation_plan = actor_validation_plan or {}
    schema_validation_plan = schema_validation_plan or {}
    if trusted_diff.get("status") != "pass":
        blockers.update(MOBILE_CORRELATION_TRUSTED_DIFF_BLOCKERS.values())
    return {
        "profile_version": "mobile-correlation-reportability-decision-v1",
        "commercial_gap_ids": ["#43", "#44", "#45"],
        "decision": "do-not-report-mobile-correlation-as-device-wide-or-identity-complete",
        "allowed_use": "mobile-correlation-and-schema-triage-pivot",
        "blockers": sorted(blockers),
        "failed_validation_check_ids": list(failed_validation_check_ids),
        "message_count": message_count,
        "media_count": media_count,
        "unified_actor_count": unified_actor_count,
        "schema_version_count": schema_version_count,
        "timeline_report_grade_validation_plan_present": bool(timeline_validation_plan),
        "timeline_report_grade_validation_plan_hash": str(
            timeline_validation_plan.get("validation_plan_sha256") or ""
        ),
        "timeline_report_grade_ready_slot_count": int(timeline_validation_plan.get("ready_slot_count") or 0),
        "timeline_report_grade_blocking_slot_count": int(timeline_validation_plan.get("blocking_slot_count") or 0),
        "actor_report_grade_validation_plan_present": bool(actor_validation_plan),
        "actor_report_grade_validation_plan_hash": str(actor_validation_plan.get("validation_plan_sha256") or ""),
        "actor_report_grade_ready_slot_count": int(actor_validation_plan.get("ready_slot_count") or 0),
        "actor_report_grade_blocking_slot_count": int(actor_validation_plan.get("blocking_slot_count") or 0),
        "schema_report_grade_validation_plan_present": bool(schema_validation_plan),
        "schema_report_grade_validation_plan_hash": str(schema_validation_plan.get("validation_plan_sha256") or ""),
        "schema_report_grade_ready_slot_count": int(schema_validation_plan.get("ready_slot_count") or 0),
        "schema_report_grade_blocking_slot_count": int(schema_validation_plan.get("blocking_slot_count") or 0),
        "ready_for_court_report": False,
        "required_before_report": [
            "validate device-wide timeline joins, timezone assumptions, and attachment recovery",
            "attach analyst-reviewed identity merge/split decisions for contacts/calls/SMS actors",
            "gate each app parser with schema migration fixtures and release-reviewed compatibility matrices",
            "attach passing vendor/native known-answer diffs for mobile correlation, actor view, and schema registry claims",
        ],
    }
