"""Review workflow assessment and saved-search serialization."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ..forensic_accuracy import build_accuracy_gate
from ..review_reporting_controls import build_review_reporting_contract
from .base import (
    CaseDatabaseError,
)
from .constants import (
    REVIEW_WORKFLOW_REPORT_GRADE_BLOCKERS,
    REVIEW_WORKFLOW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
    REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
    REVIEW_WORKFLOW_TRUSTED_TOOLS,
)
from .helpers import (
    artifact_match_source,
    artifact_search_metadata,
    artifact_source_path,
    compact_text,
    optional_int,
    optional_str,
    parse_json_object,
    stable_payload_sha256,
)

__all__ = [
    "_review_workflow_diff_key",
    "_review_workflow_diff_values",
    "acquisition_metadata_to_dict",
    "build_case_search_review_workflow_summary",
    "build_review_assignment_manifest",
    "build_review_queue_source_viewer_locator",
    "build_review_workflow_report_grade_validation_plan",
    "build_reviewer_workflow_trusted_diff",
    "build_source_review_handoff",
    "load_review_target_match",
    "normalize_review_priority",
    "normalize_source_citation_package",
    "normalize_tags",
    "review_mark_to_dict",
    "review_queue_action",
    "review_workflow_assessment",
    "saved_search_to_dict",
    "source_citation_package_hash",
]

def load_review_target_match(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    target_type: str,
    target_id: str,
) -> dict[str, object] | None:
    try:
        numeric_id = int(target_id)
    except ValueError:
        return None
    if target_type == "indexed_document":
        row = connection.execute(
            """
            SELECT
                indexed_document.citation_id,
                indexed_document.id,
                indexed_document.source_type,
                indexed_document.field_name,
                indexed_document.title,
                indexed_document.body,
                file_record.path AS file_path,
                file_record.hash_md5 AS file_hash_md5,
                file_record.hash_sha1 AS file_hash_sha1,
                file_record.hash_sha256 AS file_hash_sha256,
                artifact.parser_name AS artifact_parser,
                artifact.parser_version AS artifact_parser_version,
                artifact.confidence AS artifact_confidence,
                evidence_source.original_path AS evidence_path,
                evidence_source.hash_md5 AS evidence_hash_md5,
                evidence_source.hash_sha1 AS evidence_hash_sha1,
                evidence_source.hash_sha256 AS evidence_hash_sha256
            FROM indexed_document
            LEFT JOIN file_record ON indexed_document.file_record_id = file_record.id
            LEFT JOIN artifact ON indexed_document.artifact_id = artifact.id
            LEFT JOIN evidence_source ON indexed_document.evidence_source_id = evidence_source.id
            WHERE indexed_document.case_id = ? AND indexed_document.id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        body = str(row["body"] or "")
        source_path = str(row["file_path"] or row["evidence_path"] or row["title"] or "")
        source_hashes = {
            "md5": str(row["file_hash_md5"] or row["evidence_hash_md5"] or ""),
            "sha1": str(row["file_hash_sha1"] or row["evidence_hash_sha1"] or ""),
            "sha256": str(row["file_hash_sha256"] or row["evidence_hash_sha256"] or ""),
        }
        source_hashes = {key: value for key, value in source_hashes.items() if value}
        return {
            "source": "documents",
            "citation_id": str(row["citation_id"]),
            "target_type": "indexed_document",
            "target_id": str(row["id"]),
            "title": str(row["title"] or "indexed document"),
            "kind": str(row["field_name"] or row["source_type"] or ""),
            "path": source_path,
            "preview": compact_text(body, 240),
            "metadata": {
                "source_path": source_path,
                "source_type": str(row["source_type"] or ""),
                "field_name": str(row["field_name"] or ""),
                "parser": str(row["artifact_parser"] or row["source_type"] or ""),
                "parser_version": str(row["artifact_parser_version"] or "1"),
                "parser_confidence": row["artifact_confidence"] if row["artifact_confidence"] is not None else 0.65,
                "source_index": optional_int(row["id"]),
                "source_hashes": source_hashes,
                "evidence_strength": "indexed-document-match",
                "reportability": "reviewed-report-candidate",
            },
        }
    if target_type == "file_record":
        row = connection.execute(
            """
            SELECT citation_id, id, path, extension, size_bytes, modified_at, hash_md5, hash_sha1, hash_sha256
            FROM file_record
            WHERE case_id = ? AND id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "source": "files",
            "citation_id": str(row["citation_id"]),
            "target_type": "file_record",
            "target_id": str(row["id"]),
            "title": Path(str(row["path"])).name,
            "kind": str(row["extension"] or ""),
            "path": str(row["path"] or ""),
            "preview": str(row["path"] or ""),
            "metadata": {
                "size_bytes": optional_int(row["size_bytes"]),
                "modified_at": optional_str(row["modified_at"]),
                "source_hashes": {
                    key: str(row[column])
                    for key, column in (("md5", "hash_md5"), ("sha1", "hash_sha1"), ("sha256", "hash_sha256"))
                    if row[column]
                },
            },
        }
    if target_type == "artifact":
        row = connection.execute(
            """
            SELECT citation_id, id, artifact_type, title, summary, data_json
            FROM artifact
            WHERE case_id = ? AND id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        artifact_row = parse_json_object(row["data_json"])
        metadata = artifact_search_metadata(artifact_row)
        return {
            "source": artifact_match_source(str(row["artifact_type"])),
            "citation_id": str(row["citation_id"]),
            "target_type": "artifact",
            "target_id": str(row["id"]),
            "title": str(row["title"] or row["artifact_type"]),
            "kind": str(row["artifact_type"]),
            "path": artifact_source_path(artifact_row),
            "preview": str(row["summary"] or row["artifact_type"]),
            "metadata": metadata,
        }
    if target_type == "event":
        row = connection.execute(
            """
            SELECT citation_id, id, event_type, timestamp, target, description, source
            FROM event
            WHERE case_id = ? AND id = ?
            """,
            (case_id, numeric_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "source": "timeline",
            "citation_id": str(row["citation_id"]),
            "target_type": "event",
            "target_id": str(row["id"]),
            "title": str(row["description"] or row["event_type"]),
            "kind": str(row["event_type"]),
            "timestamp": str(row["timestamp"]),
            "path": str(row["target"] or ""),
            "preview": str(row["description"] or row["target"] or row["event_type"]),
            "metadata": {
                "timestamp": str(row["timestamp"] or ""),
                "timeline_source": str(row["source"] or ""),
            },
        }
    return None


def normalize_tags(tags: Iterable[str]) -> list[str]:
    normalized = []
    seen = set()
    for item in tags:
        tag = str(item).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        normalized.append(tag)
    return normalized


def normalize_review_priority(value: str) -> str:
    normalized = str(value or "normal").strip().lower()
    aliases = {"medium": "normal", "med": "normal", "p0": "urgent", "p1": "high", "p2": "normal", "p3": "low"}
    normalized = aliases.get(normalized, normalized)
    supported = {"urgent", "high", "normal", "low"}
    if normalized not in supported:
        raise CaseDatabaseError(f"unsupported review priority {normalized!r}; expected one of: {', '.join(sorted(supported))}")
    return normalized


def normalize_source_citation_package(package: object) -> dict[str, object]:
    if not isinstance(package, Mapping):
        return {}
    normalized = dict(package)
    package_hash = str(normalized.get("package_hash") or "").strip()
    if not package_hash:
        normalized["package_hash"] = stable_payload_sha256(normalized)
    return normalized


def source_citation_package_hash(package: Mapping[str, object]) -> str:
    if not package:
        return ""
    package_hash = str(package.get("package_hash") or "").strip()
    return package_hash or stable_payload_sha256(dict(package))


def build_source_review_handoff(package: Mapping[str, object]) -> dict[str, object]:
    if not package:
        return {
            "profile_version": "source-review-handoff-v1",
            "present": False,
            "ready_for_report_candidate": False,
            "blockers": ["source-read-citation-package-not-attached"],
        }
    blockers = []
    if not package.get("source_locator"):
        blockers.append("source-read-locator-missing")
    if not package.get("source_sha256"):
        blockers.append("source-read-source-hash-not-computed")
    if not package.get("snippet_sha256"):
        blockers.append("source-read-snippet-hash-missing")
    if not package.get("package_hash"):
        blockers.append("source-read-package-hash-missing")
    return {
        "profile_version": "source-review-handoff-v1",
        "present": True,
        "citation_text": str(package.get("citation_text") or ""),
        "package_hash": source_citation_package_hash(package),
        "source_locator_present": bool(package.get("source_locator")),
        "source_sha256_present": bool(package.get("source_sha256")),
        "snippet_sha256_present": bool(package.get("snippet_sha256")),
        "ready_for_report_candidate": not blockers,
        "ready_for_court_report": False,
        "blockers": blockers + ["trusted-source-viewer-locator-diff-required-before-court-use"],
    }


def review_mark_to_dict(row: sqlite3.Row) -> dict[str, object]:
    try:
        tags = json.loads(str(row["tags_json"] or "[]"))
    except json.JSONDecodeError:
        tags = []
    assignee = str(row["assignee"] or "") if "assignee" in row.keys() else ""
    priority = str(row["priority"] or "normal") if "priority" in row.keys() else "normal"
    due_at = str(row["due_at"] or "") if "due_at" in row.keys() else ""
    source_citation_package = (
        normalize_source_citation_package(parse_json_object(row["source_citation_package_json"]))
        if "source_citation_package_json" in row.keys()
        else {}
    )
    review_mark = {
        "citation_id": str(row["citation_id"]),
        "case_id": str(row["case_id"]),
        "target_type": str(row["target_type"]),
        "target_id": str(row["target_id"]),
        "status": str(row["status"]),
        "verification_status": str(row["verification_status"]),
        "tags": tags if isinstance(tags, list) else [],
        "note": str(row["note"] or ""),
        "include_in_report": bool(row["include_in_report"]),
        "reviewer": str(row["reviewer"] or ""),
        "assignee": assignee,
        "priority": priority,
        "due_at": due_at,
        "source_citation_package": source_citation_package,
        "source_citation_package_hash": source_citation_package_hash(source_citation_package),
        "source_review_handoff": build_source_review_handoff(source_citation_package),
        "review_workflow": review_workflow_assessment(assignee=assignee, priority=priority, due_at=due_at),
        "evidence_selection_versioning": {
            "commercial_gap_ids": ["#65"],
            "status": "versioned-review-mark",
            "include_in_report": bool(row["include_in_report"]),
            "ready_for_court_report": False,
        },
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }
    review_mark["review_reporting_qc_contract"] = build_review_reporting_contract(review_marks=[review_mark])
    return review_mark


def review_workflow_assessment(
    *,
    assignee: str,
    priority: str,
    due_at: str,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    satisfied = [
        "review status fields persisted",
        "verification status captured",
        "report inclusion state captured",
        "history/audit limitation warning",
    ]
    if assignee or priority:
        satisfied.append("assignment and priority captured")
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted reviewer workflow audit diff pass")
    validation_plan = build_review_workflow_report_grade_validation_plan(
        context="review-mark",
        assignment_present=bool(assignee),
        priority=priority,
        due_at=due_at,
        review_queue_count=1,
        source_viewer_locator_count=1,
        audit_history_linked=True,
        review_assignment_manifest_hash="",
        trusted_diff=trusted_diff,
    )
    satisfied.append("review workflow report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("review workflow report-grade ready slots")
    blockers = [
        "local-single-database-review-workflow-until-role-based-server-is-enabled",
        "review-status-does-not-replace-source-verification-and-parser-validation",
        REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
    ]
    core_accuracy_gates = [
        build_accuracy_gate(
            51,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"assignee:{assignee}",
                f"priority:{priority}",
                f"due_at:{due_at}",
                "case_db:review_mark",
                "case_db:review_mark_history",
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
            ],
        )
    ]
    active_blockers = [blocker for blocker in blockers if blocker != REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER or trusted_diff.get("status") != "pass"]
    return {
        "commercial_gap_ids": ["#51"],
        "status": "implemented-baseline-validation-required",
        "assignment_present": bool(assignee),
        "priority": priority,
        "due_at": due_at,
        "core_accuracy_gates": core_accuracy_gates,
        "trusted_review_workflow_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_id": REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(REVIEW_WORKFLOW_TRUSTED_TOOLS),
        },
        "review_workflow_report_grade_validation_plan": validation_plan,
        "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "commercial_uplift_evidence": {
            "batch_id": "commercial-uplift-051-055",
            "item_numbers": [51],
            "implementation_track": "case-db-reviewer-assignment-status-workflow",
            "source_refs": [
                f"assignee:{assignee}",
                f"priority:{priority}",
                f"due_at:{due_at}",
                "case_db:review_mark",
                "case_db:review_mark_history",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
            ],
            "reportability_decision": {
                "profile_version": "case-review-workflow-reportability-decision-v1",
                "commercial_gap_ids": ["#51"],
                "decision": "do-not-report-review-workflow-as-role-based-case-management",
                "allowed_use": "single-user-review-status-triage-pivot",
                "blockers": [
                    "multi-user-conflict-resolution",
                    "notification-workflow",
                    "role-based-assignment-queue",
                    "sla-dashboard",
                    *([] if trusted_diff.get("status") == "pass" else [REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER]),
                ],
                "ready_for_court_report": False,
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
                "required_before_report": [
                    "enable role-based multi-user queues, conflict handling, notifications, and signed reviewer SOPs",
                    "verify source hashes, parser limitations, and immutable history before report inclusion",
                ],
            },
            "passed_validation_check_ids": sorted(set(satisfied)),
            "failed_validation_check_ids": [
                "role-based-assignment-queue",
                "sla-dashboard",
                "notification-workflow",
                "multi-user-conflict-resolution",
                *([] if trusted_diff.get("status") == "pass" else [REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER]),
            ],
            "commercial_blockers": active_blockers,
            "large_data_controls": {
                "local_case_db_review_mark": True,
                "assignment_present": bool(assignee),
                "priority_normalized": bool(priority),
                "due_date_recorded": bool(due_at),
                "audit_history_linked": True,
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
                "role_based_case_server": False,
            },
            "reporting_status": "implemented-baseline-validation-required",
        },
        "ready_for_court_report": False,
        "blockers": active_blockers,
        "supported_fields": [
            "status",
            "verification_status",
            "reviewer",
            "assignee",
            "priority",
            "due_at",
            "tags",
            "include_in_report",
            "history",
        ],
    }


def build_review_workflow_report_grade_validation_plan(
    *,
    context: str,
    assignment_present: bool,
    priority: str,
    due_at: str,
    review_queue_count: int,
    source_viewer_locator_count: int,
    audit_history_linked: bool,
    review_assignment_manifest_hash: str,
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    trusted_diff = trusted_diff if isinstance(trusted_diff, Mapping) else {}

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
            "case-review-status-fields-persisted",
            ready=True,
            evidence=f"context={context}",
            blocker_id="case-review-status-fields-required",
            operator_action="Persist review status, verification status, and report inclusion state.",
        ),
        slot(
            "case-review-assignment-priority-metadata",
            ready=assignment_present or bool(priority),
            evidence=f"assignment_present={assignment_present} priority={priority}",
            blocker_id="case-review-assignment-priority-required",
            operator_action="Capture assignee/priority metadata before using rows as a review queue.",
        ),
        slot(
            "case-review-due-date-or-followup-state",
            ready=True,
            evidence=f"due_at={due_at}",
            blocker_id="case-review-followup-state-required",
            operator_action="Record due date or explicit empty follow-up state.",
        ),
        slot(
            "case-review-source-viewer-locators",
            ready=source_viewer_locator_count > 0,
            evidence=f"source_viewer_locator_count={source_viewer_locator_count}",
            blocker_id="case-review-source-viewer-locators-required",
            operator_action="Attach source-viewer locators so reviewers can verify evidence before report inclusion.",
        ),
        slot(
            "case-review-audit-history-linked",
            ready=audit_history_linked,
            evidence=f"audit_history_linked={audit_history_linked}",
            blocker_id="case-review-audit-history-required",
            operator_action="Link review state changes to review mark history before report use.",
        ),
        slot(
            "case-review-bounded-queue-or-mark-emitted",
            ready=review_queue_count > 0,
            evidence=f"review_queue_count={review_queue_count} assignment_manifest_hash={review_assignment_manifest_hash}",
            blocker_id="case-review-queue-or-mark-required",
            operator_action="Emit at least one review queue row or review mark workflow record.",
        ),
        slot(
            "case-review-role-based-assignment-queue",
            ready=False,
            evidence="role_based_assignment_queue=false",
            blocker_id="role-based-assignment-queue-required",
            operator_action="Add role-based queues and per-action permission enforcement.",
        ),
        slot(
            "case-review-notification-workflow",
            ready=False,
            evidence="notification_workflow=false",
            blocker_id="notification-workflow-required",
            operator_action="Add notifications for assignment, due dates, and review handoffs.",
        ),
        slot(
            "case-review-multi-user-conflict-resolution",
            ready=False,
            evidence="multi_user_conflict_resolution=false",
            blocker_id="multi-user-conflict-resolution-required",
            operator_action="Add locking/conflict records for concurrent reviewers.",
        ),
        slot(
            "case-review-sla-dashboard",
            ready=False,
            evidence="sla_dashboard=false",
            blocker_id="sla-dashboard-required",
            operator_action="Add SLA/aging dashboards for review queues.",
        ),
        slot(
            "case-review-reviewer-sop-signoff",
            ready=False,
            evidence="reviewer_sop_signoff=false",
            blocker_id="reviewer-sop-signoff-required",
            operator_action="Attach signed reviewer SOP/training signoff for commercial workflow claims.",
        ),
        slot(
            "case-review-trusted-audit-diff",
            ready=trusted_diff.get("status") == "pass",
            evidence=f"trusted_diff_status={trusted_diff.get('status', 'missing')}",
            blocker_id=REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
            operator_action="Attach a passing trusted reviewer workflow audit diff before report-grade claims.",
        ),
    ]
    blockers = sorted(
        str(slot_row.get("blocker_id"))
        for slot_row in validation_slots
        if slot_row.get("status") != "complete" and slot_row.get("blocker_id")
    )
    ready_slot_count = sum(1 for slot_row in validation_slots if slot_row.get("status") == "complete")
    plan_core: dict[str, object] = {
        "profile_version": REVIEW_WORKFLOW_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 51,
        "gap_id": "#51",
        "batch_id": "commercial-uplift-051-055",
        "selected_track": "single-case-review-workflow-report-validation",
        "context": context,
        "assignment_present": assignment_present,
        "priority": priority,
        "due_at": due_at,
        "review_queue_count": review_queue_count,
        "source_viewer_locator_count": source_viewer_locator_count,
        "audit_history_linked": audit_history_linked,
        "review_assignment_manifest_hash": review_assignment_manifest_hash,
        "trusted_diff_status": str(trusted_diff.get("status") or "missing"),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": len(blockers),
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "commercial_grade_ready": False,
        "validation_slots": validation_slots,
        "blockers": blockers,
        "commercial_grade_blockers": list(REVIEW_WORKFLOW_REPORT_GRADE_BLOCKERS),
        "validation_commands": [
            "rapidtriage case-review --case-id <case> --target-type <type> --target-id <id> --json",
            "rapidtriage case-search --case-id <case> --query <keyword> --json",
            "rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-051-060-known-answer.json --limit 51 --json",
        ],
        "report_guidance": {
            "allowed_use": "single-user-review-status-triage-pivot",
            "forbidden_claim": "role-based multi-user case-management workflow",
            "required_disclaimer": (
                "Review workflow rows are local Case DB triage state and require role-based queues, "
                "notifications, multi-user conflict handling, SLA dashboards, reviewer SOP signoff, and "
                "trusted audit diffs before commercial case-management claims."
            ),
        },
    }
    return {**plan_core, "validation_plan_sha256": stable_payload_sha256(plan_core)}


def build_case_search_review_workflow_summary(
    matches: Sequence[Mapping[str, object]],
    *,
    review_status_filter: str | None = None,
    verification_status_filter: str | None = None,
) -> dict[str, object]:
    status_counts: dict[str, int] = {}
    verification_counts: dict[str, int] = {}
    assignee_counts: dict[str, int] = {}
    priority_counts: dict[str, int] = {}
    review_queue: list[dict[str, object]] = []
    assigned_count = 0
    unassigned_count = 0
    report_candidate_count = 0
    for index, match in enumerate(matches):
        review = match.get("review") if isinstance(match.get("review"), Mapping) else {}
        status = str(review.get("status") or "unreviewed")
        verification = str(review.get("verification_status") or "unverified")
        assignee = str(review.get("assignee") or "")
        priority = normalize_review_priority(str(review.get("priority") or "normal"))
        include_in_report = bool(review.get("include_in_report"))
        status_counts[status] = status_counts.get(status, 0) + 1
        verification_counts[verification] = verification_counts.get(verification, 0) + 1
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        if assignee:
            assigned_count += 1
            assignee_counts[assignee] = assignee_counts.get(assignee, 0) + 1
        else:
            unassigned_count += 1
        if include_in_report:
            report_candidate_count += 1
        queue_row_core = {
            "queue_position": index + 1,
            "target_type": str(match.get("target_type") or ""),
            "target_id": str(match.get("target_id") or ""),
            "citation_id": str(match.get("citation_id") or review.get("citation_id") or ""),
            "title": str(match.get("title") or match.get("path") or ""),
            "source": str(match.get("source") or "unknown"),
            "status": status,
            "verification_status": verification,
            "assignee": assignee,
            "priority": priority,
            "due_at": str(review.get("due_at") or ""),
            "include_in_report": include_in_report,
            "review_action": review_queue_action(status=status, verification_status=verification, assignee=assignee),
            "source_viewer_locator": build_review_queue_source_viewer_locator(match, review),
        }
        review_queue.append({**queue_row_core, "queue_row_hash": stable_payload_sha256(queue_row_core)})
    review_assignment_manifest = build_review_assignment_manifest(
        review_queue,
        status_counts=status_counts,
        verification_counts=verification_counts,
        assignee_counts=assignee_counts,
        priority_counts=priority_counts,
        report_candidate_count=report_candidate_count,
        review_status_filter=review_status_filter,
        verification_status_filter=verification_status_filter,
    )
    validation_plan = build_review_workflow_report_grade_validation_plan(
        context="case-search-review-summary",
        assignment_present=assigned_count > 0,
        priority=",".join(sorted(priority_counts)) or "normal",
        due_at="",
        review_queue_count=len(review_queue),
        source_viewer_locator_count=review_assignment_manifest["source_viewer_locator_count"],
        audit_history_linked=True,
        review_assignment_manifest_hash=review_assignment_manifest["manifest_hash"],
        trusted_diff=None,
    )
    satisfied = [
        "search result review state attached",
        "review status summary emitted",
        "verification status summary emitted",
        "assignment queue metadata emitted",
        "report inclusion queue emitted",
        "review assignment manifest hash emitted",
        "history/audit limitation warning",
    ]
    if review_assignment_manifest["source_viewer_locator_count"]:
        satisfied.append("review source viewer locators emitted")
    if review_status_filter:
        satisfied.append("review status filter applied")
    if verification_status_filter:
        satisfied.append("verification status filter applied")
    satisfied.append("review workflow report-grade validation plan")
    if int(validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("review workflow report-grade ready slots")
    core_accuracy_gates = [
        build_accuracy_gate(
            51,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"match_count:{len(matches)}",
                f"assigned_count:{assigned_count}",
                f"report_candidate_count:{report_candidate_count}",
                f"review_status_filter:{review_status_filter or ''}",
                f"verification_status_filter:{verification_status_filter or ''}",
                f"review_assignment_manifest_hash:{review_assignment_manifest['manifest_hash']}",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
                "case_db:review_mark",
                "case_db:review_mark_history",
            ],
        )
    ]
    return {
        "profile_version": "case-search-review-workflow-summary-v1",
        "commercial_gap_ids": ["#51"],
        "status": "implemented-baseline-validation-required",
        "match_count": len(matches),
        "status_counts": dict(sorted(status_counts.items())),
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "assignee_counts": dict(sorted(assignee_counts.items())),
        "priority_counts": dict(sorted(priority_counts.items())),
        "assigned_count": assigned_count,
        "unassigned_count": unassigned_count,
        "report_candidate_count": report_candidate_count,
        "review_queue": review_queue[:100],
        "review_queue_count": len(review_queue),
        "review_queue_truncated": len(review_queue) > 100,
        "review_assignment_manifest": review_assignment_manifest,
        "review_assignment_manifest_hash": review_assignment_manifest["manifest_hash"],
        "review_workflow_report_grade_validation_plan": validation_plan,
        "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
        "source_viewer_locator_count": review_assignment_manifest["source_viewer_locator_count"],
        "filters": {
            "review_status": review_status_filter or "",
            "verification_status": verification_status_filter or "",
        },
        "core_accuracy_gates": core_accuracy_gates,
        "commercial_uplift_evidence": {
            "batch_id": "commercial-uplift-051-055",
            "item_numbers": [51],
            "implementation_track": "case-db-search-reviewer-assignment-status-summary",
            "source_refs": [
                f"matches:{len(matches)}",
                f"assigned:{assigned_count}",
                f"report_candidates:{report_candidate_count}",
                "case_db:review_mark",
                "case_db:review_mark_history",
                f"review_workflow_report_grade_validation_plan_sha256:{validation_plan['validation_plan_sha256']}",
            ],
            "passed_validation_check_ids": sorted(set(satisfied)),
            "failed_validation_check_ids": [
                "role-based-assignment-queue",
                "notification-workflow",
                "multi-user-conflict-resolution",
                REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
            ],
            "large_data_controls": {
                "bounded_review_queue": True,
                "review_queue_limit": 100,
                "assigned_count": assigned_count,
                "report_candidate_count": report_candidate_count,
                "review_assignment_manifest_present": True,
                "review_assignment_manifest_hash": review_assignment_manifest["manifest_hash"],
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
                "source_viewer_locator_count": review_assignment_manifest["source_viewer_locator_count"],
                "role_based_case_server": False,
                "notification_sla_enabled": False,
            },
            "reportability_decision": {
                "profile_version": "case-search-review-workflow-reportability-decision-v1",
                "commercial_gap_ids": ["#51"],
                "decision": "do-not-report-review-search-summary-as-role-based-case-management",
                "allowed_use": "single-user-review-queue-triage-summary",
                "blockers": [
                    "multi-user-conflict-resolution",
                    "notification-workflow",
                    "role-based-assignment-queue",
                    REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
                ],
                "ready_for_court_report": False,
                "review_workflow_report_grade_validation_plan_present": True,
                "review_workflow_report_grade_validation_plan_hash": validation_plan["validation_plan_sha256"],
                "review_workflow_report_grade_ready_slot_count": int(validation_plan.get("ready_slot_count") or 0),
                "review_workflow_report_grade_blocking_slot_count": int(
                    validation_plan.get("blocking_slot_count") or 0
                ),
            },
        },
        "ready_for_court_report": False,
        "blockers": [
            "role-based-assignment-queue",
            "notification-workflow",
            "multi-user-conflict-resolution",
            REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
        ],
    }


def build_review_queue_source_viewer_locator(match: Mapping[str, object], review: Mapping[str, object]) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    upstream_locator = (
        dict(metadata.get("source_viewer_locator")) if isinstance(metadata.get("source_viewer_locator"), Mapping) else {}
    )
    return {
        "viewer": "case-review-source",
        "source": str(match.get("source") or "unknown"),
        "target_type": str(match.get("target_type") or ""),
        "target_id": str(match.get("target_id") or ""),
        "citation_id": str(match.get("citation_id") or ""),
        "review_citation_id": str(review.get("citation_id") or ""),
        "path": str(match.get("path") or metadata.get("source_path") or ""),
        "kind": str(match.get("kind") or metadata.get("kind") or ""),
        "title": str(match.get("title") or match.get("path") or ""),
        "source_record": {
            "row_id": metadata.get("row_id") if metadata.get("row_id") is not None else match.get("target_id"),
            "line": metadata.get("line") if metadata.get("line") is not None else "",
            "table": str(metadata.get("table") or ""),
            "record_offset": metadata.get("record_offset") if metadata.get("record_offset") is not None else "",
            "source_index": metadata.get("source_index") if metadata.get("source_index") is not None else "",
        },
        "upstream_source_viewer_locator": upstream_locator,
        "parser_manifest_hashes": dict(metadata.get("parser_manifest_hashes"))
        if isinstance(metadata.get("parser_manifest_hashes"), Mapping)
        else {},
        "open_action": "open-source-and-verify-before-report",
    }


def build_review_assignment_manifest(
    review_queue: Sequence[Mapping[str, object]],
    *,
    status_counts: Mapping[str, int],
    verification_counts: Mapping[str, int],
    assignee_counts: Mapping[str, int],
    priority_counts: Mapping[str, int],
    report_candidate_count: int,
    review_status_filter: str | None,
    verification_status_filter: str | None,
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    source_viewer_locator_count = 0
    for row in review_queue[:100]:
        locator = row.get("source_viewer_locator") if isinstance(row.get("source_viewer_locator"), Mapping) else {}
        if locator.get("target_type") and locator.get("target_id"):
            source_viewer_locator_count += 1
        entries.append(
            {
                "queue_position": int(row.get("queue_position") or 0),
                "target_type": str(row.get("target_type") or ""),
                "target_id": str(row.get("target_id") or ""),
                "citation_id": str(row.get("citation_id") or ""),
                "status": str(row.get("status") or "unreviewed"),
                "verification_status": str(row.get("verification_status") or "unverified"),
                "assignee": str(row.get("assignee") or ""),
                "priority": str(row.get("priority") or "normal"),
                "due_at": str(row.get("due_at") or ""),
                "include_in_report": bool(row.get("include_in_report")),
                "review_action": str(row.get("review_action") or ""),
                "source_viewer_locator": dict(locator),
                "queue_row_hash": str(row.get("queue_row_hash") or ""),
            }
        )
    manifest_core: dict[str, object] = {
        "manifest_version": "case-review-assignment-manifest-v1",
        "item_number": 51,
        "commercial_gap_ids": ["#51"],
        "queue_entry_count": len(review_queue),
        "bounded_entry_count": len(entries),
        "queue_truncated": len(review_queue) > len(entries),
        "status_counts": dict(sorted(status_counts.items())),
        "verification_status_counts": dict(sorted(verification_counts.items())),
        "assignee_counts": dict(sorted(assignee_counts.items())),
        "priority_counts": dict(sorted(priority_counts.items())),
        "report_candidate_count": report_candidate_count,
        "source_viewer_locator_count": source_viewer_locator_count,
        "filters": {
            "review_status": review_status_filter or "",
            "verification_status": verification_status_filter or "",
        },
        "entries": entries,
        "blockers": [
            "role-based-assignment-queue",
            "notification-workflow",
            "multi-user-conflict-resolution",
            REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
        ],
        "commercial_claim_allowed": False,
        "operator_warning": (
            "This manifest supports single-case reviewer triage and source opening only; "
            "it is not a multi-user RBAC/SLA workflow until the listed blockers are resolved."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def review_queue_action(*, status: str, verification_status: str, assignee: str) -> str:
    if status == "unreviewed":
        return "assign-reviewer-and-open-source"
    if verification_status in {"unverified", ""}:
        return "verify-source-before-report"
    if not assignee:
        return "assign-owner-for-follow-up"
    return "ready-for-lead-review" if verification_status == "verified" else "continue-review"


def build_reviewer_workflow_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "review-workflow-trusted-audit-diff",
) -> dict[str, object]:
    rapid_index = {_review_workflow_diff_key(row): _review_workflow_diff_values(row) for row in rapid_rows}
    trusted_index = {_review_workflow_diff_key(row): _review_workflow_diff_values(row) for row in trusted_rows}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing_in_trusted = sorted(key for key in rapid_index if key not in trusted_index)
    unexpected_in_trusted = sorted(key for key in trusted_index if key not in rapid_index)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index) & set(trusted_index)):
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field in ("status", "verification_status", "reviewer", "assignee", "priority", "due_at", "include_in_report", "tags"):
            if rapid.get(field) != trusted.get(field):
                mismatches.append({"row_key": key, "field": field, "rapid": rapid.get(field, ""), "trusted": trusted.get(field, "")})
    tool_accepted = trusted_tool.strip().lower() in REVIEW_WORKFLOW_TRUSTED_TOOLS
    status = "pass" if tool_accepted and rapid_index and trusted_index and not missing_in_trusted and not unexpected_in_trusted and not mismatches else "fail"
    return {
        "profile_version": "review-workflow-trusted-audit-diff-v1",
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else REVIEW_WORKFLOW_TRUSTED_DIFF_BLOCKER,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(REVIEW_WORKFLOW_TRUSTED_TOOLS),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_count": len(set(rapid_index) & set(trusted_index)),
        "missing_in_trusted_count": len(missing_in_trusted),
        "unexpected_in_trusted_count": len(unexpected_in_trusted),
        "mismatch_count": len(mismatches),
        "mismatched_fields": mismatches[:50],
        "missing_in_trusted": missing_in_trusted[:50],
        "unexpected_in_trusted": unexpected_in_trusted[:50],
        "commercial_grade_evidence": status == "pass",
    }


def _review_workflow_diff_key(row: Mapping[str, object]) -> str:
    citation = str(row.get("citation_id") or row.get("review_citation_id") or "").strip()
    if citation:
        return citation
    target_type = str(row.get("target_type") or "").strip()
    target_id = str(row.get("target_id") or "").strip()
    return f"{target_type}:{target_id}" if target_type or target_id else ""


def _review_workflow_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    tags = row.get("tags")
    if isinstance(tags, str):
        normalized_tags = sorted(item.strip() for item in tags.split(",") if item.strip())
    elif isinstance(tags, Sequence) and not isinstance(tags, (bytes, bytearray, str)):
        normalized_tags = sorted(str(item).strip() for item in tags if str(item).strip())
    else:
        normalized_tags = []
    return {
        "status": str(row.get("status") or ""),
        "verification_status": str(row.get("verification_status") or ""),
        "reviewer": str(row.get("reviewer") or ""),
        "assignee": str(row.get("assignee") or ""),
        "priority": str(row.get("priority") or ""),
        "due_at": str(row.get("due_at") or ""),
        "include_in_report": bool(row.get("include_in_report")),
        "tags": ",".join(normalized_tags),
    }


def saved_search_to_dict(row: sqlite3.Row) -> dict[str, object]:
    try:
        keywords = json.loads(str(row["keywords_json"] or "[]"))
    except json.JSONDecodeError:
        keywords = []
    try:
        filters = json.loads(str(row["filters_json"] or "{}"))
    except json.JSONDecodeError:
        filters = {}
    return {
        "citation_id": str(row["citation_id"]),
        "case_id": str(row["case_id"]),
        "name": str(row["name"]),
        "keywords": keywords if isinstance(keywords, list) else [],
        "filters": filters if isinstance(filters, dict) else {},
        "created_by": str(row["created_by"] or ""),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "last_run_at": str(row["last_run_at"] or ""),
    }


def acquisition_metadata_to_dict(row: sqlite3.Row | None) -> dict[str, object]:
    if row is None:
        return {}
    return {
        "citation_id": str(row["citation_id"]),
        "case_id": str(row["case_id"]),
        "evidence_source_citation_id": str(row["evidence_source_citation_id"] or ""),
        "operator": str(row["operator"] or ""),
        "acquisition_started_at": str(row["acquisition_started_at"] or ""),
        "acquisition_completed_at": str(row["acquisition_completed_at"] or ""),
        "source_identifier": str(row["source_identifier"] or ""),
        "write_blocker": str(row["write_blocker"] or ""),
        "acquisition_tool": str(row["acquisition_tool"] or ""),
        "acquisition_tool_version": str(row["acquisition_tool_version"] or ""),
        "whole_source_sha256": str(row["whole_source_sha256"] or ""),
        "notes": str(row["notes"] or ""),
        "created_at": str(row["created_at"]),
    }
