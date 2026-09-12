"""Case search, FTS queries, and review marks."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path

from ..forensic_accuracy import build_accuracy_gate
from .base import (
    CaseDatabaseError,
)
from .constants import (
    CASE_DB_SEARCH_MIN_SCAN_ROWS,
    CASE_DB_SEARCH_SCAN_OVERSAMPLE,
    CASE_DB_SEARCH_SCAN_ROW_LIMIT,
    CASE_SEARCH_CURSOR_VERSION,
)
from .fts import (
    case_db_search_index_health,
)
from .helpers import (
    artifact_match_source,
    artifact_search_metadata,
    artifact_source_path,
    build_fts_query,
    matched_keywords,
    optional_float,
    optional_int,
    optional_str,
    parse_json_object,
    stable_payload_sha256,
)
from .review import (
    build_review_queue_source_viewer_locator,
    review_mark_to_dict,
    source_citation_package_hash,
)

__all__ = [
    "artifact_fts_has_rows",
    "attach_review_marks",
    "build_case_search_execution_plan",
    "build_case_search_result_window_manifest",
    "build_review_priority",
    "build_source_reference",
    "case_document_extraction_errors",
    "case_search_cursor_scope",
    "case_search_priority_sort_key",
    "case_search_reportability_decision",
    "case_search_scan_candidate_limit",
    "case_search_source_requested",
    "case_table_has_more_than_scan_limit",
    "decode_case_search_cursor",
    "dedupe_matches",
    "encode_case_search_cursor",
    "enrich_case_search_matches",
    "event_fts_has_rows",
    "file_record_fts_has_rows",
    "merge_source_citation_package_into_reference",
    "search_artifacts",
    "search_artifacts_fts",
    "search_artifacts_scan",
    "search_events",
    "search_events_fts",
    "search_file_records",
    "search_file_records_fts",
    "search_indexed_documents",
]

def search_indexed_documents(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    query = build_fts_query(keywords)
    rows = connection.execute(
        """
        SELECT
            indexed_document.citation_id,
            indexed_document.id,
            indexed_document.source_type,
            indexed_document.field_name,
            indexed_document.title,
            snippet(indexed_document_fts, 1, '[', ']', ' ... ', 16) AS snippet
        FROM indexed_document_fts
        JOIN indexed_document ON indexed_document_fts.rowid = indexed_document.id
        WHERE indexed_document.case_id = ?
          AND indexed_document_fts MATCH ?
        ORDER BY rank
        LIMIT ?
        """,
        (case_id, query, limit or -1),
    ).fetchall()
    return [
        {
            "source": "documents",
            "citation_id": str(row["citation_id"]),
            "target_type": "indexed_document",
            "target_id": str(row["id"]),
            "title": str(row["title"]),
            "kind": str(row["field_name"]),
            "matched_keywords": matched_keywords(str(row["snippet"]), keywords),
            "preview": str(row["snippet"]),
        }
        for row in rows
    ]


def case_document_extraction_errors(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    limit: int = 100,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, target_id, timestamp, params_json, error
        FROM audit_event
        WHERE case_id = ?
          AND action = 'document-text-extraction'
          AND result = 'failed'
        ORDER BY id DESC
        LIMIT ?
        """,
        (case_id, max(1, int(limit))),
    ).fetchall()
    errors: list[dict[str, object]] = []
    for row in rows:
        params = parse_json_object(str(row["params_json"] or "{}"))
        error = str(row["error"] or "document extraction failed")
        error_type = error.split(":", 1)[0] if ":" in error else "DocumentExtractionError"
        errors.append(
            {
                "citation_id": str(row["citation_id"]),
                "target_id": str(row["target_id"] or ""),
                "timestamp": str(row["timestamp"] or ""),
                "path": str(params.get("path") or ""),
                "kind": str(params.get("kind") or ""),
                "error": error,
                "reason": "case-db-document-text-extraction-failed",
                "error_type": error_type,
                "message": error.split(":", 1)[1].strip() if ":" in error else error,
                "recoverable": True,
                "effect": "case-search-documents-partial-coverage",
            }
        )
    return errors


def attach_review_marks(
    connection: sqlite3.Connection,
    case_id: str,
    matches: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not matches:
        return matches
    target_pairs = sorted(
        {
            (str(match.get("target_type") or ""), str(match.get("target_id") or ""))
            for match in matches
            if match.get("target_type") not in (None, "") and match.get("target_id") not in (None, "")
        }
    )
    rows: list[sqlite3.Row] = []
    for chunk_start in range(0, len(target_pairs), 300):
        chunk = target_pairs[chunk_start : chunk_start + 300]
        if not chunk:
            continue
        predicates = " OR ".join("(target_type = ? AND target_id = ?)" for _ in chunk)
        params: list[object] = [case_id]
        for target_type, target_id in chunk:
            params.extend([target_type, target_id])
        rows.extend(
            connection.execute(
                f"SELECT * FROM review_mark WHERE case_id = ? AND ({predicates})",
                params,
            ).fetchall()
        )
    review_by_target = {
        (str(row["target_type"]), str(row["target_id"])): review_mark_to_dict(row)
        for row in rows
    }
    output = []
    for match in matches:
        copied = dict(match)
        review = review_by_target.get((str(match.get("target_type")), str(match.get("target_id"))))
        if review is not None:
            copied["review"] = review
        else:
            copied["review"] = {
                "status": "unreviewed",
                "verification_status": "unverified",
                "include_in_report": False,
                "tags": [],
            }
        output.append(copied)
    return output


def enrich_case_search_matches(matches: list[dict[str, object]], keywords: list[str]) -> list[dict[str, object]]:
    enriched = []
    for index, match in enumerate(matches):
        copied = dict(match)
        copied["source_reference"] = build_source_reference(copied)
        copied["review_priority"] = build_review_priority(copied, keywords)
        copied["_result_order"] = index
        enriched.append(copied)
    enriched.sort(key=case_search_priority_sort_key)
    for match in enriched:
        match.pop("_result_order", None)
    return enriched


def case_search_priority_sort_key(match: Mapping[str, object]) -> tuple[int, int]:
    priority = match.get("review_priority") if isinstance(match.get("review_priority"), Mapping) else {}
    score = optional_int(priority.get("score")) or 0
    order = optional_int(match.get("_result_order")) or 0
    return (-score, order)


def build_source_reference(match: Mapping[str, object]) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    source_hashes = metadata.get("source_hashes") if isinstance(metadata.get("source_hashes"), Mapping) else {}
    record_hashes = metadata.get("record_hashes") if isinstance(metadata.get("record_hashes"), Mapping) else {}
    source_viewer_locator = (
        dict(metadata.get("source_viewer_locator")) if isinstance(metadata.get("source_viewer_locator"), Mapping) else {}
    )
    source_locator = dict(metadata.get("source_locator")) if isinstance(metadata.get("source_locator"), Mapping) else {}
    parser_manifest_hashes = (
        dict(metadata.get("parser_manifest_hashes")) if isinstance(metadata.get("parser_manifest_hashes"), Mapping) else {}
    )
    reference = {
        "citation_id": str(match.get("citation_id") or ""),
        "target_type": str(match.get("target_type") or ""),
        "target_id": str(match.get("target_id") or ""),
        "path": str(metadata.get("source_path") or match.get("path") or ""),
        "source_format": str(metadata.get("source_format") or ""),
        "parser": str(metadata.get("parser") or ""),
        "parser_version": str(metadata.get("parser_version") or ""),
        "parser_confidence": metadata.get("parser_confidence"),
        "source_index": metadata.get("source_index"),
        "record_offset": metadata.get("record_offset") or metadata.get("file_offset"),
        "source_hashes": dict(source_hashes),
        "record_hashes": dict(record_hashes),
        "source_viewer_locator": source_viewer_locator,
        "source_locator": source_locator or source_viewer_locator,
        "source_locator_hash": str(metadata.get("source_locator_hash") or ""),
        "row_citation_hash": str(metadata.get("row_citation_hash") or ""),
        "parser_manifest_hashes": parser_manifest_hashes,
        "evidence_strength": str(metadata.get("evidence_strength") or ""),
        "reportability": str(metadata.get("reportability") or ""),
        "coverage_status": str(metadata.get("coverage_status") or ""),
    }
    return {
        key: value
        for key, value in reference.items()
        if value not in (None, "", {}, [])
    }


def merge_source_citation_package_into_reference(
    source_reference: Mapping[str, object],
    package: Mapping[str, object],
) -> dict[str, object]:
    merged = dict(source_reference)
    if not package:
        return merged
    locator = package.get("source_locator") if isinstance(package.get("source_locator"), Mapping) else {}
    source_hashes = dict(merged.get("source_hashes")) if isinstance(merged.get("source_hashes"), Mapping) else {}
    source_sha256 = str(package.get("source_sha256") or "").strip()
    if source_sha256:
        source_hashes.setdefault("sha256", source_sha256)
    record_hashes = dict(merged.get("record_hashes")) if isinstance(merged.get("record_hashes"), Mapping) else {}
    snippet_sha256 = str(package.get("snippet_sha256") or "").strip()
    if snippet_sha256:
        record_hashes.setdefault("snippet_sha256", snippet_sha256)
    merged.update(
        {
            "source_citation_package_hash": source_citation_package_hash(package),
            "source_read_citation_id": str(package.get("citation_id") or ""),
            "source_read_citation_text": str(package.get("citation_text") or ""),
            "source_path_hash": str(package.get("source_path_hash") or ""),
            "source_locator": dict(locator),
            "parser": str(merged.get("parser") or "rapidtriage.source-read"),
            "parser_version": str(merged.get("parser_version") or package.get("profile_version") or "source-read-citation-package-v1"),
            "reportability": str(merged.get("reportability") or "review-lead-source-citation-package"),
        }
    )
    if source_hashes:
        merged["source_hashes"] = source_hashes
    if record_hashes:
        merged["record_hashes"] = record_hashes
    locator_field_map = {
        "record_offset": ("record_offset", "byte_offset", "offset"),
        "source_index": ("source_index", "archive_entry_index"),
        "line": ("line", "line_number"),
        "row_id": ("row_id", "rowid"),
        "table": ("table",),
    }
    for output_field, locator_fields in locator_field_map.items():
        if merged.get(output_field) not in (None, ""):
            continue
        for locator_field in locator_fields:
            if locator.get(locator_field) not in (None, ""):
                merged[output_field] = locator.get(locator_field)
                break
    return {
        key: value
        for key, value in merged.items()
        if value not in (None, "", {}, [])
    }


def build_review_priority(match: Mapping[str, object], keywords: list[str]) -> dict[str, object]:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    source = str(match.get("source") or "")
    kind = str(match.get("kind") or "")
    title_preview = " ".join(str(match.get(key) or "") for key in ("title", "preview", "path")).lower()
    score = 0
    reasons: list[str] = []

    risk_score = optional_int(metadata.get("risk_score"))
    if risk_score:
        score += min(100, risk_score)
        reasons.append(f"parser risk score {risk_score}")
    risk_flags = metadata.get("risk_flags") if isinstance(metadata.get("risk_flags"), list) else []
    if risk_flags:
        score += min(30, len(risk_flags) * 10)
        reasons.append(f"{len(risk_flags)} risk flag(s)")
    matched_rules = metadata.get("matched_rules") if isinstance(metadata.get("matched_rules"), list) else []
    if matched_rules:
        score += min(30, len(matched_rules) * 15)
        reasons.append(f"{len(matched_rules)} matched rule(s)")
    if source == "indicators":
        score += 25
        reasons.append("IOC/indicator pivot")
    if source == "artifacts" and any(token in kind for token in ("eventlog", "powershell", "wmi", "prefetch", "registry-run", "rdp")):
        score += 20
        reasons.append("high-value Windows artifact")
    if source == "artifacts" and kind.startswith("synthetic-media"):
        synthetic_score = optional_float(metadata.get("score"))
        synthetic_band = str(metadata.get("band") or "").lower()
        synthetic_scan_status = str(metadata.get("scan_status") or "")
        if synthetic_band in {"high", "critical"} or (synthetic_score is not None and synthetic_score >= 70):
            score += 40
            reasons.append("high-band synthetic-media screening hit")
        elif synthetic_band in {"medium", "elevated", "moderate"} or (
            synthetic_score is not None and synthetic_score >= 35
        ):
            score += 15
            reasons.append("elevated synthetic-media screening score")
        if synthetic_scan_status == "error":
            score += 10
            reasons.append("synthetic-media scan error requires examiner follow-up")
        reasons.append("synthetic-media score orders review only; it is not an authenticity verdict")
    if any(token in title_preview for token in ("password", "credential", "token", "secret", "powershell", "rundll32", "wmic", "bitlocker")):
        score += 15
        reasons.append("high-value keyword context")
    if metadata.get("ai_service") or metadata.get("ai_conversation_candidate_count"):
        score += 12
        reasons.append("AI-service activity context")
    if metadata.get("source_hashes") or metadata.get("record_hashes"):
        reasons.append("hash-backed source reference")
    if metadata.get("parser_confidence") not in (None, ""):
        reasons.append("parser confidence available")

    score = max(0, min(100, score))
    if score >= 70:
        level = "high"
        recommended_action = "verify source, preserve hash context, and consider report inclusion"
    elif score >= 35:
        level = "medium"
        recommended_action = "review source preview and classify relevance"
    else:
        level = "low"
        recommended_action = "triage when higher-priority hits are cleared"
    return {
        "score": score,
        "level": level,
        "reasons": reasons[:6],
        "recommended_action": recommended_action,
    }


def search_file_records(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    if file_record_fts_has_rows(connection, case_id):
        fts_matches = search_file_records_fts(connection, case_id, keywords, limit)
        if fts_matches:
            return fts_matches[:limit] if limit else fts_matches
    rows = connection.execute(
        """
        SELECT citation_id, id, path, extension, size_bytes, modified_at, hash_md5, hash_sha1, hash_sha256
        FROM file_record
        WHERE case_id = ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (case_id, scan_candidate_limit),
    ).fetchall()
    matches = []
    for row in rows:
        haystack = " ".join(
            str(row[key] or "")
            for key in ("path", "extension", "size_bytes", "modified_at")
        )
        hits = matched_keywords(haystack, keywords)
        if not hits:
            continue
        matches.append(
            {
                "source": "files",
                "citation_id": str(row["citation_id"]),
                "target_type": "file_record",
                "target_id": str(row["id"]),
                "title": Path(str(row["path"])).name,
                "kind": str(row["extension"] or ""),
                "path": str(row["path"]),
                "matched_keywords": hits,
                "preview": str(row["path"]),
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
        )
        if limit and len(matches) >= limit:
            break
    return matches


def file_record_fts_has_rows(connection: sqlite3.Connection, case_id: str) -> bool:
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM file_record_fts
            JOIN file_record ON file_record_fts.rowid = file_record.id
            WHERE file_record.case_id = ?
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def search_file_records_fts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    query = build_fts_query(keywords)
    try:
        rows = connection.execute(
            """
            SELECT
                file_record.citation_id,
                file_record.id,
                file_record.path,
                file_record.extension,
                file_record.size_bytes,
                file_record.modified_at,
                file_record.hash_md5,
                file_record.hash_sha1,
                file_record.hash_sha256,
                snippet(file_record_fts, 0, '[', ']', ' ... ', 24) AS snippet
            FROM file_record_fts
            JOIN file_record ON file_record_fts.rowid = file_record.id
            WHERE file_record.case_id = ?
              AND file_record_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (case_id, query, limit or -1),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("path", "extension", "hash_md5", "hash_sha1", "hash_sha256"))
        matches.append(
            {
                "source": "files",
                "citation_id": str(row["citation_id"]),
                "target_type": "file_record",
                "target_id": str(row["id"]),
                "title": Path(str(row["path"])).name,
                "kind": str(row["extension"] or ""),
                "path": str(row["path"]),
                "matched_keywords": matched_keywords(haystack, keywords),
                "preview": str(row["snippet"] or row["path"]),
                "metadata": {
                    "size_bytes": optional_int(row["size_bytes"]),
                    "modified_at": optional_str(row["modified_at"]),
                    "search_backend": "sqlite-fts5",
                    "source_hashes": {
                        key: str(row[column])
                        for key, column in (("md5", "hash_md5"), ("sha1", "hash_sha1"), ("sha256", "hash_sha256"))
                        if row[column]
                    },
                },
            }
        )
    return matches


def search_artifacts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    if artifact_fts_has_rows(connection, case_id):
        fts_matches = search_artifacts_fts(connection, case_id, keywords, limit)
        if fts_matches:
            return fts_matches[:limit] if limit else fts_matches
    return search_artifacts_scan(connection, case_id, keywords, limit, scan_candidate_limit)


def search_artifacts_scan(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        SELECT citation_id, id, artifact_type, title, summary, data_json
        FROM artifact
        WHERE case_id = ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (case_id, scan_candidate_limit),
    ).fetchall()
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("artifact_type", "title", "summary", "data_json"))
        hits = matched_keywords(haystack, keywords)
        if not hits:
            continue
        artifact_row = parse_json_object(row["data_json"])
        metadata = artifact_search_metadata(artifact_row)
        matches.append(
            {
                "source": artifact_match_source(str(row["artifact_type"])),
                "citation_id": str(row["citation_id"]),
                "target_type": "artifact",
                "target_id": str(row["id"]),
                "title": str(row["title"] or row["artifact_type"]),
                "kind": str(row["artifact_type"]),
                "path": artifact_source_path(artifact_row),
                "matched_keywords": hits,
                "preview": str(row["summary"] or row["artifact_type"]),
                "metadata": metadata,
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def case_search_source_requested(source_filter: set[str], *sources: str) -> bool:
    return not source_filter or any(source in source_filter for source in sources)


def case_table_has_more_than_scan_limit(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    case_id: str,
    scan_candidate_limit: int,
) -> bool:
    if scan_candidate_limit <= 0:
        return False
    row = connection.execute(
        f"""
        SELECT 1
        FROM {table_name}
        WHERE case_id = ?
        ORDER BY id ASC
        LIMIT 1 OFFSET ?
        """,
        (case_id, scan_candidate_limit),
    ).fetchone()
    return row is not None


def case_search_cursor_scope(
    *,
    case_id: str,
    keywords: Sequence[str],
    sources: set[str],
    metadata_filter: Mapping[str, str],
    review_status: str | None,
    verification_status: str | None,
) -> str:
    payload = {
        "case_id": case_id,
        "keywords": [keyword.strip().lower() for keyword in keywords],
        "sources": sorted(sources),
        "metadata": dict(sorted(metadata_filter.items())),
        "review_status": review_status or "",
        "verification_status": verification_status or "",
    }
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def encode_case_search_cursor(*, offset: int, scope: str) -> str:
    payload = {
        "version": CASE_SEARCH_CURSOR_VERSION,
        "offset": max(0, int(offset)),
        "scope": scope,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_case_search_cursor(cursor: str, *, expected_scope: str) -> int:
    token = cursor.strip()
    if not token:
        return 0
    try:
        padded = token + ("=" * (-len(token) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaseDatabaseError("invalid case-search cursor") from exc
    if not isinstance(payload, Mapping) or payload.get("version") != CASE_SEARCH_CURSOR_VERSION:
        raise CaseDatabaseError("invalid case-search cursor version")
    if str(payload.get("scope") or "") != expected_scope:
        raise CaseDatabaseError("case-search cursor does not match the current query")
    offset = optional_int(payload.get("offset"))
    if offset is None or offset < 0:
        raise CaseDatabaseError("invalid case-search cursor offset")
    return offset


def build_case_search_execution_plan(
    connection: sqlite3.Connection,
    case_id: str,
    *,
    source_filter: set[str],
    limit: int,
    cursor_offset: int,
    retrieval_limit: int,
    scan_candidate_limit: int,
) -> dict[str, object]:
    requested_sources = sorted(source_filter)
    search_index_health = case_db_search_index_health(connection, case_id)
    health_by_source = {
        str(row.get("source") or ""): row
        for row in search_index_health.get("indexes", [])
        if isinstance(row, Mapping)
    }
    sources: list[dict[str, object]] = []

    def add_source(
        *,
        source: str,
        requested: bool,
        backend: str,
        table_name: str,
        uses_scan_cap: bool,
        fts_table: str = "",
        notes: Sequence[str] = (),
    ) -> None:
        health = health_by_source.get(source, {})
        health_status = str(health.get("status") or "unknown")
        missing_index_rows = int(health.get("missing_index_rows") or 0)
        orphan_fts_rows = int(health.get("orphan_fts_rows") or 0)
        entry: dict[str, object] = {
            "source": source,
            "requested": requested,
            "backend": backend if requested else "skipped",
            "table": table_name,
            "fts_table": fts_table,
            "search_index_status": health_status,
            "missing_index_rows": missing_index_rows,
            "orphan_fts_rows": orphan_fts_rows,
            "limit": limit,
            "cursor_offset": cursor_offset,
            "retrieval_limit": retrieval_limit,
            "scan_candidate_limit": scan_candidate_limit if uses_scan_cap else None,
            "partial_coverage_warning": False,
            "notes": list(notes),
        }
        if requested and uses_scan_cap:
            has_more = case_table_has_more_than_scan_limit(
                connection,
                table_name=table_name,
                case_id=case_id,
                scan_candidate_limit=scan_candidate_limit,
            )
            entry["partial_coverage_warning"] = has_more
            if has_more:
                entry["notes"].append(
                    "bounded scan reached candidate cap; use FTS-backed sources or narrower filters for complete large-case search"
                )
        if requested and health_status not in ("healthy", "unknown"):
            entry["partial_coverage_warning"] = True
            entry["notes"].append(
                "search index health is not clean; run case-db --search-index-health and --rebuild-search-indexes before absence claims"
            )
        sources.append(entry)

    add_source(
        source="documents",
        requested=case_search_source_requested(source_filter, "documents"),
        backend="sqlite-fts5",
        table_name="indexed_document",
        fts_table="indexed_document_fts",
        uses_scan_cap=False,
        notes=("full-text index over extracted/OCR/document text",),
    )
    file_requested = case_search_source_requested(source_filter, "files")
    file_uses_fts = file_requested and file_record_fts_has_rows(connection, case_id)
    add_source(
        source="files",
        requested=file_requested,
        backend="sqlite-fts5" if file_uses_fts else "bounded-scan",
        table_name="file_record",
        fts_table="file_record_fts" if file_uses_fts else "",
        uses_scan_cap=not file_uses_fts,
        notes=("file path/extension/hash metadata search uses FTS5 when file_record_fts rows are present",),
    )
    artifact_requested = case_search_source_requested(source_filter, "artifacts", "indicators")
    artifact_uses_fts = artifact_requested and artifact_fts_has_rows(connection, case_id)
    add_source(
        source="artifacts",
        requested=artifact_requested,
        backend="sqlite-fts5" if artifact_uses_fts else "bounded-scan",
        table_name="artifact",
        fts_table="artifact_fts" if artifact_uses_fts else "",
        uses_scan_cap=not artifact_uses_fts,
        notes=("artifact and indicator rows share this backend; source filters are applied after matching",),
    )
    timeline_requested = case_search_source_requested(source_filter, "timeline")
    timeline_uses_fts = timeline_requested and event_fts_has_rows(connection, case_id)
    add_source(
        source="timeline",
        requested=timeline_requested,
        backend="sqlite-fts5" if timeline_uses_fts else "bounded-scan",
        table_name="event",
        fts_table="event_fts" if timeline_uses_fts else "",
        uses_scan_cap=not timeline_uses_fts,
        notes=("timeline event type/time/target/description/source search uses FTS5 when event_fts rows are present",),
    )
    return {
        "profile_version": "case-search-large-case-plan-v1",
        "case_id": case_id,
        "requested_sources": requested_sources,
        "scan_policy": {
            "scan_candidate_limit": scan_candidate_limit,
            "cursor_offset": cursor_offset,
            "retrieval_limit": retrieval_limit,
            "min_scan_rows": CASE_DB_SEARCH_MIN_SCAN_ROWS,
            "max_scan_rows": CASE_DB_SEARCH_SCAN_ROW_LIMIT,
            "oversample_per_requested_result": CASE_DB_SEARCH_SCAN_OVERSAMPLE,
        },
        "sources": sources,
        "search_index_health": search_index_health,
        "commercial_gap_ids": ["#61", "#74", "#78", "#79"],
        "status": "validated-local-search-plan-validation-required"
        if search_index_health["status"] == "healthy"
        else "search-index-rebuild-required-before-absence-claims",
    }


def build_case_search_result_window_manifest(
    *,
    case_id: str,
    keywords: Sequence[str],
    source_filter: set[str],
    metadata_filter: Mapping[str, str],
    review_status: str | None,
    verification_status: str | None,
    cursor_scope: str,
    page_offset: int,
    page_size: int,
    retrieval_limit: int,
    scan_candidate_limit: int,
    total_returnable_count: int,
    returned_matches: Sequence[Mapping[str, object]],
    source_counts: Mapping[str, int],
    keyword_counts: Mapping[str, int],
    priority_counts: Mapping[str, int],
    has_more: bool,
    next_cursor: str,
    large_case_search_plan: Mapping[str, object],
    review_workflow_summary: Mapping[str, object],
) -> dict[str, object]:
    source_plan_rows = [
        row for row in large_case_search_plan.get("sources", []) if isinstance(row, Mapping)
    ]
    partial_sources = [
        str(row.get("source") or "")
        for row in source_plan_rows
        if row.get("requested") and row.get("partial_coverage_warning")
    ]
    backend_counts: dict[str, int] = {}
    for row in source_plan_rows:
        if not row.get("requested"):
            continue
        backend = str(row.get("backend") or "unknown")
        backend_counts[backend] = backend_counts.get(backend, 0) + 1

    match_rows: list[dict[str, object]] = []
    for index, match in enumerate(returned_matches[:200]):
        source_reference = match.get("source_reference") if isinstance(match.get("source_reference"), Mapping) else {}
        locator = build_review_queue_source_viewer_locator(match, {})
        raw_matched_terms = match.get("matched_keywords")
        matched_terms = raw_matched_terms if isinstance(raw_matched_terms, (list, tuple, set)) else []
        row_core = {
            "window_position": page_offset + index + 1,
            "source": str(match.get("source") or "unknown"),
            "target_type": str(match.get("target_type") or ""),
            "target_id": str(match.get("target_id") or ""),
            "citation_id": str(match.get("citation_id") or ""),
            "kind": str(match.get("kind") or ""),
            "title": str(match.get("title") or match.get("path") or ""),
            "path": str(match.get("path") or source_reference.get("path") or ""),
            "matched_keywords": [str(item) for item in matched_terms],
            "review_status": str((match.get("review") or {}).get("status") or "unreviewed")
            if isinstance(match.get("review"), Mapping)
            else "unreviewed",
            "verification_status": str((match.get("review") or {}).get("verification_status") or "unverified")
            if isinstance(match.get("review"), Mapping)
            else "unverified",
            "source_reference_hash": stable_payload_sha256(source_reference) if source_reference else "",
            "source_viewer_locator": locator,
        }
        match_rows.append({**row_core, "row_hash": stable_payload_sha256(row_core)})

    filter_after_retrieval = bool(metadata_filter or review_status or verification_status)
    page_core = {
        "case_id": case_id,
        "query_scope_hash": cursor_scope,
        "page_offset": page_offset,
        "page_size": page_size,
        "match_row_hashes": [str(row.get("row_hash") or "") for row in match_rows],
    }
    satisfied = [
        "opaque cursor scope hash emitted",
        "page window row hashes emitted",
        "source viewer locators emitted",
        "source backend plan emitted",
        "bounded scan partial coverage disclosure emitted",
        "review workflow manifest linked",
    ]
    if next_cursor:
        satisfied.append("next cursor emitted for continued pagination")
    if not partial_sources:
        satisfied.append("no bounded source reported scan cap truncation")
    if filter_after_retrieval:
        satisfied.append("post-retrieval filter disclosure emitted")

    manifest_core: dict[str, object] = {
        "profile_version": "case-search-result-window-manifest-v1",
        "commercial_gap_ids": ["#61", "#74", "#78", "#79"],
        "case_id": case_id,
        "query_scope_hash": cursor_scope,
        "query_hash": stable_payload_sha256(
            {
                "case_id": case_id,
                "keywords": [str(keyword).strip().lower() for keyword in keywords],
                "sources": sorted(source_filter),
                "metadata": dict(sorted(metadata_filter.items())),
                "review_status": review_status or "",
                "verification_status": verification_status or "",
            }
        ),
        "page_window_hash": stable_payload_sha256(page_core),
        "cursor": {
            "profile_version": CASE_SEARCH_CURSOR_VERSION,
            "offset": page_offset,
            "page_size": page_size,
            "retrieval_limit": retrieval_limit,
            "scan_candidate_limit": scan_candidate_limit,
            "has_more": bool(has_more),
            "next_cursor_hash": stable_payload_sha256({"next_cursor": next_cursor}) if next_cursor else "",
        },
        "filters": {
            "sources": sorted(source_filter),
            "metadata": dict(sorted(metadata_filter.items())),
            "review_status": review_status or "",
            "verification_status": verification_status or "",
            "post_retrieval_filtering": filter_after_retrieval,
            "post_retrieval_filtering_warning": (
                "metadata/review filters are applied after candidate retrieval; treat absence as validation-required "
                "when bounded sources report partial coverage"
                if filter_after_retrieval
                else ""
            ),
        },
        "counts": {
            "returned_count": len(returned_matches),
            "total_returnable_count": total_returnable_count,
            "source_counts": dict(sorted(source_counts.items())),
            "keyword_counts": dict(sorted(keyword_counts.items())),
            "priority_counts": dict(sorted(priority_counts.items())),
            "backend_counts": dict(sorted(backend_counts.items())),
            "partial_source_count": len(partial_sources),
        },
        "large_case_controls": {
            "source_plan_profile": str(large_case_search_plan.get("profile_version") or ""),
            "source_plan_status": str(large_case_search_plan.get("status") or ""),
            "partial_sources": partial_sources,
            "bounded_window_rows": len(match_rows),
            "bounded_window_limit": 200,
            "window_truncated": len(returned_matches) > len(match_rows),
            "review_assignment_manifest_hash": str(review_workflow_summary.get("review_assignment_manifest_hash") or ""),
        },
        "match_rows": match_rows,
        "core_accuracy_gates": [
            build_accuracy_gate(
                61,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"query_scope_hash:{cursor_scope}",
                    f"page_window_hash:{stable_payload_sha256(page_core)}",
                    f"returned_count:{len(returned_matches)}",
                ],
            ),
            build_accuracy_gate(
                78,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"cursor_offset:{page_offset}",
                    f"page_size:{page_size}",
                    f"has_more:{bool(has_more)}",
                ],
            ),
            build_accuracy_gate(
                79,
                satisfied_checks=satisfied,
                evidence_refs=[
                    f"bounded_window_rows:{len(match_rows)}",
                    f"window_truncated:{len(returned_matches) > len(match_rows)}",
                    "ui:virtualized-table-compatible-window",
                ],
            ),
        ],
        "ready_for_court_absence_claim": not partial_sources and not filter_after_retrieval,
        "operator_warning": (
            "Use manifest_hash, page_window_hash, source locators, and source-plan warnings when moving search hits "
            "into review or reports; bounded-source no-hit claims still require validation evidence."
        ),
    }
    return {**manifest_core, "manifest_hash": stable_payload_sha256(manifest_core)}


def case_search_reportability_decision(
    *,
    result_window_manifest: Mapping[str, object],
    large_case_search_plan: Mapping[str, object],
    returned_matches: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    search_index_health = (
        large_case_search_plan.get("search_index_health")
        if isinstance(large_case_search_plan.get("search_index_health"), Mapping)
        else {}
    )
    health_summary = search_index_health.get("summary") if isinstance(search_index_health.get("summary"), Mapping) else {}
    large_case_controls = (
        result_window_manifest.get("large_case_controls")
        if isinstance(result_window_manifest.get("large_case_controls"), Mapping)
        else {}
    )
    filters = result_window_manifest.get("filters") if isinstance(result_window_manifest.get("filters"), Mapping) else {}
    partial_sources = [str(item) for item in large_case_controls.get("partial_sources", [])]
    blockers: list[str] = [
        "open-source-viewer-and-record-review-mark-before-report",
        "trusted-parser-or-known-answer-validation-required-before-court-use",
    ]
    if partial_sources:
        blockers.append("bounded-or-stale-search-source-partial-coverage")
    if search_index_health.get("status") not in ("healthy", None, ""):
        blockers.append("case-search-index-rebuild-required-before-absence-claims")
    if filters.get("post_retrieval_filtering"):
        blockers.append("post-retrieval-filtering-blocks-absence-claims")
    ready_for_absence_claim = bool(result_window_manifest.get("ready_for_court_absence_claim")) and not any(
        blocker
        in {
            "bounded-or-stale-search-source-partial-coverage",
            "case-search-index-rebuild-required-before-absence-claims",
            "post-retrieval-filtering-blocks-absence-claims",
        }
        for blocker in blockers
    )
    core: dict[str, object] = {
        "profile_version": "case-search-reportability-decision-v1",
        "decision": "case-search-results-are-review-leads-not-standalone-proof",
        "allowed_use": "triage-search-pivot-and-review-queue",
        "match_count": len(returned_matches),
        "ready_for_review_queue": True,
        "ready_for_absence_claim": ready_for_absence_claim,
        "ready_for_court_report": False,
        "source_plan_status": str(large_case_search_plan.get("status") or ""),
        "result_window_manifest_hash": str(result_window_manifest.get("manifest_hash") or ""),
        "search_index_health_status": str(search_index_health.get("status") or "unknown"),
        "search_index_missing_rows": int(health_summary.get("missing_index_rows") or 0),
        "partial_sources": partial_sources,
        "blockers": blockers,
        "required_before_report": [
            "open the source viewer for selected hits",
            "record review status and analyst note",
            "carry citation/source locator into report item",
            "attach trusted validation evidence before court/report-grade claims",
        ],
        "commercial_gap_ids": ["#52", "#61", "#64", "#65", "#74", "#78", "#79"],
    }
    return {**core, "decision_hash": stable_payload_sha256(core)}


def case_search_scan_candidate_limit(limit: int) -> int:
    if limit <= 0:
        return CASE_DB_SEARCH_SCAN_ROW_LIMIT
    requested = max(CASE_DB_SEARCH_MIN_SCAN_ROWS, int(limit) * CASE_DB_SEARCH_SCAN_OVERSAMPLE)
    return min(CASE_DB_SEARCH_SCAN_ROW_LIMIT, requested)


def dedupe_matches(matches: list[dict[str, object]], *, limit: int) -> list[dict[str, object]]:
    output = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        key = (str(match.get("target_type") or ""), str(match.get("target_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        output.append(match)
        if limit and len(output) >= limit:
            break
    return output


def artifact_fts_has_rows(connection: sqlite3.Connection, case_id: str) -> bool:
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM artifact_fts
            JOIN artifact ON artifact_fts.rowid = artifact.id
            WHERE artifact.case_id = ?
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def search_artifacts_fts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    query = build_fts_query(keywords)
    try:
        rows = connection.execute(
            """
            SELECT
                artifact.citation_id,
                artifact.id,
                artifact.artifact_type,
                artifact.title,
                artifact.summary,
                artifact.data_json,
                snippet(artifact_fts, 2, '[', ']', ' ... ', 18) AS snippet
            FROM artifact_fts
            JOIN artifact ON artifact_fts.rowid = artifact.id
            WHERE artifact.case_id = ?
              AND artifact_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (case_id, query, limit or -1),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    matches = []
    for row in rows:
        artifact_row = parse_json_object(row["data_json"])
        metadata = artifact_search_metadata(artifact_row)
        preview = str(row["summary"] or row["snippet"] or row["artifact_type"])
        matches.append(
            {
                "source": artifact_match_source(str(row["artifact_type"])),
                "citation_id": str(row["citation_id"]),
                "target_type": "artifact",
                "target_id": str(row["id"]),
                "title": str(row["title"] or row["artifact_type"]),
                "kind": str(row["artifact_type"]),
                "path": artifact_source_path(artifact_row),
                "matched_keywords": matched_keywords(f"{row['title']} {row['summary']} {row['snippet']}", keywords),
                "preview": preview,
                "metadata": metadata,
            }
        )
    return matches


def search_events(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
    scan_candidate_limit: int,
) -> list[dict[str, object]]:
    if event_fts_has_rows(connection, case_id):
        fts_matches = search_events_fts(connection, case_id, keywords, limit)
        if fts_matches:
            return fts_matches[:limit] if limit else fts_matches
    rows = connection.execute(
        """
        SELECT citation_id, id, event_type, timestamp, target, description, source
        FROM event
        WHERE case_id = ?
        ORDER BY timestamp ASC, id ASC
        LIMIT ?
        """,
        (case_id, scan_candidate_limit),
    ).fetchall()
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("event_type", "timestamp", "target", "description", "source"))
        hits = matched_keywords(haystack, keywords)
        if not hits:
            continue
        matches.append(
            {
                "source": "timeline",
                "citation_id": str(row["citation_id"]),
                "target_type": "event",
                "target_id": str(row["id"]),
                "title": str(row["description"] or row["event_type"]),
                "kind": str(row["event_type"]),
                "timestamp": str(row["timestamp"]),
                "path": str(row["target"] or ""),
                "matched_keywords": hits,
                "preview": str(row["description"] or row["target"] or row["event_type"]),
            }
        )
        if limit and len(matches) >= limit:
            break
    return matches


def event_fts_has_rows(connection: sqlite3.Connection, case_id: str) -> bool:
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM event_fts
            JOIN event ON event_fts.rowid = event.id
            WHERE event.case_id = ?
            LIMIT 1
            """,
            (case_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def search_events_fts(
    connection: sqlite3.Connection,
    case_id: str,
    keywords: list[str],
    limit: int,
) -> list[dict[str, object]]:
    query = build_fts_query(keywords)
    try:
        rows = connection.execute(
            """
            SELECT
                event.citation_id,
                event.id,
                event.event_type,
                event.timestamp,
                event.target,
                event.description,
                event.source,
                snippet(event_fts, 3, '[', ']', ' ... ', 24) AS snippet
            FROM event_fts
            JOIN event ON event_fts.rowid = event.id
            WHERE event.case_id = ?
              AND event_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (case_id, query, limit or -1),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    matches = []
    for row in rows:
        haystack = " ".join(str(row[key] or "") for key in ("event_type", "timestamp", "target", "description", "source"))
        matches.append(
            {
                "source": "timeline",
                "citation_id": str(row["citation_id"]),
                "target_type": "event",
                "target_id": str(row["id"]),
                "title": str(row["description"] or row["event_type"]),
                "kind": str(row["event_type"]),
                "timestamp": str(row["timestamp"]),
                "path": str(row["target"] or ""),
                "matched_keywords": matched_keywords(haystack, keywords),
                "preview": str(row["snippet"] or row["description"] or row["target"] or row["event_type"]),
                "metadata": {
                    "timeline_source": str(row["source"] or ""),
                    "search_backend": "sqlite-fts5",
                },
            }
        )
    return matches
