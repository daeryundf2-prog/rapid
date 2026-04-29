from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import parse_qs, unquote_plus, urlparse

from ...core.models import ArtifactRecord
from .common import (
    isoformat_from_unix_micros,
    isoformat_from_timestamp,
    isoformat_from_webkit_micros,
    iter_windows_user_homes,
    open_sqlite_snapshot,
)

CHROMIUM_BROWSER_ROOTS: Tuple[Tuple[str, Sequence[str]], ...] = (
    ("chrome", ("AppData", "Local", "Google", "Chrome", "User Data")),
    ("edge", ("AppData", "Local", "Microsoft", "Edge", "User Data")),
    ("brave", ("AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")),
)
FIREFOX_PROFILE_ROOT = ("AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
PARSER_VERSION = "windows-browser-v5"
MAX_USAGE_ROWS = 500
MAX_AI_STORAGE_FILES = 80
MAX_AI_STORAGE_FILE_BYTES = 5 * 1024 * 1024
MAX_AI_CONVERSATION_ROWS = 200
MAX_BROWSER_INVENTORY_FILES = 5000
MAX_BROWSER_INVENTORY_SAMPLE_FILES = 6
MAX_BROWSER_INVENTORY_HASH_BYTES = 16 * 1024 * 1024
MAX_BROWSER_TIMELINE_ROWS = 1000

AI_SERVICE_DOMAINS: Tuple[Tuple[str, str], ...] = (
    ("chatgpt.com", "ChatGPT"),
    ("chat.openai.com", "ChatGPT"),
    ("openai.com", "OpenAI"),
    ("claude.ai", "Claude"),
    ("gemini.google.com", "Gemini"),
    ("bard.google.com", "Gemini"),
    ("aistudio.google.com", "Google AI Studio"),
    ("perplexity.ai", "Perplexity"),
    ("copilot.microsoft.com", "Microsoft Copilot"),
    ("bing.com", "Microsoft Copilot/Bing Chat"),
    ("poe.com", "Poe"),
    ("huggingface.co", "Hugging Face"),
    ("grok.com", "Grok"),
    ("x.ai", "Grok"),
    ("you.com", "You.com"),
    ("phind.com", "Phind"),
    ("chat.mistral.ai", "Mistral Le Chat"),
    ("deepseek.com", "DeepSeek"),
    ("meta.ai", "Meta AI"),
    ("character.ai", "Character.AI"),
    ("notion.so", "Notion AI"),
)
QUERY_HINT_KEYS = ("q", "query", "prompt", "text", "message", "ask", "p")
SEARCH_HOST_HINTS = ("google.", "bing.com", "duckduckgo.com", "naver.com", "daum.net", "yahoo.")
EMAIL_HOST_HINTS = ("mail.google.com", "outlook.live.com", "outlook.office.com", "mail.naver.com", "mail.daum.net")
SOCIAL_HOST_HINTS = ("facebook.com", "instagram.com", "x.com", "twitter.com", "threads.net", "linkedin.com")
CLOUD_HOST_HINTS = ("drive.google.com", "onedrive.live.com", "dropbox.com", "icloud.com", "box.com")
AI_STORAGE_DIRS: Tuple[Tuple[str, ...], ...] = (
    ("Local Storage", "leveldb"),
    ("Session Storage",),
    ("IndexedDB",),
    ("Cache", "Cache_Data"),
    ("Cache",),
)
AI_STORAGE_SUFFIXES = {".log", ".ldb", ".sqlite", ".sqlite3", ".db", ".json", ".txt"}
BROWSER_STORAGE_LOCATIONS: Tuple[Tuple[str, str, Tuple[str, ...], str, bool], ...] = (
    ("cache", "cache-data", ("Cache", "Cache_Data"), "browser-cache-inventory", False),
    ("cache", "legacy-cache", ("Cache",), "browser-cache-inventory", False),
    ("session", "session-storage", ("Session Storage",), "browser-session-storage-inventory", True),
    ("session", "sessions", ("Sessions",), "browser-session-restore-inventory", True),
    ("extension", "extensions", ("Extensions",), "browser-extension-inventory", False),
    ("extension", "extension-state", ("Extension State",), "browser-extension-state-inventory", True),
    ("sync", "sync-data", ("Sync Data",), "browser-sync-inventory", True),
    ("sync", "account-web-data", ("Web Data",), "browser-sync-profile-inventory", True),
    ("cookie", "network-cookies", ("Network", "Cookies"), "browser-cookie-store-inventory", True),
    ("cookie", "cookies", ("Cookies",), "browser-cookie-store-inventory", True),
    ("credential", "login-data", ("Login Data",), "browser-credential-store-inventory", True),
    ("storage", "local-storage-leveldb", ("Local Storage", "leveldb"), "browser-local-storage-inventory", True),
    ("storage", "indexeddb", ("IndexedDB",), "browser-indexeddb-inventory", True),
)
BROWSER_PRIVACY_WARNING = (
    "Browser cache, session, sync, cookie, and credential stores can contain private communications, "
    "tokens, identifiers, and regulated personal data. Treat this inventory as legally sensitive, "
    "review authority/scope before opening raw files, and do not report secrets from this parser alone."
)
BROWSER_SECRET_HANDLING_WARNING = (
    "Password, cookie, and session stores are handled as scoped inventory only. RapidTriage does not "
    "decrypt or expose secret values from this parser; confirm legal authority and case scope before "
    "opening raw browser stores with any external credential tooling."
)
BROWSER_COMMERCIAL_BLOCKERS = [
    "full-browser-cache-entry-decoding-not-implemented",
    "cookie-value-decryption-and-legal-opt-in-not-implemented",
    "extension-schema-and-sync-engine-validation-required",
    "cross-browser-session-restore-decoding-incomplete",
    "known-answer-validation-corpus-required",
]
BROWSER_NATIVE_CAPABILITIES = {
    "chromium_history_downloads_sqlite": True,
    "firefox_places_history": True,
    "bounded_unified_visit_download_timeline": True,
    "browser_storage_inventory": True,
    "ai_service_visit_detection": True,
    "password_cookie_session_inventory": True,
    "full_cache_entry_decode": False,
    "cookie_value_decryption": False,
    "password_cookie_session_secret_extraction": False,
    "legal_scope_gate": True,
    "extension_schema_specific_decode": False,
    "sync_engine_state_decode": False,
    "cross_browser_deleted_session_recovery": False,
    "safari_windows_profile_support": False,
}
BROWSER_REPORT_GRADE_BLOCKERS = [
    "full-browser-cache-entry-decoding-not-implemented",
    "cookie-value-decryption-and-legal-opt-in-not-implemented",
    "extension-schema-and-sync-engine-validation-required",
    "sync-engine-state-validation-required",
    "cross-browser-session-restore-decoding-incomplete",
    "cross-browser-timeline-known-answer-corpus-required",
]
AI_TRANSCRIPT_BLOCKERS = [
    "service-side-transcript-export-not-validated",
    "browser-storage-snippet-pairing-is-order-based",
    "deleted-fragment-recovery-and-schema-versioning-incomplete",
    "known-answer-validation-corpus-required",
]


class WindowsBrowserArtifactsProvider:
    collector_kind = "browser"
    name = "windows-browser-artifacts"
    description = "Windows browser history/download collectors backed by real profile files"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for user_root in iter_windows_user_homes(root):
            user_name = user_root.name
            for browser_name, relative_parts in CHROMIUM_BROWSER_ROOTS:
                user_data_root = user_root.joinpath(*relative_parts)
                if not user_data_root.is_dir():
                    continue
                for profile_dir in sorted(user_data_root.iterdir(), key=lambda item: item.name.lower()):
                    if not profile_dir.is_dir():
                        continue
                    history_path = profile_dir / "History"
                    if not history_path.is_file():
                        yield from build_browser_storage_only_artifacts(
                            provider=self.name,
                            user=user_name,
                            browser=browser_name,
                            profile=profile_dir.name,
                            profile_dir=profile_dir,
                        )
                        continue
                    history_rows, download_rows = extract_chromium_history_and_downloads(history_path)
                    if not history_rows and not download_rows:
                        continue
                    yield from build_browser_artifacts(
                        provider=self.name,
                        artifact_type="browser-history-downloads",
                        user=user_name,
                        browser=browser_name,
                        profile=profile_dir.name,
                        source_path=history_path,
                        history_rows=history_rows,
                        download_rows=download_rows,
                    )

            firefox_root = user_root.joinpath(*FIREFOX_PROFILE_ROOT)
            if not firefox_root.is_dir():
                continue
            for profile_dir in sorted(firefox_root.iterdir(), key=lambda item: item.name.lower()):
                if not profile_dir.is_dir():
                    continue
                places_path = profile_dir / "places.sqlite"
                if not places_path.is_file():
                    continue
                history_rows = extract_firefox_history(places_path)
                if not history_rows:
                    continue
                yield from build_browser_artifacts(
                    provider=self.name,
                    artifact_type="browser-history",
                    user=user_name,
                    browser="firefox",
                    profile=profile_dir.name,
                    source_path=places_path,
                    history_rows=history_rows,
                    download_rows=[],
                )


def build_browser_storage_only_artifacts(
    *,
    provider: str,
    user: str,
    browser: str,
    profile: str,
    profile_dir: Path,
    parser_version: str = PARSER_VERSION,
    ai_conversation_artifact_type: str = "browser-ai-conversation",
    storage_inventory_artifact_type: str = "browser-storage-inventory",
) -> List[ArtifactRecord]:
    conversation_rows = extract_ai_conversation_candidates(profile_dir)
    storage_inventory = inventory_browser_storage_artifacts(profile_dir)
    records: List[ArtifactRecord] = []
    if storage_inventory:
        records.append(
            build_browser_storage_inventory_record(
                provider=provider,
                artifact_type=storage_inventory_artifact_type,
                user=user,
                browser=browser,
                profile=profile,
                profile_dir=profile_dir,
                storage_inventory=storage_inventory,
                parser_version=parser_version,
            )
        )
    if conversation_rows:
        records.append(
            build_ai_conversation_record(
                provider=provider,
                artifact_type=ai_conversation_artifact_type,
                user=user,
                browser=browser,
                profile=profile,
                profile_dir=profile_dir,
                conversation_rows=conversation_rows,
                parser_version=parser_version,
            )
        )
    return records


def build_browser_artifacts(
    *,
    provider: str,
    artifact_type: str,
    user: str,
    browser: str,
    profile: str,
    source_path: Path,
    history_rows: List[Dict[str, object]],
    download_rows: List[Dict[str, object]],
    parser: str | None = None,
    parser_version: str = PARSER_VERSION,
    ai_artifact_type: str = "browser-ai-usage",
    ai_conversation_artifact_type: str = "browser-ai-conversation",
    storage_inventory_artifact_type: str = "browser-storage-inventory",
) -> List[ArtifactRecord]:
    usage_rows = summarize_internet_usage(history_rows)
    ai_rows = extract_ai_usage(history_rows)
    profile_dir = source_path.parent
    conversation_rows = extract_ai_conversation_candidates(profile_dir)
    storage_inventory = inventory_browser_storage_artifacts(profile_dir)
    unified_timeline = build_unified_browser_timeline(
        browser=browser,
        profile=profile,
        user=user,
        source_path=source_path,
        history_rows=history_rows,
        download_rows=download_rows,
        ai_rows=ai_rows,
    )
    source_hashes = file_hashes(source_path)
    validation_checks = browser_validation_checks(
        history_rows=history_rows,
        download_rows=download_rows,
        storage_inventory=storage_inventory,
        conversation_rows=conversation_rows,
        unified_timeline=unified_timeline,
    )
    base_details = {
        "parser": parser or "browser-history",
        "parser_version": parser_version,
        "coverage_status": "parsed",
        "reportability": "triage",
        "source_path": str(source_path.resolve()),
        "source_hashes": source_hashes,
        "source_profile": build_source_profile_metadata(
            user=user,
            browser=browser,
            profile=profile,
            source_path=source_path,
        ),
        "user": user,
        "browser": browser,
        "profile": profile,
        "history_count": len(history_rows),
        "download_count": len(download_rows),
        "internet_usage_count": len(usage_rows),
        "ai_usage_count": len(ai_rows),
        "ai_conversation_candidate_count": len(conversation_rows),
        "browser_storage_inventory_count": len(storage_inventory),
        "browser_sensitive_inventory_count": sum(1 for row in storage_inventory if row.get("sensitive")),
        "unified_timeline_count": len(unified_timeline),
        "internet_category_counts": count_field(usage_rows, "category"),
        "top_domains": count_field(usage_rows, "domain", limit=20),
        "history": history_rows,
        "downloads": download_rows,
        "internet_usage": usage_rows,
        "ai_usage": ai_rows,
        "ai_conversation_candidates": conversation_rows[:25],
        "browser_storage_inventory": storage_inventory,
        "unified_timeline": unified_timeline,
        "browser_validation_checks": validation_checks,
        "browser_validation_matrix": browser_validation_matrix(validation_checks),
        "browser_report_grade_assessment": browser_report_grade_assessment(validation_checks),
        "browser_native_capabilities": dict(BROWSER_NATIVE_CAPABILITIES),
        "privacy_legal_warning": BROWSER_PRIVACY_WARNING,
        "commercial_grade_ready": False,
        "commercial_grade_blockers": BROWSER_REPORT_GRADE_BLOCKERS,
    }
    records = [
        ArtifactRecord(
            provider=provider,
            artifact_type=artifact_type,
            path=str(source_path.resolve()),
            supported=True,
            details=base_details,
        )
    ]
    if ai_rows:
        seen = sorted([str(row.get("last_visited_at")) for row in ai_rows if row.get("last_visited_at")])
        records.append(
            ArtifactRecord(
                provider=provider,
                artifact_type=ai_artifact_type,
                path=str(source_path.resolve()),
                supported=True,
                details={
                    "parser": "browser-ai-usage",
                    "parser_version": parser_version,
                    "coverage_status": "detected",
                    "reportability": "review",
                    "source_path": str(source_path.resolve()),
                    "source_hashes": source_hashes,
                    "source_profile": build_source_profile_metadata(
                        user=user,
                        browser=browser,
                        profile=profile,
                        source_path=source_path,
                    ),
                    "user": user,
                    "browser": browser,
                    "profile": profile,
                    "ai_usage_count": len(ai_rows),
                    "ai_conversation_candidate_count": len(conversation_rows),
                    "ai_service_counts": count_field(ai_rows, "ai_service"),
                    "first_seen_at": seen[0] if seen else None,
                    "last_seen_at": seen[-1] if seen else None,
                    "ai_usage": ai_rows,
                    "ai_conversation_candidates": conversation_rows[:25],
                    "browser_storage_inventory_count": len(storage_inventory),
                    "ai_transcript_validation_status": (
                        build_ai_transcript_summary(conversation_rows)["validation_status"] if conversation_rows else "none"
                    ),
                    "privacy_legal_warning": BROWSER_PRIVACY_WARNING,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": AI_TRANSCRIPT_BLOCKERS,
                    "browser_report_grade_assessment": {
                        **browser_report_grade_assessment(validation_checks),
                        "commercial_gap_ids": ["#20", "#21"],
                    },
                    "browser_native_capabilities": dict(BROWSER_NATIVE_CAPABILITIES),
                    "risk_flags": ["ai-service-usage"],
                    "triage_recommendation": (
                        "Browser history proves visits to AI services only. Review page titles, URL query hints, "
                        "browser cache, downloads, synced cloud exports, and app logs before claiming prompt content."
                    ),
                },
            )
        )
    if conversation_rows:
        records.append(
            build_ai_conversation_record(
                provider=provider,
                artifact_type=ai_conversation_artifact_type,
                user=user,
                browser=browser,
                profile=profile,
                profile_dir=profile_dir,
                conversation_rows=conversation_rows,
                parser_version=parser_version,
            )
        )
    if storage_inventory:
        records.append(
            build_browser_storage_inventory_record(
                provider=provider,
                artifact_type=storage_inventory_artifact_type,
                user=user,
                browser=browser,
                profile=profile,
                profile_dir=profile_dir,
                storage_inventory=storage_inventory,
                parser_version=parser_version,
            )
        )
    return records


def build_ai_conversation_record(
    *,
    provider: str,
    artifact_type: str,
    user: str,
    browser: str,
    profile: str,
    profile_dir: Path,
    conversation_rows: List[Dict[str, object]],
    parser_version: str,
) -> ArtifactRecord:
    transcript = build_ai_transcript_summary(conversation_rows)
    source_summary = summarize_ai_conversation_sources(conversation_rows)
    return ArtifactRecord(
        provider=provider,
        artifact_type=artifact_type,
        path=str(profile_dir.resolve()),
        supported=True,
        details={
            "parser": "browser-ai-conversation-storage",
            "parser_version": parser_version,
            "coverage_status": "candidate",
            "reportability": "review",
            "source_path": str(profile_dir.resolve()),
            "user": user,
            "browser": browser,
            "profile": profile,
            "ai_conversation_candidate_count": len(conversation_rows),
            "question_count": sum(1 for row in conversation_rows if row.get("direction") == "question"),
            "answer_count": sum(1 for row in conversation_rows if row.get("direction") == "answer"),
            "ai_service_counts": count_field(conversation_rows, "ai_service"),
            "transcript_pair_count": transcript["pair_count"],
            "complete_pair_count": transcript["complete_pair_count"],
            "orphan_question_count": transcript["orphan_question_count"],
            "orphan_answer_count": transcript["orphan_answer_count"],
            "transcript_completeness_score": transcript["completeness_score"],
            "transcript_validation_status": transcript["validation_status"],
            "pairing_confidence_summary": transcript["pairing_confidence_summary"],
            "source_storage_summary": source_summary,
            "transcript_validation_checks": {
                "has_service_label": bool(count_field(conversation_rows, "ai_service")),
                "has_question_answer_pair": bool(transcript["complete_pair_count"]),
                "has_source_hashes": all(bool(row.get("source_sha256")) for row in conversation_rows),
                "has_source_storage_area": all(bool(row.get("storage_area")) for row in conversation_rows),
                "has_orphans": bool(transcript["orphan_question_count"] or transcript["orphan_answer_count"]),
                "service_side_export_validated": False,
            },
            "conversation_candidates": conversation_rows,
            "transcript_pairs": transcript["pairs"],
            "privacy_legal_warning": BROWSER_PRIVACY_WARNING,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": AI_TRANSCRIPT_BLOCKERS,
            "browser_report_grade_assessment": {
                "status": "validation-required",
                "commercial_gap_ids": ["#21"],
                "failed_check_ids": ["service-side-transcript-export", "schema-version-validation"],
                "blockers": list(AI_TRANSCRIPT_BLOCKERS),
                "ready_for_court_report": False,
                "recommended_validation": [
                    "Validate recovered browser-storage snippets against service-side exports when legally available.",
                    "Confirm question/answer pairing and source offsets in the raw storage files before reporting transcript content.",
                ],
            },
            "browser_native_capabilities": {
                **BROWSER_NATIVE_CAPABILITIES,
                "ai_question_answer_pairing": True,
                "service_side_transcript_export_validation": False,
                "deleted_ai_transcript_fragment_recovery": False,
                "service_schema_version_tracking": False,
            },
            "risk_flags": ["ai-conversation-storage-candidate"],
            "triage_recommendation": (
                "Review these recovered browser-storage snippets against the raw source files. "
                "Pairs with both question and answer are stronger review pivots, but still not guaranteed complete AI transcripts."
            ),
        },
    )


def build_browser_storage_inventory_record(
    *,
    provider: str,
    artifact_type: str,
    user: str,
    browser: str,
    profile: str,
    profile_dir: Path,
    storage_inventory: Sequence[Mapping[str, object]],
    parser_version: str,
) -> ArtifactRecord:
    sensitive_count = sum(1 for row in storage_inventory if row.get("sensitive"))
    secret_validation_checks = browser_secret_handling_validation_checks(sensitive_count)
    return ArtifactRecord(
        provider=provider,
        artifact_type=artifact_type,
        path=str(profile_dir.resolve()),
        supported=True,
        details={
            "parser": "browser-storage-sensitive-inventory",
            "parser_version": parser_version,
            "coverage_status": "inventory-candidate",
            "reportability": "review",
            "source_path": str(profile_dir.resolve()),
            "user": user,
            "browser": browser,
            "profile": profile,
            "inventory_count": len(storage_inventory),
            "sensitive_inventory_count": sensitive_count,
            "storage_type_counts": count_field(storage_inventory, "storage_type"),
            "storage_inventory": list(storage_inventory),
            "privacy_legal_warning": BROWSER_PRIVACY_WARNING,
            "browser_secret_legal_warning": BROWSER_SECRET_HANDLING_WARNING,
            "validation_checks": {
                "raw_secret_values_extracted": False,
                "bounded_inventory": True,
                "sample_file_hashes_present": any(row.get("sample_files") for row in storage_inventory),
                "requires_scope_review": sensitive_count > 0,
            },
            "secret_handling_validation_checks": secret_validation_checks,
            "browser_secret_handling_assessment": browser_secret_handling_assessment(secret_validation_checks),
            "browser_validation_matrix": browser_validation_matrix(
                {
                    "storage_inventory_present": bool(storage_inventory),
                    "sensitive_storage_inventory_present": sensitive_count > 0,
                    "commercial_validation_required": True,
                    "full_cache_entry_decode": False,
                    "cookie_values_decrypted": False,
                    "extension_schema_validated": False,
                    "sync_state_validated": False,
                    "unified_timeline_present": False,
                }
            ),
            "browser_report_grade_assessment": browser_report_grade_assessment(
                {
                    "storage_inventory_present": bool(storage_inventory),
                    "sensitive_storage_inventory_present": sensitive_count > 0,
                    "commercial_validation_required": True,
                    "full_cache_entry_decode": False,
                    "cookie_values_decrypted": False,
                    "extension_schema_validated": False,
                    "sync_state_validated": False,
                    "unified_timeline_present": False,
                }
            ),
            "browser_native_capabilities": dict(BROWSER_NATIVE_CAPABILITIES),
            "commercial_grade_ready": False,
            "commercial_grade_blockers": BROWSER_REPORT_GRADE_BLOCKERS,
            "triage_recommendation": (
                "Use this row to decide which browser stores require scoped manual review. "
                "The parser inventories cache/session/extension/sync/cookie/credential stores but does not decrypt secrets."
            ),
        },
    )


def build_source_profile_metadata(*, user: str, browser: str, profile: str, source_path: Path) -> Dict[str, object]:
    return {
        "user": user,
        "browser": browser,
        "profile": profile,
        "source_database": source_path.name,
        "profile_dir": str(source_path.parent.resolve()),
        "source_platform": "macos" if "Library" in source_path.parts else "windows",
    }


def browser_validation_checks(
    *,
    history_rows: Sequence[Mapping[str, object]],
    download_rows: Sequence[Mapping[str, object]],
    storage_inventory: Sequence[Mapping[str, object]],
    conversation_rows: Sequence[Mapping[str, object]],
    unified_timeline: Sequence[Mapping[str, object]] | None = None,
) -> Dict[str, object]:
    return {
        "history_rows_present": bool(history_rows),
        "download_rows_present": bool(download_rows),
        "typed_url_metadata_present": any("typed_count" in row for row in history_rows),
        "visit_transition_metadata_present": any("transition" in row for row in history_rows),
        "storage_inventory_present": bool(storage_inventory),
        "sensitive_storage_inventory_present": any(row.get("sensitive") for row in storage_inventory),
        "ai_conversation_candidates_present": bool(conversation_rows),
        "unified_timeline_present": bool(unified_timeline),
        "timeline_has_visit_rows": any(row.get("timeline_type") == "visit" for row in (unified_timeline or [])),
        "timeline_has_download_rows": any(row.get("timeline_type") == "download" for row in (unified_timeline or [])),
        "timeline_source_indices_present": all("source_index" in row for row in (unified_timeline or [])),
        "full_cache_entry_decode": False,
        "cookie_values_decrypted": False,
        "extension_schema_validated": False,
        "sync_state_validated": False,
        "commercial_validation_required": True,
    }


def browser_validation_matrix(checks: Mapping[str, object]) -> List[Dict[str, object]]:
    return [
        {
            "id": "history-or-download-source",
            "label": "History or download database rows are present",
            "passed": bool(checks.get("history_rows_present") or checks.get("download_rows_present")),
            "severity": "medium",
        },
        {
            "id": "storage-inventory",
            "label": "Browser cache/session/extension/sync/cookie inventory is present when profile stores exist",
            "passed": bool(checks.get("storage_inventory_present")),
            "severity": "high",
        },
        {
            "id": "unified-timeline",
            "label": "Visit/download rows are normalized into a source-indexed unified timeline",
            "passed": bool(checks.get("unified_timeline_present"))
            and bool(checks.get("timeline_source_indices_present", True)),
            "severity": "high",
        },
        {
            "id": "storage-report-grade",
            "label": "Cache entries, cookies, extensions, session restore, and sync state decoded with schema validation",
            "passed": False,
            "severity": "critical",
        },
        {
            "id": "cross-browser-known-answer",
            "label": "Chrome/Edge/Firefox/Safari timeline behavior validated against known-answer corpora",
            "passed": False,
            "severity": "critical",
        },
    ]


def browser_report_grade_assessment(checks: Mapping[str, object]) -> Dict[str, object]:
    matrix = browser_validation_matrix(checks)
    failed = [item for item in matrix if not item["passed"]]
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#19", "#20"],
        "failed_check_ids": [str(item["id"]) for item in failed],
        "blockers": list(BROWSER_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Validate cache/session/cookie/extension findings with browser-specific parsers and legal scope review.",
            "Correlate unified browser timeline rows with filesystem, downloads, Zone.Identifier, EVTX, and cloud/app exports.",
        ],
    }


def browser_secret_handling_validation_checks(sensitive_count: int) -> Dict[str, object]:
    return {
        "raw_secret_values_extracted": False,
        "cookie_values_decrypted": False,
        "password_values_decrypted": False,
        "session_tokens_extracted": False,
        "strict_legal_warning_present": True,
        "scope_review_required": sensitive_count > 0,
        "inventory_only_mode": True,
    }


def browser_secret_handling_assessment(checks: Mapping[str, object]) -> Dict[str, object]:
    return {
        "status": "inventory-only-validation-required",
        "commercial_gap_ids": ["#42"],
        "ready_for_court_report": False,
        "secret_values_extracted": bool(checks.get("raw_secret_values_extracted")),
        "blockers": [
            "password-cookie-session-secret-decryption-not-implemented",
            "case-scope-and-legal-authority-must-be-confirmed-before-secret-review",
            "browser-and-os-keychain-specific-known-answer-validation-required",
        ],
        "recommended_validation": [
            "Use this inventory to identify candidate stores, then document legal authority before any external credential review.",
            "Validate password/cookie/session interpretation with browser-version and OS-keychain known-answer fixtures.",
        ],
    }


def build_ai_transcript_summary(conversation_rows: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    pairs: List[Dict[str, object]] = []
    pending_question: Mapping[str, object] | None = None
    orphan_questions = 0
    orphan_answers = 0
    for row in conversation_rows:
        direction = str(row.get("direction") or "")
        if direction == "question":
            if pending_question is not None:
                orphan_questions += 1
            pending_question = row
            continue
        if direction == "answer":
            if pending_question is None:
                orphan_answers += 1
                continue
            pairs.append(build_ai_transcript_pair(pending_question, row, len(pairs)))
            pending_question = None
    if pending_question is not None:
        orphan_questions += 1
    question_count = sum(1 for row in conversation_rows if row.get("direction") == "question")
    answer_count = sum(1 for row in conversation_rows if row.get("direction") == "answer")
    complete_pair_count = len(pairs)
    denominator = max(question_count, answer_count, 1)
    completeness_score = round(min(1.0, complete_pair_count / denominator), 3)
    if complete_pair_count and orphan_questions == 0 and orphan_answers == 0:
        validation_status = "paired-candidate"
    elif complete_pair_count:
        validation_status = "partial-paired-candidate"
    elif conversation_rows:
        validation_status = "unpaired-candidate"
    else:
        validation_status = "none"
    return {
        "pair_count": len(pairs),
        "complete_pair_count": complete_pair_count,
        "orphan_question_count": orphan_questions,
        "orphan_answer_count": orphan_answers,
        "completeness_score": completeness_score,
        "validation_status": validation_status,
        "pairing_confidence_summary": summarize_pairing_confidence(pairs),
        "pairs": pairs,
    }


def build_ai_transcript_pair(question: Mapping[str, object], answer: Mapping[str, object], index: int) -> Dict[str, object]:
    service = str(question.get("ai_service") or answer.get("ai_service") or "AI service")
    question_text = str(question.get("text") or "")
    answer_text = str(answer.get("text") or "")
    source_hashes = sorted(
        {
            str(value)
            for value in (question.get("source_sha256"), answer.get("source_sha256"))
            if value
        }
    )
    source_paths = sorted(
        {
            str(value)
            for value in (question.get("source_path"), answer.get("source_path"))
            if value
        }
    )
    confidence = min(float(question.get("confidence") or 0), float(answer.get("confidence") or 0))
    pair_material = f"{service}\n{question_text}\n{answer_text}\n{','.join(source_hashes)}"
    return {
        "pair_id": hashlib.sha256(pair_material.encode("utf-8")).hexdigest()[:24],
        "pair_index": index,
        "ai_service": service,
        "question": question_text,
        "answer": answer_text,
        "question_source_path": str(question.get("source_path") or ""),
        "answer_source_path": str(answer.get("source_path") or ""),
        "source_paths": source_paths,
        "source_sha256s": source_hashes,
        "same_source": bool(source_hashes) and len(source_hashes) == 1,
        "confidence": round(confidence, 3),
        "pairing_confidence": classify_pairing_confidence(confidence, bool(source_hashes) and len(source_hashes) == 1),
        "validation_status": "paired-candidate",
        "evidence_note": "Question/answer pair inferred from recovered browser storage order; verify against raw source before reporting.",
    }


def classify_pairing_confidence(confidence: float, same_source: bool) -> str:
    if same_source and confidence >= 0.8:
        return "high-candidate"
    if confidence >= 0.7:
        return "medium-candidate"
    return "low-candidate"


def summarize_pairing_confidence(pairs: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    counts = {"high-candidate": 0, "medium-candidate": 0, "low-candidate": 0}
    confidence_values: List[float] = []
    for pair in pairs:
        label = str(pair.get("pairing_confidence") or "low-candidate")
        counts[label] = counts.get(label, 0) + 1
        try:
            confidence_values.append(float(pair.get("confidence") or 0))
        except (TypeError, ValueError):
            continue
    average = round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0
    return {
        "counts": counts,
        "average_confidence": average,
        "pairing_method": "bounded-source-order",
        "validation_required": True,
    }


def summarize_ai_conversation_sources(conversation_rows: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    source_paths = sorted({str(row.get("source_path") or "") for row in conversation_rows if row.get("source_path")})
    source_hashes = sorted({str(row.get("source_sha256") or "") for row in conversation_rows if row.get("source_sha256")})
    return {
        "source_file_count": len(source_paths),
        "source_paths": source_paths[:25],
        "source_sha256s": source_hashes[:25],
        "storage_area_counts": count_field(conversation_rows, "storage_area"),
        "service_counts": count_field(conversation_rows, "ai_service"),
    }


def extract_ai_conversation_candidates(profile_dir: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for source in iter_ai_storage_files(profile_dir):
        if len(rows) >= MAX_AI_CONVERSATION_ROWS:
            break
        try:
            data = source.read_bytes()[:MAX_AI_STORAGE_FILE_BYTES]
        except OSError:
            continue
        try:
            stat = source.stat()
        except OSError:
            stat = None
        text = decode_storage_blob(data)
        if not text:
            continue
        service = detect_ai_service(text, "")
        if not service and not likely_ai_storage_text(text):
            continue
        service = service or infer_ai_service_from_path(source)
        fragments = extract_ai_text_fragments(text)
        if not fragments:
            continue
        source_hash = hashlib.sha256(data).hexdigest()
        for fragment in fragments:
            if len(rows) >= MAX_AI_CONVERSATION_ROWS:
                break
            rows.append(
                {
                    "ai_service": service or "AI service",
                    "direction": fragment["direction"],
                    "role": fragment["role"],
                    "text": fragment["text"],
                    "confidence": fragment["confidence"],
                    "storage_area": storage_area(profile_dir, source),
                    "source_storage_kind": classify_storage_kind(storage_area(profile_dir, source)),
                    "source_relative_path": relative_profile_path(profile_dir, source),
                    "source_size": int(stat.st_size) if stat else None,
                    "source_modified_at": isoformat_from_timestamp(stat.st_mtime) if stat else None,
                    "source_offset": fragment.get("source_offset"),
                    "service_detection_source": "content-or-path",
                    "source_path": str(source.resolve()),
                    "source_sha256": source_hash,
                    "evidence_note": "Recovered from browser storage; verify with the raw storage file before reporting as a transcript.",
                }
            )
    return deduplicate_conversation_rows(rows)


def inventory_browser_storage_artifacts(profile_dir: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    seen: set[Path] = set()
    for storage_type, storage_name, relative_parts, artifact_hint, sensitive in BROWSER_STORAGE_LOCATIONS:
        source = profile_dir.joinpath(*relative_parts)
        if source in seen or not source.exists():
            continue
        seen.add(source)
        row = inventory_browser_storage_path(
            profile_dir=profile_dir,
            source=source,
            storage_type=storage_type,
            storage_name=storage_name,
            artifact_hint=artifact_hint,
            sensitive=sensitive,
        )
        if row:
            rows.append(row)
    return rows


def inventory_browser_storage_path(
    *,
    profile_dir: Path,
    source: Path,
    storage_type: str,
    storage_name: str,
    artifact_hint: str,
    sensitive: bool,
) -> Dict[str, object]:
    file_count = 0
    total_bytes = 0
    sample_files: List[Dict[str, object]] = []
    truncated = False
    candidates = [source] if source.is_file() else sorted(source.rglob("*"), key=lambda item: str(item).lower())
    for candidate in candidates:
        if not candidate.is_file():
            continue
        if file_count >= MAX_BROWSER_INVENTORY_FILES:
            truncated = True
            break
        try:
            stat = candidate.stat()
        except OSError:
            continue
        file_count += 1
        total_bytes += int(stat.st_size)
        if len(sample_files) >= MAX_BROWSER_INVENTORY_SAMPLE_FILES:
            continue
        sample_files.append(
            {
                "relative_path": relative_profile_path(profile_dir, candidate),
                "size": int(stat.st_size),
                "modified_at": isoformat_from_timestamp(stat.st_mtime),
                "hashes": safe_sample_hashes(candidate, int(stat.st_size)),
            }
        )
    if source.is_file() and file_count == 0:
        try:
            stat = source.stat()
        except OSError:
            return {}
        file_count = 1
        total_bytes = int(stat.st_size)
    return {
        "storage_type": storage_type,
        "storage_name": storage_name,
        "artifact_hint": artifact_hint,
        "relative_path": relative_profile_path(profile_dir, source),
        "source_path": str(source.resolve()),
        "exists": True,
        "is_file": source.is_file(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "sample_files": sample_files,
        "inventory_truncated": truncated,
        "sensitive": sensitive,
        "raw_values_extracted": False,
        "privacy_legal_warning": BROWSER_PRIVACY_WARNING if sensitive else "",
        "validation_status": "inventory-candidate",
        "commercial_grade_ready": False,
        "commercial_grade_blockers": BROWSER_COMMERCIAL_BLOCKERS,
    }


def build_unified_browser_timeline(
    *,
    browser: str,
    profile: str,
    user: str,
    source_path: Path,
    history_rows: Sequence[Mapping[str, object]],
    download_rows: Sequence[Mapping[str, object]],
    ai_rows: Sequence[Mapping[str, object]],
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    ai_urls = {str(row.get("url") or ""): row for row in ai_rows}
    for index, row in enumerate(history_rows[:MAX_BROWSER_TIMELINE_ROWS]):
        url = str(row.get("url") or "")
        ai_row = ai_urls.get(url, {})
        rows.append(
            {
                "timeline_type": "visit",
                "timestamp": row.get("last_visited_at"),
                "browser": browser,
                "profile": profile,
                "user": user,
                "url": url,
                "title": row.get("title") or "",
                "domain": normalize_host(safe_parse_url(url).netloc),
                "visit_count": int(row.get("visit_count") or 0),
                "typed_count": int(row.get("typed_count") or 0),
                "transition": row.get("transition") or "",
                "visit_duration_micros": int(row.get("visit_duration_micros") or 0),
                "ai_service": ai_row.get("ai_service") or detect_ai_service(url, str(row.get("title") or "")),
                "query_hint": row.get("query_hint") or extract_query_hint(url),
                "source_path": str(source_path.resolve()),
                "source_table": "history",
                "source_index": index,
                "validation_status": "normalized-candidate",
            }
        )
    for index, row in enumerate(download_rows[:MAX_BROWSER_TIMELINE_ROWS]):
        source_url = str(row.get("source_url") or row.get("tab_url") or "")
        rows.append(
            {
                "timeline_type": "download",
                "timestamp": row.get("started_at"),
                "browser": browser,
                "profile": profile,
                "user": user,
                "url": source_url,
                "title": "",
                "domain": normalize_host(safe_parse_url(source_url).netloc),
                "target_path": row.get("target_path") or "",
                "total_bytes": int(row.get("total_bytes") or 0),
                "state": int(row.get("state") or 0),
                "ended_at": row.get("ended_at"),
                "source_path": str(source_path.resolve()),
                "source_table": "downloads",
                "source_index": index,
                "validation_status": "normalized-candidate",
            }
        )
    return sorted(rows, key=lambda item: str(item.get("timestamp") or ""), reverse=True)[:MAX_BROWSER_TIMELINE_ROWS]


def relative_profile_path(profile_dir: Path, source: Path) -> str:
    try:
        return str(source.relative_to(profile_dir))
    except ValueError:
        return source.name


def classify_storage_kind(area: str) -> str:
    lowered = area.lower()
    if "local storage" in lowered:
        return "local-storage"
    if "session" in lowered:
        return "session-storage"
    if "indexeddb" in lowered:
        return "indexeddb"
    if "cache" in lowered:
        return "cache"
    return "browser-storage"


def safe_sample_hashes(path: Path, size: int) -> Dict[str, object]:
    if size > MAX_BROWSER_INVENTORY_HASH_BYTES:
        return {
            "sha256": None,
            "hash_scope": "not-hashed-large-file",
            "reason": f"file exceeds {MAX_BROWSER_INVENTORY_HASH_BYTES} byte bounded inventory limit",
        }
    try:
        return {**file_hashes(path), "hash_scope": "full-file"}
    except OSError:
        return {"sha256": None, "hash_scope": "unreadable"}


def iter_ai_storage_files(profile_dir: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    yielded = 0
    for relative in AI_STORAGE_DIRS:
        root = profile_dir.joinpath(*relative)
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*"), key=lambda item: str(item).lower())
        for candidate in candidates:
            if yielded >= MAX_AI_STORAGE_FILES:
                return
            if not candidate.is_file() or candidate in seen:
                continue
            if candidate.suffix.lower() not in AI_STORAGE_SUFFIXES and candidate.name.lower() not in {"data_0", "data_1", "index"}:
                continue
            try:
                if candidate.stat().st_size <= 0:
                    continue
            except OSError:
                continue
            seen.add(candidate)
            yielded += 1
            yield candidate


def decode_storage_blob(data: bytes) -> str:
    if not data:
        return ""
    decoded = data.decode("utf-8", errors="ignore")
    printable = re.sub(r"[^\x09\x0a\x0d\x20-\x7e\u00a0-\uffff]+", " ", decoded)
    return printable[:MAX_AI_STORAGE_FILE_BYTES]


def likely_ai_storage_text(text: str) -> bool:
    lowered = text.lower()
    if any(domain in lowered for domain, _service in AI_SERVICE_DOMAINS):
        return True
    return any(token in lowered for token in ("chatgpt", "claude", "gemini", "perplexity", "assistant", '"role"', '"content"'))


def infer_ai_service_from_path(path: Path) -> str:
    lowered = str(path).lower()
    for domain, service in AI_SERVICE_DOMAINS:
        if domain in lowered:
            return service
    return ""


def extract_ai_text_fragments(text: str) -> List[Dict[str, object]]:
    fragments: List[Dict[str, object]] = []
    fragments.extend(extract_json_role_content_fragments(text))
    fragments.extend(extract_named_prompt_answer_fragments(text))
    return fragments


def extract_json_role_content_fragments(text: str) -> List[Dict[str, object]]:
    fragments: List[Dict[str, object]] = []
    patterns = (
        r'"role"\s*:\s*"(?P<role>user|assistant|system)"[\s\S]{0,800}?"content"\s*:\s*"(?P<content>(?:\\.|[^"\\]){2,4000})"',
        r'"content"\s*:\s*"(?P<content>(?:\\.|[^"\\]){2,4000})"[\s\S]{0,800}?"role"\s*:\s*"(?P<role>user|assistant|system)"',
        r'"author"\s*:\s*\{[\s\S]{0,400}?"role"\s*:\s*"(?P<role>user|assistant|system)"[\s\S]{0,1200}?"text"\s*:\s*"(?P<content>(?:\\.|[^"\\]){2,4000})"',
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            role = match.group("role").lower()
            content = clean_recovered_text(match.group("content"))
            if not useful_conversation_text(content):
                continue
            fragments.append(
                {
                    "role": role,
                    "direction": role_to_direction(role),
                    "text": content,
                    "confidence": 0.82 if role in {"user", "assistant"} else 0.65,
                    "source_offset": match.start(),
                }
            )
    return fragments


def extract_named_prompt_answer_fragments(text: str) -> List[Dict[str, object]]:
    fragments: List[Dict[str, object]] = []
    key_roles = {
        "prompt": ("user", "question"),
        "question": ("user", "question"),
        "query": ("user", "question"),
        "answer": ("assistant", "answer"),
        "response": ("assistant", "answer"),
        "completion": ("assistant", "answer"),
    }
    pattern = r'"(?P<key>prompt|question|query|answer|response|completion)"\s*:\s*"(?P<content>(?:\\.|[^"\\]){4,3000})"'
    for match in re.finditer(pattern, text, flags=re.IGNORECASE):
        key = match.group("key").lower()
        role, direction = key_roles[key]
        content = clean_recovered_text(match.group("content"))
        if not useful_conversation_text(content):
            continue
        fragments.append(
            {
                "role": role,
                "direction": direction,
                "text": content,
                "confidence": 0.72,
                "source_offset": match.start(),
            }
        )
    return fragments


def role_to_direction(role: str) -> str:
    if role == "user":
        return "question"
    if role == "assistant":
        return "answer"
    return "context"


def clean_recovered_text(value: str) -> str:
    try:
        decoded = json.loads(f'"{value}"')
    except json.JSONDecodeError:
        decoded = value
    normalized = re.sub(r"\s+", " ", str(decoded)).strip()
    return normalized[:1500]


def useful_conversation_text(value: str) -> bool:
    if len(value) < 4:
        return False
    lowered = value.lower()
    if lowered in {"null", "true", "false", "undefined"}:
        return False
    return any(character.isalpha() for character in value)


def storage_area(profile_dir: Path, source: Path) -> str:
    try:
        relative = source.relative_to(profile_dir)
    except ValueError:
        return source.parent.name
    parts = relative.parts
    if len(parts) >= 2 and parts[0] in {"Local Storage", "Cache"}:
        return "/".join(parts[:2])
    return parts[0] if parts else source.parent.name


def deduplicate_conversation_rows(rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    deduped: List[Dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (str(row.get("ai_service") or ""), str(row.get("direction") or ""), str(row.get("text") or "")[:240])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(row))
    return deduped


def summarize_internet_usage(history_rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    usage_rows: List[Dict[str, object]] = []
    for index, row in enumerate(history_rows[:MAX_USAGE_ROWS]):
        url = str(row.get("url") or "")
        parsed = safe_parse_url(url)
        if not parsed.scheme.startswith("http") or not parsed.netloc:
            continue
        title = str(row.get("title") or "")
        service = detect_ai_service(url, title)
        usage_rows.append(
            {
                "source_index": index,
                "url": url,
                "title": title,
                "domain": normalize_host(parsed.netloc),
                "category": classify_url(parsed, title, service),
                "visit_count": int(row.get("visit_count") or 0),
                "last_visited_at": row.get("last_visited_at"),
                "ai_service": service,
                "query_hint": extract_query_hint(url),
            }
        )
    return usage_rows


def extract_ai_usage(history_rows: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    ai_rows: List[Dict[str, object]] = []
    for index, row in enumerate(history_rows[:MAX_USAGE_ROWS]):
        url = str(row.get("url") or "")
        title = str(row.get("title") or "")
        service = detect_ai_service(url, title)
        if not service:
            continue
        parsed = safe_parse_url(url)
        query_hint = extract_query_hint(url)
        ai_rows.append(
            {
                "source_index": index,
                "ai_service": service,
                "url": url,
                "domain": normalize_host(parsed.netloc),
                "title": title,
                "visit_count": int(row.get("visit_count") or 0),
                "last_visited_at": row.get("last_visited_at"),
                "query_hint": query_hint,
                "prompt_hint": query_hint,
                "confidence": ai_usage_confidence(service, url, title, query_hint),
                "evidence_note": "AI service visit detected from browser history; prompt contents may be absent from history.",
            }
        )
    return ai_rows


def detect_ai_service(url: str, title: str = "") -> str:
    parsed = safe_parse_url(url)
    host = normalize_host(parsed.netloc)
    lowered = f"{url} {title}".lower()
    for domain, service in AI_SERVICE_DOMAINS:
        if not host_matches(host, domain):
            continue
        if domain == "bing.com" and not any(token in lowered for token in ("copilot", "bing chat", "chat")):
            continue
        if domain == "notion.so" and "ai" not in lowered:
            continue
        return service
    if "chatgpt" in lowered:
        return "ChatGPT"
    if "claude" in lowered:
        return "Claude"
    if "perplexity" in lowered:
        return "Perplexity"
    if "copilot" in lowered or "bing chat" in lowered:
        return "Microsoft Copilot"
    return ""


def classify_url(parsed, title: str, ai_service: str) -> str:
    host = normalize_host(parsed.netloc)
    lowered = f"{host} {parsed.path} {parsed.query} {title}".lower()
    if ai_service:
        return "ai"
    if any(token in host for token in SEARCH_HOST_HINTS):
        return "search"
    if any(host_matches(host, token) for token in EMAIL_HOST_HINTS):
        return "email"
    if any(host_matches(host, token) for token in SOCIAL_HOST_HINTS):
        return "social"
    if any(host_matches(host, token) for token in CLOUD_HOST_HINTS):
        return "cloud"
    if any(token in lowered for token in ("download", ".zip", ".exe", ".dmg", ".pkg", ".msi")):
        return "download"
    return "web"


def extract_query_hint(url: str) -> str:
    query = parse_qs(safe_parse_url(url).query, keep_blank_values=False)
    for key in QUERY_HINT_KEYS:
        values = query.get(key)
        if not values:
            continue
        value = unquote_plus(str(values[0])).strip()
        if value:
            return value[:240]
    return ""


def ai_usage_confidence(service: str, url: str, title: str, query_hint: str) -> float:
    if query_hint:
        return 0.9
    lowered = f"{url} {title}".lower()
    if service and service.lower().split()[0] in lowered:
        return 0.85
    return 0.75


def safe_parse_url(url: str):
    try:
        return urlparse(url)
    except ValueError:
        return urlparse("")


def normalize_host(host: str) -> str:
    return host.lower().split("@")[-1].split(":")[0].strip(".")


def host_matches(host: str, domain: str) -> bool:
    domain = domain.lower()
    return host == domain or host.endswith(f".{domain}")


def count_field(rows: Sequence[Mapping[str, object]], key: str, *, limit: int = 10) -> List[Dict[str, object]]:
    counts: Dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "")
        if value:
            counts[value] = counts.get(value, 0) + 1
    return [
        {"value": value, "count": count}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def file_hashes(path: Path) -> dict[str, str]:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def extract_chromium_history_and_downloads(history_db: Path) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    try:
        with open_sqlite_snapshot(history_db) as connection:
            if not sqlite_table_exists(connection, "urls"):
                return [], []

            has_visits = sqlite_table_exists(connection, "visits")
            url_columns = sqlite_table_columns(connection, "urls")
            visit_join = (
                """
                    LEFT JOIN (
                        SELECT url, transition, visit_duration, MAX(visit_time) AS max_visit_time
                        FROM visits
                        GROUP BY url
                    ) AS latest_visit ON latest_visit.url = urls.id
                """
                if has_visits
                else ""
            )
            transition_column = "latest_visit.transition" if has_visits else "NULL"
            duration_column = "latest_visit.visit_duration" if has_visits else "NULL"
            typed_count_column = "urls.typed_count" if "typed_count" in url_columns else "NULL"
            history_rows = [
                {
                    "url": row["url"],
                    "title": row["title"] or "",
                    "visit_count": int(row["visit_count"] or 0),
                    "typed_count": int(row["typed_count"] or 0),
                    "last_visited_at": isoformat_from_webkit_micros(row["last_visit_time"]),
                    "last_visit_time_source": "urls.last_visit_time",
                    "transition": str(row["transition"] or ""),
                    "visit_duration_micros": int(row["visit_duration"] or 0),
                    "query_hint": extract_query_hint(row["url"] or ""),
                }
                for row in connection.execute(
                    f"""
                    SELECT
                        urls.url AS url,
                        urls.title AS title,
                        urls.visit_count AS visit_count,
                        {typed_count_column} AS typed_count,
                        urls.last_visit_time AS last_visit_time,
                        {transition_column} AS transition,
                        {duration_column} AS visit_duration
                    FROM urls
                    {visit_join}
                    WHERE urls.url IS NOT NULL AND urls.url != ''
                    ORDER BY urls.last_visit_time DESC, urls.url ASC
                    """
                )
            ]

            download_rows: List[Dict[str, object]] = []
            if sqlite_table_exists(connection, "downloads"):
                download_rows = extract_chromium_downloads(connection)
            return history_rows, download_rows
    except (sqlite3.DatabaseError, OSError):
        return [], []


def extract_chromium_downloads(connection: sqlite3.Connection) -> List[Dict[str, object]]:
    columns = sqlite_table_columns(connection, "downloads")
    if "id" not in columns:
        return []

    chain_urls: Dict[int, str] = {}
    if sqlite_table_exists(connection, "downloads_url_chains"):
        for row in connection.execute(
            """
            SELECT id, url
            FROM downloads_url_chains
            WHERE url IS NOT NULL AND url != ''
            ORDER BY id ASC, chain_index ASC
            """
        ):
            chain_urls.setdefault(int(row["id"]), str(row["url"]))

    select_columns = [
        "id",
        column_or_null(columns, "target_path"),
        column_or_null(columns, "current_path"),
        column_or_null(columns, "tab_url"),
        column_or_null(columns, "total_bytes"),
        column_or_null(columns, "state"),
        column_or_null(columns, "start_time"),
        column_or_null(columns, "end_time"),
    ]
    order_column = "start_time" if "start_time" in columns else "id"
    query = f"SELECT {', '.join(select_columns)} FROM downloads ORDER BY {order_column} DESC, id ASC"

    rows: List[Dict[str, object]] = []
    for row in connection.execute(query):
        download_id = int(row["id"])
        target_path = row["target_path"] or row["current_path"] or ""
        rows.append(
            {
                "source_url": chain_urls.get(download_id) or row["tab_url"] or "",
                "target_path": str(target_path),
                "tab_url": row["tab_url"] or "",
                "total_bytes": int(row["total_bytes"] or 0),
                "state": int(row["state"] or 0),
                "started_at": isoformat_from_webkit_micros(row["start_time"]),
                "ended_at": isoformat_from_webkit_micros(row["end_time"]),
            }
        )
    return rows


def extract_firefox_history(places_db: Path) -> List[Dict[str, object]]:
    try:
        with open_sqlite_snapshot(places_db) as connection:
            if not sqlite_table_exists(connection, "moz_places"):
                return []
            history_rows = []
            for row in connection.execute(
                """
                SELECT
                    moz_places.url AS url,
                    moz_places.title AS title,
                    moz_places.visit_count AS visit_count,
                    MAX(moz_historyvisits.visit_date) AS last_visit_date
                FROM moz_places
                LEFT JOIN moz_historyvisits ON moz_historyvisits.place_id = moz_places.id
                WHERE moz_places.url IS NOT NULL AND moz_places.url != ''
                GROUP BY moz_places.id, moz_places.url, moz_places.title, moz_places.visit_count
                ORDER BY last_visit_date DESC, moz_places.url ASC
                """
            ):
                history_rows.append(
                    {
                        "url": row["url"],
                        "title": row["title"] or "",
                        "visit_count": int(row["visit_count"] or 0),
                        "last_visited_at": isoformat_from_unix_micros(row["last_visit_date"]),
                        "last_visit_time_source": "moz_historyvisits.visit_date",
                        "typed_count": 0,
                        "transition": "",
                        "visit_duration_micros": 0,
                        "query_hint": extract_query_hint(row["url"] or ""),
                    }
                )
            return history_rows
    except (sqlite3.DatabaseError, OSError):
        return []


def sqlite_table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1",
        (table_name,),
    ).fetchone()
    return row is not None


def sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table_name})")}


def column_or_null(columns: set[str], name: str) -> str:
    if name in columns:
        return name
    return f"NULL AS {name}"
